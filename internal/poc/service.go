package poc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"devsecops/internal/infra"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

type Config struct {
	GitHubToken string
	Agent       infra.AgentConfig
}

type Service struct {
	db      *pgxpool.Pool
	redis   *redis.Client
	cfg     Config
	agent   *infra.NetAgent
	agentMu sync.RWMutex
	client  *http.Client
	lookups singleflight.Group
}

func New(db *pgxpool.Pool, rdb *redis.Client, cfg Config) *Service {
	return &Service{
		db:      db,
		redis:   rdb,
		cfg:     cfg,
		agent:   infra.NewNetAgent(cfg.Agent),
		client:  &http.Client{Timeout: 45 * time.Second},
	}
}

func (s *Service) fetch(ctx context.Context, address string, out any, next *string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "devsecops-cve")
	if req.URL.Host == "api.github.com" {
		req.Header.Set("Accept", "application/vnd.github+json")
		if s.cfg.GitHubToken != "" {
			req.Header.Set("Authorization", "Bearer "+s.cfg.GitHubToken)
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return &sourceError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		detail := fmt.Sprintf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
		for _, key := range []string{"Retry-After", "X-RateLimit-Reset"} {
			if value := resp.Header.Get(key); value != "" {
				detail += "; " + key + "=" + value
			}
		}
		return &sourceError{errors.New(detail)}
	}
	if next != nil {
		*next = ""
		for _, part := range strings.Split(resp.Header.Get("Link"), ",") {
			if strings.Contains(part, `rel="next"`) {
				segment := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
				*next = strings.Trim(segment, "<>")
			}
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return &sourceError{err}
	}
	return nil
}

func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Service) currentAgent() *infra.NetAgent {
	s.agentMu.RLock()
	defer s.agentMu.RUnlock()
	return s.agent
}

func (s *Service) agentView() map[string]any {
	agent := s.currentAgent()
	message := ""
	if err := agent.Ready(); err != nil {
		message = err.Error()
	}
	return map[string]any{
		"protocol":            agent.Config.Protocol,
		"base_url":            agent.Config.BaseURL,
		"model":               agent.Config.Model,
		"has_api_key":         agent.Config.APIKey != "",
		"configuration_error": message,
		"schema":              SpecSchema,
	}
}

func (s *Service) saveAgent(in infra.AgentConfig) error {
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	if in.APIKey == "" {
		if in.BaseURL != s.agent.Config.BaseURL || in.Protocol != s.agent.Config.Protocol {
			return errors.New("更换协议或地址时请重新填写 API Key")
		}
		in.APIKey = s.agent.Config.APIKey
	}
	agent := infra.NewNetAgent(in)
	if err := agent.Ready(); err != nil {
		return err
	}
	values, err := godotenv.Read(".env")
	if err != nil {
		return err
	}
	for key, value := range map[string]string{
		"AI_PROTOCOL": in.Protocol,
		"AI_BASE_URL": in.BaseURL,
		"AI_MODEL":    in.Model,
		"AI_API_KEY":  in.APIKey,
	} {
		values[key] = value
	}
	raw, err := godotenv.Marshal(values)
	if err != nil {
		return err
	}
	if err := os.Chmod(".env", 0600); err != nil {
		return err
	}
	if err := os.WriteFile(".env", []byte(raw+"\n"), 0600); err != nil {
		return err
	}
	s.agent = agent
	return nil
}

// Run owns the scheduler; generation workers claim separate durable jobs.
func (s *Service) Run(ctx context.Context) error {
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(7192301)`).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return errors.New("PoC job runner already active")
	}
	defer conn.Conn().Close(context.Background())
	if _, err := conn.Exec(ctx, `
		BEGIN;
		DROP INDEX IF EXISTS poc_one_job;
		CREATE UNIQUE INDEX IF NOT EXISTS poc_one_source_job ON poc_jobs ((true))
			WHERE kind IN ('sync','search') AND status IN ('queued','running');
		COMMIT;
	`); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `UPDATE poc_jobs SET status='failed',error='服务重启，任务中断；可重新提交',finished_at=now() WHERE status='running'`); err != nil {
		return err
	}
	workers, workerCtx := errgroup.WithContext(ctx)
	for range 4 {
		workers.Go(func() error { return s.consumeJobs(workerCtx, []string{"generate"}) })
	}
	workers.Go(func() error { return s.consumeJobs(workerCtx, []string{"sync", "search"}) })
	return workers.Wait()
}

func (s *Service) consumeJobs(ctx context.Context, kinds []string) error {
	for {
		var id int64
		var kind string
		var raw json.RawMessage
		err := s.db.QueryRow(ctx, `WITH next_job AS (
			SELECT id FROM poc_jobs WHERE status='queued' AND kind=ANY($1)
			ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED
		) UPDATE poc_jobs AS job SET status='running' FROM next_job
		WHERE job.id=next_job.id RETURNING job.id,job.kind,job.input`, kinds).Scan(&id, &kind, &raw)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := wait(ctx, 3*time.Second); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		progress := func(value string) error {
			_, err := s.db.Exec(ctx, `UPDATE poc_jobs SET progress=$2 WHERE id=$1`, id, value)
			return err
		}
		jobErr := s.runJob(ctx, kind, raw, progress)
		status, message := "done", ""
		if jobErr != nil {
			status = "failed"
			var partial *syncFailure
			if errors.As(jobErr, &partial) && partial.completed > 0 {
				status = "partial"
			}
			message = jobErr.Error()
		}
		if _, err := s.db.Exec(ctx, `UPDATE poc_jobs SET status=$2,error=$3,finished_at=now() WHERE id=$1`, id, status, message); err != nil {
			return err
		}
	}
}

func (s *Service) runJob(ctx context.Context, kind string, raw json.RawMessage, progress func(string) error) error {
	switch kind {
	case "sync":
		var in SyncInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return err
		}
		return s.syncCVE(ctx, in, progress)
	case "search":
		var in struct {
			IDs []string `json:"ids"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			return err
		}
		for _, id := range in.IDs {
			if err := s.search(ctx, id); err != nil {
				return err
			}
			if err := progress(id); err != nil {
				return err
			}
			if err := wait(ctx, 7*time.Second); err != nil {
				return err
			}
		}
		return nil
	case "generate":
		var in GenerateInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return err
		}
		return s.generate(ctx, in, progress)
	}
	return fmt.Errorf("unknown job kind %s", kind)
}
