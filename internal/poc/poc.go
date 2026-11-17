package poc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"devsecops/internal/infra"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

type Config struct {
	GitHubToken, NVDKey string
	Agent               infra.AgentConfig
}
type Service struct {
	db      *pgxpool.Pool
	redis   *redis.Client
	cfg     Config
	agent   *infra.NetAgent
	agentMu sync.RWMutex
	client  *http.Client
	mu      sync.Mutex
	cached  []byte
	expires time.Time
	lookups singleflight.Group
}

func New(db *pgxpool.Pool, rdb *redis.Client, cfg Config) *Service {
	return &Service{db: db, redis: rdb, cfg: cfg, agent: infra.NewNetAgent(cfg.Agent), client: &http.Client{Timeout: 45 * time.Second}}
}

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

type Link struct {
	URL   string `json:"url"`
	Title string `json:"title"`
}
type Manual struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	PoCs        []Link `json:"pocs"`
	Notes       string `json:"notes"`
}
type CVE struct {
	ID         string                     `json:"id"`
	Sources    map[string]json.RawMessage `json:"sources"`
	Discovered []Link                     `json:"discovered"`
	Manual     Manual                     `json:"manual"`
	SearchedAt *time.Time                 `json:"searched_at"`
	UpdatedAt  time.Time                  `json:"updated_at"`
}

type CVEFilter struct {
	Query  string
	Status string
	Year   string
	Start  string
	End    string
	Limit  int
}

func (s *Service) invalidate() {}
func (s *Service) list(ctx context.Context, f CVEFilter) ([]CVE, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	clauses := []string{}
	args := []any{}
	argIdx := 1

	if f.Query != "" {
		clauses = append(clauses, fmt.Sprintf("(id ILIKE $%d OR manual->>'title' ILIKE $%d OR manual->>'description' ILIKE $%d)", argIdx, argIdx, argIdx))
		args = append(args, "%"+f.Query+"%")
		argIdx++
	}

	if f.Year == "2018-2026" {
		clauses = append(clauses, "substring(id from 5 for 4) BETWEEN '2018' AND '2026'")
	} else if f.Year != "" && f.Year != "all" {
		clauses = append(clauses, fmt.Sprintf("id LIKE $%d", argIdx))
		args = append(args, "CVE-"+f.Year+"-%")
		argIdx++
	}

	switch f.Status {
	case "missing":
		clauses = append(clauses, "discovered = '[]'::jsonb AND (manual->'pocs' IS NULL OR manual->'pocs' = '[]'::jsonb)")
	case "manual":
		clauses = append(clauses, "manual->'pocs' IS NOT NULL AND manual->'pocs' <> '[]'::jsonb")
	case "candidate":
		clauses = append(clauses, "discovered <> '[]'::jsonb")
	}

	if f.Start != "" {
		clauses = append(clauses, fmt.Sprintf("updated_at >= $%d::timestamptz", argIdx))
		args = append(args, f.Start)
		argIdx++
	}
	if f.End != "" {
		clauses = append(clauses, fmt.Sprintf("updated_at <= $%d::timestamptz", argIdx))
		args = append(args, f.End+" 23:59:59")
		argIdx++
	}

	query := "SELECT id,sources,discovered,manual,searched_at,updated_at FROM poc_cves"
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY updated_at DESC, id LIMIT %d", limit)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []CVE{}
	for rows.Next() {
		var c CVE
		if err := rows.Scan(&c.ID, &c.Sources, &c.Discovered, &c.Manual, &c.SearchedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		if err := c.mergeLinks(); err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return items, rows.Err()
}
func (s *Service) get(ctx context.Context, id string) (CVE, error) {
	var c CVE
	err := s.db.QueryRow(ctx, `SELECT id,sources,discovered,manual,searched_at,updated_at FROM poc_cves WHERE id=$1`, id).Scan(&c.ID, &c.Sources, &c.Discovered, &c.Manual, &c.SearchedAt, &c.UpdatedAt)
	if err == nil {
		err = c.mergeLinks()
	}
	return c, err
}
func (s *Service) fetch(ctx context.Context, address string, out any, next *string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "devsecops-cve")
	switch req.URL.Host {
	case "api.github.com":
		req.Header.Set("Accept", "application/vnd.github+json")
		if s.cfg.GitHubToken != "" {
			req.Header.Set("Authorization", "Bearer "+s.cfg.GitHubToken)
		}
	case "services.nvd.nist.gov":
		if s.cfg.NVDKey != "" {
			req.Header.Set("apiKey", s.cfg.NVDKey)
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
func (s *Service) ingest(ctx context.Context, id, source string, raw json.RawMessage) error {
	if !cvePattern.MatchString(id) {
		return fmt.Errorf("invalid CVE ID: %s", id)
	}
	sources, err := json.Marshal(map[string]json.RawMessage{source: raw})
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO poc_cves(id,sources) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET sources=poc_cves.sources || EXCLUDED.sources,updated_at=now()`, id, sources)
	if err == nil {
		s.invalidate()
	}
	return err
}

type SyncInput struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

func (in SyncInput) dates() (time.Time, time.Time, error) {
	start, err := time.Parse("2006-01-02", in.Start)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("开始日期须为 YYYY-MM-DD")
	}
	end, err := time.Parse("2006-01-02", in.End)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("结束日期须为 YYYY-MM-DD")
	}
	if end.Before(start) {
		return time.Time{}, time.Time{}, errors.New("结束日期不能早于开始日期")
	}
	return start, end.Add(24*time.Hour - time.Millisecond), nil
}
func syncWindows(ctx context.Context, start, end time.Time, run func(time.Time, time.Time) error) error {
	for from := start; !from.After(end); {
		until := from.AddDate(0, 0, 30).Add(-time.Millisecond)
		if until.After(end) {
			until = end
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := run(from, until); err != nil {
			return err
		}
		from = until.Add(time.Millisecond)
		if !from.After(end) {
			if err := wait(ctx, 6*time.Second); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) syncCVE(ctx context.Context, in SyncInput, progress func(string) error) error {
	start, end, err := in.dates()
	if err != nil {
		return err
	}
	ids := map[string]struct{}{}
	recentIDs := map[string]struct{}{}
	years := map[string]struct{}{}
	for year := start.Year(); year <= end.Year(); year++ {
		years[fmt.Sprint(year)] = struct{}{}
	}
	sources := []struct {
		name string
		run  func() error
	}{
		{"nomi-sec/PoC-in-GitHub", func() error { return s.syncRepository(ctx, repositorySources[0], years, ids, progress) }},
		{"trickest/cve", func() error { return s.syncRepository(ctx, repositorySources[1], years, ids, progress) }},
		{"projectdiscovery/nuclei-templates", func() error { return s.syncRepository(ctx, repositorySources[2], years, ids, progress) }},
		{"GitHub Advisories", func() error {
			return syncWindows(ctx, start, end, func(from, until time.Time) error {
				if err := progress("GitHub 公告 " + from.Format("2006-01-02") + " 至 " + until.Format("2006-01-02")); err != nil {
					return err
				}
				return s.syncAdvisories(ctx, SyncInput{Start: from.Format("2006-01-02"), End: until.Format("2006-01-02")}, recentIDs)
			})
		}},
		{"NVD", func() error {
			return syncWindows(ctx, start, end, func(from, until time.Time) error { return s.syncNVD(ctx, from, until, recentIDs, progress) })
		}},
		{"GitHub 仓库搜索", func() error { return s.searchMissing(ctx, recentIDs, progress) }},
	}
	completed := 0
	failures := []error{}
	summary := []string{}
	for _, source := range sources {
		if err := progress(strings.Join(append(summary, source.name+"：同步中"), "；")); err != nil {
			return err
		}
		err := source.run()
		if err != nil {
			var remote *sourceError
			if !errors.As(err, &remote) {
				return err
			}
			failures = append(failures, fmt.Errorf("%s: %w", source.name, err))
			summary = append(summary, source.name+"：失败")
		} else {
			completed++
			summary = append(summary, source.name+"：完成")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	for id := range recentIDs {
		ids[id] = struct{}{}
	}
	if err := progress(fmt.Sprintf("处理 %d 个 CVE；%s", len(ids), strings.Join(summary, "；"))); err != nil {
		return err
	}
	if len(failures) > 0 {
		return &syncFailure{completed, errors.Join(failures...)}
	}
	return nil
}
func (s *Service) syncNVD(ctx context.Context, start, end time.Time, ids map[string]struct{}, progress func(string) error) error {
	for offset := 0; ; {
		q := url.Values{"lastModStartDate": {start.Format("2006-01-02T15:04:05.000")}, "lastModEndDate": {end.Format("2006-01-02T15:04:05.000")}, "resultsPerPage": {"2000"}, "startIndex": {fmt.Sprint(offset)}}
		var page struct {
			TotalResults    int
			Vulnerabilities []struct{ CVE json.RawMessage }
		}
		if err := s.fetch(ctx, "https://services.nvd.nist.gov/rest/json/cves/2.0?"+q.Encode(), &page, nil); err != nil {
			return err
		}
		for _, entry := range page.Vulnerabilities {
			var v struct{ ID string }
			if err := json.Unmarshal(entry.CVE, &v); err != nil {
				return err
			}
			if err := s.ingest(ctx, v.ID, "nvd", entry.CVE); err != nil {
				return err
			}
			ids[v.ID] = struct{}{}
		}
		offset += len(page.Vulnerabilities)
		if err := progress(fmt.Sprintf("NVD %d/%d", offset, page.TotalResults)); err != nil {
			return err
		}
		if offset >= page.TotalResults {
			break
		}
		if len(page.Vulnerabilities) == 0 {
			return errors.New("NVD returned an empty intermediate page")
		}
		if err := wait(ctx, 6*time.Second); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) syncAdvisories(ctx context.Context, in SyncInput, ids map[string]struct{}) error {
	q := url.Values{"modified": {in.Start + ".." + in.End}, "per_page": {"100"}, "sort": {"updated"}, "direction": {"asc"}}
	next := "https://api.github.com/advisories?" + q.Encode()
	for next != "" {
		var entries []json.RawMessage
		if err := s.fetch(ctx, next, &entries, &next); err != nil {
			return err
		}
		for _, raw := range entries {
			var v struct {
				CVEID  string `json:"cve_id"`
				GHSAID string `json:"ghsa_id"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				return err
			}
			if v.CVEID == "" {
				continue
			}
			if err := s.ingest(ctx, v.CVEID, "github:"+v.GHSAID, raw); err != nil {
				return err
			}
			ids[v.CVEID] = struct{}{}
		}
		if next != "" {
			if err := wait(ctx, time.Second); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) searchMissing(ctx context.Context, ids map[string]struct{}, progress func(string) error) error {
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] > ordered[j] })
	count := 0
	const maxSearch = 50
	for _, id := range ordered {
		if count >= maxSearch {
			break
		}
		c, err := s.get(ctx, id)
		if err != nil {
			return err
		}
		if len(c.Discovered) > 0 || len(c.Manual.PoCs) > 0 || (c.SearchedAt != nil && time.Since(*c.SearchedAt) < 24*time.Hour) {
			continue
		}
		if err := s.searchRepositories(ctx, id); err != nil {
			return err
		}
		count++
		if err := progress(fmt.Sprintf("GitHub 补充搜索 %d/%d，当前 %s；共收录 %d 个 CVE", count, maxSearch, id, len(ids))); err != nil {
			return err
		}
		if err := wait(ctx, 7*time.Second); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) searchRepositories(ctx context.Context, id string) error {
	if !cvePattern.MatchString(id) {
		return errors.New("invalid CVE ID")
	}
	var result struct {
		Incomplete bool `json:"incomplete_results"`
		Items      []struct {
			HTMLURL string `json:"html_url"`
			Name    string `json:"full_name"`
		}
	}
	q := url.Values{"q": {id + " in:name,description,readme"}, "per_page": {"10"}, "sort": {"stars"}}
	if err := s.fetch(ctx, "https://api.github.com/search/repositories?"+q.Encode(), &result, nil); err != nil {
		return err
	}
	if result.Incomplete {
		return &sourceError{errors.New("GitHub search incomplete; retry this CVE later")}
	}
	links := []Link{}
	for _, r := range result.Items {
		links = append(links, Link{r.HTMLURL, r.Name})
	}
	raw, err := json.Marshal(links)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, `UPDATE poc_cves SET discovered=$2,searched_at=now(),updated_at=now() WHERE id=$1`, id, raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("CVE not found")
	}
	s.invalidate()
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
func (s *Service) enqueue(ctx context.Context, kind string, input any) (int64, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRow(ctx, `INSERT INTO poc_jobs(kind,input) VALUES($1,$2) RETURNING id`, kind, raw).Scan(&id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "poc_one_source_job" {
		return 0, errors.New("已有数据同步或搜索任务正在排队或执行，请等待完成")
	}
	return id, err
}
func decode(c *echo.Context, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 2<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}
func respond(c *echo.Context, data any, err error) error {
	if err != nil {
		return c.JSON(400, map[string]string{"error": err.Error()})
	}
	return c.JSON(200, data)
}
func (s *Service) Register(g *echo.Group) {
	g.GET("/pocs", func(c *echo.Context) error {
		limit := 200
		if l := c.QueryParam("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}
		f := CVEFilter{
			Query:  strings.TrimSpace(c.QueryParam("q")),
			Status: strings.TrimSpace(c.QueryParam("filter")),
			Year:   strings.TrimSpace(c.QueryParam("year")),
			Start:  strings.TrimSpace(c.QueryParam("start")),
			End:    strings.TrimSpace(c.QueryParam("end")),
			Limit:  limit,
		}
		items, err := s.list(c.Request().Context(), f)
		if err != nil {
			return respond(c, nil, err)
		}
		return c.JSON(200, items)
	})
	g.PUT("/pocs/:id", func(c *echo.Context) error {
		id := strings.ToUpper(c.Param("id"))
		if !cvePattern.MatchString(id) {
			return respond(c, nil, errors.New("invalid CVE ID"))
		}
		var in Manual
		if err := decode(c, &in); err != nil {
			return respond(c, nil, err)
		}
		for _, link := range in.PoCs {
			u, err := url.Parse(link.URL)
			if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
				return respond(c, nil, errors.New("PoC links must use HTTP(S)"))
			}
		}
		raw, err := json.Marshal(in)
		if err != nil {
			return respond(c, nil, err)
		}
		_, err = s.db.Exec(c.Request().Context(), `INSERT INTO poc_cves(id,sources,manual) VALUES($1,'{}',$2) ON CONFLICT(id) DO UPDATE SET manual=EXCLUDED.manual,updated_at=now()`, id, raw)
		if err == nil {
			s.invalidate()
		}
		return respond(c, in, err)
	})
	g.POST("/pocs/sync", func(c *echo.Context) error {
		var in SyncInput
		if err := decode(c, &in); err != nil {
			return respond(c, nil, err)
		}
		if _, _, err := in.dates(); err != nil {
			return respond(c, nil, err)
		}
		id, err := s.enqueue(c.Request().Context(), "sync", in)
		return respond(c, id, err)
	})
	g.POST("/pocs/search", func(c *echo.Context) error {
		var in struct {
			IDs []string `json:"ids"`
		}
		if err := decode(c, &in); err != nil {
			return respond(c, nil, err)
		}
		if len(in.IDs) == 0 || len(in.IDs) > 100 {
			return respond(c, nil, errors.New("选择 1–100 个 CVE"))
		}
		id, err := s.enqueue(c.Request().Context(), "search", in)
		return respond(c, id, err)
	})
	g.GET("/poc-jobs", func(c *echo.Context) error {
		rows, err := s.db.Query(c.Request().Context(), `SELECT json_build_object('id',id,'kind',kind,'status',status,'progress',progress,'error',error,'created_at',created_at) FROM poc_jobs ORDER BY id DESC LIMIT 30`)
		if err != nil {
			return respond(c, nil, err)
		}
		defer rows.Close()
		data := []json.RawMessage{}
		for rows.Next() {
			var raw json.RawMessage
			if err := rows.Scan(&raw); err != nil {
				return respond(c, nil, err)
			}
			data = append(data, raw)
		}
		return respond(c, data, rows.Err())
	})
	s.registerAgent(g)
}
