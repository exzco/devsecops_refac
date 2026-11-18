package sast

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	workerRegistryKey       = "sast:workers"
	workerHeartbeatPrefix   = "sast:worker:"
	workerHeartbeatInterval = 10 * time.Second
	workerHeartbeatTTL      = 30 * time.Second
	workerRedisTimeout      = 3 * time.Second
	workerRetryDelay        = 2 * time.Second
)

type Worker struct {
	id      string
	service *Service
}

func NewWorker(id string, service *Service) *Worker {
	return &Worker{id: strings.TrimSpace(id), service: service}
}

func (w *Worker) Run(ctx context.Context, concurrency int) error {
	if err := w.sendEnvironment(ctx); err != nil {
		log.Printf("worker=%s send environment failed: %v", w.id, err)
	}

	if err := w.sendHeartbeat(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("register worker %s: %w", w.id, err)
	}

	var group sync.WaitGroup
	group.Go(func() {
		ticker := time.NewTicker(workerHeartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := w.sendHeartbeat(ctx); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("worker=%s heartbeat failed: %v", w.id, err)
				}
			}
		}
	})
	for range concurrency {
		group.Go(func() { w.consume(ctx) })
	}
	group.Wait()
	return nil
}

func (w *Worker) consume(ctx context.Context) {
	for {
		scanID, err := w.service.queue.Pop(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("worker=%s pop task: %v", w.id, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(workerRetryDelay):
				continue
			}
		}

		if err := w.service.ProcessScan(ctx, scanID, w.id); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("worker=%s scan=%d failed: %v", w.id, scanID, err)
			continue
		}
		log.Printf("worker=%s scan=%d completed", w.id, scanID)
	}
}

func (w *Worker) sendEnvironment(ctx context.Context) error {
	env, err := w.service.DetectEnvironment(w.id)
	if err != nil {
		return fmt.Errorf("detect environment: %w", err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal worker env: %w", err)
	}

	optCtx, cancel := context.WithTimeout(ctx, workerRedisTimeout)
	defer cancel()

	key := workerHeartbeatPrefix + w.id + ":env"
	if err := w.service.queue.redis.Set(optCtx, key, string(raw), 7*24*time.Hour).Err(); err != nil {
		return fmt.Errorf("send worker env to redis: %w", err)
	}
	return nil
}

func (w *Worker) sendHeartbeat(ctx context.Context) error {
	optCtx, cancel := context.WithTimeout(ctx, workerRedisTimeout)
	defer cancel()

	key := workerHeartbeatPrefix + w.id + ":alive"
	_, err := w.service.queue.redis.TxPipelined(optCtx, func(pipe redis.Pipeliner) error {
		pipe.SAdd(optCtx, workerRegistryKey, w.id)
		pipe.Set(optCtx, key, time.Now().UTC().Format(time.RFC3339Nano), workerHeartbeatTTL)
		return nil
	})
	if err != nil {
		return fmt.Errorf("send heartbeat: %w", err)
	}
	return nil
}

type WorkerStatus struct {
	ID         string     `json:"worker_id"`
	Online     bool       `json:"online"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	Hostname   string     `json:"hostname,omitempty"`
	Arch       string     `json:"arch,omitempty"`
	PID        int        `json:"pid,omitempty"`
	NumCPU     int        `json:"num_cpu,omitempty"`
	CodeQLPath string     `json:"codeql_path,omitempty"`
	CodeQLOk   bool       `json:"codeql_ok,omitempty"`
	WorkRoot   string     `json:"work_root,omitempty"`
}

func (s *Service) ListWorkers(ctx context.Context) ([]WorkerStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, workerRedisTimeout)
	defer cancel()

	ids, err := s.queue.redis.SMembers(ctx, workerRegistryKey).Result()
	if err != nil {
		return nil, fmt.Errorf("list workers: %w", err)
	}
	workers := make([]WorkerStatus, 0, len(ids))
	if len(ids) == 0 {
		return workers, nil
	}
	sort.Strings(ids)
	aliveKeys := make([]string, len(ids))
	envKeys := make([]string, len(ids))
	for i, id := range ids {
		aliveKeys[i] = workerHeartbeatPrefix + id + ":alive"
		envKeys[i] = workerHeartbeatPrefix + id + ":env"
	}
	aliveValues, err := s.queue.redis.MGet(ctx, aliveKeys...).Result()
	if err != nil {
		return nil, fmt.Errorf("read worker heartbeats: %w", err)
	}
	envValues, _ := s.queue.redis.MGet(ctx, envKeys...).Result()

	for i, id := range ids {
		worker := WorkerStatus{ID: id, Online: aliveValues[i] != nil}
		if value, ok := aliveValues[i].(string); ok {
			lastSeen, err := time.Parse(time.RFC3339Nano, value)
			if err == nil {
				worker.LastSeenAt = &lastSeen
			}
		}
		if i < len(envValues) {
			if envRaw, ok := envValues[i].(string); ok && envRaw != "" {
				var env WorkerEnv
				if err := json.Unmarshal([]byte(envRaw), &env); err == nil {
					worker.Hostname = env.Hostname
					worker.Arch = env.Arch
					worker.PID = env.PID
					worker.NumCPU = env.NumCPU
					worker.CodeQLPath = env.CodeQLPath
					worker.CodeQLOk = env.CodeQLOk
					worker.WorkRoot = env.WorkRoot
				}
			}
		}
		if worker.Hostname == "" && strings.Contains(id, "-") {
			parts := strings.Split(id, "-")
			if len(parts) >= 2 {
				worker.Hostname = parts[0]
			}
		}
		workers = append(workers, worker)
	}
	return workers, nil
}
