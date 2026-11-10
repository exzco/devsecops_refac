package sast

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
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

func (w *Worker) Run(ctx context.Context) error {
	if err := w.sendHeartbeat(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("register worker %s: %w", w.id, err)
	}

	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	// 发送心跳的协程
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(workerHeartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				if err := w.sendHeartbeat(heartbeatCtx); err != nil {
					if heartbeatCtx.Err() != nil {
						return
					}
					log.Printf("worker=%s heartbeat failed: %v", w.id, err)
				}
			}
		}
	}()
	// 退出时清理
	defer func() {
		cancelHeartbeat()
		<-heartbeatDone
	}()

	// worker 消费
	for {
		scanID, err := w.service.queue.Pop(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("worker=%s pop task: %v", w.id, err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(workerRetryDelay):
				continue
			}
		}

		if err := w.service.ProcessScan(ctx, scanID, w.id); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("worker=%s scan=%d failed: %v", w.id, scanID, err)
			continue
		}
		log.Printf("worker=%s scan=%d completed", w.id, scanID)

	}
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
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = workerHeartbeatPrefix + id + ":alive"
	}
	values, err := s.queue.redis.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("read worker heartbeats: %w", err)
	}
	for i, id := range ids {
		worker := WorkerStatus{ID: id, Online: values[i] != nil}
		if value, ok := values[i].(string); ok {
			lastSeen, err := time.Parse(time.RFC3339Nano, value)
			if err == nil {
				worker.LastSeenAt = &lastSeen
			}
		}
		workers = append(workers, worker)
	}
	return workers, nil
}
