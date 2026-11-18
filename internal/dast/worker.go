package dast

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
)

const (
	workerRegistryKey = "dast:workers"
	heartbeatInterval = 10 * time.Second
)

type WorkerStatus struct {
	InstanceID      string    `json:"instance_id"`
	ClusterID       string    `json:"cluster_id"`
	NetworkZone     string    `json:"network_zone"`
	TemplateVersion string    `json:"template_version"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	Online          bool      `json:"online"`
}

type WorkerConfig struct {
	ClusterID   string
	NetworkZone string
	Concurrency int
}

// taskProcessor 只描述 worker 消费任务时需要的能力。
type taskProcessor interface {
	ProcessTask(context.Context, int64, WorkerStatus) error
}

type Worker struct {
	redis *redis.Client
	processor taskProcessor
	status  WorkerStatus
	concurrency int
}

func NewWorker(cfg WorkerConfig, rdb *redis.Client, processor taskProcessor, templateVersion string) (*Worker, error) {
	if cfg.ClusterID == "" || cfg.NetworkZone == "" || rdb == nil || processor == nil || templateVersion == "" {
		return nil, fmt.Errorf("worker placement, Redis, task processor and template version are required")
	}
	if cfg.Concurrency <= 0 {
		return nil, fmt.Errorf("worker concurrency must be positive")
	}
	return &Worker{redis: rdb, processor: processor, concurrency: cfg.Concurrency, status: WorkerStatus{
		InstanceID: rand.Text(), ClusterID: cfg.ClusterID, NetworkZone: cfg.NetworkZone,
		TemplateVersion: templateVersion,
	}}, nil
}

func taskQueueKey(cluster, zone, version string) string {
	return "dast:tasks:" + url.QueryEscape(cluster) + ":" + url.QueryEscape(zone) + ":" + url.QueryEscape(version)
}

// Run 并发消费本集群、区域和模板版本的任务，具体执行与保存交给 service。
func (w *Worker) Run(ctx context.Context) error {
	if err := w.sendHeartbeat(ctx); err != nil {
		return err
	}
	group, runCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return nil
			case <-ticker.C:
				if err := w.sendHeartbeat(runCtx); err != nil {
					return err
				}
			}
		}
	})
	for range w.concurrency {
		group.Go(func() error {
			key := taskQueueKey(w.status.ClusterID, w.status.NetworkZone, w.status.TemplateVersion)
			for {
				if err := runCtx.Err(); err != nil {
					return err
				}
				entry, err := w.redis.BRPop(runCtx, 2*time.Second, key).Result()
				if errors.Is(err, redis.Nil) {
					continue
				}
				if err != nil {
					return fmt.Errorf("wait for DAST task: %w", err)
				}
				taskID, err := strconv.ParseInt(entry[1], 10, 64)
				if err != nil {
					return fmt.Errorf("decode DAST task ID: %w", err)
				}
				if err := w.processor.ProcessTask(runCtx, taskID, w.status); err != nil {
					return err
				}
			}
		})
	}
	err := group.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (w *Worker) sendHeartbeat(ctx context.Context) error {
	status := w.status
	status.LastSeenAt = time.Now().UTC()
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return w.redis.HSet(ctx, workerRegistryKey, status.InstanceID, data).Err()
}
