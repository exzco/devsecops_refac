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

type WorkerConfig struct {
	ClusterID   string
	NetworkZone string
}

type Worker struct {
	service *Service
	status  WorkerStatus
}

func NewWorker(cfg WorkerConfig, service *Service) (*Worker, error) {
	if cfg.ClusterID == "" || cfg.NetworkZone == "" || service.scanner == nil {
		return nil, fmt.Errorf("worker placement and scanner are required")
	}
	return &Worker{service: service, status: WorkerStatus{
		InstanceID: rand.Text(), ClusterID: cfg.ClusterID, NetworkZone: cfg.NetworkZone,
		TemplateVersion: service.scanner.version,
	}}, nil
}

func taskQueueKey(cluster, zone, version string) string {
	return "dast:tasks:" + url.QueryEscape(cluster) + ":" + url.QueryEscape(zone) + ":" + url.QueryEscape(version)
}

// Run 阻塞消费本集群、区域和模板版本的任务，具体执行与保存交给 service。
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
	group.Go(func() error {
		key := taskQueueKey(w.status.ClusterID, w.status.NetworkZone, w.status.TemplateVersion)
		for {
			if err := runCtx.Err(); err != nil {
				return err
			}
			entry, err := w.service.redis.BRPop(runCtx, 2*time.Second, key).Result()
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
			if err := w.service.ProcessTask(runCtx, taskID, w.status); err != nil {
				return err
			}
		}
	})
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
	return w.service.redis.HSet(ctx, workerRegistryKey, status.InstanceID, data).Err()
}
