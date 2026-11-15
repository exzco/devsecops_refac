package dast

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// ServerConfig 是 service 写入扫描结果文件的位置；server 和 worker 使用同一配置结构。
type ServerConfig struct {
	ResultRoot string
}

const (
	queueTimeout    = 30 * time.Minute
	saveWindow      = 5 * time.Minute
	onlineTTL       = 30 * time.Second
	cleanupInterval = 10 * time.Second
)

type Service struct {
	store   *Store
	redis   *redis.Client
	scanner *Scanner
	source  AssetSource
	cfg     ServerConfig
}

func NewService(store *Store, rdb *redis.Client, scanner *Scanner, source AssetSource, cfg ServerConfig) (*Service, error) {
	if store == nil || rdb == nil || cfg.ResultRoot == "" {
		return nil, fmt.Errorf("DAST store, Redis and result directory are required")
	}
	return &Service{store: store, redis: rdb, scanner: scanner, source: source, cfg: cfg}, nil
}

// 回收固定期限已到的任务
func (s *Service) ExpireRun(ctx context.Context) error {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		if err := s.store.ExpireTasks(ctx); err != nil {
			if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
				return nil
			}
			return fmt.Errorf("expire DAST tasks: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Service) ListAssets(ctx context.Context, filter AssetFilter) ([]Asset, error) {
	if s.source == nil {
		return nil, errors.New("CMDB/SIEM asset source has not been configured")
	}
	assets, err := s.source.ListAssets(ctx)
	if err != nil {
		return nil, fmt.Errorf("read CMDB/SIEM assets: %w", err)
	}
	result := make([]Asset, 0, len(assets))
	seen := map[AssetKey]struct{}{}
	for _, a := range assets {
		if a.SourceID == "" || a.CMDBID == "" || a.ClusterID == "" || a.NetworkZone == "" {
			return nil, errors.New("asset source returned an asset without identity or placement")
		}
		if _, exists := seen[a.AssetKey]; exists {
			return nil, errors.New("asset source returned duplicate identity")
		}
		seen[a.AssetKey] = struct{}{}
		if filter.Matches(a) {
			a.RegisteredServices = append([]AssetService(nil), a.RegisteredServices...)
			result = append(result, a)
		}
	}
	return result, nil
}

func canonicalRequest(req CreateScanRequest) (CreateScanRequest, error) {
	if req.RequestKey == "" || len(req.RequestKey) > 128 || strings.TrimSpace(req.RequestKey) != req.RequestKey || len(req.Assets) == 0 {
		return req, errors.New("request_key and selected assets are required")
	}
	req.Assets = append([]AssetKey(nil), req.Assets...)
	sort.Slice(req.Assets, func(i, j int) bool {
		a, b := req.Assets[i], req.Assets[j]
		if a.SourceID == b.SourceID {
			return a.CMDBID < b.CMDBID
		}
		return a.SourceID < b.SourceID
	})
	for i, a := range req.Assets {
		if a.SourceID == "" || a.CMDBID == "" {
			return req, errors.New("asset identity is required")
		}
		if i > 0 && a == req.Assets[i-1] {
			return req, errors.New("duplicate selected asset")
		}
	}
	req.Options.TemplateIDs = append([]string(nil), req.Options.TemplateIDs...)
	sort.Strings(req.Options.TemplateIDs)
	req.Options.ProbePorts = append([]PortSpec(nil), req.Options.ProbePorts...)
	sort.Slice(req.Options.ProbePorts, func(i, j int) bool {
		a, b := req.Options.ProbePorts[i], req.Options.ProbePorts[j]
		if a.Transport == b.Transport {
			return a.Port < b.Port
		}
		return a.Transport < b.Transport
	})
	return req, nil
}

func (s *Service) CreateScan(ctx context.Context, user string, req CreateScanRequest) (*Scan, error) {
	if user == "" {
		return nil, errors.New("created by is required")
	}
	req, err := canonicalRequest(req)
	if err != nil {
		return nil, err
	}
	assets, err := s.ListAssets(ctx, req.Filter)
	if err != nil {
		return nil, err
	}
	byID := make(map[AssetKey]Asset, len(assets))
	for _, a := range assets {
		byID[a.AssetKey] = a
	}
	selected := make([]Asset, 0, len(req.Assets))
	for _, key := range req.Assets {
		a, ok := byID[key]
		if !ok {
			return nil, errors.New("selected asset no longer exists in the selected scope")
		}
		selected = append(selected, a)
	}
	plans, err := BuildTaskPlans(selected, req.Options)
	if err != nil {
		return nil, err
	}
	scan, err := s.store.CreateScan(ctx, user, req, plans, queueTimeout)
	if err != nil {
		return nil, err
	}
	detail, err := s.store.GetScan(ctx, scan.ID, user)
	if err != nil {
		return nil, err
	}
	// 请求重试可能再次投递同一任务 ID；StartTask 只允许 pending -> running 一次。
	_, err = s.redis.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		for _, task := range detail.Tasks {
			if task.Status == TaskPending {
				key := taskQueueKey(task.Plan.Asset.ClusterID, task.Plan.Asset.NetworkZone, task.Plan.Options.TemplateVersion)
				pipe.LPush(ctx, key, task.ID)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("enqueue DAST tasks: %w", err)
	}
	return scan, nil
}

func (s *Service) ListScans(ctx context.Context, user string) ([]Scan, error) {
	return s.store.ListScans(ctx, user)
}
func (s *Service) GetScan(ctx context.Context, id int64, user string) (*ScanDetail, error) {
	return s.store.GetScan(ctx, id, user)
}
func (s *Service) ListFindings(ctx context.Context, id int64, user string) ([]Finding, error) {
	return s.store.ListFindings(ctx, id, user)
}
func (s *Service) GetTask(ctx context.Context, id int64, user string) (*TaskDetail, error) {
	detail, err := s.store.GetTask(ctx, id, user)
	if err != nil {
		return nil, err
	}
	detail.Unregistered = make([]AssetService, 0)
	if detail.Result != nil {
		detail.Unregistered, err = FindUnregistered(detail.Task.Plan.Asset, *detail.Result)
		if err != nil {
			return nil, err
		}
	}
	return detail, nil
}

// FindUnregistered 按本次解析的 IP、端口和传输协议比较登记服务与扫描结果。
func FindUnregistered(asset Asset, result TaskResult) ([]AssetService, error) {
	known := make(map[Endpoint]struct{})
	for _, value := range result.ResolvedIPs {
		ip, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("resolved IP: %w", err)
		}
		for _, service := range asset.RegisteredServices {
			endpoint := service.Endpoint
			endpoint.Host = ip.Unmap().String()
			endpoint, err = NormalizeEndpoint(endpoint)
			if err != nil {
				return nil, fmt.Errorf("registered service: %w", err)
			}
			known[endpoint] = struct{}{}
		}
	}
	unregistered := make([]AssetService, 0)
	for _, service := range result.Services {
		endpoint, err := NormalizeEndpoint(service.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("discovered service: %w", err)
		}
		if service.ObservedAt.IsZero() {
			return nil, errors.New("discovered service observed time is required")
		}
		if _, exists := known[endpoint]; exists {
			continue
		}
		known[endpoint] = struct{}{}
		unregistered = append(unregistered, service)
	}
	return unregistered, nil
}

// ProcessTask 由 worker 消费队列后调用：开始任务、扫描，再保存结果。
func (s *Service) ProcessTask(ctx context.Context, taskID int64, worker WorkerStatus) error {
	task, err := s.store.StartTask(ctx, taskID, worker)
	if err != nil || task == nil {
		return err
	}
	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(task.Plan.Options.TimeoutSeconds)*time.Second)
	result, scanErr := s.scanner.Scan(scanCtx, task.Plan)
	if scanErr == nil {
		scanErr = scanCtx.Err()
	}
	cancel()
	task.Status = TaskSuccess
	if scanErr != nil {
		task.Status = TaskFailed
		task.Error = scanErr.Error()
	}
	return s.SaveResult(ctx, *task, result)
}

// SaveResult 编排结果文件和数据库写入；store 只处理数据库事务。
func (s *Service) SaveResult(ctx context.Context, task Task, result TaskResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.cfg.ResultRoot, strconv.FormatInt(task.ID, 10)+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write DAST result file: %w", err)
	}
	return s.store.SaveResult(ctx, task, result)
}

func (s *Service) ListWorkers(ctx context.Context) ([]WorkerStatus, error) {
	entries, err := s.redis.HGetAll(ctx, workerRegistryKey).Result()
	if err != nil {
		return nil, err
	}
	workers := make([]WorkerStatus, 0, len(entries))
	for _, entry := range entries {
		var worker WorkerStatus
		if err := json.Unmarshal([]byte(entry), &worker); err != nil {
			return nil, err
		}
		worker.Online = time.Since(worker.LastSeenAt) < onlineTTL
		workers = append(workers, worker)
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].InstanceID < workers[j].InstanceID })
	return workers, nil
}
