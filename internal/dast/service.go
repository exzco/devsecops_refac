package dast

import (
	dastscanner "devsecops/internal/dast/scanner"
	"devsecops/internal/dast/domain"
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

// AssetSource 由资产查询用例声明，数据源只需提供资产列表。
type AssetSource interface {
	ListAssets(context.Context) ([]domain.Asset, error)
}

type Service struct {
	store   *Store
	redis   *redis.Client
	scanner *dastscanner.Scanner
	source  AssetSource
	cfg     ServerConfig
}

func NewService(store *Store, rdb *redis.Client, scanner *dastscanner.Scanner, source AssetSource, cfg ServerConfig) (*Service, error) {
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

func (s *Service) CreateAsset(ctx context.Context, asset domain.Asset) (domain.Asset, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(asset.Host))
	if err != nil || ip.Zone() != "" {
		return domain.Asset{}, errors.New("请输入有效的 IPv4 或 IPv6 地址")
	}
	asset.Host = ip.Unmap().String()
	if asset.SourceID == "" {
		asset.SourceID = "manual"
	}
	if asset.CMDBID == "" {
		asset.CMDBID = asset.Host
	}
	if asset.ClusterID == "" {
		asset.ClusterID = "local"
	}
	if asset.NetworkZone == "" {
		asset.NetworkZone = "local"
	}
	if asset.BusinessID == "" {
		asset.BusinessID = "default"
	}
	if asset.Owner == "" {
		asset.Owner = "admin"
	}
	if asset.RegisteredServices == nil {
		asset.RegisteredServices = []domain.AssetService{}
	}
	asset, err = domain.NormalizeAsset(asset)
	if err != nil {
		return domain.Asset{}, err
	}
	if err := s.store.CreateAsset(ctx, asset); err != nil {
		return domain.Asset{}, err
	}
	return asset, nil
}

func (s *Service) ListAssets(ctx context.Context, filter domain.AssetFilter) ([]domain.Asset, error) {
	if s.source == nil {
		return nil, errors.New("CMDB/SIEM asset source has not been configured")
	}
	assets, err := s.source.ListAssets(ctx)
	if err != nil {
		return nil, fmt.Errorf("read asset source: %w", err)
	}
	result := make([]domain.Asset, 0, len(assets))
	seen := map[domain.AssetKey]struct{}{}
	for _, a := range assets {
		if a.SourceID == "" || a.CMDBID == "" || a.ClusterID == "" || a.NetworkZone == "" {
			return nil, errors.New("asset source returned an asset without identity or placement")
		}
		if _, exists := seen[a.AssetKey]; exists {
			return nil, errors.New("asset source returned duplicate identity")
		}
		seen[a.AssetKey] = struct{}{}
		if filter.Matches(a) {
			a.RegisteredServices = append([]domain.AssetService{}, a.RegisteredServices...)
			result = append(result, a)
		}
	}
	return result, nil
}

func canonicalRequest(req domain.CreateScanRequest) (domain.CreateScanRequest, error) {
	if strings.TrimSpace(req.RequestKey) == "" {
		req.RequestKey = fmt.Sprintf("scan-%d", time.Now().UnixNano())
	}
	if len(req.RequestKey) > 128 || strings.TrimSpace(req.RequestKey) != req.RequestKey || len(req.Assets) == 0 {
		return req, errors.New("request_key and selected assets are required")
	}
	if req.Options.TimeoutSeconds <= 0 {
		req.Options.TimeoutSeconds = 600
	}
	if req.Options.RateLimit <= 0 {
		req.Options.RateLimit = 1000
	}
	if req.Options.Concurrency <= 0 {
		req.Options.Concurrency = 10
	}
	if len(req.Options.ProbePorts) == 0 {
		req.Options.ProbePorts = make([]domain.PortSpec, 65535)
		for i := 1; i <= 65535; i++ {
			req.Options.ProbePorts[i-1] = domain.PortSpec{Port: i, Transport: domain.TransportTCP}
		}
	}
	if len(req.Options.ProbePorts) > 1000 && req.Options.RateLimit <= 100 {
		req.Options.RateLimit = 1000
	}
	req.Assets = append([]domain.AssetKey(nil), req.Assets...)
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
	req.Options.ProbePorts = append([]domain.PortSpec(nil), req.Options.ProbePorts...)
	sort.Slice(req.Options.ProbePorts, func(i, j int) bool {
		a, b := req.Options.ProbePorts[i], req.Options.ProbePorts[j]
		if a.Transport == b.Transport {
			return a.Port < b.Port
		}
		return a.Transport < b.Transport
	})
	return req, nil
}

func (s *Service) CreateScan(ctx context.Context, user string, req domain.CreateScanRequest) (*domain.Scan, error) {
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
	byID := make(map[domain.AssetKey]domain.Asset, len(assets))
	for _, a := range assets {
		byID[a.AssetKey] = a
	}
	selected := make([]domain.Asset, 0, len(req.Assets))
	for _, key := range req.Assets {
		a, ok := byID[key]
		if !ok {
			return nil, errors.New("selected asset no longer exists in the selected scope")
		}
		selected = append(selected, a)
	}
	if strings.TrimSpace(req.Options.TemplateVersion) == "" {
		workers, _ := s.ListWorkers(ctx)
		for _, w := range workers {
			if w.Online && w.TemplateVersion != "" {
				req.Options.TemplateVersion = w.TemplateVersion
				break
			}
		}
		if req.Options.TemplateVersion == "" && s.scanner != nil && s.scanner.Version() != "" {
			req.Options.TemplateVersion = s.scanner.Version()
		}
		if req.Options.TemplateVersion == "" {
			req.Options.TemplateVersion = "v1"
		}
	}
	plans, err := domain.BuildTaskPlans(selected, req.Options)
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
			if task.Status == domain.TaskPending {
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

func (s *Service) ListScans(ctx context.Context, user string) ([]domain.Scan, error) {
	return s.store.ListScans(ctx, user)
}
func (s *Service) GetScan(ctx context.Context, id int64, user string) (*domain.ScanDetail, error) {
	return s.store.GetScan(ctx, id, user)
}
func (s *Service) CancelScan(ctx context.Context, id int64, user string) (bool, error) {
	return s.store.CancelScan(ctx, id, user)
}
func (s *Service) ListFindings(ctx context.Context, id int64, user string) ([]domain.Finding, error) {
	findings, err := s.store.ListFindings(ctx, id, user)
	if err != nil {
		return nil, err
	}
	return domain.DeduplicateFindings(findings), nil
}
func (s *Service) GetTask(ctx context.Context, id int64, user string) (*domain.TaskDetail, error) {
	detail, err := s.store.GetTask(ctx, id, user)
	if err != nil {
		return nil, err
	}
	if detail.Result != nil {
		detail.Result.Findings = domain.DeduplicateFindings(detail.Result.Findings)
	}
	detail.Unregistered = make([]domain.AssetService, 0)
	if detail.Result != nil {
		detail.Unregistered, err = domain.FindUnregistered(detail.Task.Plan.Asset, *detail.Result)
		if err != nil {
			return nil, err
		}
	}
	return detail, nil
}

// ProcessTask 由 worker 消费队列后调用：开始任务、扫描，再保存结果。
func (s *Service) ProcessTask(ctx context.Context, taskID int64, worker WorkerStatus) error {
	task, err := s.store.StartTask(ctx, taskID, worker)
	if err != nil || task == nil {
		return err
	}
	if task.ExecutionDeadline == nil {
		return errors.New("running task has no execution deadline")
	}
	scanCtx, cancel := context.WithDeadline(ctx, *task.ExecutionDeadline)
	stopWatch := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-scanCtx.Done():
				stopWatch <- nil
				return
			case <-ticker.C:
				cancelled, err := s.store.taskCancelled(scanCtx, taskID)
				if scanCtx.Err() != nil {
					stopWatch <- nil
					return
				}
				if err != nil || cancelled {
					if cancelled { err = domain.ErrTaskCancelled }
					cancel()
					stopWatch <- err
					return
				}
			}
		}
	}()
	result, scanErr := s.scanner.Scan(scanCtx, task.Plan)
	if scanErr == nil {
		scanErr = scanCtx.Err()
	}
	cancel()
	if err := <-stopWatch; err != nil {
		if errors.Is(err, domain.ErrTaskCancelled) { return nil }
		return err
	}
	return s.SaveResult(ctx, *task, result, scanErr)
}

// SaveResult 编排结果文件和数据库写入；store 只处理数据库事务。
func (s *Service) SaveResult(ctx context.Context, task domain.Task, result domain.TaskResult, scanErr error) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.cfg.ResultRoot, strconv.FormatInt(task.ID, 10)+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write DAST result file: %w", err)
	}
	err = s.store.SaveResult(ctx, task, result, scanErr)
	// 取消或回收先完成时，丢弃迟到结果，worker 继续处理其他任务。
	if errors.Is(err, domain.ErrTaskCancelled) || errors.Is(err, domain.ErrTaskExpired) {
		return os.Remove(path)
	}
	return err
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
