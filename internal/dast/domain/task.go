package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type ScanStatus string

const (
	ScanPending ScanStatus = "pending"
	ScanRunning ScanStatus = "running"
	ScanSuccess ScanStatus = "success"
	ScanFailed  ScanStatus = "failed"
	ScanCancelled ScanStatus = "cancelled"
)

type TaskStatus string

const (
	TaskPending TaskStatus = "pending"
	TaskRunning TaskStatus = "running"
	TaskSuccess TaskStatus = "success"
	TaskFailed  TaskStatus = "failed"
	TaskCancelled TaskStatus = "cancelled"
)

type TaskEvent string

const (
	EventTaskStarted TaskEvent = "started"
	EventTaskSucceeded TaskEvent = "succeeded"
	EventTaskFailed TaskEvent = "failed"
	EventTaskCancelled TaskEvent = "cancelled"
	EventTaskExpired TaskEvent = "expired"
)

type TaskTransition struct {
	From []TaskStatus
	To TaskStatus
}

// 状态转换的来源同时用于 SQL 条件更新，终态没有出边。
var taskTransitions = map[TaskEvent]TaskTransition{
	EventTaskStarted: {From: []TaskStatus{TaskPending}, To: TaskRunning},
	EventTaskSucceeded: {From: []TaskStatus{TaskRunning}, To: TaskSuccess},
	EventTaskFailed: {From: []TaskStatus{TaskRunning}, To: TaskFailed},
	EventTaskCancelled: {From: []TaskStatus{TaskPending, TaskRunning}, To: TaskCancelled},
	EventTaskExpired: {From: []TaskStatus{TaskPending, TaskRunning}, To: TaskFailed},
}

// TransitionFor 返回转换规则的独立副本，调用方不能修改包内状态表。
func TransitionFor(event TaskEvent) (TaskTransition, error) {
	transition, ok := taskTransitions[event]
	if !ok {
		return TaskTransition{}, fmt.Errorf("unknown task event %q", event)
	}
	transition.From = append([]TaskStatus(nil), transition.From...)
	return transition, nil
}

const (
	QueueDeadlineExceeded = "queue_deadline_exceeded"
	ResultDeadlineExceeded = "result_deadline_exceeded"
)

var (
	ErrTaskCancelled = errors.New("task cancelled")
	ErrTaskExpired = errors.New("task expired")
)

type ScanOptions struct {
	TemplateVersion string     `json:"template_version"`
	TemplateIDs     []string   `json:"template_ids"`
	RateLimit       int        `json:"rate_limit"`  // 每个 IP 的 Nmap 发包速率和 Nuclei 请求速率，各阶段每秒上限。
	Concurrency     int        `json:"concurrency"` // 每个 IP 的 PoC 模板并发，不限制 IP 并发数。
	TimeoutSeconds  int        `json:"timeout_seconds"`
	ProbePorts      []PortSpec `json:"probe_ports"`
}

// Scan 是批次，具体执行输入由每个 Task 的 Plan 保存。
type HostTask struct {
	ID     int64      `json:"id,string"`
	Host   string     `json:"host"`
	Status TaskStatus `json:"status"`
}

type Scan struct {
	Hosts         []HostTask `json:"hosts,omitempty"`
	ID            int64      `json:"id,string"`
	CreatedBy     string     `json:"created_by"`
	TotalTasks    int        `json:"total_tasks"`
	FinishedTasks int        `json:"finished_tasks"`
	FailedTasks   int        `json:"failed_tasks"`
	Status        ScanStatus `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

type TaskPlan struct {
	Asset   Asset       `json:"asset"`
	Options ScanOptions `json:"options"`
}

type Task struct {
	ID                int64      `json:"id,string"`
	ScanID            int64      `json:"scan_id,string"`
	Plan              TaskPlan   `json:"plan"`
	Status            TaskStatus `json:"status"`
	WorkerID          string     `json:"worker_id"`
	ExecutionDeadline *time.Time `json:"execution_deadline,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	FinishedAt        *time.Time `json:"finished_at,omitempty"`
	Error             string     `json:"error,omitempty"`
}

type CreateScanRequest struct {
	RequestKey string      `json:"request_key"`
	Assets     []AssetKey  `json:"assets"`
	Filter     AssetFilter `json:"filter"`
	Options    ScanOptions `json:"options"`
}

type TaskDetail struct {
	Task         Task           `json:"task"`
	Result       *TaskResult    `json:"result"`
	Unregistered []AssetService `json:"unregistered"`
}

type ScanDetail struct {
	Scan  Scan   `json:"scan"`
	Tasks []Task `json:"tasks"`
}

func BuildTaskPlans(assets []Asset, options ScanOptions) ([]TaskPlan, error) {
	// 扫描参数校验
	if len(assets) == 0 {
		return nil, fmt.Errorf("assets must not be empty")
	}
	if options.RateLimit <= 0 || options.Concurrency <= 0 || options.TimeoutSeconds <= 0 {
		return nil, fmt.Errorf("rate limit, concurrency and timeout seconds must be positive")
	}
	if strings.TrimSpace(options.TemplateVersion) == "" {
		return nil, fmt.Errorf("template version is required")
	}
	if options.TimeoutSeconds > 86400 {
		return nil, fmt.Errorf("timeout seconds must not exceed 86400")
	}
	if len(options.ProbePorts) == 0 {
		return nil, fmt.Errorf("probe ports must not be empty")
	}
	templates := make(map[string]struct{}, len(options.TemplateIDs))
	for i, id := range options.TemplateIDs {
		if strings.TrimSpace(id) == "" || id != strings.TrimSpace(id) {
			return nil, fmt.Errorf("template ID %d must be nonempty and have no surrounding whitespace", i)
		}
		if _, exists := templates[id]; exists {
			return nil, fmt.Errorf("duplicate template ID: %q", id)
		}
		templates[id] = struct{}{}
	}
	ports := make(map[PortSpec]struct{}, len(options.ProbePorts))
	for i, port := range options.ProbePorts {
		if err := validatePort(port.Port, port.Transport); err != nil {
			return nil, fmt.Errorf("probe port %d: %w", i, err)
		}
		if _, exists := ports[port]; exists {
			return nil, fmt.Errorf("duplicate probe port: %v", port)
		}
		ports[port] = struct{}{}
	}

	seen := make(map[AssetKey]struct{}, len(assets))
	plans := make([]TaskPlan, 0, len(assets))

	for i, asset := range assets {
		asset, err := NormalizeAsset(asset)
		if err != nil {
			return nil, fmt.Errorf("asset %d: %w", i, err)
		}
		if _, exists := seen[asset.AssetKey]; exists {
			return nil, fmt.Errorf("duplicate CMDB ID: %q", asset.CMDBID)
		}

		seen[asset.AssetKey] = struct{}{}
		// 为每个计划复制切片，避免调用方后续修改影响已创建的执行输入。
		asset.RegisteredServices = append([]AssetService(nil), asset.RegisteredServices...)
		planOptions := options
		planOptions.TemplateIDs = append([]string(nil), options.TemplateIDs...)
		planOptions.ProbePorts = append([]PortSpec(nil), options.ProbePorts...)
		plans = append(plans, TaskPlan{Asset: asset, Options: planOptions})
	}
	return plans, nil
}

