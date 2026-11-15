package dast

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 只负责持久化与原子状态迁移；不在数据库事务中执行扫描或外部请求。
type Store struct{ db *pgxpool.Pool }

func NewStore(db *pgxpool.Pool) (*Store, error) {
	if db == nil {
		return nil, errors.New("DAST database pool is required")
	}
	return &Store{db: db}, nil
}

const scanColumns = `s.id, s.created_by, s.created_at,
    count(t.id), count(t.id) FILTER (WHERE t.status IN ('success','failed')),
    count(t.id) FILTER (WHERE t.status = 'failed'),
    CASE WHEN count(t.id) FILTER (WHERE t.status IN ('pending','running')) > 0
         THEN CASE WHEN min(t.started_at) IS NULL THEN 'pending' ELSE 'running' END
         WHEN count(t.id) FILTER (WHERE t.status = 'failed') > 0 THEN 'failed' ELSE 'success' END,
    min(t.started_at),
    CASE WHEN count(t.id) FILTER (WHERE t.status IN ('pending','running')) = 0 THEN max(t.finished_at) END`

const taskColumns = `t.id,t.scan_id,t.plan,t.status,COALESCE(t.worker_id,''),
    t.execution_deadline,t.created_at,t.started_at,t.finished_at,t.error`

func readScan(row pgx.Row) (*Scan, error) {
	var s Scan
	if err := row.Scan(&s.ID, &s.CreatedBy, &s.CreatedAt, &s.TotalTasks, &s.FinishedTasks,
		&s.FailedTasks, &s.Status, &s.StartedAt, &s.FinishedAt); err != nil {
		return nil, err
	}
	return &s, nil
}

func readTask(row pgx.Row, extra ...any) (*Task, error) {
	var t Task
	var plan []byte
	fields := []any{&t.ID, &t.ScanID, &plan, &t.Status, &t.WorkerID,
		&t.ExecutionDeadline, &t.CreatedAt, &t.StartedAt, &t.FinishedAt, &t.Error}
	if err := row.Scan(append(fields, extra...)...); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(plan, &t.Plan); err != nil {
		return nil, fmt.Errorf("decode task plan: %w", err)
	}
	return &t, nil
}

// CreateScan 存储批次与任务列表；相同请求键的重复请求返回已有批次。
func (s *Store) CreateScan(ctx context.Context, createdBy string, req CreateScanRequest, plans []TaskPlan, queueTimeout time.Duration) (*Scan, error) {
	if createdBy == "" || req.RequestKey == "" || len(plans) == 0 || queueTimeout <= 0 {
		return nil, errors.New("creator, request key, task plans and positive queue timeout are required")
	}
	request, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode create request: %w", err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO dast_scans(created_by,request_key,request,queue_expires_at)
        VALUES ($1,$2,$3,clock_timestamp()+$4::double precision*interval '1 second')
        ON CONFLICT (created_by,request_key) DO NOTHING RETURNING id`, createdBy, req.RequestKey, request, queueTimeout.Seconds()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// 请求键已存在：同样的请求返回原批次，不同的请求直接失败。
		var same bool
		if err = tx.QueryRow(ctx, `SELECT id, request=$3::jsonb FROM dast_scans WHERE created_by=$1 AND request_key=$2`, createdBy, req.RequestKey, request).Scan(&id, &same); err != nil {
			return nil, err
		}
		if !same {
			return nil, errors.New("request key is already used for a different request")
		}
	} else if err != nil {
		return nil, fmt.Errorf("create DAST scan: %w", err)
	} else {
		for _, plan := range plans {
			raw, encodeErr := json.Marshal(plan)
			if encodeErr != nil {
				return nil, encodeErr
			}
			if _, err = tx.Exec(ctx, `INSERT INTO dast_tasks(scan_id,plan,status) VALUES($1,$2,'pending')`, id, raw); err != nil {
				return nil, fmt.Errorf("create DAST task: %w", err)
			}
		}
	}
	scan, err := readScan(tx.QueryRow(ctx, `SELECT `+scanColumns+` FROM dast_scans s LEFT JOIN dast_tasks t ON t.scan_id=s.id WHERE s.id=$1 GROUP BY s.id`, id))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return scan, nil
}

// ListScans 读取批次列表。
func (s *Store) ListScans(ctx context.Context, createdBy string) ([]Scan, error) {
	rows, err := s.db.Query(ctx, `SELECT `+scanColumns+` FROM dast_scans s LEFT JOIN dast_tasks t ON t.scan_id=s.id
        WHERE s.created_by=$1 GROUP BY s.id ORDER BY s.id DESC`, createdBy)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scans := make([]Scan, 0)
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.ID, &s.CreatedBy, &s.CreatedAt, &s.TotalTasks, &s.FinishedTasks,
			&s.FailedTasks, &s.Status, &s.StartedAt, &s.FinishedAt); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

// GetScan 读取批次及其任务列表。
func (s *Store) GetScan(ctx context.Context, id int64, createdBy string) (*ScanDetail, error) {
	scan, err := s.scanByID(ctx, id, createdBy)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT `+taskColumns+` FROM dast_tasks t WHERE t.scan_id=$1 ORDER BY t.id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	detail := &ScanDetail{Scan: *scan, Tasks: make([]Task, 0)}
	for rows.Next() {
		task, err := readTask(rows)
		if err != nil {
			return nil, err
		}
		detail.Tasks = append(detail.Tasks, *task)
	}
	return detail, rows.Err()
}

func (s *Store) scanByID(ctx context.Context, id int64, createdBy string) (*Scan, error) {
	scan, err := readScan(s.db.QueryRow(ctx, `SELECT `+scanColumns+` FROM dast_scans s LEFT JOIN dast_tasks t ON t.scan_id=s.id WHERE s.id=$1 AND s.created_by=$2 GROUP BY s.id`, id, createdBy))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("scan not found")
	}
	return scan, err
}

// GetTask 读取任务、扫描结果和漏洞。
func (s *Store) GetTask(ctx context.Context, id int64, createdBy string) (*TaskDetail, error) {
	var raw []byte
	task, err := readTask(s.db.QueryRow(ctx, `SELECT `+taskColumns+`,t.result FROM dast_tasks t JOIN dast_scans s ON s.id=t.scan_id WHERE t.id=$1 AND s.created_by=$2`, id, createdBy), &raw)
	if err != nil {
		return nil, err
	}
	detail := &TaskDetail{Task: *task}
	if raw == nil {
		return detail, nil
	}
	var result TaskResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT id,task_id,$2::bigint,data FROM dast_findings WHERE task_id=$1 ORDER BY ordinal`, id, task.ScanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result.Findings = make([]Finding, 0)
	for rows.Next() {
		finding, err := readFinding(rows)
		if err != nil {
			return nil, err
		}
		result.Findings = append(result.Findings, *finding)
	}
	detail.Result = &result
	return detail, rows.Err()
}

// ListFindings 读取批次下的漏洞列表。
func (s *Store) ListFindings(ctx context.Context, scanID int64, createdBy string) ([]Finding, error) {
	if _, err := s.scanByID(ctx, scanID, createdBy); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT f.id,f.task_id,t.scan_id,f.data FROM dast_findings f JOIN dast_tasks t ON t.id=f.task_id
        WHERE t.scan_id=$1 ORDER BY f.id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	findings := make([]Finding, 0)
	for rows.Next() {
		f, err := readFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, *f)
	}
	return findings, rows.Err()
}

func readFinding(row pgx.Row) (*Finding, error) {
	var id, taskID, scanID int64
	var data []byte
	if err := row.Scan(&id, &taskID, &scanID, &data); err != nil {
		return nil, err
	}
	var finding Finding
	if err := json.Unmarshal(data, &finding); err != nil {
		return nil, err
	}
	finding.ID = id
	finding.TaskID = taskID
	finding.ScanID = scanID
	return &finding, nil
}

// StartTask 是一次原子状态更新；重复投递或已过期的任务不会再次执行。
func (s *Store) StartTask(ctx context.Context, id int64, worker WorkerStatus) (*Task, error) {
	task, err := readTask(s.db.QueryRow(ctx, `UPDATE dast_tasks t SET status='running',worker_id=$2,
        started_at=clock_timestamp(),
        execution_deadline=clock_timestamp()+(plan->'options'->>'timeout_seconds')::double precision*interval '1 second'
        FROM dast_scans s WHERE t.id=$1 AND t.scan_id=s.id AND t.status='pending'
        AND s.queue_expires_at>clock_timestamp()
        AND t.plan->'asset'->>'cluster_id'=$3 AND t.plan->'asset'->>'network_zone'=$4
        AND t.plan->'options'->>'template_version'=$5
        RETURNING `+taskColumns, id, worker.InstanceID, worker.ClusterID, worker.NetworkZone, worker.TemplateVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return task, err
}

// SaveResult 将任务状态、观察结果和漏洞放在同一个数据库事务中。
func (s *Store) SaveResult(ctx context.Context, task Task, result TaskResult) error {
	findings := result.Findings
	result.Findings = nil // 漏洞单独保存，供批次漏洞列表查询。
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	updated, err := tx.Exec(ctx, `UPDATE dast_tasks SET status=$2,error=$3,finished_at=clock_timestamp(),result=$4
        WHERE id=$1 AND status='running' AND worker_id=$5
        AND execution_deadline+$6::double precision*interval '1 second'>clock_timestamp()`,
		task.ID, task.Status, task.Error, data, task.WorkerID, saveWindow.Seconds())
	if err != nil {
		return err
	}
	if updated.RowsAffected() != 1 {
		return errors.New("task is no longer running for this worker or its save deadline has expired")
	}
	for i, finding := range findings {
		finding.ID, finding.ScanID, finding.TaskID = 0, 0, 0
		raw, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO dast_findings(task_id,ordinal,data) VALUES($1,$2,$3)`, task.ID, i, raw); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ExpireTasks 结束无人消费的任务以及 worker 中断后未保存结果的任务。
func (s *Store) ExpireTasks(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `UPDATE dast_tasks t SET status='failed',finished_at=clock_timestamp(),
        error=CASE WHEN t.status='pending' THEN 'queue_deadline_exceeded' ELSE 'result_deadline_exceeded' END
        FROM dast_scans s WHERE s.id=t.scan_id AND
        ((t.status='pending' AND s.queue_expires_at<=clock_timestamp()) OR
         (t.status='running' AND t.execution_deadline+$1::double precision*interval '1 second'<=clock_timestamp()))`, saveWindow.Seconds())
	return err
}
