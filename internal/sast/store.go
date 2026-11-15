package sast

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

func (s *Store) Create(c context.Context, scan *Scan) error {
	// Store 负责保存记录，队列投递由 Service 完成。
	const query = `
		INSERT INTO sast_scans (
			repo_url,
			status,
			error,
			language,
			timeout
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at, language, timeout
	`
	return s.db.QueryRow(c, query, scan.RepoURL, scan.Status, scan.Error, scan.Language, scan.Timeout).Scan(&scan.ID, &scan.CreatedAt, &scan.UpdatedAt, &scan.Language, &scan.Timeout)
}

func (s *Store) GetByID(c context.Context, scanID uint64) (*Scan, error) {
	const query = `
		SELECT id, repo_url, status, COALESCE(error, ''), created_at, updated_at, language, timeout, report_path, commit_sha, worker_id
		FROM sast_scans
		WHERE id = $1
	`
	scan := &Scan{}

	err := s.db.QueryRow(c, query, scanID).Scan(
		&scan.ID,
		&scan.RepoURL,
		&scan.Status,
		&scan.Error,
		&scan.CreatedAt,
		&scan.UpdatedAt,
		&scan.Language,
		&scan.Timeout,
		&scan.ReportPath,
		&scan.CommitSHA,
		&scan.WorkerID,
	)
	if err != nil {
		return nil, err
	}

	return scan, nil
}

func (s *Store) ListScans(ctx context.Context) ([]Scan, error) {
	const query = `
		SELECT id, repo_url, status, COALESCE(error, ''), created_at, updated_at,
		       language, timeout, report_path, commit_sha, worker_id
		FROM sast_scans
		ORDER BY created_at DESC, id DESC
	`
	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	defer rows.Close()

	scans := make([]Scan, 0)
	for rows.Next() {
		var scan Scan
		if err := rows.Scan(
			&scan.ID, &scan.RepoURL, &scan.Status, &scan.Error,
			&scan.CreatedAt, &scan.UpdatedAt, &scan.Language, &scan.Timeout,
			&scan.ReportPath, &scan.CommitSHA, &scan.WorkerID,
		); err != nil {
			return nil, fmt.Errorf("read scan row: %w", err)
		}
		scans = append(scans, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scans: %w", err)
	}
	return scans, nil
}

func (s *Store) UpdateScanStatus(c context.Context, scanID uint64, status ScanStatus, e string) error {
	const query = `
		UPDATE sast_scans
		SET status = $1, error = $2, updated_at = NOW()
		WHERE id = $3
	`
	result, err := s.db.Exec(c, query, status, e, scanID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("scan %d not found", scanID)
	}

	return nil
}

func (s *Store) SaveSastResult(c context.Context, scanID uint64, result *ScanResult) (string, error) {
	if result == nil {
		return "", fmt.Errorf("scan %d result is required", scanID)
	}
	const query = `
		UPDATE sast_scans
		SET report_path = $1,
		commit_sha = $2,
		status = $3,
		error = '',
		updated_at = NOW()
		WHERE id = $4
	`

	tag, err := s.db.Exec(c, query, result.ReportPath, result.CommitSHA, ScanSuccess, scanID)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", fmt.Errorf("scan %d not found", scanID)
	}

	return result.ReportPath, nil
}

func (s *Store) ClaimScan(ctx context.Context, scanID uint64, workerID string) error {
	const query = `
		UPDATE sast_scans
		SET worker_id = $1,
		    status = $2,
		    error = '',
		    updated_at = NOW()
		WHERE id = $3 AND status = $4
	`

	tag, err := s.db.Exec(ctx, query,
		workerID, ScanRunning, scanID, ScanPending,
	)
	if err != nil {
		return fmt.Errorf("claim scan %d: %w", scanID, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("scan %d does not exist or is not pending", scanID)
	}
	return nil
}

func (s *Store) SaveFindings(ctx context.Context, scanID uint64, findings []Finding) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin save findings transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()

	const query = `
		INSERT INTO sast_findings (scan_id, ordinal, rule_id, title, message, level,
		security_score, cwes, locations, related_locations,code_flows, fingerprints)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		`
	for ordinal, finding := range findings {
		cwes, err := json.Marshal(finding.CWEs)
		if err != nil {
			return err
		}
		locations, err := json.Marshal(finding.Locations)
		if err != nil {
			return err
		}
		related, err := json.Marshal(finding.Related)
		if err != nil {
			return err
		}
		codeFlows, err := json.Marshal(finding.CodeFlows)
		if err != nil {
			return err
		}

		fingerprints, err := json.Marshal(finding.Fingerprints)
		if err != nil {
			return err
		}

		var securityScore any
		if finding.SecurityScore != nil {
			securityScore = *finding.SecurityScore
		}

		_, err = tx.Exec(
			ctx,
			query,
			scanID,
			ordinal,
			finding.RuleID,
			finding.Title,
			finding.Message,
			finding.Level,
			securityScore,
			string(cwes),
			string(locations),
			string(related),
			string(codeFlows),
			string(fingerprints),
		)

		if err != nil {
			return fmt.Errorf("insert finding %d for scan %d: %w", ordinal, scanID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit findings: %w", err)
	}
	return nil
}

func (s *Store) ListFindings(ctx context.Context, scanID uint64) ([]Finding, error) {
	const query = `
		SELECT rule_id, title, message, level, security_score,
		       cwes, locations, related_locations, code_flows, fingerprints
		FROM sast_findings
		WHERE scan_id = $1
		ORDER BY ordinal
	`

	rows, err := s.db.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	findings := make([]Finding, 0)

	for rows.Next() {
		var finding Finding

		err := rows.Scan(
			&finding.RuleID,
			&finding.Title,
			&finding.Message,
			&finding.Level,
			&finding.SecurityScore,
			&finding.CWEs,
			&finding.Locations,
			&finding.Related,
			&finding.CodeFlows,
			&finding.Fingerprints,
		)
		if err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}

		findings = append(findings, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}

	return findings, nil
}

func (s *Store) DeleteFindings(ctx context.Context, scanID uint64) error {
	const query = `DELETE FROM sast_findings WHERE scan_id = $1`
	_, err := s.db.Exec(ctx, query, scanID)
	if err != nil {
		return fmt.Errorf("delete findings for scan %d: %w", scanID, err)
	}
	return nil
}

func (s *Store) DeleteScan(ctx context.Context, scanID uint64) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM sast_findings WHERE scan_id = $1`, scanID); err != nil {
		return fmt.Errorf("delete findings for scan %d: %w", scanID, err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sast_scans WHERE id = $1`, scanID); err != nil {
		return fmt.Errorf("delete scan %d: %w", scanID, err)
	}
	return tx.Commit(ctx)
}
