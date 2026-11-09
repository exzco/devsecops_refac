package sast

import (
	"context"
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

func (s *Store) SaveSastResult(c context.Context, scanID uint64, result *ScanResult) (string,error) {
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
		return "",err
	}
	if tag.RowsAffected() != 1 {
		return "",fmt.Errorf("scan %d not found", scanID)
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
