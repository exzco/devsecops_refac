package sast

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Service struct {
	store   *Store
	queue   *Queue
	scanner *SASTScanner
}

func NewService(store *Store, queue *Queue, scanner *SASTScanner) *Service {
	return &Service{
		store:   store,
		queue:   queue,
		scanner: scanner,
	}
}

func (s *Service) CreateScan(c context.Context, repoURL string, language string, timeout time.Duration) (*Scan, error) {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return nil, errors.New("repo_url is required")
	}

	scan := &Scan{
		RepoURL:  repoURL,
		Status:   ScanPending,
		Language: language,
		Timeout:  timeout,
	}

	if err := s.store.Create(c, scan); err != nil {
		return nil, fmt.Errorf("service create scan error: %w", err)
	}

	if err := s.queue.Push(c, scan.ID); err != nil {
		return nil, fmt.Errorf("service push scan error: %w", err)
	}

	return scan, nil
}

func (s *Service) ProcessScan(c context.Context, scanID uint64, workerID string) error {
	scan, err := s.store.GetByID(c, scanID)
	if err != nil {
		return fmt.Errorf("get scan from id error: %w", err)
	}
	
	if err := s.store.ClaimScan(c, scanID, workerID); err != nil {
		return err
	}

	result, err := s.scanner.Scan(c, scan.RepoURL, scan.Language, scan.Timeout)
	if err != nil {
		failureCtx, cancel := context.WithTimeout(context.WithoutCancel(c), 5*time.Second)
		defer cancel()
		updateErr := s.store.UpdateScanStatus(failureCtx, scan.ID, ScanFailed, err.Error())
		if updateErr != nil {
			return errors.Join(
				fmt.Errorf("scan %d: %w", scan.ID, err),
				fmt.Errorf("save failed status: %w", updateErr),
			)
		}
		return fmt.Errorf("scan %d: %w", scan.ID, err)
	}

	if err := s.store.SaveSastResult(c, scanID, result); err != nil {
		return fmt.Errorf("save sast result: %w", err)
	}
	return nil
}
