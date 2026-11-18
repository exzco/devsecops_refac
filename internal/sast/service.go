package sast

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

func (s *Service) CreateScanWithZip(c context.Context, filename string, zipReader io.Reader, language string, timeout time.Duration) (*Scan, error) {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		filename = "source.zip"
	}

	scan := &Scan{
		RepoURL:  filename,
		Status:   ScanPending,
		Language: language,
		Timeout:  timeout,
	}

	if err := s.store.Create(c, scan); err != nil {
		return nil, fmt.Errorf("service create scan error: %w", err)
	}

	uploadDir := filepath.Join(s.scanner.WorkRoot, "uploads")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return nil, fmt.Errorf("create uploads dir: %w", err)
	}

	zipFilePath := filepath.Join(uploadDir, fmt.Sprintf("%d.zip", scan.ID))
	dst, err := os.Create(zipFilePath)
	if err != nil {
		return nil, fmt.Errorf("create zip file on disk: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, zipReader); err != nil {
		return nil, fmt.Errorf("write uploaded zip: %w", err)
	}

	if err := s.queue.Push(c, scan.ID); err != nil {
		return nil, fmt.Errorf("service push scan error: %w", err)
	}

	return scan, nil
}

func (s *Service) ProcessScan(c context.Context, scanID uint64, workerID string) (err error) {
	scan, err := s.store.GetByID(c, scanID)
	if err != nil {
		return fmt.Errorf("get scan from id error: %w", err)
	}

	if err := s.store.ClaimScan(c, scanID, workerID); err != nil {
		return err
	}

	defer func() {
		if err == nil {
			return
		}
		failureCtx, cancel := context.WithTimeout(context.WithoutCancel(c), 5*time.Second)
		defer cancel()
		updateErr := s.store.UpdateScanStatus(failureCtx, scan.ID, ScanFailed, err.Error())
		if updateErr != nil {
			err = errors.Join(
				err,
				fmt.Errorf("save failed status: %w", updateErr),
			)
		}
	}()

	zipFilePath := filepath.Join(s.scanner.WorkRoot, "uploads", fmt.Sprintf("%d.zip", scanID))
	if _, err := os.Stat(zipFilePath); err != nil {
		if _, err2 := os.Stat(scan.RepoURL); err2 == nil {
			zipFilePath = scan.RepoURL
		} else {
			return fmt.Errorf("source zip archive not found at %s: %w", zipFilePath, err)
		}
	}

	policy, _, err := s.store.policy(c)
	if err != nil { return fmt.Errorf("load scan policy: %w", err) }
	result, err := s.scanner.Scan(c, zipFilePath, scan.Language, scan.Timeout, policy)
	if err != nil {
		return fmt.Errorf("scan %d: %w", scan.ID, err)
	}

	file, err := os.Open(result.ReportPath)
	if err != nil {
		return fmt.Errorf("open SARIF report: %w", err)
	}
	findings, parseErr := ParseSARIF(file)
	closeErr := file.Close()
	if parseErr != nil || closeErr != nil {
		return fmt.Errorf("read SARIF report: %w", errors.Join(parseErr, closeErr))
	}
	return s.store.CompleteScan(c, scanID, result, findings)
}

func (s *Service) ListScans(ctx context.Context) ([]Scan, error) {
	return s.store.ListScans(ctx)
}

func (s *Service) GetScan(ctx context.Context, scanID uint64) (*Scan, error) {
	scan, err := s.store.GetByID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("get scan %d: %w", scanID, err)
	}
	return scan, nil
}

func (s *Service) GetScanFindings(ctx context.Context, scanID uint64) ([]Finding, error) {
	findings, err := s.store.ListFindings(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("get scan %d findings: %w", scanID, err)
	}
	return findings, nil
}

func (s *Service) DeleteScanFindings(ctx context.Context, scanID uint64) error {
	if err := s.store.DeleteFindings(ctx, scanID); err != nil {
		return fmt.Errorf("delete scan %d findings: %w", scanID, err)
	}

	return nil
}

func (s *Service) DeleteScan(ctx context.Context, scanID uint64) error {
	return s.store.DeleteScan(ctx, scanID)
}

type WorkerEnv struct {
	WorkerID   string `json:"worker_id"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	PID        int    `json:"pid"`
	NumCPU     int    `json:"num_cpu"`
	CodeQLPath string `json:"codeql_path"`
	CodeQLOk   bool   `json:"codeql_ok"`
	WorkRoot   string `json:"work_root"`
}

func (s *Service) DetectEnvironment(workerID string) (*WorkerEnv, error) {
	hostname, _ := os.Hostname()
	codeqlOk := false
	codeqlPath := s.scanner.CodeQLPath
	workRoot := s.scanner.WorkRoot
	
	if codeqlPath != "" {
		if _, err := os.Stat(codeqlPath); err == nil {
			codeqlOk = true
		}
	}
	
	return &WorkerEnv{
		WorkerID:   workerID,
		Hostname:   hostname,
		OS:         runtime.GOOS,
		Arch:       fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH),
		PID:        os.Getpid(),
		NumCPU:     runtime.NumCPU(),
		CodeQLPath: codeqlPath,
		CodeQLOk:   codeqlOk,
		WorkRoot:   workRoot,
	}, nil
}
