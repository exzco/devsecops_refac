package sast

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"errors"
	"log"

	"strings"
)

type ScanStatus string

const (
	ScanPending ScanStatus = "pending"
	ScanRunning ScanStatus = "running"
	ScanSuccess ScanStatus = "success"
	ScanFailed  ScanStatus = "failed"
)

type Scan struct {
	WorkerID string
	ID        uint64
	RepoURL   string
	Status    ScanStatus
	Error     string
	CreatedAt time.Time
	UpdatedAt time.Time
	Language   string
	Timeout    time.Duration
	ReportPath string
	CommitSHA  string
}

type SASTScanner struct {
	CodeQLPath string
	WorkRoot   string
	QuerySuite string
}

func NewSASTScanner(cfg SASTScanner) *SASTScanner {
	return &SASTScanner{CodeQLPath: cfg.CodeQLPath, WorkRoot: cfg.WorkRoot, QuerySuite: cfg.QuerySuite}
}
func selectL(language string,querySuite string) (string, string, string, error){
	var codeqlLanguage, buildMode string

	switch strings.ToLower(strings.TrimSpace(language)) {
	case "java", "kotlin", "java-kotlin":
		codeqlLanguage = "java"
		buildMode = "autobuild"

	case "go", "golang":
		codeqlLanguage = "go"
		buildMode = "autobuild"

	case "python":
		codeqlLanguage = "python"
		buildMode = "none"

	case "javascript", "typescript", "javascript-typescript":
		codeqlLanguage = "javascript"
		buildMode = "none"

	default:
		return "","","", fmt.Errorf("unsupported language: %q", language)
	}

	switch querySuite {
	case "code-scanning", "security-extended":
		// 支持的默认规则档位。
	default:
		return "","","", fmt.Errorf("unsupported query suite: %q", querySuite)
	}

	QuerySuite := fmt.Sprintf(
		"codeql/%s-queries:codeql-suites/%s-%s.qls",
		codeqlLanguage,
		codeqlLanguage,
		querySuite,
	)
	return codeqlLanguage, buildMode, QuerySuite,nil
}
func (s *SASTScanner) Scan(ctx context.Context, repoURL string, language string, timeout time.Duration) (*ScanResult, error) {
	repoURL = strings.TrimSpace(repoURL);
	ctx, cancel := context.WithTimeout(ctx, timeout);
	defer cancel();

	if err := ctx.Err(); err != nil {
		return nil, err 
	}

	workRoot, err := filepath.Abs(s.WorkRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve work root: %w", err)
	}

	taskDir, err := os.MkdirTemp(workRoot, "scan-")
	if err != nil {
		return nil, fmt.Errorf("create scan workspace: %w",err)
	}

	sourceDir := filepath.Join(taskDir,"src")
	dbDir := filepath.Join(taskDir, "db")
	reportPath := filepath.Join(taskDir, "results.sarif")

	completed := false
	defer func() {
		paths := []string{taskDir}
		if completed {
			paths = []string{sourceDir,dbDir}
		}
		for _, path := range paths {
			if err := os.RemoveAll(path); err != nil {
				log.Printf("cleanup scan path %s: %v",path,err)
			}
		}
	}()

	cmd := exec.CommandContext(ctx,"git", "clone", "--depth=1", "--", repoURL, sourceDir,)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("clone repository: %w\n%s",errors.Join(err, ctx.Err()), output,)
	}

	cmd = exec.CommandContext(ctx,"git", "-C", sourceDir, "rev-parse", "--verify", "HEAD",)
	cmd.WaitDelay = 5 * time.Second
	output, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read repository commit: %w",errors.Join(err, ctx.Err()))
	}
	commitSHA := strings.TrimSpace(string(output))

	codeqlLanguage, buildMode, querySuite,err := selectL(language,s.QuerySuite)
	if err != nil {
		return nil, fmt.Errorf("select querysuite error:%w",err)
	}
	cmd = exec.CommandContext(ctx, s.CodeQLPath,"database", "create",
	"--language="+codeqlLanguage,
	"--build-mode="+buildMode,
	"--source-root="+sourceDir,
	"--", dbDir,)
	cmd.WaitDelay = 5 * time.Second
	output, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("create codeql database: %w\n%s",errors.Join(err, ctx.Err()), output,)
	}

	cmd = exec.CommandContext(ctx, s.CodeQLPath,
		"database", "analyze",
		"--sarif-add-snippets",
		"--format=sarifv2.1.0",
		"--output="+reportPath,
		"--", dbDir, querySuite,
	)
	cmd.WaitDelay = 5 * time.Second
	output, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("analyze codeql database: %w\n%s",errors.Join(err, ctx.Err()), output,)
	}

	report, err := os.Stat(reportPath)
	if err != nil {
		return nil, fmt.Errorf("check scan report: %w", err)
	}
	if !report.Mode().IsRegular() || report.Size() == 0 {
		return nil, errors.New("scan report is missing or empty")
	}
	completed = true
	return &ScanResult{ReportPath: reportPath,CommitSHA: commitSHA,}, nil
}


type ScanResult struct {
	ReportPath string
	CommitSHA  string
}
