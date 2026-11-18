package sast

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
func selectL(language string) (string, string, error){
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
		return "","", fmt.Errorf("unsupported language: %q", language)
	}

	return codeqlLanguage, buildMode, nil
}
func (s *SASTScanner) queries(ctx context.Context, dir, language string, p Policy) ([]string, error) {
	switch p.Active {
	case "code-scanning", "security-extended":
		return []string{fmt.Sprintf("codeql/%s-queries:codeql-suites/%s-%s.qls", language, language, p.Active)}, nil
	}
	selected := map[string]bool{}
	for _, suite := range p.Suites {
		if suite.ID == p.Active {
			for _, id := range suite.Rules { selected[id] = true }
		}
	}
	if err := os.Mkdir(dir, 0700); err != nil { return nil, err }
	var paths []string
	for i, rule := range p.Rules {
		if !selected[rule.ID] || language != rule.Language { continue }
		path := filepath.Join(dir, fmt.Sprintf("rule-%d.ql", i))
		if err := os.WriteFile(path, []byte(rule.Code), 0600); err != nil { return nil, err }
		paths = append(paths, path)
	}
	if len(paths) == 0 { return nil, fmt.Errorf("当前套件没有 %s 规则", language) }
	manifest := fmt.Sprintf("name: devsecops/custom-%s\nversion: 0.0.1\ndependencies:\n  codeql/%s-all: '*'\n", language, language)
	if err := os.WriteFile(filepath.Join(dir, "qlpack.yml"), []byte(manifest), 0600); err != nil { return nil, err }
	cmd := exec.CommandContext(ctx, s.CodeQLPath, "pack", "install", dir)
	if out, err := cmd.CombinedOutput(); err != nil { return nil, fmt.Errorf("resolve CodeQL dependencies: %w: %s", err, out) }
	return paths, nil
}
func unzipSource(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip archive: %w", err)
	}
	defer r.Close()

	destClean := filepath.Clean(destDir)
	for _, f := range r.File {
		targetPath := filepath.Join(destClean, f.Name)
		cleanTarget := filepath.Clean(targetPath)
		if !strings.HasPrefix(cleanTarget, destClean+string(filepath.Separator)) && cleanTarget != destClean {
			return fmt.Errorf("illegal file path in zip: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}
		outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}
		_, err = io.Copy(outFile, rc)
		rc.Close()
		closeErr := outFile.Close()
		if err != nil || closeErr != nil {
			return errors.Join(err, closeErr)
		}
	}
	return nil
}

func computeFileSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:12], nil
}

func (s *SASTScanner) Scan(ctx context.Context, repoURL string, language string, timeout time.Duration, policy Policy) (*ScanResult, error) {
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
			paths = []string{sourceDir,dbDir,filepath.Join(taskDir, "queries")}
		}
		for _, path := range paths {
			if err := os.RemoveAll(path); err != nil {
				log.Printf("cleanup scan path %s: %v",path,err)
			}
		}
	}()

	if err := unzipSource(repoURL, sourceDir); err != nil {
		return nil, fmt.Errorf("extract source zip: %w", err)
	}

	commitSHA, err := computeFileSHA256(repoURL)
	if err != nil {
		commitSHA = "zip-" + time.Now().Format("20060102150405")
	}

	codeqlLanguage, buildMode, err := selectL(language)
	if err != nil {
		return nil, fmt.Errorf("select querysuite error:%w",err)
	}
	queries, err := s.queries(ctx, filepath.Join(taskDir, "queries"), codeqlLanguage, policy)
	if err != nil { return nil, err }
	cmd := exec.CommandContext(ctx, s.CodeQLPath,"database", "create",
	"--language="+codeqlLanguage,
	"--build-mode="+buildMode,
	"--source-root="+sourceDir,
	"--", dbDir,)
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("create codeql database: %w\n%s",errors.Join(err, ctx.Err()), output,)
	}

	args := []string{
		"database", "analyze",
		"--sarif-add-snippets",
		"--format=sarifv2.1.0",
		"--output="+reportPath,
		"--", dbDir,
	}
	cmd = exec.CommandContext(ctx, s.CodeQLPath, append(args, queries...)...)
	cmd.WaitDelay = 5 * time.Second
	output, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("analyze codeql database: %w\n%s",errors.Join(err, ctx.Err()), output,)
	}

	completed = true
	return &ScanResult{ReportPath: reportPath,CommitSHA: commitSHA,}, nil
}


type ScanResult struct {
	ReportPath string
	CommitSHA  string
}
