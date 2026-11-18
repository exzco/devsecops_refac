package scanner

import (
	"devsecops/internal/dast/domain"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type nucleiEvent struct {
	TemplateID    string   `json:"template-id"`
	MatcherName   string   `json:"matcher-name"`
	MatchedAt     string   `json:"matched-at"`
	IP            string   `json:"ip"`
	Error         string   `json:"error"`
	MatcherStatus *bool    `json:"matcher-status"`
	Request       string   `json:"request"`
	Response      string   `json:"response"`
	Extracted     []string `json:"extracted-results"`
	Info          struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Severity       domain.Severity `json:"severity"`
		References     []string `json:"reference"`
		Classification struct {
			CVEs []string `json:"cve-id"`
			CWEs []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
}

// 固定 IP 作为输入，独立保留 HTTP Host 和 TLS SNI，避免引擎再次解析目标域名。
func nucleiTarget(ctx context.Context, target scanTarget, template Template) (string, []string, error) {
	endpoint := target.service.Endpoint
	input := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
	if template.Protocol == "tcp" || template.Protocol == "ssl" {
		return input, nil, nil
	}
	parsed, err := url.Parse(target.url)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", nil, fmt.Errorf("HTTP template requires a valid HTTP target URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return "", nil, fmt.Errorf("target URL cannot include credentials or fragment")
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber != endpoint.Port {
		return "", nil, fmt.Errorf("HTTP target port does not match endpoint")
	}
	hostname := parsed.Hostname()
	ips, err := resolveHost(ctx, hostname)
	if err != nil {
		return "", nil, err
	}
	matches := false
	for _, ip := range ips {
		if ip == endpoint.Host {
			matches = true
		}
	}
	if !matches {
		return "", nil, fmt.Errorf("URL host %q does not resolve to task endpoint %s", hostname, endpoint.Host)
	}
	args := []string{}
	if _, err := netip.ParseAddr(hostname); err != nil {
		args = append(args, "-H", "Host: "+parsed.Host, "-sni", hostname)
	}
	parsed.Host = input
	return parsed.String(), args, nil
}

func (s *Scanner) runPoC(ctx context.Context, target scanTarget, template Template, options domain.ScanOptions) ([]domain.Finding, int, error) {
	input, binding, err := nucleiTarget(ctx, target, template)
	if err != nil {
		return nil, 0, err
	}
	engineProtocol := template.Protocol
	if engineProtocol == "https" {
		engineProtocol = "http"
	}
	args := []string{"-config", os.DevNull, "-auth=false", "-u", input, "-t", template.Path, "-include-templates", template.Path,
		"-type", engineProtocol, "-jsonl", "-matcher-status", "-silent", "-no-color", "-disable-update-check", "-no-interactsh", "-disable-redirects", "-no-httpx", "-no-stdin",
		"-omit-template", "-rate-limit", strconv.Itoa(options.RateLimit), "-concurrency", strconv.Itoa(options.Concurrency), "-bulk-size", "1", "-retries", "0"}
	args = append(args, binding...)
	output, runErr := runEngine(ctx, s.cfg.NucleiPath, args, maxOutputBytes)
	findings, eventCount, parseErr := parseNucleiOutput(output, target, template)
	return findings, eventCount, errors.Join(runErr, parseErr)
}

// parseNucleiOutput 保留错误前已解析的发现，进程错误由调用方合并。
func parseNucleiOutput(output []byte, target scanTarget, template Template) ([]domain.Finding, int, error) {
	lines := bufio.NewScanner(bytes.NewReader(output))
	lines.Buffer(make([]byte, 4096), maxOutputBytes)
	findings := make([]domain.Finding, 0)
	eventCount := 0
	seen := make(map[string]int)
	for lines.Scan() {
		if len(bytes.TrimSpace(lines.Bytes())) == 0 {
			continue
		}
		var event nucleiEvent
		if err := json.Unmarshal(lines.Bytes(), &event); err != nil {
			return findings, eventCount, fmt.Errorf("parse nuclei JSONL: %w", err)
		}
		if event.Error != "" {
			return findings, eventCount, fmt.Errorf("nuclei execution error: %s", event.Error)
		}
		if event.TemplateID != template.ID || event.MatcherStatus == nil {
			return findings, eventCount, fmt.Errorf("nuclei event lacks expected template identity or matcher status")
		}
		eventCount++
		if !*event.MatcherStatus {
			continue
		}
		if event.Info.Name == "" || event.MatchedAt == "" {
			return findings, eventCount, fmt.Errorf("nuclei finding lacks title or matched location")
		}
		switch event.Info.Severity {
		case domain.SeverityInfo, domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical, domain.SeverityUnknown:
		default:
			return findings, eventCount, fmt.Errorf("unknown nuclei severity %q", event.Info.Severity)
		}
		if event.IP != "" {
			ip, err := netip.ParseAddr(event.IP)
			if err != nil || ip.Unmap().String() != target.service.Endpoint.Host {
				return findings, eventCount, fmt.Errorf("nuclei finding IP is outside task endpoint")
			}
		}
		findingKey := template.ID
		if existingIdx, duplicate := seen[findingKey]; duplicate {
			if findings[existingIdx].Evidence == nil && (event.Request != "" || event.Response != "" || len(event.Extracted) > 0) {
				findings[existingIdx].Evidence = &domain.HTTPEvidence{Request: event.Request, Response: event.Response, ExtractedValues: event.Extracted}
			}
			if event.MatcherName != "" && !strings.Contains(findings[existingIdx].MatcherName, event.MatcherName) {
				if findings[existingIdx].MatcherName == "" {
					findings[existingIdx].MatcherName = event.MatcherName
				} else {
					findings[existingIdx].MatcherName += ", " + event.MatcherName
				}
			}
			continue
		}
		seen[findingKey] = len(findings)
		finding := domain.Finding{TemplateID: template.ID, MatcherName: event.MatcherName, Title: event.Info.Name, Description: event.Info.Description, Severity: event.Info.Severity, Endpoint: target.service.Endpoint, TargetURL: target.url, MatchedAt: event.MatchedAt, CVEs: event.Info.Classification.CVEs, CWEs: event.Info.Classification.CWEs, References: event.Info.References}
		if event.Request != "" || event.Response != "" || len(event.Extracted) > 0 {
			finding.Evidence = &domain.HTTPEvidence{Request: event.Request, Response: event.Response, ExtractedValues: event.Extracted}
		}
		findings = append(findings, finding)
	}
	if err := lines.Err(); err != nil {
		return findings, eventCount, fmt.Errorf("read nuclei JSONL: %w", err)
	}
	return findings, eventCount, nil
}

