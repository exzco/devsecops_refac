package domain

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

type HTTPEvidence struct {
	Request         string   `json:"request,omitempty"`
	Response        string   `json:"response,omitempty"`
	ExtractedValues []string `json:"extracted_values,omitempty"`
}

type Finding struct {
	ID          int64         `json:"id,string,omitempty"`
	ScanID      int64         `json:"scan_id,string,omitempty"`
	TaskID      int64         `json:"task_id,string,omitempty"`
	MatcherName string        `json:"matcher_name"`
	TemplateID  string        `json:"template_id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    Severity      `json:"severity"`
	Endpoint    Endpoint      `json:"endpoint"`
	TargetURL   string        `json:"target_url,omitempty"`
	MatchedAt   string        `json:"matched_at"`
	CWEs        []string      `json:"cwes"`
	CVEs        []string      `json:"cves"`
	References  []string      `json:"references"`
	Evidence    *HTTPEvidence `json:"evidence,omitempty"`
}

type TaskResult struct {
	ResolvedIPs    []string          `json:"resolved_ips"`
	Ports          []PortObservation `json:"ports"`
	Coverage       []CoverageIssue   `json:"coverage"`
	Services       []AssetService    `json:"services"`
	Findings       []Finding         `json:"findings"`
	ExecutedChecks *int              `json:"executed_checks"` // null 表示引擎未提供可靠统计。
	FailedChecks   *int              `json:"failed_checks"`
}

type PortObservation struct {
	Endpoint   Endpoint  `json:"endpoint"`
	State      string    `json:"state"`
	Reason     string    `json:"reason,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type CoverageIssue struct {
	Endpoint   Endpoint `json:"endpoint"`
	TemplateID string   `json:"template_id,omitempty"`
	Reason     string   `json:"reason"`
}

// DeduplicateFindings 按 (端点, 模板ID/标题) 幂等合并漏洞条目，汇聚不同匹配器名称与有效回放证据。
func DeduplicateFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}
	seen := make(map[string]int, len(findings))
	unique := make([]Finding, 0, len(findings))
	for _, f := range findings {
		key := fmt.Sprintf("%s:%d/%s|%s", f.Endpoint.Host, f.Endpoint.Port, f.Endpoint.Transport, f.TemplateID)
		if f.TemplateID == "" {
			key = fmt.Sprintf("%s:%d/%s|%s", f.Endpoint.Host, f.Endpoint.Port, f.Endpoint.Transport, f.Title)
		}
		if existingIdx, exists := seen[key]; exists {
			if unique[existingIdx].Evidence == nil && f.Evidence != nil {
				unique[existingIdx].Evidence = f.Evidence
			}
			if f.MatcherName != "" && !strings.Contains(unique[existingIdx].MatcherName, f.MatcherName) {
				if unique[existingIdx].MatcherName == "" {
					unique[existingIdx].MatcherName = f.MatcherName
				} else {
					unique[existingIdx].MatcherName += ", " + f.MatcherName
				}
			}
			if len(f.CVEs) > 0 {
				cveSet := make(map[string]struct{}, len(unique[existingIdx].CVEs)+len(f.CVEs))
				for _, c := range unique[existingIdx].CVEs {
					cveSet[c] = struct{}{}
				}
				for _, c := range f.CVEs {
					if _, ok := cveSet[c]; !ok {
						cveSet[c] = struct{}{}
						unique[existingIdx].CVEs = append(unique[existingIdx].CVEs, c)
					}
				}
			}
			if len(f.CWEs) > 0 {
				cweSet := make(map[string]struct{}, len(unique[existingIdx].CWEs)+len(f.CWEs))
				for _, c := range unique[existingIdx].CWEs {
					cweSet[c] = struct{}{}
				}
				for _, c := range f.CWEs {
					if _, ok := cweSet[c]; !ok {
						cweSet[c] = struct{}{}
						unique[existingIdx].CWEs = append(unique[existingIdx].CWEs, c)
					}
				}
			}
			continue
		}
		seen[key] = len(unique)
		unique = append(unique, f)
	}
	return unique
}

// FindUnregistered 按本次解析的 IP、端口和传输协议比较登记服务与扫描结果。
func FindUnregistered(asset Asset, result TaskResult) ([]AssetService, error) {
	known := make(map[Endpoint]struct{})
	for _, value := range result.ResolvedIPs {
		ip, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("resolved IP: %w", err)
		}
		for _, service := range asset.RegisteredServices {
			endpoint := service.Endpoint
			endpoint.Host = ip.Unmap().String()
			endpoint, err = NormalizeEndpoint(endpoint)
			if err != nil {
				return nil, fmt.Errorf("registered service: %w", err)
			}
			known[endpoint] = struct{}{}
		}
	}
	unregistered := make([]AssetService, 0)
	for _, service := range result.Services {
		endpoint, err := NormalizeEndpoint(service.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("discovered service: %w", err)
		}
		if service.ObservedAt.IsZero() {
			service.ObservedAt = time.Now().UTC()
		}
		if _, exists := known[endpoint]; exists {
			continue
		}
		known[endpoint] = struct{}{}
		unregistered = append(unregistered, service)
	}
	return unregistered, nil
}

