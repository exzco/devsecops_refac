package dast

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type ScanStatus string

const (
	ScanPending ScanStatus = "pending"
	ScanRunning ScanStatus = "running"
	ScanSuccess ScanStatus = "success"
	ScanFailed  ScanStatus = "failed"
)

type TaskStatus string

const (
	TaskPending TaskStatus = "pending"
	TaskRunning TaskStatus = "running"
	TaskSuccess TaskStatus = "success"
	TaskFailed  TaskStatus = "failed"
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

type PortSpec struct {
	Port      int       `json:"port"`
	Transport Transport `json:"transport"`
}

type DASTScannerConfig struct {
	NmapPath     string
	NucleiPath   string
	TemplateRoot string
}

type ScanOptions struct {
	TemplateVersion string     `json:"template_version"`
	TemplateIDs     []string   `json:"template_ids"`
	RateLimit       int        `json:"rate_limit"`  // Nmap 发包速率和 Nuclei 请求速率，各阶段每秒上限。
	Concurrency     int        `json:"concurrency"` // 单任务的 PoC 模板并发。
	TimeoutSeconds  int        `json:"timeout_seconds"`
	ProbePorts      []PortSpec `json:"probe_ports"`
}

// Scan 是批次，具体执行输入由每个 Task 的 Plan 保存。
type Scan struct {
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

type WorkerStatus struct {
	InstanceID      string    `json:"instance_id"`
	ClusterID       string    `json:"cluster_id"`
	NetworkZone     string    `json:"network_zone"`
	TemplateVersion string    `json:"template_version"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	Online          bool      `json:"online"`
}

type AssetFilter struct {
	SourceID    string `json:"source_id"`
	ClusterID   string `json:"cluster_id"`
	NetworkZone string `json:"network_zone"`
	BusinessID  string `json:"business_id"`
}

func (f AssetFilter) Matches(a Asset) bool {
	return (f.SourceID == "" || f.SourceID == a.SourceID) &&
		(f.ClusterID == "" || f.ClusterID == a.ClusterID) &&
		(f.NetworkZone == "" || f.NetworkZone == a.NetworkZone) &&
		(f.BusinessID == "" || f.BusinessID == a.BusinessID)
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
	if len(options.TemplateIDs) == 0 || len(options.ProbePorts) == 0 {
		return nil, fmt.Errorf("template IDs and probe ports must not be empty")
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
		// 校验
		for name, value := range map[string]string{"source_id": asset.SourceID, "cluster_id": asset.ClusterID, "network_zone": asset.NetworkZone, "business_id": asset.BusinessID, "owner": asset.Owner} {
			if value == "" || value != strings.TrimSpace(value) {
				return nil, fmt.Errorf("asset %d: %s is required without surrounding whitespace", i, name)
			}
		}
		if strings.TrimSpace(asset.CMDBID) == "" || asset.CMDBID != strings.TrimSpace(asset.CMDBID) {
			return nil, fmt.Errorf("asset %d: CMDB ID is required and must have no surrounding whitespace", i)
		}
		if _, exists := seen[asset.AssetKey]; exists {
			return nil, fmt.Errorf("duplicate CMDB ID: %q", asset.CMDBID)
		}

		seen[asset.AssetKey] = struct{}{}
		host, err := NormalizeHost(asset.Host)
		if err != nil {
			return nil, fmt.Errorf("asset %q: %w", asset.CMDBID, err)
		}

		for j, service := range asset.RegisteredServices {
			if err := validateRegisteredService(service, host); err != nil {
				return nil, fmt.Errorf("asset %q registered service %d: %w", asset.CMDBID, j, err)
			}
		}
		// 为每个计划复制切片，避免调用方后续修改影响已创建的执行输入。
		asset.RegisteredServices = append([]AssetService(nil), asset.RegisteredServices...)
		planOptions := options
		planOptions.TemplateIDs = append([]string(nil), options.TemplateIDs...)
		planOptions.ProbePorts = append([]PortSpec(nil), options.ProbePorts...)
		plans = append(plans, TaskPlan{Asset: asset, Options: planOptions})
	}
	return plans, nil
}

func validateRegisteredService(service AssetService, assetHost string) error {
	endpoint, err := NormalizeEndpoint(service.Endpoint)
	if err != nil {
		return err
	}
	if endpoint.Host != assetHost {
		return fmt.Errorf("endpoint host %q does not belong to asset host %q", service.Endpoint.Host, assetHost)
	}

	protocol := service.ApplicationProtocol
	if protocol == "" {
		return fmt.Errorf("application protocol is required")
	}
	for _, c := range protocol {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			return fmt.Errorf("invalid application protocol: %q", protocol)
		}
	}
	if (protocol == "http" || protocol == "https") && endpoint.Transport != TransportTCP {
		return fmt.Errorf("%s requires TCP", protocol)
	}
	if service.TargetURL == "" {
		return nil
	}

	target, err := url.Parse(service.TargetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	if target.Scheme != protocol || target.Opaque != "" || target.User != nil || target.Fragment != "" {
		return fmt.Errorf("target URL must match application protocol and contain no credentials or fragment")
	}
	if _, err := NormalizeHost(target.Hostname()); err != nil {
		return fmt.Errorf("invalid target URL host: %w", err)
	}

	port := target.Port()
	if port == "" {
		switch target.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return fmt.Errorf("target URL requires an explicit port for protocol %q", protocol)
		}
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber != endpoint.Port {
		return fmt.Errorf("target URL port must match endpoint port %d", endpoint.Port)
	}

	return nil
}

// Template 是部署时提供的固定模板目录，不接受任务请求传入任意文件路径。
// Products 和 Versions 非空时分别使用忽略大小写的软件名与精确版本匹配。
// 部署方必须仅提供已批准且连接范围局限于任务目标的模板；CLI 的 Host/SNI
// 参数不能约束模板里硬编码的额外主机或端口。
type Template struct {
	ID       string
	Path     string
	Protocol string // http（含 HTTPS）、https、tcp 或 ssl
	Products []string
	Versions []string
}

type Scanner struct {
	cfg       DASTScannerConfig
	version   string
	templates map[string]Template
}

func NewScanner(cfg DASTScannerConfig) (*Scanner, error) {
	for _, path := range []*string{&cfg.NmapPath, &cfg.NucleiPath} {
		if *path == "" {
			return nil, fmt.Errorf("nmap and nuclei paths are required")
		}
		resolved, err := exec.LookPath(*path)
		if err != nil {
			return nil, fmt.Errorf("engine path: %w", err)
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return nil, err
		}
		*path = resolved
	}
	root, err := filepath.EvalSymlinks(cfg.TemplateRoot)
	if err != nil {
		return nil, fmt.Errorf("template root: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	cfg.TemplateRoot = root
	data, err := os.ReadFile(filepath.Join(root, "catalog.json"))
	if err != nil {
		return nil, fmt.Errorf("read template catalog: %w", err)
	}
	var catalog struct {
		Version   string     `json:"version"`
		Templates []Template `json:"templates"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode template catalog: %w", err)
	}
	if catalog.Version == "" || len(catalog.Templates) == 0 {
		return nil, fmt.Errorf("template catalog requires a version and templates")
	}
	s := &Scanner{cfg: cfg, version: catalog.Version, templates: make(map[string]Template, len(catalog.Templates))}
	for _, template := range catalog.Templates {
		if strings.TrimSpace(template.ID) == "" {
			return nil, fmt.Errorf("template ID is required")
		}
		if _, exists := s.templates[template.ID]; exists {
			return nil, fmt.Errorf("duplicate template ID %q", template.ID)
		}
		switch template.Protocol {
		case "http", "https", "tcp", "ssl":
		default:
			return nil, fmt.Errorf("unsupported template protocol %q", template.Protocol)
		}
		if template.Path == "" || !filepath.IsLocal(template.Path) {
			return nil, fmt.Errorf("template %q requires a relative local path", template.ID)
		}
		path, err := filepath.EvalSymlinks(filepath.Join(root, template.Path))
		if err != nil {
			return nil, fmt.Errorf("template %q: %w", template.ID, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || !filepath.IsLocal(rel) {
			return nil, fmt.Errorf("template %q escapes template root", template.ID)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("template %q is not a regular file", template.ID)
		}
		template.Path = path
		template.Products = append([]string(nil), template.Products...)
		template.Versions = append([]string(nil), template.Versions...)
		s.templates[template.ID] = template
	}
	return s, nil
}

type scanTarget struct {
	service AssetService
	url     string
}

type checkKey struct {
	endpoint   Endpoint
	url        string
	templateID string
}

func resolveHost(ctx context.Context, host string) ([]string, error) {
	normalized, err := NormalizeHost(host)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(normalized); err == nil {
		return []string{ip.Unmap().String()}, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", normalized)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if address.Zone() != "" {
			return nil, fmt.Errorf("scoped IP is not supported")
		}
		seen[address.Unmap().String()] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("host %q resolved to no addresses", host)
	}
	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips, nil
}

func (s *Scanner) Scan(ctx context.Context, plan TaskPlan) (result TaskResult, scanErr error) {
	if _, err := BuildTaskPlans([]Asset{plan.Asset}, plan.Options); err != nil {
		return result, err
	}
	if plan.Options.TemplateVersion != s.version {
		return result, fmt.Errorf("template version mismatch")
	}
	for _, id := range plan.Options.TemplateIDs {
		if _, exists := s.templates[id]; !exists {
			return result, fmt.Errorf("template %q is not installed", id)
		}
	}
	ips, err := resolveHost(ctx, plan.Asset.Host)
	if err != nil {
		return result, err
	}
	result.ResolvedIPs = ips
	checked := make(map[checkKey]struct{})
	portIndexes := make(map[Endpoint]int)
	observedServices := make(map[Endpoint]AssetService)
	// 任务可能对端点进行两次观察；以最后状态构造当前服务集合，包括错误返回。
	defer func() {
		for _, port := range result.Ports {
			if port.State != "open" {
				continue
			}
			if service, exists := observedServices[port.Endpoint]; exists {
				result.Services = append(result.Services, service)
			}
		}
	}()
	merge := func(ports []PortObservation, services []AssetService) {
		for _, p := range ports {
			if i, exists := portIndexes[p.Endpoint]; exists {
				result.Ports[i] = p
			} else {
				portIndexes[p.Endpoint] = len(result.Ports)
				result.Ports = append(result.Ports, p)
			}
		}
		for _, service := range services {
			observedServices[service.Endpoint] = service
		}
	}
	// 每个地址先处理登记服务，再发现其他指定端口；引擎调用顺序共享任务预算。
	for _, ip := range ips {
		registeredPorts := make([]PortSpec, 0, len(plan.Asset.RegisteredServices))
		portSet := make(map[PortSpec]struct{})
		for _, registered := range plan.Asset.RegisteredServices {
			port := PortSpec{Port: registered.Endpoint.Port, Transport: registered.Endpoint.Transport}
			if _, exists := portSet[port]; !exists {
				portSet[port] = struct{}{}
				registeredPorts = append(registeredPorts, port)
			}
		}
		if len(registeredPorts) > 0 {
			ports, services, err := s.discover(ctx, ip, registeredPorts, plan.Options.RateLimit)
			merge(ports, services)
			if err != nil {
				return result, err
			}
			observed := make(map[Endpoint]AssetService, len(services))
			for _, service := range services {
				observed[service.Endpoint] = service
			}
			for _, registered := range plan.Asset.RegisteredServices {
				endpoint := registered.Endpoint
				endpoint.Host = ip
				service, open := observed[endpoint]
				if !open {
					result.Coverage = append(result.Coverage, CoverageIssue{Endpoint: endpoint, Reason: "registered_service_not_confirmed_open"})
					continue
				}
				if err := s.check(ctx, scanTarget{service: service, url: registered.TargetURL}, plan.Options, checked, &result); err != nil {
					return result, err
				}
			}
		}
		ports, services, err := s.discover(ctx, ip, plan.Options.ProbePorts, plan.Options.RateLimit)
		merge(ports, services)
		if err != nil {
			return result, err
		}
		for _, service := range services {
			if err := s.check(ctx, scanTarget{service: service}, plan.Options, checked, &result); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

func applicable(template Template, service AssetService) string {
	if service.Endpoint.Transport != TransportTCP {
		return "unsupported_transport"
	}
	protocol := service.ApplicationProtocol
	matches := template.Protocol == "tcp" || template.Protocol == "http" && (protocol == "http" || protocol == "https") || template.Protocol == "https" && protocol == "https" || template.Protocol == "ssl" && (protocol == "https" || protocol == "tls")
	if !matches {
		return "protocol_mismatch"
	}
	if len(template.Products) > 0 {
		if service.Product == "" {
			return "insufficient_fingerprint"
		}
		found := false
		for _, product := range template.Products {
			if strings.EqualFold(product, service.Product) {
				found = true
				break
			}
		}
		if !found {
			return "product_mismatch"
		}
	}
	if len(template.Versions) > 0 {
		if service.Version == "" {
			return "insufficient_fingerprint"
		}
		found := false
		for _, version := range template.Versions {
			if version == service.Version {
				found = true
				break
			}
		}
		if !found {
			return "version_mismatch"
		}
	}
	return ""
}

func (s *Scanner) check(ctx context.Context, target scanTarget, options ScanOptions, checked map[checkKey]struct{}, result *TaskResult) error {
	if target.url == "" && (target.service.ApplicationProtocol == "http" || target.service.ApplicationProtocol == "https") {
		target.url = (&url.URL{Scheme: target.service.ApplicationProtocol, Host: net.JoinHostPort(target.service.Endpoint.Host, strconv.Itoa(target.service.Endpoint.Port)), Path: "/"}).String()
	}
	for _, id := range options.TemplateIDs {
		template := s.templates[id]
		if reason := applicable(template, target.service); reason != "" {
			result.Coverage = append(result.Coverage, CoverageIssue{Endpoint: target.service.Endpoint, TemplateID: id, Reason: reason})
			continue
		}
		selectedTarget := target
		if template.Protocol == "tcp" || template.Protocol == "ssl" {
			selectedTarget.url = ""
		} else {
			parsed, err := url.Parse(target.url)
			if err != nil || parsed.Scheme != target.service.ApplicationProtocol {
				result.Coverage = append(result.Coverage, CoverageIssue{Endpoint: target.service.Endpoint, TemplateID: id, Reason: "registered_protocol_mismatch"})
				continue
			}
		}
		key := checkKey{endpoint: selectedTarget.service.Endpoint, url: selectedTarget.url, templateID: id}
		if _, exists := checked[key]; exists {
			continue
		}
		checked[key] = struct{}{}
		findings, eventCount, err := s.runPoC(ctx, selectedTarget, template, options)
		result.Findings = append(result.Findings, findings...)
		reason := "engine_execution_statistics_unavailable"
		if eventCount == 0 {
			reason = "engine_execution_unconfirmed"
		}
		result.Coverage = append(result.Coverage, CoverageIssue{Endpoint: selectedTarget.service.Endpoint, TemplateID: id, Reason: reason})
		if err != nil {
			return err
		}

	}
	return nil
}

type nmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports struct {
			Items []struct {
				Protocol Transport `xml:"protocol,attr"`
				ID       int       `xml:"portid,attr"`
				State    struct {
					State  string `xml:"state,attr"`
					Reason string `xml:"reason,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
					Tunnel  string `xml:"tunnel,attr"`
					Method  string `xml:"method,attr"`
				} `xml:"service"`
			} `xml:"port"`
			Extra []struct {
				State   string `xml:"state,attr"`
				Count   int    `xml:"count,attr"`
				Reasons []struct {
					Reason   string    `xml:"reason,attr"`
					Count    int       `xml:"count,attr"`
					Protocol Transport `xml:"proto,attr"`
					Ports    string    `xml:"ports,attr"`
				} `xml:"extrareasons"`
			} `xml:"extraports"`
		} `xml:"ports"`
	} `xml:"host"`
	Finished struct {
		Exit  string `xml:"exit,attr"`
		Error string `xml:"errormsg,attr"`
	} `xml:"runstats>finished"`
}

func (s *Scanner) discover(ctx context.Context, ip string, requested []PortSpec, rateLimit int) ([]PortObservation, []AssetService, error) {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, nil, err
	}
	byTransport := map[Transport][]string{TransportTCP: {}, TransportUDP: {}}
	unique := make(map[PortSpec]struct{}, len(requested))
	for _, port := range requested {
		if _, err := NormalizeEndpoint(Endpoint{Host: ip, Port: port.Port, Transport: port.Transport}); err != nil {
			return nil, nil, err
		}
		if _, exists := unique[port]; exists {
			continue
		}
		unique[port] = struct{}{}
		byTransport[port.Transport] = append(byTransport[port.Transport], strconv.Itoa(port.Port))
	}
	if len(unique) == 0 {
		return nil, nil, fmt.Errorf("discovery requires explicit ports")
	}
	args := []string{"-Pn", "-n", "-sV", "--version-light", "--max-rate", strconv.Itoa(rateLimit), "-oX", "-"}
	var specs []string
	if len(byTransport[TransportTCP]) > 0 {
		args = append(args, "-sT")
		specs = append(specs, "T:"+strings.Join(byTransport[TransportTCP], ","))
	}
	if len(byTransport[TransportUDP]) > 0 {
		args = append(args, "-sU")
		specs = append(specs, "U:"+strings.Join(byTransport[TransportUDP], ","))
	}
	if address.Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-p", strings.Join(specs, ","), ip)
	output, runErr := runEngine(ctx, s.cfg.NmapPath, args, maxOutputBytes)
	var parsed nmapRun
	if err := xml.Unmarshal(output, &parsed); err != nil {
		return nil, nil, errors.Join(runErr, fmt.Errorf("parse nmap XML: %w", err))
	}
	if parsed.Finished.Exit != "success" {
		return nil, nil, errors.Join(runErr, fmt.Errorf("nmap did not finish successfully: %s", parsed.Finished.Error))
	}
	var ports []PortObservation
	var services []AssetService
	observedAt := time.Now().UTC()
	seen := make(map[PortSpec]struct{}, len(unique))
	hostFound := false
	for _, host := range parsed.Hosts {
		matches := false
		for _, addr := range host.Addresses {
			if addr.Type != "ipv4" && addr.Type != "ipv6" {
				continue
			}
			observed, err := netip.ParseAddr(addr.Addr)
			if err != nil {
				return ports, services, fmt.Errorf("invalid nmap address %q", addr.Addr)
			}
			if observed.Unmap() == address.Unmap() {
				matches = true
			}
		}
		if !matches {
			return ports, services, fmt.Errorf("nmap returned a host outside task: %q", ip)
		}
		if hostFound {
			return ports, services, fmt.Errorf("nmap returned duplicate host %q", ip)
		}
		hostFound = true
		for _, port := range host.Ports.Items {
			key := PortSpec{Port: port.ID, Transport: port.Protocol}
			if _, allowed := unique[key]; !allowed {
				return ports, services, fmt.Errorf("nmap returned unrequested port %d/%s", port.ID, port.Protocol)
			}
			if _, duplicate := seen[key]; duplicate {
				return ports, services, fmt.Errorf("duplicate nmap port")
			}
			seen[key] = struct{}{}
			switch port.State.State {
			case "open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered":
			default:
				return ports, services, fmt.Errorf("unknown nmap port state %q", port.State.State)
			}
			endpoint := Endpoint{Host: ip, Port: port.ID, Transport: port.Protocol}
			ports = append(ports, PortObservation{Endpoint: endpoint, State: port.State.State, Reason: port.State.Reason, ObservedAt: observedAt})
			if port.State.State != "open" {
				continue
			}
			service := AssetService{Endpoint: endpoint, ObservedAt: observedAt}
			// method=table 仅代表端口表猜测，不作为服务指纹。
			if port.Service.Method == "probed" {
				service.ApplicationProtocol = port.Service.Name
				service.Product, service.Version = port.Service.Product, port.Service.Version
				if port.Service.Tunnel == "ssl" {
					if port.Service.Name == "http" {
						service.ApplicationProtocol = "https"
					} else {
						service.ApplicationProtocol = "tls"
					}
				}
			}
			services = append(services, service)
		}

		// 现代 XML 在 extrareasons 中给出 proto/ports，可还原多个压缩状态。
		type unresolvedState struct {
			state string
			count int
		}
		var unresolved []unresolvedState
		for _, extra := range host.Ports.Extra {
			switch extra.State {
			case "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered":
			default:
				return ports, services, fmt.Errorf("unsupported aggregated nmap state %q", extra.State)
			}
			expanded := 0
			for _, reason := range extra.Reasons {
				if reason.Ports == "" {
					continue
				}
				if reason.Protocol != TransportTCP && reason.Protocol != TransportUDP {
					return ports, services, fmt.Errorf("nmap aggregate lacks explicit TCP/UDP protocol")
				}
				numbers, err := parseNmapPorts(reason.Ports)
				if err != nil {
					return ports, services, err
				}
				if len(numbers) != reason.Count {
					return ports, services, fmt.Errorf("nmap aggregate count does not match port list")
				}
				for _, number := range numbers {
					key := PortSpec{Port: number, Transport: reason.Protocol}
					if _, allowed := unique[key]; !allowed {
						return ports, services, fmt.Errorf("nmap aggregate includes an unrequested port")
					}
					if _, duplicate := seen[key]; duplicate {
						return ports, services, fmt.Errorf("nmap aggregate repeats an observed port")
					}
					seen[key] = struct{}{}
					ports = append(ports, PortObservation{Endpoint: Endpoint{Host: ip, Port: number, Transport: reason.Protocol}, State: extra.State, Reason: reason.Reason, ObservedAt: observedAt})
				}
				expanded += len(numbers)
			}
			if expanded > extra.Count {
				return ports, services, fmt.Errorf("nmap aggregate count is inconsistent")
			}
			if expanded < extra.Count {
				unresolved = append(unresolved, unresolvedState{extra.State, extra.Count - expanded})
			}
		}
		missing := len(unique) - len(seen)
		if missing > 0 {
			if len(unresolved) != 1 || unresolved[0].count != missing {
				return ports, services, errors.Join(runErr, fmt.Errorf("nmap XML cannot identify remaining port states"))
			}
			for port := range unique {
				if _, exists := seen[port]; exists {
					continue
				}
				ports = append(ports, PortObservation{Endpoint: Endpoint{Host: ip, Port: port.Port, Transport: port.Transport}, State: unresolved[0].state, Reason: "nmap_aggregated_state", ObservedAt: observedAt})
			}
		} else if len(unresolved) > 0 {
			return ports, services, fmt.Errorf("nmap aggregate counts exceed requested ports")
		}

	}
	if !hostFound {
		return ports, services, errors.Join(runErr, fmt.Errorf("nmap returned no host for %s", ip))
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Endpoint.Transport != ports[j].Endpoint.Transport {
			return ports[i].Endpoint.Transport < ports[j].Endpoint.Transport
		}
		return ports[i].Endpoint.Port < ports[j].Endpoint.Port
	})
	return ports, services, runErr
}

// Nmap 的 ports 属性是逗号分隔的端口或闭区间，例如 80,443,8000-8002。
func parseNmapPorts(raw string) ([]int, error) {
	var ports []int
	for _, item := range strings.Split(raw, ",") {
		bounds := strings.Split(item, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid nmap port range %q", item)
		}
		first, err := strconv.Atoi(bounds[0])
		if err != nil || first < 1 || first > 65535 {
			return nil, fmt.Errorf("invalid nmap port %q", item)
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.Atoi(bounds[1])
			if err != nil || last < first || last > 65535 {
				return nil, fmt.Errorf("invalid nmap port range %q", item)
			}
		}
		for port := first; port <= last; port++ {
			ports = append(ports, port)
		}
	}
	return ports, nil
}

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
		Severity       Severity `json:"severity"`
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

func (s *Scanner) runPoC(ctx context.Context, target scanTarget, template Template, options ScanOptions) ([]Finding, int, error) {
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
	lines := bufio.NewScanner(bytes.NewReader(output))
	lines.Buffer(make([]byte, 4096), maxOutputBytes)
	findings := make([]Finding, 0)
	eventCount := 0
	seen := make(map[string]struct{})
	for lines.Scan() {
		if len(bytes.TrimSpace(lines.Bytes())) == 0 {
			continue
		}
		var event nucleiEvent
		if err := json.Unmarshal(lines.Bytes(), &event); err != nil {
			return findings, eventCount, errors.Join(runErr, fmt.Errorf("parse nuclei JSONL: %w", err))
		}
		if event.Error != "" {
			return findings, eventCount, errors.Join(runErr, fmt.Errorf("nuclei execution error: %s", event.Error))
		}
		if event.TemplateID != template.ID || event.MatcherStatus == nil {
			return findings, eventCount, errors.Join(runErr, fmt.Errorf("nuclei event lacks expected template identity or matcher status"))
		}
		eventCount++
		if !*event.MatcherStatus {
			continue
		}
		if event.Info.Name == "" || event.MatchedAt == "" {
			return findings, eventCount, errors.Join(runErr, fmt.Errorf("nuclei finding lacks title or matched location"))
		}
		switch event.Info.Severity {
		case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical, SeverityUnknown:
		default:
			return findings, eventCount, errors.Join(runErr, fmt.Errorf("unknown nuclei severity %q", event.Info.Severity))
		}
		if event.IP != "" {
			ip, err := netip.ParseAddr(event.IP)
			if err != nil || ip.Unmap().String() != target.service.Endpoint.Host {
				return findings, eventCount, errors.Join(runErr, fmt.Errorf("nuclei finding IP is outside task endpoint"))
			}
		}
		key := event.MatcherName + "\x00" + event.MatchedAt
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		finding := Finding{TemplateID: template.ID, MatcherName: event.MatcherName, Title: event.Info.Name, Description: event.Info.Description, Severity: event.Info.Severity, Endpoint: target.service.Endpoint, TargetURL: target.url, MatchedAt: event.MatchedAt, CVEs: event.Info.Classification.CVEs, CWEs: event.Info.Classification.CWEs, References: event.Info.References}
		if event.Request != "" || event.Response != "" || len(event.Extracted) > 0 {
			finding.Evidence = &HTTPEvidence{Request: event.Request, Response: event.Response, ExtractedValues: event.Extracted}
		}
		findings = append(findings, finding)
	}
	if err := lines.Err(); err != nil {
		return findings, eventCount, errors.Join(runErr, fmt.Errorf("read nuclei JSONL: %w", err))
	}
	return findings, eventCount, runErr
}

const maxOutputBytes = 16 << 20

var errOutputLimit = errors.New("engine output exceeds limit")

type boundedOutput struct {
	bytes.Buffer
	limit  int
	cancel context.CancelFunc
	err    error
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.err = errOutputLimit
		b.cancel()
		return 0, b.err
	}
	return b.Buffer.Write(p)
}

// 引擎各自拥有进程组；取消时终止整个组，而非只终止入口进程。
func runEngine(ctx context.Context, path string, args []string, maxOutput int) (output []byte, err error) {
	// 运行时配置目录用于隔离引擎配置，不读取用户的 Nuclei 配置、代理或环境模板。
	runtimeDir, err := os.MkdirTemp("", "dast-engine-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(runtimeDir)) }()
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := &boundedOutput{limit: maxOutput, cancel: cancel}
	stderr := &boundedOutput{limit: maxOutput, cancel: cancel}
	cmd := exec.CommandContext(processCtx, path, args...)
	cmd.Dir = runtimeDir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "LANG=C",
		"NUCLEI_CONFIG_DIR=" + runtimeDir, "XDG_CONFIG_HOME=" + runtimeDir,
		"XDG_DATA_HOME=" + runtimeDir, "XDG_CACHE_HOME=" + runtimeDir, "XDG_STATE_HOME=" + runtimeDir,
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 3 * time.Second
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	runErr := cmd.Run()
	var cleanupErr error
	if cmd.Process != nil {
		cleanupErr = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(cleanupErr, syscall.ESRCH) {
			cleanupErr = nil
		}
	}
	err = errors.Join(runErr, cleanupErr, stdout.err, stderr.err, ctx.Err())
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("engine %s: %w; stderr: %s", path, err, stderr.String())
	}
	return stdout.Bytes(), nil
}
