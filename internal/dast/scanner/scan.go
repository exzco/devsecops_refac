package scanner

import (
	"devsecops/internal/dast/domain"
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"

	"golang.org/x/sync/errgroup"
)

type Config struct {
	NmapPath     string
	NucleiPath   string
	TemplateRoot string
}

type Scanner struct {
	cfg       Config
	version   string
	templates map[string]Template
}

func New(cfg Config) (*Scanner, error) {
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
	version, templates, err := loadTemplates(cfg.TemplateRoot)
	if err != nil {
		return nil, err
	}
	return &Scanner{cfg: cfg, version: version, templates: templates}, nil
}

func (s *Scanner) Version() string {
	return s.version
}

type scanTarget struct {
	service domain.AssetService
	url     string
}

type checkKey struct {
	endpoint   domain.Endpoint
	url        string
	templateID string
}

func resolveHost(ctx context.Context, host string) ([]string, error) {
	normalized, err := domain.NormalizeHost(host)
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

func (s *Scanner) Scan(ctx context.Context, plan domain.TaskPlan) (result domain.TaskResult, scanErr error) {
	if _, err := domain.BuildTaskPlans([]domain.Asset{plan.Asset}, plan.Options); err != nil {
		return result, err
	}
	if plan.Options.TemplateVersion != s.version {
		return result, fmt.Errorf("template version mismatch")
	}
	templateIDs := plan.Options.TemplateIDs
	if len(templateIDs) == 0 {
		templateIDs = make([]string, 0, len(s.templates))
		for id := range s.templates {
			templateIDs = append(templateIDs, id)
		}
		sort.Strings(templateIDs)
	} else {
		for _, id := range templateIDs {
			if _, exists := s.templates[id]; !exists {
				return result, fmt.Errorf("template %q is not installed", id)
			}
		}
	}
	plan.Options.TemplateIDs = templateIDs
	ips, err := resolveHost(ctx, plan.Asset.Host)
	if err != nil {
		return result, err
	}
	result.ResolvedIPs = ips
	results := make([]domain.TaskResult, len(ips))
	group, scanCtx := errgroup.WithContext(ctx)
	for i, ip := range ips {
		if scanCtx.Err() != nil {
			break
		}
		group.Go(func() error {
			if err := scanCtx.Err(); err != nil {
				return err
			}
			var err error
			results[i], err = s.scanIP(scanCtx, plan, ip)
			if err != nil {
				return fmt.Errorf("scan IP %s: %w", ip, err)
			}
			return nil
		})
	}
	scanErr = group.Wait()
	if scanErr == nil {
		scanErr = ctx.Err()
	}
	for _, partial := range results {
		result.Ports = append(result.Ports, partial.Ports...)
		result.Coverage = append(result.Coverage, partial.Coverage...)
		result.Services = append(result.Services, partial.Services...)
		result.Findings = append(result.Findings, partial.Findings...)
	}
	return result, scanErr
}

func (s *Scanner) scanIP(ctx context.Context, plan domain.TaskPlan, ip string) (result domain.TaskResult, scanErr error) {
	checked := make(map[checkKey]struct{})
	portIndexes := make(map[domain.Endpoint]int)
	observedServices := make(map[domain.Endpoint]domain.AssetService)
	defer func() {
		for _, port := range result.Ports {
			if port.State != "open" {
				continue
			}
			if service, exists := observedServices[port.Endpoint]; exists {
				result.Services = append(result.Services, service)
			}
		}
		if len(result.Coverage) > 1 {
			seen := make(map[domain.CoverageIssue]struct{}, len(result.Coverage))
			unique := make([]domain.CoverageIssue, 0, len(result.Coverage))
			for _, item := range result.Coverage {
				if _, exists := seen[item]; !exists {
					seen[item] = struct{}{}
					unique = append(unique, item)
				}
			}
			result.Coverage = unique
		}
		result.Findings = domain.DeduplicateFindings(result.Findings)
	}()
	merge := func(ports []domain.PortObservation, services []domain.AssetService) {
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
	registeredPorts := make([]domain.PortSpec, 0, len(plan.Asset.RegisteredServices))
	portSet := make(map[domain.PortSpec]struct{})
	for _, registered := range plan.Asset.RegisteredServices {
		port := domain.PortSpec{Port: registered.Endpoint.Port, Transport: registered.Endpoint.Transport}
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
		observed := make(map[domain.Endpoint]domain.AssetService, len(services))
		for _, service := range services {
			observed[service.Endpoint] = service
		}
		for _, registered := range plan.Asset.RegisteredServices {
			endpoint := registered.Endpoint
			endpoint.Host = ip
			service, open := observed[endpoint]
			if !open {
				result.Coverage = append(result.Coverage, domain.CoverageIssue{Endpoint: endpoint, Reason: "registered_service_not_confirmed_open"})
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
	return result, nil
}

func (s *Scanner) check(ctx context.Context, target scanTarget, options domain.ScanOptions, checked map[checkKey]struct{}, result *domain.TaskResult) error {
	if target.url == "" && (target.service.ApplicationProtocol == "http" || target.service.ApplicationProtocol == "https") {
		target.url = (&url.URL{Scheme: target.service.ApplicationProtocol, Host: net.JoinHostPort(target.service.Endpoint.Host, strconv.Itoa(target.service.Endpoint.Port)), Path: "/"}).String()
	}
	for _, id := range options.TemplateIDs {
		template := s.templates[id]
		if reason := applicable(template, target.service); reason != "" {
			result.Coverage = append(result.Coverage, domain.CoverageIssue{Endpoint: target.service.Endpoint, TemplateID: id, Reason: reason})
			continue
		}
		selectedTarget := target
		if template.Protocol == "tcp" || template.Protocol == "ssl" {
			selectedTarget.url = ""
		} else {
			parsed, err := url.Parse(target.url)
			if err != nil || parsed.Scheme != target.service.ApplicationProtocol {
				result.Coverage = append(result.Coverage, domain.CoverageIssue{Endpoint: target.service.Endpoint, TemplateID: id, Reason: "registered_protocol_mismatch"})
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
		result.Coverage = append(result.Coverage, domain.CoverageIssue{Endpoint: selectedTarget.service.Endpoint, TemplateID: id, Reason: reason})
		if err != nil {
			return err
		}

	}
	return nil
}

