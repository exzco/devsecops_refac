package scanner

import (
	"devsecops/internal/dast/domain"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Template 是部署时提供的固定模板目录，不接受任务请求传入任意文件路径。
type Template struct {
	ID       string
	Path     string
	Protocol string // http（含 HTTPS）、https、tcp 或 ssl
	Products []string
	Versions []string
}

func loadTemplates(templateRoot string) (string, map[string]Template, error) {
	root, err := filepath.EvalSymlinks(templateRoot)
	if err != nil {
		return "", nil, fmt.Errorf("template root: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(filepath.Join(root, "catalog.json"))
	if err != nil {
		return "", nil, fmt.Errorf("read template catalog: %w", err)
	}
	var catalog struct {
		Version   string     `json:"version"`
		Templates []Template `json:"templates"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return "", nil, fmt.Errorf("decode template catalog: %w", err)
	}
	if catalog.Version == "" || len(catalog.Templates) == 0 {
		return "", nil, fmt.Errorf("template catalog requires a version and templates")
	}
	templates := make(map[string]Template, len(catalog.Templates))
	for _, template := range catalog.Templates {
		if strings.TrimSpace(template.ID) == "" {
			return "", nil, fmt.Errorf("template ID is required")
		}
		if _, exists := templates[template.ID]; exists {
			return "", nil, fmt.Errorf("duplicate template ID %q", template.ID)
		}
		switch template.Protocol {
		case "http", "https", "tcp", "ssl":
		default:
			return "", nil, fmt.Errorf("unsupported template protocol %q", template.Protocol)
		}
		if template.Path == "" || !filepath.IsLocal(template.Path) {
			return "", nil, fmt.Errorf("template %q requires a relative local path", template.ID)
		}
		path, err := filepath.EvalSymlinks(filepath.Join(root, template.Path))
		if err != nil {
			return "", nil, fmt.Errorf("template %q: %w", template.ID, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || !filepath.IsLocal(rel) {
			return "", nil, fmt.Errorf("template %q escapes template root", template.ID)
		}
		info, err := os.Stat(path)
		if err != nil {
			return "", nil, err
		}
		if !info.Mode().IsRegular() {
			return "", nil, fmt.Errorf("template %q is not a regular file", template.ID)
		}
		template.Path = path
		template.Products = append([]string(nil), template.Products...)
		template.Versions = append([]string(nil), template.Versions...)
		templates[template.ID] = template
	}
	return catalog.Version, templates, nil
}

func applicable(template Template, service domain.AssetService) string {
	if service.Endpoint.Transport != domain.TransportTCP {
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

