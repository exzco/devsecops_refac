package domain

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Transport string

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

type Endpoint struct {
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Transport Transport `json:"transport"`
}

// AssetService 同时用于 CMDB 登记服务和扫描发现的服务。
type AssetService struct {
	Endpoint            Endpoint  `json:"endpoint"`
	ApplicationProtocol string    `json:"application_protocol"`
	TargetURL           string    `json:"target_url,omitempty"`
	Product             string    `json:"product,omitempty"`
	Version             string    `json:"version,omitempty"`
	ObservedAt          time.Time `json:"observed_at,omitzero"`
}

type AssetKey struct {
	SourceID string `json:"source_id"`
	CMDBID   string `json:"cmdb_id"`
}

type Asset struct {
	AssetKey
	ClusterID          string         `json:"cluster_id"`
	Host               string         `json:"host"`
	BusinessID         string         `json:"business_id"`
	Owner              string         `json:"owner"`
	NetworkZone        string         `json:"network_zone"`
	RegisteredServices []AssetService `json:"registered_services"`
}

func NormalizeAsset(asset Asset) (Asset, error) {
	for name, value := range map[string]string{
		"source_id": asset.SourceID, "cmdb_id": asset.CMDBID, "cluster_id": asset.ClusterID,
		"network_zone": asset.NetworkZone, "business_id": asset.BusinessID, "owner": asset.Owner,
	} {
		if value == "" || value != strings.TrimSpace(value) {
			return Asset{}, fmt.Errorf("%s is required without surrounding whitespace", name)
		}
	}
	host, err := NormalizeHost(asset.Host)
	if err != nil {
		return Asset{}, err
	}
	asset.Host = host
	for i, service := range asset.RegisteredServices {
		if err := validateRegisteredService(service, host); err != nil {
			return Asset{}, fmt.Errorf("registered service %d: %w", i, err)
		}
	}
	return asset, nil
}

func NormalizeHost(host string) (string, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", fmt.Errorf("host must not contain an IPv6 zone: %q", host)
		}
		return addr.Unmap().String(), nil
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", fmt.Errorf("invalid host: %q", host)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid host: %q", host)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid host: %q", host)
			}
		}
	}
	return name, nil
}

func NormalizeEndpoint(endpoint Endpoint) (Endpoint, error) {
	host, err := NormalizeHost(endpoint.Host)
	if err != nil {
		return Endpoint{}, err
	}
	if err := validatePort(endpoint.Port, endpoint.Transport); err != nil {
		return Endpoint{}, err
	}
	endpoint.Host = host
	return endpoint, nil
}

func validatePort(port int, transport Transport) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %d", port)
	}
	if transport != TransportTCP && transport != TransportUDP {
		return fmt.Errorf("invalid transport: %q", transport)
	}
	return nil
}

type PortSpec struct {
	Port      int       `json:"port"`
	Transport Transport `json:"transport"`
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

