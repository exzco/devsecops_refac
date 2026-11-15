package dast

import (
	"context"
	"fmt"
	"net/netip"
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

// AssetSource 是 CMDB／SIEM 资产接口，由公司的资产系统实现。
type AssetSource interface {
	ListAssets(context.Context) ([]Asset, error)
}
