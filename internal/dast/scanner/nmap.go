package scanner

import (
	"devsecops/internal/dast/domain"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

type nmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports struct {
			Items []struct {
				Protocol domain.Transport `xml:"protocol,attr"`
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
					Protocol domain.Transport `xml:"proto,attr"`
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

func compressPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	sort.Ints(ports)
	var ranges []string
	start, end := ports[0], ports[0]
	for i := 1; i < len(ports); i++ {
		if ports[i] == end+1 {
			end = ports[i]
		} else if ports[i] == end {
			continue
		} else {
			if start == end {
				ranges = append(ranges, strconv.Itoa(start))
			} else {
				ranges = append(ranges, fmt.Sprintf("%d-%d", start, end))
			}
			start, end = ports[i], ports[i]
		}
	}
	if start == end {
		ranges = append(ranges, strconv.Itoa(start))
	} else {
		ranges = append(ranges, fmt.Sprintf("%d-%d", start, end))
	}
	return strings.Join(ranges, ",")
}

func (s *Scanner) discover(ctx context.Context, ip string, requested []domain.PortSpec, rateLimit int) ([]domain.PortObservation, []domain.AssetService, error) {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, nil, err
	}
	byTransport := map[domain.Transport][]int{domain.TransportTCP: {}, domain.TransportUDP: {}}
	unique := make(map[domain.PortSpec]struct{}, len(requested))
	for _, port := range requested {
		if _, err := domain.NormalizeEndpoint(domain.Endpoint{Host: ip, Port: port.Port, Transport: port.Transport}); err != nil {
			return nil, nil, err
		}
		if _, exists := unique[port]; exists {
			continue
		}
		unique[port] = struct{}{}
		byTransport[port.Transport] = append(byTransport[port.Transport], port.Port)
	}
	if len(unique) == 0 {
		return nil, nil, fmt.Errorf("discovery requires explicit ports")
	}
	args := []string{"-Pn", "-n", "-sV", "--version-light", "--max-rate", strconv.Itoa(rateLimit), "-oX", "-"}
	var specs []string
	if len(byTransport[domain.TransportTCP]) > 0 {
		args = append(args, "-sT")
		specs = append(specs, "T:"+compressPorts(byTransport[domain.TransportTCP]))
	}
	if len(byTransport[domain.TransportUDP]) > 0 {
		args = append(args, "-sU")
		specs = append(specs, "U:"+compressPorts(byTransport[domain.TransportUDP]))
	}
	if address.Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-p", strings.Join(specs, ","), ip)
	output, runErr := runEngine(ctx, s.cfg.NmapPath, args, maxOutputBytes)
	if runErr != nil {
		if errors.Is(runErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || strings.Contains(runErr.Error(), "context deadline exceeded") {
			return nil, nil, fmt.Errorf("Nmap 端口探测超时（已达单任务超时时限，请在发起扫描时增加超时时限或缩小探测端口范围/提高发包速率）: %w", runErr)
		}
		return nil, nil, runErr
	}
	return parseNmapOutput(output, ip, unique, time.Now().UTC())
}

// parseNmapOutput 只转换引擎输出；目标、请求端口和观察时间均由调用方提供。
func parseNmapOutput(output []byte, ip string, unique map[domain.PortSpec]struct{}, observedAt time.Time) ([]domain.PortObservation, []domain.AssetService, error) {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, nil, err
	}
	var parsed nmapRun
	if err := xml.Unmarshal(output, &parsed); err != nil {
		return nil, nil, fmt.Errorf("parse nmap XML: %w", err)
	}
	if parsed.Finished.Exit != "success" {
		return nil, nil, fmt.Errorf("nmap did not finish successfully: %s", parsed.Finished.Error)
	}
	var ports []domain.PortObservation
	var services []domain.AssetService
	seen := make(map[domain.PortSpec]struct{}, len(unique))
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
			key := domain.PortSpec{Port: port.ID, Transport: port.Protocol}
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
			endpoint := domain.Endpoint{Host: ip, Port: port.ID, Transport: port.Protocol}
			ports = append(ports, domain.PortObservation{Endpoint: endpoint, State: port.State.State, Reason: port.State.Reason, ObservedAt: observedAt})
			if port.State.State != "open" {
				continue
			}
			service := domain.AssetService{Endpoint: endpoint, ObservedAt: observedAt}
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
				if reason.Protocol != domain.TransportTCP && reason.Protocol != domain.TransportUDP {
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
					key := domain.PortSpec{Port: number, Transport: reason.Protocol}
					if _, allowed := unique[key]; !allowed {
						return ports, services, fmt.Errorf("nmap aggregate includes an unrequested port")
					}
					if _, duplicate := seen[key]; duplicate {
						return ports, services, fmt.Errorf("nmap aggregate repeats an observed port")
					}
					seen[key] = struct{}{}
					ports = append(ports, domain.PortObservation{Endpoint: domain.Endpoint{Host: ip, Port: number, Transport: reason.Protocol}, State: extra.State, Reason: reason.Reason, ObservedAt: observedAt})
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
				return ports, services, fmt.Errorf("nmap XML cannot identify remaining port states")
			}
			for port := range unique {
				if _, exists := seen[port]; exists {
					continue
				}
				ports = append(ports, domain.PortObservation{Endpoint: domain.Endpoint{Host: ip, Port: port.Port, Transport: port.Transport}, State: unresolved[0].state, Reason: "nmap_aggregated_state", ObservedAt: observedAt})
			}
		} else if len(unresolved) > 0 {
			return ports, services, fmt.Errorf("nmap aggregate counts exceed requested ports")
		}

	}
	if !hostFound {
		return ports, services, fmt.Errorf("nmap returned no host for %s", ip)
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Endpoint.Transport != ports[j].Endpoint.Transport {
			return ports[i].Endpoint.Transport < ports[j].Endpoint.Transport
		}
		return ports[i].Endpoint.Port < ports[j].Endpoint.Port
	})
	return ports, services, nil
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

