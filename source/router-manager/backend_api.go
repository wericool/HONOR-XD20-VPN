package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

type ManagerLatencyResult struct {
	LatencyMS int64  `json:"latencyMs"`
	Status    string `json:"status"`
	CheckedAt int64  `json:"checkedAt"`
}

// ManagerMeasureTCP measures a direct TCP connection to the node's public
// server. DNS and all connection attempts share a four-second budget. Latency
// itself is TCP connection time, not a VPN request, throughput, or an ICMP RTT.
// Both hostname and address remain private; WireGuard's UDP transport is unsupported.
func ManagerMeasureTCP(nodeID string) (ManagerLatencyResult, error) {
	out, err := ManagerGetOutbound(nodeID)
	if err != nil {
		return ManagerLatencyResult{Status: "unsupported", CheckedAt: time.Now().Unix()}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	dialer := &net.Dialer{}
	return managerMeasureTCPTarget(ctx, out, net.DefaultResolver.LookupIP, dialer.DialContext), nil
}
func managerTCPAddress(out map[string]any) (string, string, bool) {
	protocol, _ := out["protocol"].(string)
	key := ""
	switch protocol {
	case "vless", "vmess":
		key = "vnext"
	case "trojan", "shadowsocks":
		key = "servers"
	default:
		return "", "", false
	}
	settings, ok := out["settings"].(map[string]any)
	if !ok {
		return "", "", false
	}
	list, ok := settings[key].([]any)
	if !ok || len(list) == 0 {
		return "", "", false
	}
	first, ok := list[0].(map[string]any)
	if !ok {
		return "", "", false
	}
	host, ok := first["address"].(string)
	if !ok || host == "" || len(host) > 253 || strings.ContainsAny(host, "\r\n /\\%") {
		return "", "", false
	}
	port := 0
	switch v := first["port"].(type) {
	case int:
		port = v
	case float64:
		port = int(v)
		if v != float64(port) {
			return "", "", false
		}
	case json.Number:
		port, _ = strconv.Atoi(v.String())
	case string:
		port, _ = strconv.Atoi(v)
	}
	if port < 1 || port > 65535 {
		return "", "", false
	}
	return host, strconv.Itoa(port), true
}
func managerMeasureTCPTarget(ctx context.Context, out map[string]any,
	lookup func(context.Context, string, string) ([]net.IP, error),
	dial func(context.Context, string, string) (net.Conn, error)) ManagerLatencyResult {
	result := ManagerLatencyResult{Status: "unsupported", CheckedAt: time.Now().Unix()}
	host, port, ok := managerTCPAddress(out)
	if !ok {
		return result
	}
	ips := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else {
		var err error
		ips, err = lookup(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			result.Status = "timeout"
			return result
		}
	}
	for _, ip := range ips {
		if !managerPublicIP(ip) {
			return result
		}
	}
	result.Status = "timeout"
	started := time.Now()
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		if ip.To4() == nil {
			continue
		}
		conn, err := dial(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
		if err == nil {
			conn.Close()
			result.LatencyMS = time.Since(started).Milliseconds()
			result.Status = "ok"
			return result
		}
	}
	return result
}

type ManagerProbeResult struct {
	OK          bool   `json:"ok"`
	Country     string `json:"country,omitempty"`
	Path        string `json:"path"`
	TLSVerified bool   `json:"tlsVerified"`
}

// ManagerProbeVPN checks the currently running outbound through its local-only
// SOCKS listener. It deliberately returns no trace body or egress IP address.
func ManagerProbeVPN(ctx context.Context) (ManagerProbeResult, error) {
	return managerProbe(ctx, true)
}

func ManagerProbeDirect(ctx context.Context) (ManagerProbeResult, error) {
	return managerProbe(ctx, false)
}

func managerProbe(ctx context.Context, vpn bool) (ManagerProbeResult, error) {
	path := "direct"
	if vpn {
		path = "vpn"
	}
	body, _, err := managerFetchPath(ctx, "https://www.cloudflare.com/cdn-cgi/trace", vpn)
	if err != nil {
		return ManagerProbeResult{Path: path}, err
	}
	country := ""
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "loc=") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "loc="))
			if len(v) == 2 && v[0] >= 'A' && v[0] <= 'Z' && v[1] >= 'A' && v[1] <= 'Z' {
				country = v
			}
		}
	}
	if country == "" {
		return ManagerProbeResult{Path: path}, errors.New("vpn_probe_unexpected_response")
	}
	return ManagerProbeResult{OK: true, Country: country, Path: path, TLSVerified: true}, nil
}

type ManagerSeedSubscription struct {
	Name      string `json:"name"`
	URL       string `json:"url,omitempty"`
	FetchMode string `json:"fetchMode,omitempty"`
	Content   string `json:"content,omitempty"`
}

// ManagerSeed is for a private installer/CLI seed. Existing storage is never
// overwritten. It does not select a candidate or change any router route.
func ManagerSeed(seeds []ManagerSeedSubscription, domains []string) (PublicState, error) {
	unlock, e := managerLock()
	if e != nil {
		return PublicState{}, e
	}
	defer unlock()
	s, e := managerLoad()
	if e != nil {
		return PublicState{}, e
	}
	if len(s.Subscriptions) > 0 {
		return managerPublic(s), nil
	}
	if len(seeds) > managerMaxSubs {
		return PublicState{}, errors.New("subscription_limit")
	}
	s.Domains, e = managerNormalizeDomains(domains)
	if e != nil {
		return PublicState{}, e
	}
	for _, seed := range seeds {
		mode, e := managerMode(seed.FetchMode)
		if e != nil {
			return PublicState{}, e
		}
		id, e := managerRandomID()
		if e != nil {
			return PublicState{}, e
		}
		name := managerSafeName(seed.Name)
		if name == "" {
			name = "Subscription"
		}
		sub := ManagerSubscription{ID: id, Name: name, URL: seed.URL, FetchMode: mode, Kind: "subscription", Status: "not_refreshed", Nodes: []ManagerNode{}}
		if seed.URL != "" {
			if e = managerValidateURL(seed.URL); e != nil {
				return PublicState{}, e
			}
		} else {
			sub.Kind = "import"
		}
		if seed.Content != "" {
			sub.Nodes, e = managerParseProfile([]byte(seed.Content), id, name)
			if e != nil {
				return PublicState{}, e
			}
			sub.Status = "cached_import"
			if sub.Kind == "import" {
				sub.Status = "ready"
			}
			sub.Updated = time.Now().Unix()
			sub.SkippedCount = managerProfileSkipped([]byte(seed.Content), len(sub.Nodes))
			if sub.SkippedCount > 0 {
				sub.Warning = "some_entries_unsupported_or_duplicate"
			}
		}
		s.Subscriptions = append(s.Subscriptions, sub)
	}
	if e = managerSave(s); e != nil {
		return PublicState{}, e
	}
	return managerPublic(s), nil
}
