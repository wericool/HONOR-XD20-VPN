package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var managerUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var managerPublicUUID = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
var managerSecretLink = regexp.MustCompile(`(?i)(?:https?|vless|vmess|trojan|ss|happ)://\S+`)
var managerDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func managerSafeName(s string) string {
	s = managerSecretLink.ReplaceAllString(s, "[link]")
	s = managerPublicUUID.ReplaceAllString(s, "[credential]")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	words := strings.Fields(s)
	for i, w := range words {
		if net.ParseIP(strings.Trim(w, "[](),;")) != nil {
			words[i] = "[address]"
		}
	}
	s = strings.Join(words, " ")
	r := []rune(s)
	if len(r) > 120 {
		s = string(r[:120])
	}
	return s
}
func managerNormalizeDomains(in []string) ([]string, error) {
	if len(in) > 4096 {
		return nil, errors.New("domain_limit")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.Contains(d, "://") {
			u, e := url.Parse(d)
			if e != nil {
				return nil, errors.New("invalid_domain")
			}
			d = u.Hostname()
		}
		d = strings.TrimPrefix(d, "*.")
		d = strings.TrimSuffix(d, ".")
		if len(d) > 253 || !managerDomain.MatchString(d) || net.ParseIP(d) != nil {
			return nil, errors.New("invalid_domain")
		}
		if !seen[d] {
			out = append(out, d)
			seen[d] = true
		}
	}
	return out, nil
}
func managerDecodeBase64(text string) ([]byte, error) {
	text = strings.Join(strings.Fields(text), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, e := enc.DecodeString(text); e == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid_base64")
}
func managerParseProfile(body []byte, subID, name string) ([]ManagerNode, error) {
	if len(body) > managerMaxBody {
		return nil, errors.New("profile_too_large")
	}
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if strings.HasPrefix(text, "happ://crypt") {
		return nil, errors.New("encrypted_happ_link_requires_plain_subscription")
	}
	if strings.Contains(text, "[Interface]") {
		if len(body) > 16384 {
			return nil, errors.New("wireguard_profile_too_large")
		}
		n, e := managerParseWireGuard(text, subID, name)
		if e != nil {
			return nil, e
		}
		return []ManagerNode{n}, nil
	}
	if !strings.Contains(text, "://") && !strings.HasPrefix(text, "[") {
		if b, e := managerDecodeBase64(text); e == nil {
			text = strings.TrimSpace(string(b))
		}
	}
	nodes := []ManagerNode{}
	seen := map[string]bool{}
	providerInstructions := managerProviderInstructions{allPlaceholders: true, allUnsupportedCaptions: true}
	add := func(n ManagerNode) error {
		// Inspect every caption before deduplication: providers often repeat the
		// same dummy endpoint while each caption carries part of an instruction.
		providerInstructions.observe(n)
		if seen[n.ID] {
			return nil
		}
		if len(nodes) >= managerMaxNodes {
			return errors.New("node_limit")
		}
		seen[n.ID] = true
		nodes = append(nodes, n)
		return nil
	}
	var xrayRows []json.RawMessage
	if strings.HasPrefix(text, "[") && json.Unmarshal([]byte(text), &xrayRows) == nil && managerIsXrayJSON(xrayRows) {
		if len(xrayRows) > managerMaxNodes*4 {
			return nil, errors.New("node_limit")
		}
		for _, row := range xrayRows {
			n, e := managerParseXrayConfig(row, subID)
			if e == nil {
				if e = add(n); e != nil {
					return nil, e
				}
			}
		}
	} else if strings.HasPrefix(text, "[") {
		var legacy []struct {
			Scheme string            `json:"scheme"`
			Server string            `json:"server"`
			Port   int               `json:"port"`
			ID     string            `json:"id"`
			Params map[string]string `json:"params"`
			Label  string            `json:"label"`
			Name   string            `json:"name"`
		}
		if json.Unmarshal([]byte(text), &legacy) != nil {
			return nil, errors.New("invalid_profile")
		}
		if len(legacy) > managerMaxNodes {
			return nil, errors.New("node_limit")
		}
		for _, l := range legacy {
			if l.Scheme != "vless" && l.Scheme != "trojan" {
				continue
			}
			q := url.Values{}
			for k, v := range l.Params {
				q.Set(k, v)
			}
			label := l.Label
			if label == "" {
				label = l.Name
			}
			u := url.URL{Scheme: l.Scheme, User: url.User(l.ID), Host: net.JoinHostPort(l.Server, strconv.Itoa(l.Port)), RawQuery: q.Encode(), Fragment: label}
			n, e := managerParseURI(u.String(), subID)
			if e == nil {
				if e = add(n); e != nil {
					return nil, e
				}
			}
		}
	} else {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "://") {
				continue
			}
			n, e := managerParseURI(line, subID)
			if e == nil {
				if e = add(n); e != nil {
					return nil, e
				}
			}
		}
	}
	if providerInstructions.requiresRegistration() {
		return nil, errors.New("provider_device_registration_required")
	}
	if providerInstructions.count > 0 && ((providerInstructions.allPlaceholders && providerInstructions.unsupportedApp) || providerInstructions.allUnsupportedCaptions) {
		return nil, errors.New("provider_app_unsupported")
	}
	if len(nodes) == 0 {
		return nil, errors.New("no_compatible_nodes")
	}
	return nodes, nil
}

type managerProviderInstructions struct {
	count                  int
	allPlaceholders        bool
	unsupportedApp         bool
	mentionsHWID           bool
	allUnsupportedCaptions bool
}

func managerUnsupportedCaption(label string) bool {
	// Some providers use a perfectly ordinary hostname/UUID for their instruction
	// response. The exact known caption is the diagnostic marker, not connectivity.
	label = strings.ToLower(strings.TrimSpace(label))
	label = strings.TrimLeftFunc(label, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
	label = strings.TrimSpace(strings.TrimRight(label, ".!。"))
	return label == "программа не поддерживается" || label == "приложение не поддерживается"
}

func managerPlaceholderEndpoint(n ManagerNode) bool {
	host, port, ok := managerTCPAddress(n.Outbound)
	if !ok || port != "1" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && !managerPublicIP(ip)
}
func (p *managerProviderInstructions) observe(n ManagerNode) {
	p.count++
	if !managerUnsupportedCaption(n.Name) {
		p.allUnsupportedCaptions = false
	}
	if !managerPlaceholderEndpoint(n) {
		p.allPlaceholders = false
	}
	label := strings.ToLower(n.Name)
	if strings.Contains(label, "не поддерж") || strings.Contains(label, "unsupported") || strings.Contains(label, "not supported") {
		p.unsupportedApp = true
	}
	if strings.Contains(label, "hwid") || strings.Contains(label, "регистрац") || strings.Contains(label, "device registration") {
		p.mentionsHWID = true
	}
}
func (p managerProviderInstructions) requiresRegistration() bool {
	return p.count > 0 && p.allPlaceholders && p.unsupportedApp && p.mentionsHWID
}
func managerProfileSkipped(body []byte, imported int) int {
	text := strings.TrimSpace(string(body))
	if strings.Contains(text, "[Interface]") {
		return 0
	}
	if !strings.Contains(text, "://") && !strings.HasPrefix(text, "[") {
		if b, e := managerDecodeBase64(text); e == nil {
			text = string(b)
		}
	}
	count := 0
	if strings.HasPrefix(strings.TrimSpace(text), "[") {
		var rows []json.RawMessage
		if json.Unmarshal([]byte(text), &rows) == nil {
			count = len(rows)
		}
	} else {
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(strings.TrimSpace(line), "://") {
				count++
			}
		}
	}
	if count > imported {
		return count - imported
	}
	return 0
}
func managerFinishNode(subID, name, protocol, transport, security string, out map[string]any) (ManagerNode, error) {
	b, e := json.Marshal(out)
	if e != nil || len(b) > 16384 {
		return ManagerNode{}, errors.New("node_config_too_large")
	}
	digest := sha256.Sum256(append([]byte(subID+":"), b...))
	name = managerSafeName(name)
	if name == "" {
		name = protocol + " / " + transport + " / " + security
	}
	return ManagerNode{ID: hex.EncodeToString(digest[:12]), Name: name, Protocol: protocol, Transport: transport, Security: security, Outbound: out}, nil
}
func managerParseVLESS(line, subID string) (ManagerNode, error) {
	fail := func() (ManagerNode, error) { return ManagerNode{}, errors.New("invalid_vless_node") }
	if len(line) > 32768 {
		return fail()
	}
	u, e := url.Parse(line)
	if e != nil || u.Scheme != "vless" || u.User == nil {
		return fail()
	}
	id := u.User.Username()
	if !managerUUID.MatchString(id) {
		return fail()
	}
	host := u.Hostname()
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 || host == "" || strings.ContainsAny(host, "/\\\r\n ") {
		return fail()
	}
	q := u.Query()
	transport := strings.ToLower(q.Get("type"))
	if transport == "" || transport == "raw" {
		transport = "tcp"
	}
	if transport == "websocket" {
		transport = "ws"
	}
	if transport != "tcp" && transport != "xhttp" && transport != "ws" && transport != "grpc" {
		return ManagerNode{}, errors.New("unsupported_transport")
	}
	security := strings.ToLower(q.Get("security"))
	if security == "" {
		security = "none"
	}
	if security != "none" && security != "tls" && security != "reality" {
		return ManagerNode{}, errors.New("unsupported_security")
	}
	if managerTrue(q.Get("allowInsecure")) || managerTrue(q.Get("insecure")) {
		return ManagerNode{}, errors.New("insecure_tls_node_rejected")
	}
	user := map[string]any{"id": id, "encryption": "none"}
	if v := q.Get("encryption"); v != "" {
		if len(v) > 1024 {
			return fail()
		}
		user["encryption"] = v
	}
	if flow := q.Get("flow"); flow != "" {
		if flow != "xtls-rprx-vision" {
			return fail()
		}
		user["flow"] = flow
	}
	stream := map[string]any{"network": transport, "security": security}
	sni := q.Get("sni")
	if sni == "" {
		sni = host
	}
	if len(sni) > 253 || strings.ContainsAny(sni, "/\\\r\n ") {
		return fail()
	}
	if security == "tls" {
		tls := map[string]any{"serverName": sni, "allowInsecure": false}
		if fp := q.Get("fp"); fp != "" {
			tls["fingerprint"] = fp
		}
		if alpn := q.Get("alpn"); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		stream["tlsSettings"] = tls
	}
	if security == "reality" {
		pbk := q.Get("pbk")
		if pbk == "" {
			pbk = q.Get("password")
		}
		key, e := base64.RawURLEncoding.DecodeString(strings.TrimRight(pbk, "="))
		if e != nil || len(key) != 32 {
			return fail()
		}
		sid := q.Get("sid")
		if len(sid) > 16 || len(sid)%2 != 0 {
			return fail()
		}
		if _, e := hex.DecodeString(sid); e != nil {
			return fail()
		}
		fp := q.Get("fp")
		if fp == "" {
			fp = "chrome"
		}
		reality := map[string]any{"serverName": sni, "fingerprint": fp, "publicKey": pbk, "shortId": sid}
		if v := q.Get("spx"); v != "" {
			reality["spiderX"] = v
		}
		if v := q.Get("mldsa65Verify"); v != "" {
			reality["mldsa65Verify"] = v
		}
		stream["realitySettings"] = reality
	}
	switch transport {
	case "xhttp":
		x := map[string]any{}
		if v := q.Get("path"); v != "" {
			x["path"] = v
		}
		if v := q.Get("host"); v != "" {
			x["host"] = v
		}
		if v := q.Get("mode"); v != "" {
			x["mode"] = v
		}
		if extra := q.Get("extra"); extra != "" {
			var v map[string]any
			if len(extra) > 8192 || json.Unmarshal([]byte(extra), &v) != nil {
				return fail()
			}
			x["extra"] = v
		}
		stream["xhttpSettings"] = x
	case "ws":
		ws := map[string]any{}
		if v := q.Get("path"); v != "" {
			ws["path"] = v
		}
		if v := q.Get("host"); v != "" {
			ws["host"] = v
			ws["headers"] = map[string]any{"Host": v}
		}
		stream["wsSettings"] = ws
	case "grpc":
		grpc := map[string]any{}
		service := q.Get("serviceName")
		if service == "" {
			service = q.Get("path")
		}
		if service != "" {
			grpc["serviceName"] = service
		}
		if v := q.Get("authority"); v != "" {
			grpc["authority"] = v
		}
		if managerTrue(q.Get("multiMode")) || q.Get("mode") == "multi" {
			grpc["multiMode"] = true
		}
		stream["grpcSettings"] = grpc
	case "tcp":
		header := q.Get("headerType")
		if header != "" && header != "none" {
			if header != "http" {
				return fail()
			}
			request := map[string]any{}
			if v := q.Get("path"); v != "" {
				request["path"] = strings.Split(v, ",")
			}
			if v := q.Get("host"); v != "" {
				request["headers"] = map[string]any{"Host": strings.Split(v, ",")}
			}
			stream["tcpSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": request}}
		}
	}
	out := map[string]any{"tag": "vpn", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{user}}}}, "streamSettings": stream}
	label := u.Fragment
	label = strings.ReplaceAll(label, id, "[credential]")
	label = strings.ReplaceAll(label, host, "[server]")
	return managerFinishNode(subID, label, "vless", transport, security, out)
}
func managerTrue(s string) bool { s = strings.ToLower(s); return s == "true" || s == "1" || s == "yes" }

func managerParseWireGuard(text, subID, name string) (ManagerNode, error) {
	invalid := func() (ManagerNode, error) { return ManagerNode{}, errors.New("invalid_wireguard_profile") }
	section := ""
	iface := map[string]string{}
	peer := map[string]string{}
	peers := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			if section == "[peer]" {
				peers++
			}
			if section != "[interface]" && section != "[peer]" {
				return invalid()
			}
			continue
		}
		bits := strings.SplitN(line, "=", 2)
		if len(bits) != 2 {
			return invalid()
		}
		k := strings.ToLower(strings.TrimSpace(bits[0]))
		v := strings.TrimSpace(bits[1])
		if len(v) > 2048 {
			return invalid()
		}
		if section == "[interface]" {
			iface[k] = v
		} else if section == "[peer]" {
			peer[k] = v
		} else {
			return invalid()
		}
	}
	if peers != 1 {
		return invalid()
	}
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		if _, ok := iface[k]; ok {
			return ManagerNode{}, errors.New("amneziawg_profile_not_supported")
		}
	}
	for _, key := range []string{iface["privatekey"], peer["publickey"]} {
		b, e := base64.StdEncoding.DecodeString(key)
		if e != nil || len(b) != 32 {
			return invalid()
		}
	}
	if psk := peer["presharedkey"]; psk != "" {
		b, e := base64.StdEncoding.DecodeString(psk)
		if e != nil || len(b) != 32 {
			return invalid()
		}
	}
	address := []string{}
	for _, a := range strings.Split(iface["address"], ",") {
		a = strings.TrimSpace(a)
		ip, _, e := net.ParseCIDR(a)
		if e != nil {
			ip = net.ParseIP(a)
		}
		if ip == nil {
			return invalid()
		}
		if ip.To4() != nil {
			address = append(address, ip.String())
		}
	}
	if len(address) == 0 {
		return invalid()
	}
	host, port, e := net.SplitHostPort(peer["endpoint"])
	n, pe := strconv.Atoi(port)
	if e != nil || pe != nil || host == "" || n < 1 || n > 65535 {
		return invalid()
	}
	allowed := []string{}
	for _, a := range strings.Split(peer["allowedips"], ",") {
		a = strings.TrimSpace(a)
		if _, _, e := net.ParseCIDR(a); e != nil {
			return invalid()
		}
		allowed = append(allowed, a)
	}
	dns := []string{}
	if iface["dns"] != "" {
		for _, a := range strings.Split(iface["dns"], ",") {
			ip := net.ParseIP(strings.TrimSpace(a))
			if ip == nil {
				return invalid()
			}
			if ip.To4() != nil {
				dns = append(dns, ip.String())
			}
		}
	}
	if len(dns) == 0 {
		dns = []string{"1.1.1.1"}
	}
	keep := 0
	if peer["persistentkeepalive"] != "" {
		keep, e = strconv.Atoi(peer["persistentkeepalive"])
		if e != nil || keep < 0 || keep > 65535 {
			return invalid()
		}
	}
	p := map[string]any{"endpoint": peer["endpoint"], "publicKey": peer["publickey"], "allowedIPs": allowed, "keepAlive": keep}
	if v := peer["presharedkey"]; v != "" {
		p["preSharedKey"] = v
	}
	out := map[string]any{"tag": "vpn", "protocol": "wireguard", "settings": map[string]any{"secretKey": iface["privatekey"], "address": address, "peers": []any{p}, "noKernelTun": true, "mtu": 1400, "remoteDNS": dns}}
	return managerFinishNode(subID, name, "wireguard", "udp", "wireguard", out)
}

// Xray JSON subscriptions are arrays of complete Xray configs, each with a
// "remarks" title. A config becomes a node only when it has exactly one proxy
// outbound; balancer/"AUTO" configs and unsupported protocols are skipped.
func managerIsXrayJSON(rows []json.RawMessage) bool {
	if len(rows) == 0 {
		return false
	}
	var probe struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	return json.Unmarshal(rows[0], &probe) == nil && len(probe.Outbounds) > 0
}
func managerParseXrayConfig(raw json.RawMessage, subID string) (ManagerNode, error) {
	var cfg struct {
		Remarks   string            `json:"remarks"`
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if len(raw) > 262144 || json.Unmarshal(raw, &cfg) != nil {
		return ManagerNode{}, errors.New("invalid_xray_config")
	}
	var proxy map[string]any
	for _, o := range cfg.Outbounds {
		dec := json.NewDecoder(strings.NewReader(string(o)))
		dec.UseNumber()
		var m map[string]any
		if dec.Decode(&m) != nil {
			return ManagerNode{}, errors.New("invalid_xray_config")
		}
		switch m["protocol"] {
		case "vless", "vmess", "trojan", "shadowsocks":
			if proxy != nil {
				return ManagerNode{}, errors.New("xray_config_with_multiple_servers")
			}
			proxy = m
		}
	}
	if proxy == nil {
		return ManagerNode{}, errors.New("unsupported_protocol")
	}
	if _, _, ok := managerTCPAddress(proxy); !ok {
		return ManagerNode{}, errors.New("invalid_xray_config")
	}
	transport, security := "tcp", "none"
	if st, ok := proxy["streamSettings"].(map[string]any); ok {
		if v, _ := st["network"].(string); v != "" {
			transport = strings.ToLower(v)
		}
		if v, _ := st["security"].(string); v != "" {
			security = strings.ToLower(v)
		}
		if transport == "raw" {
			transport = "tcp"
		}
		if transport != "tcp" && transport != "ws" && transport != "grpc" && transport != "xhttp" {
			return ManagerNode{}, errors.New("unsupported_transport")
		}
		if security != "none" && security != "tls" && security != "reality" {
			return ManagerNode{}, errors.New("unsupported_security")
		}
		if _, chained := st["sockopt"]; chained {
			return ManagerNode{}, errors.New("unsupported_transport")
		}
		if tls, ok := st["tlsSettings"].(map[string]any); ok {
			if v, _ := tls["allowInsecure"].(bool); v {
				return ManagerNode{}, errors.New("insecure_tls_node_rejected")
			}
		}
	}
	proxy["tag"] = "vpn"
	delete(proxy, "mux")
	return managerFinishNode(subID, cfg.Remarks, proxy["protocol"].(string), transport, security, proxy)
}
