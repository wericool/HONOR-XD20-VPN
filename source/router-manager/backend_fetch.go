package main

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type managerFetchMeta struct{ Expires, Total, Used int64 }

var managerForbiddenNets = func() []*net.IPNet {
	out := []*net.IPNet{}
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"} {
		_, n, _ := net.ParseCIDR(s)
		out = append(out, n)
	}
	return out
}()

func managerPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, n := range managerForbiddenNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
func managerValidateURL(raw string) error {
	if len(raw) > 4096 || strings.HasPrefix(raw, "happ://") {
		return errors.New("encrypted_happ_link_requires_plain_subscription")
	}
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("invalid_subscription_url")
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if strings.ContainsAny(h, "\r\n\\ /%") || h == "localhost" || !strings.Contains(h, ".") {
		return errors.New("private_subscription_address_rejected")
	}
	for _, suffix := range []string{".localhost", ".local", ".lan", ".internal", ".home"} {
		if strings.HasSuffix(h, suffix) {
			return errors.New("private_subscription_address_rejected")
		}
	}
	if ip := net.ParseIP(h); ip != nil && !managerPublicIP(ip) {
		return errors.New("private_subscription_address_rejected")
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return errors.New("invalid_subscription_url")
		}
	}
	return nil
}
func managerFetch(ctx context.Context, raw, mode string) ([]byte, managerFetchMeta, string, error) {
	if e := managerValidateURL(raw); e != nil {
		return nil, managerFetchMeta{}, "", e
	}
	mode, e := managerMode(mode)
	if e != nil {
		return nil, managerFetchMeta{}, "", e
	}
	if mode == "vpn" {
		b, m, e := managerFetchPath(ctx, raw, true)
		return b, m, "vpn", e
	}
	b, m, e := managerFetchPath(ctx, raw, false)
	if e == nil || mode == "direct" {
		return b, m, "direct", e
	}
	b, m, e = managerFetchPath(ctx, raw, true)
	return b, m, "vpn", e
}
func managerCACerts() (*x509.CertPool, error) {
	path := os.Getenv("ROUTER_MANAGER_CA")
	if path == "" {
		path = "/data/xray-test/cacert.pem"
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("ca_file_unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 512*1024+1))
	if e != nil || len(b) > 512*1024 {
		return nil, errors.New("ca_file_invalid")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("ca_file_invalid")
	}
	return pool, nil
}
func managerFetchPath(parent context.Context, raw string, vpn bool) ([]byte, managerFetchMeta, error) {
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	pool, e := managerCACerts()
	if e != nil {
		return nil, managerFetchMeta{}, e
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxIdleConns: 1,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		DialContext: func(c context.Context, network, address string) (net.Conn, error) {
			return managerSafeDial(c, address, vpn)
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return errors.New("redirect_limit")
		}
		return managerValidateURL(req.URL.String())
	}}
	req, e := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if e != nil {
		return nil, managerFetchMeta{}, errors.New("invalid_subscription_url")
	}
	req.Header.Set("User-Agent", "Happ/1.0")
	managerDeviceHeaders(req)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, e := client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return nil, managerFetchMeta{}, errors.New("fetch_timeout")
		}
		return nil, managerFetchMeta{}, errors.New("fetch_failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, managerFetchMeta{}, errors.New("fetch_http_rejected")
	}
	body, e := managerReadBody(resp.Body, resp.Header.Get("Content-Encoding"))
	if e != nil {
		return nil, managerFetchMeta{}, e
	}
	meta := managerFetchMeta{}
	var upload, download int64
	for _, field := range strings.Split(resp.Header.Get("subscription-userinfo"), ";") {
		p := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(p) != 2 {
			continue
		}
		v, e := strconv.ParseInt(p[1], 10, 64)
		if e != nil || v < 0 {
			continue
		}
		switch p[0] {
		case "expire":
			meta.Expires = v
		case "total":
			meta.Total = v
		case "upload":
			upload = v
		case "download":
			download = v
		}
	}
	if upload <= int64(^uint64(0)>>1)-download {
		meta.Used = upload + download
	}
	return body, meta, nil
}

// Count and cap both wire bytes and inflated bytes, including multi-member gzip.
func managerReadBody(source io.Reader, encoding string) ([]byte, error) {
	compressed := &io.LimitedReader{R: source, N: managerMaxBody + 1}
	var reader io.Reader = compressed
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if encoding == "gzip" {
		gz, e := gzip.NewReader(compressed)
		if e != nil {
			return nil, errors.New("invalid_compressed_response")
		}
		defer gz.Close()
		reader = gz
	} else if encoding != "" && encoding != "identity" {
		return nil, errors.New("unsupported_compression")
	}
	body, e := io.ReadAll(io.LimitReader(reader, managerMaxBody+1))
	if e != nil {
		return nil, errors.New("fetch_body_failed")
	}
	if len(body) > managerMaxBody || compressed.N == 0 {
		return nil, errors.New("subscription_response_too_large")
	}
	return body, nil
}
func managerSafeDial(ctx context.Context, address string, vpn bool) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, errors.New("fetch_address_invalid")
	}
	ips := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else if vpn {
		ips, e = managerRemoteDNS(ctx, host)
	} else {
		ips, e = net.DefaultResolver.LookupIP(ctx, "ip4", host)
	}
	if e != nil || len(ips) == 0 {
		return nil, errors.New("dns_lookup_failed")
	}
	// Reject mixed public/private answers as well as pure private answers. Pin the checked address.
	for _, ip := range ips {
		if !managerPublicIP(ip) {
			return nil, errors.New("private_subscription_address_rejected")
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil {
			continue
		} // This router deliberately uses IPv4 WAN transport.
		target := net.JoinHostPort(ip.String(), port)
		var conn net.Conn
		if vpn {
			conn, e = managerSOCKSDial(ctx, target)
		} else {
			conn, e = (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp4", target)
		}
		if e == nil {
			return conn, nil
		}
	}
	return nil, errors.New("fetch_connect_failed")
}
func managerSOCKSDial(ctx context.Context, target string) (net.Conn, error) {
	proxy := os.Getenv("ROUTER_MANAGER_SOCKS")
	if proxy == "" {
		proxy = "127.0.0.1:10809"
	}
	ph, pp, e := net.SplitHostPort(proxy)
	pIP := net.ParseIP(ph)
	if e != nil || pIP == nil || !pIP.IsLoopback() {
		return nil, errors.New("proxy_configuration_invalid")
	}
	if _, e = strconv.Atoi(pp); e != nil {
		return nil, errors.New("proxy_configuration_invalid")
	}
	conn, e := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", proxy)
	if e != nil {
		return nil, errors.New("vpn_fetch_proxy_unavailable")
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	if _, e = conn.Write([]byte{5, 1, 0}); e != nil {
		return nil, errors.New("proxy_handshake_failed")
	}
	hello := make([]byte, 2)
	if _, e = io.ReadFull(conn, hello); e != nil || hello[0] != 5 || hello[1] != 0 {
		return nil, errors.New("proxy_handshake_failed")
	}
	host, port, e := net.SplitHostPort(target)
	if e != nil {
		return nil, errors.New("proxy_target_invalid")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, errors.New("proxy_target_invalid")
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, 1)
			request = append(request, v4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("proxy_target_invalid")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(n>>8), byte(n))
	if _, e = conn.Write(request); e != nil {
		return nil, errors.New("proxy_connect_failed")
	}
	response := make([]byte, 4)
	if _, e = io.ReadFull(conn, response); e != nil || response[0] != 5 || response[1] != 0 {
		return nil, errors.New("proxy_connect_failed")
	}
	remain := 0
	switch response[3] {
	case 1:
		remain = 6
	case 4:
		remain = 18
	case 3:
		var size [1]byte
		if _, e = io.ReadFull(conn, size[:]); e != nil {
			return nil, errors.New("proxy_connect_failed")
		}
		remain = int(size[0]) + 2
	default:
		return nil, errors.New("proxy_connect_failed")
	}
	if _, e = io.ReadFull(conn, make([]byte, remain)); e != nil {
		return nil, errors.New("proxy_connect_failed")
	}
	conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}
func managerRemoteDNS(ctx context.Context, host string) ([]net.IP, error) {
	if len(host) > 253 || strings.ContainsAny(host, "\r\n /\\") {
		return nil, errors.New("dns_name_invalid")
	}
	id := make([]byte, 2)
	if _, e := rand.Read(id); e != nil {
		return nil, errors.New("random_unavailable")
	}
	query := make([]byte, 12)
	copy(query, id)
	query[2] = 1
	query[5] = 1
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) < 1 || len(label) > 63 {
			return nil, errors.New("dns_name_invalid")
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1) // IPv4 A / IN, transported through VPN over TCP.
	conn, e := managerSOCKSDial(ctx, "1.1.1.1:53")
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	deadline := time.Now().Add(4 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	wire := []byte{byte(len(query) >> 8), byte(len(query))}
	wire = append(wire, query...)
	if _, e = conn.Write(wire); e != nil {
		return nil, errors.New("dns_lookup_failed")
	}
	size := make([]byte, 2)
	if _, e = io.ReadFull(conn, size); e != nil {
		return nil, errors.New("dns_lookup_failed")
	}
	length := int(binary.BigEndian.Uint16(size))
	if length < 12 || length > 16384 {
		return nil, errors.New("dns_response_invalid")
	}
	response := make([]byte, length)
	if _, e = io.ReadFull(conn, response); e != nil {
		return nil, errors.New("dns_lookup_failed")
	}
	return managerDNSAnswers(response, binary.BigEndian.Uint16(id))
}
func managerDNSSkipName(b []byte, pos int) (int, error) {
	for i := 0; i < 128; i++ {
		if pos >= len(b) {
			break
		}
		n := int(b[pos])
		pos++
		if n == 0 {
			return pos, nil
		}
		if n&0xc0 == 0xc0 {
			if pos >= len(b) {
				break
			}
			return pos + 1, nil
		}
		if n > 63 || pos+n > len(b) {
			break
		}
		pos += n
	}
	return 0, errors.New("dns_response_invalid")
}
func managerDNSAnswers(b []byte, id uint16) ([]net.IP, error) {
	if len(b) < 12 || binary.BigEndian.Uint16(b) != id || b[2]&0x80 == 0 || b[3]&15 != 0 {
		return nil, errors.New("dns_response_invalid")
	}
	questions := int(binary.BigEndian.Uint16(b[4:6]))
	answers := int(binary.BigEndian.Uint16(b[6:8]))
	if questions > 4 || answers > 128 {
		return nil, errors.New("dns_response_invalid")
	}
	pos := 12
	var e error
	for i := 0; i < questions; i++ {
		pos, e = managerDNSSkipName(b, pos)
		if e != nil || pos+4 > len(b) {
			return nil, errors.New("dns_response_invalid")
		}
		pos += 4
	}
	ips := []net.IP{}
	for i := 0; i < answers; i++ {
		pos, e = managerDNSSkipName(b, pos)
		if e != nil || pos+10 > len(b) {
			return nil, errors.New("dns_response_invalid")
		}
		kind := binary.BigEndian.Uint16(b[pos:])
		class := binary.BigEndian.Uint16(b[pos+2:])
		length := int(binary.BigEndian.Uint16(b[pos+8:]))
		pos += 10
		if pos+length > len(b) {
			return nil, errors.New("dns_response_invalid")
		}
		if kind == 1 && class == 1 && length == 4 {
			ips = append(ips, net.IPv4(b[pos], b[pos+1], b[pos+2], b[pos+3]))
		}
		pos += length
	}
	if len(ips) == 0 {
		return nil, errors.New("dns_no_ipv4_answers")
	}
	return ips, nil
}

// managerHWID is this router's own persistent device identifier, sent the way
// subscription clients identify themselves (Remnawave/Happ-style panels). It is
// generated once and stored next to the manager data; nothing is borrowed from
// another device, so the provider's device limit applies to the router normally.
func managerHWID() string {
	path := os.Getenv("ROUTER_MANAGER_HWID")
	if path == "" {
		path = "/data/xray-manager/hwid"
	}
	if b, e := os.ReadFile(path); e == nil {
		if v := strings.TrimSpace(string(b)); len(v) == 32 && strings.Trim(v, "0123456789abcdef") == "" {
			return v
		}
	}
	raw := make([]byte, 16)
	if _, e := rand.Read(raw); e != nil {
		return ""
	}
	v := hex.EncodeToString(raw)
	if e := os.WriteFile(path, []byte(v+"\n"), 0o600); e != nil {
		return ""
	}
	return v
}
func managerDeviceHeaders(req *http.Request) {
	id := managerHWID()
	if id == "" {
		return
	}
	req.Header.Set("x-hwid", id)
	req.Header.Set("x-device-os", "Linux")
	req.Header.Set("x-ver-os", "4.4")
	req.Header.Set("x-device-model", "HONOR Router 3 XD20")
}
