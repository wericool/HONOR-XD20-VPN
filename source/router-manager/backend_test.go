package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestManagerProviderHWIDInstructionsAreNotServers(t *testing.T) {
	labels := []string{"🚫 Приложение не поддерживается.", "Как починить?", "Передавать HWID"}
	lines := []string{}
	legacy := []map[string]any{}
	for _, label := range labels {
		// Identical UUID/endpoint exercises diagnosis BEFORE node deduplication.
		u := url.URL{Scheme: "vless", User: url.User(managerTestID), Host: "0.0.0.0:1", RawQuery: "security=none&type=tcp", Fragment: label}
		lines = append(lines, u.String())
		legacy = append(legacy, map[string]any{"scheme": "vless", "server": "127.0.0.1", "port": 1, "id": managerTestID, "params": map[string]string{"security": "none", "type": "tcp"}, "label": label})
	}
	plain := []byte(strings.Join(lines, "\n"))
	legacyJSON, _ := json.Marshal(legacy)
	for _, body := range [][]byte{plain, []byte(base64.StdEncoding.EncodeToString(plain)), legacyJSON} {
		nodes, e := managerParseProfile(body, "device", "White")
		if e == nil || e.Error() != "provider_device_registration_required" || len(nodes) != 0 {
			t.Fatal("provider instruction placeholders were imported as VPN nodes")
		}
	}
}
func TestManagerPrivateVPNEndpointDoesNotTriggerProviderDiagnosis(t *testing.T) {
	body := []byte("vless://" + managerTestID + "@192.168.10.2:443?security=tls&sni=vpn.example#Private%20VPN")
	nodes, e := managerParseProfile(body, "privatevpn", "Private")
	if e != nil || len(nodes) != 1 {
		t.Fatal("ordinary private VPN endpoint rejected")
	}
	body = append(body, []byte("\nvless://"+managerTestID+"@0.0.0.0:1?security=none#Передавать%20HWID")...)
	if _, e = managerParseProfile(body, "mixed", "Mixed"); e != nil {
		t.Fatal("mixed real server and message body misdiagnosed")
	}
}
func TestManagerUnsupportedProgramPlaceholderIsNotServer(t *testing.T) {
	u := url.URL{Scheme: "vless", User: url.User(managerTestID), Host: "127.0.0.1:1", RawQuery: "security=none&type=tcp", Fragment: "Программа не поддерживается"}
	plain := []byte(u.String())
	legacy, _ := json.Marshal([]map[string]any{{"scheme": "vless", "server": "0.0.0.0", "port": 1, "id": managerTestID, "params": map[string]string{"security": "none", "type": "tcp"}, "name": "Программа не поддерживается"}})
	for _, body := range [][]byte{plain, []byte(base64.StdEncoding.EncodeToString(plain)), legacy} {
		nodes, e := managerParseProfile(body, "ultra", "Ultra")
		if e == nil || e.Error() != "provider_app_unsupported" || len(nodes) != 0 {
			t.Fatal("unsupported program instruction imported as VPN server")
		}
	}
	// The actual Ultra reply uses an ordinary hostname:443 and nonzero UUID;
	// an exact instruction caption still must not be offered as a real server.
	ordinary := strings.Replace(u.String(), "127.0.0.1:1", "vpn.example:443", 1)
	if nodes, e := managerParseProfile([]byte(ordinary), "ultrahostname", "Ultra"); e == nil || e.Error() != "provider_app_unsupported" || len(nodes) != 0 {
		t.Fatal("hostname instruction response accepted as server")
	}
	u.Host = "vpn.example:443"
	u.Fragment = "Netherlands server (app unsupported by this test client)"
	if nodes, e := managerParseProfile([]byte(u.String()), "real", "Real"); e != nil || len(nodes) != 1 {
		t.Fatal("ordinary server caption incorrectly diagnosed as provider error")
	}
}

func TestManagerRefreshRetainsExactActiveNodeAndDeleteGuard(t *testing.T) {
	active, e := managerParseVLESS("vless://"+managerTestID+"@old.example:443?security=tls#Original", "subactive")
	if e != nil {
		t.Fatal(e)
	}
	fresh, e := managerParseProfile([]byte("vless://"+managerTestID+"@new.example:443?security=tls#New"), "subactive", "Example")
	if e != nil {
		t.Fatal(e)
	}
	retained, kept, fits := managerRetainActiveNode(active.ID, []ManagerNode{active}, fresh, managerMaxNodes)
	if !kept || !fits || len(retained) != 2 || retained[1].ID != active.ID || !reflect.DeepEqual(retained[1].Outbound, active.Outbound) {
		t.Fatal("refresh changed or removed the live outbound")
	}
	store := &ManagerStore{Version: 1, SelectedID: active.ID, Domains: []string{}, Subscriptions: []ManagerSubscription{{ID: "subactive", Name: "Example", Nodes: retained, Warning: "active_server_from_previous_update"}}}
	state := managerPublic(store)
	if !state.SelectionAvailable || state.SelectedID != active.ID {
		t.Fatal("active node disappeared from public state")
	}
	t.Setenv("ROUTER_MANAGER_DIR", t.TempDir())
	if e = managerSave(store); e != nil {
		t.Fatal(e)
	}
	if out, e := ManagerGetOutbound(active.ID); e != nil || !reflect.DeepEqual(out, active.Outbound) {
		// JSON storage converts numeric ports to float64, so compare canonical JSON.
		actual, _ := json.Marshal(out)
		expected, _ := json.Marshal(active.Outbound)
		if e != nil || !bytes.Equal(actual, expected) {
			t.Fatal("stored active outbound changed")
		}
	}
	request, _ := json.Marshal(map[string]string{"id": "subactive"})
	if _, e = ManagerAction("subscription-delete", request); e == nil || e.Error() != "select_another_node_before_delete" {
		t.Fatal("active subscription became deletable")
	}
}
func TestManagerRefreshRetentionRespectsCapacityAndDoesNotDuplicateActive(t *testing.T) {
	old := ManagerNode{ID: "active", Outbound: map[string]any{"protocol": "vless"}}
	fresh := []ManagerNode{{ID: "new1"}, {ID: "new2"}, {ID: "new3"}}
	nodes, kept, fits := managerRetainActiveNode("active", []ManagerNode{old}, fresh, 3)
	if !kept || !fits || len(nodes) != 3 || nodes[0].ID != "new1" || nodes[1].ID != "new2" || nodes[2].ID != "active" {
		t.Fatal("active retention exceeded global capacity")
	}
	nodes, kept, fits = managerRetainActiveNode("active", []ManagerNode{old}, []ManagerNode{old, {ID: "new"}}, 2)
	if kept || !fits || len(nodes) != 2 {
		t.Fatal("active node duplicated")
	}
	if _, _, fits = managerRetainActiveNode("active", []ManagerNode{old}, fresh, 2); fits {
		t.Fatal("oversized fresh list was accepted")
	}
	if _, _, fits = managerRetainActiveNode("active", []ManagerNode{old}, nil, 0); fits {
		t.Fatal("active retention accepted zero capacity")
	}
}

func TestManagerTCPMeasurePinsPublicIPv4AndKeepsAddressPrivate(t *testing.T) {
	out := map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "node.example", "port": float64(443)}}}}
	looked, dialed := false, false
	result := managerMeasureTCPTarget(context.Background(), out,
		func(ctx context.Context, network, host string) ([]net.IP, error) {
			looked = true
			if network != "ip4" || host != "node.example" {
				t.Fatal("wrong IPv4 DNS target")
			}
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		},
		func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = true
			if network != "tcp4" || address != "8.8.8.8:443" {
				t.Fatal("address was not pinned")
			}
			a, b := net.Pipe()
			b.Close()
			return a, nil
		})
	if !looked || !dialed || result.Status != "ok" || result.CheckedAt == 0 {
		t.Fatal("TCP result invalid")
	}
	public, _ := json.Marshal(result)
	for _, secret := range []string{"node.example", "8.8.8.8", "vnext"} {
		if strings.Contains(string(public), secret) {
			t.Fatal("latency result leaked endpoint")
		}
	}
}
func TestManagerTCPMeasureRejectsPrivateTargetsAndUDP(t *testing.T) {
	cases := []map[string]any{
		{"protocol": "wireguard", "settings": map[string]any{}},
		{"protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": 443}}}},
		{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": "mixed.example", "port": 8388}}}},
	}
	for _, out := range cases {
		result := managerMeasureTCPTarget(context.Background(), out,
			func(context.Context, string, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("192.168.3.1")}, nil
			},
			func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("private/UDP target dialed")
				return nil, errors.New("must not dial")
			})
		if result.Status != "unsupported" {
			t.Fatal("unsupported/private target accepted")
		}
	}
}
func TestManagerTCPMeasureSharesDNSAndDialDeadline(t *testing.T) {
	out := map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{"address": "node.example", "port": 443}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	result := managerMeasureTCPTarget(ctx, out,
		func(ctx context.Context, _ string, _ string) ([]net.IP, error) { <-ctx.Done(); return nil, ctx.Err() },
		func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dial ran after DNS timeout")
			return nil, errors.New("must not dial")
		})
	if result.Status != "timeout" || time.Since(started) > time.Second {
		t.Fatal("DNS did not share the deadline")
	}
}
func TestManagerLockRecoversOnlyEmptyStaleDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ROUTER_MANAGER_DIR", dir)
	lock := filepath.Join(dir, ".manager-lock")
	if e := os.Mkdir(lock, 0700); e != nil {
		t.Fatal(e)
	}
	past := time.Now().Add(-3 * time.Minute)
	if e := os.Chtimes(lock, past, past); e != nil {
		t.Fatal(e)
	}
	unlock, e := managerLock()
	if e != nil {
		t.Fatal("empty stale lock was not recovered")
	}
	unlock()
	if e = os.Mkdir(lock, 0700); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(lock, "do-not-delete")
	if e = os.WriteFile(marker, []byte("retain"), 0600); e != nil {
		t.Fatal(e)
	}
	os.Chtimes(lock, past, past)
	started := time.Now()
	if _, e = managerLock(); e == nil {
		t.Fatal("non-empty lock directory removed")
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("failed stale removal caused an unbounded wait")
	}
	if _, e = os.Stat(marker); e != nil {
		t.Fatal("lock content was deleted")
	}
}

func TestManagerBodyLimitsIncludeGzipExpansion(t *testing.T) {
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	w.Write(bytes.Repeat([]byte("x"), managerMaxBody+1))
	w.Close()
	if _, e := managerReadBody(bytes.NewReader(compressed.Bytes()), "gzip"); e == nil {
		t.Fatal("gzip expansion exceeded limit")
	}
	if _, e := managerReadBody(bytes.NewReader(bytes.Repeat([]byte("x"), managerMaxBody+1)), ""); e == nil {
		t.Fatal("plain response exceeded limit")
	}
	if _, e := managerReadBody(strings.NewReader("bad"), "gzip"); e == nil {
		t.Fatal("malformed gzip accepted")
	}
	if _, e := managerReadBody(strings.NewReader("test"), "br"); e == nil {
		t.Fatal("unexpected compression accepted")
	}
}
func TestManagerCompatibleURIProtocols(t *testing.T) {
	vmess, _ := json.Marshal(map[string]any{"v": "2", "add": "vmess.example", "port": "443", "id": managerTestID, "aid": "0", "net": "ws", "host": "cdn.example", "path": "/socket", "tls": "tls", "sni": "cert.example", "ps": "VMess"})
	ss := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:example-test-password"))
	lines := []string{"trojan://example-test-password@trojan.example:443?security=tls&sni=cert.example#Trojan", "vmess://" + base64.StdEncoding.EncodeToString(vmess), "ss://" + ss + "@ss.example:8388#Shadowsocks"}
	nodes, e := managerParseProfile([]byte(strings.Join(lines, "\n")), "subprotocols", "")
	if e != nil || len(nodes) != 3 {
		t.Fatalf("compatible protocol parse failed: %v", e)
	}
	if nodes[0].Protocol != "trojan" || nodes[1].Protocol != "vmess" || nodes[2].Protocol != "shadowsocks" {
		t.Fatal("protocol mapping changed")
	}
	if nodes[1].Transport != "ws" || nodes[0].Security != "tls" {
		t.Fatal("transport parameters changed")
	}
}

const managerTestID = "13572468-1234-5678-9abc-0123456789ab"

func TestManagerParsesVLESSAndPreservesXHTTP(t *testing.T) {
	line := "vless://" + managerTestID + "@vpn.example:443?security=tls&type=xhttp&sni=cert.example&fp=firefox&alpn=h2&path=%2Fapi&mode=stream-one&extra=%7B%22noSSEHeader%22%3Atrue%7D#Netherlands"
	n, e := managerParseProfile([]byte(base64.StdEncoding.EncodeToString([]byte(line))), "sub1", "Example")
	if e != nil || len(n) != 1 {
		t.Fatalf("parse failed: %v", e)
	}
	if n[0].Transport != "xhttp" || n[0].Security != "tls" {
		t.Fatal("transport/security changed")
	}
	stream := n[0].Outbound["streamSettings"].(map[string]any)
	tls := stream["tlsSettings"].(map[string]any)
	if tls["serverName"] != "cert.example" || tls["fingerprint"] != "firefox" || tls["allowInsecure"] != false {
		t.Fatal("TLS parameters changed")
	}
	x := stream["xhttpSettings"].(map[string]any)
	if x["path"] != "/api" || x["mode"] != "stream-one" || x["extra"].(map[string]any)["noSSEHeader"] != true {
		t.Fatal("XHTTP parameters changed")
	}
}
func TestManagerRealityAndUnsafeProfiles(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	n, e := managerParseProfile([]byte("vless://"+managerTestID+"@vpn.example:443?security=reality&type=tcp&sni=cover.example&fp=chrome&pbk="+key+"&sid=12ab&flow=xtls-rprx-vision"), "sub1", "")
	if e != nil || len(n) != 1 || n[0].Security != "reality" {
		t.Fatalf("REALITY parse failed: %v", e)
	}
	for _, s := range []string{"happ://crypt5/encrypted", "vless://" + managerTestID + "@vpn.example:443?security=tls&allowInsecure=1", strings.Repeat("x", managerMaxBody+1)} {
		if _, e = managerParseProfile([]byte(s), "sub1", ""); e == nil {
			t.Fatal("unsafe/invalid input accepted")
		}
	}
}
func TestManagerStoreIsPrivateAndCandidateDoesNotSelect(t *testing.T) {
	d := t.TempDir()
	t.Setenv("ROUTER_MANAGER_DIR", d)
	body := map[string]any{"name": "Example", "content": "vless://" + managerTestID + "@vpn.example:443?security=tls#Safe"}
	input, _ := json.Marshal(body)
	state, e := ManagerAction("profile-import", input)
	if e != nil {
		t.Fatal(e)
	}
	p := state.(PublicState)
	if len(p.Nodes) != 1 {
		t.Fatal("no nodes")
	}
	encoded, _ := json.Marshal(p)
	for _, secret := range []string{managerTestID, "vpn.example", "outbound", "vless://"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("public state leaked private config")
		}
	}
	if _, e = ManagerGetOutbound(p.Nodes[0].ID); e != nil {
		t.Fatal(e)
	}
	id, _ := ManagerCurrentID()
	if id != "" {
		t.Fatal("candidate lookup changed selection")
	}
	input, _ = json.Marshal(map[string]string{"id": p.Nodes[0].ID})
	if _, e = ManagerAction("node-select", input); e != nil {
		t.Fatal(e)
	}
	id, _ = ManagerCurrentID()
	if id != p.Nodes[0].ID {
		t.Fatal("selection not committed")
	}
	st, e := os.Stat(filepath.Join(d, "subscriptions.json"))
	if e != nil {
		t.Fatal(e)
	}
	if st.Mode().Perm() != 0600 && os.PathSeparator != '\\' {
		t.Fatal("private store permissions wrong")
	}
}
func TestManagerSSRFAndDomains(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1/a", "https://192.168.3.1/secret", "https://localhost/a", "https://169.254.169.254/", "https://user:pass@example.com/a", "https://example.local/", "file:///etc/passwd"} {
		if managerValidateURL(u) == nil {
			t.Fatal("unsafe subscription address accepted")
		}
	}
	for _, s := range []string{"127.0.0.1", "192.168.1.2", "100.64.1.1", "169.254.1.1", "224.0.0.1", "::1", "fc00::1", "fe80::1"} {
		if managerPublicIP(net.ParseIP(s)) {
			t.Fatal("private IP accepted")
		}
	}
	if !managerPublicIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("public IPv4 rejected")
	}
	d, e := managerNormalizeDomains([]string{"https://YouTube.com/watch?v=x", "*.googlevideo.com", "youtube.com"})
	if e != nil || len(d) != 2 || d[0] != "youtube.com" {
		t.Fatalf("domain normalization failed: %v", e)
	}
	if _, e = managerNormalizeDomains([]string{"x;rm -rf /"}); e == nil {
		t.Fatal("invalid domain accepted")
	}
}
func TestManagerWireGuardImport(t *testing.T) {
	k := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := "[Interface]\nPrivateKey = " + k + "\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = " + k + "\nPresharedKey = " + k + "\nEndpoint = wg.example:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 30\n"
	nodes, e := managerParseProfile([]byte(body), "subwg", "WireGuard")
	if e != nil || len(nodes) != 1 || nodes[0].Protocol != "wireguard" {
		t.Fatalf("WG parse failed: %v", e)
	}
	settings := nodes[0].Outbound["settings"].(map[string]any)
	if settings["address"].([]string)[0] != "10.8.0.2" || settings["noKernelTun"] != true {
		t.Fatal("WG address/kernel mode changed")
	}
	if _, e = managerParseProfile([]byte(strings.Replace(body, "[Peer]", "Jc = 3\n[Peer]", 1)), "subwg", "WG"); e == nil {
		t.Fatal("AmneziaWG accepted as ordinary WG")
	}
}
func TestManagerDNSBounds(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 12), {0, 1, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0}} {
		if _, e := managerDNSAnswers(b, 1); e == nil {
			t.Fatal("malformed DNS accepted")
		}
	}
}

// The fake SOCKS proxy handles DNS and a subsequent connection. No external DNS
// or network service is contacted; the returned public IPv4 must be pinned.
func TestManagerVPNResolvesThroughSOCKSAndPinsIP(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	t.Setenv("ROUTER_MANAGER_SOCKS", ln.Addr().String())
	targets := make(chan string, 2)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			c, e := ln.Accept()
			if e != nil {
				done <- e
				return
			}
			c.SetDeadline(time.Now().Add(3 * time.Second))
			hello := make([]byte, 3)
			if _, e = io.ReadFull(c, hello); e != nil {
				c.Close()
				done <- e
				return
			}
			c.Write([]byte{5, 0})
			req := make([]byte, 10)
			if _, e = io.ReadFull(c, req); e != nil {
				c.Close()
				done <- e
				return
			}
			if req[3] != 1 {
				c.Close()
				done <- io.ErrUnexpectedEOF
				return
			}
			target := net.JoinHostPort(net.IP(req[4:8]).String(), strconvManagerTest(int(binary.BigEndian.Uint16(req[8:]))))
			targets <- target
			c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
			if i == 0 {
				sz := make([]byte, 2)
				if _, e = io.ReadFull(c, sz); e != nil {
					c.Close()
					done <- e
					return
				}
				q := make([]byte, int(binary.BigEndian.Uint16(sz)))
				if _, e = io.ReadFull(c, q); e != nil {
					c.Close()
					done <- e
					return
				}
				ans := append([]byte{}, q...)
				ans[2] = 0x81
				ans[3] = 0x80
				ans[7] = 1
				ans = append(ans, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 8, 8, 8, 8)
				wire := []byte{byte(len(ans) >> 8), byte(len(ans))}
				c.Write(append(wire, ans...))
			}
			c.Close()
		}
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := managerSafeDial(ctx, "subscription.example:443", true)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if a, b := <-targets, <-targets; a != "1.1.1.1:53" || b != "8.8.8.8:443" {
		t.Fatalf("proxy targets wrong: %s / %s", a, b)
	}
}
func strconvManagerTest(n int) string {
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte(n%10) + '0'}, b...)
		n /= 10
	}
	if len(b) == 0 {
		return "0"
	}
	return string(b)
}

func TestManagerDeviceHeadersStableHWID(t *testing.T) {
	t.Setenv("ROUTER_MANAGER_HWID", filepath.Join(t.TempDir(), "hwid"))
	r1, _ := http.NewRequest("GET", "https://example.com/", nil)
	r2, _ := http.NewRequest("GET", "https://example.com/", nil)
	managerDeviceHeaders(r1)
	managerDeviceHeaders(r2)
	id := r1.Header.Get("x-hwid")
	if len(id) != 32 || id != r2.Header.Get("x-hwid") || r1.Header.Get("x-device-os") != "Linux" {
		t.Fatalf("unstable or missing device headers: %q %q", id, r2.Header.Get("x-hwid"))
	}
}

func TestManagerParseXrayJSONSubscription(t *testing.T) {
	body := `[
	 {"remarks":"AUTO","outbounds":[{"tag":"a","protocol":"vless","settings":{"vnext":[{"address":"a.example","port":443,"users":[{"id":"` + managerTestID + `"}]}]}},{"tag":"b","protocol":"vless","settings":{"vnext":[{"address":"b.example","port":443,"users":[{"id":"` + managerTestID + `"}]}]}}]},
	 {"remarks":"Germany (WiFi)","outbounds":[{"tag":"wifi","protocol":"vless","settings":{"vnext":[{"address":"de.example","port":443,"users":[{"id":"` + managerTestID + `","encryption":"none"}]}]},"streamSettings":{"network":"grpc","security":"reality","realitySettings":{"serverName":"x.example","publicKey":"k","shortId":"ab"}}},{"tag":"direct","protocol":"freedom"}]},
	 {"remarks":"Hy2","outbounds":[{"tag":"h","protocol":"hysteria","settings":{}}]}
	]`
	nodes, e := managerParseProfile([]byte(body), "sub", "name")
	if e != nil || len(nodes) != 1 || nodes[0].Name != "Germany (WiFi)" || nodes[0].Outbound["tag"] != "vpn" || nodes[0].Transport != "grpc" || nodes[0].Security != "reality" {
		t.Fatalf("unexpected result: %+v %v", nodes, e)
	}
}
