package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type adapterFixture struct {
	dir    string
	oldID  string
	newID  string
	oldSub string
	newSub string
	config []byte
}

func adapterTestFixture(t *testing.T) adapterFixture {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("ROUTER_MANAGER_DIR", filepath.Join(dir, "store"))
	t.Setenv("ROUTER_MANAGER_CONFIG", filepath.Join(dir, "data", "xray.json"))
	if e := os.MkdirAll(adapterDataDirectory(), 0700); e != nil {
		t.Fatal(e)
	}
	write := func(name, content string) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(adapterDataDirectory(), name), []byte(content), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("mode", "selective\n")
	write("autostart.enabled", "1\n")
	write("httpd-private.conf", "A:192.168.3.0/24\n/:old:OriginalTest9\n")
	oldSpawn, oldRunning := adapterSpawn, adapterRuntimeRunning
	adapterSpawn = func(string, ...string) error { return nil }
	adapterRuntimeRunning = func() bool { return true }
	t.Cleanup(func() { adapterSpawn, adapterRuntimeRunning = oldSpawn, oldRunning })
	oldOut := map[string]any{"tag": "vpn", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "old.example", "port": float64(443), "users": []any{map[string]any{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}}}}}}
	newOut := map[string]any{"tag": "profile", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "new.example", "port": float64(443), "users": []any{map[string]any{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "encryption": "none"}}}}}}
	f := adapterFixture{dir: dir, oldID: "oldnode", newID: "newnode", oldSub: "oldsub", newSub: "newsub"}
	s := &ManagerStore{Version: 1, SelectedID: f.oldID, Domains: []string{"example.com"}, Subscriptions: []ManagerSubscription{
		{ID: f.oldSub, Name: "Old", Kind: "subscription", URL: "https://provider.example/private-token", FetchMode: "auto", Status: "ready", Nodes: []ManagerNode{{ID: f.oldID, Name: "Old server", Protocol: "vless", Outbound: oldOut}}},
		{ID: f.newSub, Name: "New", Kind: "import", FetchMode: "direct", Status: "ready", Nodes: []ManagerNode{{ID: f.newID, Name: "New server", Protocol: "vless", Outbound: newOut}}},
	}}
	if e := managerSave(s); e != nil {
		t.Fatal(e)
	}
	c := map[string]any{"outbounds": []any{oldOut, map[string]any{"tag": "direct", "protocol": "freedom"}}, "inbounds": []any{map[string]any{"tag": "tun", "protocol": "tun"}}, "routing": map[string]any{"rules": []any{map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "direct"}}}}
	f.config, _ = json.Marshal(c)
	if e := os.WriteFile(adapterConfigPath(), f.config, 0600); e != nil {
		t.Fatal(e)
	}
	return f
}
func adapterTestQueue(t *testing.T, f adapterFixture) *adapterPending {
	t.Helper()
	p, e := adapterQueue(f.newSub, f.newID)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestAdapterQueueDoesNotSelectOrReplaceLiveConfig(t *testing.T) {
	f := adapterTestFixture(t)
	var script string
	var args []string
	adapterSpawn = func(s string, a ...string) error { script, args = s, a; return nil }
	p := adapterTestQueue(t, f)
	if script != "/data/xray-test/xray-switch.sh" || len(args) != 1 || args[0] != p.JobID {
		t.Fatal("worker is not fixed or bound to job")
	}
	selected, _ := ManagerCurrentID()
	if selected != f.oldID {
		t.Fatal("candidate prematurely selected")
	}
	live, _ := os.ReadFile(adapterConfigPath())
	if !bytes.Equal(live, f.config) {
		t.Fatal("queue changed live config")
	}
	backup, _ := os.ReadFile(adapterSwitchPath("backup.json"))
	if !bytes.Equal(backup, f.config) {
		t.Fatal("backup differs from exact original")
	}
	marker, _ := os.ReadFile(adapterSwitchPath("pending.id"))
	if string(marker) != p.JobID+"\n" {
		t.Fatal("native supervisor binding missing")
	}
	b, _ := os.ReadFile(adapterSwitchPath("candidate.json"))
	c, e := adapterJSONConfig(b)
	if e != nil {
		t.Fatal(e)
	}
	outs := c["outbounds"].([]any)
	if outs[0].(map[string]any)["tag"] != "vpn" || outs[1].(map[string]any)["tag"] != "direct" {
		t.Fatal("outbound tags changed")
	}
	ins := c["inbounds"].([]any)
	socks := ins[len(ins)-1].(map[string]any)
	if socks["listen"] != "127.0.0.1" || socks["port"] != float64(10809) {
		t.Fatal("probe listener not loopback")
	}
	rules := c["routing"].(map[string]any)["rules"].([]any)
	if rules[0].(map[string]any)["outboundTag"] != "vpn" {
		t.Fatal("probe might use a direct catchall")
	}
}
func TestAdapterOnlyInstalledCandidateCommitsAndPublishesSafeState(t *testing.T) {
	f := adapterTestFixture(t)
	p := adapterTestQueue(t, f)
	if e := adapterCommit(p.JobID); e == nil || e.Error() != "candidate_not_installed" {
		t.Fatal("uninstalled candidate committed")
	}
	b, _ := os.ReadFile(adapterSwitchPath("candidate.json"))
	if e := adapterAtomic(adapterConfigPath(), b); e != nil {
		t.Fatal(e)
	}
	if e := adapterCommit(p.JobID); e != nil {
		t.Fatal(e)
	}
	id, _ := ManagerCurrentID()
	if id != f.newID {
		t.Fatal("verified candidate not selected")
	}
	if _, e := os.Stat(adapterSwitchPath("pending.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("pending guard not cleared")
	}
	if _, e := os.Stat(adapterSwitchPath("pending.id")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("native binding not cleared")
	}
	pub, _ := os.ReadFile(filepath.Join(managerDirectory(), "public-state.json"))
	for _, secret := range []string{"private-token", "old.example", "new.example", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "OriginalTest9", "outbound", "URL"} {
		if bytes.Contains(pub, []byte(secret)) {
			t.Fatalf("public state leaks %s", secret)
		}
	}
	var state adapterPublicState
	if json.Unmarshal(pub, &state) != nil || state.Active.NodeID != f.newID || state.Job.Status != "done" || state.Access.Login != "old" {
		t.Fatal("public commit state wrong")
	}
}
func TestAdapterRollbackAndBootRecoveryRestoreExactPreviousState(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "boot"}[recovery], func(t *testing.T) {
			f := adapterTestFixture(t)
			p := adapterTestQueue(t, f)
			candidate, _ := os.ReadFile(adapterSwitchPath("candidate.json"))
			_ = adapterAtomic(adapterConfigPath(), candidate)
			_ = adapterRestoreSelection(f.newID) // interruption after a partial commit
			var e error
			if recovery {
				e = adapterRecover()
			} else {
				e = adapterRollback(p.JobID)
			}
			if e != nil {
				t.Fatal(e)
			}
			live, _ := os.ReadFile(adapterConfigPath())
			selected, _ := ManagerCurrentID()
			if !bytes.Equal(live, f.config) || selected != f.oldID {
				t.Fatal("previous private config/selection not restored")
			}
			job, _ := adapterJobLoad()
			if job.Status != "rolled_back" {
				t.Fatal("recovery not reported")
			}
		})
	}
}
func TestAdapterFailedWorkerLeavesOriginalConfigAndNoPending(t *testing.T) {
	f := adapterTestFixture(t)
	adapterSpawn = func(string, ...string) error { return errors.New("https://secret.example/token") }
	if _, e := adapterQueue(f.newSub, f.newID); e == nil || e.Error() != "worker_unavailable" {
		t.Fatal("spawn error not sanitized")
	}
	live, _ := os.ReadFile(adapterConfigPath())
	id, _ := ManagerCurrentID()
	if !bytes.Equal(live, f.config) || id != f.oldID {
		t.Fatal("spawn failure changed current state")
	}
	if p, e := adapterPendingLoad(); p != nil || e != nil {
		t.Fatal("spawn failure left a stale guard")
	}
}
func TestAdapterGuardBindsJobAndBlocksMutation(t *testing.T) {
	f := adapterTestFixture(t)
	p := adapterTestQueue(t, f)
	if _, e := adapterQueue(f.newSub, f.newID); e == nil {
		t.Fatal("second switch admitted")
	}
	if _, e := adapterAction([]byte(`{"action":"remove","subscriptionId":"newsub"}`)); e == nil || e.Error() != "switch_in_progress" {
		t.Fatal("mutation allowed during switch")
	}
	if e := adapterCommit("differentjob"); e == nil {
		t.Fatal("wrong worker can commit")
	}
	if e := adapterJobSave(p, "probing", "https://private.example/secret uuid"); e != nil {
		t.Fatal(e)
	}
	s, _ := adapterCache()
	pub, _ := json.Marshal(s)
	if bytes.Contains(pub, []byte("private.example")) || bytes.Contains(pub, []byte("secret uuid")) {
		t.Fatal("worker message leaked")
	}
	_ = os.WriteFile(adapterSwitchPath("pending.id"), []byte("differentjob\n"), 0600)
	if _, e := adapterPendingLoad(); e == nil {
		t.Fatal("supervisor/job binding ignored")
	}
}
func TestAdapterToggleTransactionsAndRecovery(t *testing.T) {
	f := adapterTestFixture(t)
	p, e := adapterQueueToggle(false)
	if e != nil {
		t.Fatal(e)
	}
	if p.Kind != "toggle" || !p.PreviousEnabled || !p.PreviousAutostart || p.PreviousDisabled {
		t.Fatal("previous toggle flags not recorded")
	}
	if e := adapterCompleteToggle(p.JobID, false); e == nil {
		t.Fatal("unapplied toggle committed")
	}
	_ = adapterSetFlag("vpn.disabled", true)
	adapterRuntimeRunning = func() bool { return false }
	if e := adapterCompleteToggle(p.JobID, false); e != nil {
		t.Fatal(e)
	}
	vpn, _, _ := adapterVPNState()
	if vpn.Enabled || vpn.Running || vpn.Autostart {
		t.Fatal("disabled state wrong")
	}
	if yes, _ := adapterFlag("autostart.enabled"); !yes {
		t.Fatal("web boot flag removed")
	}
	if _, e := adapterQueue(f.newSub, f.newID); e == nil || e.Error() != "enable_vpn_before_switch" {
		t.Fatal("switch silently enables VPN")
	}
	p, e = adapterQueueToggle(true)
	if e != nil {
		t.Fatal(e)
	}
	_ = adapterSetFlag("vpn.disabled", false) // interrupted enable
	if e := adapterRecover(); e != nil {
		t.Fatal(e)
	}
	if disabled, _ := adapterFlag("vpn.disabled"); !disabled {
		t.Fatal("boot did not restore prior disabled setting")
	}
	if yes, _ := adapterFlag("autostart.enabled"); !yes {
		t.Fatal("boot recovery killed panel autostart")
	}
}
func TestAdapterSettingsAreExplicitAtomicAndSecretFree(t *testing.T) {
	_ = adapterTestFixture(t)
	original, _ := os.ReadFile(filepath.Join(adapterDataDirectory(), "httpd-private.conf"))
	for _, bad := range []string{"short", "newline\nsecret9", "colon:pass9", "space pass9", "$(touch /tmp/bad)"} {
		if e := adapterSettings("admin", bad); e == nil {
			t.Fatalf("invalid password %q admitted", bad)
		}
	}
	after, _ := os.ReadFile(filepath.Join(adapterDataDirectory(), "httpd-private.conf"))
	if !bytes.Equal(original, after) {
		t.Fatal("invalid settings altered authentication")
	}
	var called string
	adapterSpawn = func(s string, a ...string) error {
		called = s
		if len(a) != 0 {
			t.Fatal("credentials passed as argv")
		}
		return nil
	}
	if e := adapterSettings("new-admin", "NewSafeTest9"); e != nil {
		t.Fatal(e)
	}
	after, _ = os.ReadFile(filepath.Join(adapterDataDirectory(), "httpd-private.conf"))
	if !bytes.Contains(after, []byte("A:192.168.3.0/24\n")) || !bytes.Contains(after, []byte("/:new-admin:NewSafeTest9")) {
		t.Fatal("auth rule or other directives lost")
	}
	if called != "/data/xray-test/xray-web-reload.sh" {
		t.Fatal("reload script not fixed")
	}
	cache, _ := os.ReadFile(filepath.Join(managerDirectory(), "public-state.json"))
	if bytes.Contains(cache, []byte("NewSafeTest9")) {
		t.Fatal("auth secret published")
	}
	adapterSpawn = func(string, ...string) error { return errors.New("fail") }
	if e := adapterSettings("bad-new", "AnotherTest9"); e == nil {
		t.Fatal("reload failure ignored")
	}
	afterFail, _ := os.ReadFile(filepath.Join(adapterDataDirectory(), "httpd-private.conf"))
	if !bytes.Equal(after, afterFail) {
		t.Fatal("reload failure did not restore prior auth")
	}
}
func TestAdapterCGIBoundsOriginAndUnknownFields(t *testing.T) {
	_ = adapterTestFixture(t)
	valid := `{"action":"state"}`
	base := map[string]string{"REQUEST_METHOD": "POST", "HTTP_HOST": "192.168.3.1:8088", "REMOTE_ADDR": "192.168.3.3", "HTTP_ORIGIN": "http://192.168.3.1:8088", "HTTP_X_XD20_UI": "manager-v1", "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": "18"}
	for _, tc := range []struct {
		name, key, value string
		status           string
	}{
		{"origin", "HTTP_ORIGIN", "http://evil.example", "403"}, {"header", "HTTP_X_XD20_UI", "bad", "403"}, {"host", "HTTP_HOST", "evil.example:8088", "403"}, {"guest", "REMOTE_ADDR", "192.168.4.3", "403"}, {"length", "CONTENT_LENGTH", "16385", "413"}, {"type", "CONTENT_TYPE", "text/plain", "415"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			for k, v := range base {
				env[k] = v
			}
			env[tc.key] = tc.value
			var out bytes.Buffer
			if code := adapterCGI(strings.NewReader(valid), &out, func(k string) string { return env[k] }); code == 0 || !strings.HasPrefix(out.String(), "Status: "+tc.status) {
				t.Fatal("CGI gate bypass")
			}
		})
	}
	for _, input := range []string{`{"action":"state","unknown":true}`, `{"action":"state"} {}`, `null`} {
		if _, e := adapterAction([]byte(input)); e == nil {
			t.Fatalf("malformed %s accepted", input)
		}
	}
}
func TestAdapterCandidatePreservesNonVPNAndRefusesListenerCollision(t *testing.T) {
	f := adapterTestFixture(t)
	c, _ := adapterJSONConfig(f.config)
	out, _ := ManagerGetOutbound(f.newID)
	c["inbounds"] = []any{map[string]any{"tag": "other", "listen": "0.0.0.0", "port": float64(10809), "protocol": "socks"}}
	if e := adapterCandidate(c, out); e == nil {
		t.Fatal("conflicting listener accepted")
	}
}
func TestAdapterSeedMatchesCurrentOutboundWithoutTagAndBinding(t *testing.T) {
	_ = adapterTestFixture(t)
	_ = os.Remove(filepath.Join(managerDirectory(), "subscriptions.json"))
	content := `vless://11111111-2222-3333-4444-555555555555@seed.example:443?security=tls&type=tcp&sni=seed.example#Known`
	nodes, e := managerParseProfile([]byte(content), "initial", "Initial")
	if e != nil {
		t.Fatal(e)
	}
	current := adapterNormalizeOutbound(nodes[0].Outbound)
	current["tag"] = "vpn"
	stream := current["streamSettings"].(map[string]any)
	stream["sockopt"] = map[string]any{"interface": "eth0"}
	in := map[string]any{"subscriptions": []ManagerSeedSubscription{{Name: "Initial", URL: "https://provider.example/private-token", Content: content, FetchMode: "auto"}}, "currentConfig": map[string]any{"outbounds": []any{current}}, "domains": []string{"example.com"}}
	b, _ := json.Marshal(in)
	if e := adapterSeed(b); e != nil {
		t.Fatal(e)
	}
	selected, e := ManagerSelectedOutbound()
	if e != nil || !reflect.DeepEqual(adapterNormalizeOutbound(selected), adapterNormalizeOutbound(current)) {
		t.Fatal("seed did not recognize current working endpoint")
	}
	firstID, _ := ManagerCurrentID()
	if e := adapterSeed(b); e != nil {
		t.Fatal(e)
	}
	secondID, _ := ManagerCurrentID()
	if firstID != secondID {
		t.Fatal("seed replaced existing store")
	}
}

func TestAdapterSeedFallbackPreservesExactWorkingOutbound(t *testing.T) {
	_ = adapterTestFixture(t)
	_ = os.Remove(filepath.Join(managerDirectory(), "subscriptions.json"))
	content := `vless://11111111-2222-3333-4444-555555555555@seed.example:443?security=tls&type=tcp&sni=seed.example#Imported`
	nodes, e := managerParseProfile([]byte(content), "initial", "Initial")
	if e != nil {
		t.Fatal(e)
	}
	current := adapterNormalizeOutbound(nodes[0].Outbound)
	current["tag"] = "vpn"
	current["mux"] = map[string]any{"enabled": false, "concurrency": float64(3)}
	b, _ := json.Marshal(map[string]any{"subscriptions": []ManagerSeedSubscription{{Name: "Initial", Content: content}}, "currentConfig": map[string]any{"outbounds": []any{current}}})
	if e = adapterSeed(b); e != nil {
		t.Fatal(e)
	}
	selected, e := ManagerSelectedOutbound()
	if e != nil || !reflect.DeepEqual(selected, current) {
		t.Fatal("fallback did not retain the exact known working outbound")
	}
	state, e := adapterState()
	if e != nil || state.Active.Label != "Текущий сервер" || state.Subscriptions[0].NodeCount != 2 {
		t.Fatal("fallback is not visible as the actual active node")
	}
}

func TestAdapterWarningAndFailureMessagesAreTranslatedAndSecretFree(t *testing.T) {
	_ = adapterTestFixture(t)
	store, _ := managerLoad()
	store.Subscriptions[0].Warning = "active_server_from_previous_update,some_entries_unsupported_or_duplicate"
	store.Subscriptions[0].Status = "fetch_timeout"
	store.Subscriptions[0].LastFetchPath = "vpn"
	store.Subscriptions[1].Status = "provider_device_registration_required"
	if e := managerSave(store); e != nil {
		t.Fatal(e)
	}
	state, e := adapterState()
	if e != nil {
		t.Fatal(e)
	}
	if len(state.Subscriptions[0].Warnings) != 2 || !strings.Contains(state.Subscriptions[0].Warnings[0], "предыдущего обновления") || state.Subscriptions[0].Error == "" || state.Subscriptions[0].LastFetchPath != "vpn" {
		t.Fatal("refresh warning/error/path not mapped")
	}
	if !strings.Contains(state.Subscriptions[1].Error, "регистрацию") {
		t.Fatal("provider requirement hidden")
	}
}
