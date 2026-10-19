package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func extraSetup(t *testing.T) string {
	dir := t.TempDir()
	t.Setenv("ROUTER_MANAGER_DIR", dir)
	t.Setenv("ROUTER_MANAGER_HWID", filepath.Join(dir, "hwid"))
	t.Setenv("ROUTER_MANAGER_EVENTS", filepath.Join(dir, "events.log"))
	return dir
}

func TestAutoRefreshSettingsAndNextFile(t *testing.T) {
	dir := extraSetup(t)
	if e := adapterAutoRefreshSet(6); e != nil {
		t.Fatal(e)
	}
	info := adapterAutoRefreshInfoLoad()
	if info.Hours != 6 || info.Next <= info.Last {
		t.Fatalf("unexpected info %+v", info)
	}
	b, e := os.ReadFile(filepath.Join(dir, "refresh.next"))
	if e != nil || strings.TrimSpace(string(b)) != strconv.FormatInt(info.Next, 10) {
		t.Fatalf("next file %q %v", b, e)
	}
	// Not due yet: nothing runs.
	if ran, e := adapterAutoRefresh(); ran || e != nil {
		t.Fatalf("ran=%v err=%v", ran, e)
	}
	if e := adapterAutoRefreshSet(0); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, "refresh.next")); e == nil {
		t.Fatal("next file must be removed when disabled")
	}
	if adapterAutoRefreshSet(managerMaxRefreshHours+1) == nil {
		t.Fatal("hours above the maximum must be rejected")
	}
}

func TestEventLogIsBoundedAndSafe(t *testing.T) {
	extraSetup(t)
	for i := 0; i < 400; i++ {
		adapterLogEvent("ping-all", nil, "vless://secret@host:443 line "+strconv.Itoa(i))
	}
	b, _ := os.ReadFile(adapterEventsPath())
	if len(b) > 40000 || strings.Contains(string(b), "vless://") {
		t.Fatalf("log not bounded or leaks link: %d bytes", len(b))
	}
}

func TestBackupRoundTrip(t *testing.T) {
	extraSetup(t)
	src := `[Interface]
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Address = 10.0.0.2/32
[Peer]
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
Endpoint = wg.example.com:10700
AllowedIPs = 0.0.0.0/0
`
	if _, e := ManagerAction("profile-import", mustJSON(managerInput{Name: "WG", Content: src})); e != nil {
		t.Fatal(e)
	}
	if _, e := ManagerAction("subscription-add", mustJSON(managerInput{Name: "Main", URL: "https://sub.example.com/abc", FetchMode: "auto"})); e != nil {
		t.Fatal(e)
	}
	exp, e := adapterBackupExport()
	if e != nil || len(exp.Subscription) != 1 || len(exp.Manual) != 1 {
		t.Fatalf("export %+v %v", exp, e)
	}
	raw, _ := json.Marshal(exp)
	// Restore into an empty store.
	extraSetup(t)
	added, e := adapterBackupImport(raw)
	if e != nil || added != 2 {
		t.Fatalf("import added=%d err=%v", added, e)
	}
	s, _ := managerLoad()
	if len(s.Subscriptions) != 2 {
		t.Fatalf("subscriptions %d", len(s.Subscriptions))
	}
	// Importing twice must not duplicate the URL subscription.
	added, e = adapterBackupImport(raw)
	if e != nil || added != 0 {
		t.Fatalf("second import added=%d err=%v", added, e)
	}
	if _, e := adapterBackupImport([]byte(`{"format":"other"}`)); e == nil {
		t.Fatal("foreign format must be rejected")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
