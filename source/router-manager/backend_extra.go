package main

// Panel extras: scheduled refresh, bulk latency test, a small event log kept in
// RAM, device information and settings backup. Nothing here stores secrets in
// the event log, and nothing writes to flash unless the user's data changes.
import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const managerClockFloor = 1767225600 // 2026-01-01, same plausibility guard as xrayctl.sh
const managerMaxRefreshHours = 168

type ManagerSettings struct {
	RefreshHours int   `json:"refreshHours,omitempty"`
	LastAuto     int64 `json:"lastAuto,omitempty"`
}

type adapterAutoRefreshInfo struct {
	Hours int   `json:"hours"`
	Last  int64 `json:"last,omitempty"`
	Next  int64 `json:"next,omitempty"`
}

type adapterDevice struct {
	HWID  string `json:"hwid,omitempty"`
	Model string `json:"model"`
}

func adapterNow() int64 { return time.Now().Unix() }

func managerSettingsUpdate(fn func(*ManagerSettings)) error {
	unlock, e := managerLock()
	if e != nil {
		return e
	}
	defer unlock()
	s, e := managerLoad()
	if e != nil {
		return e
	}
	fn(&s.Settings)
	return managerSave(s)
}

func adapterRefreshNextPath() string { return filepath.Join(managerDirectory(), "refresh.next") }

// The shell watchdog only reads this one number; the Go manager starts when due.
func adapterWriteRefreshNext(hours int, from int64) {
	path := adapterRefreshNextPath()
	if hours <= 0 {
		os.Remove(path)
		return
	}
	_ = adapterAtomic(path, []byte(strconv.FormatInt(from+int64(hours)*3600, 10)+"\n"))
}

func adapterAutoRefreshInfoLoad() adapterAutoRefreshInfo {
	info := adapterAutoRefreshInfo{}
	s, e := managerLoad()
	if e != nil {
		return info
	}
	info.Hours, info.Last = s.Settings.RefreshHours, s.Settings.LastAuto
	if info.Hours > 0 {
		info.Next = info.Last + int64(info.Hours)*3600
	}
	return info
}

func adapterAutoRefreshSet(hours int) error {
	if hours < 0 || hours > managerMaxRefreshHours {
		return errors.New("invalid_json")
	}
	now := adapterNow()
	if e := managerSettingsUpdate(func(s *ManagerSettings) {
		s.RefreshHours = hours
		if hours > 0 {
			s.LastAuto = now // first scheduled run is one interval from now
		}
	}); e != nil {
		return e
	}
	adapterWriteRefreshNext(hours, now)
	return nil
}

// adapterAutoRefresh refreshes every subscription when the interval has passed.
// It reports whether anything ran, so a not-due check never rewrites flash.
func adapterAutoRefresh() (bool, error) {
	now := adapterNow()
	if now < managerClockFloor {
		return false, nil
	}
	s, e := managerLoad()
	if e != nil {
		return false, e
	}
	hours := s.Settings.RefreshHours
	if hours <= 0 {
		os.Remove(adapterRefreshNextPath())
		return false, nil
	}
	if now < s.Settings.LastAuto+int64(hours)*3600 {
		return false, nil
	}
	b, _ := json.Marshal(managerInput{ID: "all"})
	_, e = ManagerAction("subscription-refresh", b)
	if e != nil {
		// Try again at the next interval rather than hammering a broken provider.
		_ = managerSettingsUpdate(func(s *ManagerSettings) { s.LastAuto = now })
		adapterWriteRefreshNext(hours, now)
		return true, e
	}
	_ = managerSettingsUpdate(func(s *ManagerSettings) { s.LastAuto = now })
	adapterWriteRefreshNext(hours, now)
	return true, nil
}

// adapterPingAll measures TCP connect time to every server (or one
// subscription's servers) with a small worker pool and writes latency.json once.
func adapterPingAll(subID string) (total, ok int, e error) {
	unlock, e := managerLock()
	if e != nil {
		return 0, 0, e
	}
	s, e := managerLoad()
	unlock()
	if e != nil {
		return 0, 0, e
	}
	type job struct {
		id  string
		out map[string]any
	}
	jobs := []job{}
	known := map[string]bool{}
	for _, sub := range s.Subscriptions {
		for _, n := range sub.Nodes {
			known[n.ID] = true
			if subID == "" || sub.ID == subID {
				jobs = append(jobs, job{n.ID, n.Outbound})
			}
		}
	}
	if subID != "" && len(jobs) == 0 {
		return 0, 0, errors.New("subscription_not_found")
	}
	results := make(map[string]ManagerLatencyResult, len(jobs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	queue := make(chan job)
	workers := 8
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{}
			for j := range queue {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				r := managerMeasureTCPTarget(ctx, j.out, net.DefaultResolver.LookupIP, dialer.DialContext)
				cancel()
				mu.Lock()
				results[j.id] = r
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		queue <- j
	}
	close(queue)
	wg.Wait()
	latencies := adapterLatencies()
	for id := range latencies {
		if !known[id] {
			delete(latencies, id)
		}
	}
	for id, r := range results {
		latencies[id] = r
		if r.Status == "ok" {
			ok++
		}
	}
	if e = adapterWriteJSON(filepath.Join(managerDirectory(), "latency.json"), latencies); e != nil {
		return len(jobs), ok, e
	}
	return len(jobs), ok, nil
}

// ---- event log (tmpfs, bounded, no secrets) ----

func adapterEventsPath() string {
	if p := os.Getenv("ROUTER_MANAGER_EVENTS"); p != "" {
		return p
	}
	return "/tmp/xd20-manager-events.log"
}

func adapterEventSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == '|' || r == 127 {
			return ' '
		}
		return r
	}, managerSafeName(s))
	r := []rune(s)
	if len(r) > 160 {
		s = string(r[:160])
	}
	return s
}

func adapterLogEvent(action string, err error, detail string) {
	path := adapterEventsPath()
	line := strconv.FormatInt(adapterNow(), 10) + "|" + adapterEventSafe(action) + "|"
	if err == nil {
		line += "ok|" + adapterEventSafe(detail)
	} else {
		line += "error|" + adapterEventSafe(err.Error())
	}
	old, _ := os.ReadFile(path)
	if len(old) > 16384 {
		lines := strings.Split(strings.TrimRight(string(old), "\n"), "\n")
		if len(lines) > 120 {
			lines = lines[len(lines)-120:]
		}
		old = []byte(strings.Join(lines, "\n") + "\n")
	}
	_ = os.WriteFile(path, append(old, []byte(line+"\n")...), 0o600)
}

// ---- device information ----

func adapterDeviceInfo() adapterDevice {
	return adapterDevice{HWID: managerHWID(), Model: "HONOR Router 3 XD20"}
}

// ---- settings backup ----

type adapterBackupSub struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	FetchMode string `json:"fetchMode"`
}
type adapterBackupManual struct {
	Name  string        `json:"name"`
	Nodes []ManagerNode `json:"nodes"`
}
type adapterBackup struct {
	Format       string                `json:"format"`
	Created      int64                 `json:"created"`
	RefreshHours int                   `json:"refreshHours,omitempty"`
	Subscription []adapterBackupSub    `json:"subscriptions"`
	Manual       []adapterBackupManual `json:"manual,omitempty"`
}

const adapterBackupFormat = "xd20-backup-1"

func adapterBackupExport() (*adapterBackup, error) {
	s, e := managerLoad()
	if e != nil {
		return nil, e
	}
	b := &adapterBackup{Format: adapterBackupFormat, Created: adapterNow(), RefreshHours: s.Settings.RefreshHours, Subscription: []adapterBackupSub{}}
	for _, sub := range s.Subscriptions {
		if sub.URL != "" {
			b.Subscription = append(b.Subscription, adapterBackupSub{sub.Name, sub.URL, sub.FetchMode})
		} else if sub.Kind == "import" && len(sub.Nodes) > 0 {
			b.Manual = append(b.Manual, adapterBackupManual{sub.Name, sub.Nodes})
		}
	}
	return b, nil
}

func adapterBackupNodeOK(n ManagerNode) bool {
	switch n.Protocol {
	case "vless", "vmess", "trojan", "shadowsocks":
		if _, _, ok := managerTCPAddress(n.Outbound); !ok {
			return false
		}
	case "wireguard":
		settings, ok := n.Outbound["settings"].(map[string]any)
		if !ok {
			return false
		}
		if k, _ := settings["secretKey"].(string); k == "" {
			return false
		}
		if p, _ := settings["peers"].([]any); len(p) != 1 {
			return false
		}
	default:
		return false
	}
	raw, e := json.Marshal(n.Outbound)
	return e == nil && len(raw) <= 16384
}

// adapterBackupImport adds subscriptions and manual profiles that are not
// already present. Existing data is never replaced or removed.
func adapterBackupImport(raw json.RawMessage) (added int, e error) {
	var b adapterBackup
	if len(raw) == 0 || json.Unmarshal(raw, &b) != nil || b.Format != adapterBackupFormat {
		return 0, errors.New("backup_invalid")
	}
	if b.RefreshHours < 0 || b.RefreshHours > managerMaxRefreshHours {
		return 0, errors.New("backup_invalid")
	}
	unlock, e := managerLock()
	if e != nil {
		return 0, e
	}
	defer unlock()
	s, e := managerLoad()
	if e != nil {
		return 0, e
	}
	have := map[string]bool{}
	manual := map[string]bool{}
	for _, sub := range s.Subscriptions {
		if sub.URL != "" {
			have[sub.URL] = true
		} else {
			manual[sub.Name] = true
		}
	}
	for _, item := range b.Subscription {
		if have[item.URL] {
			continue
		}
		if len(s.Subscriptions) >= managerMaxSubs {
			return added, errors.New("subscription_limit")
		}
		if e = managerValidateURL(item.URL); e != nil {
			return added, e
		}
		mode, e := managerMode(item.FetchMode)
		if e != nil {
			return added, e
		}
		id, e := managerRandomID()
		if e != nil {
			return added, e
		}
		name := managerSafeName(item.Name)
		if name == "" {
			name = "Subscription"
		}
		s.Subscriptions = append(s.Subscriptions, ManagerSubscription{ID: id, Name: name, URL: item.URL, FetchMode: mode, Kind: "subscription", Status: "not_refreshed", Nodes: []ManagerNode{}})
		have[item.URL] = true
		added++
	}
	for _, item := range b.Manual {
		if manual[managerSafeName(item.Name)] {
			continue
		}
		if len(s.Subscriptions) >= managerMaxSubs {
			return added, errors.New("subscription_limit")
		}
		id, e := managerRandomID()
		if e != nil {
			return added, e
		}
		nodes := []ManagerNode{}
		for _, n := range item.Nodes {
			if !adapterBackupNodeOK(n) {
				continue
			}
			n.Outbound["tag"] = "vpn"
			fresh, e := managerFinishNode(id, n.Name, n.Protocol, n.Transport, n.Security, n.Outbound)
			if e != nil {
				continue
			}
			nodes = append(nodes, fresh)
		}
		if len(nodes) == 0 {
			continue
		}
		if managerNodeCount(s)+len(nodes) > managerMaxNodes {
			return added, errors.New("node_limit")
		}
		name := managerSafeName(item.Name)
		if name == "" {
			name = "Imported profile"
		}
		s.Subscriptions = append(s.Subscriptions, ManagerSubscription{ID: id, Name: name, FetchMode: "direct", Kind: "import", Status: "ready", Updated: adapterNow(), Nodes: nodes})
		added++
	}
	if b.RefreshHours > 0 && s.Settings.RefreshHours == 0 {
		s.Settings.RefreshHours = b.RefreshHours
		s.Settings.LastAuto = adapterNow()
	}
	if e = managerSave(s); e != nil {
		return added, e
	}
	if s.Settings.RefreshHours > 0 {
		adapterWriteRefreshNext(s.Settings.RefreshHours, s.Settings.LastAuto)
	}
	return added, nil
}
