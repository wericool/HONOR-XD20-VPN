package main

// The adapter owns the HTTP contract and the single-core switch transaction.
// Subscription parsing/fetching lives in backend_*.go. No secret is returned by
// this file: candidates, backups and URLs remain in the private store.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const adapterVersion = "xd20-manager-1"
const adapterCGILimit = 16384

type adapterInput struct {
	Action         string `json:"action"`
	ID             string `json:"id,omitempty"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	NodeID         string `json:"nodeId,omitempty"`
	Name           string `json:"name,omitempty"`
	URL            string `json:"url,omitempty"`
	Content        string `json:"content,omitempty"`
	FetchMode      string `json:"fetchMode,omitempty"`
	Login          string `json:"login,omitempty"`
	Password       string `json:"password,omitempty"`
	Enabled        *bool  `json:"enabled,omitempty"`
	Hours          *int   `json:"hours,omitempty"`
	Mode           string `json:"mode,omitempty"`
	// Backup is the settings file produced by "backup-export".
	Backup json.RawMessage `json:"backup,omitempty"`
}

type adapterJob struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	Message        string `json:"message"`
	SubscriptionID string `json:"subscriptionId"`
	NodeID         string `json:"nodeId"`
	UpdatedAt      int64  `json:"updatedAt"`
}

type adapterPending struct {
	JobID              string `json:"jobId"`
	NodeID             string `json:"nodeId"`
	SubscriptionID     string `json:"subscriptionId"`
	Mode               string `json:"mode"`
	PreviousSelectedID string `json:"previousSelectedID"`
	Kind               string `json:"kind"`
	Enabled            bool   `json:"enabled"`
	PreviousEnabled    bool   `json:"previousEnabled"`
	PreviousAutostart  bool   `json:"previousAutostart"`
	PreviousDisabled   bool   `json:"previousDisabled"`
	// TargetMode is set when a toggle job also changes the routing mode.
	TargetMode string `json:"targetMode,omitempty"`
}

type adapterVPN struct {
	Enabled   bool `json:"enabled"`
	Running   bool `json:"running"`
	Autostart bool `json:"autostart"`
}

type adapterPublicNode struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Protocol      string `json:"protocol"`
	Supported     bool   `json:"supported"`
	LatencyMs     *int64 `json:"latencyMs,omitempty"`
	LatencyStatus string `json:"latencyStatus,omitempty"`
	LatencyAt     int64  `json:"latencyAt,omitempty"`
}

type adapterPublicSub struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	Status        string              `json:"status"`
	FetchMode     string              `json:"fetchMode"`
	LastFetchPath string              `json:"lastFetchPath,omitempty"`
	SourceType    string              `json:"sourceType"`
	UpdatedAt     int64               `json:"updatedAt,omitempty"`
	NodeCount     int                 `json:"nodeCount"`
	ExpiresAt     int64               `json:"expiresAt,omitempty"`
	TotalBytes    int64               `json:"totalBytes,omitempty"`
	UsedBytes     int64               `json:"usedBytes,omitempty"`
	SkippedCount  int                 `json:"skippedCount"`
	Warnings      []string            `json:"warnings"`
	Error         string              `json:"error,omitempty"`
	Nodes         []adapterPublicNode `json:"nodes"`
}

type adapterActive struct {
	SubscriptionID string `json:"subscriptionId"`
	NodeID         string `json:"nodeId"`
	Label          string `json:"label"`
}

type adapterPublicState struct {
	OK            bool               `json:"ok"`
	Active        adapterActive      `json:"active"`
	Subscriptions []adapterPublicSub `json:"subscriptions"`
	Job           *adapterJob        `json:"job"`
	VPN           adapterVPN         `json:"vpn"`
	Access        struct {
		Login string `json:"login"`
	} `json:"access"`
	Device      adapterDevice          `json:"device"`
	AutoRefresh adapterAutoRefreshInfo `json:"autoRefresh"`
}

type adapterResponse struct {
	OK      bool                `json:"ok"`
	Message string              `json:"message,omitempty"`
	Error   string              `json:"error,omitempty"`
	JobID   string              `json:"jobId,omitempty"`
	State   *adapterPublicState `json:"state,omitempty"`
	Backup  *adapterBackup      `json:"backup,omitempty"`
	Probe   *ManagerProbeResult `json:"probe,omitempty"`
}

var adapterSpawn = adapterSpawnFixed
var adapterRuntimeRunning = adapterRuntimeRunningNative

func adapterRuntimeRunningNative() bool {
	b, e := adapterRead("/tmp/xd20-xray.pid", 128)
	if e != nil {
		return false
	}
	fields := strings.Fields(string(b))
	if len(fields) != 2 {
		return false
	}
	pid, e := strconv.Atoi(fields[0])
	if e != nil || pid <= 1 {
		return false
	}
	stamp, e := strconv.ParseUint(fields[1], 10, 64)
	if e != nil {
		return false
	}
	proc := "/proc/" + strconv.Itoa(pid)
	stat, e := adapterRead(proc+"/stat", 4096)
	if e != nil {
		return false
	}
	end := strings.LastIndex(string(stat), ") ")
	if end < 0 {
		return false
	}
	tail := strings.Fields(string(stat[end+2:]))
	if len(tail) < 20 || tail[19] != strconv.FormatUint(stamp, 10) {
		return false
	}
	exe, e := os.Readlink(proc + "/exe")
	return e == nil && exe == "/dev/xd20-xray/xray"
}
func adapterFlag(name string) (bool, error) {
	st, e := os.Lstat(filepath.Join(adapterDataDirectory(), name))
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil || !st.Mode().IsRegular() {
		return false, errors.New("runtime_mode_invalid")
	}
	return true, nil
}
func adapterVPNState() (adapterVPN, bool, error) {
	autostart, e := adapterFlag("autostart.enabled")
	if e != nil {
		return adapterVPN{}, false, e
	}
	disabled, e := adapterFlag("vpn.disabled")
	if e != nil {
		return adapterVPN{}, false, e
	}
	enabled := autostart && !disabled
	return adapterVPN{enabled, adapterRuntimeRunning(), enabled}, disabled, nil
}

func adapterConfigPath() string {
	if p := os.Getenv("ROUTER_MANAGER_CONFIG"); p != "" {
		return p
	}
	return "/data/xray-test/xray.json"
}
func adapterDataDirectory() string { return filepath.Dir(adapterConfigPath()) }
func adapterSwitchPath(name string) string {
	return filepath.Join(managerDirectory(), "switch", name)
}
func adapterRead(path string, limit int64) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() > limit {
		return nil, errors.New("private_file_unavailable")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("private_file_unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("private_file_unavailable")
	}
	return b, nil
}
func adapterEnsureDirectory(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return errors.New("private_directory_unavailable")
	}
	st, e := os.Lstat(path)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || os.Chmod(path, 0700) != nil {
		return errors.New("private_directory_unavailable")
	}
	return nil
}
func adapterSyncDirectory(path string) error {
	// Windows cannot fsync a directory; these sources are also tested there.
	if runtime.GOOS == "windows" {
		return nil
	}
	f, e := os.Open(path)
	if e != nil {
		return errors.New("private_write_failed")
	}
	defer f.Close()
	if f.Sync() != nil {
		return errors.New("private_write_failed")
	}
	return nil
}
func adapterAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if e := adapterEnsureDirectory(dir); e != nil {
		return e
	}
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return errors.New("private_write_failed")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return errors.New("private_write_failed")
	}
	f, e := os.CreateTemp(dir, ".manager-write-*")
	if e != nil {
		return errors.New("private_write_failed")
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil || os.Rename(name, path) != nil {
		return errors.New("private_write_failed")
	}
	return adapterSyncDirectory(dir)
}
func adapterWriteJSON(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return errors.New("private_write_failed")
	}
	return adapterAtomic(path, append(b, '\n'))
}
func adapterLock() (func(), error) {
	if e := adapterEnsureDirectory(managerDirectory()); e != nil {
		return nil, e
	}
	path := "/tmp/xd20-manager-adapter.lock"
	if os.Getenv("ROUTER_MANAGER_DIR") != "" {
		path = filepath.Join(managerDirectory(), ".adapter-lock")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if os.Mkdir(path, 0700) == nil {
			// The sites CGI uses this same EMPTY directory. Never add an
			// owner file or remove a non-empty directory recursively.
			return func() { _ = os.Remove(path) }, nil
		}
		if st, e := os.Lstat(path); e == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 && time.Since(st.ModTime()) > 2*time.Minute {
			if os.Remove(path) == nil {
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, errors.New("manager_busy")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func adapterPendingLoad() (*adapterPending, error) {
	path := adapterSwitchPath("pending.json")
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	b, e := adapterRead(path, 4096)
	if e != nil {
		return nil, errors.New("switch_state_invalid")
	}
	var p adapterPending
	if json.Unmarshal(b, &p) != nil || !adapterID(p.JobID) || (p.Mode != "selective" && p.Mode != "full" && p.Mode != "inverse") {
		return nil, errors.New("switch_state_invalid")
	}
	if p.TargetMode != "" && p.TargetMode != "selective" && p.TargetMode != "inverse" {
		return nil, errors.New("switch_state_invalid")
	}
	if p.Kind == "" {
		p.Kind = "switch"
	}
	if p.Kind != "switch" && p.Kind != "toggle" {
		return nil, errors.New("switch_state_invalid")
	}
	if p.Kind == "switch" && (!adapterID(p.NodeID) || !adapterID(p.SubscriptionID)) {
		return nil, errors.New("switch_state_invalid")
	}
	marker, e := adapterRead(adapterSwitchPath("pending.id"), 64)
	if e != nil || strings.TrimSpace(string(marker)) != p.JobID {
		return nil, errors.New("switch_state_invalid")
	}
	return &p, nil
}
func adapterID(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func adapterJobLoad() (*adapterJob, error) {
	path := filepath.Join(managerDirectory(), "job.json")
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	b, e := adapterRead(path, 4096)
	if e != nil {
		return nil, errors.New("switch_state_invalid")
	}
	var j adapterJob
	if json.Unmarshal(b, &j) != nil || !adapterID(j.ID) || !adapterJobStatus(j.Status) {
		return nil, errors.New("switch_state_invalid")
	}
	return &j, nil
}
func adapterJobStatus(s string) bool {
	switch s {
	case "queued", "running", "starting", "switching", "probing", "done", "failed", "rolled_back":
		return true
	}
	return false
}
func adapterJobMessage(status string) string {
	switch status {
	case "done":
		return "Сервер подключён и проверен."
	case "rolled_back":
		return "Новый сервер не подключился. Прежний профиль восстановлен."
	case "failed":
		return "Переключение не завершено. Повторный запуск восстановит прежний профиль."
	case "probing":
		return "Проверяю подключение нового сервера."
	default:
		return "Переключаю сервер. Дождись завершения проверки."
	}
}
func adapterJobSave(p *adapterPending, status string, _ string) error {
	if !adapterJobStatus(status) {
		return errors.New("invalid_job_status")
	}
	// The optional shell message is deliberately never copied into public JSON.
	// Worker logs may contain endpoint details; UI receives only fixed text.
	j := adapterJob{p.JobID, status, adapterJobMessage(status), p.SubscriptionID, p.NodeID, time.Now().Unix()}
	if p.Kind == "toggle" {
		if status == "done" {
			if p.Enabled {
				j.Message = "VPN включён. Выбранные сайты идут через текущий сервер."
			} else {
				j.Message = "VPN выключен. Интернет идёт напрямую; панель остаётся доступна."
			}
		} else if status == "rolled_back" {
			j.Message = "Действие не завершено. Прежнее состояние VPN восстановлено."
		} else {
			j.Message = "Меняю состояние VPN. Дождись завершения."
		}
	}
	return adapterWriteJSON(filepath.Join(managerDirectory(), "job.json"), j)
}
func adapterAccessLogin() string {
	b, e := adapterRead(filepath.Join(adapterDataDirectory(), "httpd-private.conf"), 8192)
	if e != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "/:") {
			parts := strings.SplitN(strings.TrimPrefix(line, "/:"), ":", 2)
			if len(parts) == 2 && adapterLogin(parts[0]) {
				return parts[0]
			}
		}
	}
	return ""
}
func adapterState() (*adapterPublicState, error) {
	raw, e := ManagerAction("state", nil)
	if e != nil {
		return nil, e
	}
	p, ok := raw.(PublicState)
	if !ok {
		return nil, errors.New("store_invalid")
	}
	s := &adapterPublicState{OK: true, Subscriptions: []adapterPublicSub{}}
	s.VPN, _, e = adapterVPNState()
	if e != nil {
		return nil, e
	}
	s.Access.Login = adapterAccessLogin()
	s.Device = adapterDeviceInfo()
	s.AutoRefresh = adapterAutoRefreshInfoLoad()
	latencies := adapterLatencies()
	for _, sub := range p.Subscriptions {
		kind := "subscription"
		if sub.Kind == "import" {
			kind = "manual"
		}
		pub := adapterPublicSub{ID: sub.ID, Name: sub.Name, Status: sub.Status, FetchMode: sub.FetchMode, LastFetchPath: sub.LastFetchPath, SourceType: kind, UpdatedAt: sub.Updated, NodeCount: sub.NodeCount, ExpiresAt: sub.Expires, TotalBytes: sub.TotalBytes, UsedBytes: sub.UsedBytes, SkippedCount: sub.SkippedCount, Warnings: []string{}, Nodes: []adapterPublicNode{}}
		if sub.LastFetchPath != "direct" && sub.LastFetchPath != "vpn" {
			pub.LastFetchPath = ""
		}
		for _, warning := range strings.Split(sub.Warning, ",") {
			if warning == "active_server_from_previous_update" {
				pub.Warnings = append(pub.Warnings, "Активный сервер сохранён из предыдущего обновления: текущий VPN продолжает работать.")
			} else if warning != "" {
				pub.Warnings = append(pub.Warnings, "Часть записей несовместима или повторяется. Доступные серверы сохранены.")
			}
		}
		if strings.HasPrefix(sub.Status, "provider_device_registration_required") {
			pub.Error = "Провайдер требует регистрацию приложения или устройства. Получи у него обычную подписку для роутера."
		} else if strings.HasPrefix(sub.Status, "provider_app_unsupported") {
			pub.Error = "Провайдер вернул сообщение «Программа не поддерживается» вместо серверов. Нужна обычная подписка для Xray или роутера."
		} else if strings.HasPrefix(sub.Status, "fetch_") || strings.Contains(sub.Status, "failed") || strings.Contains(sub.Status, "invalid") || strings.Contains(sub.Status, "node_limit") {
			pub.Error = "Не удалось обновить подписку. Сохранённые серверы остаются доступны."
		}
		for _, n := range p.Nodes {
			if n.SubscriptionID == sub.ID {
				node := adapterPublicNode{ID: n.ID, Label: n.Name, Protocol: n.Protocol, Supported: true}
				if latency, ok := latencies[n.ID]; ok {
					node.LatencyStatus, node.LatencyAt = latency.Status, latency.CheckedAt
					if latency.Status == "ok" {
						ms := latency.LatencyMS
						node.LatencyMs = &ms
					}
				}
				pub.Nodes = append(pub.Nodes, node)
				if n.ID == p.SelectedID {
					s.Active = adapterActive{sub.ID, n.ID, n.Name}
				}
			}
		}
		s.Subscriptions = append(s.Subscriptions, pub)
	}
	s.Job, e = adapterJobLoad()
	if e != nil {
		return nil, e
	}
	if pending, err := adapterPendingLoad(); err != nil {
		return nil, err
	} else if pending != nil && (s.Job == nil || s.Job.ID != pending.JobID) {
		s.Job = &adapterJob{pending.JobID, "running", adapterJobMessage("running"), pending.SubscriptionID, pending.NodeID, time.Now().Unix()}
	}
	return s, nil
}
func adapterCache() (*adapterPublicState, error) {
	s, e := adapterState()
	if e != nil {
		return nil, e
	}
	if e = adapterWriteJSON(filepath.Join(managerDirectory(), "public-state.json"), s); e != nil {
		return nil, e
	}
	return s, nil
}
func adapterLatencies() map[string]ManagerLatencyResult {
	latencies := map[string]ManagerLatencyResult{}
	b, e := adapterRead(filepath.Join(managerDirectory(), "latency.json"), 65536)
	if e != nil {
		return latencies
	}
	if json.Unmarshal(b, &latencies) != nil || len(latencies) > managerMaxNodes {
		return map[string]ManagerLatencyResult{}
	}
	for id, result := range latencies {
		if !adapterID(id) || result.Status != "ok" && result.Status != "timeout" && result.Status != "unsupported" || result.LatencyMS < 0 || result.LatencyMS > 60000 {
			delete(latencies, id)
		}
	}
	return latencies
}
func adapterPing(subID, nodeID string) error {
	if _, e := adapterNodeSubscription(nodeID, subID); e != nil {
		return e
	}
	result, e := ManagerMeasureTCP(nodeID)
	if e != nil {
		return e
	}
	raw, e := ManagerAction("state", nil)
	if e != nil {
		return e
	}
	latencies := adapterLatencies()
	known := map[string]bool{}
	for _, node := range raw.(PublicState).Nodes {
		known[node.ID] = true
	}
	for id := range latencies {
		if !known[id] {
			delete(latencies, id)
		}
	}
	latencies[nodeID] = result
	return adapterWriteJSON(filepath.Join(managerDirectory(), "latency.json"), latencies)
}
func adapterJSONConfig(b []byte) (map[string]any, error) {
	var c map[string]any
	if len(b) == 0 || len(b) > managerMaxBody || json.Unmarshal(b, &c) != nil || c == nil {
		return nil, errors.New("runtime_config_invalid")
	}
	if _, ok := c["outbounds"].([]any); !ok {
		return nil, errors.New("runtime_config_invalid")
	}
	return c, nil
}
func adapterCandidate(c map[string]any, outbound map[string]any) error {
	outs := c["outbounds"].([]any)
	count := 0
	for i, v := range outs {
		o, ok := v.(map[string]any)
		if ok && o["tag"] == "vpn" {
			b, e := json.Marshal(outbound)
			if e != nil {
				return errors.New("node_invalid")
			}
			var candidate map[string]any
			if json.Unmarshal(b, &candidate) != nil {
				return errors.New("node_invalid")
			}
			candidate["tag"] = "vpn"
			outs[i] = candidate
			count++
		}
	}
	if count != 1 {
		return errors.New("runtime_config_invalid")
	}
	c["outbounds"] = outs
	ins, _ := c["inbounds"].([]any)
	listenerExists := false
	for _, v := range ins {
		i, ok := v.(map[string]any)
		if ok && i["tag"] == "manager-socks" {
			if listenerExists {
				return errors.New("manager_listener_conflict")
			}
			if i["listen"] != "127.0.0.1" || i["protocol"] != "socks" || i["port"] != float64(10809) {
				return errors.New("manager_listener_conflict")
			}
			listenerExists = true
			continue
		}
		if i, ok := v.(map[string]any); ok && i["port"] == float64(10809) {
			return errors.New("manager_listener_conflict")
		}
	}
	if !listenerExists {
		c["inbounds"] = append(ins, map[string]any{"tag": "manager-socks", "listen": "127.0.0.1", "port": 10809, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}})
	}
	// Route this local listener through vpn even when the stock config contains
	// a broader direct rule. Rule priority is first match in Xray.
	routing, ok := c["routing"].(map[string]any)
	if !ok {
		routing = map[string]any{}
		c["routing"] = routing
	}
	rules, _ := routing["rules"].([]any)
	kept := []any{}
	for _, item := range rules {
		if r, ok := item.(map[string]any); ok && len(r) == 3 && r["type"] == "field" && r["outboundTag"] == "vpn" {
			if tags, ok := r["inboundTag"].([]any); ok && len(tags) == 1 && tags[0] == "manager-socks" {
				continue
			}
		}
		kept = append(kept, item)
	}
	routing["rules"] = append([]any{map[string]any{"type": "field", "inboundTag": []string{"manager-socks"}, "outboundTag": "vpn"}}, kept...)
	return nil
}
func adapterNodeSubscription(nodeID, subscriptionID string) (string, error) {
	raw, e := ManagerAction("state", nil)
	if e != nil {
		return "", e
	}
	for _, n := range raw.(PublicState).Nodes {
		if n.ID == nodeID && (subscriptionID == "" || n.SubscriptionID == subscriptionID) {
			return n.SubscriptionID, nil
		}
	}
	return "", errors.New("node_not_found")
}
func adapterQueue(subscriptionID, nodeID string) (*adapterPending, error) {
	if pending, e := adapterPendingLoad(); e != nil {
		return nil, e
	} else if pending != nil {
		return nil, errors.New("switch_in_progress")
	}
	if _, e := os.Lstat("/tmp/xd20-xray.switching"); !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("switch_in_progress")
	}
	vpn, disabled, e := adapterVPNState()
	if e != nil {
		return nil, e
	}
	if !vpn.Enabled {
		return nil, errors.New("enable_vpn_before_switch")
	}
	subscriptionID, e = adapterNodeSubscription(nodeID, subscriptionID)
	if e != nil {
		return nil, e
	}
	outbound, e := ManagerGetOutbound(nodeID)
	if e != nil {
		return nil, e
	}
	backup, e := adapterRead(adapterConfigPath(), managerMaxBody)
	if e != nil {
		return nil, e
	}
	candidate, e := adapterJSONConfig(backup)
	if e != nil {
		return nil, e
	}
	if e = adapterCandidate(candidate, outbound); e != nil {
		return nil, e
	}
	mode := "selective"
	if b, err := adapterRead(filepath.Join(adapterDataDirectory(), "mode"), 32); err == nil {
		mode = strings.TrimSpace(string(b))
	}
	if mode != "selective" && mode != "full" && mode != "inverse" {
		return nil, errors.New("runtime_mode_invalid")
	}
	previous, e := ManagerCurrentID()
	if e != nil {
		return nil, e
	}
	id, e := managerRandomID()
	if e != nil {
		return nil, e
	}
	p := &adapterPending{JobID: id, NodeID: nodeID, SubscriptionID: subscriptionID, Mode: mode, PreviousSelectedID: previous, Kind: "switch", PreviousEnabled: vpn.Enabled, PreviousAutostart: vpn.Autostart, PreviousDisabled: disabled}
	if e = adapterAtomic(adapterSwitchPath("backup.json"), backup); e != nil {
		return nil, e
	}
	if e = adapterWriteJSON(adapterSwitchPath("candidate.json"), candidate); e != nil {
		return nil, e
	}
	if e = adapterJobSave(p, "queued", ""); e != nil {
		return nil, e
	}
	if e = adapterAtomic(adapterSwitchPath("pending.id"), []byte(p.JobID+"\n")); e != nil {
		return nil, e
	}
	if e = adapterWriteJSON(adapterSwitchPath("pending.json"), p); e != nil {
		return nil, e
	}
	if _, e = adapterCache(); e != nil {
		_ = adapterFinishPending(p, "rolled_back")
		return nil, e
	}
	if e = adapterSpawn("/data/xray-test/xray-switch.sh", p.JobID); e != nil {
		_ = adapterFinishPending(p, "rolled_back")
		_, _ = adapterCache()
		return nil, errors.New("worker_unavailable")
	}
	return p, nil
}

func adapterQueueToggle(enabled bool) (*adapterPending, error) {
	return adapterQueueToggleMode(enabled, "")
}

// adapterSetRoutingMode changes between selective and inverse routing. With the
// VPN off only the saved mode changes; otherwise the toggle worker restarts the
// routing in the new mode and restores the old one when anything fails.
func adapterSetRoutingMode(target string) (*adapterPending, string, error) {
	if target != "selective" && target != "inverse" {
		return nil, "", errors.New("invalid_json")
	}
	current := "selective"
	if b, err := adapterRead(filepath.Join(adapterDataDirectory(), "mode"), 32); err == nil {
		current = strings.TrimSpace(string(b))
	}
	if current == target {
		return nil, "Этот режим уже включён.", nil
	}
	vpn, _, e := adapterVPNState()
	if e != nil {
		return nil, "", e
	}
	if !vpn.Enabled {
		if e = adapterAtomic(filepath.Join(adapterDataDirectory(), "mode"), []byte(target+"\n")); e != nil {
			return nil, "", e
		}
		return nil, "Режим сохранён и применится при включении VPN.", nil
	}
	p, e := adapterQueueToggleMode(true, target)
	return p, "Меняю режим маршрутизации. Интернет может ненадолго пропасть.", e
}

func adapterQueueToggleMode(enabled bool, targetMode string) (*adapterPending, error) {
	if p, e := adapterPendingLoad(); e != nil {
		return nil, e
	} else if p != nil {
		return nil, errors.New("switch_in_progress")
	}
	if _, e := os.Lstat("/tmp/xd20-xray.switching"); !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("switch_in_progress")
	}
	vpn, disabled, e := adapterVPNState()
	if e != nil {
		return nil, e
	}
	mode := "selective"
	if b, err := adapterRead(filepath.Join(adapterDataDirectory(), "mode"), 32); err == nil {
		mode = strings.TrimSpace(string(b))
	}
	if mode != "selective" && mode != "full" && mode != "inverse" {
		return nil, errors.New("runtime_mode_invalid")
	}
	previous, e := ManagerCurrentID()
	if e != nil {
		return nil, e
	}
	autostart, e := adapterFlag("autostart.enabled")
	if e != nil {
		return nil, e
	}
	id, e := managerRandomID()
	if e != nil {
		return nil, e
	}
	p := &adapterPending{JobID: id, Mode: mode, PreviousSelectedID: previous, Kind: "toggle", Enabled: enabled, PreviousEnabled: vpn.Enabled, PreviousAutostart: autostart, PreviousDisabled: disabled, TargetMode: targetMode}
	if e = adapterJobSave(p, "queued", ""); e != nil {
		return nil, e
	}
	if e = adapterAtomic(adapterSwitchPath("pending.id"), []byte(p.JobID+"\n")); e != nil {
		return nil, e
	}
	if e = adapterWriteJSON(adapterSwitchPath("pending.json"), p); e != nil {
		return nil, e
	}
	if _, e = adapterCache(); e == nil {
		e = adapterSpawn("/data/xray-test/xray-switch.sh", p.JobID)
	}
	if e != nil {
		_ = adapterFinishPending(p, "rolled_back")
		_, _ = adapterCache()
		return nil, errors.New("worker_unavailable")
	}
	return p, nil
}
func adapterSpawnFixed(script string, args ...string) error {
	if script != "/data/xray-test/xray-switch.sh" && script != "/data/xray-test/xray-web-reload.sh" {
		return errors.New("worker_unavailable")
	}
	st, e := os.Lstat(script)
	if e != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("worker_unavailable")
	}
	if e = adapterEnsureDirectory(managerDirectory()); e != nil {
		return e
	}
	log, e := os.OpenFile(filepath.Join(managerDirectory(), "worker.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return errors.New("worker_unavailable")
	}
	defer log.Close()
	null, e := os.Open(os.DevNull)
	if e != nil {
		return errors.New("worker_unavailable")
	}
	defer null.Close()
	argv := append([]string{script}, args...)
	cmd := exec.Command("/bin/sh", argv...)
	adapterDetach(cmd)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, log, log
	cmd.Env = append(os.Environ(), "GOMAXPROCS=1", "GOMEMLIMIT=6MiB")
	if cmd.Start() != nil {
		return errors.New("worker_unavailable")
	}
	return cmd.Process.Release()
}
func adapterRequirePending(id string) (*adapterPending, error) {
	p, e := adapterPendingLoad()
	if e != nil {
		return nil, e
	}
	if p == nil || !adapterID(id) || p.JobID != id {
		return nil, errors.New("job_not_found")
	}
	return p, nil
}
func adapterFinishPending(p *adapterPending, status string) error {
	if e := adapterJobSave(p, status, ""); e != nil {
		return e
	}
	if _, e := adapterCache(); e != nil {
		return e
	}
	if os.Remove(adapterSwitchPath("pending.json")) != nil {
		return errors.New("private_write_failed")
	}
	_ = os.Remove(adapterSwitchPath("pending.id"))
	if e := adapterSyncDirectory(filepath.Dir(adapterSwitchPath("pending.json"))); e != nil {
		return e
	}
	_ = os.Remove(adapterSwitchPath("candidate.json"))
	_ = os.Remove(adapterSwitchPath("backup.json"))
	return nil
}
func adapterCommit(id string) error {
	p, e := adapterRequirePending(id)
	if e != nil {
		return e
	}
	if p.Kind != "switch" {
		return errors.New("job_not_found")
	}
	candidate, e := adapterRead(adapterSwitchPath("candidate.json"), managerMaxBody)
	if e != nil {
		return e
	}
	current, e := adapterRead(adapterConfigPath(), managerMaxBody)
	if e != nil {
		return e
	}
	a, e := adapterJSONConfig(candidate)
	if e != nil {
		return e
	}
	b, e := adapterJSONConfig(current)
	if e != nil || !reflect.DeepEqual(a, b) {
		return errors.New("candidate_not_installed")
	}
	selection, _ := json.Marshal(managerInput{ID: p.NodeID})
	if _, e = ManagerAction("node-select", selection); e != nil {
		return e
	}
	return adapterFinishPending(p, "done")
}
func adapterRestoreSelection(id string) error {
	unlock, e := managerLock()
	if e != nil {
		return e
	}
	defer unlock()
	s, e := managerLoad()
	if e != nil {
		return e
	}
	// A disappeared/empty previous ID must also be restored exactly. Refresh
	// preserves the live core; the store can temporarily lack its old node.
	s.SelectedID = id
	return managerSave(s)
}
func adapterRollback(id string) error {
	p, e := adapterRequirePending(id)
	if e != nil {
		return e
	}
	if p.Kind == "toggle" {
		if e = adapterRestoreToggleFlags(p); e != nil {
			return e
		}
		return adapterFinishPending(p, "rolled_back")
	}
	backup, e := adapterRead(adapterSwitchPath("backup.json"), managerMaxBody)
	if e != nil {
		return e
	}
	if _, e = adapterJSONConfig(backup); e != nil {
		return e
	}
	if e = adapterAtomic(adapterConfigPath(), backup); e != nil {
		return e
	}
	if e = adapterRestoreSelection(p.PreviousSelectedID); e != nil {
		return e
	}
	return adapterFinishPending(p, "rolled_back")
}
func adapterSetFlag(name string, present bool) error {
	path := filepath.Join(adapterDataDirectory(), name)
	if present {
		return adapterAtomic(path, []byte("1\n"))
	}
	if _, e := adapterFlag(name); e != nil {
		return e
	}
	if e := os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
		return errors.New("private_write_failed")
	}
	return adapterSyncDirectory(adapterDataDirectory())
}
func adapterRestoreToggleFlags(p *adapterPending) error {
	if e := adapterSetFlag("autostart.enabled", p.PreviousAutostart); e != nil {
		return e
	}
	return adapterSetFlag("vpn.disabled", p.PreviousDisabled)
}
func adapterCompleteToggle(id string, rollback bool) error {
	p, e := adapterRequirePending(id)
	if e != nil {
		return e
	}
	if p.Kind != "toggle" {
		return errors.New("job_not_found")
	}
	expected := p.Enabled
	if rollback {
		if e = adapterRestoreToggleFlags(p); e != nil {
			return e
		}
		expected = p.PreviousEnabled
	}
	vpn, _, e := adapterVPNState()
	if e != nil {
		return e
	}
	if vpn.Enabled != expected || vpn.Running != expected {
		return errors.New("toggle_not_applied")
	}
	status := "done"
	if rollback {
		status = "rolled_back"
	}
	if p.TargetMode != "" {
		if rollback {
			adapterLogEvent("routing-mode", errors.New("rolled_back"), "")
		} else {
			adapterLogEvent("routing-mode", nil, "Режим: "+p.TargetMode)
		}
	}
	return adapterFinishPending(p, status)
}
func adapterRecover() error {
	p, e := adapterPendingLoad()
	if e != nil {
		return e
	}
	if p == nil {
		_, e = adapterCache()
		return e
	}
	return adapterRollback(p.JobID)
}
func adapterLogin(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func adapterPassword(s string) bool {
	if len(s) < 8 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 || b == ':' {
			return false
		}
	}
	return true
}
func adapterSettings(login, password string) error {
	if !adapterLogin(login) {
		return errors.New("invalid_login")
	}
	if !adapterPassword(password) {
		return errors.New("invalid_password")
	}
	path := filepath.Join(adapterDataDirectory(), "httpd-private.conf")
	original, e := adapterRead(path, 8192)
	if e != nil {
		return errors.New("auth_configuration_unavailable")
	}
	lines := strings.Split(string(original), "\n")
	found := 0
	for i, line := range lines {
		if strings.HasPrefix(line, "/:") {
			lines[i] = "/:" + login + ":" + password
			found++
		}
	}
	if found != 1 {
		return errors.New("auth_configuration_unavailable")
	}
	if e = adapterAtomic(path, []byte(strings.Join(lines, "\n"))); e != nil {
		return e
	}
	if _, e = adapterCache(); e == nil {
		e = adapterSpawn("/data/xray-test/xray-web-reload.sh")
	}
	if e != nil {
		if restoreErr := adapterAtomic(path, original); restoreErr != nil {
			return errors.New("auth_restore_failed")
		}
		_, _ = adapterCache()
		return errors.New("worker_unavailable")
	}
	return nil
}
func adapterDecode(input []byte) (adapterInput, error) {
	var in adapterInput
	d := json.NewDecoder(bytes.NewReader(input))
	d.DisallowUnknownFields()
	if e := d.Decode(&in); e != nil {
		return in, errors.New("invalid_json")
	}
	if d.Decode(new(any)) != io.EOF {
		return in, errors.New("invalid_json")
	}
	return in, nil
}
func adapterAction(input []byte) (adapterResponse, error) {
	in, e := adapterDecode(input)
	if e != nil {
		return adapterResponse{}, e
	}
	unlock, e := adapterLock()
	if e != nil {
		return adapterResponse{}, e
	}
	defer unlock()
	if p, e := adapterPendingLoad(); e != nil {
		return adapterResponse{}, e
	} else if p != nil && in.Action != "state" {
		return adapterResponse{}, errors.New("switch_in_progress")
	}
	subID := in.SubscriptionID
	if subID == "" {
		subID = in.ID
	}
	message, jobID, detail := "Настройки сохранены.", "", ""
	backend := managerInput{ID: subID, Name: in.Name, URL: in.URL, Content: in.Content, FetchMode: in.FetchMode}
	call := func(action string) error {
		b, _ := json.Marshal(backend)
		_, err := ManagerAction(action, b)
		return err
	}
	switch in.Action {
	case "state":
		message = ""
	case "add", "subscription-add", "profile-import":
		if in.Content != "" && in.URL != "" {
			return adapterResponse{}, errors.New("choose_url_or_content")
		}
		if in.Content != "" {
			e = call("profile-import")
		} else {
			if !strings.HasPrefix(in.URL, "https://") {
				return adapterResponse{}, errors.New("https_subscription_required")
			}
			e = call("subscription-add")
			if e == nil {
				// The new subscription is the final public entry; refresh only it.
				v, err := ManagerAction("state", nil)
				if err != nil {
					e = err
				} else {
					subs := v.(PublicState).Subscriptions
					backend.ID = subs[len(subs)-1].ID
					e = call("subscription-refresh")
				}
			}
		}
		message = "Подписка сохранена. Выбери сервер, чтобы подключиться."
	case "update", "subscription-refresh":
		if !adapterID(subID) {
			return adapterResponse{}, errors.New("subscription_not_found")
		}
		if in.FetchMode != "" {
			e = call("subscription-update")
		}
		if e == nil {
			e = call("subscription-refresh")
		}
		message = "Список серверов обновлён. Текущий VPN продолжает работать."
	case "remove", "subscription-delete":
		if !adapterID(subID) {
			return adapterResponse{}, errors.New("subscription_not_found")
		}
		e = call("subscription-delete")
		message = "Подписка удалена."
	case "switch-job":
		var p *adapterPending
		p, e = adapterQueue(subID, in.NodeID)
		if p != nil {
			jobID = p.JobID
		}
		message = "Проверяю новый сервер. Дождись завершения переключения."
	case "vpn-job":
		if in.Enabled == nil {
			return adapterResponse{}, errors.New("invalid_json")
		}
		var p *adapterPending
		p, e = adapterQueueToggle(*in.Enabled)
		if p != nil {
			jobID = p.JobID
		}
		message = "Меняю состояние VPN. Дождись завершения."
	case "ping":
		e = adapterPing(subID, in.NodeID)
		message = "Задержка TCP-соединения проверена."
	case "settings":
		e = adapterSettings(in.Login, in.Password)
		message = "Данные входа изменены. Через несколько секунд войди в панель заново."
	case "routing-mode":
		var p *adapterPending
		var note string
		p, note, e = adapterSetRoutingMode(in.Mode)
		if p != nil {
			jobID = p.JobID
		}
		message = note
		detail = note
	case "ping-all":
		scope := ""
		if subID != "" {
			if !adapterID(subID) {
				return adapterResponse{}, errors.New("subscription_not_found")
			}
			scope = subID
		}
		var total, ok int
		total, ok, e = adapterPingAll(scope)
		message = "Проверено серверов: " + strconv.Itoa(total) + ", отвечают: " + strconv.Itoa(ok) + "."
		detail = message
	case "autorefresh-set":
		if in.Hours == nil {
			return adapterResponse{}, errors.New("invalid_json")
		}
		e = adapterAutoRefreshSet(*in.Hours)
		message = "Автообновление выключено."
		if *in.Hours > 0 {
			message = "Автообновление подписок: раз в " + strconv.Itoa(*in.Hours) + " ч."
		}
		detail = message
	case "auto-refresh":
		var ran bool
		ran, e = adapterAutoRefresh()
		if !ran && e == nil {
			return adapterResponse{OK: true}, nil
		}
		message = "Подписки обновлены по расписанию."
		detail = message
	case "probe":
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		var result ManagerProbeResult
		result, e = ManagerProbeVPN(ctx)
		if e != nil {
			return adapterResponse{}, e
		}
		return adapterResponse{OK: true, Message: "Выход через VPN работает.", Probe: &result}, nil
	case "backup-export":
		var b *adapterBackup
		b, e = adapterBackupExport()
		if e != nil {
			return adapterResponse{}, e
		}
		return adapterResponse{OK: true, Backup: b}, nil
	case "backup-import":
		var added int
		added, e = adapterBackupImport(in.Backup)
		message = "Из копии добавлено подписок и профилей: " + strconv.Itoa(added) + ". Нажми «Обновить» у подписок."
		detail = message
	default:
		return adapterResponse{}, errors.New("unknown_action")
	}
	if in.Action != "state" && in.Action != "settings" && in.Action != "switch-job" && in.Action != "vpn-job" && (in.Action != "routing-mode" || jobID == "") {
		adapterLogEvent(in.Action, e, detail)
	}
	if e != nil {
		return adapterResponse{}, e
	}
	state, e := adapterCache()
	if e != nil {
		return adapterResponse{}, e
	}
	return adapterResponse{OK: true, Message: message, JobID: jobID, State: state}, nil
}
func adapterNormalizeOutbound(o map[string]any) map[string]any {
	b, _ := json.Marshal(o)
	var copy map[string]any
	_ = json.Unmarshal(b, &copy)
	delete(copy, "tag")
	// The installer can bind a node to the WAN interface; it is not part of
	// the subscription's endpoint identity.
	if stream, ok := copy["streamSettings"].(map[string]any); ok {
		delete(stream, "sockopt")
	}
	return copy
}
func adapterSeed(input []byte) error {
	var in struct {
		Subscriptions []ManagerSeedSubscription `json:"subscriptions"`
		CurrentConfig map[string]any            `json:"currentConfig"`
		Domains       []string                  `json:"domains"`
	}
	if json.Unmarshal(input, &in) != nil {
		return errors.New("invalid_json")
	}
	p, e := ManagerSeed(in.Subscriptions, in.Domains)
	if e != nil {
		return e
	}
	if p.SelectedID == "" && in.CurrentConfig != nil {
		outs, _ := in.CurrentConfig["outbounds"].([]any)
		for _, out := range outs {
			o, ok := out.(map[string]any)
			if !ok || o["tag"] != "vpn" {
				continue
			}
			wanted := adapterNormalizeOutbound(o)
			for _, n := range p.Nodes {
				candidate, err := ManagerGetOutbound(n.ID)
				if err != nil {
					return err
				}
				if reflect.DeepEqual(wanted, adapterNormalizeOutbound(candidate)) {
					b, _ := json.Marshal(managerInput{ID: n.ID})
					if _, e = ManagerAction("node-select", b); e != nil {
						return e
					}
					_, e = adapterCache()
					return e
				}
			}
			// A parser can normalize defaults differently from the already
			// verified runtime. Preserve that exact working outbound as a node
			// rather than claiming that another imported endpoint is active.
			if e = adapterSeedWorkingOutbound(o); e != nil {
				return e
			}
			_, e = adapterCache()
			return e
		}
	}
	_, e = adapterCache()
	return e
}
func adapterSeedWorkingOutbound(outbound map[string]any) error {
	unlock, e := managerLock()
	if e != nil {
		return e
	}
	defer unlock()
	store, e := managerLoad()
	if e != nil {
		return e
	}
	if store.SelectedID != "" {
		return nil
	}
	if len(store.Subscriptions) == 0 {
		id, err := managerRandomID()
		if err != nil {
			return err
		}
		store.Subscriptions = append(store.Subscriptions, ManagerSubscription{ID: id, Name: "Текущий сервер", Kind: "import", FetchMode: "direct", Status: "ready", Nodes: []ManagerNode{}})
	}
	protocol, _ := outbound["protocol"].(string)
	if protocol == "" {
		return errors.New("runtime_config_invalid")
	}
	transport, security := "tcp", "none"
	if stream, ok := outbound["streamSettings"].(map[string]any); ok {
		if v, ok := stream["network"].(string); ok && v != "" {
			transport = v
		}
		if v, ok := stream["security"].(string); ok && v != "" {
			security = v
		}
	}
	node, e := managerFinishNode(store.Subscriptions[0].ID, "Текущий сервер", protocol, transport, security, outbound)
	if e != nil {
		return e
	}
	store.Subscriptions[0].Nodes = append(store.Subscriptions[0].Nodes, node)
	store.SelectedID = node.ID
	return managerSave(store)
}
func adapterPublicError(e error) string {
	if e == nil {
		return ""
	}
	switch e.Error() {
	case "switch_in_progress", "manager_busy":
		return "Другое действие ещё выполняется. Дождись завершения и перечитай состояние."
	case "enable_vpn_before_switch":
		return "Для переключения сервера сначала включи VPN."
	case "invalid_login":
		return "Логин: 1–32 латинских буквы, цифры, точки, дефисы или подчёркивания."
	case "invalid_password":
		return "Пароль: 8–128 печатных латинских символов без пробелов и двоеточия."
	case "select_another_node_before_delete":
		return "Перед удалением этой подписки выбери сервер из другой."
	case "subscription_limit", "node_limit", "node_or_subscription_limit":
		return "Достигнут лимит: 8 подписок или 256 серверов."
	case "https_subscription_required", "invalid_subscription_url", "private_subscription_address_rejected":
		return "Нужна обычная HTTPS-ссылка подписки на публичный сервер."
	case "encrypted_happ_link_requires_plain_subscription":
		return "Нужна обычная ссылка подписки. Зашифрованная ссылка Happ здесь не поддерживается."
	case "node_not_found", "subscription_not_found", "job_not_found":
		return "Запись больше недоступна. Перечитай состояние и выбери её снова."
	case "subscription_already_added":
		return "Эта подписка уже добавлена."
	case "input_too_large":
		return "Запрос слишком большой."
	case "invalid_json", "unknown_action", "choose_url_or_content":
		return "Неверный запрос. Выбери ссылку подписки или одну готовую конфигурацию."
	case "backup_invalid":
		return "Файл копии настроек не распознан."
	case "worker_unavailable":
		return "Не удалось запустить действие. Прежние настройки сохранены."
	case "candidate_not_installed", "switch_state_invalid", "runtime_config_invalid", "runtime_mode_invalid":
		return "Не удалось завершить переключение. Прежний профиль сохранён для восстановления."
	default:
		return "Не удалось выполнить действие. Перечитай состояние перед повторной попыткой."
	}
}
func adapterJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	return enc.Encode(value)
}
func adapterReadInput(r io.Reader, limit int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("input_too_large")
	}
	return b, nil
}
func adapterCGI(r io.Reader, w io.Writer, env func(string) string) int {
	status, body, e := 200, any(nil), error(nil)
	ip := net.ParseIP(env("REMOTE_ADDR"))
	if env("HTTP_HOST") != "192.168.3.1:8088" || ip == nil || ip.To4() == nil || ip.To4()[0] != 192 || ip.To4()[1] != 168 || ip.To4()[2] != 3 {
		status, e = 403, errors.New("cgi_forbidden")
	} else {
		switch env("REQUEST_METHOD") {
		case "GET":
			body, e = adapterCache()
		case "POST":
			contentType := env("CONTENT_TYPE")
			length, err := strconv.Atoi(env("CONTENT_LENGTH"))
			if env("HTTP_ORIGIN") != "http://192.168.3.1:8088" || env("HTTP_X_XD20_UI") != "manager-v1" {
				status, e = 403, errors.New("cgi_forbidden")
			} else if contentType != "application/json" && contentType != "application/json; charset=utf-8" {
				status, e = 415, errors.New("invalid_json")
			} else if err != nil || length < 2 || length > adapterCGILimit {
				status, e = 413, errors.New("input_too_large")
			} else {
				b := make([]byte, length)
				if _, err = io.ReadFull(r, b); err != nil {
					e = errors.New("invalid_json")
				} else {
					body, e = adapterAction(b)
				}
			}
		default:
			status, e = 405, errors.New("unknown_action")
		}
	}
	if e != nil {
		if status == 200 {
			status = 422
			if e.Error() == "manager_busy" || e.Error() == "switch_in_progress" {
				status = 409
			}
		}
		body = adapterResponse{OK: false, Error: adapterPublicError(e)}
	}
	_, _ = fmt.Fprintf(w, "Status: %d\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n", status)
	if adapterJSON(w, body) != nil || e != nil {
		return 1
	}
	return 0
}
func adapterRun(args []string, r io.Reader, w io.Writer) error {
	if len(args) == 0 {
		return errors.New("unknown_action")
	}
	if args[0] == "version" {
		_, e := fmt.Fprintln(w, adapterVersion)
		return e
	}
	if args[0] == "probe" || args[0] == "probe-direct" {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		var result ManagerProbeResult
		var e error
		if args[0] == "probe-direct" {
			result, e = ManagerProbeDirect(ctx)
		} else {
			result, e = ManagerProbeVPN(ctx)
		}
		if e != nil {
			return e
		}
		return adapterJSON(w, result)
	}
	if args[0] == "action" {
		b, e := adapterReadInput(r, managerMaxBody+8192)
		if e != nil {
			return e
		}
		if len(args) == 2 {
			var in map[string]any
			if len(bytes.TrimSpace(b)) == 0 {
				in = map[string]any{}
			} else if json.Unmarshal(b, &in) != nil {
				return errors.New("invalid_json")
			}
			in["action"] = args[1]
			b, _ = json.Marshal(in)
		}
		result, e := adapterAction(b)
		if e != nil {
			return e
		}
		return adapterJSON(w, result)
	}
	unlock, e := adapterLock()
	if e != nil {
		return e
	}
	defer unlock()
	switch args[0] {
	case "seed":
		b, e := adapterReadInput(r, managerMaxStore)
		if e != nil {
			return e
		}
		if e = adapterSeed(b); e != nil {
			return e
		}
	case "queue-switch":
		if len(args) < 2 || len(args) > 3 {
			return errors.New("unknown_action")
		}
		sub, node := "", args[1]
		if len(args) == 3 {
			sub, node = args[1], args[2]
		}
		p, e := adapterQueue(sub, node)
		if e != nil {
			return e
		}
		return adapterJSON(w, adapterResponse{OK: true, JobID: p.JobID})
	case "switch-mode":
		if len(args) != 2 {
			return errors.New("unknown_action")
		}
		p, e := adapterRequirePending(args[1])
		if e != nil {
			return e
		}
		_, e = fmt.Fprintln(w, p.Mode)
		return e
	case "job-kind", "toggle-target", "toggle-previous":
		if len(args) != 2 {
			return errors.New("unknown_action")
		}
		p, e := adapterRequirePending(args[1])
		if e != nil {
			return e
		}
		value := p.Kind
		if args[0] != "job-kind" {
			if p.Kind != "toggle" {
				return errors.New("job_not_found")
			}
			value = "disable"
			enabled := p.Enabled
			if args[0] == "toggle-previous" {
				enabled = p.PreviousEnabled
			}
			if enabled {
				value = "enable"
			}
		}
		_, e = fmt.Fprintln(w, value)
		return e
	case "toggle-mode":
		if len(args) != 2 {
			return errors.New("unknown_action")
		}
		p, e := adapterRequirePending(args[1])
		if e != nil {
			return e
		}
		if p.Kind != "toggle" {
			return errors.New("job_not_found")
		}
		_, e = fmt.Fprintln(w, p.TargetMode)
		return e
	case "complete-toggle":
		if len(args) < 2 || len(args) > 3 || len(args) == 3 && args[2] != "rollback" {
			return errors.New("unknown_action")
		}
		if e = adapterCompleteToggle(args[1], len(args) == 3); e != nil {
			return e
		}
	case "job-status":
		if len(args) < 3 || len(args) > 4 {
			return errors.New("unknown_action")
		}
		p, e := adapterRequirePending(args[1])
		if e != nil {
			return e
		}
		// Terminal success/rollback must go through their transaction helpers.
		if args[2] == "done" || args[2] == "rolled_back" {
			return errors.New("invalid_job_status")
		}
		if e = adapterJobSave(p, args[2], ""); e != nil {
			return e
		}
	case "commit-switch":
		if len(args) != 2 {
			return errors.New("unknown_action")
		}
		if e = adapterCommit(args[1]); e != nil {
			adapterLogEvent("switch", e, "")
			return e
		}
		adapterLogEvent("switch", nil, "Сервер переключён.")
	case "rollback-switch":
		if len(args) < 2 || len(args) > 3 {
			return errors.New("unknown_action")
		}
		if e = adapterRollback(args[1]); e != nil {
			adapterLogEvent("switch", e, "")
			return e
		}
		adapterLogEvent("switch", errors.New("rolled_back"), "")
	case "recover-switch":
		if len(args) != 1 {
			return errors.New("unknown_action")
		}
		if e = adapterRecover(); e != nil {
			return e
		}
	default:
		return errors.New("unknown_action")
	}
	state, e := adapterCache()
	if e != nil {
		return e
	}
	return adapterJSON(w, adapterResponse{OK: true, State: state})
}
func main() {
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(6 << 20) // A soft GC target, not a total-RAM guarantee.
	code := 0
	if len(os.Args) > 1 && os.Args[1] == "cgi" {
		code = adapterCGI(os.Stdin, os.Stdout, os.Getenv)
	} else if e := adapterRun(os.Args[1:], os.Stdin, os.Stdout); e != nil {
		_ = adapterJSON(os.Stdout, adapterResponse{OK: false, Error: adapterPublicError(e)})
		code = 1
	}
	os.Exit(code)
}
