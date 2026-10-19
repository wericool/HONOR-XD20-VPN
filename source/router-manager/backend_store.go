package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const managerMaxSubs = 8
const managerMaxNodes = 256
const managerMaxBody = 1 << 20
const managerMaxStore = 2 << 20

type ManagerNode struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Protocol  string         `json:"protocol"`
	Transport string         `json:"transport"`
	Security  string         `json:"security"`
	Outbound  map[string]any `json:"outbound"`
}
type ManagerSubscription struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	URL           string        `json:"url,omitempty"`
	FetchMode     string        `json:"fetchMode"`
	Kind          string        `json:"kind"`
	Status        string        `json:"status"`
	LastFetchPath string        `json:"lastFetchPath,omitempty"`
	Updated       int64         `json:"updated,omitempty"`
	Expires       int64         `json:"expires,omitempty"`
	TotalBytes    int64         `json:"totalBytes,omitempty"`
	UsedBytes     int64         `json:"usedBytes,omitempty"`
	SkippedCount  int           `json:"skippedCount,omitempty"`
	Warning       string        `json:"warning,omitempty"`
	Nodes         []ManagerNode `json:"nodes"`
}
type ManagerStore struct {
	Version       int                   `json:"version"`
	SelectedID    string                `json:"selectedId"`
	Domains       []string              `json:"domains"`
	Subscriptions []ManagerSubscription `json:"subscriptions"`
	Settings      ManagerSettings       `json:"settings,omitempty"`
}
type PublicNode struct {
	ID             string `json:"id"`
	SubscriptionID string `json:"subscriptionId"`
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	Transport      string `json:"transport"`
	Security       string `json:"security"`
}
type PublicSubscription struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	FetchMode     string `json:"fetchMode"`
	Status        string `json:"status"`
	LastFetchPath string `json:"lastFetchPath,omitempty"`
	Updated       int64  `json:"updated,omitempty"`
	Expires       int64  `json:"expires,omitempty"`
	TotalBytes    int64  `json:"totalBytes,omitempty"`
	UsedBytes     int64  `json:"usedBytes,omitempty"`
	NodeCount     int    `json:"nodeCount"`
	SkippedCount  int    `json:"skippedCount,omitempty"`
	Warning       string `json:"warning,omitempty"`
}
type PublicState struct {
	SelectedID         string               `json:"selectedId"`
	SelectionAvailable bool                 `json:"selectionAvailable"`
	Domains            []string             `json:"domains"`
	Subscriptions      []PublicSubscription `json:"subscriptions"`
	Nodes              []PublicNode         `json:"nodes"`
}

func managerDirectory() string {
	if d := os.Getenv("ROUTER_MANAGER_DIR"); d != "" {
		return d
	}
	return "/data/xray-manager"
}
func managerLoad() (*ManagerStore, error) {
	s := &ManagerStore{Version: 1, Domains: []string{}, Subscriptions: []ManagerSubscription{}}
	f, err := os.Open(filepath.Join(managerDirectory(), "subscriptions.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, errors.New("store_unavailable")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, managerMaxStore+1))
	if err != nil || len(b) > managerMaxStore || json.Unmarshal(b, s) != nil || s.Version != 1 {
		return nil, errors.New("store_invalid")
	}
	if len(s.Subscriptions) > managerMaxSubs || managerNodeCount(s) > managerMaxNodes {
		return nil, errors.New("store_limit")
	}
	return s, nil
}
func managerSave(s *ManagerStore) error {
	if len(s.Subscriptions) > managerMaxSubs || managerNodeCount(s) > managerMaxNodes {
		return errors.New("node_or_subscription_limit")
	}
	b, err := json.Marshal(s)
	if err != nil || len(b) > managerMaxStore {
		return errors.New("store_limit")
	}
	d := managerDirectory()
	if os.MkdirAll(d, 0700) != nil || os.Chmod(d, 0700) != nil {
		return errors.New("store_unavailable")
	}
	f, err := os.CreateTemp(d, ".subscriptions-*")
	if err != nil {
		return errors.New("store_unavailable")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if f.Chmod(0600) != nil {
		f.Close()
		return errors.New("store_unavailable")
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(tmp, filepath.Join(d, "subscriptions.json")) != nil {
		return errors.New("store_unavailable")
	}
	// Persist the rename itself on the router. Windows cannot fsync a directory
	// and is used only for host tests; production Linux uses file + directory fsync.
	if runtime.GOOS != "windows" {
		dirFile, e := os.Open(d)
		if e != nil {
			return errors.New("store_unavailable")
		}
		defer dirFile.Close()
		if dirFile.Sync() != nil {
			return errors.New("store_unavailable")
		}
	}
	return nil
}
func managerLock() (func(), error) {
	d := managerDirectory()
	if os.MkdirAll(d, 0700) != nil {
		return nil, errors.New("store_unavailable")
	}
	// Production locks live in tmpfs, so an interrupted operation cannot leave a
	// persistent future-dated lock across boot/NTP synchronization. Explicit test
	// stores retain an isolated local lock and never touch production /tmp.
	lock := "/tmp/xd20-manager-store.lock"
	if os.Getenv("ROUTER_MANAGER_DIR") != "" {
		lock = filepath.Join(d, ".manager-lock")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if os.Mkdir(lock, 0700) == nil {
			return func() { os.Remove(lock) }, nil
		}
		if st, e := os.Lstat(lock); e == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 && time.Since(st.ModTime()) > 2*time.Minute {
			if os.Remove(lock) == nil {
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, errors.New("manager_busy")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func managerRandomID() (string, error) {
	b := make([]byte, 10)
	if _, e := rand.Read(b); e != nil {
		return "", errors.New("random_unavailable")
	}
	return hex.EncodeToString(b), nil
}
func managerNodeCount(s *ManagerStore) int {
	n := 0
	for _, sub := range s.Subscriptions {
		n += len(sub.Nodes)
	}
	return n
}
func managerPublic(s *ManagerStore) PublicState {
	p := PublicState{SelectedID: s.SelectedID, Domains: append([]string{}, s.Domains...), Subscriptions: []PublicSubscription{}, Nodes: []PublicNode{}}
	for _, sub := range s.Subscriptions {
		p.Subscriptions = append(p.Subscriptions, PublicSubscription{ID: sub.ID, Name: sub.Name, Kind: sub.Kind, FetchMode: sub.FetchMode, Status: sub.Status, LastFetchPath: sub.LastFetchPath, Updated: sub.Updated, Expires: sub.Expires, TotalBytes: sub.TotalBytes, UsedBytes: sub.UsedBytes, NodeCount: len(sub.Nodes), SkippedCount: sub.SkippedCount, Warning: sub.Warning})
		for _, n := range sub.Nodes {
			p.Nodes = append(p.Nodes, PublicNode{n.ID, sub.ID, n.Name, n.Protocol, n.Transport, n.Security})
			if n.ID == s.SelectedID {
				p.SelectionAvailable = true
			}
		}
	}
	return p
}
func ManagerCurrentID() (string, error) {
	s, e := managerLoad()
	if e != nil {
		return "", e
	}
	return s.SelectedID, nil
}
func ManagerSites() ([]string, error) {
	s, e := managerLoad()
	if e != nil {
		return nil, e
	}
	return append([]string{}, s.Domains...), nil
}
func ManagerGetOutbound(nodeID string) (map[string]any, error) {
	s, e := managerLoad()
	if e != nil {
		return nil, e
	}
	for _, sub := range s.Subscriptions {
		for _, n := range sub.Nodes {
			if n.ID == nodeID {
				return n.Outbound, nil
			}
		}
	}
	return nil, errors.New("node_not_found")
}
func ManagerSelectedOutbound() (map[string]any, error) {
	id, e := ManagerCurrentID()
	if e != nil {
		return nil, e
	}
	return ManagerGetOutbound(id)
}

type managerInput struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	FetchMode string   `json:"fetchMode"`
	Content   string   `json:"content"`
	Domains   []string `json:"domains"`
}

// ManagerAction returns ONLY public state. Candidate lookup never changes selection;
// callers commit node-select only after their runtime transaction has succeeded.
func ManagerAction(action string, input []byte) (any, error) {
	if len(input) > managerMaxBody+8192 {
		return nil, errors.New("input_too_large")
	}
	var in managerInput
	if len(strings.TrimSpace(string(input))) > 0 && json.Unmarshal(input, &in) != nil {
		return nil, errors.New("invalid_json")
	}
	if action == "state" {
		s, e := managerLoad()
		if e != nil {
			return nil, e
		}
		return managerPublic(s), nil
	}
	unlock, e := managerLock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	s, e := managerLoad()
	if e != nil {
		return nil, e
	}
	switch action {
	case "subscription-add":
		if len(s.Subscriptions) >= managerMaxSubs {
			return nil, errors.New("subscription_limit")
		}
		if e = managerValidateURL(in.URL); e != nil {
			return nil, e
		}
		mode, e := managerMode(in.FetchMode)
		if e != nil {
			return nil, e
		}
		for _, sub := range s.Subscriptions {
			if sub.URL == in.URL {
				return nil, errors.New("subscription_already_added")
			}
		}
		id, e := managerRandomID()
		if e != nil {
			return nil, e
		}
		name := managerSafeName(in.Name)
		if name == "" {
			name = "Subscription"
		}
		s.Subscriptions = append(s.Subscriptions, ManagerSubscription{ID: id, Name: name, URL: in.URL, FetchMode: mode, Kind: "subscription", Status: "not_refreshed", Nodes: []ManagerNode{}})
	case "subscription-update":
		idx := managerSubIndex(s, in.ID)
		if idx < 0 {
			return nil, errors.New("subscription_not_found")
		}
		sub := &s.Subscriptions[idx]
		if in.Name != "" {
			sub.Name = managerSafeName(in.Name)
		}
		if in.URL != "" {
			if e = managerValidateURL(in.URL); e != nil {
				return nil, e
			}
			sub.URL = in.URL
		}
		if in.FetchMode != "" {
			mode, e := managerMode(in.FetchMode)
			if e != nil {
				return nil, e
			}
			sub.FetchMode = mode
		}
	case "subscription-refresh":
		if in.ID != "" && in.ID != "all" && managerSubIndex(s, in.ID) < 0 {
			return nil, errors.New("subscription_not_found")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		for i := range s.Subscriptions {
			sub := &s.Subscriptions[i]
			if sub.URL == "" || (in.ID != "" && in.ID != "all" && in.ID != sub.ID) {
				continue
			}
			body, meta, path, err := managerFetch(ctx, sub.URL, sub.FetchMode)
			sub.LastFetchPath = path
			if err != nil {
				sub.Status = "fetch_failed_cached_preserved"
				continue
			}
			nodes, err := managerParseProfile(body, sub.ID, sub.Name)
			if err != nil {
				if err.Error() == "provider_device_registration_required" || err.Error() == "provider_app_unsupported" {
					sub.Status = err.Error()
					// Retain actual cached servers; old instruction placeholders must
					// not remain selectable as if they were real provider endpoints.
					cached := []ManagerNode{}
					for _, n := range sub.Nodes {
						if !managerPlaceholderEndpoint(n) && !managerUnsupportedCaption(n.Name) {
							cached = append(cached, n)
						}
					}
					sub.Nodes = cached
					continue
				}
				sub.Status = "unsupported_or_invalid_cached_preserved"
				continue
			}
			freshCount := len(nodes)
			capacity := managerMaxNodes - (managerNodeCount(s) - len(sub.Nodes))
			nodes, retainedActive, fits := managerRetainActiveNode(s.SelectedID, sub.Nodes, nodes, capacity)
			if !fits {
				sub.Status = "node_limit_cached_preserved"
				continue
			}
			sub.Nodes = nodes
			sub.SkippedCount = managerProfileSkipped(body, freshCount)
			sub.Warning = ""
			if sub.SkippedCount > 0 {
				sub.Warning = "some_entries_unsupported_or_duplicate"
			}
			if retainedActive {
				if sub.Warning != "" {
					sub.Warning += ","
				}
				sub.Warning += "active_server_from_previous_update"
			}
			sub.Status = "ready"
			sub.Updated = time.Now().Unix()
			sub.Expires = meta.Expires
			sub.TotalBytes = meta.Total
			sub.UsedBytes = meta.Used
		}
	case "subscription-delete":
		idx := managerSubIndex(s, in.ID)
		if idx < 0 {
			return nil, errors.New("subscription_not_found")
		}
		for _, n := range s.Subscriptions[idx].Nodes {
			if n.ID == s.SelectedID {
				return nil, errors.New("select_another_node_before_delete")
			}
		}
		s.Subscriptions = append(s.Subscriptions[:idx], s.Subscriptions[idx+1:]...)
	case "profile-import":
		if len(s.Subscriptions) >= managerMaxSubs {
			return nil, errors.New("subscription_limit")
		}
		id, e := managerRandomID()
		if e != nil {
			return nil, e
		}
		name := managerSafeName(in.Name)
		if name == "" {
			name = "Imported profile"
		}
		nodes, e := managerParseProfile([]byte(in.Content), id, name)
		if e != nil {
			return nil, e
		}
		if managerNodeCount(s)+len(nodes) > managerMaxNodes {
			return nil, errors.New("node_limit")
		}
		skipped := managerProfileSkipped([]byte(in.Content), len(nodes))
		warning := ""
		if skipped > 0 {
			warning = "some_entries_unsupported_or_duplicate"
		}
		s.Subscriptions = append(s.Subscriptions, ManagerSubscription{ID: id, Name: name, FetchMode: "direct", Kind: "import", Status: "ready", Updated: time.Now().Unix(), Nodes: nodes, SkippedCount: skipped, Warning: warning})
	case "node-select":
		exists := false
		for _, sub := range s.Subscriptions {
			for _, n := range sub.Nodes {
				if n.ID == in.ID {
					exists = true
				}
			}
		}
		if !exists {
			return nil, errors.New("node_not_found")
		}
		s.SelectedID = in.ID
	case "sites-set":
		domains, e := managerNormalizeDomains(in.Domains)
		if e != nil {
			return nil, e
		}
		s.Domains = domains
	default:
		return nil, errors.New("unknown_action")
	}
	if e = managerSave(s); e != nil {
		return nil, e
	}
	return managerPublic(s), nil
}

// The core keeps using the selected outbound while a subscription refreshes.
// Preserve that exact old node until a separate, tested selection commits. At
// capacity, remove one fresh (unselected) node rather than hide the active core.
func managerRetainActiveNode(selectedID string, old, fresh []ManagerNode, capacity int) ([]ManagerNode, bool, bool) {
	if len(fresh) > capacity {
		return nil, false, false
	}
	for _, n := range fresh {
		if n.ID == selectedID {
			return fresh, false, true
		}
	}
	if selectedID == "" {
		return fresh, false, true
	}
	for _, active := range old {
		if active.ID != selectedID {
			continue
		}
		if capacity < 1 {
			return nil, false, false
		}
		if len(fresh) == capacity {
			fresh = fresh[:len(fresh)-1]
		}
		nodes := append([]ManagerNode{}, fresh...)
		nodes = append(nodes, active)
		return nodes, true, true
	}
	return fresh, false, true // Selection belongs to a different subscription.
}
func managerSubIndex(s *ManagerStore, id string) int {
	for i := range s.Subscriptions {
		if s.Subscriptions[i].ID == id {
			return i
		}
	}
	return -1
}
func managerMode(mode string) (string, error) {
	if mode == "" {
		mode = "auto"
	}
	if mode != "auto" && mode != "direct" && mode != "vpn" {
		return "", errors.New("invalid_fetch_mode")
	}
	return mode, nil
}
