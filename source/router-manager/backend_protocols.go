package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func managerParseURI(line, subID string) (ManagerNode, error) {
	switch {
	case strings.HasPrefix(line, "vless://"):
		return managerParseVLESS(line, subID)
	case strings.HasPrefix(line, "trojan://"):
		return managerParseTrojan(line, subID)
	case strings.HasPrefix(line, "vmess://"):
		return managerParseVMess(line, subID)
	case strings.HasPrefix(line, "ss://"):
		return managerParseShadowsocks(line, subID)
	default:
		return ManagerNode{}, errors.New("unsupported_protocol")
	}
}
func managerTransportTemplate(host, port, label string, q url.Values, subID string) (ManagerNode, error) {
	q.Del("flow")
	q.Set("encryption", "none")
	u := url.URL{Scheme: "vless", User: url.User("00000000-0000-0000-0000-000000000000"), Host: net.JoinHostPort(host, port), RawQuery: q.Encode(), Fragment: label}
	return managerParseVLESS(u.String(), subID)
}
func managerParseTrojan(line, subID string) (ManagerNode, error) {
	u, e := url.Parse(line)
	if e != nil || u.User == nil || len(line) > 32768 {
		return ManagerNode{}, errors.New("invalid_trojan_node")
	}
	password := u.User.Username()
	if password == "" || len(password) > 1024 {
		return ManagerNode{}, errors.New("invalid_trojan_node")
	}
	q := u.Query()
	if q.Get("security") == "" {
		q.Set("security", "tls")
	}
	if q.Get("security") != "tls" {
		return ManagerNode{}, errors.New("unsupported_trojan_security")
	}
	n, e := managerTransportTemplate(u.Hostname(), u.Port(), u.Fragment, q, subID)
	if e != nil {
		return ManagerNode{}, e
	}
	port, _ := strconv.Atoi(u.Port())
	n.Outbound["protocol"] = "trojan"
	n.Outbound["settings"] = map[string]any{"servers": []any{map[string]any{"address": u.Hostname(), "port": port, "password": password}}}
	label := strings.ReplaceAll(u.Fragment, password, "[credential]")
	label = strings.ReplaceAll(label, u.Hostname(), "[server]")
	return managerFinishNode(subID, label, "trojan", n.Transport, n.Security, n.Outbound)
}
func managerParseVMess(line, subID string) (ManagerNode, error) {
	invalid := func() (ManagerNode, error) { return ManagerNode{}, errors.New("invalid_vmess_node") }
	encoded := strings.SplitN(strings.TrimPrefix(line, "vmess://"), "#", 2)[0]
	b, e := managerDecodeBase64(encoded)
	if e != nil || len(b) > 16384 {
		return invalid()
	}
	var d map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.UseNumber()
	if decoder.Decode(&d) != nil {
		return invalid()
	}
	value := func(k string) string {
		switch v := d[k].(type) {
		case string:
			return v
		case json.Number:
			return v.String()
		}
		return ""
	}
	host, port, id := value("add"), value("port"), value("id")
	if !managerUUID.MatchString(id) {
		return invalid()
	}
	q := url.Values{}
	q.Set("type", value("net"))
	if q.Get("type") == "" {
		q.Set("type", "tcp")
	}
	security := value("tls")
	if security == "" {
		security = "none"
	}
	q.Set("security", security)
	for _, k := range []string{"host", "path", "sni", "alpn", "fp"} {
		if v := value(k); v != "" {
			q.Set(k, v)
		}
	}
	if q.Get("type") == "grpc" {
		q.Set("serviceName", value("path"))
	}
	if q.Get("type") == "tcp" && value("type") == "http" {
		q.Set("headerType", "http")
	}
	u := url.URL{Scheme: "vless", User: url.User(id), Host: net.JoinHostPort(host, port), RawQuery: q.Encode(), Fragment: value("ps")}
	n, e := managerParseVLESS(u.String(), subID)
	if e != nil {
		return ManagerNode{}, e
	}
	aid := 0
	if v := value("aid"); v != "" {
		aid, e = strconv.Atoi(v)
		if e != nil || aid < 0 || aid > 65535 {
			return invalid()
		}
	}
	scy := value("scy")
	if scy == "" {
		scy = "auto"
	}
	switch scy {
	case "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero":
	default:
		return invalid()
	}
	p, _ := strconv.Atoi(port)
	n.Outbound["protocol"] = "vmess"
	n.Outbound["settings"] = map[string]any{"vnext": []any{map[string]any{"address": host, "port": p, "users": []any{map[string]any{"id": id, "alterId": aid, "security": scy}}}}}
	label := strings.ReplaceAll(value("ps"), id, "[credential]")
	label = strings.ReplaceAll(label, host, "[server]")
	return managerFinishNode(subID, label, "vmess", n.Transport, n.Security, n.Outbound)
}
func managerParseShadowsocks(line, subID string) (ManagerNode, error) {
	invalid := func() (ManagerNode, error) { return ManagerNode{}, errors.New("invalid_shadowsocks_node") }
	if len(line) > 32768 {
		return invalid()
	}
	u, e := url.Parse(line)
	if e != nil {
		return invalid()
	}
	if u.User == nil {
		rest := strings.TrimPrefix(line, "ss://")
		bits := strings.SplitN(rest, "#", 2)
		b, e := managerDecodeBase64(bits[0])
		if e != nil {
			return invalid()
		}
		raw := "ss://" + string(b)
		if len(bits) == 2 {
			raw += "#" + bits[1]
		}
		u, e = url.Parse(raw)
		if e != nil || u.User == nil {
			return invalid()
		}
	}
	if u.Query().Get("plugin") != "" {
		return ManagerNode{}, errors.New("shadowsocks_plugin_not_supported")
	}
	method, password := u.User.Username(), ""
	if p, yes := u.User.Password(); yes {
		password = p
	} else {
		b, e := managerDecodeBase64(method)
		if e != nil {
			return invalid()
		}
		bits := strings.SplitN(string(b), ":", 2)
		if len(bits) != 2 {
			return invalid()
		}
		method, password = bits[0], bits[1]
	}
	if password == "" || len(password) > 2048 {
		return invalid()
	}
	switch method {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
	default:
		return ManagerNode{}, errors.New("unsupported_shadowsocks_cipher")
	}
	q := url.Values{}
	q.Set("type", "tcp")
	q.Set("security", "none")
	n, e := managerTransportTemplate(u.Hostname(), u.Port(), u.Fragment, q, subID)
	if e != nil {
		return ManagerNode{}, e
	}
	if method == "chacha20-ietf-poly1305" {
		method = "chacha20-poly1305"
	}
	port, _ := strconv.Atoi(u.Port())
	n.Outbound["protocol"] = "shadowsocks"
	n.Outbound["settings"] = map[string]any{"servers": []any{map[string]any{"address": u.Hostname(), "port": port, "method": method, "password": password}}}
	label := strings.ReplaceAll(u.Fragment, password, "[credential]")
	label = strings.ReplaceAll(label, u.Hostname(), "[server]")
	return managerFinishNode(subID, label, "shadowsocks", "tcp", "aead", n.Outbound)
}
