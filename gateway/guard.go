package main

// Browser-facing guards (D-059) — the same policy as the engine's
// loom.webguard, from the same env, so one configuration covers both:
//
//   LOOM_ALLOWED_HOSTS    extra Host names ("loom.example.com", "*.corp.example.com");
//                         "*" turns the Host check off
//   LOOM_ALLOWED_ORIGINS  browser origins allowed cross-origin; "*" = any
//
// Always allowed: IP literals, localhost / *.localhost, single-label names
// (compose services, same-namespace k8s Services) and cluster suffixes
// (*.svc, *.svc.cluster.local, *.cluster.local, *.internal). A DNS-
// rebinding page's Host is the attacker's domain, never one of these.
// Loopback and same-origin Origins pass; others are refused. POSTs under
// /v1/ must declare a JSON media type: text/plain, form encodings and
// typeless bodies are what a cross-site page can send without a CORS
// preflight.

import (
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var defaultHostSuffixes = []string{".localhost", ".svc", ".svc.cluster.local", ".cluster.local", ".internal"}

var jsonMediaTypes = map[string]bool{
	"application/json": true, "application/x-ndjson": true, "application/ndjson": true,
	"application/x-ldjson": true, "application/jsonl": true, "application/x-jsonlines": true,
	"application/jsonlines": true,
}

type hostPolicy struct {
	anyHost   bool
	exact     map[string]bool
	suffixes  []string
	origins   map[string]bool
	anyOrigin bool
}

func parseHostPolicy(hosts, origins string) hostPolicy {
	p := hostPolicy{exact: map[string]bool{}, origins: map[string]bool{},
		suffixes: append([]string(nil), defaultHostSuffixes...)}
	for _, e := range strings.Split(hosts, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		switch {
		case e == "":
		case e == "*":
			p.anyHost = true
		case strings.HasPrefix(e, "*."):
			p.suffixes = append(p.suffixes, e[1:])
		case strings.HasPrefix(e, "."):
			p.suffixes = append(p.suffixes, e)
		default:
			p.exact[hostOnly(e)] = true
		}
	}
	for _, e := range strings.Split(origins, ",") {
		e = strings.ToLower(strings.TrimRight(strings.TrimSpace(e), "/"))
		switch {
		case e == "":
		case e == "*":
			p.anyOrigin = true
		default:
			p.origins[e] = true
		}
	}
	return p
}

func hostPolicyFromEnv() hostPolicy {
	return parseHostPolicy(os.Getenv("LOOM_ALLOWED_HOSTS"), os.Getenv("LOOM_ALLOWED_ORIGINS"))
}

// hostOnly: the hostname of a Host value — port dropped, brackets off,
// lowercased, trailing dot removed.
func hostOnly(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	v = strings.TrimPrefix(strings.TrimSuffix(v, "]"), "[")
	return strings.TrimSuffix(v, ".")
}

func (p hostPolicy) allowsHost(header string) bool {
	if p.anyHost || header == "" {
		return true
	}
	h := hostOnly(header)
	if h == "" || h == "localhost" || net.ParseIP(h) != nil || p.exact[h] || !strings.Contains(h, ".") {
		return true
	}
	for _, s := range p.suffixes {
		if strings.HasSuffix(h, s) {
			return true
		}
	}
	return false
}

func (p hostPolicy) allowsOrigin(origin, host string) bool {
	if origin == "" || p.anyOrigin {
		return true
	}
	origin = strings.ToLower(strings.TrimRight(strings.TrimSpace(origin), "/"))
	if p.origins[origin] {
		return true
	}
	if origin == "null" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return u.Scheme == "http" || u.Scheme == "https"
	}
	return host != "" && u.Host == strings.ToLower(host)
}

func isJSONMediaType(ct string) bool {
	media, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return jsonMediaTypes[media] || (strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json"))
}

// guardBrowser wraps the gateway's handler with the Host / Origin /
// Content-Type checks. Nothing here reads a body.
func guardBrowser(next http.Handler, p hostPolicy, m *gwMetrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.allowsHost(r.Host) {
			m.rejectedBad.Add(1)
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"detail": "invalid Host header: add this name to LOOM_ALLOWED_HOSTS if Loom is served under it"})
			return
		}
		if !p.allowsOrigin(r.Header.Get("Origin"), r.Host) {
			m.rejectedAuth.Add(1)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"detail": "cross-origin browser requests are not allowed: list the origin in LOOM_ALLOWED_ORIGINS to permit it"})
			return
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/") &&
			!isJSONMediaType(r.Header.Get("Content-Type")) {
			m.rejectedBad.Add(1)
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{
				"detail": "Content-Type must be application/json (or application/x-ndjson on /v1/ingest/batch)"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
