package main

// Per-namespace API keys (docs/decisions.md D-013) — the SAME env format the
// Python engine parses, so one secret configures the whole deployment:
//
//	LOOM_API_KEYS="key:namespace:perms,key:namespace:perms"
//
// perms ⊆ {r,w}; namespace "*" = all. Unset => auth disabled (open dev mode).

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
)

type authEntry struct {
	key       string
	namespace string
	perms     string
}

type authConfig struct {
	entries []authEntry
}

func parseAuth(raw string) (*authConfig, error) {
	cfg := &authConfig{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cfg, nil
	}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.Split(item, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, fmt.Errorf("LOOM_API_KEYS: bad entry %q — expected key:namespace:perms", item)
		}
		for _, c := range parts[2] {
			if c != 'r' && c != 'w' {
				return nil, fmt.Errorf("LOOM_API_KEYS: perms must be r/w/rw, got %q", parts[2])
			}
		}
		cfg.entries = append(cfg.entries, authEntry{key: parts[0], namespace: parts[1], perms: parts[2]})
	}
	return cfg, nil
}

func (a *authConfig) enabled() bool { return len(a.entries) > 0 }

func (a *authConfig) allows(key, namespace, action string) bool {
	if !a.enabled() {
		return true
	}
	if key == "" {
		return false
	}
	for _, e := range a.entries {
		if subtle.ConstantTimeCompare([]byte(e.key), []byte(key)) != 1 {
			continue
		}
		if e.namespace != "*" && e.namespace != namespace {
			continue
		}
		if strings.Contains(e.perms, action) {
			return true
		}
	}
	return false
}

func extractKey(r *http.Request) string {
	if k := r.Header.Get("X-Loom-Key"); k != "" {
		return k
	}
	authz := r.Header.Get("Authorization")
	if len(authz) > 7 && strings.EqualFold(authz[:7], "bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}
