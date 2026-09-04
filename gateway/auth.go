package main

// API keys with scoping gates (docs/decisions.md D-013/D-013a) — parses the
// SAME configuration the Python engine does, so one Secret configures both:
//
//   LOOM_AUTH_FILE=/etc/loom/keys.json   preferred: hashed keys + gates,
//                                        hot-reloaded on mtime change
//   LOOM_API_KEYS="key:ns:perms,..."     legacy plaintext (hashed in memory)
//
// Both unset => auth disabled (open dev mode).

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type grant struct {
	ID          string   `json:"id"`
	Namespaces  []string `json:"namespaces"`
	Perms       string   `json:"perms"`
	EntityTypes []string `json:"entity_types"`
	Sources     []string `json:"sources"`
	Expires     string   `json:"expires"`
	Disabled    bool     `json:"disabled"`

	expiresAt time.Time // parsed; zero = never
}

func (g *grant) allows(namespace, action string) bool {
	if !strings.Contains(g.Perms, action) {
		return false
	}
	for _, ns := range g.Namespaces {
		if ns == "*" || ns == namespace {
			return true
		}
	}
	return false
}

func (g *grant) allowsEntityType(t string) bool {
	if g.EntityTypes == nil {
		return true
	}
	for _, e := range g.EntityTypes {
		if e == t {
			return true
		}
	}
	return false
}

func (g *grant) allowsSource(s string) bool {
	if g.Sources == nil {
		return true
	}
	for _, e := range g.Sources {
		if e == s {
			return true
		}
	}
	return false
}

type authEntry struct {
	hash  []byte // sha256 of the plaintext key
	grant *grant
}

type authConfig struct {
	mu      sync.Mutex
	entries []authEntry
	path    string // keys file for hot reload; "" = env/static
	mtime   time.Time
}

func loadAuth() (*authConfig, error) {
	if path := strings.TrimSpace(os.Getenv("LOOM_AUTH_FILE")); path != "" {
		cfg := &authConfig{path: path}
		if err := cfg.reload(); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	return parseAuth(os.Getenv("LOOM_API_KEYS"))
}

func (a *authConfig) reload() error {
	raw, err := os.ReadFile(a.path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", a.path, err)
	}
	var doc struct {
		Keys []*grantFile `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parsing %s: %w", a.path, err)
	}
	var entries []authEntry
	for _, k := range doc.Keys {
		if k.Disabled {
			continue
		}
		hash, err := hex.DecodeString(strings.ToLower(k.SHA256))
		if err != nil || len(hash) != sha256.Size {
			return fmt.Errorf("key %q: bad sha256", k.ID)
		}
		g := &grant{ID: k.ID, Namespaces: k.Namespaces, Perms: k.Perms,
			EntityTypes: k.EntityTypes, Sources: k.Sources}
		if k.Expires != "" {
			t, err := time.Parse(time.RFC3339, k.Expires)
			if err != nil {
				return fmt.Errorf("key %q: bad expires: %w", k.ID, err)
			}
			g.expiresAt = t
		}
		entries = append(entries, authEntry{hash: hash, grant: g})
	}
	info, _ := os.Stat(a.path)
	a.mu.Lock()
	a.entries = entries
	if info != nil {
		a.mtime = info.ModTime()
	}
	a.mu.Unlock()
	return nil
}

type grantFile struct {
	ID          string   `json:"id"`
	SHA256      string   `json:"sha256"`
	Namespaces  []string `json:"namespaces"`
	Perms       string   `json:"perms"`
	EntityTypes []string `json:"entity_types"`
	Sources     []string `json:"sources"`
	Expires     string   `json:"expires"`
	Disabled    bool     `json:"disabled"`
}

func parseAuth(raw string) (*authConfig, error) {
	cfg := &authConfig{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cfg, nil
	}
	for i, item := range strings.Split(raw, ",") {
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
		sum := sha256.Sum256([]byte(parts[0]))
		cfg.entries = append(cfg.entries, authEntry{
			hash: sum[:],
			grant: &grant{ID: fmt.Sprintf("env-%d", i),
				Namespaces: []string{parts[1]}, Perms: parts[2]},
		})
	}
	return cfg, nil
}

func (a *authConfig) enabled() bool {
	return a.path != "" || len(a.entries) > 0
}

func (a *authConfig) maybeReload() {
	if a.path == "" {
		return
	}
	info, err := os.Stat(a.path)
	if err != nil || info.ModTime().Equal(a.mtime) {
		return
	}
	_ = a.reload() // keep previous keys on a broken rewrite
}

// grantFor resolves a presented key; nil if unknown, expired, or empty.
func (a *authConfig) grantFor(key string) *grant {
	if key == "" {
		return nil
	}
	a.maybeReload()
	sum := sha256.Sum256([]byte(key))
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if subtle.ConstantTimeCompare(e.hash, sum[:]) != 1 {
			continue
		}
		if !e.grant.expiresAt.IsZero() && !now.Before(e.grant.expiresAt) {
			continue
		}
		return e.grant
	}
	return nil
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
