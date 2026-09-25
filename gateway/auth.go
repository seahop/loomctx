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
	"log"
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
	// per-key rate limit (R-10); nil = the LOOM_RATE_PER_SEC default. The
	// engine reads the same two fields (and rate_llm_per_sec, which only
	// it enforces — the gateway has no LLM routes), so one keys file
	// serves both.
	RatePerSec *float64 `json:"rate_per_sec"`
	RateBurst  *int     `json:"rate_burst"`

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
		if sourceMatches(e, s) {
			return true
		}
	}
	return false
}

// sourceMatches: an exact source name, or a family ending in ":*" — "nvd:*"
// covers "nvd:cve@mitre.org" but not "nvd" itself (the engine's rule, D-063).
func sourceMatches(pattern, source string) bool {
	if strings.HasSuffix(pattern, ":*") {
		return strings.HasPrefix(source, pattern[:len(pattern)-1])
	}
	return pattern == source
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
	// One malformed entry disables THAT key (logged), never the whole file —
	// the same tolerance the Python engine applies, so both sides of a
	// shared Secret see the same live key set (H-A13).
	var entries []authEntry
	for i, k := range doc.Keys {
		if k == nil || k.Disabled {
			continue
		}
		entry, err := parseEntry(k)
		if err != nil {
			log.Printf("auth: skipping key entry %d (%q): %v", i, k.ID, err)
			continue
		}
		entries = append(entries, entry)
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

// expiresLayouts: RFC3339 first; a naive timestamp or a bare date is taken
// as UTC — same rule as the Python engine and the stored data (H-A5).
var expiresLayouts = []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"}

func parseExpires(value string) (time.Time, error) {
	var last error
	for _, layout := range expiresLayouts {
		t, err := time.Parse(layout, value)
		if err == nil {
			return t.UTC(), nil
		}
		last = err
	}
	return time.Time{}, last
}

func parseEntry(k *grantFile) (authEntry, error) {
	hash, err := hex.DecodeString(strings.ToLower(k.SHA256))
	if err != nil || len(hash) != sha256.Size {
		return authEntry{}, fmt.Errorf("bad sha256")
	}
	if k.ID == "" || len(k.Namespaces) == 0 {
		return authEntry{}, fmt.Errorf("id and namespaces are required")
	}
	if k.Perms == "" {
		return authEntry{}, fmt.Errorf("perms is required")
	}
	for _, c := range k.Perms {
		if c != 'r' && c != 'w' {
			return authEntry{}, fmt.Errorf("perms must be r/w/rw, got %q", k.Perms)
		}
	}
	g := &grant{ID: k.ID, Namespaces: k.Namespaces, Perms: k.Perms,
		EntityTypes: k.EntityTypes, Sources: k.Sources,
		RatePerSec: k.RatePerSec, RateBurst: k.RateBurst}
	// zero/negative is a configuration error, not "unlimited" (the way to
	// lift a key's cap is to remove the field) — same rule as the engine
	if k.RatePerSec != nil && *k.RatePerSec <= 0 {
		return authEntry{}, fmt.Errorf("rate_per_sec must be positive")
	}
	if k.RateBurst != nil && *k.RateBurst <= 0 {
		return authEntry{}, fmt.Errorf("rate_burst must be positive")
	}
	if k.Expires != "" {
		t, err := parseExpires(k.Expires)
		if err != nil {
			return authEntry{}, fmt.Errorf("bad expires: %w", err)
		}
		g.expiresAt = t
	}
	return authEntry{hash: hash, grant: g}, nil
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
	RatePerSec  *float64 `json:"rate_per_sec"`
	RateBurst   *int     `json:"rate_burst"`
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
	if err != nil {
		return
	}
	a.mu.Lock()
	unchanged := info.ModTime().Equal(a.mtime)
	if !unchanged {
		// advance the marker first: a broken rewrite is reported once, not
		// re-parsed on every request (H-A12)
		a.mtime = info.ModTime()
	}
	a.mu.Unlock()
	if unchanged {
		return
	}
	if err := a.reload(); err != nil {
		log.Printf("auth: reload of %s failed, keeping previous keys: %v", a.path, err)
	}
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
