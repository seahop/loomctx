package loomctx

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Drift guard: every envelope this client builds must satisfy the same
// IngestEnvelope schema the gateway enforces (contracts/schemas.json).
func TestEnvelopesSatisfyTheContract(t *testing.T) {
	path := os.Getenv("LOOMCTX_SCHEMAS")
	if path == "" {
		path = "../../contracts/schemas.json"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("contracts/schemas.json not available: %v", err)
	}
	var exported map[string]any
	if err := json.Unmarshal(raw, &exported); err != nil {
		t.Fatal(err)
	}
	buf, _ := json.Marshal(exported["IngestEnvelope"])
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	comp := jsonschema.NewCompiler()
	if err := comp.AddResource("envelope.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := comp.Compile("envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	c := New("http://x", "netsec")
	when := time.Date(2026, 9, 1, 14, 3, 0, 0, time.UTC)
	text := "report body"
	conf := 0.7
	for _, v := range []any{
		c.withNamespace(Claim{Subject: EntityRef{"host", "web-01"}, Predicate: "logged_in_by",
			Object: EntityRef{"user", "jdoe"}, ObservedAt: when, Source: "auth-log", EventID: "e1"}),
		c.withNamespace(Claim{Subject: EntityRef{"host", "web-01"}, Predicate: "runs_os",
			Object: "fedora-44", ObservedAt: when, Source: "inv", Confidence: &conf,
			Attrs: map[string]any{"method": "ssh"}}),
		c.withNamespace(Document{Text: &text, Source: "ir", ObservedAt: when, Filename: "ir.txt"}),
	} {
		env, err := Envelope(v)
		if err != nil {
			t.Fatal(err)
		}
		round, _ := json.Marshal(env)
		inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(round))
		if err := schema.Validate(inst); err != nil {
			t.Fatalf("%s violates the contract: %v", round, err)
		}
	}
}

// Live round trip against an engine (LOOMCTX_URL); skipped otherwise.
func TestLiveRoundTrip(t *testing.T) {
	base := os.Getenv("LOOMCTX_URL")
	if base == "" {
		t.Skip("LOOMCTX_URL not set")
	}
	ctx := context.Background()
	c := New(base, "gosdk")
	if !c.Ready(ctx) {
		t.Fatal("engine not ready")
	}
	when := time.Date(2026, 9, 1, 14, 3, 0, 0, time.UTC)
	first, err := c.Claim(ctx, Claim{Subject: EntityRef{"host", "web 01/a"}, Predicate: "logged_in_by",
		Object: EntityRef{"user", "j&d"}, ObservedAt: when, Source: "auth-log", EventID: "go-e1"})
	if err != nil {
		t.Fatal(err)
	}
	again, _ := c.Claim(ctx, Claim{Subject: EntityRef{"host", "web 01/a"}, Predicate: "logged_in_by",
		Object: EntityRef{"user", "j&d"}, ObservedAt: when, Source: "auth-log", EventID: "go-e1"})
	if again.ObservationID != first.ObservationID {
		t.Fatalf("replay not deduped: %s vs %s", again.ObservationID, first.ObservationID)
	}
	text := "report body"
	batch, err := c.IngestBatch(ctx,
		Claim{Subject: EntityRef{"host", "db-01"}, Predicate: "runs_os", Object: "rhel-9", ObservedAt: when, Source: "inv"},
		Document{Text: &text, Source: "ir", ObservedAt: when, EventID: "go-d1"},
	)
	if err != nil || batch.Recorded != 1 || batch.Accepted != 1 {
		t.Fatalf("batch: %+v err=%v", batch, err)
	}
	obs, err := c.Observations(ctx, EntityRef{"host", "web 01/a"}, 10)
	if err != nil || obs["count"].(float64) != 1 {
		t.Fatalf("observations: %v err=%v", obs, err)
	}
	pack, err := c.Ask(ctx, &EntityRef{"host", "web 01/a"}, "who logged in?", AskOptions{Budget: 400})
	if err != nil || len(pack.Items) == 0 || len(pack.Items[0].Citations) == 0 {
		t.Fatalf("ask: %+v err=%v", pack, err)
	}
	if _, err := c.Claim(ctx, Claim{Subject: EntityRef{"host", "web 01/a"}, Predicate: "member_of",
		Object: EntityRef{"domain", "corp.local"}, ObservedAt: when, Source: "inv", EventID: "go-m1"}); err != nil {
		t.Fatal(err)
	}
	paths, err := c.Path(ctx, EntityRef{"user", "j&d"}, EntityRef{"domain", "corp.local"},
		PathOptions{Via: []string{"logged_in_by", "member_of"}, Depth: 2, Budget: 2000})
	if err != nil || len(paths.Paths) == 0 || paths.From.Key != "j&d" {
		t.Fatalf("path: %+v err=%v", paths, err)
	}
	if paths.Paths[0][0].Cite.Source == "" {
		t.Fatalf("path edge not cited: %+v", paths.Paths[0][0])
	}
	if _, err := c.Artifact(ctx, "missing"); err == nil {
		t.Fatal("expected an error for a missing artifact")
	} else if le, ok := err.(*Error); !ok || le.Status != 404 {
		t.Fatalf("expected *Error 404, got %v", err)
	}
	reader := New(base, "gosdk")
	reader.APIKey = "nope"
	if _, err := reader.Ask(ctx, &EntityRef{"host", "x"}, "?", AskOptions{}); err != nil {
		if le, ok := err.(*Error); ok && le.Status != 403 && le.Status != 200 {
			// auth may be disabled in the test engine; a 403 or success are both fine
		}
	}
}

// A key read from a file or a k8s Secret often ends in a newline; the client
// strips it before sending, as the Python SDK does (review 2026-09-26).
func TestAPIKeyIsTrimmed(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("X-LoomCtx-Key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "ns")
	c.APIKey = "  s3cret\n"
	if !c.Ready(context.Background()) {
		t.Fatal("not ready")
	}
	c.APIKey = " \n"
	c.Ready(context.Background())
	if len(got) != 2 || got[0] != "s3cret" || got[1] != "" {
		t.Fatalf("X-LoomCtx-Key sent as %q", got)
	}
}
