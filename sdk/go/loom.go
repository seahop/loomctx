// Package loom is a thin, dependency-free Go client for the Loom context
// engine's HTTP API (docs/sdk.md, D-034). Typed transport only — no logic —
// over the same contract the Go gateway validates (contracts/schemas.json);
// loom_test.go proves the envelopes this package builds satisfy that schema,
// so the client cannot drift from the server.
package loom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// EntityRef addresses an entity by natural key, e.g. {Type: "host", Key: "web-01"}.
type EntityRef struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

// Claim is a structured, entity-addressed fact (kind "claim").
type Claim struct {
	Namespace  string         `json:"namespace,omitempty"`
	EventID    string         `json:"event_id,omitempty"`
	Subject    EntityRef      `json:"subject"`
	Predicate  string         `json:"predicate"`
	Object     any            `json:"object"` // EntityRef or a scalar
	ObservedAt time.Time      `json:"observed_at"`
	ValidFrom  *time.Time     `json:"valid_from,omitempty"`
	ValidTo    *time.Time     `json:"valid_to,omitempty"`
	Source     string         `json:"source"`
	Confidence *float64       `json:"confidence,omitempty"`
	Attrs      map[string]any `json:"attrs,omitempty"`
}

// Document is unstructured content, stored verbatim and mined asynchronously
// (kind "document"). Exactly one of Text / ContentB64.
type Document struct {
	Namespace   string         `json:"namespace,omitempty"`
	EventID     string         `json:"event_id,omitempty"`
	Text        *string        `json:"text,omitempty"`
	ContentB64  *string        `json:"content_b64,omitempty"`
	ContentType string         `json:"content_type,omitempty"`
	Filename    string         `json:"filename,omitempty"`
	Source      string         `json:"source"`
	ObservedAt  time.Time      `json:"observed_at"`
	Attrs       map[string]any `json:"attrs,omitempty"`
}

// AskOptions: As_of = what was KNOWN at T; ValidAt = what was TRUE at T.
type AskOptions struct {
	Budget  int
	AsOf    *time.Time
	ValidAt *time.Time
	Scope   *Scope
}

type Scope struct {
	Subjects []EntityRef `json:"subjects"`
	Expand   []string    `json:"expand,omitempty"`
	Depth    int         `json:"depth"`
}

// Citation names an observation or an artifact span (D-023).
type Citation struct {
	ObservationID string    `json:"observation_id,omitempty"`
	ArtifactID    string    `json:"artifact_id,omitempty"`
	SpanStart     *int      `json:"span_start,omitempty"`
	SpanEnd       *int      `json:"span_end,omitempty"`
	Source        string    `json:"source"`
	ObservedAt    time.Time `json:"observed_at"`
}

type ContextItem struct {
	Kind      string     `json:"kind"`
	Text      string     `json:"text"`
	Score     float64    `json:"score"`
	Citations []Citation `json:"citations"`
}

type ExpansionHandle struct {
	ID        string `json:"id"`
	Hint      string `json:"hint"`
	EstTokens *int   `json:"est_tokens,omitempty"`
	Kind      string `json:"kind"`
}

type ContextPack struct {
	Namespace string            `json:"namespace"`
	Subject   *EntityRef        `json:"subject"`
	Subjects  []EntityRef       `json:"subjects"`
	Question  *string           `json:"question"`
	Budget    int               `json:"budget"`
	Items     []ContextItem     `json:"items"`
	Handles   []ExpansionHandle `json:"handles"`
}

type IngestResult struct {
	Status        string `json:"status"`
	ObservationID string `json:"observation_id,omitempty"`
	ArtifactID    string `json:"artifact_id,omitempty"`
	Extraction    string `json:"extraction,omitempty"`
}

type BatchItemResult struct {
	Index         int    `json:"index"`
	Status        string `json:"status"`
	ObservationID string `json:"observation_id,omitempty"`
	ArtifactID    string `json:"artifact_id,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type BatchResult struct {
	Total    int               `json:"total"`
	Recorded int               `json:"recorded"`
	Accepted int               `json:"accepted"`
	Rejected int               `json:"rejected"`
	Results  []BatchItemResult `json:"results"`
}

// Error is a non-2xx response: Status is the HTTP code, Detail the engine's message.
type Error struct {
	Status int
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("loom: HTTP %d: %s", e.Status, e.Detail) }

// Client is safe for concurrent use.
type Client struct {
	BaseURL   string
	Namespace string
	APIKey    string // X-Loom-Key
	LLMKey    string // X-Loom-LLM-Key on Answer (bill LLM spend to the caller)
	HTTP      *http.Client
}

// New returns a client for baseURL in namespace ns ("" = "default").
func New(baseURL, ns string) *Client {
	if ns == "" {
		ns = "default"
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Namespace: ns,
		HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// ---------------------------------------------------------------- write side

// Envelope wraps a Claim or Document with its kind for /v1/ingest.
func Envelope(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	switch v.(type) {
	case Claim, *Claim:
		m["kind"] = "claim"
	case Document, *Document:
		m["kind"] = "document"
	default:
		return nil, fmt.Errorf("loom: envelope must be a Claim or Document, got %T", v)
	}
	return m, nil
}

func (c *Client) ingest(ctx context.Context, v any) (*IngestResult, error) {
	env, err := Envelope(c.withNamespace(v))
	if err != nil {
		return nil, err
	}
	var out IngestResult
	return &out, c.post(ctx, "/v1/ingest", env, nil, &out)
}

func (c *Client) withNamespace(v any) any {
	switch t := v.(type) {
	case Claim:
		if t.Namespace == "" {
			t.Namespace = c.Namespace
		}
		return t
	case Document:
		if t.Namespace == "" {
			t.Namespace = c.Namespace
		}
		return t
	}
	return v
}

func (c *Client) Claim(ctx context.Context, cl Claim) (*IngestResult, error) { return c.ingest(ctx, cl) }

func (c *Client) Document(ctx context.Context, d Document) (*IngestResult, error) {
	return c.ingest(ctx, d)
}

// IngestBatch sends many Claims/Documents in one request (D-034); each item
// is reported individually in Results, so one bad record never blocks the rest.
func (c *Client) IngestBatch(ctx context.Context, items ...any) (*BatchResult, error) {
	envs := make([]map[string]any, 0, len(items))
	for _, it := range items {
		env, err := Envelope(c.withNamespace(it))
		if err != nil {
			return nil, err
		}
		envs = append(envs, env)
	}
	var out BatchResult
	return &out, c.post(ctx, "/v1/ingest/batch", envs, nil, &out)
}

// ---------------------------------------------------------------- read side

func (c *Client) Ask(ctx context.Context, subject *EntityRef, question string, opts AskOptions) (*ContextPack, error) {
	body := map[string]any{"namespace": c.Namespace, "question": question,
		"budget": orDefault(opts.Budget, 800), "subject": subject, "scope": opts.Scope}
	if opts.AsOf != nil {
		body["as_of"] = opts.AsOf
	}
	if opts.ValidAt != nil {
		body["valid_at"] = opts.ValidAt
	}
	var out ContextPack
	return &out, c.post(ctx, "/v1/ask", body, nil, &out)
}

func (c *Client) Expand(ctx context.Context, handle string, budget int) (*ContextPack, error) {
	var out ContextPack
	return &out, c.post(ctx, "/v1/expand", map[string]any{"handle": handle, "budget": orDefault(budget, 800)}, nil, &out)
}

// Answer: retrieval-grounded LLM answer; nil subject = auto-resolve from the question.
func (c *Client) Answer(ctx context.Context, question string, subject *EntityRef, opts AskOptions) (map[string]any, error) {
	body := map[string]any{"namespace": c.Namespace, "question": question, "subject": subject,
		"scope": opts.Scope, "budget": orDefault(opts.Budget, 1200)}
	if opts.AsOf != nil {
		body["as_of"] = opts.AsOf
	}
	if opts.ValidAt != nil {
		body["valid_at"] = opts.ValidAt
	}
	headers := map[string]string{}
	if c.LLMKey != "" {
		headers["X-Loom-LLM-Key"] = c.LLMKey
	}
	var out map[string]any
	return out, c.post(ctx, "/v1/answer", body, headers, &out)
}

func (c *Client) Search(ctx context.Context, query string, limit int) (map[string]any, error) {
	var out map[string]any
	return out, c.get(ctx, "/v1/entities/search", url.Values{"q": {query}, "limit": {strconv.Itoa(orDefault(limit, 10))}}, &out)
}

// Semantic: entities related to a question by meaning (D-025); 503 until the engine has an embedder.
func (c *Client) Semantic(ctx context.Context, question string, limit int) (map[string]any, error) {
	var out map[string]any
	return out, c.get(ctx, "/v1/entities/semantic", url.Values{"q": {question}, "limit": {strconv.Itoa(orDefault(limit, 10))}}, &out)
}

func (c *Client) Observations(ctx context.Context, subject EntityRef, limit int) (map[string]any, error) {
	var out map[string]any
	p := "/v1/entities/" + url.PathEscape(subject.Type) + "/" + url.PathEscape(subject.Key) + "/observations"
	return out, c.get(ctx, p, url.Values{"limit": {strconv.Itoa(orDefault(limit, 100))}}, &out)
}

func (c *Client) Artifact(ctx context.Context, id string) (map[string]any, error) {
	var out map[string]any
	return out, c.get(ctx, "/v1/artifacts/"+url.PathEscape(id), nil, &out)
}

func (c *Client) RegisterSchema(ctx context.Context, reg map[string]any) (map[string]any, error) {
	body := map[string]any{"namespace": c.Namespace}
	for k, v := range reg {
		body[k] = v
	}
	var out map[string]any
	return out, c.post(ctx, "/v1/schemas", body, nil, &out)
}

// Ready reports whether the engine is up and its store answers.
func (c *Client) Ready(ctx context.Context) bool {
	var out map[string]any
	return c.get(ctx, "/readyz", nil, &out) == nil && out["status"] == "ready"
}

// ---------------------------------------------------------------- plumbing

func orDefault(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

func (c *Client) headers(req *http.Request, extra map[string]string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Loom-Namespace", c.Namespace)
	if c.APIKey != "" {
		req.Header.Set("X-Loom-Key", c.APIKey)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		detail := string(body)
		var parsed struct {
			Detail any `json:"detail"`
		}
		if json.Unmarshal(body, &parsed) == nil && parsed.Detail != nil {
			if s, ok := parsed.Detail.(string); ok {
				detail = s
			} else if b, err := json.Marshal(parsed.Detail); err == nil {
				detail = string(b)
			}
		}
		return &Error{Status: resp.StatusCode, Detail: detail}
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (c *Client) post(ctx context.Context, path string, body any, extra map[string]string, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	c.headers(req, extra)
	return c.do(req, out)
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	c.headers(req, nil)
	return c.do(req, out)
}
