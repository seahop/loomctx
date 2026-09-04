# Decisions & constraints

Running log of choices with rationale. Newest additions at the bottom. If a decision
is revisited, strike it here and add the replacement — don't rewrite history.

## Hard constraints (hold unless the user says otherwise)

1. **Docker-only builds and runs.** Nothing installs or executes on the host beyond
   `docker compose ...`. Tests, servers, and one-off scripts all run in containers.
   This keeps the host sanitary and is a standing project rule.
2. **Small-resource posture.** Target: large *context*, not big data. One or two
   containers, volume-backed state, runs on a laptop or a $10 VPS. No Kafka, no
   Elasticsearch, no managed-cloud dependencies in the core. Two deployment
   shapes only: local Docker Compose, and the k8s manifests in `deploy/k8s`
   (D-008) — same image, same behavior.
3. **Provenance is mandatory.** Every observation names its source; every context-pack
   item cites its observations. No uncited derived facts.
4. **Observations are append-only.** Corrections supersede; nothing is edited in place.
5. **Budgets are mandatory on reads.** No API that returns unbounded context.
6. **Domain-agnostic core.** Domain knowledge lives in the schema registry and
   plugins (see "malleable" in `concepts.md`), never in core code.

## D-001 · Core language: Python 3.12

- **Why:** best MCP + LLM ecosystem (official MCP SDK, every model provider),
  Pydantic v2 gives contracts-as-code with JSON Schema export for free, and it is the
  language the widest range of target teams can extend. Performance is a non-issue at
  this scale (I/O-bound; SQLite does the heavy lifting).
- **Considered:** TypeScript (fine MCP story, weaker data tooling); Go/Rust (faster,
  but slower iteration and much weaker LLM-library ecosystem; nothing here needs the
  speed).
- **Escape hatch:** contracts are JSON-Schema-first (exported from Pydantic), so SDKs
  in other languages implement against the schema, not against Python.

### D-001a · Scaling addendum (2026-09-03): Python is not the bottleneck

Considered deliberately early, at the user's request. Where load actually lands,
in order:

1. **Store first.** SQLite's single writer caps out long before Python does
   (~1–3k req/s per uvicorn worker ≈ tens of millions of claims/day per pod).
   Remedy is the D-008 store swap (Postgres/Neo4j) — no language change.
2. **Replicas second.** With a server-backed store, stateless engine pods scale
   horizontally on k8s. The request path is I/O-bound, where replicas beat a
   faster language; the GIL only penalizes CPU-bound work we don't do in-process.
3. **Enrichment is LLM-bound** and *wants* Python's ML/MCP ecosystem; vector
   math runs in C (sqlite-vec/numpy) regardless.

Python becomes wrong only outside the project charter (>~10k events/sec/node
sustained, sub-ms p99, heavy per-request CPU). The plan then is a **partial**
rewrite — the ingest gateway alone in Go/Rust against the same JSON contracts —
never a whole-system port.

**Guardrails that keep that option cheap (enforce from now on):**
- Contracts and wire/storage formats stay language-neutral: JSON + SQL only,
  never pickle, never Python-typed blobs, no framework types leaking into
  responses.
- Business logic stays out of surface adapters (HTTP/MCP/CLI remain thin), so
  a replacement gateway re-implements transport, not semantics.
- Before claiming capacity numbers (e.g. at the conference), measure with a
  load test rather than citing this addendum.

## D-002 · Default store: SQLite (+ sqlite-vec later), behind a `GraphStore` interface

- **Why:** single-file, zero-ops, trivially Dockerized, handles millions of
  observations; matches the small-resource constraint. Embedded vector search via
  sqlite-vec when embeddings land (phase 4) — no separate vector DB.
- **Neo4j** stays on the menu as a drop-in `GraphStore` implementation (compose
  profile already sketched) for teams wanting Cypher or visual exploration — but it
  is not required and not the default. Kùzu is a middle option if traversal ever
  outgrows SQLite.
- **Rule:** no code outside `src/loom/store/` may touch persistence directly.

## D-003 · Contracts before code

The Pydantic models in `src/loom/contracts.py` *are* the API. HTTP, MCP, SDK, and CLI
all serialize these exact shapes. Breaking a contract is a versioned event, not a
refactor.

## D-004 · Async enrichment, in-process first

Documents are acknowledged on artifact write; extraction/embedding/dossier work runs
in background tasks inside the engine container. A real queue (e.g. Redis + worker
container) is added only when measured ingestion volume demands it. No speculative
infrastructure.

## D-005 · Working name "Loom"

Provisional; chosen for the weaving metaphor and a short CLI name. Known collision
with loom.com — acceptable since there is no website planned for this project
(2026-09-03), but revisit the name before the conference for slide/branding
purposes. Repo is public at github.com/seahop/Loom.
Python package: `loom` internally; PyPI-safe name TBD (e.g. `loom-ctx`) if published.

## D-006 · API surface order: HTTP first, MCP second, SDK third, CLI alongside

HTTP is the substrate (easiest to test, everything can call it). The MCP server wraps
the same core service functions in-process. The Python SDK is a thin typed client
over HTTP. See `docs/sdk.md`.

## D-007 · LLM access is a pluggable interface

Enrichers depend on an `LLMClient` protocol (default: Anthropic API via env-provided
key), so teams can point at whatever provider or local model they have. The core
never imports a provider SDK outside the default adapter.

## D-008 · Kubernetes deployment: single replica + PVC now, scale via store swap (2026-09-03)

`deploy/k8s` ships a Deployment (replicas: 1, Recreate), PVC, and Service.
One replica is the *correct* shape for the SQLite store (single writer on an
RWO volume), not a stopgap — it comfortably serves the target workload. The
scale-out path is swapping `GraphStore` for a server-backed implementation
(Postgres or Neo4j, phase 5); then replicas scale horizontally with no API,
image, or manifest-structure changes. No ingress in-repo (environment-specific;
requires auth first, OQ-3). Local Compose remains the primary dev/demo shape.

## D-009 · CI + image publishing via GitHub Actions → GHCR (2026-09-03)

Every push/PR runs the Docker test suite; pushes to `main` publish
`ghcr.io/seahop/loom:latest` and a per-SHA tag, which the k8s manifests
consume. The repo is public, so `main` must always be green and presentable
(conference: end of October 2026).

## D-010 · Ingestion tier: Go gateway + standard load balancing, two deployment shapes (2026-09-03)

Direction set by the user: the ingestion point should be Go or Rust, and the
design must accommodate load balancing, multiple ingestion nodes, and a
built-in proxy story. Decisions:

- **Language: Go** for the ingest gateway. Tiny static binaries, trivial
  concurrency for an I/O fan-in workload, JSON Schema validation against the
  exported contracts (the D-001a language-neutral payoff), and the easiest
  contributor story for infra-minded teams. Rust remains the fallback if
  profiling ever demands it; nothing else changes since the boundary is the
  wire contract.
- **The gateway is stateless**: authenticate, validate the envelope, rate-limit,
  batch, forward. All semantics (entity resolution, storage) stay in the core.
  Stateless is what makes "multiple ingestion nodes" free.
- **Proxy/LB = boring, shipped, not invented.** We do not write a custom proxy.
  "Built in" means the repo ships working configs: on k8s, a Service +
  HorizontalPodAutoscaler over gateway replicas (round-robin LB is native);
  locally, a compose `scale` profile with nginx in front of N gateways.
- **Two shapes, one contract.** Default shape: single engine container, no
  gateway, no queue — unchanged. Scale shape: N Go gateways → durable buffer
  (NATS JetStream: one small container, chosen over Kafka-class infra per hard
  constraint 2) → writer consumer(s) → server-backed GraphStore (D-008). The
  buffer absorbs bursts, gives backpressure and at-least-once delivery, and
  reconciles many ingestion nodes with the store's write path.
- `POST /v1/ingest` is identical at every boundary; SDKs and pipeline devices
  cannot tell which shape is deployed.

Build order: design now (this entry + architecture.md), build post-conference
unless demo load requires it sooner (roadmap phase 5). Resolves OQ-1's shape:
the queue exists only in the scale profile.

**Update 2026-09-03: built same day at the user's request.** `gateway/` (Go,
validates against `contracts/schemas.json` — the checked-in export that CI
keeps in sync with the Pydantic contracts), compose `scale` profile (nginx lb
on host :8081), `deploy/k8s/scale` overlay, `loom.consumer` writer, SQLite
WAL mode. Verified live: multi-gateway ingest → JetStream → consumer →
`/v1/ask`, with contract violations rejected at the gateway.

## D-011 · Database: two lanes — tuned singular SQLite, or Postgres by connection string (2026-09-03)

User requirement: the database must be able to scale, AND a singular setup
must handle decent input volume if that's all a team wants. Both lanes ship:

- **Singular lane (default): SQLite, tuned.** WAL + `synchronous=NORMAL`
  (one fsync per transaction, safe under WAL), busy timeout, and batched
  claim writes (`GraphStore.record_claims`) committed as one transaction —
  the queue consumer writes whole fetched batches this way. Measured
  2026-09-03 (laptop, one container, per-request HTTP ingest): **~507
  claims/s, 0 errors** (~44M/day). The measuring tool ships as
  `python -m loom.loadgen`; at these rates the load *generator* is the
  bottleneck, so treat the numbers as floors.
- **Scaling lane: `PostgresStore`,** selected purely by connection string —
  `LOOM_DB=postgresql://...` and nothing else changes (engine, consumer, and
  seed all go through `store.factory`). Identical column shapes and shared
  row converters keep behavior byte-for-byte equal; the same contract test
  suite runs against both backends (CI spins up Postgres via the compose
  `pg` profile). Measured: ~454 claims/s through the same per-request path.
  This is what lets engine replicas + writer consumers scale horizontally on
  k8s (D-008's promise, now real).
- Scale-shape intake measured end-to-end the same day: lb → 3 gateways →
  NATS at **~515/s intake** with the consumer draining all messages in
  batched transactions.
- Rule: backends must stay behaviorally identical — new store features land
  in the shared contract tests first. Neo4j remains a possible third backend
  for graph-native traversal, not a throughput play.

## D-012 · Answering LLMs: OpenAI-compatible everywhere + Anthropic native + self-hosted; scoped questions (2026-09-03)

User requirements: agents/models talking to Loom must work with OpenRouter,
Venice, other common providers, or a custom self-hosted instance; and
questions may span multiple computers or "a domain and its contents".

**Provider strategy — one wire format covers nearly everyone.** OpenRouter,
Venice, Groq, Together, Mistral, OpenAI, Ollama, vLLM, and LM Studio all
speak the OpenAI-compatible chat-completions API, so `loom/llm.py` ships one
stdlib-only client for all of them (provider shortcut → base URL, or
`LOOM_LLM_BASE_URL` for anything self-hosted/custom) plus a native Anthropic
client. Config is four env vars: `LOOM_LLM_MODEL` (required),
`LOOM_LLM_PROVIDER` or `LOOM_LLM_BASE_URL`, `LOOM_LLM_API_KEY`. Unconfigured
=> `/v1/answer` returns 503 with setup instructions; everything else works
without any LLM. No provider SDK dependencies in the core, per D-007.

**`POST /v1/answer` = ask + synthesize.** Builds the context pack, hands
pack + question to the LLM under a system prompt that requires citations,
surfaces conflicts both-sided, and forbids guessing beyond the pack. The
response returns the pack alongside the answer so callers can audit exactly
what the model saw.

**Scopes (multi-entity questions).** `ScopeSpec {subjects, expand, depth}`:
several subjects at once, optionally expanded by BFS over named containment
predicates (e.g. `member_of`) — "domain corp.local and everything in it"
is `{subjects: [domain:corp.local], expand: [member_of], depth: 1}`. Packs
gather across the resolved entities, dedupe observations, run conflict
detection per subject, and share one budget. `AskRequest` now takes exactly
one of `subject` | `scope`; `ContextPack.subject` became optional with a new
always-populated `subjects` list (contract change, pre-1.0).

**Auto-resolution.** With neither subject nor scope, `/v1/answer` resolves
subjects from entity keys appearing verbatim in the question (backed by the
new `search_entities` store method + `GET /v1/entities/search`). Exact
matches only — auto-resolution must never guess; unresolvable => 422.
Registry-declared containment predicates (so scopes expand without the
caller naming predicates) land with schema-registry persistence.

## D-013 · Auth & abuse resistance: per-namespace API keys, cheap rejection first (2026-09-04)

One env var configures the engine AND the Go gateway identically:
`LOOM_API_KEYS="key:namespace:perms,..."` (perms r/w/rw, namespace `*` = all).
Unset ⇒ open dev mode with a logged warning. Keys arrive as `X-Loom-Key` or
`Authorization: Bearer`; comparison is constant-time. Enforcement: writes
check the envelope's namespace, reads check the queried namespace (expand
decodes the handle's namespace before touching the store). `/healthz`,
`/readyz`, `/metrics` stay open for probes and scrapes.

Bad traffic is shed in cost order at the gateway — missing key (when auth is
on) and the **per-key token bucket** both reject before the body is even
read; then size cap, JSON parse, schema validation, then namespace authz —
so abusive or misconfigured senders never reach the queue or the store, and
one noisy key can't starve the others (429 carries Retry-After). Contracts
cap question length (2k chars) and budgets (32k tokens). MCP stdio is
local-trust by design; the MCP http profile should sit behind cluster policy
until it grows its own auth (open item).

## D-013a · Key generation, hashed keys file, and data-scoping gates (2026-09-04)

Design principle, set by the user: **capabilities are never gated — data is.**
A valid reader always has the full query surface including `/v1/answer`; the
rules control which slice of the world those queries operate over.

- **Generation:** `python -m loom.keys generate` mints `loomk_...` keys
  (32 random bytes), prints the plaintext exactly once, and stores only the
  SHA-256 in a keys file. `list`/`revoke` manage it. Distribute the file via
  `LOOM_AUTH_FILE` (a k8s Secret mount / compose bind mount); the engine and
  the Go gateway **hot-reload it on change**, so rotation is
  generate → hand over → revoke, with no restarts. Legacy `LOOM_API_KEYS`
  plaintext env entries keep working (hashed in memory).
- **Grants (per key):** `namespaces` + `perms` (a sender's key is `w` only —
  it can put data in but never read anything back), optional
  `entity_types` allowlist (an operator's agent key scoped to what that user
  may see), optional `sources` allowlist for writes (**source pinning**: a
  compromised log shipper cannot forge facts attributed to other sources),
  optional `expires`, and `disabled`.
- **Enforcement style:** explicit requests for out-of-scope data get a 403
  naming the gate; list-shaped operations (entity search, `/v1/answer`
  auto-resolution) silently operate over the scoped world instead — the
  agent experience is "this is my universe", not a wall of errors. Expand
  handles inherit the namespace check from the ask that produced them.
- **Two credentials, cleanly separated:** the Loom bearer is the *user's*
  identity + data permissions; the LLM provider key is the *server's*
  (`LOOM_LLM_API_KEY`) — users never touch it. Optionally an agent presents
  its own provider key per request (`X-Loom-LLM-Key`) so LLM spend bills to
  the caller; the provider/model stays server-chosen and the bearer still
  bounds visibility.
- Future (post-conference): per-entity ACLs / attribute rules via the schema
  registry, and an admin API for key management beyond the CLI+file flow.

## D-014 · Idempotent ingest via sender event_id (2026-09-04)

The scale shape is at-least-once (NATS redelivery after a consumer crash
would duplicate observations — and the conflict detector would then treat
copies as corroboration). Envelopes therefore carry an optional `event_id`
(≤128 chars); both stores dedupe on a partial unique index over
`(namespace, event_id)` and return the original observation. Applies to
claims and documents; envelopes without an event_id are never deduped.
Verified end-to-end through lb → gateway → NATS → consumer (3 posts → 1 row).

## D-015 · Operability: /metrics, /readyz, and a retrieval-quality harness (2026-09-04)

- Engine exposes Prometheus at `/metrics` (`loom_ingest_total{kind}`,
  `loom_ingest_deduped_total`, `loom_requests_rejected_total{reason}`,
  `loom_pack_build_seconds` histogram, `loom_answers_total{outcome}`) and a
  store-probing `/readyz` that the k8s readiness probes now use. The gateway
  serves its own hand-rolled counters at `/metrics` (requests, forwarded,
  rejected-invalid/unauthorized/ratelimited, upstream errors) — a client
  library isn't worth a dependency in the hot path.
- **Quality loop:** `tests/test_quality.py` is a golden-question scorecard
  over the seed corpus (conflict-first, relevance@5, lease history, as-of
  time travel, scope coverage, budget compliance — 9/9 passing). It runs in
  CI, so ranking changes (the phase-4 embedding swap especially) ship with
  before/after evidence.

## D-016 · Data lifecycle: export/import, retention, tombstone redaction (2026-09-04)

`python -m loom.lifecycle` provides: `export`/`import` (JSONL — backup,
SQLite⇄Postgres migration path, and the "your data is never trapped"
guarantee), `purge --older-than-days` (retention sweep of observations +
artifacts per namespace), and `redact` (a **tombstone**: the observation
stops appearing in every read but the append-only record and the tombstone
remain for audit — deletion without falsified history). Stores migrate
in-place at startup (capability-checked column/table adds), so existing
database files survive upgrades.

## D-017 · License: Apache-2.0 (2026-09-04)

Public framework needs a real license; Apache-2.0 for the patent grant and
infrastructure-ecosystem norm. Canonical text in `LICENSE`.

## Open questions (decide when the use case firms up)

- **OQ-1:** ~~Real-time requirements on ingestion → do we need a queue sooner?~~
  Shape resolved by D-010 (queue exists only in the scale profile); remaining
  question is *when* demo/adopter volume forces the scale shape.
- **OQ-2:** One shared deployment with namespaces vs. per-team stacks as the primary
  story? (Both work; affects auth priority.)
- **OQ-3:** ~~AuthN/Z on the HTTP surface~~ Resolved by D-013 (per-namespace
  API keys). Remaining: key management API (rotation without redeploy) and
  auth for the MCP http profile.
- **OQ-4:** Embedding model choice + dimensionality (affects sqlite-vec schema).
- **OQ-5:** ~~Retention/TTL policy~~ Mechanism shipped (D-016 purge/redact);
  remaining is per-team policy defaults and a scheduled sweep (cron/k8s Job).
- **OQ-6:** Public name (D-005).
