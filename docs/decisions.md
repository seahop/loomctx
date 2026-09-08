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
- **Administration:** the CLI + mounted-file flow is the audited admin path
  (recipes in `docs/administration.md`); `keys update` changes a principal's
  grants in place without re-minting their secret, and Secret-mount refresh
  + hot reload means no admin action restarts anything.
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

## D-018 · Phase 4 enrichment: embeddings, extraction, dossiers (2026-09-04)

Async worker `python -m loom.enrich` (compose profile `enrich`, or `--once`
for a cron/k8s Job), all three jobs idempotent and each skipped-not-failed
when unconfigured:

- **Embeddings** — pluggable `Embedder` (OpenAI-compatible `/embeddings`:
  OpenAI/Mistral/Together/Ollama/self-hosted via `LOOM_EMBED_*`), plus a
  dependency-free `HashingEmbedder` for offline/CI. Vectors stored per model;
  the pack builder ranks by cosine when vectors exist and silently falls back
  to keyword overlap otherwise, so nothing breaks unconfigured. Verified: on
  the seed corpus, a semantic query surfaces the relevant fact into the top
  slot ahead of higher-recency noise.
- **Claim extraction** — the pending-artifact backlog is mined by the LLM into
  ordinary observations with `Provenance{artifact_id, span}`; the quote is
  located back in the source text for a real character span. Each claim's
  `event_id="extract:<artifact>:<n>"` makes re-extraction idempotent (reuses
  D-014). Bad JSON → status `failed`; body-less artifacts → `skipped`. Live
  run extracted 24 claims from the 5 seed documents with correct spans.
- **Dossiers** — rolling per-entity briefs, rebuilt when `min_new`
  observations accumulate since the last build; served by the pack builder as
  a `brief` item (the cheap orientation layer). Live briefs synthesized real
  seed data well (e.g. web-01's logins, alert, and peer communications in 3
  sentences).

Extracted entities use the LLM's own keys/types (`ip_address:10.0.4.7`);
reconciling them with structured entities is D-019. The quality scorecard
(D-015) guards the structured-ranking baseline against regressions from the
embedding swap.

## D-019 · Entity resolution: same-key/cross-type merge with reversible aliases (2026-09-04)

The enrichment worker's `resolve_entities` pass folds entities that share a
natural key across differing types — the drift LLM extraction produces
(`ip_address:10.0.4.7` beside the structured `ip:10.0.4.7`) — into one node.

- **Canonical choice:** the most-connected member (most observations), ties
  broken by earliest creation — the established structured entity absorbs the
  stray extracted one, not the reverse.
- **Reversible & lossless:** `merge_entities` repoints the folded entity's
  observations onto the canonical, records the old `type:key` as an **alias**,
  and deletes only the now-empty node. Entity lookups (`get_entity`,
  `observations_for`) follow alias records, so a query for a merged-away ref
  still resolves — nothing 404s after a merge.
- **Scope of v1:** exact-key/cross-type only (deterministic, safe to
  auto-run). Embedding/typo matching (`web-01` vs `web01`) and LLM
  adjudication for genuinely ambiguous cases are the next increment
  (roadmap) — deliberately deferred because loose auto-merging is worse than
  none. Both stores implement it; the parametrized contract tests cover both.

## D-020 · Configurable budget ceiling + document-excerpt retrieval (2026-09-04)

Two related read-side additions, prompted by "a pentest report could be more
than 800 tokens."

- **The budget is the slider, and its ceiling is tunable.** Every read carries
  a per-request `budget`; the operator sets the hard ceiling via
  `LOOM_MAX_BUDGET` (default 32k). Requests above it are clamped and the pack
  reports the effective budget. The contract allows up to 1e6 as an
  absurd-value guard; `LOOM_MAX_BUDGET` is the real limit. A big *document*
  never floods the window regardless — it's mined into discrete facts, and the
  budget governs how many surface.
- **`doc_excerpt` retrieval (RAG over artifacts).** The enrichment worker now
  also chunks document artifacts (~400-char passages on paragraph/sentence
  boundaries, offsets preserved) and embeds each chunk. At read time, packs
  pull the top-cosine passages *from the documents that produced this entity's
  facts* (via observation provenance), emitted as `doc_excerpt` items citing
  `[doc:<artifact> @start-end]`, capped at half the remaining budget so
  passages inform without crowding out structured facts. This is the "read a
  large report in, get the relevant part back within budget" path; the whole
  artifact remains at `GET /v1/artifacts/{id}`.

**Operational note:** semantic ranking AND excerpt retrieval require the
*serving* engine to have `LOOM_EMBED_*` configured, not just the enrichment
worker — the query is embedded at read time. Without an embedder the engine
still answers (keyword ranking, facts only, no excerpts); it just isn't
semantic. Verified live: a pentest passage surfaces as a cited `doc_excerpt`
alongside the extracted facts.

## D-021 · Data gates apply to what a pack *contains*, not just what it was asked about (2026-09-08)

From the hardening review (`docs/hardening.md` H-A1/H-A2/H-A3). D-013a
gated the *anchor* of a read (the subject named in an ask) but not the data
the read returned: scope expansion reached any entity type, object-side
entities of returned facts were never checked, and `/v1/expand` — whose
handles are unsigned base64 JSON, i.e. a query the caller could type by
hand — checked only the namespace. A type-scoped reader could therefore
read anything in its namespace via a minted handle or a BFS hop.

- **Rule:** an observation is visible to a key only if *every* entity it
  touches (subject and, for edges, object) is in the key's `entity_types`.
  This mirrors the ingest gate, which already checks both ends. Subjects
  reached by scope expansion outside the allowlist are dropped, silently —
  the "scoped world, not a wall" experience of D-013a is preserved; only an
  *explicitly named* out-of-scope subject (in an ask, or in a handle) is a
  403.
- **Expand handles pass the same gates as a fresh ask** (namespace, then the
  decoded subject's type) and honor `LOOM_MAX_BUDGET` like ask does.
- **Optional signing:** with `LOOM_HANDLE_SECRET` set, handles are
  HMAC-SHA256 signed (`h2_` prefix) and unsigned handles are refused.
  Defense in depth — the gates above are the security boundary, signing
  just guarantees a handle is one this deployment issued. Multi-replica
  deployments must share the secret (same Secret mount as the keys file);
  rotating it invalidates outstanding handles, which is fine because
  handles are meant to live for one agent session.
- Provider error bodies no longer reach callers of `/v1/answer` (they can
  echo URLs, model names, account details): the 502 carries a short public
  form, the full detail goes to the server log.

## D-022 · Store invariants: transactional methods, race-safe dedupe, faithful export, UTC text (2026-09-08)

From `docs/hardening.md` H-B1…H-B11. Behavioral rules both backends now
share (enforced by the parametrized contract tests, per D-011):

- **Every public store method is one transaction** that rolls back on any
  exception. A failed statement never leaves partial rows for the next
  commit to persist, and never strands a Postgres connection in the
  aborted state.
- **Dedupe is race-safe.** The `(namespace, event_id)` pre-check stays as
  the cheap path; the insert itself carries `ON CONFLICT DO NOTHING` on the
  partial unique index and re-reads the winner, so two writer processes
  (engine + queue consumer) replaying the same event both get the one
  stored row.
- **Replaying a redacted event returns identity, not content.** The
  dedupe path hands back a stand-in (`object="[redacted]"`,
  `attrs={"redacted": true}`) so an idempotent sender still gets its
  observation id while nothing tombstoned is ever resurrected. Tombstoned
  rows are also excluded from dossier-candidate counts.
- **Export is faithful.** JSONL now carries `alias` and `tombstone` records
  (and entities restore with their `provisional`/`created_at`), so a
  restore keeps redactions hidden and merged-away refs resolving. Import is
  idempotent across both the id and the event_id index.
- **Timestamps are stored as UTC ISO text** (`+00:00`), naive input taken
  as UTC — contract rule — so the stores' lexical `ORDER BY`/cutoff
  comparisons are chronological across senders in different zones. Rows
  written before this change keep their original offset text; a
  normalization sweep is a one-off `lifecycle` export/import.
- **Merges are complete:** the folded node's dossier is dropped and edges
  pointing at it are rewritten to the canonical ref on both the id and the
  rendered-object side; dossier lookups follow aliases.
- **Purge sweeps derived rows** (embeddings, chunks, tombstones, dossiers of
  now-fact-less entities). Entities are kept — they carry no content.
- `search_entities` is case-insensitive on both backends and treats LIKE
  metacharacters in the query as literals.

## D-023 · Every pack item is cited; extracted claims are second-class witnesses (2026-09-08)

From `docs/hardening.md` H-C1…H-C6 and H-D1…H-D10. The review found the
project's own hard constraint 3 ("every derived fact carries citations")
broken by the two newest item kinds: `brief` items shipped with no
citations at all, and `doc_excerpt` items cited only inside their text.

**Contract change (pre-1.0):** `Citation` now names *either* an
observation *or* an artifact span — `observation_id` became optional and
`artifact_id`/`span_start`/`span_end` were added, with a validator
requiring one of the two; `ContextItem.citations` requires at least one
entry. `ExpansionHandle` gained `kind: "more" | "conflict"`.

- **Briefs cite what built them.** Dossiers persist the observation ids
  the LLM was given; at read time the brief cites those that are still
  visible to the caller (redacted or out-of-scope ones drop out). A brief
  is present-tense, so it is withheld from `as_of` reads entirely.
- **Excerpts cite `(artifact, span)`** with the artifact's source and
  observed time, and are withheld when the document postdates `as_of`.
  Chunks are keyed by embedding model — a serving embedder that differs
  from the worker's sees no chunks rather than mixing vector spaces.
  Relevance is relative (within 60% of the best passage) instead of an
  absolute cosine floor that meant nothing across embedders.
- **Conflicts are never dropped silently.** One that doesn't fit the
  budget becomes a `conflict` handle, so the agent knows contested ground
  exists and can expand it.
- **Extracted claims are tagged and discounted.** Document text is
  untrusted input (prompt injection is the obvious attack): it is
  delimited and labeled as data in the extraction prompt, every mined
  claim carries `attrs.extracted=true` (and a `doc:` source), ranks a
  notch below sender-asserted facts, and a conflict *introduced* by an
  extracted side scores 0.9 rather than 1.0 — a hostile document can
  raise a question, never outrank the asset inventory. Extracted claims'
  event ids are content hashes of (subject, predicate, object), so a
  re-extraction in a different order can't shadow a new fact.
- **The worker never dies on a job failure**: each job is guarded and
  retried next tick; per-artifact exponential backoff keeps a failing
  document from hogging the extraction slots; blank documents are skipped
  at the query; provider calls retry transient failures with backoff and
  honor `Retry-After`.

## D-024 · Closing the review: two time axes, registry served, resolution tier 2, MCP auth (2026-09-08)

The remainder of `docs/hardening.md` plus the roadmap's deferred phase-1
and phase-4 items, landed as four commits (303b225…HEAD).

- **Two time axes are now two parameters.** `as_of` is knowledge time
  (hide what was recorded after T); the new `valid_at` is fact time (keep
  only observations whose validity window covers T; un-windowed facts are
  timeless and kept). "Which host *held* 10.0.4.7 on Aug 20" is
  `valid_at`; "what did we *know* on Aug 20" is `as_of`. Handles inherit
  both. Ranking recency is time-decayed (30-day half-life relative to the
  newest gathered fact) rather than rank-based, stopwords are dropped from
  the keyword scorer, and when an embedder serves, un-embedded facts use
  the same formula with a neutral cosine so populations stay comparable.
- **Schema registry served** (`POST`/`GET /v1/schemas`, SDK
  `register_schema()`), additive by name, persisted per namespace. A
  registered predicate always enforces its `object_types`; a `strict`
  namespace rejects unregistered predicates and entity types (422).
  `PredicateDef.containment` marks the relations a scope follows when the
  caller names none — the D-012 promise. Domain knowledge stays data.
- **Entity resolution tier 2.** Entities carry a normalized key
  (lowercase, punctuation stripped). Same-type collisions
  (`web-01`/`WEB_01`/`web01`) are spelling drift and auto-merge into the
  most-connected member. Cross-type collisions are ambiguous: the worker
  asks the LLM with each record's facts as evidence and merges only on a
  confident "same" (≥0.8); declined pairs aren't re-asked. Spelling alone
  never merges across types.
- **Extraction covers the whole document** in overlapping ~8k windows;
  backoff and attempt counts persist on the artifact (dead-letter as
  `failed` after 5); a garbled reply is retried like a provider error.
- **Excerpt handles:** each `doc_excerpt` carries an `excerpt` handle that
  expands to the cited passage with its neighbours (artifact gate applies).
- **MCP auth on the HTTP transports.** stdio stays local trust. For
  streamable-http/SSE an ASGI gate rejects requests without a valid key,
  and every tool call applies the key's namespace/perms/type/source gates
  through the request headers — the same rules as the REST routes.
- **Stores:** versioned one-shot migrations on a `loom_meta` table (v2 =
  norm-key backfill) beside the idempotent DDL; SQLite enforces foreign
  keys (a startup check reports pre-existing dangling rows instead of
  refusing to start); Postgres reconnects a dropped connection; exports
  stream in keyset pages; dossier candidates count only observations
  recorded since the last brief.
- **Containers run as uid 10001** with image `HEALTHCHECK`s; k8s pods set
  `runAsNonRoot`/`fsGroup`. Bind-mounted admin recipes pass `--user`.
  Queued messages carry the sender's grant id (`Loom-Principal`) so the
  writer's log attributes each batch; the key itself never travels.
- Optional `vector` extra (numpy) batches the cosine loop; the image
  installs it, pure Python remains the fallback.

## D-025 · Vector index: sqlite-vec / pgvector beside the JSON tables, exact scan as fallback (2026-09-08)

The D-002 promise, built now for future-proofing rather than because seed
scale needed it.

- **Source of truth stays portable.** `embeddings` and `doc_chunks` keep
  vectors as JSON text: they export/import with `lifecycle`, survive a
  backend swap, and need no extension. The ANN index is *derived*: each
  backend keeps one table per (kind, embedding model, dimension) —
  `vobs_<model>_<dim>` for observations, `vchk_<model>_<dim>` for
  passages — as a sqlite-vec `vec0` virtual table (cosine metric,
  namespace partition key) or a pgvector table with an HNSW cosine index.
  Keying by dimension means a model that changes size never mixes spaces.
- **Writes populate both; reads prefer the index.** `put_embeddings` /
  `put_doc_chunks` upsert into the index in the same transaction. The
  worker's `index_pending` job backfills rows that reached the JSON
  tables without an index (imports, older builds). `nearest_observations`
  and `nearest_chunks` use the index when one exists for the query's
  (model, dimension) and otherwise scan exactly — so an engine without
  the extension is slower, never wrong. `/readyz` reports which.
- **What uses it.** Excerpt candidates in `build_pack` come from
  `nearest_chunks` restricted to the entity's cited artifacts (was: every
  chunk decoded and scored in Python). New: **semantic entity search** —
  `GET /v1/entities/semantic?q=`, MCP `find_related`, SDK `semantic()` —
  the namespace's nearest facts grouped by subject, each entity backed by
  its best-matching fact as cited evidence and filtered by the caller's
  entity-type scope. This is the read that only an index makes
  affordable at scale ("what looks exploitable?" without knowing a key).
- **Deployment.** The `vector` extra (numpy + sqlite-vec) is installed in
  the image; the compose `postgres` service is `pgvector/pgvector:pg17`.
  A Postgres without the extension simply reports `exact`.

## D-026 · TypeScript SDK generated from the contract schema; privilege-dropping entrypoint (2026-09-08)

- **`sdk/typescript/` is the D-001 escape hatch made real:** `src/contracts.ts`
  is *generated* from `contracts/schemas.json` (every root that
  `python -m loom.schemas` exports — now the full read/write surface, not
  just the envelope) by `scripts/gen.mjs`, and CI regenerates it and fails
  on drift, exactly like the Go gateway's schema check. The client
  (`src/client.ts`) is a zero-dependency `fetch` wrapper mirroring the
  Python SDK method for method (claim/document/registerSchema, observations/
  artifact/ask/expand/answer/search/semantic/schema/ready, `LoomError`
  with status + engine detail). Its test runs against a live engine in the
  compose `sdk` profile; the toolchain lives in a `node:22-alpine` image so
  nothing installs on the host. No second hand-written client will exist:
  contract fidelity is the whole compatibility story.
- **Engine entrypoint.** Running as uid 10001 (D-024) broke any volume
  created by an earlier root build (the database file was root-owned). The
  image now starts as root only to `chown` `/data`, then drops to `loom`
  via `setpriv` (util-linux, already in the base image) before exec'ing
  the command; a container started as a non-root user already (k8s
  `runAsUser`, `docker compose run --user`) execs straight through. The
  entrypoint never writes to stdout, so `python -m loom.schemas > file`
  stays clean.
- **MCP exercised by a real client.** `tests/test_mcp_client.py` spawns
  the server over stdio with the MCP SDK's client — the transport
  `claude mcp add` uses — and runs the find → ask → expand → record_claim
  loop against the seed corpus, including the fact-time `valid_at` ask.

## D-027 · Enterprise scale: the infra dials and the order to turn them (2026-09-08, direction)

Direction set by the user: large organizations must be able to scale Loom
from the infrastructure side — add database nodes, run highly available
ingestion for large volumes — without touching the contract. This entry
records what already scales, what is a single point today, and the
staged plan (`roadmap.md` phase 6). It is a *plan*; each stage gets its
own decision entry when built.

**What already scales (validated on k8s, D-026):** gateways (stateless,
HPA), engine replicas (stateless once `LOOM_DB` is Postgres, HPA), writer
consumers (shared JetStream durable, add replicas freely). The contract
(`/v1/ingest`, packs, MCP tools) is identical at every scale — that is the
D-010 promise and it holds.

**What does not, yet — verified in the code, not assumed:**

1. **The queue is one pod.** The gateway creates `LOOM_INGEST` with the
   default single replica and no retention limits; NATS runs as a
   one-replica Deployment. A NATS restart pauses ingestion (the PVC keeps
   the stream, so nothing is lost), and there is no cap on how much an
   ingestion storm can buffer.
2. **The engine serializes the database.** `PostgresStore` holds one
   connection behind a process-wide lock and uvicorn runs one worker, so a
   pod's throughput is one query at a time regardless of CPU. Adding pods
   helps; a pool would help more per pod.
3. **The database is one instance** with no replicas, failover, or read
   scaling. Every read and write hits the same node.
4. **The enrichment worker is a single process** with no job leasing: two
   workers would extract the same artifact twice (dedupe by event_id
   absorbs the duplicates, but the LLM spend is doubled).
5. **Multi-tenant growth has one database.** Namespaces isolate data but
   not capacity: every tenant shares one Postgres's write throughput.
   Every query in the store is already namespace-scoped, which is what
   makes tenant sharding cheap later.

**Stages, in the order that removes the biggest limit first:**

- **6.1 Engine concurrency.** `psycopg_pool` per process (the interface
  doesn't change: `_tx()` borrows a connection), drop the process lock for
  Postgres (SQLite keeps it — single writer by design), run uvicorn with
  N workers. Measure with `loom.loadgen` before/after; this is the
  cheapest win and the one the load test will expose first.
- **6.2 Ingestion HA.** NATS as a 3-node JetStream cluster (StatefulSet
  with routes, or the official chart), stream `replicas: 3`, explicit
  limits (`max_bytes`, `discard: old|new` chosen per deployment) so a storm
  degrades predictably; consumer `ack_wait`/`max_deliver` tuned and a
  dead-letter subject for poison messages; gateway publish retries. Global
  per-principal rate limits stay per-gateway approximations (documented)
  until a shared counter is worth its dependency.
- **6.3 Database HA + read scaling.** Postgres via an operator
  (CloudNativePG first: it ships `rw`/`ro` Services, backups, failover)
  with a 3-instance Cluster manifest in `deploy/k8s/scale-pg`; the store
  gains an optional `LOOM_DB_READ` DSN so packs, expand, search, and
  semantic reads go to replicas while ingest stays on the primary
  (replication lag is acceptable for reads: observations are append-only
  and `as_of` already makes staleness explicit).
- **6.4 Worker fleet.** Lease-based job claiming (`claimed_by`,
  `claimed_until`, `FOR UPDATE SKIP LOCKED`) on artifacts and dossier
  candidates so N enrichment replicas share the backlog without double
  work; embedding calls batched per worker.
- **6.5 Tenant sharding.** A `ShardedStore` implementing `GraphStore` that
  routes each namespace to a DSN from `LOOM_SHARDS` (a small JSON map or
  file, hot-reloaded like the keys file); cross-namespace admin ops
  (`iter_*`, `merge_candidates(None)`) fan out. Moving a tenant is
  `lifecycle export` → import on the new shard → flip the map. Heavy
  tenants get their own Postgres cluster; the contract never sees it.
- **6.6 Artifact offload.** Documents above a size threshold stored in
  S3-compatible object storage (MinIO in-cluster or a managed bucket) with
  the artifact row keeping the pointer, so document-heavy tenants don't
  bloat the transactional database; `GET /v1/artifacts/{id}` streams
  through unchanged.
- **6.7 Capacity evidence.** A `loadgen` k8s Job and a published table of
  measured claims/s and p99 ask latency per shape, refreshed per release
  (D-001a's rule: quote measurements, not this entry).

**Non-goals for now:** multi-region active/active, Kafka-class
infrastructure (hard constraint 2 still holds — every stage above is one
more replica of something already shipped, or an operator the platform
team already runs), and Neo4j (unchanged: only if graph-native traversal
demand appears).

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
