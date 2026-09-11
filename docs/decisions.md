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

## D-028 · Engine concurrency: connection pool, read replica, worker processes (2026-09-08, phase 6.1)

The first phase-6 dial (D-027), built and measured. Off by default: the
SQLite shape is untouched (one writer, one process), and a Postgres shape
with no extra configuration behaves as before with a pool of 4.

- `PostgresStore` borrows a connection per transaction from a
  `psycopg_pool` (`LOOM_DB_POOL`, default 4) instead of serializing every
  query through one connection and a process lock. Nested calls share the
  outer transaction; broken connections are discarded by the pool; the
  pool waits up to 90 s for Postgres at startup instead of crash-looping.
- `LOOM_DB_READ` (optional) names a replica DSN. Packs, searches, exports,
  and index lookups borrow from that pool; ingest and the worker's backlog
  queries stay on the primary. Reads may lag by replication delay —
  acceptable because observations are append-only and `as_of` makes
  staleness explicit. `/readyz` pings both.
- `python -m loom.serve` runs uvicorn with `LOOM_WORKERS` processes
  (default 1); the `scale-pg` engine manifest sets 2 workers × 4
  connections. Keep `workers × pool × pods` under Postgres
  `max_connections`.
- `loom.loadgen` gained `--mode ask` and p50/p99 reporting so the read
  path is measured too.

**Measured** (one laptop, compose, pgvector Postgres, load generator on the
same machine — treat as relative):

| Config | Ingest | Ask | Ask p99 |
| --- | --- | --- | --- |
| before: 1 connection, 1 worker | 388/s | 181/s | 178 ms |
| pool 4, 1 worker | 416/s | 251/s | 93 ms |
| pool 4, 2 workers | 515/s | 184/s | 141 ms |
| pool 4, 4 workers | 473/s | 206/s | 284 ms |

The pool alone buys the read path +39 % throughput and halves p99;
workers add a third to ingest but saturate a laptop's cores (the ask
dip at 2–4 workers is contention with the generator and Postgres, not a
regression). On real nodes, start at 2 workers and let the HPA add pods.

## D-029 · Ingestion HA: replicated JetStream, bounded buffer, dead-letter (2026-09-08, phase 6.2)

The queue was one pod with an unreplicated, unbounded stream (D-027 #1).
Now, all opt-in:

- **Stream shape is configuration.** The gateway creates `LOOM_INGEST`
  with `LOOM_STREAM_REPLICAS` (default 1 — a single-node NATS cannot host
  a 3-replica stream), `LOOM_STREAM_MAX_BYTES` (compose default 1 GiB,
  `scale-pg` 4 GiB) and `LOOM_STREAM_DISCARD` (`old`: shed the oldest
  when full; `new`: refuse new publishes so senders back off). Publishes
  retry three times over ~1 s so a leader election never surfaces as a
  502.
- **Redelivery is bounded and poison is parked.** The writer consumer's
  durable has `ack_wait` (30 s) and `max_deliver` (5). A batch the store
  rejects is nak'd for prompt redelivery — event_id dedupe absorbs any
  partial writes (D-022) — and any message on its last allowed delivery
  is published to the `LOOM_DEADLETTER` stream (`loom.deadletter.<kind>`)
  with the sender's principal and the error as headers, then acked. One
  bad envelope can no longer hold the queue hostage, and nothing is
  silently dropped.
- **`scale-pg` runs NATS as a 3-node JetStream cluster** (StatefulSet,
  headless Service, per-node PVC, `replicas: 3` on both streams). Clients
  keep using `nats://nats:4222`; the client library discovers the peers.
  The `scale` overlay and compose stay single-node — a small team's
  ingestion tier is still one small container.

**Validated on the cluster:** with the stream replicated 3/3, a
3000-envelope burst through the gateway Service while the stream leader
pod was deleted mid-burst: 3000/3000 acknowledged (0 errors), leadership
moved to another node, and Postgres held exactly every acknowledged
envelope afterwards — nothing lost, nothing duplicated.

## D-030 · Database HA: CloudNativePG cluster, reads on replicas (2026-09-08, phase 6.3)

`deploy/k8s/scale-pg-ha` layers a CloudNativePG `Cluster` (3 instances,
streaming replication, automatic failover, pgvector via the operator's
images) on `scale-pg`. The engine writes to the operator's `-rw` Service
and reads from `-ro` through `LOOM_DB_READ` (D-028), assembled from the
operator-issued credentials with Kubernetes env expansion — no second
Secret to manage. Writer consumers stay on the primary. The operator is a
one-line cluster install and is the only new dependency; the plain
`scale-pg` overlay still takes any external Postgres, and a small team
never sees any of this.

**Validated on the cluster:** reads confirmed on a replica
(`pg_is_in_recovery() = true` on the read DSN) and writes on the primary;
the primary pod deleted under a probe of synchronous engine writes and
replica reads at ~4 req/s: 319/319 writes and 319/319 reads succeeded,
failover completed to another instance, every write present afterwards.
The pool's connection check and the operator's promotion together kept
the outage below the probe interval. A second run, with gateway ingest
instead of synchronous writes, behaved the same (273/273).

Two small fixes fell out: the seed CLI printed the DSN with the
operator-issued password (now redacted), and the store's startup wait for
Postgres is 180 s to cover an operator bootstrap.

## D-031 · Worker fleet: leased jobs and a sharded backlog (2026-09-08, phase 6.4)

One enrichment process with no coordination meant two workers would mine
the same document twice (D-027 #4). Now N workers share the backlog:

- **Leases for the LLM-priced work.** `pending_artifacts`,
  `artifacts_needing_chunks` and `dossier_candidates` take
  `lease=(worker_id, seconds)` and *claim* what they return — one atomic
  statement (`UPDATE … RETURNING`, `FOR UPDATE SKIP LOCKED` on Postgres,
  inside a `MATERIALIZED` CTE because an inline subquery under `IN` does
  not honour its `LIMIT`) — so no two workers hold the same artifact or
  entity. Completion releases the lease (`set_extraction_status`,
  `put_doc_chunks`, `put_dossier`, `defer_extraction`); a crashed worker's
  lease simply expires (`LOOM_LEASE_SECONDS`, default 600).
- **A hash partition for the cheap, idempotent work.** Embeddings are
  split by the observation id's last hex digit across
  `LOOM_WORKER_SHARD="i/n"` (or the StatefulSet ordinal with
  `LOOM_WORKER_COUNT`); no locks, no double calls, n ≤ 16.
- **Workers have identities** (`LOOM_WORKER_ID`, default hostname) that
  land on the claim for audit. `scale-pg` gains a `loom-enrich`
  StatefulSet (2 replicas); compose and `scale` keep one worker, and a
  lone worker with the defaults behaves exactly as before.

## D-032 · Tenant sharding by namespace (2026-09-08, phase 6.5)

Namespaces isolated data; now they can isolate *capacity*. `LOOM_SHARDS`
(inline JSON or a file: namespace → connection string, SQLite paths and
Postgres DSNs mixable) wraps the engine's store in a `ShardedStore` that
implements the full `GraphStore` contract:

- a `namespace` argument, or an envelope/record carrying one, routes to
  that shard; everything unmapped goes to `LOOM_DB`;
- `namespace=None` admin calls (`iter_*`, merge candidates) fan out and
  concatenate — so `lifecycle export` of everything still works;
- worker backlog calls walk the shards until `limit` is filled, so a
  lease is never taken on a row that isn't returned;
- health and maintenance hit every shard; `/readyz` requires all of them.

The router for every plain `namespace`-first method is generated from the
`GraphStore` signature at import time, so a new store method cannot be
silently mis-routed: it either routes correctly or the import fails. The
contract test suite runs a third lane, two SQLite shards with the suite's
namespaces split across them, so every existing test also proves routing.

Moving a tenant: `lifecycle export --namespace X` from the old shard,
`import` on the new one, flip the map, restart engines/workers (the map is
read at startup; hot reload is deliberately not built until someone needs
it). A heavy tenant gets its own Postgres cluster; the contract never sees
it. A small team never sets `LOOM_SHARDS`.

## D-033 · Artifact offload to blob storage (2026-09-08, phase 6.6)

Document-heavy tenants would otherwise grow the transactional database
with bodies it never queries (D-027 #6). Off by default. With
`LOOM_BLOB_THRESHOLD` (bytes) plus a backend — `LOOM_BLOB_DIR` (a shared
volume) or `LOOM_BLOB_S3_BUCKET` (+ `_ENDPOINT` for MinIO/Ceph/…, extra
`s3`, boto3) — `BlobOffloadStore` wraps the store the factory built:
bodies above the threshold are written to `<namespace>/<uuid>` and the row
keeps an empty body plus a pointer in `attrs["_blob"]`. Every read path
that returns an Artifact reinflates it (API, worker backlogs, exports), a
replay of the same `event_id` never leaves an orphan blob, purge deletes
the blob with the row, and import offloads again. Persistence still lives
behind `GraphStore`; nothing above it knows. `GET /v1/artifacts/{id}`
streams the same bytes as before.

## D-034 · Pipeline integration surface: batch ingest, OpenAPI, Go SDK, Kafka (2026-09-08)

User direction: teams must be able to tie Loom into whatever pipelines they
already run. Pipelines end in log shippers, queues, and scheduled exports —
rarely in custom code — so the investment went into the integration points
those already speak, with generated clients for the languages that remain.

- **`POST /v1/ingest/batch`** on the engine and the Go gateway: a JSON
  array, NDJSON, or a wrapped `items`/`records` object of envelopes, up to
  `LOOM_MAX_BATCH` (1000). Every item passes the same gates as
  `/v1/ingest` and is reported individually (`recorded` / `accepted` /
  `rejected` + detail) — one bad record never blocks the rest. Claims land
  in one transaction per store; the gateway charges a batch of n against
  the principal's rate bucket as n. This is what Fluent Bit's, Vector's,
  Logstash's and the OpenTelemetry Collector's HTTP outputs produce.
  Shipped configs in `deploy/integrations/` (Vector VRL remap, Fluent Bit
  Lua filter) were validated live: records reshaped in the shipper, posted
  as batches, stored once (event_id dedupe absorbed repeated flushes).
- **`contracts/openapi.json`**, generated from the running app and
  drift-checked in CI beside `schemas.json`; CI also proves it generates
  Java and C# clients cleanly with `openapi-generator-cli`. That is the
  answer for every language without a hand-written SDK.
- **Go SDK** (`sdk/go`): zero dependencies at runtime; its envelopes are
  validated in tests against the same schema the gateway enforces, so it
  cannot drift. Live-tested in CI like the TypeScript SDK.
- **`python -m loom.ingest`**: NDJSON files or stdin → batches over HTTP
  (`--url`) or straight into a store (`--db`, the consumer's code path).
  Anything that can write JSON lines is now a pipeline.
- **Kafka / Redpanda consumer** (`python -m loom.kafka_consumer`, extra
  `kafka`, compose profile `kafka` with a Redpanda for trial,
  `deploy/k8s/integrations/kafka-consumer.yaml`): reads envelopes from your
  topics, commits offsets only after the batch is written, retries a
  rejected batch with backoff and dead-letters it to `loom.deadletter`
  with the error after `LOOM_MAX_DELIVER`. Consuming from a team's Kafka
  is not the same as requiring one: nothing in the default shape depends
  on it (hard constraint 2). Validated live: produce, replay, poison.
- **Deliberately not built:** hand-written Rust, Lua, Ruby, Java or C#
  clients. Java/C# come from the generator; Lua's real role is Fluent
  Bit's filter language, covered by the shipped example; Rust waits for a
  shop that asks.

## D-035 · Real data: the vulnerability-intelligence connector (2026-09-08)

Everything before this was validated against a corpus we wrote knowing the
answers (~590 seed claims, 5 documents). The product claim — good, cited,
budgeted packs from messy data — had never met data we did not author. The
first connector fixes that with three public, keyless feeds and one command
(`python -m loom.connectors.vulns load`), and doubles as the demo's second
act: "is web-01 exposed to something actively exploited, and why?"

- **Sources → one namespace.** NVD 2.0 yearly feeds (status, trimmed
  summary, CVSS per *scorer*, CWE, products from vulnerable CPEs), CISA KEV
  (exploited-in-the-wild flag, ransomware use, freehand vendor/product,
  and the advisory text as a *document*), FIRST EPSS (score + percentile,
  only for CVEs already present). Loaded into `netsec` so it joins the seed
  hosts; `--bridge-seed-hosts` adds `runs_software` edges so the demo
  question is a two-hop scope (`expand: [runs_software, affects]`).
- **Conflicts are real, not planted.** NIST and the CNA score the same CVE
  differently often enough that `cvss_score` conflicts surface on their
  own. One score per scorer (newest CVSS version) so a v4.0/v3.1 pair from
  the *same* scorer is not misread as disagreement.
- **Entity resolution is left honest.** KEV's "NGINX Open Source" becomes
  `nginx:nginx_open_source`, the CPE says `nginx:nginx`; the connector does
  not paper over that. It is the resolution worker's job (D-023) and the
  gap is documented in `docs/real-data.md` rather than hidden.
- **History for free.** Every event_id embeds the record's own
  modification stamp: re-runs dedupe, a re-scored NVD record records a new
  observation. A nightly CronJob (`deploy/k8s/jobs/vulns-refresh.yaml`)
  makes `as_of` questions answerable against real revisions.
- **Small-resource posture kept.** The feeds are streamed (`ijson`, extra
  `connectors`), never loaded whole; the cache uses conditional GETs; the
  default is this year's NVD feed only (`--years` widens it). A connector
  is a domain adapter like `loom.seed`, not core: the engine learns
  nothing about CVEs, the namespace's schema registration carries it.
- **Measured, not assumed:** load rate, corpus size and pack quality from
  the first real run are recorded in `docs/real-data.md`, including what
  the run got wrong.

**What the first run changed in core** (each with a regression test):

- `GraphStore.observations_for` was `subject_id = ? OR object_entity_id = ?`;
  SQLite planned it as a scan of the whole namespace (229 ms per call at
  465k rows, so a 1,000-subject scope took 262 s). Both stores now run two
  indexed halves merged with `UNION ALL` (0.1 ms; the scope 0.5 s).
- Conflict detection scanned every observation once per subject
  (quadratic on scopes); grouped once.
- **Contract, additive:** `ContextPack.omitted_handles`. Handles are
  capped at 32 in priority order; a hub produced 8,234.
- Edges pointing *into* a pack subject from outside the pack aggregate into
  one `pointing at` handle on that subject (965 one-observation handles
  before).
- Conflicts still ship first but take at most half the budget
  (`_CONFLICT_BUDGET_SHARE`); the overflow becomes conflict handles (H-C4
  holds). A wide scope had produced 53 conflicts and zero facts.
- A fact about an entity a scope *reached* ships with the edges it was
  reached through, as `relation` items (the contract's until-now-unused
  kind) right before it; if the chain doesn't fit, neither does the fact.
  Without the chain the answering model correctly refused to connect
  "CVE-X exploited" to web-01.

**Left open, on purpose (roadmap phase 8):** `_GATHER_LIMIT` (1,000)
silently truncates hub expansion (the kernel has 2,740 CVEs this year);
KEV's freehand product names match NVD's CPE keys for 91 of 708 products
and one product carries two CPE keys across eras (`nginx:nginx` /
`f5:nginx_open_source`, `haxx:curl` / `curl:curl`) — entity-resolution
work, not connector work; the 1,699 KEV documents were loaded but not yet
embedded in this pass.

## D-036 · Agent end-to-end evaluation, and what it changed in the MCP surface (2026-09-09)

`/v1/answer` tests a model as a *reader* of a pack Loom built; the demo's
promise is an *agent* that finds the data itself. `python -m loom.agent_eval`
runs a real model over the real MCP transport (stdio, the transport
`claude mcp add` uses) against the real corpus with four tasks and no
pre-built scope. Ground truth comes from the store, never a fixture; the
score is: right entities named, none invented, every cited id seen in a
tool result during that run. The harness is provider-agnostic (OpenAI-
compatible tool calling or Anthropic tool use), CI-tested against a
scripted model, and live only on request.

The first live run (deepseek-chat-v3.1, four tasks) passed the lease and
conflict questions with correct, faithful citations and failed the
two-hop exposure question — not on retrieval: after two calls the agent
stopped passing `namespace`, every later query hit the empty `default`
namespace, Loom truthfully returned nothing, and the agent spent twelve
steps and 130k input tokens looking for CVEs that were one argument away.
That is a surface problem, so the surface changed:

- **`list_namespaces` and `describe_namespace` tools** — entity types with
  counts, registered predicates with descriptions and containment flags,
  and a hint for multi-hop `ask_scope`. Needs `GraphStore.namespace_summary()`
  (one GROUP BY; sharded stores merge).
- **An empty namespace is an error, not an empty list**: every read tool
  checks the namespace holds data and names the ones that do.
- **`LOOM_MCP_NAMESPACE`** sets the default namespace for a single-team
  deployment, so the argument becomes optional.
- **Server instructions** tell agents to orient first and to pass the same
  namespace every call; the harness forwards them like a real client does.
- **`expand` explains itself** when handed an observation id instead of a
  handle (the agent tried that once).
- **Handles omit a null `as_of`** — agents carry every handle in context.

The second run passed three of four and produced the next three changes:
the two-hop `ask_scope` result was 69k chars of which 3.7k was fact text
(the 1,077-entity subject list came first and dwarfed everything), and the
pack held no KEV fact because the question named the subject and every
recent fact *about the subject* tied the KEV fact on keyword overlap.

- **Agent view of packs** (`_agent_view` in the MCP server): items first,
  `exclude_none` citations, subjects summarized to 20 plus a total. The
  HTTP contract is unchanged; this is presentation. 69k → 18k chars.
- **Root subjects are the frame, not the topic**: their name tokens are
  removed from the question's relevance tokens (kept only if nothing else
  remains). Applies to single-subject asks too — "what os does web-01
  run?" no longer rewards every fact for mentioning web-01.
- **Compact handles**: short keys, positional subject, no nulls; legacy
  long-form handles still decode. 131 → 83 chars average.

Outcome table (five runs, two models) in `docs/real-data.md`. Claude
Haiku 4.5 passes all four tasks including the two-hop question; the
weaker model still omits `expand_predicates` and wanders. The surface is
now judged adequate: it answers a correctly formed call in one shot.

## D-037 · Model scorecard: which LLMs drive Loom well as agents (2026-09-09)

User question: is it worth a list of models that work well with the
platform, measured with the OpenRouter key? Yes — Loom ships no model,
so "which agent models can actually use these tools" is a question every
adopter has on day one, and the D-036 harness made it cheap to answer.

- `python -m loom.agent_eval --models a,b,c --markdown out.md` runs the
  four-task evaluation per model and asks OpenRouter to report billed
  cost per call (`usage: {include: true}`), so each row carries real
  dollars. `scorecard()` ranks by passes then cost: the cheapest model
  that gets it right wins. `LOOM_AGENT_MAX_STEPS` overrides the step cap.
- Twenty models across price tiers, one run each, then an eight-model
  retest of the two-hop task at 30 steps. Results and recommendations in
  `docs/models.md`; the transcripts stayed in the data volume.
- What the numbers say about Loom rather than about models: faithfulness
  was 20/20 (no invented entities, no unseen citations) because the pack
  hands every item an id; the two-hop task is the only discriminator and
  eleven models pass it cold; input tokens dominate cost, which is why the
  agent view of packs (D-036) was worth more than prompt tuning; and the
  one failure mode citations cannot catch is a confident negative
  ("no KEV data exists") — a claim of absence cites nothing.
- Harness default step cap raised from 14 to 20: four capable models
  passed at 13–17 steps once allowed to finish verifying.
- **Repeats, because one run is not a statistic** (`--repeat N`, pass
  rates per task, per-run averages, sorted by pass rate then cost). The
  fourteen two-hop-capable models ran three more times each: seven are
  12/12 (`gpt-5.4-nano` at one cent per run is the default
  recommendation; `claude-sonnet-5` the flagship pick), faithfulness was
  168/168, and every two-hop miss was a confident wrong answer rather
  than a step-out — including `mistral-small-2603`, screening's cheapest
  4/4, at 1/3. The decision table in `docs/models.md` is the repeated
  one; the single-run screening numbers live in this log and in git
  history (D-041 removed them from the page).
- Spend for the whole exercise was on the order of twelve dollars, most of
  it the two Opus 5 runs.

## D-038 · Partial coverage is reported, never silent (2026-09-09)

Two findings pointed at one gap. The kernel has 2,740 CVEs this year and
scope expansion gathers a node's newest 1,000, so 1,740 were never
reached and nothing said so (open since D-035). And the only agent
failure the scorecard's citation check could not catch was the confident
negative: "no, web-01 is not exposed" (D-037) — a claim of absence cites
nothing. Both are the same fact left unstated: *the reader did not see
everything*.

- **Contract, additive:** `ContextPack.truncated: list[ScopeTruncation]`
  (`entity`, `gathered`, `total`). Recorded wherever the gather limit
  applies — a pack's own subjects, each hop of a scope, an expanded handle.
  The count is taken only when the limit was actually hit, so ordinary
  entities pay nothing; a hub costs one indexed COUNT (~1 ms).
- **Both readers see it.** The MCP agent view adds a `coverage_warning`
  sentence per pack; `render_user_prompt` adds a `coverage:` line, so the
  server-side answering model is told too.
- **`count_observations` had the D-035 bug**: `subject_id = ? OR
  object_entity_id = ?`, planned as a namespace scan. Rewritten as two
  indexed COUNTs in both stores; a self-edge counts once.
- What it does not do: raise the limit. Gathering 2,740 observations for
  one hop is the wrong answer to "the hub is big"; saying so and offering
  `valid_at`, a direct ask, or a handle is the right one.

## D-039 · Documents in the loop: claims cite by event id; embeddings measured on real data (2026-09-09)

The last Loom feature never exercised on real data was documents: the
1,699 CISA KEV advisories were loaded but never embedded, and every agent
run hit "no embedder configured". Embedding them exposed a gap first.

- **A structured claim can cite the document it came with.**
  `Provenance.artifact_id` became optional and `artifact_event_id` was
  added (one of the two is required). The store resolves the event id to
  the artifact id at write time; the HTTP batch gate, the single route and
  the queue consumer resolve or reject/skip per item with the same
  message. Same-batch works because documents are stored before a batch's
  claims. Without this the KEV connector's flags and the advisory text
  were unrelated rows: the pack builder only considers passages from
  documents its observations cite, so the advisories could never surface
  as excerpts for their CVE. The connector now emits the document first
  and every KEV claim cites it. The vendor edge (`made_by`) does not — it
  is derived, not stated in the text.
- **The enrichment worker got two dials.** `LOOM_EMBED_BATCH` (default
  128; hosted embedders take 512–2048) and `LOOM_CHUNK_LIMIT` (default 4).
  At 128 per ~4 s tick the 465k-observation backlog was a four-hour job;
  four sharded workers at 512 did it in about an hour for ~$0.40.
- **OpenRouter serves embeddings** (`openai/text-embedding-3-small`,
  `qwen/qwen3-embedding-8b`), so one key covers the answering LLM, the
  agent scorecard, and embeddings; `.env.example` says so.
- **The existing dev corpus was wiped and reloaded** to carry provenance:
  observations are append-only and deduped by event id, so re-running a
  connector cannot retrofit a citation onto a row that already exists.
  That is the right property for production and a known cost for
  connector upgrades; the CronJob's history stays intact because new
  revisions get new event ids anyway.
- **Vectors were stored as JSON text.** 228k 1,536-dim embeddings as
  `json.dumps(vec)` were ~30 KB each; the SQLite store grew to 10.7 GB
  with a 10 GB write-ahead log, and wiping it ran for ten minutes before
  I killed it. Schema v3 stores vectors packed (`\x00f32` + float32
  little-endian, ~6 KB per row) in both stores; reads accept the packed
  form, legacy JSON text, and legacy JSON carried through the Postgres
  TEXT → BYTEA migration (verified on a hand-built v2 database). The
  sqlite-vec index now receives the float32 buffer directly instead of
  JSON it had to parse. `LOOM_EMBED_DIM` asks a Matryoshka model for a
  smaller output (512 for this corpus: a third of the storage at most of
  the quality).
- **A stalled embedder must not stall an ask.** Query embeddings are
  single-attempt with a 10 s timeout (`LOOM_EMBED_QUERY_TIMEOUT`) and any
  failure degrades that ask to keyword ranking with a warning; the batch
  path keeps its 120 s × 3. One ask had waited 30 s.
- **Excerpts name who they are about.** `[about cve:X] "..."` — the
  entities whose observations cite the document. Without it a small model
  attributed one CVE's advisory to its neighbours and went from 3/3 to
  0/2 on the two-hop task; with it, 12/12.
- **Worker robustness under several writers:** a failed job is `FAILED`,
  not zero work, so `--once` no longer exits on a failed first tick
  (bounded retries, non-zero exit after 20); store opens retry on lock; an
  up-to-date SQLite open takes no write lock; busy timeout 15 s.
- `/v1/entities/search` and `/v1/entities/semantic` accept `namespace`
  as a query parameter as well as the header — the docs implied the
  parameter and it silently answered for `default`.
- Measurements with embeddings live — excerpt retrieval, `find_related`,
  semantic ranking versus the keyword-only scorecard — are in
  `docs/real-data.md` under "Documents".

## D-040 · Meaning-based search reads documents, not just facts (2026-09-09)

`find_related` / `GET /v1/entities/semantic` searched vectors of rendered
facts only. On the real corpus "ransomware campaigns against web servers"
returned CVEs whose best fact was `ransomware_campaign_use Unknown`: a
rendered fact carries its predicate's *name*, and that is what the vector
matched. The advisories that actually name campaigns were embedded (D-039)
but never consulted.

- The search now runs two nearest-neighbour queries in the same embedding
  space — facts and document passages — and maps a passage to the
  entities whose claims cite its document (`GraphStore.subjects_citing`,
  backed by an expression index on the provenance artifact id in both
  stores). Best score per entity wins; the evidence is the fact or the
  passage, cited, and a passage opens with `[about …]` (D-039 rule).
- A document nobody cites maps to nothing and is skipped: an agent can
  only ask about entities, so a passage with no citing claim has no
  handle to offer.
- Scoping holds: a scoped key sees only citing subjects (and objects)
  inside its entity types — the same rule as `artifact_cited_within`.
- Real corpus, after: the ransomware question returns advisories about
  webshell uploads and coerced connections for the CVEs they describe;
  "remote code execution in VPN appliances used for initial access"
  returns BeyondTrust and TP-Link summaries; "which hosts talk to the
  database" returns db-01's port fact and the netflow edges. 0.8–1.5 s per
  search over 465k fact vectors and 3.6k passage vectors.

## D-041 · Scorecard on the current build; short cite tokens (2026-09-09)

The surface changed four times after the D-037 scorecard (coverage
warnings, attributed excerpts, passage search, semantic ranking on when
embeddings exist), so the numbers on `docs/models.md` no longer described
this build. Eighteen models, three runs each (~$12, two hours): nine
models at 12/12 (was seven), two hand-copied 32-hex ids mangled by one
character (`claude-sonnet-5`, `deepseek-v4-flash`), and the first
invented entities in some 400 task-runs — `glm-5.3-flash` named two
real-world OpenSSH CVEs absent from the store, from memory. The
faithfulness check caught all three, which is its job.

- MCP pack citations now carry a 12-hex `cite` token (the prefix the
  answer route already uses) and the server instructions say to cite by
  it, so agents copy less. Full ids stay for auditing.
- `docs/models.md` now carries only the current build: a TL;DR, the
  short-answer table, the method, the decision table, and the re-run
  command. The earlier screening and previous-build tables were internal
  iterations and live in this log and in git history. The recommendation
  moved from `gpt-5.4-nano` (11/12 here) to `gemini-3.5-flash-lite`
  (12/12) as the default, with `qwen3.7-flash` as the cheapest open-weight
  clean pass.

## D-042 · Entity resolution tier 3: structural aliases, adjudicated (2026-09-10)

The rehearsal (D-041) had the agent discover the seam itself: the KEV
connector keys the kernel as `linux:kernel`, NVD as `linux:linux_kernel`,
so 25-odd kernel KEV entries never reached a host through the graph.
Tiers 1 and 2 (D-019, D-024) only merge keys that collide exactly once
normalized; these do not.

- **Candidates are structural, decisions are the LLM's.** For entity
  types named in `LOOM_ALIAS_TYPES` (off by default — each candidate is a
  model call), keys of the form `vendor:product` are compared by shape:
  the vendor name repeated inside the product (`linux:kernel` ~
  `linux:linux_kernel`), the same product token under exactly one other
  vendor when the token is specific or one vendor *is* the product
  (`haxx:curl` ~ `curl:curl`), or a bare family name with exactly one
  longer key of its vendor whose remainder is not a version marker. Any
  ambiguity — two longer keys, a versioned suffix — yields no candidate.
  The existing adjudicator then sees both records' facts and a stricter
  system prompt (same product line: yes; edition, version line or
  sibling: no); the less-connected key merges into the more-connected one
  on a confident yes, which is how a freehand KEV key becomes an alias of
  the CPE product and its `affects` edges repoint.
- `python -m loom.enrich resolve [--dry-run]` runs the spelling tiers and
  this one once, outside the worker loop; the worker runs it each tick
  when `LOOM_ALIAS_TYPES` is set. Declines are remembered per process (as
  in D-023); persisting them is a known gap.
- **Measured on the corpus** with `google/gemini-3.5-flash-lite` as judge:
  283 candidates, 58 merged, 223 declined, 2 deferred, about three cents.
  Every merge reviewed by hand reads as correct (curl, php, sudo,
  grafana, Pulse Secure → Ivanti, Docker Desktop, the kernel); the
  declines include the ones that had to be declined (Android kernel,
  DirectX vs its graphics kernel, the Cisco and Confluence groupings).
  KEV product keys matching an NVD key: 105 → 128 of 689. KEV CVEs
  reachable from a seed host: web-01 3 → 29, db-01 3 → 29, laptop-17
  14 → 40. The rest of the unmatched keys have no counterpart in a
  one-year NVD feed at all; loading more years is the lever there, not
  matching.
- What it does not do: guess. `microsoft:windows` stays unmerged next to
  ten Windows keys, and a sibling like `cisco:ios` ~ `cisco:ios_xe` is
  offered and declined, not assumed.

## D-043 · Validated on GKE: what a real cloud found that k3s could not (2026-09-10)

Project `loom1-508221`, one zonal GKE Standard cluster (3 × e2-standard-4,
us-central1-a), the `scale-pg-ha` overlay with CloudNativePG 1.26 on
`standard-rwo` disks, images pushed from the local build to Artifact
Registry, the seed plus the full vulnerability corpus loaded, the
enrichment workers embedding with the OpenRouter key from a Secret. About
four hours and under five dollars for the session. Every item below is a
difference between a laptop cluster and a real one; each is fixed in the
repo or written into the deploy guide.

- **Nodes could not pull.** A new project's default compute service
  account has no roles; the nodes need `roles/artifactregistry.reader`
  (or GHCR). Deploy guide.
- **JetStream refused the stream.** The gateway asks for a 4 GiB stream ×
  3 replicas; the NATS PVC was 1 Gi, which local-path never enforced and
  GKE did (`insufficient storage resources`). NATS PVC is now 8 Gi.
- **Open-time DDL deadlocked the loader.** The Postgres store ran its
  idempotent `ALTER TABLE … IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`
  on every open; those take AccessExclusive locks even as no-ops, and a
  pod opening the store while a bulk loader was mid-batch produced
  `deadlock detected` on `observations`. An up-to-date database now gets
  no DDL on open (one SELECT of `schema_version`), and `record_claims` /
  `store_artifact` retry a transaction that loses a deadlock or a
  serialization race — validated in the field: two writer consumers
  deadlocked each other on entity upserts, retried once, and every row
  landed.
- **Postgres ran out of disk.** The HA manifest gave each instance 2 Gi;
  the corpus with vectors needs more, and GKE enforced it: two instances
  crash-looped with `Not enough disk space`. Now 20 Gi. The recovery is in
  the deploy guide because the operator will not expand a volume for a
  cluster that is down: patch the PVCs, mount each from a throwaway pod so
  the filesystem grows, and the operator restarts the instances.
- **The N+1 that a laptop hides.** The pack builder fetched each reached
  entity's observations with its own query — 1,077 round trips for the
  two-hop scope, 0.1 ms each in-process and 5 ms each across a network:
  5–6 s on GKE. `GraphStore.observations_for_many` does one round trip per
  400 entities (a window function gives the per-entity limit, aliases are
  followed, a ref that resolves to nothing is absent); scope frontiers and
  subject lists use it. Two-hop on GKE: 5.3–6.2 s → 1.4–2.4 s; on the
  laptop it also got faster.

**The overnight soak** (18 h with the enrichment workers running the
full pipeline — extraction, resolution, alias adjudication, embedding,
dossiers — on the real corpus, the first time all of it ran unattended):

- **The vector-index backfill OOM-killed the worker every ~6 minutes**,
  117 and 111 restarts. `ensure_vector_index` ran every tick and, to find
  rows missing from the ANN index, loaded every indexed id into a Python
  set and then every vector row in the table into memory: a transient
  400 MB at 200k vectors against a 512 MiB limit, and minutes of wasted
  work per tick even when nothing was missing. It is now an SQL anti-join
  streamed in 1,000-row chunks, skipped outright when the counts already
  match, in both stores. The worker kept making progress between kills
  (913 documents extracted, 196k vectors), which is why nothing else
  noticed.
- **Extraction's loose entity types hijacked a structured key.** The
  extractor named `ip_address:10.0.4.7`; tier-1 resolution merges same
  key across types into the most-connected side, the extracted side had
  as many facts as the DHCP log, and the tie-break made `ip:10.0.4.7` the
  alias. Ranking now puts a structured-backed entity first, then count,
  then age: a sender's key absorbs an extracted one, never the reverse.
  The 1,506 `ip_address`, 624 `vulnerability`, 107 `url` entities the
  extractor created are the case for `strict` registries on namespaces
  fed by extraction (D-024), left as an operator choice.
- **Dossiers ran for the first time on real data** — 23 briefs — and
  spent them on the synthetic loadtest hosts, which had the most new
  facts. Correct by the rule, useless in practice; candidate selection
  should weigh structured activity, not volume. Roadmap.
- Nothing else restarted in 18 hours: engine, consumers, gateways, NATS
  and Postgres all at zero restarts; the database grew to 2.1 GB on
  20 GiB volumes; asks against the busy primary stayed under a second
  for single entities and under 4 s for the two-hop scope.

**The failover number was wrong, and the correction is a fix.** The
190 s "write outage" (and a 137 s repeat on a clean cluster) came from a
probe whose `psql` hung in a TCP connect to the deleted primary's address
until the kernel gave up; CloudNativePG's `smartShutdownTimeout` was my
hypothesis and changing it changed nothing. With `connect_timeout=2` on
the probe the operator promotes a replica in **11 s** with its defaults —
and through a real engine, `POST /v1/ingest` every 0.5 s across the
deletion failed 3 requests of 617, an 11 s window. Loom's own pool had the
same gap as the probe, so it now sets `connect_timeout=5` and TCP
keepalives (`keepalives_idle=15`, `interval=5`, `count=3`): a connection
to a vanished primary fails in seconds and a held one is detected within
half a minute, instead of hanging for two minutes.

**Measured** (details and the reproduction in `deploy/README.md`):
direct load 715 envelopes/s into the HA primary from one loader; gateway
single-envelope ingest 175–189/s with every pod's CPU idle — the
three-replica JetStream acknowledgement over persistent disks is the
bound, concurrency 128 only raised latency (p50 126 → 596 ms); the batch
endpoint through the same gateway 660/s; asks 287/s at p99 86 ms on 482k
observations with two engine replicas; primary pod deleted under 20,000
in-flight ingests: 0 client errors, 55,000 of 55,000 rows present, the
queue absorbed the outage with no redeliveries lost and nothing
dead-lettered. Write availability during a primary loss: 11 s (see the
correction above).

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
