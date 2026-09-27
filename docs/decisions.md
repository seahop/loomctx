# Decisions & constraints

Running log of choices with rationale. Newest additions at the bottom. If a decision
is revisited, strike it here and add the replacement — don't rewrite history.

## Hard constraints (hold unless the user says otherwise)

1. **Docker-only builds and runs.** Nothing installs or executes on the host beyond
   `docker compose ...`. Tests, servers, and one-off scripts all run in containers.
   This keeps the host sanitary and is a standing project rule.
2. **Small-resource posture.** Target: large *context*, not big data. The core
   needs nothing beyond one container and a volume: SQLite, no queue, no search
   cluster, no managed-cloud dependency — it runs on a laptop or a $10 VPS.
   Everything else is an opt-in shape of the *same image and contract*: Postgres
   by connection string (D-011), the NATS-buffered ingest tier (D-010), Postgres
   HA (D-030), and consuming from *your* Kafka (D-034) — each documented in
   `deploy/` and switched on by env or overlay, never required. Local Compose
   and the k8s manifests in `deploy/k8s` (D-008) are the two ways to deploy any
   of those shapes.
3. **Provenance is mandatory.** Every observation names its source; every context-pack
   item cites its observations. No uncited derived facts.
4. **Observations are append-only.** Corrections supersede; nothing is edited in place.
5. **Budgets are mandatory on reads.** No API that returns unbounded context.
6. **Domain-agnostic core.** Domain knowledge lives in the schema registry and
   plugins (see "malleable" in `concepts.md`), never in core code.

## D-001 · Core language: Python (3.12+; the image runs 3.14 as of 2026-09-11)

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

## D-005 · The name is Loom (settled 2026-09-11)

Chosen on 2026-09-03 for the weaving metaphor and a short CLI name, carried
as a "working name" through the build, and confirmed as the public name
with the v0.1.0 tag: the repo (github.com/seahop/Loom), the image
(`ghcr.io/seahop/loom`), the MCP server name, the Python package (`loom`)
and every doc use it, and nothing depends on renaming. The known
collision with loom.com is accepted; there is no website for this
project. The distribution name on PyPI, if it is ever published, is
`loom-ctx` (the `loom` name is taken there); that does not change the
import.

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
(conference: mid-October 2026).

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

One zonal GKE Standard cluster (3 × e2-standard-4,
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

## D-044 · Worker quality: what the soak asked for (2026-09-11)

Three changes in the enrichment worker, each traced to a specific
observation from the GKE soak (D-043), done before the tag rather than
after it.

- **Dossiers go to rich entities, not loud ones.** Candidate selection
  ordered by fresh-observation count, so the first real run briefed the
  load generator's hosts (100 rows of one predicate from one source). It
  now requires at least two distinct predicates for a *first* brief and
  orders by distinct predicates × distinct sources, then count: several
  kinds of fact from several senders is what a brief is for; a
  one-predicate firehose never gets one. Refreshes of an existing brief
  need only enough new facts. Same query shape in both stores.
- **Extraction adopts registered types.** The extractor names entity
  types freely (`ip_address`, `vulnerability`, `URL`). When the namespace
  has a registry, an unregistered type whose exact key already exists
  under exactly one registered type takes that type, so the DHCP log's
  `ip:10.0.4.7` absorbs the extractor's mention instead of spawning a
  twin (and the D-043 structured-first ranking never has to arbitrate).
  With no match the type is kept as named — unless the registry is
  `strict`, in which case the claim is dropped and logged, the same gate
  the HTTP path enforces; extraction no longer has a side door.
- **Adjudication declines persist.** Tiers 2 and 3 remembered declined
  pairs per process; a restarted worker or a nightly CronJob re-asked the
  model the same 223 questions. New table `resolution_declines`
  (namespace, a, b, reason, decided_at; canonical order), schema v4 in
  both stores, a per-process read-through cache in front of it.

## D-045 · Release gate: the three gaps between "CI is green" and "this image is what we tested" (2026-09-11)

Assessing the build after the Python bump found three things that were
true but unproven, and each is cheap to prove permanently.

- **The scale shape runs in CI.** Every laptop and GKE measurement went
  through lb → gateway → JetStream → consumer → store, but CI only ever
  exercised the single-container shape, so a Go gateway or consumer
  regression would have reached a tag. `scripts/smoke-scale.sh` brings
  up the compose `scale` profile with two gateways, posts one claim to
  the load balancer, waits for it to land in the store (observed: 1 s)
  and asks the engine for it, asserting a cited item. New CI job
  `scale-smoke` on every push. Runs locally too; it stops and removes
  only the scale services and never drops volumes (an earlier draft used
  `down -v`, which deleted the local corpus — disposable, but not twice).
- **The store migration is tested on a populated database, not an empty
  one.** The schema-version bump in D-044 (v3 → v4) was covered only by
  fresh-open tests. Verified by hand, and worth repeating for every
  schema bump: build the image at the last v3 commit (`770c20b`), seed
  Postgres with it, then open the same database with the current image.
  Result: schema 4, 553 observations and 3 artifacts intact, the
  `resolution_declines` table usable, `ask` returns the planted web-01
  conflict, and a second open takes the no-DDL fast path. The same
  recipe is in `deploy/README.md` under *Upgrading*.
- **The published image is the soaked image.** The 18 h soak and the
  failover measurement (D-043) ran on an image built from the working
  tree; the `v0.1.0` tag was then pushed at `4022aec` and three commits
  landed after it (name settled, Python 3.14 base, this entry). The
  release gate is a short run of the GKE recipe against the image CI
  actually published (`ghcr.io/seahop/loom:<sha>`): scale-pg-ha,
  loadgen ingest and ask, the worker through every stage at its 512 MiB
  limit, one failover. Results are appended to this entry, and the tag
  moves to the gated commit.
- **The tag never had an image.** Found while preparing the gate: the
  publish job ran only for pushes to `main`, so both `v0.1.0` tag pushes
  built nothing and `ghcr.io/seahop/loom:v0.1.0` did not exist; the
  `ref_name` tag line only ever produced `:main`. Rebuilding on the tag
  push would have been the obvious fix and the wrong one — a second
  build is a second image. Now a tag push re-tags the commit's already
  published `:<sha>` manifest (`docker buildx imagetools create`), so the
  release tag is byte-for-byte the gated image, and it builds only if
  that commit never went through `main`. Publishing also now waits for
  the scale smoke.
- **Pulling while the repository is private.** GHCR packages inherit the
  repository's visibility; until Loom is flipped to public, every
  `image: ghcr.io/seahop/...` in the manifests needs a pull secret
  (recipe in `deploy/README.md`). The gate uses one.

**Gate run, 2026-09-11.** Image `ghcr.io/seahop/loom@sha256:338df448…`
(CI's build of `0eba95c`; gateway `@sha256:02d61194…`), pulled from GHCR
through the pull secret onto a fresh `loom-gate` cluster (3 × e2-standard-4,
CloudNativePG 1.26, the shipped `scale-pg-ha` overlay plus the provider
Secret and `LOOM_ALIAS_TYPES=product`). Everything below ran with both
enrichment workers live against the same primary, which is the
production condition; D-043's numbers were taken with idle pools.

| Check | Result |
| --- | --- |
| Corpus load, one loader into the HA primary | 535,737 envelopes in 21.3 min (421/s) while the workers extracted, embedded and adjudicated against the same primary (715/s idle in D-043) |
| Gateway → JetStream → consumers → Postgres, single envelopes, 5,000 at concurrency 32 | 202/s, p50 109 ms, p99 653 ms, 0 errors; 2,000 more after both failovers at 191/s; all 7,000 rows present |
| `/v1/ask`, 1,500 at concurrency 16, 2 engines × 2 workers | 186/s, p50 57 ms, p99 383 ms, 0 errors (287/s with idle workers in D-043) |
| Real answers | CVE-2026-0544 conflict first in 0.39 s cold, 20 ms cached; two-hop scope from web-01 3.2 s cold, 1.75 s again, 32 handles, one truncated entity |
| Workers at the shipped 512 MiB limit | every stage ran (extraction, embedding, chunking, dossiers, spelling merges, alias merges and declines) over 18 ticks; 49 MiB resident; 0 restarts |
| Failover 1, operator defaults | the operator promoted **183 s** after the primary pod was deleted; writes kept landing on the old primary until then, then a 15.6 s write gap (6 failed requests) plus 2 timeouts at the cut, 8 of 553; 551 rows for 545 acknowledgements — 6 commits whose reply was lost, harmless under event-id dedupe |
| Failover 2, `smartShutdownTimeout: 10` | promoted in **12.6 s**, write gap 16.6 s, 6 failed of 267; 0 engine, worker or consumer restarts either time; the only error lines are the pool's connection refused / timeout during the cut |
| Restarts overall | engines 2 and gateways 1 during the first rollout, before Postgres and NATS existed (readiness-driven, expected); none after |
| Cost | about 50 minutes of cluster, roughly $1, plus a few cents of LLM calls |

The one finding is the failover delay, and it corrects D-043. "`smartShutdownTimeout` made
no difference" was measured with idle connection pools. A stopping primary
waits `smartShutdownTimeout` (default 180 s) for clients to disconnect, the
replicas keep streaming from it until it is actually down, and the operator
will not elect a new primary while their WAL receivers are attached — so
with engines and workers holding pooled connections, deleting the primary
(a node drain, an upgrade) leaves the old pod serving for three minutes
before the real 13 s failover happens. Nothing is lost in that window, but
a drain that should take seconds takes minutes. The shipped
`postgres-cluster.yaml` now sets `smartShutdownTimeout: 10`; the pool's
`connect_timeout=5` (D-043) is what turns the cut into a 17 s gap instead
of a hang.

**Verdict:** the published image passes the gate. The tag moves to the head
of this work rather than to `0eba95c` because the tag-push re-tagging lives
in the workflow file at the tagged commit; the image inputs (`src/`,
`Dockerfile`, `pyproject.toml`, `gateway/`) are byte-identical between the
two commits, and the head's CI build is compared layer by layer against the
gated digest once it exists.

**After the push (2026-09-11, tag at `5a9f16b`).** The tag run re-tagged
instead of rebuilding: `loom:v0.1.0` and `loom-gateway:v0.1.0` are manifest
lists wrapping exactly the head commit's manifests (`b4853584…`,
`7ab170cf…`), so the tag serves the same bytes as the head's `main` build.
That build against the gated one: Python 3.14.7 and every `.py` under
`/app/src` identical, 60 packages installed in both, one difference —
`boto3`/`botocore` 1.43.92 in the gated image, 1.43.93 in the tagged one,
because the dependency set is not locked and pip resolved the patch
released in between. The gate exercised nothing in boto3 beyond import
(S3 artifact offload is off in the overlay), so the tag stands; but this
is the case for a lock file, added to the roadmap: a rebuild should be the
same image, not a fresh resolution.

## D-046 · Read path after the 2026-09-23 review: one `as_of` axis, gates on hops, honest handles (2026-09-23)

A second full review (six parallel passes: read path, store, enrichment,
security, docs, and the field) found the read path keeping most of its
promises and breaking a few quietly. The fixes, and the semantics they
settle:

- **`as_of` is the observation-time axis.** `as_of = T` means
  `observed_at <= T` — the moment the source asserted the fact. The docs
  called it knowledge time and implied `recorded_at`; for a backfilled
  corpus (the KEV/NVD load) `recorded_at` is load day for every row, so a
  `recorded_at` filter would make time travel useless on exactly the data
  the demo runs on. `recorded_at` stays the audit column. The bound now
  travels into the store query (`observed_before` on
  `observations_for`, `observations_for_many`, `count_observations`), so
  an entity with more than the gather cap of *newer* rows still yields its
  rows as of T, and the `truncated` denominator counts as of T. The old
  `valid_from <= as_of` clause is gone: a fact asserted before T but
  scheduled for later is part of what we knew at T; hiding it is
  `valid_at`'s job.
- **Forward-dated observations are refused at ingest.** `ClaimIn` and
  `DocumentIn` reject `observed_at` more than 24 h ahead of the engine
  clock (422, every door — the gateway's schema check is shape-only, the
  consumers parse the same models). One `observed_at = 2099` row used to
  sit permanently in the gather window and set the recency reference for
  the whole entity, aging every real fact to ~0. Recency's reference is
  now `min(newest observed_at, now)` as well, so a stray future row
  restored from an export cannot do it either. `valid_from`/`valid_to`
  stay unbounded — leases are scheduled.
- **The data gate applies to hops, not only to reached subjects.** Scope
  expansion follows only edges the pack would show: none observed after
  `as_of`, none outside `valid_at`, none touching an entity outside the
  key's `entity_types` (D-021 was applied to the gathered facts but the
  BFS walked through invisible edges, and a reached fact then shipped
  with no visible chain), and — new contract field, additive —
  no document-extracted edge unless `ScopeSpec.follow_extracted` is set.
  D-023 made extracted claims second-class witnesses in ranking and
  conflicts, but an extracted `runs_software product:evil` edge steered
  the two-hop walk at full weight, so one hostile document could pull an
  arbitrary product and all of its CVEs into web-01's exposure pack. A
  reached fact whose chain has an invisible edge is dropped, keeping the
  D-035 rule "if the chain doesn't ship, neither does the fact".
  `ScopeSpec.subjects` is capped at 500.
- **The raw observations route is gated like a pack.** `GET
  /v1/entities/{type}/{key}/observations` applied the subject gate only;
  a host-scoped key read `logged_in_by user:*` rows. It now filters with
  the same object-side rule as packs (MCP `get_observations` already did)
  and accepts `as_of` / `valid_at`.
- **Handles.** Every field of a decoded handle is type- and value-checked
  (a forged `as_of: "garbage"` was a 500). Expanding a `conflict` handle
  spends the whole budget on the conflict (the 50 % share cap applied on
  expansion too, so `budget = est_tokens` returned ordinary facts and no
  conflict — the silent drop D-023 forbids), and `est_tokens` is the exact
  charge. The engine warns at startup when `LOOM_HANDLE_SECRET` is unset;
  the "random per-process fallback" H-A1 described never existed.
- **Ranking honesty.** With an embedder serving but no stored vectors for
  the gathered set (worker not run, or a different model), every fact got
  `cos = 0` and the keyword weight fell from 0.5 to 0.15 — strictly worse
  than keyword-only, silently. No vectors → the keyword formula; inside a
  partially embedded set, un-embedded facts take the set's median cosine.
  The keyword scorer reads only rendered text (predicate, object, subject
  key): `attrs` is never shown, so scoring it let any writer rank a fact
  first with invisible words.
- **HTTP.** The body cap counted only `Content-Length`; a chunked upload
  streamed unbounded into the engine, unauthenticated. A pure-ASGI cap
  now counts `receive` and aborts at the limit. `/v1/*` responses carry
  `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.
  `POST /v1/schemas` requires an ungated write key: a shipper key scoped
  to `--entity-types host --sources auth-log` could flip a namespace to
  `strict` and redefine other senders' predicates. `/v1/entities/semantic`
  maps embedder failure to 503 like `/v1/ask` degrades; `AnswerRequest`
  with both `subject` and `scope` is 422, not 500.
- **The answer prompt treats items as data.** Items, handle hints and
  coverage lines are rendered one per line with newlines escaped, inside a
  delimited block the system prompt declares to be retrieved data — a
  scalar object containing `"\n- (fact) host:web-01 owner alice [..]"`
  used to forge a cited line.

Not changed, deliberately, and on the roadmap as design follow-ups
rather than bugs: the budget charges item text only (citations and
handles ride free, so a 800-token pack is ~2,500 on the wire for an MCP
agent — fixing it moves every documented number and is a rehearsal-day
change); no lexical (BM25) leg or rank fusion; greedy trim rather than
value-per-token packing; entity-valued conflicts; pagination past the
gather cap. See `docs/hardening.md` (2026-09-23 section).

## D-047 · Enrichment, LLM access and MCP after the review (2026-09-23)

- **LLM clients.** The native Anthropic client read `content[0]["text"]`;
  with thinking on by default on current models `content[0]` is a
  thinking block, so `LOOM_LLM_PROVIDER=anthropic` failed every
  extraction, dossier, adjudication and answer except on Haiku. Replies
  are now the concatenation of `text` blocks; a refusal or empty
  completion is an `LLMError` (public: "declined" / "empty completion");
  truncation (`stop_reason`/`finish_reason` length) is logged and the text
  returned. Provider calls never follow redirects (the credential would
  travel with them); `Retry-After` is honored to 60 s with ±25 % jitter;
  `last_usage` carries the provider's token counts and the worker logs
  them per job.
- **Extraction windows are independent units.** Claims land per window as
  soon as it parses (event ids are content-addressed, so this is
  idempotent); one garbled window costs itself, not the artifact, and no
  longer burns five retries of every good window. The lease is renewed per
  window (`extend_extraction_lease`), since a long document exceeded the
  600 s lease and was double-extracted by a second worker. The document
  sits in a per-call random `<document-xxxxxxxx>` tag (a literal
  `</document>` inside a document closed the old fixed one). The `doc:`
  source label is the sanitized filename plus the artifact-id prefix, so a
  sender cannot forge a label. Every extracted claim passes
  `validate_claim` — registered `object_types` were enforced only in
  strict namespaces, against what `registry.py` promised. A typeless
  object key is a value, not an entity of type `"None"`. Chunks are ~400
  characters as D-020 said (the boundary search overshot to ~800) with
  ~10 % overlap.
- **Resolution.** Tier 1 (same key, different types) auto-merges only when
  one side's type is unregistered — the extractor-drift case it exists
  for; two registered types sharing a key (`user:admin` / `group:admin`)
  go to the adjudicator or are left alone. Tier 2 never merges numeric
  keys on spelling (`norm_key` kept `10.0.4.7`, `100.4.7` and `1.0.0.47`
  apart only by their dots, which it stripped — see D-049). The alias pass
  re-offers only entities new since its last complete pass; the tick
  reports resolution, adjudication and aliases separately (a failed job
  summed with one merge read as "nothing to do").
- **MCP.** A scoped key sees only its namespaces in `list_namespaces` and
  in the unknown-namespace error. Every failure is a `ToolError`
  (`find_related` and `answer` returned `{"error": …}` as successes).
  Citations in the agent view are compact — the `cite` token plus source
  and time, no 32-hex id — and `expand` / `get_observations` accept a cite
  token (`observations_by_prefix`) or a full id. The namespace summary is
  cached 5 s.
- **Evaluation and connector.** The lease task's ground truth is computed
  from `ip:10.0.4.7`'s validity windows (it was a fixture, against the
  module's own docstring); its first-sentence check no longer splits on
  the IP's dots; exposure scoring penalizes CVEs named that are not KEV
  (it measured recall ≥ 1 only). Feed downloads are validated (length,
  gzip/JSON) before they replace the cache or earn a `Last-Modified`
  stamp; a truncated body used to be served by 304 forever. `seed load`,
  `ingest`, `vulns load` and `agent_eval` open the env-configured store
  (sharding and offload apply) unless `--db` overrides.

## D-048 · Supply chain, CI and deployment posture (2026-09-23)

- **Locked dependencies, pinned images.** `requirements.lock` (uv,
  `--universal --all-extras`, Python ≥ 3.12; `scripts/lock-deps.sh`
  regenerates it) is what the Dockerfile installs, then the package with
  `--no-deps` — the boto3 drift D-045 found cannot recur. Every base image
  is `tag@sha256`; the Python pin is `ARG PYTHON_DIGEST` so the CI matrix
  still builds 3.12/3.13 by tag. Dependabot moves the pins (actions,
  docker ×4, pip, gomod ×2). The gateway runtime left EOL Alpine 3.20; the
  Go SDK image and `go.mod` match the gateway's Go. The `test` extra stays
  in the image on purpose (D-011: one image).
- **Build once, publish the tested image.** The test job builds each image
  once and pushes it as `:ci-<sha>` with SBOM and provenance, pulls it
  back by digest for the suite and the SDK tests, and `publish-image`
  promotes by manifest re-tag after a Trivy gate (CRITICAL/HIGH, fixed
  only). Nothing is rebuilt for publishing. `ci-*` tags accumulate; their
  retention is OQ-7. Workflow token is `contents: read` by default;
  actions are SHA-pinned; `govulncheck` runs beside `go vet`.
- **Registry validation on every write path.** The NATS and Kafka
  consumers apply the namespace registry per claim (HTTP, MCP
  `record_claim` and extraction already did); a `strict` namespace was
  enforced only on `/v1/ingest`. Violations are dropped with a reason and
  counted. Dead-letter headers carry the exception class and a code only
  — a Postgres `DETAIL: Key (...)=(...)` used to ride in a header — and
  the dead-letter stream is bounded (`LOOM_DEADLETTER_MAX_BYTES`, 256
  MiB). The Kafka consumer takes SASL/TLS settings; broker auth
  authenticates Loom to the broker, and the topic ACL *is* the write
  permission.
- **Kubernetes posture.** Every pod: non-root, read-only root filesystem
  with an emptyDir at `/tmp`, no capabilities, no service-account token.
  Default-deny ingress with one allowance per tier (CNPG's operator must
  reach the cluster pods, or failover stalls); PodDisruptionBudgets on the
  tiers that run two or more replicas; the `scale` overlay's JetStream is
  bounded (the Go default was unlimited on a 1 Gi PVC) and the NATS
  monitor port is off the client Services. Egress is deliberately open.
- **Local defaults.** Compose binds the engine, load balancer and MCP to
  `127.0.0.1` (`LOOM_BIND=0.0.0.0` for LAN access); documented env vars
  that compose never passed (`LOOM_MCP_NAMESPACE`, `LOOM_ALIAS_TYPES`,
  the agent-eval and worker dials) are passed; the keys file is written
  atomically at 0600 under `secrets/`.

## D-049 · Store after the review: reversible merges, faithful export, owned leases (2026-09-23, schema v5)

- **D-019 made real.** `merge_entities` logged nothing it moved, overwrote
  `object_json`, deleted the source, and no unmerge existed — "reversible"
  meant only that the old key still resolved. Now a merge writes
  `merge_log` (who folded into whom, the folded node's identity and prior
  aliases) and `merge_log_observations` (per repointed row: prior subject,
  object entity, object_json), and `GraphStore.unmerge(namespace, alias)`
  reverses exactly that merge — recreating the node, repointing only the
  logged rows still on the target (so chained A→B→C merges reverse in any
  order), restoring `object_json`, returning the aliases, dropping both
  dossiers. `lifecycle unmerge --namespace N --alias type:key`. Writes that
  name a merged-away ref (claims, restored observations, `add_alias`)
  attach to the canonical entity: an exact-key upsert used to resurrect
  the node, and the worker then re-merged it and dropped both dossiers on
  every extracted mention of `ip_address:10.0.4.7` — the demo's own
  resolution moment undoing itself.
- **`norm_key` keeps structure in numeric keys (D-024 tier 2).** It
  stripped every non-alphanumeric, so `10.0.4.7`, `100.4.7` and
  `1.0.0.47` collided and were auto-merged as spelling drift. Keys made
  only of digits and `. : / -` keep those characters after case and
  whitespace folding; `web-01` / `WEB_01` / `web01` still collide. The v5
  migration recomputes the column for existing rows. Hex-containing keys
  (IPv6) are not special-cased yet.
- **Export is faithful, extended (D-022).** JSONL carries `schema`,
  `decline` and `merge` records; a restore used to turn a `strict`
  namespace permissive and forget every adjudication. The lifecycle CLI —
  and `seed`, `ingest`, `vulns`, `agent_eval` — open the engine's store
  (`store_from_env`: `LOOM_SHARDS` and `LOOM_BLOB_*` apply), so an export
  covers every shard with real bodies; `--db` is an explicit
  single-database escape hatch. The D-032 tenant-move recipe works as
  written now.
- **Wrappers.** `BlobOffloadStore` delegated only abstract methods, so
  with offload on, `record_claims` ran one transaction per claim and
  `observations_for_many` one round trip per ref — the D-043 regression
  back through a wrapper the contract suite never wrapped. Every public
  store method is delegated, with a guard test on both wrappers. A shard
  no longer inherits `LOOM_DB_READ` (a tenant's reads went to the
  default cluster's replica); a shard's own `{"dsn", "read"}` entry names
  its replica. A vanished blob is reported (`_blob_missing`, body `None`)
  rather than served as the stub text; the blob is written before the
  row and removed if the insert fails.
- **Leases have owners (D-031).** `set_extraction_status`,
  `defer_extraction`, `put_doc_chunks`, `put_dossier` take `worker_id`
  and apply only while that worker holds the lease — or while nobody
  does, so direct calls and a `--once` run on fresh rows still land.
  `extend_extraction_lease` renews per extraction window; chunk and
  dossier leases record their holder.
- **Vectors (D-025).** `ensure_vector_index` matched every model's
  tables (a model switch never backfilled); purge left stale ANN rows.
  Both are per model and per row now. Postgres HNSW with a namespace
  post-filter returned short or empty results for a minority tenant;
  queries widen `ef_search`, use iterative scan on pgvector ≥ 0.8, and
  fall back to the exact scan when the index starves, matching SQLite.
- **Smaller.** An older image never lowers the stored schema version or
  re-runs DDL (it warns and skips). `search_entities` uses an expression
  index on `lower(key)` with a half-open range on both backends;
  `observations_by_prefix` (cite tokens) is an index range too.
  `subjects_citing` is bounded in SQL. `wipe()` sweeps declines and the
  merge log. The SQLite lock is re-entrant with outermost-only commit.

## D-050 · Recorded supersession and PROV-O export (2026-09-24)

`ClaimIn.supersedes` / `Observation.supersedes` name an earlier observation
this one corrects; it is **recorded, never inferred**. Read side: an
observation that a *visible* later observation supersedes is excluded from
conflict detection, ranks at ×0.5, and renders `[superseded by <cite>]`;
for an `as_of` before the correction it is current again (visibility
decides, so a redacted, out-of-scope, or after-T correction does not act).
Ingest validates against the store at every HTTP door — same namespace,
same subject, visible, else 422 or a rejected batch item, and a batch
cannot supersede a row recorded earlier in the same batch. The store
persists the column (schema v6, D-054); export/import carry it;
`superseded_ids` answers the single-row question. `GET
/v1/observations/{id}/prov` exports one observation as PROV-O JSON-LD
(prov:Entity/Agent/Activity, derivation from the artifact span, an
extraction Activity with the model agent when attrs name one,
wasRevisionOf/wasInvalidatedBy for a supersession), gated like the raw
observations route with 404 for anything outside the reader's world — a
plain dict, not a contract model. The seed carries one same-source
`contract_owner` correction so the demo can show a recorded correction
next to the two-source conflict.

## D-051 · Honest budget, hybrid ranking, value-per-token packing, entity conflicts, pages (2026-09-24)

The read-path design gaps the 2026-09-23 review left open (hardening §R
1–5), all landed and measured with the retrieval scorecard (D-053):

- **Honest budget.** The budget charges the compact rendering an agent
  actually receives — item text plus every citation (cite, source, date),
  handle hint plus id — not item text alone. `est_tokens` is recalibrated
  to `len/3 + 4` from a cl100k measurement (2.7 chars/token on rendered
  facts; the old `len/4 + 8` under-counted conflicts by about a quarter).
  `ContextPack.charged_tokens` (additive) reports the sum; handles take at
  most 15 % of the budget with the first always shipped (a pack that cut
  something must say so; it rides outside the budget only when the budget
  is below twice a handle's cost). The scorecard checks the rendered prompt
  with a real tokenizer (`tiktoken` in the test extra): measured
  wire/budget 0.82–0.99, never over 1.0. Every documented pack number
  moved (web-01 at budget 400 is now `charged_tokens` 378, one handle
  "74 more", `omitted_handles` 4; the IP lease pack is 47).
- **Hybrid ranking.** A BM25 leg over the gathered candidates (predicate
  names split so "operating system" reaches `runs_os` and "port" reaches
  `listens_on_port`, one suffix rule, `attrs` never scored) fused with the
  cosine leg by reciprocal rank fusion (k=60) when vectors exist; with a
  single leg the normalized scores are used, because RRF collapses rank 1
  vs 2 to 1/61 vs 1/62 and the rare-term IDF signal would vanish. Recency
  and confidence are post-fusion multipliers; a relevance floor keeps
  unmatched facts shippable by recency; extracted ×0.85; superseded ×0.5.
  Two new scorecard rows (predicate-name words, rare-term IDF) fail the
  old keyword scorer.
- **Value-per-token packing.** Selection is score per charged token with
  an MMR-style diversity penalty (×0.5 once a predicate holds three items),
  so 40 logins no longer crowd out flows and ports; conflicts still ship
  first.
- **Entity-valued conflicts.** Values are normalized before comparison
  (casefold, bool↔"true", 9 == 9.0) and validity windows must overlap;
  entity-valued predicates now conflict when each source asserts one
  current object (a single source asserting several current objects makes
  the predicate a set on that subject, e.g. logins, `affects` — not a
  contradiction). The single-source lease reassignment stays a time
  series.
- **Pages past the gather cap.** A truncated entity gets a `more` handle
  carrying the window edge and the question; expanding it gathers
  `observed_before` that edge and pages until exhausted, so the 1,7xx
  older kernel observations are reachable — the confident-"no" gap D-038
  described now has a handle to pull.

## D-052 · GKE re-validation of the posture changes (2026-09-24)

D-048 changed what every pod is allowed to do (read-only root, no
capabilities, no service-account token), what may talk to what
(default-deny NetworkPolicies with one allowance per tier, including the
CloudNativePG operator's path to the instance manager), and what a node
drain may take (PodDisruptionBudgets) — all kustomize-validated only. A
fresh cluster with NetworkPolicy enforcement on (Dataplane V2) ran the
D-043 recipe against images built from the batch: rollout clean, an
unlabeled pod refused by NATS and Postgres and answered by the gateway and
engine, ingest 174/s and asks 284/s at zero errors (D-043's numbers),
primary promoted in 13 s with **zero** failed writes across a 2/s probe
(D-045 had three: the pool's `connect_timeout` and keepalives now cover
the gap), and a drain that evicted one queue node and one replica at a
time while reads stayed ready. Two recipe additions: the project had lost
its `default` VPC, and `kubectl` needs `gke-gcloud-auth-plugin`. The
first gated publish failed on Trivy — pip's vendored `msgpack` and the
base image's `setuptools`, both HIGH with fixes — and the answer was to
remove the package manager from the runtime image rather than pin it
(nothing imports either at run time); both images scan clean now. Table
in `deploy/README.md`. The fully-merged batch image (schema v6) was then rolled onto the same cluster: the **v5→v6 migration ran in place on the populated 3-instance HA Postgres** (readyz reported schema 6, pgvector, no downtime), and the read-side supersession and the PROV-O route were confirmed live (the hooli `contract_owner` correction ranks current with its predecessor `[superseded by …]`; `GET /v1/observations/{id}/prov` returns valid JSON-LD).

## D-053 · Retrieval scorecard: packs against the obvious baselines, rule-scored, no judge (2026-09-24)

`python -m loom.retrieval_eval` compares `loom@{400,800,1600,3200}`,
`full` (everything about the question's entities; its token cost is the
point, and it is not sent past a cap), `vector` top-k and `recency` top-k
on the same store, the same generated questions, and the same prompt
rendering `/v1/answer` uses. Six question families with store-derived
truth (never hand-written): lease-at-T in both `valid_at` and `as_of`
forms, cross-source conflict, multi-hop, abstention (an entity or
predicate that does not exist — a confident answer is a hallucination),
numeric lookup, and temporal order. Answers use a fixed two-line format so
scoring is rule-based; there is no LLM judge, because a second model's
errors are indistinguishable from the first's and drift with its version.
Citation support is measured at the id level — support@pack (the truth
ids are among the context's citations) and support@answer (the model
cited them) — rather than by NLI, because every Loom item carries an
observation id and the ground truth *is* a set of ids. A rule-based
scripted reader that answers only from the rendered context isolates
retrieval recall from reading; `--runs` reports variance; live runs carry
provider-reported cost under a `--max-cost` ceiling. Baselines get no time
axis on purpose: the question states the date, and reading the windows is
what a model without Loom has to do. Seed-corpus result with the hashing
embedder: `loom@1600` matches `full` at about 60 % of its mean tokens and
18 % of its maximum; recency loses half the conflicts and chains,
cosine-only half the orderings; the scripted reader abstains correctly
everywhere, so the abstention row only discriminates live models. R-6 is
addressed except MRR/nDCG, which accuracy at graded budgets plus
support@pack replaces for these answer shapes. `docs/evaluation.md` has
the talk command; the real-corpus table with the chosen model is a
rehearsal-week task. Local output lives in `eval/` (gitignored).

## D-054 · Store after R-9: incremental worker ticks, per-entity gather limits, WAL readers (2026-09-24, schema v6)

- **Worker ticks are incremental.** `observations_without_embeddings`,
  `artifacts_needing_chunks` and `dossier_candidates` walked their tables
  from the beginning every tick (a per-row anti-join over everything
  already embedded). Each backlog now starts from a per-(model, shard)
  high-water mark in `loom_meta` (`hwm:*`), kept 1,000 rows below the
  oldest pending row and monotonic, with a full rescan on a process's
  first and every 16th tick to catch backfills with old `recorded_at` and
  leases that expired unreleased. Dossier candidacy evaluates only
  entities touched since the mark or holding a lease, over a new
  `(subject_id, recorded_at)` index the namespace-led index could not
  serve; anything that drops a brief (redact, merge, unmerge) resets the
  mark. Accepted: a row that lands below the mark waits for the rescan.
- **The gather pre-limits per entity.** `observations_for_many` pulled
  every row of up to 400 entities before the window function trimmed, so
  a hub cost its degree per ask. Each entity's newest `limit` rows per
  side now come from an index range with its own LIMIT (`LATERAL` on
  Postgres; a generated `UNION ALL` of 200 entities per statement on
  SQLite, under the compound-select bound). 20k-edge hub, limit 20:
  SQLite 101 → 21 ms, Postgres 170 → 13 ms.
- **SQLite reads use WAL readers.** One writer plus a pool of four read
  connections (`LOOM_DB_READERS`, 0 restores the single connection);
  reads inside a thread's own write transaction still join it. Reads
  racing batch ingest: 63 → 649 reads/s, p50 61 → 6 ms. Known cost: a
  pure-read multi-threaded mix loses about 40 % to GIL convoying (2.9k →
  1.7k reads/s at 8 threads); revisit on a free-threaded interpreter.
- **`iter_entities(since=)`** over `entities (namespace, created_at)`, so
  the alias pass can be incremental. **`norm_key`** keeps the separators
  of colon-separated hex keys (IPv6, MAC, host:port); v6 recomputes keys
  carrying `:`.
- **Schema v6** = `observations.supersedes` (D-050), five indexes and the
  norm_key recompute; an older image warns and skips DDL (H-B12).

## D-055 · MCP 2026-07-28 alignment, the third scorer, extraction retries (2026-09-24)

- **Every MCP tool publishes an `outputSchema`** derived from the
  contract models and returns `structuredContent` beside the text mirror;
  the pack tools' schema is the *agent view* of `ContextPack` (TypedDicts
  nested over contract models) — presentation, not a second contract;
  HTTP still serializes `ContextPack`. Annotations: `readOnlyHint` on all
  read tools, `destructiveHint: false` everywhere (append-only),
  `idempotentHint` on every tool but `answer`, `openWorldHint: false`.
  `format: concise|detailed` on ask/ask_scope/expand (concise = cite
  tokens and twenty subjects; detailed = 32-hex ids and every subject).
  Handles are described as stateless, HMAC-signed when a secret is set,
  without TTL, invalidated only by secret rotation. `record_claim`
  derives a content-addressed `event_id` when none is given (a retried
  write-back is one observation) and takes `supersedes` (cite token or id)
  — a recorded correction, never inferred (D-050). `ask` and `ask_scope`
  stay two tools with disjoint descriptions; the server instructions
  recommend budget ≤ 1500 for scope asks, the size at which Claude Code
  stopped spilling tool results to disk in the rehearsal.
- **CISA's ADP is the third scorer.** NVD 2.0 metric entries whose
  `source` is the CISA ADP org id land as source `cisa-adp` (they surfaced
  as `nvd:<uuid>`), so CNA-vs-CISA is a readable cross-source conflict;
  SSVC decision points from the CVE 5.1 ADP container become `ssvc_*`
  claims when a record carries it (the NVD feeds do not).
- **Extraction retries only what failed (amends D-047).** A partly
  garbled document stays `pending`; parsed windows are remembered by
  content hash per process, so the retry spends only the failed windows;
  at the attempt bound a partial is `done` with the offsets logged, not
  `failed`. A vanished blob is `skipped` by extraction (chunking needs a
  store-side marker — open). The alias pass asks `iter_entities(since=)`
  and skips the walk when nothing is new. `agent_eval`'s Anthropic path
  uses `max_tokens` 8000 with adaptive thinking (`LOOM_AGENT_THINKING=off`
  to disable); refusals are errors.
- **Seed:** 592 claims — a same-source `contract_owner` correction that
  `supersedes` its predecessor, resolved at load time: "recorded
  correction, not a conflict" next to the two-source initech conflict.

## D-056 · Engine-side rate limiting; STIX 2.1 and OCSF as connectors (2026-09-24)

- **The gateway's bucket model also runs in the engine**
  (`loom.ratelimit.RateLimitMiddleware`, pure ASGI): auth first, one token
  bucket per grant id, never one for a raw header value, an LRU-bounded
  map, and a second stricter bucket for the LLM and embedder routes
  (`/v1/answer`, `/v1/entities/semantic`) so a valid reader cannot burn
  provider spend without bound. Dials `LOOM_RATE_PER_SEC` (the gateway's
  name), `LOOM_RATE_BURST`, `LOOM_RATE_LLM_PER_SEC`, `LOOM_RATE_LLM_BURST`;
  unset = unlimited, so dev mode is unchanged; open mode limits per client
  IP only when dialled. The keys file gains `rate_per_sec`, `rate_burst`,
  `rate_llm_per_sec` (engine and Go loader; the gateway ignores the LLM
  field), hot-reloaded and retuning the live bucket; zero or negative is a
  configuration error that disables the entry. 429 with `Retry-After`;
  probes and scrapes are never limited.
- **Interop lives in connectors, not core.** `loom.connectors.stix`
  (bundle → envelopes, observations → a valid 2.1 bundle) and
  `loom.connectors.ocsf` (`vulnerability_finding` in and out) plus a
  non-strict schema registration; the engine learns nothing about either
  standard, and a `mapping` dict overrides the default table per
  namespace. Identity conventions: a STIX `vulnerability` with a CVE
  reference and an OCSF `cve.uid` both land on `cve:<id>`, the entity the
  vulns connector writes, with the same predicate names, so one CVE reads
  as one record whatever produced it; a scanner's CVSS is its own source
  so conflicts surface honestly (D-035). STIX `observed_at` is the
  object's `modified` (event ids embed it: replays dedupe, revisions
  append); reports and notes are documents cited by the claims of the
  objects they list (D-039). Skipped by design: revoked objects, markings,
  `observed-data`, custom properties. Exports carry per-item Loom
  citations (`x_loom_observation_id`, `unmapped.loom_observation_ids`).

## D-057 · Evaluation validity: equal-token baselines, graded answers, unsent rows excluded (2026-09-24)

A whole-project review (`docs/hardening.md` §S) found the scorecards on the
talk slides could be wrong in Loom's favour. The harnesses now hold every
condition to the same bar, and a row nobody answered is never a score.

- **Equal tokens.** `vector@B` and `recency@B` fill the same budget B as
  `loom@B` with the pack builder's own item accounting (was a fixed top-20,
  ~320 tokens, against packs up to 3,200). `--k` is gone.
- **`full` is everything.** It walks the scope and gathers with no
  per-entity cap; `--full-cap` then applies by tokens. Loom keeps its
  1,000-per-entity gather, and each question records whether its truth is
  inside it (`in_loom_gather`); misses are listed with the table, never
  filtered out (filtering would flatter Loom).
- **Unanswered rows** — over `--full-cap`, past `--max-cost`, provider
  errors, empty or `finish_reason=length` replies, failed context builds —
  are counted per condition in a *Not sent / errored* column and excluded
  from every denominator; the table shows n. A tripped `--max-cost` marks
  the scorecard **INCOMPLETE** and exits 3. Rows stream to `<out>.jsonl`.
- **Grading.** Conflicts need every value named (the word "conflict" alone
  passed); numbers within half a unit of the recorded last decimal (EPSS
  < 0.005 made "0" pass under the old absolute 0.005); orderings exactly A
  or B; entities as whole tokens (web-01 no longer matches web-010);
  history in asides is not graded; citations are hex with an a-f letter or
  a full 32-hex id (dates were read as citations).
- **Generation.** Seeded sampling over the whole population; snapshot-feed
  predicates (EPSS) excluded from ordering questions; conflicts asked
  `as_of` a store-derived instant (`--reference-time`) so the set does not
  drift with the wall clock.
- **Live calls** run at temperature 0 (dropped once for a model that
  rejects it), `--max-tokens` 2048, `--reasoning-effort` optional.
- **agent_eval.** Exposure passes on recall ≥ 50 % of the KEV set (all of
  it when ≤ 4), precision 1 (no invented or non-KEV CVE) and the software
  named per CVE — naming one of 29 was a pass. Every factual task needs at
  least one citation the agent saw and none it did not. A provider outage
  (`LLMError.transient`: rate limit, 5xx, unreachable, an OpenRouter
  200-with-error-body) is retried once per task, then shown as *Not run* —
  out of the pass rate, cost kept — never scored as the model's failure.
  `--out` is rewritten atomically after each task.
- **Consequence.** Every earlier table (the 2026-09-09 models table, D-053
  retrieval numbers) was scored under the old rules and is not comparable;
  both are re-run on this build. Equal tokens first narrowed the story
  (on the seed, vector caught up at 1,600; on the real corpus it won at
  400 and on multi-hop); D-061 and D-062 closed both gaps. Final, live,
  real corpus: Loom 81 / 84 / 86 / 96 % against vector 75 / 77 / 79 / 87 %
  at 400 / 800 / 1,600 / 3,200 tokens (`docs/evaluation.md`); agent
  scorecard: two of eighteen models 12/12 (`docs/models.md`).

## D-058 · Read-path correctness and wire-honest budgets (2026-09-24)

- **Scalar conflicts compare each source's newest claim only.** A source
  that moved on (cmdb 20.04 → 22.04, nmap 22.04) is no longer a side;
  values one source asserts at the same instant still count as a set. The
  planted seed conflicts (web-01 `runs_os`, initech `contract_owner`)
  still surface — verified on a live engine.
- **Briefs are second-class citizens no more.** A type-scoped key gets a
  brief only if it can see every observation the brief cites; briefs are
  withheld for `as_of` and `valid_at` reads; a brief takes at most 25 % of
  the budget and carries its newest 8 citations. Withheld briefs are
  counted in `ContextPack.withheld_briefs` (additive).
- **Subjects resolve to their canonical entity** at `build_pack`,
  `expand_pack` and scope entry (`resolve_refs`), so a merged-away name
  keeps its conflicts and does not reappear as a second subject.
- **Scope walks are bounded**: `LOOM_MAX_SCOPE_ENTITIES` (2,000) and
  `LOOM_MAX_SCOPE_OBSERVATIONS` (100,000); a cut is reported as
  `ScopeTruncation.reason = "scope_cap"` (additive; `gather_limit` for the
  per-entity cap). Walks skip superseded edges. A scope expand predicate
  the question names ranks as the question's topic (the seed
  alert→host→logins question went from 0/2 users to 2/2).
- **Budget honesty on the MCP wire.** D-051 measured only the answer
  prompt; an MCP agent received 2.2–3.6× the budget. The concise view now
  carries citations as `"<cite> <source> <date>"` strings, drops the
  per-item score, adds `charged_tokens`, and pack tools send compact JSON;
  the charge is recalibrated to that output: worst 1.02× (cl100k, items +
  handles; the fixed ~70-token envelope is not charged). Demo numbers moved
  (60 / 380 / "76 more") and were re-verified on a live engine.
- **Excerpt KNN filters inside the index** (sqlite-vec metadata filter;
  exact SQL sort over the cited artifacts on Postgres): 196 → 33 ms on
  SQLite for 60 cited artifacts among 30k chunks.
- **Smaller:** expand supersession uses only rows the reader can see and
  finds corrections outside a page's window (`corrections_of`); thread
  expansions hand back a conflict that does not fit as a handle; excerpt
  expansion charges its citations; `truncated` counts only visible rows;
  exports write tombstones first and `restore_tombstone` drops briefs
  citing the row; trailing punctuation no longer breaks auto-resolution;
  the SQLite v5→v6 migration takes `BEGIN IMMEDIATE`; `merge_candidates`
  skips groups whose every pair was declined — grouped first, then tested,
  because the direct self-join made SQLite compare 74k × 74k entities per
  worker tick on the vulns corpus (found while embedding it).

## D-059 · Browser-facing guards and write-side scope (2026-09-24)

- **Open dev mode is no longer writable from a web page.** The engine, the
  MCP http transports and the gateway refuse a foreign `Host` (400; DNS
  rebinding), a foreign `Origin` (403) and non-JSON bodies on `/v1` POSTs
  (415; a `text/plain` no-cors POST was a CSRF write). Allowed by default:
  IP literals, `localhost`, single-label names and the cluster suffixes
  (`*.svc`, `*.cluster.local`, `*.internal`); `LOOM_ALLOWED_HOSTS` and
  `LOOM_ALLOWED_ORIGINS` extend them, `*` disables the host check. The MCP
  server's `--host` defaults to 127.0.0.1.
- **Citations are a write-side gate.** H-A6 let a type-scoped reader open a
  document once some visible fact cites it — but the citing key chose the
  citation. A type-gated key may now cite only a document it ingested or
  one already backing a fact inside its entity types. The engine records
  the uploader in `attrs["loom.uploader"]` (reserved: a sender that
  supplies it is refused). HTTP single and batch ingest, and the NATS
  writer — which resolves the gateway-stamped `Loom-Principal` to a live
  grant when the keys file is mounted on it — apply the same check.
  Extraction keeps claims from such a document inside the uploader's
  entity types.
- **Supersession** is one shared check for HTTP, MCP and the queue: a
  correction stays on its subject and inside the key's entity types.
- **Auth before parse:** no key → 401, unknown key → 403, before the body
  is read.
- **Spend control:** MCP tool calls spend the general bucket, and `answer`
  / `find_related` the LLM bucket (`rate_llm_per_sec` now holds there). A
  batch of n costs n tokens on the engine as on the gateway; a batch over
  the burst is 413, not a 429 a shipper retries forever. The gateway parses
  rate dials as floats (`0.5` silently meant unlimited) and fails start-up
  on garbage, as the engine does. Compose passes `LOOM_RATE_*`,
  `LOOM_MAX_BATCH`, `LOOM_ALLOWED_*` through. Buckets stay per process:
  the ceiling is rate × workers × replicas — documented, not a shared
  limiter.
- **Scoped views:** type-scoped keys get a narrowed `GET /v1/schemas` and
  filtered counts from MCP `list_namespaces` / `describe_namespace`. The
  gateway's HTTP-forward batch path reports the engine's per-item verdict.

## D-060 · Sticky resolution, bounded adjudication, lifecycle-chained imports (2026-09-24)

- **An unmerge sticks.** It records a decline for the pair; every
  resolution tier honours declines and re-reads them each job, so the
  worker no longer re-merges within one tick. `python -m loom.enrich
  distinct a b --namespace ns` marks two entities as different (splitting
  a current merge first); `lifecycle unmerge` gains `--allow-remerge`.
- **Adjudication spend is bounded.** Every model call counts against
  `ADJUDICATIONS_PER_TICK`; an unreadable verdict backs off per pair
  (60 s doubling to 1 h) and becomes a persisted decline after 3; an outage
  ends the pass without charging the pair; verdicts parse leniently
  ("yes", "95%") but are never guessed.
- **EPSS emits movement only** (`--epss-ledger`): a new observation when
  the score moves ≥ 0.001 or 5 %, or the percentile ≥ 0.01 — a nightly
  refresh added ~109k unchanged rows (and their embedding cost) before.
- **Imports chain versions.** OCSF and STIX imports set `supersedes` on
  each new version of a record (`connectors/chain.py`); a resolved OCSF
  finding closes the host's exposure, Suppressed (3) is not resolved, and a
  STIX revocation closes an imported edge. Malformed records are counted,
  not fatal.
- **The queue consumer settles per message**: a failed batch is re-written
  one message at a time so one poison envelope parks only itself, and a
  claim whose document has not arrived is redelivered with a growing delay
  instead of dropped. `python -m loom.ingest` retries 429 / 5xx honouring
  `Retry-After`.
- **Declined groups never starve a tier; a decline can be taken back.**
  Tier-2 (fuzzy) candidates skip settled groups — every pair of differing
  raw keys declined — as tier 1 does, grouped first by normalized key
  (41 ms on a 49.5k-entity SQLite store with 3.5k settled groups).
  `GraphStore.forget_decline` and `python -m loom.enrich undistinct a b
  --namespace ns` forget one pair, whoever declined it; nothing merges at
  that step — the next tick may merge or ask again. In a scope pack a fact
  pointing into a reached entity from outside the pack carries that
  entity's path, like one whose subject is the reached entity.
- **KEV value changes are recorded; exports speak versions.** KEV event
  ids are keyed on `dateAdded`, so a changed ransomware flag, due date or
  required action was dropped as a replay. `load` now reads each KEV CVE's
  stored rows and records a changed value as `<id>:<catalog stamp>`,
  observed at the catalog's `dateReleased`, superseding the previous
  version and citing a re-recorded advisory; unchanged values keep their
  ids, so an existing store gains only the changes (the refresh job's key
  now needs `r` as well as `w`; `emit` has no store and keeps the old ids).
  STIX export gives every version of an object one `id` and `created` with
  increasing `modified`; OCSF versions share `finding_info.uid`; both
  export the newest version unless `--history`. Exports carry the original
  event ids and sources, so importing an export is a replay.

## D-061 · Scope topics reach past a hub's window (2026-09-24)

On the embedded vulns corpus every KEV multihop question ("which CVEs that
CISA lists as exploited in the wild affect software host:web-01 runs?")
sat outside Loom's gather: the kernel product keeps its newest 1,000 of
~2,785 `affects` edges and 26 of the 31 KEV CVEs are older. A token-matched
vector baseline got 5/6 at 3,200 tokens; Loom got 0/6 at every budget.

- **Topic.** A scope question's topic is the predicates it names — every
  content word of the predicate in the question — from the registry plus
  the gathered rows, minus the walk's own edges.
- **Hub completion.** For a hub the gather limit cut,
  `GraphStore.edges_to_carriers` (additive) joins its expand edges (newest
  10,000) to far-end rows on the topic in one indexed join per side
  (SQLite `CROSS JOIN`: the planner otherwise scanned the namespace, 7 s →
  19 ms; Postgres `LATERAL`). Those carriers are admitted whatever their
  age, and first when the D-058 entity cap binds. Skipped when most far
  ends carry the topic, so "highest CVSS" does not fill the scope to its
  cap. `observations_for_many(predicates=)` (additive).
- **Pack.** A reached entity's conflict ships first only on a focus
  predicate; otherwise it is a conflict handle after the pages (the root
  subject's conflicts still ship first). Topic facts are selected before
  briefs and excerpts. Siblings sharing value, source and the reaching
  edge render four per item, citing each fact and edge (~56 tokens per
  CVE instead of ~127).
- **Measured** (scripted reader, real corpus, `--namespaces netsec`):
  loom@3200 multihop 0/6 → 6/6 (vector@3200 5/6), loom@3200 overall 85 % →
  100 %; every other family at every budget unchanged; no multihop
  question outside Loom's gather any more; build_pack p50 ~1.4 → ~1.55 s
  on a shared host (roughly flat). `SqliteStore.observations_by_ids` now
  uses the primary key (255 → 4 ms per 500 ids). Seed demo numbers
  unchanged (verified live).
- **Limits.** Completion needs the attribute named in the question in the
  registry's words ("exploited in the wild" → `exploited_in_wild`); a
  question saying only "KEV" gathers as before, and agents can still page
  (R-5). At 1,600 tokens no condition passes multihop — 32–44 CVEs do not
  fit. The retrieval harness's rule-based reader learned to read grouped
  items; scoring is unchanged (D-057).

## D-062 · The asked attribute ships first; handle ids are plain text (2026-09-24)

At 400 tokens Loom trailed a token-matched vector baseline (scripted 62 % vs
72 % on the real corpus; live DeepSeek 68 % vs 74 %). Three packing faults
and one cost fault, each with a concrete question behind it:

- **Conflict order was alphabetical.** Asked for a CVE's `has_severity`,
  the pack shipped the `cvss_score` conflict and made the asked one a
  handle. Equal-standing conflicts now order by H-C5 score, then the
  attribute the question names, then relevance; conflicts still ship
  first and one that does not fit is still a handle.
- **An excerpt could crowd out every fact** (a KEV advisory excerpt plus
  its handle filled a pack asked for an EPSS score), and the diversity term
  cut the invoice holding the maximum asked for. The attribute a subject
  question names (`subject_attribute`: the predicates it names, minus those
  whose value it also names, so ordering questions keep their lexical
  match) is picked before briefs and excerpts, like D-061's scope topic,
  and is exempt from the diversity term. The first pass holds back room for
  one thread handle, so the handle no longer rides over the budget.
- **Handles cost ~128 tokens** — base64 JSON tokenizes at ~1.45 chars per
  token, and the first handle always ships: a third of a 400 pack. Handle
  ids are now `ns~type~key~predicate` plus tagged fields, percent-escaped,
  times in ISO basic form: 55–65 tokens. Prefixes, HMAC signing and
  decoding of old handles are unchanged (base64 never hid anything).
- **Measured** (scripted, a rebuilt corpus of the same shape — the review
  sandbox blocked copying the live scorecard volume): loom@400 68 % → 79 %
  (vector 77 %), conflict 9/9, numeric 12/12; 800 and above unchanged; no
  pack over budget (six multihop@400 packs had been charged 594–633).
  Live DeepSeek on lease/conflict/numeric at 400: 81 % → 100 %. Latency
  flat. Demo: web-01's `charged_tokens` 380 → 351 (the handle is 57 tokens,
  not 86), re-verified on a live engine.

## D-063 · GKE with auth on and real data: what a production-shaped run found (2026-09-25)

The D-057…D-062 batch re-validated on GKE (`deploy/README.md`) the way a
production deployment runs it — keys on engine, gateway and consumer,
signed handles, provider keys, the corpus loaded by the documented Jobs.
Every earlier validation ran open, keyless and without an LLM, and that
is where most of what broke was hiding. Choices made fixing it:

- **The first load is an operator's; the refresh is a pinned key's.**
  Connectors read the namespace registry and register only what is
  missing (`merge_schema` is additive), so the nightly job never needs
  registry rights (D-059 keeps those for ungated keys).
- **Source grants take families**, `nvd:*`, with one rule in the engine
  and the gateway: an exact name, or a `:*` suffix matching that prefix —
  not bare globbing. NVD's per-scorer sources (D-035) made exact names
  unusable for a feed key.
- **A partial load is a failed load.** A loader exits non-zero when the
  engine refuses any envelope, and advances the EPSS ledger only after a
  load that landed whole — a refused row must be re-offered, never
  recorded as sent.
- **Worker pools.** `loom.enrich run --jobs` / `LOOM_ENRICH_JOBS`
  (`vectors`, `llm`, or named jobs); a vector backlog drains without the
  interval sleep; LLM work keeps its pacing. One tick running everything
  in turn stays the default: split pools trade "embed after the merge" for
  throughput.
- **Mounts and inputs are forgiving where operators trip:** keys mount at
  `/etc/loom-keys` (not over an image's files), keys are stripped
  (`--from-file` newlines), the load generator takes a key.
- **Nothing a scorecard or log prints carries a credential**
  (`redact_dsn`), and the MCP server closes its store on exit.
- **Teardown deletes volumes before the cluster** — six orphaned disks
  (84 GB) from D-052 had filled the project's SSD quota.

Measured (one cluster, one run each): load 605,803 envelopes at 435/s
and a refresh at 724/s, both 0 refused; ingest 178/s; asks 201/s with
auth, signing and semantic ranking on (D-052's 284/s had none of them);
failover 12 s, 0 of 235 writes lost; drain 34 s, 0 of 470 readiness
checks failed; retrieval on the cluster's corpus: Loom 69 / 83 / 83 /
92 % against vector 74 / 74 / 74 / 80 % at 400 / 800 / 1,600 / 3,200.
Findings: `docs/hardening.md` S-35…S-45.

**Review 2026-09-26.** As first shipped, skipping the sleep re-ran every
job on each drain iteration, and only `vulns` exited non-zero on refusals.
Now a `Pacer` restricts drain ticks to the vector jobs until `interval` has
elapsed since the last full tick and backs off a failed job (one interval,
doubling, 10-minute cap); `ingest.fail_on_refusals` makes every loader
(`loom.ingest`, `vulns`, `stix`, `ocsf`, `ldap`) fail on a refusal, and
`load_direct` counts store-side refusals.

## D-064 · Scope asks the agents actually make (2026-09-25)

The 2026-09-24 agent scorecard's transcripts, not its pass counts, set
this work: 45 of 54 two-hop exposure runs failed, and the failures were
mostly Loom's ergonomics, not the models' reasoning.

- **The scope budget is measured, not remembered.** The ≤ 1,500 guidance
  predated D-058, when a scope pack was 2.2–3.6× its budget on the wire;
  since D-058 the concise view is ~1.02×. Measured (cl100k, whole concise
  view, web-01's two-hop pack on the real corpus): 1,500 → 2,070 wire
  tokens and 17 of 32 KEV CVEs; 3,000 → 3,707 and 32/32; 4,000 → 4,738.
  `ask_scope` defaults to 3,000 and the instructions cap it at 4,000 —
  ≥ 4.5× under Claude Code's 25k MCP output limit. `ask` is unchanged.
- **The agent's words pick the topic.** An attribute placed in
  `expand_predicates` (registered with no object types, or seen only with
  values and never linking) is the scope topic and is not walked. When the
  question names no attribute by name, a registered attribute whose
  *description* it names (≥ 2 shared words, ≥ 40 % of the description, the
  best match only) is. On the real corpus both phrasings agents used went
  from 1 of 32 CVEs to 32 of 32 at budget 3,000.
- **Silence is a bug.** `ContextPack.notes` (additive): an unknown expand
  predicate with up to three close matches, an attribute taken as topic, a
  scope that stops a hop short of the link the question names, a subject
  that names no entity. Shown before the items in the MCP view and in the
  answer prompt; not charged.
- **Paths are discoverable.** `describe_namespace` lists, per entity type,
  its outgoing and incoming links with the other end's type and its
  attributes (`GraphStore.relation_summary`, additive, cached 60 s), and
  names the namespace's own two-hop paths.
- MCP `ask_scope` accepts list arguments a model sends as JSON text.

The retrieval scorecard (scripted) and the seed demo numbers are
unchanged; the agent scorecard is re-run on this build.

## D-065 · A raw-LDAP / LDIF connector for object-level AD reachability (2026-09-25)

> **Experimental — review 2026-09-26.** Decoding gaps to fix before real
> use: mapped generic rights (e.g. GenericWrite stored as `0x20028`) are not
> recognised; some `has_ace` event ids collide and drop; inherit-only ACEs
> are attributed to the object itself; an inbound trust is emitted reversed;
> large imports scan the DN index per ACE. Kept on `main` as experimental;
> the fixes were deferred out of this session. The DSN-redaction and
> exit-code fixes (af65b92) did land.

`loom.connectors.ldap` decodes a raw Active Directory export (canonical
input LDIF, RFC 2849) into typed, cited, time-stamped claims in an `ad`
namespace, so an agent can ask "what rights, trust and membership path
connects user:X to domain:B?" over the existing scope walk.

- **Decode, don't compute.** The connector emits the direct directory
  edges — `member_of`, `contains`, `trusts` (direction, transitive,
  sid_filtering, forest_transitive), `has_ace` (GenericAll, GenericWrite,
  WriteDacl, WriteOwner, ForceChangePassword, AddMember,
  AllExtendedRights), `can_delegate_to`, `rbcd_from` — and
  userAccountControl / SPN attributes. It does no transitive
  effective-admin computation and no attack-path ranking: Loom carries
  the evidence, the agent assembles the path, and group nesting is the
  walk's job at depth N. That is the line against BloodHound, whose output
  schema we chose not to track.
- **Our schema, a stable input.** LDIF and the Windows attributes it
  carries barely move; the mapping is ours. Entities are keyed by
  objectSid (decoded to `S-1-5-…`), with DN and sAMAccountName carried
  for entity resolution.
- **A hand-rolled Security Descriptor / ACE parser** (the self-relative SD
  layout is documented in MS-DTYP and stable) keeps `requirements.lock`
  free of a heavy dependency. Allowed and object ACEs are decoded;
  deny ACEs, the SACL and rights outside the table are skipped; a
  malformed ACE ends the parse rather than raising.
- **Object-level only, stated plainly.** Sessions and local admin on
  member servers are not in the directory; they need host collection. If
  loaded as their own claims, the same walk extends over them.
- **Time and citations are the point.** Every claim cites the source
  object's DN and the export, observed at the export's timestamp, so
  `valid_at` answers "was this ACE or trust in place as of X?".
  Re-import is idempotent; a later export is appended as history.
  Cross-export supersession (auto-closing an ACE that was later removed)
  is deferred.

No core, contract or store changes. The connector reads a file and
performs no directory operations.

## D-066 · An object-level AD reachability capability benchmark (2026-09-26)

> **Numbers withdrawn — review 2026-09-26.** The published 100% recall is
> not a blind result (the walk was handed the planted chain's predicates and
> depth), and the decoy-exclusion and edge-precision metrics are tautological
> as computed and are withdrawn; the "gathered" fraction reflects the
> generator's uniform density, not hub pressure. A blind re-measurement is
> deferred. See the banner in [ad-eval.md](ad-eval.md).

`loom.connectors.ad_gen` + `loom.ad_eval` are the AD analogue of the KEV
retrieval benchmark (D-053/D-061). A deterministic synthetic directory
(`corp.local` root + a bidirectional-transitive `dev.local` child + a
non-transitive `partner.local` and a SID-filtered `fabrikam.local` used
only by decoys) plants known 2/3/4-hop membership → ACL → trust chains and
decoy dead-ends (a non-transitive trust, a SID-filtered trust, a disabled
start account) under dense benign noise, all recorded to a truth sidecar.
The generator emits real self-relative SD/ACE bytes and reuses the raw-LDAP
connector's own right/GUID/UAC/trust constants, so it exercises the
shipped parser, not a mock.

The harness loads through that connector and scores with a scripted reader
(no LLM): path-recall (every edge of a planted chain present **and cited**),
edge-precision, decoy-exclusion (the dead-end's disqualifying fact is
itself surfaced and cited, so a reader can reject it), entities-gathered
vs total (how much of the directory the walk touched), truncation, build
latency and pack tokens. A chain longer than three hops is walked in
re-anchored asks (ScopeSpec.depth ≤ 3, D-046); node account-status is a
subject-scoped ask (a broad path walk ranks that scalar out).

Analysis only: it validates that pre-planted edges are present and cited,
computes no path ranking and emits no tradecraft. Medium run (seed 7,
4,429 objects, 31,430 observations, 8,702 raw edges): 100% path-recall and
100% decoy-exclusion at budgets 1,500/3,000/4,000, gathering ~2.5% of the
store per chain, build p50 ≈ 150 ms — the scope walk finds the chain by
walking outward from the start, not by scanning. The scripted number is
retrieval alone; a live reader assembling it from the pack is an optional
`--live` smoke. No core, contract or store change.

## D-067 · A first-class `path` answer type (2026-09-26)

Reachability ("what connects A to B?") was answered by an agent reassembling
a scope pack. The `path` type returns the connecting edge sequence(s)
directly: `PathRequest` / `PathPack` (with `Path` = ordered `list[PathEdge]`,
each edge `subject`/`predicate`/`object`/`cite`/`valid_from`/`valid_to`/
`source`), `POST /v1/path`, MCP `find_path`, and `path()` in the Python, TS
and Go SDKs. Additive: no existing shape changed; `ScopeTruncation.reason`
gained `max_paths` and `depth`. Contract artifacts (`schemas.json`,
`openapi.json`, the TS types) regenerated and drift-clean; the Go gateway
forwards ingest only, so reads reach the engine unchanged.

`context.find_paths` is a bounded, shortest-first BFS over the **same**
gather/walk machinery `build_pack`/`resolve_scope` use: `via` edges followed
both directions (an `affects` edge stored cve→product is walked
product→cve), simple paths only, capped by `depth` (≤ the scope cap 3, a
longer request clamped and noted), `max_paths`, the token `budget` (charged
per edge via `item_tokens`, like a pack) and `LOOM_MAX_SCOPE_*`. Endpoints
are alias-resolved (D-058); `as_of`/`valid_at` filter every edge and a
superseded edge (D-050) never appears; a path through a type-gated entity is
dropped. Cuts are reported in `truncated`, advice in `notes` (D-064).

Honest and domain-agnostic: it enumerates paths that EXIST along the named
predicates — the KEV `host → product → cve` chain and the AD
`user → group → (ACE) → domain` chain alike — and does no ranking, scoring
or exploitability weighting. It explores the gathered neighborhood, so a
"no path" with a `gather_limit` truncation means none within a hub's newest
gathered edges, not none at all; `ask_scope`'s topic completion (D-064)
reaches past a hub, `find_path` does not. Verified live on the vulns corpus
(cited `host → product → cve` chains, with the hub cap honestly reported)
and the AD fixture (`user → group → ACE → trust → domain`).


**Review fixes (2026-09-26).** The MCP SDK calls a tool with its arguments
keyed by alias, so `find_path` received `from=` and failed on every real
call; tools are now registered through an alias-to-parameter mapper, and a
test drives it over stdio. The search ran over paths, not entities, so a
hub re-reached by many routes multiplied them (a 1,000-CVE hub at depth 3
took 164 s and 2.2 GB); edge extensions are now capped at
`LOOM_MAX_SCOPE_OBSERVATIONS` and reported as `scope_cap` (1.4 s, 42 MB),
and the last hop only checks reachability. Completed paths' edges are
checked with `corrections_of` as of `as_of`, so a correction the walk never
gathered still retires its edge. A canonical entity of a gated type reached
through a cross-type alias is treated as not found and the requested ref is
echoed; the unknown-`via` vocabulary comes only from in-scope rows; a
`depth` truncation is reported only when a path could still be extended,
with `total` = paths found; a bare string argument is no longer
comma-split.

## D-068 · nmap scan-inventory connector (2026-09-26)

`loom.connectors.nmap` parses an operator's `nmap -oX` XML report (a file;
the connector performs no scanning and no probing) into cited, timestamped
inventory claims in `netsec`: a `host` keyed by hostname-else-IP (the seed
convention), `listens_on_port` / `runs_service` per open port, and
`runs_software → product:<vendor>:<product>` keyed through the shared
`vulns.parse_cpe` (nmap's 2.2 CPE URI normalized to 2.3) so a scanned host
lands on the exact `product` node NVD/KEV/OCSF/STIX populate — a scan then
fuses into the `product ← affects ← cve` chain and `find_path`/`ask_scope`
walk straight from a scanned host to its exploited-in-the-wild CVEs. `runs_os`
is a lower-confidence guess (min(0.9, accuracy/100)) that conflicts honestly
with an authoritative inventory (D-035). One scan-report document is cited by
every claim (D-039); content-addressed event ids make re-import idempotent
and a later scan history. Strictly inventory — no exploitation logic, no
attack-path scoring; reachability stays the scope walk / `find_path` (D-067),
and the loader fails on refusals (D-063). Fixtures are genuine nmap 7.98
output; a blind `find_path` test confirms a scanned host reaches its
product's KEV CVE, cited. Honest seam: nmap's service-DB CPE vendor can
differ from NVD's (nginx: `igor_sysoev` vs `nginx` / `f5`), so those don't
fuse until entity resolution reconciles them (D-042) — surfaced, not
special-cased.

## D-069 · Entity resolution: cross-vendor same-product aliases (2026-09-26)

The nmap connector (D-068) surfaced a seam D-042 left open: different CPE
vendors key one real product under different `product` entities that never
fuse — nmap's `igor_sysoev:nginx`, NVD's `nginx:nginx`, F5's
`nginx_open_source` — so KEV reachability missed a scanned host's CVEs
purely because the product node did not merge.

- **Candidate generation now proposes cross-vendor matches; the adjudicator
  still rules.** Two `product` keys of *different* vendors are proposed when
  their product tokens are equal, or one is the other plus a non-version
  `_suffix` (a CPE edition variant, `nginx` vs `nginx_open_source`), and the
  shared stem is specific (>= 6 chars, or itself used as a vendor). No
  hard-coded synonym table — the adjudicator judges with both records' facts
  and the 0.8 confidence gate decides; a wrong merge reverses via
  unmerge->decline (D-060).
- **Same-vendor pairs are never proposed by this rule** (R1/R3's job), so
  `apache:http_server` and `apache:tomcat` are never offered.
- **Catch-all tokens excluded regardless of length** (`multiple_products`,
  the `multiple_*` family, `unknown`, `various`): a first draft proposed
  `<vendor>:multiple_products` against every other such vendor on the real
  corpus (624 candidates, placeholder-dominated); the guard brings it to 464
  real cross-vendor pairs.
- Tier-1/2 spelling and the KEV<->NVD rules R1/R3 are unchanged.

**Live-corpus precision (real judge, 2026-09-26):** 200 of the 464 candidates asked (deepseek-chat-v3.1 judge on a copy of the real corpus): **12 merged, 188 declined (94% decline rate)** — the judge is conservative, and generic tokens it could have merged (`connect`, `server`) were declined. The target case merged (`nginx:nginx` ↔ `f5:nginx_open_source`, 1.00), as did `google:android`↔`android:android_os`, `mesa3d`↔`mesa_project`, Ubiquiti UniFi, DNN, October CMS. No cross-family false merge in the sample. **Known imprecision:** a few combined/bundle CPE product names (e.g. Trend Micro `apex_one_and_worry_free_business_security`, a cpanel bundle) were merged into a component on a shared CVE — same-vendor and reversible (unmerge→decline, D-060), not distinct-product errors, but a bundle node collapsing onto one member is imprecise and left as a known limitation.

## D-070 · OSV / GHSA advisory connector (2026-09-26)

`loom.connectors.osv` parses OSV-schema JSON (osv.dev / GHSA / PyPI / Go /
npm; a file, a directory, stdin, or a query/batch response — it fetches
nothing) into cited, timestamped claims in `netsec`. **Fusion is by CVE id,
not product:** a record whose `aliases` carry a CVE is keyed to the shared
`cve:` node NVD/KEV/OCSF/STIX already write to (OSV id + aliases in attrs),
so an OSV/GHSA CVSS score corroborates or conflicts with NVD's on one entity
(D-035); with no CVE alias it keys `advisory:<OSV-id>`. Per record:
`cvss_score` from the `severity[]` CVSS v3/v2 vector (v4-only keeps the
string, band from `database_specific.severity`) + `has_severity`, source
`ghsa`/`osv`; the summary+details as a cited document (D-039);
`affects -> package:<ecosystem>:<name>` (a new non-strict `package` type)
with version ranges in attrs. The package key is OSV's `ecosystem:name`,
**not** a CPE `product` — folding the two is entity resolution's job
(D-042/D-069), surfaced not hidden. Content-addressed event ids embedding
`modified` -> idempotent, a revision is history; the loader fails on
refusals (D-063). Genuine osv.dev fixtures (Log4Shell, the eslint-scope npm
compromise) + a fusion test asserting the cited cross-source CVSS conflict.
Deferred: CVSS v4.0 base scoring and CWE emission.

## D-071 · OCSF connector ingests detection findings, not just vuln findings (2026-09-26)

The OCSF connector maps `detection_finding` (2004), `security_finding`
(2001) and `incident_finding` (2005) to a `finding:<uid>` entity related to
the host it concerns (`detected_on`, host keyed hostname-else-IP as the seed
and nmap do) and to any CVE it references (`references`, fusing on the shared
`cve:` node like OSV). Severity/status ride on the edges; versions chain by
`finding_uid` (D-050) so a status transition supersedes rather than
conflicts, and Suppressed is kept distinct from Resolved (muted != remediated).
A detection thus surfaces on a host's pack beside its exposure. New `finding`
type + `detected_on`/`references`/`title` predicates are non-strict
registrations, not a contract change; vuln import and export are preserved,
export stays vuln-only. Real GuardDuty->OCSF fixture from the ocsf/examples
repo; a fusion test confirms the cited detection on the same host+cve nodes.

## D-072 · Cloud inventory / config connector (terraform + AWS Config) (2026-09-26)

`loom.connectors.cloud` parses a `terraform show -json` / `.tfstate` or an
AWS Config `configurationItems` snapshot (a file; no cloud API) into cited,
timestamped inventory claims in a non-strict `cloud` namespace: a small
generic vocabulary (`resource`, `vpc`, `subnet`, `security_group`,
`cloud_account`) with `in_subnet`/`in_vpc`/`in_account`/`member_of`
(containment), `attached_to`, `depends_on`, `references`, `allows_ingress`
edges. A resolved-reference predicate follows the *target* entity type so a
type-constrained `in_subnet`/`in_vpc` never points at a generic resource.
Content-addressed event ids + snapshot-time `observed_at` -> idempotent
re-import and drift-as-history (a later snapshot's opened port is a new
observation, not an overwrite). Strictly inventory/config-as-facts:
reachability stays the scope walk / `find_path`, no attack-path scoring. Real
terraform (1.9, null/random/local providers) + AWS Config fixtures; a walk
test reaches a vpc from an instance through `in_subnet`/`in_vpc`, cited. No
contract or store change.

## D-073 · MITRE ATT&CK taxonomy connector (2026-09-26)

Loom ingests the published MITRE ATT&CK knowledge base (STIX 2.1) as a cited
taxonomy in the `attack` namespace: technique/tactic/group/software/mitigation
entities keyed by ATT&CK external id, and the catalog relationships MITRE
publishes (`in_tactic`, `uses`, `mitigates`). **Scope is deliberately the
catalog level only** — names, ids, descriptions, edges — with no operational
how-to: the per-relationship procedure descriptions are dropped, and
`detects`/`subtechnique-of` are out of scope. Defensive reference data, held
like the vuln corpus as a queryable, cited graph. Content-addressed (event id
embeds `modified`): re-import idempotent, a version bump is history. Non-strict
registration, no contract change. Import-only (no ATT&CK export). Real
verbatim ATT&CK fixture; a walk test reaches a group's techniques and their
mitigations, cited.

## D-074 · LDAP connector S-50 deep fix (2026-09-26)

Five decoding bugs in `loom.connectors.ldap` fixed (S-50 items from the
2026-09-24 review):

1. **Mapped GenericWrite**: AD stores GenericWrite as its mapped form
   0x20028 (READ_CONTROL | DS_SELF | DS_WRITE_PROP), not the generic bit
   0x40000000. Added the mapped form to `decode_rights`.
2. **Event-id collision**: long SIDs pushed `has_ace` event ids past the
   128-char cap, so `[:128]` truncated them into collisions and dropped
   ACEs. Now uses a content-addressed hash suffix for over-length ids.
3. **Inherit-only ACEs**: ACEs with INHERIT_ONLY flag (0x08) were
   attributed to the object itself. Now skipped in `decode_rights`.
4. **Trust direction**: bidirectional trusts (trustDirection 3) now emit
   two edges (one per direction) so the scope walk / find_path traverses
   both ways. Outbound (2) swaps subject/object so `subject trusts object`
   always means "subject accepts credentials from object's principals."
5. **O(n²) SID lookup**: `ref_for_sid` scanned the full DN index per
   call. Added a `by_sid` dict alongside `by_dn` for O(1) lookups.

No contract change. Connector removed from experimental status.

## D-075 · Entra ID (Azure AD) connector (2026-09-26)

`loom.connectors.entra` parses Microsoft Graph API JSON exports — users,
groups, service principals, app registrations, directory roles, role
assignments, app-role assignments and OAuth2 permission grants — into cited
identity/RBAC claims in the `iam` namespace. Key edges: `member_of`,
`has_role` (with privileged-role tagging for Global Admin and friends),
`has_app_role`, `has_permission`, `owner_of`, `requires_permission`,
`reports_to`. Service principals carry credential expiry (`key_credential`,
`password_credential`) for secret-sprawl detection. Non-strict registration,
no contract change. 26 tests including a scope walk + find_path round trip.

## D-076 · Okta directory connector (2026-09-26)

`loom.connectors.okta` parses Okta API JSON exports — users, groups,
applications and app-user assignments — into cited identity claims in the
same `iam` namespace as the Entra connector. Key edges: `member_of`,
`assigned_to` (app-user), `has_role` (admin role). Users carry `mfa_enrolled`
/ `mfa_factor`, `credential_provider`, `status` and `last_login` for
hygiene questions. Both IdP connectors share overlapping predicates so entity
resolution can fold a user present in both. Non-strict registration, no
contract change.

## D-077 · Identity connectors checked at scale; four defects fixed (2026-09-26)

D-075/D-076 were tested only on hand-written fixtures (three users each).
`loom.connectors.iam_gen` now writes seeded Entra + Okta exports in the
shapes the real APIs return, up to 60,000 users with an every-user hub
group, and `loom.iam_eval` checks every implied edge against the store.
Run on SQLite locally and on GKE through lb → gateways → NATS →
consumers → Postgres (`deploy/README.md`), it found four defects:

1. **Per-user OAuth2 consents collided** (S-52). The event id omitted the
   consenting user, so one (client, resource, scope) kept only its first
   user: 323 of 357 grants lost at 2,000 users. The principal is now part of
   the id; the client id rides as an attr.
2. **Role holders typed as users** (S-53). A role assignment to a
   role-assignable group or a service principal became `user:<id>`, so the
   group → Global Administrator path never connected. The holder's type
   comes from `$expand=principal`, else the export's own objects.
3. **Okta role assignments dropped** (S-54). `/users|groups/{id}/roles`
   name the holder only in `_links.assignee.href`; every such object
   yielded nothing, silently. Now parsed (user or group holder), and any
   object that yields no claims is counted `empty` in the import stats.
4. **Shared predicates clobbered each other** (S-55). Registration merges
   by predicate name, later wins; Entra declared `has_role → directory_role`
   and Okta `has_role → admin_role`, so whichever registered last made the
   registry reject the other's role claims on its next import (the
   overlapping nightly refresh). `member_of` / `has_role` are now declared
   once in `loom.connectors.iam_schema` and used by both.

After the fixes: every edge stored once (0 missing, 0 extra) at 2k, 20k
and 60k users; re-import adds 0 rows; all planted role paths come back
cited from find_path and a blind scope walk. No contract change. Still open:
scope walks through the hub groups (S-57).

## D-078 · Blind AD re-measurement (2026-09-26)

S-51: the D-066 benchmark handed the walk the planted chain's predicates,
depth and interior anchors. `loom.ad_eval --blind` knows only the two
endpoints the question names: one ask anchored at each over the fixed
predicate set (`member_of, has_ace, trusts, contains, can_delegate_to,
rbcd_from`) at the depth cap, an account-status ask on the start, and
find_path between them at the default depth. Decoys now land in one of
three outcomes — *evidenced* (the apparent path and its disqualifier both
cited), *not surfaced*, *leaked* — instead of "excluded", which a walk that
found nothing also scored. Edge precision is no longer reported. The blind
numbers replace the withdrawn ones in `docs/ad-eval.md`: recall holds, the
cost does not (about half the directory gathered, seconds per ask), and
find_path misses 4-hop chains (depth cap 3, S-58).

## D-079 · Lazy-greedy fact selection (2026-09-26)

`_select_facts` rescanned the whole candidate pool every round; once the
diversity factor applied, its early exit stopped helping, so a pack cost
rounds × pool (35k candidates on an identity hub: 3 s of a 4.5 s ask). A
candidate's value only falls (density is fixed; the factor drops once), so
a heap of upper bounds picks the same fact each round — a popped candidate
still at the top is the best, ties to the earlier pool position as the scan
did — in O(n log n). The one difference: a candidate is checked for
affordability when it reaches the top rather than on every scan. Every
existing pack test, including the exact charged-token ones, is unchanged.
On the hub walk: 3.1 s → 1.2 s in selection.

## D-080 · No turning back, paths met in the middle, node status (2026-09-26)

Closes S-57 and S-58. Three changes, one contract addition each.

**Scope walks do not turn back** (`ScopeSpec.siblings`, default false). The
walk followed each expand predicate both ways with no memory of how it
reached an entity, so from a user `member_of` climbed to a group and came
straight back down to every member: through a group holding every user,
depth 2 gathered ~1,100 entities and depth 3 hit the scope cap (2–8 s per
ask at 20–60k users). Now an edge that leaves an entity along the predicate
that reached it, with the entity on the same side of both edges, is not
followed — user -member_of-> group <-member_of- co-member, OU -contains->
user <-contains- … . Up a chain, down a chain and across predicates
(host -runs_software-> product <-affects- cve, the KEV demo) are unchanged;
every seed and demo test holds. `siblings: true` restores co-members for the
question that wants them.

**find_path meets in the middle** (`MAX_PATH_DEPTH` 3 → 6,
`PathRequest.depth` default 3 → 4, `PathRequest.siblings`). Partial paths
grow from both endpoints and join where they meet; each round extends the
side whose frontier has fewer edges to follow, so a user in an every-user
group reaches Global Administrator from the role's side without walking the
group's members. A 6-edge path costs two 3-hop frontiers, which is what
makes the higher cap affordable. It applies the same no-turn-back rule (a
shared group with an admin is not a route to the admin's role; at the
bidirectional search's cost those co-membership paths had crowded the real
one out of `max_paths`), and stops once more than `max_paths` paths are
settled at a length. The depth-cut report keeps its meaning (a depth-length
walk from `from` that could extend), checked depth-first to the first
witness.

**Node status** (`PredicateDef.node_status`, `PathPack.node_status`). A
predicate the registry marks node status — `enabled` for LDAP, Entra and
Okta (declared once in `iam_schema`), Okta's `status` — is reported for every
entity on a returned path: its newest visible value (as_of, valid_at,
supersession applied), cited and charged against the budget. A path through
a disabled account is returned, because it can still matter, and says so.

Measured (blind AD medium, laptop): find_path recall 73 % → 100 % (4-hop
0/3 → 3/3), 1.0–1.2 s → 0.1 s, disabled-account decoys leaked → evidenced;
scope walk 2,108 → 920 entities gathered, 4–6 s → 0.5 s. IAM small: depth-2
hub walks 3.3 s → 0.16 s (1,052 → 16 entities), the 3-hop Global
Administrator find_path 1.1 s → 0.05 s. On GKE (Postgres,
60,000 + 41,973 users loaded through the gateway): depth-2 hub asks 2.4 s →
0.32 s p50 (1,148 → 13 entities), depth-3 8.0 s → 0.35 s (2,000, the scope
cap → 32); the 3-hop Global Administrator find_path 3.7 s → 0.47 s, 0.12 s
warm over HTTP. Blind AD on Postgres (loaded after D-081): scope walk p50
0.75–0.98 s medium, 1.35–2.1 s large (was 6–11 s), find_path 0.15–0.21 s,
every chain from 3,000 tokens and every decoy evidenced on both surfaces.

## D-081 · Planner statistics after a bulk load (2026-09-26)

On GKE a blind AD ask against Postgres took ~90 s; the same ask took 0.8 s
an hour later. Reproduced: a fresh namespace (31k observations) loaded into
a 1.5M-row store, then asked at once — 44 s; after `ANALYZE` — 0.5 s.
Autovacuum analyzes a table after 10 % of its rows change, so a namespace
under a tenth of the store was planned without statistics for it, possibly
for good. Any production import of a new source into a large store hit it;
the earlier 6–11 s GKE AD figures were inflated the same way.

Two changes, no contract change. Schema v7 sets
`autovacuum_analyze_scale_factor = 0.01` and `autovacuum_analyze_threshold
= 5000` on `observations` and `entities` (applied in place on open; the
live 1.5M-row cluster migrated with no downtime), so every writer — the
gateway → consumer path included — is re-analyzed within a minute of a
bounded change. And `GraphStore.refresh_statistics()` (ANALYZE on
Postgres, a no-op on SQLite, forwarded by the sharded store) runs when a
direct bulk load finishes (`import --db`, `ingest` direct, the eval
loaders), so a load is planned correctly the moment it returns.

## D-082 · Coverage: what an import collected (2026-09-27)

A partial export and a sparse environment looked the same once loaded: an
LDAP dump without security descriptors (no READ_CONTROL, or an ldapsearch
that did not ask for them) produced no `has_ace` edges, and find_path
answered "no path" as if nobody held rights; a user with no `enabled` on
record read as fine. Red and blue teams work from partial collection as a
rule, so the absence has to be distinguishable.

A connector now records, per import, what its export carried: one cited
claim per predicate, `coverage:collection -collected-> "<predicate>"` with
attrs `source`, `scope`, `with`, `of`, `state` (complete / partial /
absent) and, for status predicates, the entity `types` it applies to
(`loom.coverage`). A connector records only absences its format makes
meaningful: every AD object has a security descriptor and every account a
userAccountControl, so a missing one was not collected; `memberOf` may be
absent because there are no groups, so membership is recorded only when the
whole domain has none. Graph returns `members` / `owners` only when
expanded, Okta's factors are a separate call — a missing key is "not
asked", an empty list is an answer. Collection-level records (Entra role /
app-role / consent grants, Okta role assignments / app users) are made only
for a combined export; one file of several claims nothing about the others.

Reads take the newest record per (source, scope, predicate), as of `as_of`:
a scope ask or find_path over a predicate some import did not fully carry
adds a `coverage:` note naming it, the source and scope, and how much was
collected; find_path notes entities on its paths whose kind carries a
status predicate but which have no value on record ("status unknown, not
assumed"). A later, fuller export supersedes the gap. The core reads opaque
predicate names only; which absences count is the connector's call. The
synthetic AD generator now gives every object a security descriptor (an
empty DACL for most), as a real dump does. No contract change: coverage
records are ordinary claims.

## D-017 · License: Apache-2.0 (2026-09-04)

Public framework needs a real license; Apache-2.0 for the patent grant and
infrastructure-ecosystem norm. Canonical text in `LICENSE`.

## Open questions (decide when the use case firms up)

- **OQ-1:** ~~Real-time requirements on ingestion → do we need a queue sooner?~~
  Shape resolved by D-010 (queue exists only in the scale profile); remaining
  question is *when* demo/adopter volume forces the scale shape.
- **OQ-2:** One shared deployment with namespaces vs. per-team stacks as the primary
  story? (Both work; affects auth priority.)
- **OQ-3:** ~~AuthN/Z on the HTTP surface~~ Resolved: per-namespace API keys
  (D-013), the hashed keys file with data-scoping grants and hot reload, so
  rotation is a file update with no redeploy (D-013a), and the same key gate on
  the MCP http transports (D-024). A key-management *API* (as opposed to the
  `loom.keys` CLI + a mounted Secret) is not planned.
- **OQ-4:** Embedding model choice + dimensionality (affects sqlite-vec schema).
- **OQ-5:** ~~Retention/TTL policy~~ Mechanism shipped (D-016 purge/redact);
  remaining is per-team policy defaults and a scheduled sweep (cron/k8s Job).
- **OQ-6:** ~~Public name~~ Settled: Loom (D-005, 2026-09-11).
- **OQ-7:** Retention for the `ghcr.io/…:ci-<sha>` candidate tags CI pushes on every commit to `main` (D-048): a package retention rule, or a periodic cleanup Job.
