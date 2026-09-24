# Changelog

Loom is pre-1.0: contracts are stable within a minor version and every
change to them is recorded in `docs/decisions.md` (D-numbers below).

## Unreleased

Everything below is on `main` and not yet in a tagged release (the latest
tag is v0.1.0).

### The 2026-09-24 review batch (D-057…D-060)

Full list with statuses: `docs/hardening.md` §S.

#### Evaluation validity (D-057)
- Baselines fill the same token budget as the pack (`vector@B`,
  `recency@B`); `full` gathers everything; questions record whether their
  truth is inside Loom's gather
- Rows never answered (over `--full-cap`, past `--max-cost`, provider
  errors, empty or truncated replies) are excluded from denominators and
  shown per condition; a tripped cost cap marks the table INCOMPLETE and
  exits 3; rows stream to JSONL
- Stricter grading: conflicts need every value, numbers within half a unit
  of the recorded precision, whole-token entity matches, real citations
- agent_eval: exposure needs recall ≥ 50 % with precision 1 and the
  software named; every factual task needs a seen citation; provider
  outages are retried, then "not run" — never the model's failure
- Temperature 0 on live calls; seeded, whole-population question sampling

#### Read path (D-058)
- Scalar conflicts compare each source's newest value only
- Briefs: type-gate aware, withheld for `as_of` / `valid_at`, ≤ 25 % of
  the budget; `ContextPack.withheld_briefs` (additive)
- Merged-away names resolve to their canonical entity
- Scope walks capped (`LOOM_MAX_SCOPE_ENTITIES`, `LOOM_MAX_SCOPE_OBSERVATIONS`)
  and reported (`ScopeTruncation.reason`, additive); superseded edges skipped
- MCP wire within ~2 % of the charged budget (was up to 3.6×): compact
  JSON, string citations, `charged_tokens` in the agent view
- Excerpt KNN filters inside the index; SQLite `merge_candidates` no
  longer scans entities quadratically

#### Security (D-059)
- Host / Origin allowlist and JSON-only `/v1` bodies on the engine, MCP
  http and gateway (`LOOM_ALLOWED_HOSTS`, `LOOM_ALLOWED_ORIGINS`); MCP
  binds 127.0.0.1 by default
- Type-gated keys cite only documents they uploaded or ones already in
  their world — HTTP, batch and the NATS writer; extraction stays inside
  the uploader's entity types
- Rate limits on MCP tools including the LLM bucket; a batch of n costs n
  on both engine and gateway; gateway rate dials parse as floats
- Auth before body parsing; scoped schema and counts for type-scoped keys

#### Enrichment and connectors (D-060)
- Unmerges stick; `python -m loom.enrich distinct`; adjudication calls all
  count against the cap, unreadable verdicts back off and give up
- EPSS emits changes only; OCSF / STIX imports chain versions via
  `supersedes`; Suppressed is not Resolved
- Consumer settles per message and redelivers claims awaiting their
  document; `loom.ingest` retries 429 / 5xx with `Retry-After`
- Fuzzy (tier-2) candidates skip settled groups; `python -m loom.enrich
  undistinct` / `GraphStore.forget_decline` take a decline back

#### Release
- Every engine-image compose service builds (a fresh clone's
  `docker compose run --rm test` works); Go SDK CI can fail; `go.sum` and
  the TS `package-lock.json` committed; CI lint runs pyflakes; pinned
  govulncheck / openapi-generator; CI concurrency group

### Design follow-ups to the 2026-09-23 review (D-050…D-056)

#### Read path (D-050, D-051)
- Recorded supersession: `ClaimIn.supersedes` / `Observation.supersedes`
  (additive) name the earlier observation a claim corrects — recorded,
  never inferred. A visibly superseded row leaves conflict detection, ranks
  ×0.5 and renders `[superseded by <cite>]`; for an `as_of` before the
  correction it is current again. Every ingest door validates the target
  (same namespace, same subject, visible)
- `GET /v1/observations/{id}/prov` exports one observation's provenance as
  PROV-O JSON-LD, gated like the raw observations route
- Honest budget: the budget charges the compact rendering an agent receives
  (text plus citations plus handle hints); `est_tokens` recalibrated to
  `len/3 + 4`; `ContextPack.charged_tokens` (additive); handles capped at
  15 % of the budget. Documented pack numbers moved accordingly
- Hybrid ranking: BM25 over the gathered candidates (predicate names split
  into words) fused with cosine by reciprocal rank fusion; value-per-token
  packing with a diversity penalty; entity-valued conflicts with normalized
  values and overlapping validity windows; a `more` handle pages past the
  gather cap

#### Store (D-054, schema v6)
- Schema v6: `observations.supersedes`, five indexes, `norm_key` recompute
  for colon-separated hex keys (IPv6, MAC, host:port); an older image warns
  and skips DDL
- Worker ticks are incremental (per-model/shard high-water marks with a
  periodic full rescan); the multi-entity gather pre-limits per entity
  (20k-edge hub: SQLite 101 → 21 ms, Postgres 170 → 13 ms)
- SQLite reads use a pool of WAL readers (`LOOM_DB_READERS`, default 4);
  `iter_entities(since=)` makes the alias pass incremental

#### Evaluation (D-053)
- `python -m loom.retrieval_eval`: packs at graded budgets against `full`,
  vector top-k and recency top-k on store-derived questions, rule-scored,
  no LLM judge; see `docs/evaluation.md`

#### MCP, enrichment, connectors (D-055, D-056)
- MCP 2026-07-28 alignment: `outputSchema` + `structuredContent` on every
  tool, read-only/idempotent annotations, `format: concise|detailed`,
  `record_claim` takes `supersedes` and derives a content-addressed
  `event_id`
- CISA ADP lands as the third CVSS scorer (`cisa-adp`); SSVC decision points
  become `ssvc_*` claims when present
- Extraction retries only the windows that failed; a partial is `done` at
  the attempt bound; `agent_eval` uses adaptive thinking on Anthropic models
- STIX 2.1 and OCSF interop as connectors (`loom.connectors.stix`,
  `loom.connectors.ocsf`), import and export, with per-item Loom citations;
  the engine core learns nothing about either (`docs/interop.md`,
  `examples/stix_import.py`)
- Seed: 592 claims, including a same-source `contract_owner` correction
  that supersedes its predecessor

#### Security and operations (D-052, D-056)
- Engine-side rate limiting (`RateLimitMiddleware`): one token bucket per
  grant, a stricter bucket for the LLM/embedder routes, 429 +
  `Retry-After`; dials `LOOM_RATE_*` and per-key fields in the keys file;
  unset = unlimited
- Runtime image ships without a package manager (the first gated publish
  failed Trivy on pip's vendored `msgpack` and the base `setuptools`)
- GKE re-validation of the D-048 posture (NetworkPolicy enforcement, PDB
  drains, failover with zero failed writes) and an in-place v5 → v6
  migration on a populated HA Postgres (`deploy/README.md`)

### The 2026-09-23 review batch (D-046…D-049)

Six parallel review passes found ~60 verified issues; all landed except the
design follow-ups listed in `docs/hardening.md` §R.

#### Read path (D-046)
- `as_of` is the observation-time axis, applied in the store query (busy
  entities no longer yield empty time-travel packs; `truncated` counts as of T)
- Ingest rejects `observed_at` more than 24 h in the future; recency clamps to now
- Data gates apply to scope hops; extracted edges do not steer expansion
  unless `ScopeSpec.follow_extracted` (additive contract field); `subjects` ≤ 500
- Raw observations route gated and time-filtered like a pack
- Conflict handles expand at exactly `est_tokens`; forged handle fields are 400s
- Chunked-upload body cap, `nosniff`/`no-store`, ungated key required for
  `POST /v1/schemas`, answer prompt delimits items as data

#### Store (D-049)
- Reversible merges: `merge_log` + `unmerge` (schema v5); claims for a
  merged-away ref land on the canonical entity
- Blob-offload wrapper delegates the batch paths; shards no longer inherit
  `LOOM_DB_READ`; CLIs open the env-configured store
- Export carries schema registrations and adjudication declines; vector index
  per model; purge cleans ANN rows; pgvector minority-namespace fallback;
  `norm_key` keeps IP/version separators

#### Enrichment, LLM, MCP (D-047)
- Anthropic client works with thinking-enabled models; no redirects with the
  key; Retry-After to 60 s with jitter; usage logged per job
- Extraction per window with lease renewal; random document delimiter;
  sanitized `doc:` labels; registry validation on every extracted claim
- Resolution: registered-vs-registered key collisions adjudicated, numeric
  keys never spelling-merged
- MCP: scoped keys see only their namespaces; `ToolError` everywhere; compact
  citations with `cite` tokens accepted by `expand`/`get_observations`
- Eval: store-derived lease truth, non-KEV CVEs penalized; connector
  validates downloads before caching

#### Supply chain, CI, deployment (D-048)
- `requirements.lock` consumed by the Dockerfile; every base image pinned by
  digest; Dependabot; SHA-pinned actions; `govulncheck`; Trivy gate; SBOM +
  provenance; build once, promote the tested image
- Registry validation on the NATS and Kafka paths; sanitized dead-letter
  headers; bounded dead-letter stream; Kafka SASL/TLS
- k8s: securityContext, NetworkPolicies, PDBs, bounded JetStream, no SA token
- Compose binds to 127.0.0.1 by default; documented env vars now pass through

#### Docs and demo
- Demo script made honest (night-before prep, pinned judge, frozen volume,
  rendered fallback transcripts); numbers reconciled; README gains
  "How it differs" and "Limitations"; talk date is mid-October

## v0.1.0 — 2026-09-09

First tagged release: the conference build.

### Core
- Append-only, cited observations about entities; claims and documents;
  two time axes (`as_of` knowledge time, `valid_at` fact time) (D-001…D-012, D-024)
- Context packs: token-budgeted, question-ranked, conflicts first,
  expansion handles, document excerpts, relation chains for multi-hop
  scopes, handle cap with `omitted_handles`, partial-coverage reporting
  via `truncated` (D-018, D-020, D-035, D-038)
- Per-namespace schema registry; the core stays domain-agnostic (D-024)
- Stores: SQLite (WAL, sqlite-vec) and Postgres (pgvector), behaviorally
  identical under one contract test suite; namespace sharding; artifact
  offload to filesystem or S3 (D-011, D-025, D-032, D-033)
- Async enrichment: embeddings, claim extraction with span provenance,
  dossiers, two-tier entity resolution, leased worker fleet (D-018, D-019, D-023, D-031)
- API keys with data scoping, signed handles, retention and redaction (D-013, D-013a, D-016, D-021)

### Surfaces
- HTTP API with `/v1/ingest/batch`; JSON Schema and OpenAPI, drift-checked in CI (D-034)
- MCP server for agents: find, ask, ask_scope, expand, record_claim,
  answer, plus `list_namespaces` / `describe_namespace`, an agent-shaped
  pack view, and coverage warnings (D-026, D-036, D-038)
- SDKs: Python, TypeScript (generated types), Go (schema-validated) (D-026, D-034)
- Pipeline adapters: Fluent Bit, Vector, Kafka/Redpanda consumer, bulk loader (D-034)

### Scale (all opt-in)
- Go ingest gateway, NATS JetStream buffer with dead-letter, writer
  consumers, Postgres pool/read replicas, CloudNativePG HA overlay,
  load generator and capacity table (D-010, D-027…D-030)

### Real data and evaluation
- Vulnerability-intelligence connector: CISA KEV + NVD + EPSS, streamed,
  idempotent, history-preserving, nightly CronJob (D-035)
- Agent end-to-end harness over the real MCP transport with store-derived
  ground truth and a citation-faithfulness check; eighteen-model scorecard
  with billed cost (D-036, D-037)

### Validation
- Validated on GKE: capacity on real nodes, 18 h soak, HA failover at 11 s
  end to end (D-043); worker quality fixes from the soak (D-044)
- Release gate: the scale shape (lb → gateways → JetStream → consumer →
  store) smoke-tested in CI on every push; store migrations proven on a
  populated database; the published image re-validated on GKE before the
  tag moves (D-045)

### Measured on this release (laptop, generator co-located)
- 511k envelopes loaded in 81 s to SQLite; single-entity ask 2–5 ms at
  465k observations; two-hop scope over 1,077 entities in 0.5 s
- Eighteen models, three runs each: nine pass all four agent tasks three
  times out of three (12/12); citation faithfulness 216/216 task-runs
  (`docs/models.md`)
