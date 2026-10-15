# Roadmap & status

Status legend: ✅ done · 🔨 partial · ⬜ not started

**Fixed date: conference demo + presentation on 2026-10-21.**
The repo will be public on GitHub (private as of 2026-09-24); everything merged to `main` should be
presentable.

## Milestones to the conference

| When | Milestone |
| --- | --- |
| 2026-09-03 | Phases 0–2 working: contracts, store, ingestion (claims + documents), context packs, seed data, k8s manifests, CI |
| 2026-09-04 | Phase 3: MCP server — agents plug in natively (the demo's wow moment) |
| 2026-09-04 | Phase 4 core: embeddings + claim extraction from documents + first dossiers |
| 2026-09-08 | Hardening batch from the full review — `docs/hardening.md` (D-021…D-024) |
| 2026-09-08 | Enterprise-scale dials (phase 6, D-027…D-033) and pipeline integrations (phase 7, D-034), validated on k8s |
| 2026-09-08 | First real data: the vulnerability connector (D-035) — KEV + NVD + EPSS loaded next to the seed hosts, findings in `docs/real-data.md` |
| 2026-09-09 | Demo script (`docs/demo.md`), `v0.1.0` tag + `CHANGELOG.md`, cold quickstart timed from a fresh clone |
| 2026-09-11 | Validated on GKE (D-043): eight laptop-vs-cloud differences fixed in the repo, capacity numbers on real nodes, 18 h soak (found and fixed the worker OOM), HA failover measured end to end at 11 s |
| 2026-09-11 | Release gate (D-045): scale shape smoke in CI, v3→v4 migration proven on a populated Postgres, published image validated on GKE before the tag moves |
| 2026-09-23 | Review-fix batch: dependency lock consumed by the Dockerfile (the boto3 drift D-045 found), base images by digest, SHA-pinned actions + Trivy + build-once CI, pod security posture + NetworkPolicies + PDBs, registry validation on the queue paths, Kafka SASL/TLS, compose env passthroughs, demo script made honest (night-before prep, frozen volume), docs numbers reconciled |
| 2026-09-24 | Design follow-ups from the 2026-09-23 review (`docs/hardening.md` §2026-09-23, D-050…D-056): recorded supersession + PROV-O export, honest budget (`charged_tokens`) + BM25/rank fusion + value-per-token packing, retrieval scorecard with baselines (`docs/evaluation.md`), schema v6 store work, MCP 2026-07-28 alignment, engine-side rate limiting, STIX/OCSF connectors; GKE re-validation including an in-place v5→v6 migration (D-052) |
| 2026-09-24 | Whole-project review (`docs/hardening.md` §S, D-057…D-062): eval harness validity (equal-token baselines, graded answers, unsent rows excluded), read-path conflict/brief/alias/scope fixes and a wire-honest MCP budget, browser-facing guards and write-side citation gates, sticky resolution and bounded adjudication, multihop over hub entities in one ask (D-061), small-budget packing (D-062), release fixes (fresh-clone test run, Go SDK CI); scorecards re-run on this build |
| 2026-09-25 | GKE re-validation with auth on, signed handles, provider keys and the real corpus loaded by the documented Jobs (D-063): ten deployment-path bugs found and fixed (nightly refresh key, source families, worker pools, keys mount, DSN in scorecards…); failover 12 s / 0 lost writes, drain 0 not-ready, load 435/s |
| 2026-09-27 | Identity-pass throughput (D-087, S-63): FK child indexes (schema v8), batched ranking, a drainable sharded `identities` worker job, stepwise candidate query; on GKE the workers fold a 6,000-machine estate during ingest (75 merges left after the drain); 808 (SQLite) / 903 (Postgres lane) tests pass |
| 2026-09-27 | Identity across tools (D-083), host artifacts (D-084), format drift (D-085), purple correlation (D-086); one namespace per environment, registration merges shared predicates; tests run on GKE: 803 (SQLite) / 896 (Postgres lane) pass; 6,000-machine estate through the gateway: identities 100 % folded with 0 false merges, purple 600/600; S-60…S-62 fixed, S-63 (identity-pass throughput) open |
| 2026-09-27 | GKE re-validation of the renamed build; agent scorecard fixed and re-run (D-089: 36 models × 5 runs, 19 at 20/20), IAM check through identity merges (D-090); initial-load A/B 633/s vs 361/s for the 2026-09-25 build |
| 2026-09-27 | Renamed to LoomCtx (D-088): repo, package, images, env vars, k8s names and metrics; website live at loomctx.dev; 809 tests pass (904 on the Postgres lane) |
| 2026-09-27 | Coverage (D-082): connectors record what each export carried; asks and find_path note predicates an import did not (fully) collect and path entities with unknown status; 753 tests pass (845 on the Postgres lane) |
| 2026-09-26 | Hub-safe walks and paths (D-080, D-081): no same-predicate turn-back in scope walks and find_path (`siblings` opts in), bidirectional find_path to depth 6, `node_status` flags disabled accounts on paths, Postgres analyze thresholds + `refresh_statistics()` after bulk loads (schema v7); S-57/S-58/S-59 closed; re-validated on GKE; 746 tests pass (838 on the Postgres lane) |
| 2026-09-26 | Identity connectors checked at scale (D-077…D-079): Entra/Okta generator + harness, four connector defects fixed (S-52…S-55), blind AD re-measurement (S-51), lazy-greedy pack selection; validated on GKE through the gateway path to 1.38M observations; open: identity-hub walk cost (S-57), find_path depth/status (S-58); 738 tests pass |
| 2026-09-26 | Identity/IAM connectors (D-074…D-076): LDAP deep fix (S-50), Entra ID (Azure AD) connector, Okta connector; both IdPs in the shared `iam` namespace with overlapping predicates for cross-provider walks; 732 tests pass |
| 2026-09-29 | Identity at scale on the agent side (D-091…D-103): name search and named packs, sibling walks that keep their chain, one walk per pack and rare-carrier counting (delegation packs 12 s → 4.4 s); model scorecard re-run (35 models × 5, 15 at 20/20) and five Active Directory audits on a 10,000-account forest published (19 of 35 at 25/25); retrieval scorecard re-run on the current engine (80 / 85 / 86 / 97 %, within variance); site source committed; post-talk plan in `docs/future-work.md`; 841 tests pass (936 on the Postgres lane) |
| 2026-10-13 | Scale work on branch `scale-xl` (not yet on `main`): 500k-object realistic AD forest built and measured (D-104 fixes: SQLite statistics, cached relation summary, selective crowded walks); list mode (D-107), named queries (D-108), schema-drafting helper (D-106); full 10k/500k model A/B re-run pending on the final build |
| 2026-10-14 | Full AD scorecard on `scale-xl` (35 models × 5, named queries on and off, 10k and 500k): **92% on the five standard audits at 500,000 objects, 93% at 10,000** (24 of 35 perfect at 500k; 90% with named queries off); the three harder audits (D-113) 81% at both sizes, reported separately; same steps and spend at both sizes. Slow 500k list calls fixed (`contains` seeds from the label index, `of` takes a name; 482e25e). Site and `docs/models.md` updated, not yet deployed |
| 2026-10-15 | Postgres at 500k (D-105/D-112/D-113 addenda): one shared Postgres serving every agent against SQLite private copies, one build, 35 models × 5, all eight audits: **standard five 91% / 92%**, harder three 80% / 78%, same totals on every replayed call; Postgres writes batched (500k import 6.3 h → 45 min); names no longer depend on row order; kerberoast scorer checks every account put forward (published 500k harder tier 414 → 412 of 511); `LOOMCTX_MCP_WRITES=0` |
| early Oct | Freeze features; night-before load + alias pass on the frozen volume, dated re-runs of every rehearsal line (`docs/demo.md` checklist); presentation materials |
| 2026-10-21 | **Conference** |

## Phase 0 — Contracts ✅ (2026-09-03)

- ✅ `src/loomctx/contracts.py`: envelope (claim | document), Observation, Entity,
  Artifact, ContextPack/Items/Citations/Handles, AskRequest/ExpandRequest,
  schema registry shapes. JSON Schema export: `python -m loomctx.schemas`.

## Phase 1 — Core store + ingestion ✅ (2026-09-03)

- ✅ `GraphStore` protocol + SQLite implementation (entities, append-only
  observations, edges queryable from both ends, artifacts, namespaces)
- ✅ HTTP: `/healthz`, `POST /v1/ingest` (claims → 200 recorded; documents →
  202 accepted, artifact stored verbatim, extraction pending),
  `GET /v1/entities/{type}/{key}/observations`, `GET /v1/artifacts/{id}`
- ✅ Seed corpus: `python -m loomctx.seed` — 592 deterministic claims + 5
  documents across `netsec` and `procurement`, with planted demo moments
  (IP lease reassignment, two cross-source conflicts, incident report doc)
- ✅ Schema registry persistence + claim validation (2026-09-08, D-024):
  `POST/GET /v1/schemas`, additive per namespace; registered predicates
  enforce object types, `strict` namespaces reject the unregistered;
  `containment` predicates drive default scope expansion

## Phase 2 — Retrieval + context packs ✅ (2026-09-03)

- ✅ `src/loomctx/context.py`: rank (keyword sim + recency + confidence) → trim
  to mandatory token budget → cite every item → stateless expansion handles →
  cross-source conflict surfacing (single-source value changes are treated as
  time series, not conflicts) → as-of filtering
- ✅ `POST /v1/ask`, `POST /v1/expand`; SDK `ask()`/`expand()` live
- Known v1 limitation: relevance is keyword overlap — "operating system"
  doesn't match `runs_os` facts (the conflict item still surfaces the answer).
  Embedding similarity replaces this scorer in phase 4. *(Since D-051 the
  lexical leg is BM25 over the rendered facts, fused with cosine by
  reciprocal rank fusion when vectors exist.)*

## Phase 2.5 — Scopes + answering LLMs ✅ (2026-09-03, D-012)

- ✅ `ScopeSpec` (multi-subject questions; BFS expansion over containment
  predicates — "domain corp.local and its contents"); merged, deduped,
  per-subject-conflict-checked packs; `GET /v1/entities/search`
- ✅ `loomctx/llm.py`: OpenAI-compatible client covering OpenRouter, Venice,
  Groq, Together, Mistral, OpenAI, Ollama/vLLM/LM Studio (custom base URL),
  plus native Anthropic; configured by four `LOOMCTX_LLM_*` env vars
- ✅ `POST /v1/answer`: retrieval-grounded, citation-required LLM answers;
  auto-resolves entities named in the question; returns the pack for audit
- ✅ Live end-to-end run against a real provider (2026-09-04, OpenRouter /
  deepseek-chat-v3.1 via `.env`): auto-resolved 3 entities from the incident
  question, 63-item merged pack, cited answer that correctly traced the
  10.0.4.7 lease reassignment and flagged the OS conflict unresolved.
  Repeatable via `tests/test_e2e_answer.py` (skips without `.env`).

## Phase 3 — MCP server ✅ (2026-09-04)

- ✅ `src/loomctx/mcp_server.py` on MCP SDK v2 (`MCPServer`): `find_entity`,
  `ask`, `ask_scope`, `expand`, `record_claim`, `get_observations`,
  `answer` — same core functions as HTTP, `type:key` handles, server
  instructions teaching the find → ask small → expand → write-back loop.
- ✅ stdio for local agents (`claude mcp add loomctx -- docker compose run --rm
  -T loomctx python -m loomctx.mcp_server`) and streamable HTTP via compose
  profile `mcp` (:8300/mcp, boot-verified).
- ✅ Exercised by a real MCP client over stdio in CI (`tests/test_mcp_client.py`,
  2026-09-08) and by a live Claude Code agent session (see D-026 notes).

## Governance & operability batch ✅ (2026-09-04, D-013…D-017)

- ✅ Apache-2.0 LICENSE (public-adoption blocker removed)
- ✅ Per-namespace API keys enforced at engine + gateway; cheap-rejection
  ordering and per-key rate buckets shed abuse before it costs anything
- ✅ Idempotent ingest (`event_id` dedupe, both stores, verified through
  the full queue path) — at-least-once delivery no longer duplicates facts
- ✅ `/metrics` (engine + gateway), store-probing `/readyz` wired into k8s
  probes; in-place store migrations for existing DB files
- ✅ Lifecycle CLI: export/import (JSONL), retention purge, tombstone
  redaction
- ✅ Retrieval-quality scorecard in CI (9/9) — the baseline the phase-4
  embedding swap must beat
- ✅ Compose services now share one engine image (kills stale-image drift)

## Phase 4 — Async enrichment ✅ (2026-09-04, D-018/D-019)

- ✅ `python -m loomctx.enrich` worker (compose profile `enrich` / `--once` Job)
- ✅ Embeddings: pluggable `Embedder` (OpenAI-compatible + offline hashing
  fallback), cosine ranking in the pack builder with keyword fallback
- ✅ LLM claim extraction from document artifacts, with located span
  provenance and event_id idempotency; live-verified (24 claims from 5 docs)
- ✅ Dossiers: rolling per-entity briefs, served as the `brief` pack item
- ✅ **Entity resolution (D-019, 2026-09-04):** the enrichment worker folds
  same-key/cross-type duplicates (ip vs ip_address) into the most-connected
  canonical entity; merges are reversible (recorded as aliases), observations
  are repointed never dropped, and a query for a merged-away ref still
  resolves via its alias. Live-verified: doc-extracted facts reconcile onto
  the structured `ip:10.0.4.7`.
- ✅ Deeper resolution (2026-09-08, D-024): normalized-key matching
  (web-01 / WEB_01 / web01) auto-merges same-type spelling drift; cross-type
  collisions are adjudicated by the LLM with each record's facts as
  evidence and merged only on a confident verdict.
- ✅ **Document-excerpt retrieval + tunable budget (D-020, 2026-09-04):**
  artifacts are chunked + embedded; packs surface top-relevant passages as
  cited `doc_excerpt` items (RAG over the docs behind an entity's facts);
  `LOOMCTX_MAX_BUDGET` makes the budget ceiling operator-tunable.
- ✅ doc_excerpt expansion handles pull the surrounding passages (2026-09-08).
- ✅ ANN vector index (2026-09-08, D-025): sqlite-vec / pgvector tables
  derived from the portable JSON vectors, exact scan as fallback; excerpt
  retrieval uses it and `GET /v1/entities/semantic` / MCP `find_related`
  find entities by meaning.

## Phase 5 — Hardening & spread ✅ (2026-09-11; review-fix batch 2026-09-23)

- ✅ **Review batch (2026-09-08, D-021…D-024):** the full verified issue
  list with status is `docs/hardening.md` — all items landed except two
  documented won't-fixes. Includes `valid_at` (fact-time reads), MCP auth
  on the HTTP transports, non-root containers, and the hardened worker.
- ✅ **Postgres `GraphStore` (D-011, 2026-09-03):** selected by
  `LOOMCTX_DB=postgresql://...`, behaviorally identical to SQLite (shared
  contract tests run against both; CI includes a live-Postgres pass).
  Singular SQLite lane tuned (WAL, NORMAL sync, batched transactions) and
  measured with the new `loomctx.loadgen` tool: ~507/s SQLite, ~454/s
  Postgres, ~515/s scale-shape intake — all 0 errors, loadgen-bound.
- ✅ TypeScript SDK generated from the JSON Schema (2026-09-08, D-026),
  built and live-tested in CI via the compose `sdk` profile.
- Not planned unless demand appears: a Neo4j backend (a possible
  `GraphStore` implementation, nothing shipped).
- ✅ Review-fix batch (2026-09-23): `requirements.lock` consumed by the
  Dockerfile, every base image pinned by digest, SHA-pinned actions with
  Dependabot, Trivy on both images before publish, build-once CI (the
  tested candidate is the published image), container security contexts +
  default-deny NetworkPolicies + PodDisruptionBudgets in every shape,
  registry validation on the NATS and Kafka write paths, Kafka SASL/TLS,
  dead-letter headers without row data, atomic 0600 keys file.
- ✅ Design follow-ups (2026-09-24, D-050…D-056): recorded supersession
  and PROV-O export, honest budget + hybrid ranking + value-per-token
  packing, retrieval scorecard, schema v6 (incremental worker ticks,
  per-entity gather limits, SQLite WAL readers), MCP 2026-07-28
  alignment, engine-side rate limiting, STIX 2.1 / OCSF connectors.
- ~~Scale-shape ingestion tier~~ **✅ built 2026-09-03 (pulled forward by the
  user), D-010:** Go ingest gateway validating against
  `contracts/schemas.json` (go tests run in the image build), nginx-balanced
  compose `scale` profile (lb on :8081) + k8s `scale` overlay (gateway HPA,
  NATS, consumer sidecar), NATS JetStream buffer, Python writer consumer,
  SQLite WAL mode for cross-process sharing. Rehearsed live end-to-end:
  3 gateways → queue → consumer → `/v1/ask`. CI checks contract sync and
  publishes `ghcr.io/seahop/loomctx-gateway`.
- ✅ Load test on real nodes (2026-09-10/11, D-043 and D-045): GKE
  `scale-pg-ha`, 421/s corpus load with live workers, 202/s single-envelope
  ingest, 186/s ask, two primary failovers; the laptop table in
  `deploy/README.md` is kept as the relative baseline (D-001a).

## Phase 6 — Enterprise scale ✅ (D-027…D-033, 2026-09-08)

Infra-side dials for large organizations: more database nodes, HA
ingestion, tenant isolation of capacity. Contract unchanged throughout.

- ✅ 6.1 Engine concurrency (2026-09-08, D-028): connection pool,
  `LOOMCTX_DB_READ` read replica, `LOOMCTX_WORKERS`; measured (see D-028)
- ✅ 6.2 Ingestion HA (2026-09-08, D-029): 3-node JetStream cluster in
  `scale-pg`, stream replicas/limits/discard dials, bounded redelivery,
  dead-letter stream; leader-loss chaos test passed on the cluster
- ✅ 6.3 Database HA (2026-09-08, D-030): `scale-pg-ha` overlay with a
  CloudNativePG 3-instance cluster, engine reads on replicas; primary
  deleted under load with zero failed requests
- ✅ 6.4 Worker fleet (2026-09-08, D-031): leased extraction/chunking/
  dossier work, sharded embedding backlog, `loomctx-enrich` StatefulSet
- ✅ 6.5 Tenant sharding (2026-09-08, D-032): `LOOMCTX_SHARDS` →
  `ShardedStore`; the contract suite runs a two-shard lane
- ✅ 6.6 Artifact offload (2026-09-08, D-033): `LOOMCTX_BLOB_THRESHOLD` +
  `LOOMCTX_BLOB_DIR` / `LOOMCTX_BLOB_S3_BUCKET`, reinflated on every read
- ✅ 6.7 Capacity evidence (2026-09-08): `deploy/k8s/jobs/loadgen.yaml`;
  measured table in `deploy/README.md` (laptop floors; re-run on real
  nodes before the conference quote)

## Phase 7 — Pipeline integrations ✅ (D-034, 2026-09-08)

- ✅ `POST /v1/ingest/batch` (engine + gateway), per-item outcomes
- ✅ `contracts/openapi.json` drift-checked; Java + C# generation in CI
- ✅ Go SDK with a contract-drift test, live-tested in CI
- ✅ `python -m loomctx.ingest` bulk loader (HTTP batches or direct to store)
- ✅ Vector + Fluent Bit configs, live-validated (`deploy/integrations/`)
- ✅ Kafka/Redpanda consumer with retry + dead-letter, live-validated
- ⬜ On request: hand-written Rust client; webhook adapters beyond the
  shipper transform stage

## Phase 8 — Real data ✅ (D-035, 2026-09-08)

- ✅ `python -m loomctx.connectors.vulns` — CISA KEV + NVD 2.0 + FIRST EPSS,
  streamed, cached with conditional GETs, idempotent, history-preserving
- ✅ Schema registration for the namespace; seed-host bridge for the two-hop
  demo question; nightly CronJob (`deploy/k8s/jobs/vulns-refresh.yaml`)
- ✅ First run against the seeded store, findings recorded honestly in
  `docs/real-data.md`; the six core fixes it forced are listed under D-035
  (read-path namespace scan, quadratic conflicts, handle cap +
  `omitted_handles`, inbound handle aggregation, conflict budget share,
  path-carrying scope facts)
- ✅ Scope expansion over hubs is no longer silent (D-038, 2026-09-09):
  `ContextPack.truncated` reports gathered/total per capped entity, the
  MCP view warns, the answer prompt says so — the confident-negative
  failure mode from the scorecard has a fact to trip over
- ✅ Entity resolution tier 3 (D-042, 2026-09-10): structural alias
  candidates for `vendor:product` keys, LLM-adjudicated; 58 merges on the
  corpus, KEV CVEs reachable from web-01 3 → 29
- ✅ Adjudication declines persist in the store (D-044, schema v4)
- ✅ CloudNativePG failover timing (2026-09-11): the 190 s was the probe
  hanging in TCP, not the operator — true outage 11 s with defaults,
  measured through the engine; LoomCtx's pool gained `connect_timeout` and
  keepalives so clients fail over with the database
- ✅ Dossier candidates ranked by richness (distinct predicates × sources),
  single-predicate firehoses excluded (D-044)
- ✅ Extraction adopts a registered type when the key already exists under
  one; strict registries drop the rest (D-044)
- ✅ Embed the KEV documents (D-039, 2026-09-09): the enrichment worker
  run over the real corpus with an embedding provider; KEV advisories
  surface as attributed `doc_excerpt` items and via `find_related`
- ✅ Agent end-to-end evaluation (D-036, 2026-09-09): `python -m
  loomctx.agent_eval` — real model, real MCP transport, real corpus, ground
  truth from the store; the first live run forced `list_namespaces` /
  `describe_namespace`, the empty-namespace error, `LOOMCTX_MCP_NAMESPACE`
- ✅ Model scorecard (D-037, 2026-09-09): `--models` mode with billed cost;
  eighteen OpenRouter models across price tiers, three runs each (216
  task-runs, nine models clean at 12/12) — `docs/models.md`
- ✅ Documents on real data (D-039, 2026-09-09): claims cite documents by
  event id, KEV advisories embedded and surfacing as attributed excerpts,
  packed vector storage, worker robustness, query-embedding fallback
- ✅ `find_related` over document passages as well as facts (D-040,
  2026-09-09): a passage maps back to the entities whose claims cite it
- ✅ Second connector (2026-09-25, D-065): raw LDAP / LDIF → object-level
  Active Directory reachability (`member_of` / `has_ace` / `trusts` /
  delegation / GPO), keyed by objectSid, with a hand-rolled SD/ACE parser.
  Decodes directory facts as cited, time-stamped claims — NOT BloodHound (no
  transitive effective-admin, no path ranking; nesting is the walk's job).
  Object-level only: sessions / local-admin need host collection. GitHub
  issues/PRs is still the obvious non-security third one.
- ✅ AD reachability capability benchmark (2026-09-26, D-066): a synthetic
  directory generator (`loomctx.connectors.ad_gen`, deterministic by seed,
  small/medium/large) plants known 2/3/4-hop membership → ACL → trust chains
  and decoy dead-ends (non-transitive / SID-filtered trust, disabled account)
  in dense benign noise; `loomctx.ad_eval` scores whether the scope walk
  surfaces the full **cited** chain (scripted reader, no LLM). Medium run:
  100% path-recall + decoy-exclusion, ~2.5% of the store gathered per chain
  ([docs/ad-eval.md](ad-eval.md)). AD analogue of the KEV retrieval
  benchmark; no core/contract/store change.
- ✅ Scan inventory (2026-09-26, D-068): nmap `-oX` reports →
  `runs_software`/`runs_service`/`runs_os` claims that fuse with the vuln
  graph's `product` node, so a scanned host reaches its KEV CVEs via the
  scope walk / `find_path`. Inventory only; genuine nmap fixtures + a blind
  fusion test. (nmap-vs-NVD vendor-key mismatch left to D-042.)
- ✅ OSV / GHSA advisory connector (2026-09-26, D-070): parses OSV-schema
  JSON (GHSA / PyPI / Go / npm feeds) into cited claims, keying a CVE-aliased
  advisory to the SHARED `cve:` node so an OSV CVSS score conflicts with NVD's
  on one entity (D-035), and affected software to a new `package:<ecosystem>:<name>`
  entity (NOT a CPE — the package↔product seam stays for D-042). CVSS v3/v2
  base scores computed from the vector; genuine osv.dev fixtures (Log4Shell +
  the eslint-scope malware advisory) + a fusion test asserting the cited
  cross-source conflict.
- ✅ OCSF detections (2026-09-26, D-071): the OCSF connector also ingests
  detection/security/incident findings as a cited `finding` graph tied to the
  host and CVE, with status-transition supersession (Suppressed != Resolved).
- ✅ Cloud inventory / config (2026-09-26, D-072): terraform state / AWS Config
  snapshots -> resource/vpc/subnet/security_group claims with containment
  edges; drift over snapshots is history.
- ✅ MITRE ATT&CK taxonomy (2026-09-26, D-073): the published ATT&CK STIX
  bundle -> a cited technique/tactic/group/software/mitigation catalog
  (`in_tactic`/`uses`/`mitigates`), catalog-level only.
- ✅ LDAP connector deep fix (2026-09-26, D-074): mapped GenericWrite
  (0x20028) detection, content-addressed event ids (no collision), inherit-
  only ACE filtering, bidirectional trusts emit both edges, O(1) SID lookup.
  Removed from experimental status.
- ✅ Entra ID connector (2026-09-26, D-075): Microsoft Graph API JSON →
  identity/RBAC claims in `iam` namespace — users, groups, service
  principals, app registrations, directory roles, role/app-role/OAuth2
  assignments, credential expiry, privileged-role tagging. Scope walk +
  find_path tested.
- ✅ Identity connectors at scale (2026-09-26, D-077): `loomctx.connectors.iam_gen` + `loomctx.iam_eval`; GKE numbers in deploy/README.md.
- ✅ Okta connector (2026-09-26, D-076): Okta API JSON → identity claims in
  the same `iam` namespace — users, groups, apps, app-user assignments, MFA
  factors, admin roles. Both IdPs share predicates for cross-provider entity
  resolution.
- ✅ Coverage (2026-09-27, D-082): connectors record what each export
  carried; asks and find_path say when they walk an uncollected predicate.
- ✅ Identity across tools (2026-09-27, D-083): identifier edges from every
  connector, a shared-identifier resolution tier, IPs as time-stamped links;
  one namespace per environment (`netsec` default) with merging registration.
- ✅ Host artifacts (2026-09-27, D-084): `loomctx.connectors.endpoint` —
  processes and file listings from osquery, tasklist, PowerShell, ps, ls,
  sha256sum, CSV.
- ✅ Format drift (2026-09-27, D-085): import shapes compared import to
  import; `python -m loomctx.coverage drift`.
- ✅ Purple correlation (2026-09-27, D-086): `loomctx.connectors.oplog`
  (Atomic, Attire, CSV/JSON), OCSF `indicates technique`, `python -m
  loomctx.purple` / MCP `purple_report`; `loomctx.estate_eval` checks all four on
  a synthetic estate (GKE numbers in deploy/README.md).
- ✅ `path` answer type (2026-09-26, D-067): `POST /v1/path`, MCP
  `find_path`, SDK `path()` return the cited, time-scoped edge sequence(s)
  connecting two entities along named predicates — the reachability chain
  directly, not reassembled from a pack. Additive contract
  (`PathRequest`/`PathPack`); a bounded shortest-first BFS reusing the scope
  walk, honest about hub limits via `truncated`.

## Phase 9 — After the talk (in progress on `scale-xl`, 2026-10-13)

Done on the branch: item 0 measured (D-104), item 2 list mode (D-107), item
3 named queries (D-108), item 4 schema drafting (D-106), bulk import
(D-105), selective walks (D-109), compound questions and not-collected
declarations (D-110), SQL-ranked filters (D-111), search retries (D-112), a
first harder audit tier (D-113). Open: the next fresh 10k/500k run on these;
items 1, 5, 6; the rest of item 7.

Scale and the known weaknesses, each with a design, files to touch and a
done-when test: **`docs/future-work.md`**. In order: measure a 500k-object
directory; then precompute transitive membership and add a list mode for
large answer sets if the numbers call for it; named queries in the
registry; a schema-drafting helper; an entity-resolution review queue;
optional theme summaries over documents.

## Deployment & CI (2026-09-03)

- ✅ Local: `docker compose up loomctx`; tests: `docker compose run --rm test`
- ✅ Kubernetes: `kubectl apply -k deploy/k8s` (single replica + PVC by
  design), `deploy/k8s/scale` (autoscaled gateways + queue), and
  `deploy/k8s/scale-pg` (Postgres-backed, every tier autoscales — gateway
  HPA 2–10, engine HPA 2–8, consumer replicas). Manifests restructured to
  base/ + overlays; all three validated with `kustomize build`. Autoscaling
  matrix in `deploy/README.md`.
- ✅ GitHub Actions: tests on every push/PR; image published to
  `ghcr.io/seahop/loomctx` (`latest` + SHA) on `main`
- ✅ Validated on a real cluster (2026-09-08, Rancher Desktop k3s): default,
  scale, and scale-pg shapes rolled out from the shipped manifests; ingest
  through gateway → NATS → consumers → store, reads from engine replicas,
  HPAs live, non-root pods on local-path PVCs. Details in `deploy/README.md`.

## Definition of "pick-up ready"

Resume by reading: `README.md` → `docs/architecture.md` → this file (status)
→ `docs/decisions.md` (constraints). Code entry:
`src/loomctx/contracts.py` → `store/sqlite.py` → `context.py` → `api/http.py`.
Verify from clean checkout: `docker compose run --rm test` (about 730 test functions; the store contract suite runs in three lanes — SQLite, live Postgres, and a two-shard `ShardedStore` — and the Go/TypeScript SDKs run live against the engine in CI).
Demo rehearsal: `docker compose up -d loomctx && docker compose exec loomctx
python -m loomctx.seed load`, then hit `/v1/ask`.
