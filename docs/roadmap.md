# Roadmap & status

Status legend: ✅ done · 🔨 partial · ⬜ not started

**Fixed date: conference demo + presentation at the end of October 2026.**
The repo is public on GitHub; everything merged to `main` should be
presentable.

## Milestones to the conference

| When | Milestone |
| --- | --- |
| early Sep (done 2026-09-03) | Phases 0–2 working: contracts, store, ingestion (claims + documents), context packs, seed data, k8s manifests, CI |
| mid Sep (done 2026-09-04) | Phase 3: MCP server — agents plug in natively (the demo's wow moment) |
| late Sep (done 2026-09-04) | Phase 4 core: embeddings + claim extraction from documents + first dossiers |
| early Sep (done 2026-09-08) | Hardening batch from the full review — `docs/hardening.md` (D-021…D-024) |
| early Oct | Demo hardening: scripted walkthrough, k8s run validated on a real cluster, polish README for public visitors |
| mid Oct | Freeze features; rehearse demo; presentation materials; buffer |
| end Oct | **Conference** |

## Phase 0 — Contracts ✅ (2026-09-03)

- ✅ `src/loom/contracts.py`: envelope (claim | document), Observation, Entity,
  Artifact, ContextPack/Items/Citations/Handles, AskRequest/ExpandRequest,
  schema registry shapes. JSON Schema export: `python -m loom.schemas`.

## Phase 1 — Core store + ingestion ✅ (2026-09-03)

- ✅ `GraphStore` protocol + SQLite implementation (entities, append-only
  observations, edges queryable from both ends, artifacts, namespaces)
- ✅ HTTP: `/healthz`, `POST /v1/ingest` (claims → 200 recorded; documents →
  202 accepted, artifact stored verbatim, extraction pending),
  `GET /v1/entities/{type}/{key}/observations`, `GET /v1/artifacts/{id}`
- ✅ Seed corpus: `python -m loom.seed` — ~580 deterministic claims + 5
  documents across `netsec` and `procurement`, with planted demo moments
  (IP lease reassignment, two cross-source conflicts, incident report doc)
- ✅ Schema registry persistence + claim validation (2026-09-08, D-024):
  `POST/GET /v1/schemas`, additive per namespace; registered predicates
  enforce object types, `strict` namespaces reject the unregistered;
  `containment` predicates drive default scope expansion

## Phase 2 — Retrieval + context packs ✅ (2026-09-03)

- ✅ `src/loom/context.py`: rank (keyword sim + recency + confidence) → trim
  to mandatory token budget → cite every item → stateless expansion handles →
  cross-source conflict surfacing (single-source value changes are treated as
  time series, not conflicts) → as-of filtering
- ✅ `POST /v1/ask`, `POST /v1/expand`; SDK `ask()`/`expand()` live
- Known v1 limitation: relevance is keyword overlap — "operating system"
  doesn't match `runs_os` facts (the conflict item still surfaces the answer).
  Embedding similarity replaces this scorer in phase 4.

## Phase 2.5 — Scopes + answering LLMs ✅ (2026-09-03, D-012)

- ✅ `ScopeSpec` (multi-subject questions; BFS expansion over containment
  predicates — "domain corp.local and its contents"); merged, deduped,
  per-subject-conflict-checked packs; `GET /v1/entities/search`
- ✅ `loom/llm.py`: OpenAI-compatible client covering OpenRouter, Venice,
  Groq, Together, Mistral, OpenAI, Ollama/vLLM/LM Studio (custom base URL),
  plus native Anthropic; configured by four `LOOM_LLM_*` env vars
- ✅ `POST /v1/answer`: retrieval-grounded, citation-required LLM answers;
  auto-resolves entities named in the question; returns the pack for audit
- ✅ Live end-to-end run against a real provider (2026-09-04, OpenRouter /
  deepseek-chat-v3.1 via `.env`): auto-resolved 3 entities from the incident
  question, 63-item merged pack, cited answer that correctly traced the
  10.0.4.7 lease reassignment and flagged the OS conflict unresolved.
  Repeatable via `tests/test_e2e_answer.py` (skips without `.env`).

## Phase 3 — MCP server ✅ (2026-09-04)

- ✅ `src/loom/mcp_server.py` on MCP SDK v2 (`MCPServer`): `find_entity`,
  `ask`, `ask_scope`, `expand`, `record_claim`, `get_observations`,
  `answer` — same core functions as HTTP, `type:key` handles, server
  instructions teaching the find → ask small → expand → write-back loop.
- ✅ stdio for local agents (`claude mcp add loom -- docker compose run --rm
  -T loom python -m loom.mcp_server`) and streamable HTTP via compose
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

- ✅ `python -m loom.enrich` worker (compose profile `enrich` / `--once` Job)
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
  `LOOM_MAX_BUDGET` makes the budget ceiling operator-tunable.
- ✅ doc_excerpt expansion handles pull the surrounding passages (2026-09-08).
- ✅ ANN vector index (2026-09-08, D-025): sqlite-vec / pgvector tables
  derived from the portable JSON vectors, exact scan as fallback; excerpt
  retrieval uses it and `GET /v1/entities/semantic` / MCP `find_related`
  find entities by meaning.

## Phase 5 — Hardening & spread 🔨

- ✅ **Review batch (2026-09-08, D-021…D-024):** the full verified issue
  list with status is `docs/hardening.md` — all items landed except two
  documented won't-fixes. Includes `valid_at` (fact-time reads), MCP auth
  on the HTTP transports, non-root containers, and the hardened worker.
- ✅ **Postgres `GraphStore` (D-011, 2026-09-03):** selected by
  `LOOM_DB=postgresql://...`, behaviorally identical to SQLite (shared
  contract tests run against both; CI includes a live-Postgres pass).
  Singular SQLite lane tuned (WAL, NORMAL sync, batched transactions) and
  measured with the new `loom.loadgen` tool: ~507/s SQLite, ~454/s
  Postgres, ~515/s scale-shape intake — all 0 errors, loadgen-bound.
- ✅ TypeScript SDK generated from the JSON Schema (2026-09-08, D-026),
  built and live-tested in CI via the compose `sdk` profile.
- Remaining: Neo4j backend if graph-native traversal demand appears.
- ~~Scale-shape ingestion tier~~ **✅ built 2026-09-03 (pulled forward by the
  user), D-010:** Go ingest gateway validating against
  `contracts/schemas.json` (go tests run in the image build), nginx-balanced
  compose `scale` profile (lb on :8081) + k8s `scale` overlay (gateway HPA,
  NATS, consumer sidecar), NATS JetStream buffer, Python writer consumer,
  SQLite WAL mode for cross-process sharing. Rehearsed live end-to-end:
  3 gateways → queue → consumer → `/v1/ask`. CI checks contract sync and
  publishes `ghcr.io/seahop/loom-gateway`.
- 🔨 Load test before the conference (early-Oct milestone): laptop numbers
  are in `deploy/README.md`; re-run the loadgen Job on real nodes for the
  quoted figures (D-001a).

## Phase 6 — Enterprise scale ✅ (D-027…D-033, 2026-09-08)

Infra-side dials for large organizations: more database nodes, HA
ingestion, tenant isolation of capacity. Contract unchanged throughout.

- ✅ 6.1 Engine concurrency (2026-09-08, D-028): connection pool,
  `LOOM_DB_READ` read replica, `LOOM_WORKERS`; measured (see D-028)
- ✅ 6.2 Ingestion HA (2026-09-08, D-029): 3-node JetStream cluster in
  `scale-pg`, stream replicas/limits/discard dials, bounded redelivery,
  dead-letter stream; leader-loss chaos test passed on the cluster
- ✅ 6.3 Database HA (2026-09-08, D-030): `scale-pg-ha` overlay with a
  CloudNativePG 3-instance cluster, engine reads on replicas; primary
  deleted under load with zero failed requests
- ✅ 6.4 Worker fleet (2026-09-08, D-031): leased extraction/chunking/
  dossier work, sharded embedding backlog, `loom-enrich` StatefulSet
- ✅ 6.5 Tenant sharding (2026-09-08, D-032): `LOOM_SHARDS` →
  `ShardedStore`; the contract suite runs a two-shard lane
- ✅ 6.6 Artifact offload (2026-09-08, D-033): `LOOM_BLOB_THRESHOLD` +
  `LOOM_BLOB_DIR` / `LOOM_BLOB_S3_BUCKET`, reinflated on every read
- ✅ 6.7 Capacity evidence (2026-09-08): `deploy/k8s/jobs/loadgen.yaml`;
  measured table in `deploy/README.md` (laptop floors; re-run on real
  nodes before the conference quote)

## Deployment & CI (2026-09-03)

- ✅ Local: `docker compose up loom`; tests: `docker compose run --rm test`
- ✅ Kubernetes: `kubectl apply -k deploy/k8s` (single replica + PVC by
  design), `deploy/k8s/scale` (autoscaled gateways + queue), and
  `deploy/k8s/scale-pg` (Postgres-backed, every tier autoscales — gateway
  HPA 2–10, engine HPA 2–8, consumer replicas). Manifests restructured to
  base/ + overlays; all three validated with `kustomize build`. Autoscaling
  matrix in `deploy/README.md`.
- ✅ GitHub Actions: tests on every push/PR; image published to
  `ghcr.io/seahop/loom` (`latest` + SHA) on `main`
- ✅ Validated on a real cluster (2026-09-08, Rancher Desktop k3s): default,
  scale, and scale-pg shapes rolled out from the shipped manifests; ingest
  through gateway → NATS → consumers → store, reads from engine replicas,
  HPAs live, non-root pods on local-path PVCs. Details in `deploy/README.md`.

## Definition of "pick-up ready"

Resume by reading: `README.md` → `docs/architecture.md` → this file (status)
→ `docs/decisions.md` (constraints). Code entry:
`src/loom/contracts.py` → `store/sqlite.py` → `context.py` → `api/http.py`.
Verify from clean checkout: `docker compose run --rm test` (the suite is ~110 tests; the store contract tests also run against live Postgres in CI).
Demo rehearsal: `docker compose up -d loom && docker compose exec loom
python -m loom.seed load`, then hit `/v1/ask`.
