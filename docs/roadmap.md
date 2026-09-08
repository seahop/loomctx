# Roadmap & status

Status legend: ✅ done · 🔨 partial · ⬜ not started

**Fixed date: conference demo + presentation at the end of October 2026.**
The repo is public on GitHub; everything merged to `main` should be
presentable.

## Milestones to the conference

| When | Milestone |
| --- | --- |
| early Sep (done 2026-09-03) | Phases 0–2 working: contracts, store, ingestion (claims + documents), context packs, seed data, k8s manifests, CI |
| mid Sep | Phase 3: MCP server — agents plug in natively (the demo's wow moment) |
| late Sep | Phase 4 core: embeddings + claim extraction from documents + first dossiers |
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
- ⬜ Schema registry persistence + claim validation against registered
  predicates (shapes exist; any predicate currently accepted)

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
- ⬜ Exercise from a real agent session end-to-end (part of demo hardening).

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
- ⬜ Deeper resolution: embedding/fuzzy key matching (web-01 vs web01) and
  LLM adjudication for ambiguous cases — exact-key-cross-type covers the
  common extraction drift; typo/alias matching is the next increment.
- ✅ **Document-excerpt retrieval + tunable budget (D-020, 2026-09-04):**
  artifacts are chunked + embedded; packs surface top-relevant passages as
  cited `doc_excerpt` items (RAG over the docs behind an entity's facts);
  `LOOM_MAX_BUDGET` makes the budget ceiling operator-tunable.
- ⬜ Optional: sqlite-vec / pgvector for ANN search once embedded row counts
  outgrow the current exact in-memory cosine (fine at seed/demo scale);
  doc_excerpt expansion handles to pull surrounding chunks.

## Phase 5 — Hardening & spread 🔨

- 🔨 **Review batch (2026-09-08):** the full verified issue list, with
  pre-conference priorities and live status, is in `docs/hardening.md`.
  P1 items there (auth gate bypasses, store rollback/dedupe races,
  uncited briefs, worker resilience, seed idempotency) land first.
- ✅ **Postgres `GraphStore` (D-011, 2026-09-03):** selected by
  `LOOM_DB=postgresql://...`, behaviorally identical to SQLite (shared
  contract tests run against both; CI includes a live-Postgres pass).
  Singular SQLite lane tuned (WAL, NORMAL sync, batched transactions) and
  measured with the new `loom.loadgen` tool: ~507/s SQLite, ~454/s
  Postgres, ~515/s scale-shape intake — all 0 errors, loadgen-bound.
- Remaining: per-namespace API keys; retention policies; TypeScript SDK
  from JSON Schema; Neo4j backend if graph-native traversal demand appears.
- ~~Scale-shape ingestion tier~~ **✅ built 2026-09-03 (pulled forward by the
  user), D-010:** Go ingest gateway validating against
  `contracts/schemas.json` (go tests run in the image build), nginx-balanced
  compose `scale` profile (lb on :8081) + k8s `scale` overlay (gateway HPA,
  NATS, consumer sidecar), NATS JetStream buffer, Python writer consumer,
  SQLite WAL mode for cross-process sharing. Rehearsed live end-to-end:
  3 gateways → queue → consumer → `/v1/ask`. CI checks contract sync and
  publishes `ghcr.io/seahop/loom-gateway`.
- Load test before the conference (early-Oct milestone) so quoted capacity
  numbers are measured, not assumed (D-001a).

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
- ⬜ Validate the k8s manifests on a real cluster before the conference

## Definition of "pick-up ready"

Resume by reading: `README.md` → `docs/architecture.md` → this file (status)
→ `docs/decisions.md` (constraints). Code entry:
`src/loom/contracts.py` → `store/sqlite.py` → `context.py` → `api/http.py`.
Verify from clean checkout: `docker compose run --rm test` (23 tests).
Demo rehearsal: `docker compose up -d loom && docker compose exec loom
python -m loom.seed load`, then hit `/v1/ask`.
