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

## Phase 3 — MCP server ⬜ ← next

- Tools wrapping the core in-process: `find_entity`, `get_brief`, `ask`,
  `expand`, `record_observation`. Same container, compose profile `mcp`.

## Phase 4 — Async enrichment ⬜

- In-process workers (D-004): chunking, embeddings (sqlite-vec) replacing the
  keyword scorer, LLM claim extraction with span provenance
  (artifacts already carry `extraction_status`), dossiers, fuzzy entity
  resolution, provisional-entity merges. `LLMClient` protocol (D-007).

## Phase 5 — Hardening & spread ⬜

- Per-namespace API keys; retention policies; Neo4j/Postgres `GraphStore`
  (the k8s scale-out path, D-008); TypeScript SDK from JSON Schema; real
  queue if volume demands.

## Deployment & CI (2026-09-03)

- ✅ Local: `docker compose up loom`; tests: `docker compose run --rm test`
- ✅ Kubernetes: `kubectl apply -k deploy/k8s` (single replica + PVC by
  design — see `deploy/README.md`)
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
