# Roadmap & status

Phases build strictly on each other; each ends with something runnable in Docker.
Status legend: ✅ done · 🔨 scaffolded (shape exists, partial behavior) · ⬜ not started

## Phase 0 — Contracts (✅ scaffolded 2026-09-03)

The framework's real API: Pydantic models for the ingestion envelope (claim |
document), observations, entities, relations, context packs, expansion handles, and
the schema registry. JSON Schema is exportable from these for non-Python SDKs.

- ✅ `src/loom/contracts.py`
- ✅ Contract round-trip tests (`tests/test_contracts.py`)

## Phase 1 — Core store + claim ingestion (🔨)

- ✅ `GraphStore` protocol (`src/loom/store/base.py`)
- ✅ SQLite implementation: entities, observations, deterministic resolution by
  natural key, alias table (`src/loom/store/sqlite.py`)
- ✅ HTTP skeleton: `/healthz`, `POST /v1/ingest` (claims persist end-to-end),
  `GET /v1/entities/{type}/{key}/observations`
- ⬜ Schema registry persistence + validation of claims against registered predicates
  (currently: any predicate accepted)
- ⬜ Document ingestion: artifact storage (bytes land on the volume, envelope model
  exists; extraction is phase 4)
- ⬜ CLI (`loom ingest`, `loom show`)

## Phase 2 — Retrieval + context packs (⬜) ← the earliest end-to-end useful point

- Context pack builder: gather observations + 1-hop relations for a subject, rank
  (recency + confidence first; semantic similarity when embeddings land), trim to
  token budget, attach citations and expansion handles.
- `POST /v1/ask` (subject, question, budget, as_of) → ContextPack
- `POST /v1/expand` (handle) → ContextPack fragment
- As-of filtering using the bitemporal fields.
- Conflict surfacing (same subject+predicate, overlapping validity, different objects).

## Phase 3 — MCP server (⬜)

- MCP tools wrapping the core service in-process: `find_entity`, `get_brief`, `ask`,
  `expand`, `record_observation`.
- Ships in the same container; enabled via compose profile.
- This is the moment agents plug in with zero glue.

## Phase 4 — Async enrichment (⬜)

- In-process background workers (see D-004): document chunking, embeddings
  (sqlite-vec), LLM claim extraction with span provenance, dossier generation +
  refresh policy, fuzzy entity resolution (aliases → embeddings → LLM adjudication),
  provisional-entity merge flow.
- `LLMClient` protocol + Anthropic default adapter (D-007).

## Phase 5 — Hardening & spread (⬜)

- API keys per namespace; rate limits.
- Retention policies (OQ-5).
- Neo4j `GraphStore` implementation if demand exists; compose profile is sketched.
- TypeScript SDK generated from exported JSON Schema.
- Real queue for enrichment if volume demands (OQ-1).

## Definition of "pick-up ready"

Any future session should be able to resume by reading, in order:
`README.md` → `docs/architecture.md` → `docs/roadmap.md` (this file, for status) →
`docs/decisions.md` (for constraints). Code entry point: `src/loom/contracts.py`,
then `src/loom/store/sqlite.py`, then `src/loom/api/http.py`.

Verification command from a clean checkout: `docker compose run --rm test`.
