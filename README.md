# Loom (working name)

**A context engine for AI agents.** Loom absorbs pieces of data about entities as they
arrive over time — structured events *and* unstructured documents — and hands agents
small, question-scoped, token-budgeted slices of that knowledge instead of raw dumps.

> Working name is provisional. Rename freely; nothing in the docs depends on it emotionally.

## The problem

Teams accumulate facts about things (a host on a network, a user, a vendor, a case)
across many sources and long time spans. When an agent needs to reason about one of
those things, it usually gets either nothing or everything. Loom's job is the middle:
*"what do we know about `web-01` relevant to Tuesday's alert, in under 800 tokens,
with citations."*

## Core ideas (details in `docs/`)

- **Write path is greedy, read path is stingy.** Ingest everything with provenance;
  enrich asynchronously; answer reads from cheap precomputed material within a caller
  supplied token budget.
- **Two front doors, one observation model.** Structured *claims* map directly to
  observations; *documents* are stored as immutable artifacts and mined into
  observations asynchronously. Retrieval never cares where a fact came from.
- **The graph is the index, not the payload.** Agents talk to a retrieval contract
  (context packs + expansion handles), never to the graph directly.
- **Bitemporal from day one.** Every fact carries when it was true and when we learned
  it. "What host had this IP during the incident window?" is a first-class query.
- **Malleable by construction.** Teams register their own entity types and predicates,
  swap storage backends behind an interface, and plug in their own enrichers — without
  forking the core. See `docs/concepts.md`.

## Repository layout

| Path | What it is |
| --- | --- |
| `docs/architecture.md` | Full system design: layers, write/read paths, retrieval contract |
| `docs/contracts.md` | The data contracts (the real API of the framework) |
| `docs/concepts.md` | Glossary — precise definitions of every term of art |
| `docs/decisions.md` | Language/tech choices with rationale, and the constraints we hold |
| `docs/roadmap.md` | Phased execution plan with current status |
| `docs/sdk.md` | How consumers tap in: MCP, HTTP, Python SDK, CLI |
| `src/loom/` | The engine: contracts as code, store interface, SQLite store, HTTP API |
| `sdk/python/` | Thin Python client SDK (mirrors the HTTP/MCP surface) |
| `tests/` | Contract and store tests |

## Quickstart (Docker only — nothing installs on the host)

```bash
# Run the test suite
docker compose run --rm test

# Start the engine (HTTP API on :8000)
docker compose up loom

# Poke it
curl -s localhost:8000/healthz
curl -s -X POST localhost:8000/v1/ingest -H 'content-type: application/json' -d '{
  "kind": "claim",
  "subject": {"type": "host", "key": "web-01"},
  "predicate": "logged_in_by",
  "object": {"type": "user", "key": "jdoe"},
  "observed_at": "2026-09-01T14:03:00Z",
  "source": "auth-log"
}'
curl -s 'localhost:8000/v1/entities/host/web-01/observations'
```

## Status

Phases 0–1 scaffolded (contracts, ingestion of claims, SQLite store, HTTP skeleton).
See `docs/roadmap.md` for what is real, stubbed, and next.
