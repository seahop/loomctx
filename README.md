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

## Who it's for

Security teams on **both sides of the line**. Loom is neutral about the data it
holds — the value is in how each operator shapes information *out* of it:

- **Blue teams** ask *what happened, is it patched, what's exposed* — served by
  provenance, conflict-surfacing across sources, and bitemporal "what did we
  know, and when."
- **Red teams** ask *what's exploitable, what can I reach from here, what do we
  know about this target* — served by scopes and relationship traversal that
  assemble an entity and everything connected to it into one budgeted pack.

Same store, same engine; the question determines the answer. The bundled demo
is network telemetry; the [tutorial](docs/tutorial.md) builds a vulnerability-
management domain — swap in cloud posture, identities, EDR events, or recon
findings without touching Loom's code.

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
| `docs/quickstart.md` | 5-minute run: seeded demo, a cited pack, an answer |
| `docs/tutorial.md` | 30-minute build of your own security domain, end to end |
| `examples/` | Runnable sender + agent-query scripts (stdlib only) |
| `docs/architecture.md` | Full system design: layers, write/read paths, retrieval contract |
| `docs/contracts.md` | The data contracts (the real API of the framework) |
| `docs/concepts.md` | Glossary — precise definitions of every term of art |
| `docs/decisions.md` | Language/tech choices with rationale, and the constraints we hold |
| `docs/administration.md` | Running it for a team: users, scopes, rotation, retention |
| `docs/roadmap.md` | Phased execution plan with current status |
| `docs/sdk.md` | How consumers tap in: MCP, HTTP (+ batch ingest), Python / TypeScript / Go SDKs, OpenAPI for everything else, bulk loader |
| `docs/infrastructure.md` | Detailed diagrams: the one-container shape, the fully scaled shape, the read and write flows |
| `src/loom/` | The engine: contracts, store, context-pack builder, HTTP API, workers, seed data |
| `sdk/python/`, `sdk/typescript/`, `sdk/go/` | Thin client SDKs; TypeScript/Go types are generated from or validated against `contracts/` |
| `contracts/` | `schemas.json` (JSON Schema) and `openapi.json`, both regenerated and drift-checked in CI |
| `deploy/` | Kubernetes shapes (default, scale, scale-pg, scale-pg-ha), `integrations/` (Fluent Bit, Vector, Kafka), deployment guide |
| `tests/` | Contract, store, context-pack, seed, and API tests |

## Documentation

New here? **[docs/quickstart.md](docs/quickstart.md)** (5 min) → then
**[docs/tutorial.md](docs/tutorial.md)** builds your own security domain from
scratch. Full index: **[docs/README.md](docs/README.md)**.

## Quickstart (Docker only — nothing installs on the host)

```bash
# Run the test suite
docker compose run --rm test

# Start the engine (HTTP API on :8000) and load the demo dataset
docker compose up -d loom
docker compose exec loom python -m loom.seed load   # ~580 claims + 5 documents

# Ask a focused, budgeted question about an entity
curl -s -X POST localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace": "netsec",
  "subject": {"type": "ip", "key": "10.0.4.7"},
  "question": "which host was assigned this ip?",
  "budget": 600
}'
```

That last call answers with the IP's full lease timeline — it belonged to
`web-01` until 2026-08-10, then `laptop-17` — each fact cited to `dhcp-log`.
Ask about `host web-01`'s OS instead and the pack *leads with a conflict item*
(two sources disagree), plus expansion handles like
`"69 more 'logged_in_by' observations"` that agents pass to `/v1/expand` to
pull one thread deeper. Ingestion is `POST /v1/ingest` with a `claim` or
`document` envelope, or `POST /v1/ingest/batch` for many at once — which is
what log shippers (Fluent Bit, Vector), the bulk loader, and the Kafka
consumer use to tie existing pipelines in (see `docs/contracts.md` and
`deploy/integrations/`).

To enable the answering LLM (`/v1/answer`, MCP `answer`) locally, copy
`.env.example` to `.env`, fill in a provider key (OpenRouter, Venice,
Anthropic, or a self-hosted base URL), and restart — compose picks it up
automatically. The gitignored `.env` never reaches the repo or the images.
With it filled in, the real-provider e2e test activates:
`docker compose run --rm test pytest -q tests/test_e2e_answer.py`.

Deploying beyond a laptop: `kubectl apply -k deploy/k8s`, or the **scale
shape** — a load-balanced tier of Go ingest gateways feeding a NATS buffer
(`docker compose --profile scale up -d --build --scale gateway=3`, ingest on
:8081) — see [deploy/README.md](deploy/README.md).

## Governance

- **License:** Apache-2.0.
- **Auth:** real API keys via `python -m loom.keys generate` — hashed at
  rest, hot-rotated, and scoped per key: namespaces, read/write (senders get
  write-only keys), entity-type allowlists (an operator's agent sees only
  that user's slice of the world — the query/LLM surface itself is never
  gated), source pinning for writers, expiry. Enforced identically by the
  engine and the ingest gateway, with per-key rate limits and cheapest-first
  rejection of bad traffic. Unset = open dev mode.
- **Idempotency:** send an `event_id` with any envelope and retries/redelivery
  can never duplicate a fact.
- **Operability:** Prometheus `/metrics` on engine and gateway; `/readyz`
  probes the store.
- **Lifecycle:** `python -m loom.lifecycle` — JSONL export/import (backup and
  SQLite⇄Postgres migration), retention purge, tombstone redaction.
- **Quality:** a retrieval scorecard runs in CI (`tests/test_quality.py`), so
  ranking changes ship with evidence.

## Status

Phases 0–4 working: contracts, SQLite/Postgres stores, claim + document
ingestion (with an autoscaling Go gateway tier), context packs with scopes
(`/v1/ask`, `/v1/expand`), provider-flexible answering (`/v1/answer`), an
MCP server for agents, and async enrichment (`python -m loom.enrich`:
semantic embeddings, document claim extraction with span provenance, rolling
dossiers, and entity resolution that folds extracted entities into their
structured counterparts). Deterministic seed corpus, k8s shapes, CI.
See `docs/roadmap.md` for the milestone plan (conference: end of October 2026).

Agents connect natively over MCP:

```bash
claude mcp add loom -- docker compose --project-directory "$PWD" run --rm -T loom python -m loom.mcp_server
```
