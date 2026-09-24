# Loom

**A context engine for AI agents.** Loom absorbs pieces of data about entities as they
arrive over time — structured events *and* unstructured documents — and hands agents
small, question-scoped, token-budgeted slices of that knowledge instead of raw dumps.

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

Built for security teams on both sides of the line: blue teams ask *what
happened, is it patched, what's exposed* (provenance, cross-source conflicts,
bitemporal reads); red teams ask *what's exploitable and reachable from
here* (scopes and relationship traversal into one budgeted pack). Same
store, same engine — the bundled demo is network telemetry and the
[tutorial](docs/tutorial.md) builds a vulnerability-management domain
without touching Loom's code.

## How it differs

| Instead of | What you get there | With Loom |
| --- | --- | --- |
| A vector DB / RAG pipeline | the top-k chunks by similarity; no notion of *when* a fact held, *who* asserted it, or that two sources disagree | append-only, bitemporal observations; conflicts between sources are the first item in the pack; every item cites the observation ids behind it |
| Postgres + SQL | exact answers to questions you already know how to phrase; the agent writes a query and gets however many rows come back | a mandatory token budget on every read, ranked slices, expansion handles for what was cut, and `truncated` when the engine did not look at everything |
| A graph database | traversal power, but the agent talks to the graph and gets whatever the query returns | the graph is the index, not the payload: the agent gets a question-scoped pack, and a multi-hop question is one `ask_scope` call |
| SIEM search | fast search over events; entities are a pivot, not a memory | entity-centric memory across sources with provenance, conflict detection and time travel built into every read |
| "Give the agent the database" | full access, a context window full of rows, and no record of what the model actually saw | per-key data scoping, budgets, handles, and per-item citations — measured 216 of 216 task-runs across eighteen models with no invented citation (`docs/models.md`) |

## Repository layout

| Path | What it is |
| --- | --- |
| `docs/quickstart.md` | 5-minute run: seeded demo, a cited pack, an answer |
| `docs/tutorial.md` | 30-minute build of your own security domain, end to end |
| `docs/demo.md` | The conference demo script: night-before prep, three acts, fallbacks, rehearsal checklist |
| `examples/` | Runnable sender + agent-query scripts (stdlib only) |
| `demo/` | Saved agent transcripts (Claude Code over MCP, `agent_eval`) rendered as fallback pages, and an MCP config |
| `docs/architecture.md` | Full system design: layers, write/read paths, retrieval contract |
| `docs/contracts.md` | The data contracts (the real API of the framework) |
| `docs/concepts.md` | Glossary — precise definitions of every term of art |
| `docs/decisions.md` | Language/tech choices with rationale, and the constraints we hold |
| `docs/hardening.md` | The verified issue list from the 2026-09-08 review, with status |
| `docs/administration.md` | Running it for a team: users, scopes, rotation, retention |
| `docs/roadmap.md` | Phased execution plan with current status |
| `docs/sdk.md` | How consumers tap in: MCP, HTTP (+ batch ingest), Python / TypeScript / Go SDKs, OpenAPI for everything else, bulk loader |
| `docs/infrastructure.md` | Detailed diagrams: the one-container shape, the fully scaled shape, the read and write flows |
| `docs/real-data.md` | Loading real public data (vulnerability feeds) and what the first run showed |
| `docs/models.md` | Which LLMs drive Loom well as agents: measured scorecard with cost, and how to re-run it |
| `src/loom/` | The engine: contracts, store, context-pack builder, HTTP API, workers, seed data, `connectors/` (real public data) |
| `gateway/` | The Go ingest gateway for the scale shape: validates against `contracts/schemas.json`, forwards to NATS JetStream |
| `sdk/python/`, `sdk/typescript/`, `sdk/go/` | Thin client SDKs; TypeScript/Go types are generated from or validated against `contracts/` |
| `contracts/` | `schemas.json` (JSON Schema) and `openapi.json`, both regenerated and drift-checked in CI |
| `deploy/` | Kubernetes shapes (default, scale, scale-pg, scale-pg-ha), `integrations/` (Fluent Bit, Vector, Kafka), deployment guide |
| `scripts/` | `smoke-scale.sh` (the scale shape end to end, run in CI), `lock-deps.sh` (regenerate the dependency lock), `verify.sh` |
| `tests/` | Contract, store, context-pack, seed, connector, consumer, and API tests |

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
docker compose exec loom python -m loom.seed load   # 592 claims + 5 documents
# Optional: real data next to it — CISA KEV + NVD + EPSS (docs/real-data.md)
docker compose exec loom python -m loom.connectors.vulns load --db /data/loom.db --bridge-seed-hosts

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
Ask about `host web-01`'s OS instead (budget 400) and the pack *leads with a
conflict item* (two sources disagree), plus expansion handles like
`"67 more 'logged_in_by' observations"` that agents pass to `/v1/expand` to
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

Ports bind to localhost by default; set `LOOM_BIND=0.0.0.0` in `.env`
(and mount keys first) to reach the engine from the LAN.

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

## Limitations

Known and deliberate, as of `v0.1.0`; the open list is `docs/hardening.md`.

- **Ranking without an embedder is keyword overlap.** Set `LOOM_EMBED_*` for
  semantic ranking, document excerpts and `find_related`; without it the
  engine still works, but "operating system" does not match `runs_os`.
- **Gather cap.** A read collects at most 1,000 observations per entity;
  when a subject has more, the pack says so in `truncated` (gathered/total)
  and the handles reach the rest. A hub entity is never silently sampled.
- **Alias resolution costs money.** Structural aliases (`linux:kernel` vs
  `linux:linux_kernel`) are adjudicated by an LLM, one call per candidate
  (~3 cents on the vulnerability corpus with a flash-class judge); the
  merge set depends on the judge.
- **Extracted claims are second-class.** Facts mined from documents rank
  below sender-asserted ones and cannot corroborate or contradict a
  structured source on their own — a hostile document cannot manufacture a
  conflict.
- **No per-entity ACLs, admin API, or SSO.** Access is a keys file with
  namespace / entity-type / source gates, hot-reloaded; rotation is a CLI
  and a Secret update, not a console.
- **Handles are capped at 32 per pack** (`omitted_handles` says how many
  more there were).
- **A confident "no" is uncatchable by citations.** Every positive claim in
  an answer can be checked against an observation id; an absence cannot.
  `truncated` is the only signal, and the agent has to read it.

## Status

`v0.1.0` (2026-09-09, `CHANGELOG.md`). Working end to end: contracts,
SQLite/Postgres stores, claim + document ingestion (single, batch, Go
gateway, Kafka, shippers), context packs with scopes, relation chains and
coverage reporting (`/v1/ask`, `/v1/expand`), provider-flexible answering
(`/v1/answer`), an MCP server for agents, async enrichment, opt-in
Kubernetes scale shapes, and SDKs. Validated on real data (CISA KEV, NVD,
EPSS — `docs/real-data.md`) and with eighteen LLM agents over MCP
(`docs/models.md`). Measured (laptop, generator co-located): 511k
envelopes loaded in 81 s to SQLite, single-entity ask 2–5 ms at 465k
observations, two-hop scope over 1,077 entities in 0.5 s; on GKE with
real nodes 421/s load, 202/s ingest, 186/s ask (`deploy/README.md`).
Demo script: `docs/demo.md`. Milestones: `docs/roadmap.md` (conference:
mid-October 2026).

Agents connect natively over MCP:

```bash
claude mcp add loom -- docker compose --project-directory "$PWD" run --rm -T loom python -m loom.mcp_server
```
