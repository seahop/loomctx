# Decisions & constraints

Running log of choices with rationale. Newest additions at the bottom. If a decision
is revisited, strike it here and add the replacement — don't rewrite history.

## Hard constraints (hold unless the user says otherwise)

1. **Docker-only builds and runs.** Nothing installs or executes on the host beyond
   `docker compose ...`. Tests, servers, and one-off scripts all run in containers.
   This keeps the host sanitary and is a standing project rule.
2. **Small-resource posture.** Target: large *context*, not big data. One or two
   containers, volume-backed state, runs on a laptop or a $10 VPS. No Kafka, no
   Elasticsearch, no managed-cloud dependencies in the core. Two deployment
   shapes only: local Docker Compose, and the k8s manifests in `deploy/k8s`
   (D-008) — same image, same behavior.
3. **Provenance is mandatory.** Every observation names its source; every context-pack
   item cites its observations. No uncited derived facts.
4. **Observations are append-only.** Corrections supersede; nothing is edited in place.
5. **Budgets are mandatory on reads.** No API that returns unbounded context.
6. **Domain-agnostic core.** Domain knowledge lives in the schema registry and
   plugins (see "malleable" in `concepts.md`), never in core code.

## D-001 · Core language: Python 3.12

- **Why:** best MCP + LLM ecosystem (official MCP SDK, every model provider),
  Pydantic v2 gives contracts-as-code with JSON Schema export for free, and it is the
  language the widest range of target teams can extend. Performance is a non-issue at
  this scale (I/O-bound; SQLite does the heavy lifting).
- **Considered:** TypeScript (fine MCP story, weaker data tooling); Go/Rust (faster,
  but slower iteration and much weaker LLM-library ecosystem; nothing here needs the
  speed).
- **Escape hatch:** contracts are JSON-Schema-first (exported from Pydantic), so SDKs
  in other languages implement against the schema, not against Python.

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

## D-005 · Working name "Loom"

Provisional; chosen for the weaving metaphor and a short CLI name. Known collision
with loom.com — acceptable since there is no website planned for this project
(2026-09-03), but revisit the name before the conference for slide/branding
purposes. Repo is public at github.com/seahop/Loom.
Python package: `loom` internally; PyPI-safe name TBD (e.g. `loom-ctx`) if published.

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
(conference: end of October 2026).

## Open questions (decide when the use case firms up)

- **OQ-1:** Real-time requirements on ingestion → do we need a queue sooner (D-004)?
- **OQ-2:** One shared deployment with namespaces vs. per-team stacks as the primary
  story? (Both work; affects auth priority.)
- **OQ-3:** AuthN/Z on the HTTP surface — API keys per namespace is the likely v1.
- **OQ-4:** Embedding model choice + dimensionality (affects sqlite-vec schema).
- **OQ-5:** Retention/TTL policy for raw artifacts vs. derived observations.
- **OQ-6:** Public name (D-005).
