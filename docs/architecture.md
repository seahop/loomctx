# Architecture

Loom is a **context engine**: it absorbs data about entities over time and serves
agents small, question-scoped slices of that knowledge. The load-bearing decision is
the split between a **write path** and a **read path** with opposite temperaments.

- **Write path — greedy and thorough.** Accept every incoming piece of data, resolve
  it to an entity, store it append-only with full provenance and timestamps, and do
  all expensive enrichment (summarization, embedding, extraction, linking)
  **asynchronously** in background workers.
- **Read path — cheap and stingy.** When an agent asks about an entity, assemble a
  **context pack**: a token-budgeted, ranked, cited answer with opaque handles for
  drilling deeper. Never the whole record.

The graph is the *index*, not the payload. Agents never traverse it directly; they
talk to a retrieval contract that performs scoped traversal for them.

## Data model — three layers, raw to refined

### 1. Observations (append-only ground truth)

Immutable records of "source S asserted fact F about entity E at time T":

```
(id, namespace, subject, predicate, object, observed_at, valid_from?, valid_to?,
 recorded_at, source, confidence, provenance?, attrs)
```

Never edited, only superseded. This is the audit trail everything else derives from,
and the layer that makes every claim in a context pack citable.

### 2. Entities & relations (the bitemporal graph)

Canonical nodes produced by entity resolution, connected by edges that carry **two
time axes**:

- `valid_from` / `valid_to` — when the fact was true in the world
- `recorded_at` — when Loom learned it

This makes "what did we know about X as of June?" and "what was true of X in June?"
distinct, answerable questions.

**Identity-over-time rule:** identifiers that get reassigned (IP addresses, hostnames,
seat assignments, badge numbers) are modeled as **time-bounded edges**, not entity
properties. `10.0.4.7` is not a property of `web-01`; it is
`(ip:10.0.4.7) -ASSIGNED_TO{valid_from, valid_to}-> (host:web-01)`. This is what makes
"which host had this IP during the incident window?" a first-class query.

### 3. Dossiers (precomputed read-side material)

Rolling, hierarchical summaries per entity, rebuilt asynchronously when enough new
observations accumulate:

- a one-paragraph **brief**
- per-**facet** summaries (e.g. `identity`, `activity`, `relationships`, `security`)
- every sentence linked back to the observations that support it

Dossiers exist so that read-time is mostly a lookup and a trim, not an LLM call.

## Ingestion — two front doors, one observation model

A single envelope with a `kind` discriminator:

**`claim`** — structured, entity-addressed events (telemetry, logs, pipeline
outputs). Map ~1:1 onto observations. No LLM involved: cheap, synchronous,
high-volume friendly.

**`document`** — unstructured content (reports, tickets, emails, files forwarded by
pipeline devices). Path:

1. Store the raw bytes as an immutable **artifact** (nothing is ever lost).
2. Acknowledge immediately — extraction never blocks the write path.
3. Async: chunk + embed for semantic search.
4. Async: **claim extraction** — an LLM pass pulls entity mentions and factual claims,
   which become ordinary observations, each linked to the exact document span it came
   from (lower default confidence, provenance pointer into the artifact).

After extraction, a claim mined from a PDF and a claim from a syslog event are the
same shape in the store; only metadata differs.

## Entity resolution — two tiers

- **Deterministic:** structured claims resolve by natural keys per the schema
  registry (`host:web-01`, `user:jdoe`). Fast, no ambiguity.
- **Fuzzy:** document mentions resolve via alias tables → embedding similarity →
  LLM adjudication for the ambiguous remainder. An unresolvable mention becomes a
  **provisional entity** (never dropped) that can be merged later. Merges are
  recorded as events themselves, so they are auditable and reversible.

## The retrieval contract (the differentiator)

Every read request carries:

- a **subject** (entity handle or search string)
- a **question or facet** (what about it?)
- a **token budget** (the caller decides what it can afford)
- optionally an **as-of** time

The engine answers with a **context pack**:

- the relevant dossier slice, ranked and trimmed to fit the budget
- relevant edges from a *pruned* k-hop traversal (relevance-scored, never "everything
  within 2 hops")
- **citations** — which observations back each item
- **expansion handles** — opaque IDs the agent passes back to say "more about *this*
  thread" (a document chunk, a neighbor entity, a time window)
- **surfaced conflicts** — contradictions between sources are shown explicitly
  ("source A says X as of March; source B says Y as of May"), never silently merged

Ranking inside the budget combines: semantic similarity to the question, graph
distance from the subject, recency/decay, and source confidence.

**Progressive disclosure is the point:** the agent starts with ~500 tokens and pulls
more only when the question demands it. That is what keeps agent context clean.

## Access surfaces — three shells over one core

1. **MCP server** (primary, for agents): `find_entity`, `get_brief`, `ask`, `expand`,
   `record_observation`. Agents can also *write back* what they learn.
2. **HTTP API + thin SDKs** for apps, pipelines, and non-MCP frameworks.
3. **CLI** for humans: ingest files, inspect entities, and debug exactly what an
   agent would see (`loom ask host:web-01 "who logged in this week?" --budget 800`).

All three are shells over one internal service, so behavior never diverges.

## Multi-tenancy

Everything is scoped by **namespace** (present in every contract from day one).
Different teams either share a deployment with isolated namespaces or run their own
compose stack — both work because the deployment is one small container plus a volume.

## Ingestion tier — two shapes, one contract (D-010)

`POST /v1/ingest` is the same envelope everywhere; which shape sits behind it
is a deployment choice invisible to senders.

**Default shape** (laptop, small team, the demo): one engine container does
everything. The k8s Service or compose port mapping is the only "proxy".

**Scale shape** (many pipeline devices, bursty ingestion): a dedicated
ingestion tier in front of the core —

```
 pipeline devices / SDKs
        |
        v
  load balancer            (k8s Service + HPA; nginx locally — shipped
        |                   config, never a custom proxy)
        v
  ingest gateways x N      (Go; stateless: authn, JSON Schema validation,
        |                   rate limits, batching)
        v
  durable buffer           (NATS JetStream, one small container:
        |                   backpressure, burst absorption, at-least-once)
        v
  writer consumers  ->  server-backed GraphStore (Postgres/Neo4j, D-008)
                              ^
  Python core (retrieval, ---+
  enrichment, MCP) scales as separate stateless replicas
```

The gateway is Go because the hot path deserves it (D-001a/D-010); everything
stateful or LLM-adjacent stays in the Python core. Gateways being stateless is
what makes multi-node ingestion free — add replicas, the LB spreads load, the
buffer serializes writes toward the store.

## Deployment posture

- Single engine container + volume-backed state (SQLite default). Optional Neo4j
  container for teams that want Cypher/visual exploration.
- Enrichment workers run **in-process** as background tasks until ingestion volume
  forces a real queue. Do not add infrastructure speculatively.
- The same `docker-compose.yml` deploys unchanged to a laptop, a small VPS, Fly.io,
  or ECS. Design for portability, not for any specific cloud.

## Diagram

```
   structured claims          documents (artifacts)
        |                         |
        v                         v
  +-----------------------------------------+
  |            INGEST (envelope)            |  <- ack fast, never blocks
  +-----------------------------------------+
        |                         |
        v                         v (async workers)
  entity resolution         chunk/embed -> claim extraction
        |                         |
        v                         v
  +-----------------------------------------+
  |   OBSERVATIONS (append-only, cited)     |
  |   ENTITY GRAPH (bitemporal edges)       |
  |   DOSSIERS (rolling summaries)          |   all behind GraphStore interface
  +-----------------------------------------+
                     |
                     v
  +-----------------------------------------+
  |  CONTEXT PACK BUILDER                   |
  |  (rank -> trim to budget -> cite ->     |
  |   attach expansion handles)             |
  +-----------------------------------------+
        |            |            |
        v            v            v
       MCP         HTTP/SDK      CLI
```
