# Concepts & glossary

Precise definitions of the terms of art in this project. Docs and code use these
words in exactly these senses.

### Malleable

The framework's defining quality. **Teams can reshape Loom to their domain without
forking the core.** Malleability is delivered through four specific mechanisms, not
vibes:

1. **Schema registry** — entity types, key fields, and predicates are registered
   per namespace at runtime, never hardcoded. A network-security team registers
   `host`, `user`, `ip`; a procurement team registers `vendor`, `contract`. The
   engine is domain-agnostic.
2. **Store interface** — all persistence sits behind the `GraphStore` protocol.
   SQLite is the default; Neo4j (or anything else) is a drop-in implementation.
3. **Pluggable enrichers** — summarization, embedding, and claim extraction are
   interfaces with an LLM-backed default; teams can substitute their own models,
   endpoints, or rule-based extractors.
4. **Layered access** — MCP, HTTP, SDK, and CLI are thin shells over one core, so a
   new surface (a Slack bot, a Kafka consumer) is an adapter, not a rewrite.

If a proposed feature can only serve one domain, it belongs in a registered schema
or a plugin — not in the core.

### Observation

An immutable, append-only record: *source S asserted fact F about entity E,
observed at time T, recorded by Loom at time R*. Observations are never edited,
only superseded by later observations. The ground-truth layer; everything above it
is derived and rebuildable.

### Claim

A **structured** ingestion payload that is already entity-addressed
(subject / predicate / object + timestamps + source). Maps ~1:1 to an observation
with no LLM involvement.

### Document / Artifact

A **document** is unstructured ingested content (report, ticket, email, file). It is
stored verbatim as an immutable **artifact** (bytes + metadata), then asynchronously
chunked, embedded, and mined for claims. Extracted claims carry provenance pointers
back to the exact artifact span.

### Claim extraction

The async LLM pass that turns a document into observations (entity mentions +
factual claims). Extracted observations default to lower confidence than directly
asserted claims.

### Entity / Provisional entity

An **entity** is a canonical node in the graph, produced by entity resolution. A
**provisional entity** is created when a document mention cannot be confidently
resolved — it is kept (never dropped) and can be merged into a canonical entity
later. Merges are recorded as events: auditable and reversible.

### Bitemporal

Every fact carries two time axes: `valid_from`/`valid_to` (when it was true in the
world) and `recorded_at` (when Loom learned it). "What was true in June?" and "what
did we know in June?" are different questions and both are answerable.

### Identity-over-time rule

Reassignable identifiers (IP addresses, hostnames, seat numbers) are modeled as
**time-bounded edges to their own nodes**, not as properties of the entity.
`(ip:10.0.4.7) -ASSIGNED_TO{valid_from, valid_to}-> (host:web-01)`.

### Dossier

A rolling, hierarchical, per-entity summary (brief + per-facet sections), rebuilt
asynchronously as observations accumulate, with every sentence linked to supporting
observations. Exists so reads are lookups, not LLM calls.

### Facet

A named aspect of an entity that a dossier summarizes and a query can target:
`identity`, `activity`, `relationships`, `security`, etc. Facet vocabularies live in
the schema registry.

### Context pack

The unit of retrieval. Given (subject, question, token budget, as-of?), the engine
returns: ranked items trimmed to fit the budget, citations to observations,
expansion handles, and explicitly surfaced conflicts. The agent-facing product of
the whole system.

### Token budget

A **mandatory** parameter on every read. The caller declares how much context it can
afford; the engine guarantees the pack fits. Budgets are first-class, not advisory.

### Expansion handle

An opaque ID attached to a context-pack item meaning "there is more here." The agent
passes it back (`expand(handle)`) to pull the underlying document chunk, neighbor
subgraph, or time window. The mechanism behind progressive disclosure.

### Progressive disclosure

The retrieval philosophy: start the agent with a few hundred tokens and let it pull
deeper *only where the question demands it*, via handles — instead of front-loading
everything that might be relevant.

### Conflict surfacing

When sources disagree, the context pack shows the disagreement explicitly with both
citations ("auth-log says X on Mar 3; IR-4432 says Y on May 1"). Contradictions are
never silently merged or resolved by recency alone.

### Idempotency key (event_id)

An optional sender-supplied identifier on any ingestion envelope. Redelivery
of the same `(namespace, event_id)` — queue retries, sender retries, network
flakes — stores exactly one observation and returns the original. Without an
event_id, every delivery is stored (some data really is repeated
measurements). See D-014.

### Tombstone

The redaction mechanism that respects append-only: a tombstoned observation
disappears from every read (packs, expansions, raw views) but the row and
the tombstone itself remain, so history is suppressed, never falsified.
`python -m loom.lifecycle redact`. See D-016.

### API key

Per-namespace credential in `LOOM_API_KEYS` (`key:namespace:perms`),
enforced identically by the engine and the ingest gateway; presented as
`X-Loom-Key` or a Bearer token. Unset means open dev mode. See D-013.

### Namespace

The multi-tenancy boundary. Every contract carries a namespace; schemas, entities,
observations, and dossiers are scoped to one. Default: `"default"`.

### Schema registry

The per-namespace catalog of entity types (with natural-key fields), predicates, and
facets. What makes the engine domain-agnostic and teams self-serve.

### Write path / read path

The architectural split. Write path: greedy, thorough, async-enriched. Read path:
cheap, budgeted, precomputed. Expensive work always happens at write time or in the
background — never while an agent waits.
