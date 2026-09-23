# Changelog

Loom is pre-1.0: contracts are stable within a minor version and every
change to them is recorded in `docs/decisions.md` (D-numbers below).

## Unreleased

## v0.1.0 — 2026-09-09

First tagged release: the conference build.

### Core
- Append-only, cited observations about entities; claims and documents;
  two time axes (`as_of` knowledge time, `valid_at` fact time) (D-001…D-012, D-024)
- Context packs: token-budgeted, question-ranked, conflicts first,
  expansion handles, document excerpts, relation chains for multi-hop
  scopes, handle cap with `omitted_handles`, partial-coverage reporting
  via `truncated` (D-018, D-020, D-035, D-038)
- Per-namespace schema registry; the core stays domain-agnostic (D-024)
- Stores: SQLite (WAL, sqlite-vec) and Postgres (pgvector), behaviorally
  identical under one contract test suite; namespace sharding; artifact
  offload to filesystem or S3 (D-011, D-025, D-032, D-033)
- Async enrichment: embeddings, claim extraction with span provenance,
  dossiers, two-tier entity resolution, leased worker fleet (D-018, D-019, D-023, D-031)
- API keys with data scoping, signed handles, retention and redaction (D-013, D-013a, D-016, D-021)

### Surfaces
- HTTP API with `/v1/ingest/batch`; JSON Schema and OpenAPI, drift-checked in CI (D-034)
- MCP server for agents: find, ask, ask_scope, expand, record_claim,
  answer, plus `list_namespaces` / `describe_namespace`, an agent-shaped
  pack view, and coverage warnings (D-026, D-036, D-038)
- SDKs: Python, TypeScript (generated types), Go (schema-validated) (D-026, D-034)
- Pipeline adapters: Fluent Bit, Vector, Kafka/Redpanda consumer, bulk loader (D-034)

### Scale (all opt-in)
- Go ingest gateway, NATS JetStream buffer with dead-letter, writer
  consumers, Postgres pool/read replicas, CloudNativePG HA overlay,
  load generator and capacity table (D-010, D-027…D-030)

### Real data and evaluation
- Vulnerability-intelligence connector: CISA KEV + NVD + EPSS, streamed,
  idempotent, history-preserving, nightly CronJob (D-035)
- Agent end-to-end harness over the real MCP transport with store-derived
  ground truth and a citation-faithfulness check; eighteen-model scorecard
  with billed cost (D-036, D-037)

### Validation
- Validated on GKE: capacity on real nodes, 18 h soak, HA failover at 11 s
  end to end (D-043); worker quality fixes from the soak (D-044)
- Release gate: the scale shape (lb → gateways → JetStream → consumer →
  store) smoke-tested in CI on every push; store migrations proven on a
  populated database; the published image re-validated on GKE before the
  tag moves (D-045)

### Measured on this release (laptop, generator co-located)
- 511k envelopes loaded in 81 s to SQLite; single-entity ask 2–5 ms at
  465k observations; two-hop scope over 1,077 entities in 0.5 s
- Eighteen models, three runs each: nine pass all four agent tasks three
  times out of three (12/12); citation faithfulness 216/216 task-runs
  (`docs/models.md`)
