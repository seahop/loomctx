# Loom documentation

Read in this order depending on why you're here.

## Getting started
1. **[quickstart.md](quickstart.md)** — 5 minutes: run the seeded demo, see a
   cited context pack and an LLM answer.
2. **[tutorial.md](tutorial.md)** — 30 minutes: build your *own* security
   domain (vulnerability management) from an empty store, end to end, and
   connect an agent. Runnable scripts in [`../examples/`](../examples/).

## Using it
- **[sdk.md](sdk.md)** — the surfaces: MCP for agents, HTTP (single and batch
  ingest), Python / TypeScript / Go SDKs, OpenAPI for every other language,
  the bulk loader, and how to configure the answering LLM.
- **[../deploy/integrations/README.md](../deploy/integrations/README.md)** —
  tying in pipelines you already run: Fluent Bit and Vector configs, the
  Kafka/Redpanda consumer, files from any language.
- **[real-data.md](real-data.md)** — load real public data (CISA KEV, NVD,
  EPSS) next to the demo hosts with one command; what the first run
  exposed.
- **[models.md](models.md)** — which LLMs drive Loom well as agents: a
  measured scorecard (pass rate, faithfulness, cost) and the command to
  re-run it.
- **[evaluation.md](evaluation.md)** — the retrieval scorecard: context
  packs against full-context, vector top-k and recency baselines on
  store-derived questions (lease at T, conflicts, multi-hop, abstention,
  numeric, ordering), rule-scored, with the command that reproduces the
  talk table.
- **[interop.md](interop.md)** — standards at the edges: STIX 2.1 and OCSF
  connectors (import and export, mapping tables, what is not mapped,
  `examples/stix_import.py`). The PROV-O provenance export
  (`GET /v1/observations/{id}/prov`) is in
  [contracts.md](contracts.md#provenance-export-get-v1observationsidprov).
- **[demo.md](demo.md)** — the conference walkthrough: three acts, every
  command, expected output, fallbacks, rehearsal checklist.
- **[contracts.md](contracts.md)** — the wire shapes (the real API); JSON
  Schema export; PROV-O provenance export.
- **[concepts.md](concepts.md)** — glossary: observation, claim, context pack,
  scope, bitemporal, dossier, tombstone, and the rest, defined precisely.

## Running it for a team
- **[administration.md](administration.md)** — API keys, scoping users and
  senders, rotation, retention, the bearer security model, monitoring.
- **[../deploy/README.md](../deploy/README.md)** — local Compose and the three
  Kubernetes shapes; what autoscales.

## Understanding it
- **[architecture.md](architecture.md)** — the write/read split, the pipeline,
  deployment shapes, diagrams.
- **[infrastructure.md](infrastructure.md)** — detailed Mermaid views: the
  one-container shape, the fully scaled k8s shape, and the read and write
  flows through them.
- **[decisions.md](decisions.md)** — every design decision (D-001 onward) with
  rationale, the hard constraints, and the open questions.
- **[roadmap.md](roadmap.md)** — phase status and the path to the conference.
- **[hardening.md](hardening.md)** — verified issue lists from the
  2026-09-08 and 2026-09-23 reviews and later ones (security gates, store
  robustness, provenance gaps, demo risks), with priorities and status.
