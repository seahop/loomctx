# Loom documentation

Read in this order depending on why you're here.

## Getting started
1. **[quickstart.md](quickstart.md)** — 5 minutes: run the seeded demo, see a
   cited context pack and an LLM answer.
2. **[tutorial.md](tutorial.md)** — 30 minutes: build your *own* security
   domain (vulnerability management) from an empty store, end to end, and
   connect an agent. Runnable scripts in [`../examples/`](../examples/).

## Using it
- **[sdk.md](sdk.md)** — the four surfaces (MCP for agents, HTTP, Python SDK,
  CLI), the full endpoint list, and how to configure the answering LLM.
- **[contracts.md](contracts.md)** — the wire shapes (the real API); JSON
  Schema export.
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
- **[decisions.md](decisions.md)** — every design decision (D-001…D-019) with
  rationale, the hard constraints, and the open questions.
- **[roadmap.md](roadmap.md)** — phase status and the path to the conference.
- **[hardening.md](hardening.md)** — verified issue list from the 2026-09-08
  review (security gates, store robustness, provenance gaps, demo risks),
  with priorities and status.
