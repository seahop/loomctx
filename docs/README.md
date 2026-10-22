# LoomCtx documentation

Read in this order depending on why you're here.

## Getting started
1. **[quickstart.md](quickstart.md)** — 5 minutes: run the seeded demo, see a
   cited context pack and an LLM answer.
2. **[tutorial.md](tutorial.md)** — 30 minutes: build your *own* security
   domain (vulnerability management) from an empty store, end to end, and
   connect an agent. Runnable scripts in [`../examples/`](../examples/).
3. **[bring-your-own-data.md](bring-your-own-data.md)** — your own exports:
   which connector matches what you export, the load commands (LDIF, nmap,
   KEV/NVD/EPSS), checking what landed and what was not collected, a
   custom domain with aliases and `not_collected` through the Python SDK,
   and documents (what needs an LLM or an embedder).
4. **[mcp-clients.md](mcp-clients.md)** — connecting agents: Claude Code,
   Claude Desktop, Cursor, VS Code / Copilot and a generic config; stdio
   and streamable HTTP with the API-key header; the
   `LOOMCTX_MCP_WRITES` / `LOOMCTX_MCP_QUERIES` switches.
5. **[recipes.md](recipes.md)** — one worked question per team (red team,
   blue team / IR, vulnerability management, identity governance), each as
   MCP tool calls and the equivalent HTTP request.

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
- **[models.md](models.md)** — which LLMs drive LoomCtx well as agents: a
  measured scorecard (pass rate, faithfulness, cost) and the command to
  re-run it.
- **[evaluation.md](evaluation.md)** — the retrieval scorecard: context
  packs against full-context, vector top-k and recency baselines on
  store-derived questions (lease at T, conflicts, multi-hop, abstention,
  numeric, ordering), rule-scored, with the command that reproduces the
  talk table.
- **[ad-eval.md](ad-eval.md)** — the AD reachability capability benchmark:
  a synthetic directory generator (`loomctx.connectors.ad_gen`) plants known
  membership → ACL → trust chains and decoy dead-ends in dense noise, and
  `loomctx.ad_eval` scores whether LoomCtx's scope walk surfaces the full cited
  chain (scripted reader, no LLM). Synthetic, object-level only.
- **[interop.md](interop.md)** — standards at the edges: STIX 2.1 and OCSF
  connectors (import and export, mapping tables, what is not mapped,
  `examples/stix_import.py`), and the raw LDAP / LDIF connector for
  object-level Active Directory reachability. The PROV-O provenance export
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
- **[releasing.md](releasing.md)** — the maintainer checklist: version
  tags for the images, and how the Python, TypeScript and Go SDKs would be
  published (PyPI trusted publishing, npm with provenance, `sdk/go/v*`
  tags).

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
