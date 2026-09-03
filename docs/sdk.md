# Tapping in: MCP, HTTP, SDK, CLI

Four surfaces, one core. All of them speak the shapes in `src/loom/contracts.py`
(exported as JSON Schema for non-Python consumers). Behavior can never diverge
because each surface is a thin shell over the same internal service functions.

## 1. MCP server — the surface for agents (phase 3)

The primary way AI systems tap in. Tools (names are contract, keep stable):

| Tool | Signature (conceptual) | Purpose |
| --- | --- | --- |
| `find_entity` | (query, namespace?) → [EntityMatch] | Resolve a name/key/description to entity handles |
| `get_brief` | (entity, budget?) → ContextPack | The dossier brief — the cheap "who is this?" call |
| `ask` | (entity, question, budget, as_of?) → ContextPack | Question-scoped context; the main event |
| `expand` | (handle, budget?) → ContextPack fragment | Progressive disclosure — pull one thread deeper |
| `record_observation` | (Claim) → ObservationRef | Agents write back what they learn |

Design rules:
- Every tool result fits the budget and carries citations — an agent can quote Loom
  with sources without extra calls.
- `expand` is how we keep first responses small: the default `ask` budget is ~800
  tokens; anything more is an explicit agent decision.
- The MCP server runs in-process with the engine (same container, compose profile
  `mcp`), stdio or SSE.

## 2. HTTP API — the substrate

Everything else is built on this. v1 routes:

```
GET  /healthz
POST /v1/ingest                                  # ClaimIn -> 200; DocumentIn -> 202 (artifact stored, extraction pending)
GET  /v1/entities/{type}/{key}/observations      # raw, for debug/audit
GET  /v1/artifacts/{id}                          # stored document, verbatim
POST /v1/ask                                     # AskRequest -> ContextPack
POST /v1/expand                                  # ExpandRequest -> ContextPack
POST /v1/schemas                                 # register entity types/predicates (phase 1 remainder)
```

Conventions: JSON everywhere; namespace via `X-Loom-Namespace` header (default
`"default"`); errors are RFC 7807 problem+json; auth is per-namespace API keys
(phase 5, OQ-3).

## 3. Python SDK — `sdk/python/`

A thin, typed, dependency-light client. It contains **no logic** — no retries into
semantics, no client-side ranking — just typed transport, so it can never drift from
the server. Target shape:

```python
from loom_sdk import Loom

loom = Loom("http://localhost:8000", namespace="netsec")

# write side — a pipeline device pushing telemetry
loom.claim(
    subject=("host", "web-01"),
    predicate="logged_in_by",
    object=("user", "jdoe"),
    observed_at="2026-09-01T14:03:00Z",
    source="auth-log",
)
loom.document(text=report_text, source="ir-pipeline", filename="IR-4432.txt",
              observed_at="2026-09-02T09:00:00Z")

# read side — an app or agent framework without MCP
pack = loom.ask(("host", "web-01"), "who logged in this week?", budget=800)
print(pack.items[0].text, pack.items[0].citations)
more = loom.expand(pack.handles[0].id)
```

Later: a TypeScript SDK generated from the exported JSON Schema (phase 5) — no
hand-written second client.

## 4. CLI — for humans

Same core, human ergonomics. Also the debugging story: *see exactly what an agent
would see*.

```bash
loom ingest claims.jsonl                 # bulk claims
loom ingest report.pdf --source ir-pipe  # a document
loom show host:web-01                    # entity + recent observations
loom ask host:web-01 "who logged in this week?" --budget 800
loom schema register netsec.yaml         # entity types + predicates
```

Runs via `docker compose run --rm loom loom <args>` — nothing on the host.

## Choosing a surface

- Building an agent → **MCP**.
- Building a pipeline/device that pushes data → **SDK** (or raw HTTP from anything).
- Operating, exploring, debugging → **CLI**.
- Building a new surface (Slack bot, Kafka consumer) → write an adapter over HTTP;
  that's the malleability contract (see `concepts.md`).
