# Tapping in: MCP, HTTP, SDK, CLI

Four surfaces, one core. All of them speak the shapes in `src/loom/contracts.py`
(exported as JSON Schema for non-Python consumers). Behavior can never diverge
because each surface is a thin shell over the same internal service functions.

## 1. MCP server — the surface for agents (live, phase 3)

The primary way AI systems tap in: `src/loom/mcp_server.py` wraps the same
core functions the HTTP API uses (no drift possible). Entity handles are
`"type:key"` strings.

| Tool | Purpose |
| --- | --- |
| `list_namespaces()` | Where the data is: every namespace with entity counts by type (D-036) |
| `describe_namespace(namespace)` | How it connects: entity types with counts, registered predicates (descriptions, object types, containment) and a hint for multi-hop `ask_scope` |
| `find_entity(query)` | Resolve a name/key fragment to `type:key` handles |
| `find_related(question)` | Entities related by meaning — over facts *and* the passages of documents that claims cite — each with the fact or passage that matched, cited (needs `LOOM_EMBED_*`; D-040) |
| `ask(subject, question, budget, as_of?, valid_at?)` | Budgeted, cited context on one entity (`as_of` = known at T, `valid_at` = true at T) |
| `ask_scope(subjects, question, expand_predicates?, depth?)` | Several entities, or an anchor + contents ("domain:corp.local" over `member_of`) |
| `expand(handle, budget)` | Progressive disclosure — pull one thread deeper |
| `record_claim(subject, predicate, ..., object_ref \| object_value)` | Agents write back facts they learn |
| `get_observations(subject)` | Raw audit view |
| `answer(question, subject?)` | Server-side LLM synthesis (guides to `ask` when no LLM is configured) |

Every tool takes a `namespace`; a call against a namespace that holds no
data is an *error naming the namespaces that do*, not an empty list — a
live agent run dropped the argument after two calls and spent twelve steps
querying an empty `default` (D-036). A deployment that serves one team
sets `LOOM_MCP_NAMESPACE=netsec` on the server and the argument becomes
optional.

**Measuring an agent against Loom** (D-036): `python -m loom.agent_eval
--db /data/loom.db` runs a real model as an agent over the real MCP
transport with no pre-built scope — it must find the data, choose
`ask_scope` and its `expand_predicates`, and answer with citations. Ground
truth is computed from the store; the score checks the right entities were
named, none were invented, and every cited id was actually seen in a tool
result. Provider from `LOOM_LLM_*`, model override `LOOM_AGENT_MODEL`
(tool-calling required). Results and what they changed: `docs/real-data.md`.
`--models a,b,c --markdown out.md` compares models with billed cost per
run — the scorecard in `docs/models.md`.

Hook up a local agent (stdio, spawned per session — nothing on the host):

```bash
claude mcp add loom -- docker compose --project-directory "$PWD" run --rm -T loom python -m loom.mcp_server
```

Remote agents use streamable HTTP:

```bash
docker compose --profile mcp up -d mcp     # MCP endpoint at 127.0.0.1:8300/mcp
```

With `LOOM_AUTH_FILE` / `LOOM_API_KEYS` set, the HTTP transports require the
same `X-Loom-Key` / `Authorization: Bearer` header as the REST API on every
request, and each tool call is scoped by that key's grants (D-024). stdio is
local trust: the agent that spawned the process already owns the data.

Design rules:
- Every tool result fits the budget and carries citations — an agent can quote Loom
  with sources without extra calls.
- `expand` is how we keep first responses small: the default `ask` budget is ~800
  tokens; anything more is an explicit agent decision.
- Server `instructions` teach the loop (find → ask small → expand → write back)
  and that conflict items must never be silently resolved.

## 2. HTTP API — the substrate

Everything else is built on this. v1 routes:

```
GET  /healthz
POST /v1/ingest                                  # ClaimIn -> 200; DocumentIn -> 202 (artifact stored, extraction pending)
POST /v1/ingest/batch                            # JSON array or NDJSON of envelopes -> per-item outcomes (D-034)
GET  /v1/entities/{type}/{key}/observations      # raw, for debug/audit
GET  /v1/entities/search?q=                      # resolve names to entities
GET  /v1/entities/semantic?q=                    # entities by MEANING, each with a cited fact (needs an embedder, D-025)
GET  /v1/artifacts/{id}                          # stored document, verbatim
POST /v1/ask                                     # AskRequest (subject | scope) -> ContextPack
POST /v1/expand                                  # ExpandRequest -> ContextPack
POST /v1/answer                                  # retrieval-grounded LLM answer (503 until an LLM is configured, D-012)
POST /v1/schemas, GET /v1/schemas                # per-namespace registry: entity types, predicates, strictness (D-024)
GET  /readyz, GET /metrics                       # store-probing readiness (+ schema_version), Prometheus
```

Every read takes `as_of` (what was *known* at T) and/or `valid_at` (what was
*true* at T — e.g. which host held an IP during an incident window).

Multi-entity questions use a **scope** instead of a subject — several
computers at once, or an anchor expanded over containment predicates:

```json
{"scope": {"subjects": [{"type": "domain", "key": "corp.local"}],
           "expand": ["member_of"], "depth": 1},
 "question": "what alerts or unusual activity happened?", "budget": 800}
```

Conventions: JSON everywhere; namespace via `X-Loom-Namespace` header (default
`"default"`); auth via `X-Loom-Key: <key>` or `Authorization: Bearer <key>`
(`Loom(url, namespace, api_key=...)` in the SDK); optional `event_id` on any
envelope makes ingestion idempotent (D-014); `/metrics` and `/readyz` for
operations.

### Keys and scoping (D-013/D-013a)

Generate real keys (hashed at rest, plaintext printed once):

```bash
docker compose run --rm --user "$(id -u):$(id -g)" -v $PWD/secrets:/secrets loom \
  python -m loom.keys --file /secrets/keys.json generate \
  --id netsec-shipper --namespace netsec --perms w \
  --entity-types host,ip,user --sources auth-log --expires-days 180
```

Then point both the engine and gateway at it: `LOOM_AUTH_FILE=/secrets/keys.json`
(mounted Secret on k8s). Rotation is hot — rewrite the file, no restarts.

Typical grants:
- **Sender/pipeline device:** `--perms w` (+ `--sources`, `--entity-types`) —
  can put data in, can never read anything back.
- **Operator's agent:** `--perms r` scoped to the namespaces/entity types that
  user may see. The agent keeps the full query surface — ask, expand,
  search, `/v1/answer` — it just operates over that user's slice of the
  world (search and auto-resolution return only in-scope entities).
- **LLM spend:** the provider key normally lives server-side; an agent may
  instead send its own via `X-Loom-LLM-Key` per request.

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
more = loom.expand(pack["handles"][0]["id"])

# scoped: a domain and its contents
pack = loom.ask(None, "what changed?", scope={
    "subjects": [{"type": "domain", "key": "corp.local"}],
    "expand": ["member_of"], "depth": 1})

# fact time: which host HELD this ip on Aug 20 (vs. as_of = what we knew then)
pack = loom.ask(("ip", "10.0.4.7"), "which host?", valid_at="2026-08-20T00:00:00Z")

# declare the domain once; strict namespaces reject unregistered predicates
loom.register_schema(
    entity_types=[{"name": "host"}, {"name": "domain"}],
    predicates=[{"name": "member_of", "object_types": ["domain"], "containment": True}])

# retrieval-grounded LLM answer (server has LOOM_LLM_* configured; entities
# named in the question are auto-resolved)
result = loom.answer("what do web-01 and web-02 have in common?")
print(result["answer"], result["model"])
```

### Configuring the answering LLM (server side, D-012)

```bash
# OpenRouter                          # Venice
LOOM_LLM_PROVIDER=openrouter          LOOM_LLM_PROVIDER=venice
LOOM_LLM_API_KEY=sk-or-...            LOOM_LLM_API_KEY=...
LOOM_LLM_MODEL=deepseek/deepseek-v3   LOOM_LLM_MODEL=llama-3.3-70b

# Anthropic                           # Self-hosted (Ollama/vLLM/LM Studio)
LOOM_LLM_PROVIDER=anthropic           LOOM_LLM_BASE_URL=http://my-box:11434/v1
LOOM_LLM_API_KEY=sk-ant-...           LOOM_LLM_MODEL=llama3.1:8b
LOOM_LLM_MODEL=claude-sonnet-5
```

### Batch ingest, bulk loading, and other pipelines (D-034)

`POST /v1/ingest/batch` takes a JSON array or NDJSON of envelopes and reports
each item; both SDKs expose it (`ingest_batch` / `ingestBatch`). Log shippers
post to it directly — see `deploy/integrations/` for Vector and Fluent Bit
configs — and `python -m loom.ingest file.jsonl --url …` loads files from
any language. Kafka topics feed `python -m loom.kafka_consumer`.

### Go SDK — `sdk/go/` (D-034)

```go
c := loom.New("http://localhost:8000", "netsec"); c.APIKey = "loomk_..."
res, _ := c.IngestBatch(ctx, loom.Claim{...}, loom.Document{...})
pack, _ := c.Ask(ctx, &loom.EntityRef{Type: "host", Key: "web-01"}, "who logged in?", loom.AskOptions{Budget: 800})
```

Its envelopes are tested against `contracts/schemas.json`, the schema the
Go gateway enforces. `docker compose --profile sdk run --rm sdk-go`.

### Every other language — `contracts/openapi.json`

```bash
docker run --rm -v "$PWD:/local" openapitools/openapi-generator-cli:v7.10.0 generate \
  -i /local/contracts/openapi.json -g java -o /local/build/loom-java   # csharp, kotlin, rust, php, ruby, swift5 ...
```

CI regenerates the document from the app and proves Java and C# generate
cleanly, so a generated client is always current.

### TypeScript SDK — `sdk/typescript/` (D-026)

Same shape, generated types: `src/contracts.ts` is produced from
`contracts/schemas.json` and CI fails if it drifts. Zero runtime
dependencies (platform `fetch`); Node ≥ 18 or any modern runtime.

```ts
import { Loom, LoomError } from "loom-sdk";

const loom = new Loom("http://localhost:8000", { namespace: "netsec", apiKey: "loomk_..." });
await loom.claim({ subject: ["host", "web-01"], predicate: "logged_in_by",
                   object: ["user", "jdoe"], observed_at: "2026-09-01T14:03:00Z", source: "auth-log" });
const pack = await loom.ask(["host", "web-01"], "who logged in this week?", { budget: 800 });
const held = await loom.ask(["ip", "10.0.4.7"], "which host?", { valid_at: "2026-08-20T00:00:00Z" });
const related = await loom.semantic("what looks exploitable?");
```

Build/test/regenerate inside Docker: `docker compose --profile sdk run --rm sdk-ts`
(and `... sdk-ts npm run gen` after a contract change).

## 4. CLI — for humans

What ships today are operator modules, each run inside the image
(`docker compose run --rm loom python -m loom.<module> ...`):

```bash
python -m loom.seed load                 # deterministic demo corpus
python -m loom.keys generate ...         # mint/list/revoke/update API keys (D-013a)
python -m loom.lifecycle export|import|purge|redact   # backup, migration, retention (D-016)
python -m loom.enrich run --once         # drain the enrichment backlog (D-018)
python -m loom.loadgen --url ...         # measure ingest throughput (D-011)
```

The human-ergonomic `loom ask host:web-01 "..."` front-end (see exactly what
an agent would see) is planned, not built; until then `curl` against
`POST /v1/ask` or the Python SDK is the debugging story.

## Choosing a surface

- Building an agent → **MCP**.
- Building a pipeline/device that pushes data → **SDK** (or raw HTTP from anything).
- Operating, exploring, debugging → **CLI**.
- Building a new surface (Slack bot, Kafka consumer) → write an adapter over HTTP;
  that's the malleability contract (see `concepts.md`).
