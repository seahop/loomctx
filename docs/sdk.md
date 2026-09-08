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
| `find_entity(query)` | Resolve a name/key fragment to `type:key` handles |
| `ask(subject, question, budget, as_of?)` | Budgeted, cited context on one entity |
| `ask_scope(subjects, question, expand_predicates?, depth?)` | Several entities, or an anchor + contents ("domain:corp.local" over `member_of`) |
| `expand(handle, budget)` | Progressive disclosure — pull one thread deeper |
| `record_claim(subject, predicate, ..., object_ref \| object_value)` | Agents write back facts they learn |
| `get_observations(subject)` | Raw audit view |
| `answer(question, subject?)` | Server-side LLM synthesis (guides to `ask` when no LLM is configured) |

Hook up a local agent (stdio, spawned per session — nothing on the host):

```bash
claude mcp add loom -- docker compose --project-directory "$PWD" run --rm -T loom python -m loom.mcp_server
```

Remote agents use streamable HTTP:

```bash
docker compose --profile mcp up -d mcp     # MCP endpoint at :8300/mcp
```

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
GET  /v1/entities/{type}/{key}/observations      # raw, for debug/audit
GET  /v1/entities/search?q=                      # resolve names to entities
GET  /v1/artifacts/{id}                          # stored document, verbatim
POST /v1/ask                                     # AskRequest (subject | scope) -> ContextPack
POST /v1/expand                                  # ExpandRequest -> ContextPack
POST /v1/answer                                  # retrieval-grounded LLM answer (503 until an LLM is configured, D-012)
GET  /readyz, GET /metrics                       # store-probing readiness, Prometheus
```

Not yet served: `POST /v1/schemas` (schema-registry persistence is the open
phase-1 item in `roadmap.md`; the shapes exist in `contracts.py`).

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
docker compose run --rm -v $PWD/secrets:/secrets loom \
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

Later: a TypeScript SDK generated from the exported JSON Schema (phase 5) — no
hand-written second client.

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
