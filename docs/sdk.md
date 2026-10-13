# Tapping in: MCP, HTTP, SDK, CLI

Four surfaces, one core. All of them speak the shapes in `src/loomctx/contracts.py`
(exported as JSON Schema for non-Python consumers). Behavior can never diverge
because each surface is a thin shell over the same internal service functions.

## 1. MCP server — the surface for agents

The primary way AI systems tap in: `src/loomctx/mcp_server.py` wraps the same
core functions the HTTP API uses (no drift possible). Entity handles are
`"type:key"` strings.

| Tool | Purpose |
| --- | --- |
| `list_namespaces()` | Where the data is: every namespace with entity counts by type (D-036) |
| `describe_namespace(namespace)` | How it connects: entity types with counts, each with its `links` (`-runs_software-> product`, `<-affects- cve`) and `attributes`, registered predicates (descriptions, object types, containment) and a hint naming this namespace's two-hop paths (D-064) |
| `find_entity(query)` | Resolve a name/key fragment to `type:key` handles |
| `find_related(question)` | Entities related by meaning — over facts *and* the passages of documents that claims cite — each with the fact or passage that matched, cited (needs `LOOMCTX_EMBED_*`; D-040) |
| `ask(subject, question, budget, as_of?, valid_at?, format?)` | Budgeted, cited context on **one** entity (`as_of` = known at T, `valid_at` = true at T) |
| `ask_scope(subjects, question, expand_predicates?, depth?, budget?, format?, siblings?)` | **Several** entities and/or relation hops: an anchor + contents ("domain:corp.local" over `member_of`), or host → product ← cve; an attribute in `expand_predicates` is the question's topic; default budget 3000; a walk does not turn back to co-members unless `siblings` (D-080) |
| `find_path(from, to, via?, depth?, max_paths?, budget?, as_of?, valid_at?, format?, siblings?)` | The connecting **edge sequence(s)** between two entities along `via`, shortest first (default depth 4, at most 6), each hop cited (host→product→cve, user→group→domain); `node_status` flags a disabled account on a path; reports paths that EXIST, does not rank or score them (D-067, D-080) |
| `list_entities(type?, of?, via?, direction?, depth?, where?, fields?, limit?, offset?, budget?, as_of?, valid_at?)` | **Every** entity matching conditions, with an exact `total`: entities of `type`, or connected to `of` along `via` within `depth` edges (nested group members: direction `in`, depth 3–6), filtered on current values (`where`: `{predicate, op, value}` with eq / ne / in / contains / exists / absent, or text like `enabled=false`, `is_dc!=true`); rows cited, paged by `offset` / `next_offset`. Use it when the answer is a set (D-107) |
| `run_query(name, params?, limit?, offset?, budget?)` | Run one of the namespace's **named queries** — `describe_namespace` lists them (LDAP: `effective_members(group)`, `account_groups(account)`, `unconstrained_delegation_hosts`, `domain_trusts`, …); entity parameters take a handle or a name; returns a list page (D-108). `LOOMCTX_MCP_QUERIES=0` hides it |
| `expand(handle, budget, format?)` | Progressive disclosure — pull one thread deeper; a `cite` token returns that one observation |
| `record_claim(subject, predicate, ..., object_ref \| object_value, supersedes?, event_id?)` | Agents write back facts they learn; `supersedes` records a correction of an earlier observation |
| `get_observations(subject)` | Raw audit view (an entity, or a `cite` token / observation id) |
| `answer(question, subject?)` | Server-side LLM synthesis (guides to `ask` when no LLM is configured) |
| `purple_report(operation, status?, before_minutes?, after_hours?, limit?)` | A red-team operation's logged actions against the detections on the same hosts: detected / host_only / missed / no_target, latency, cite tokens for both sides (D-086) |

Every tool takes a `namespace`; a call against a namespace that holds no
data is an *error naming the namespaces that do*, not an empty list — a
live agent run dropped the argument after two calls and spent twelve steps
querying an empty `default` (D-036). A deployment that serves one team
sets `LOOMCTX_MCP_NAMESPACE=netsec` on the server and the argument becomes
optional.

**MCP 2026-07-28 alignment (R-7).** Every tool publishes an `outputSchema`
derived from the contract models and returns `structuredContent` next to
the text mirror; every tool has a title and annotations (`readOnlyHint`
on every read tool, `destructiveHint: false` everywhere — observations are
append-only — `idempotentHint` where a repeat is a no-op, `openWorldHint:
false`). The pack tools' schema is the *agent view* of `ContextPack`
(items first, compact citations, reached subjects summarized); the HTTP
surface still serializes the contract itself.

- `format: "concise" | "detailed"` on `ask`, `ask_scope`, `find_path`, `expand`.
  Concise (default) is what an agent carries in context, and what the
  budget charges: each item is `kind`, `text` and `cites` — one
  `"<cite> <source> <date>"` string per citation, the 12-hex `cite` token
  first — the first 20 reached subjects plus a total, and the pack's
  `charged_tokens` (D-058). Detailed keeps the ranking `score` and full
  citation objects with the 32-hex `observation_id` next to each `cite`,
  and lists every reached subject — for auditing, not for the loop.
- `expand` handles are stateless (the server keeps nothing per handle),
  HMAC-signed when `LOOMCTX_HANDLE_SECRET` is set, and never expire on their
  own — there is no TTL; rotating the secret is what invalidates the ones
  issued before it. `budget` is how the caller controls the size.
- `record_claim` is idempotent: `event_id` is the dedupe key (D-014); when
  omitted, one is derived from the claim's content, so a retried call
  records nothing new. `supersedes` takes a `cite` token or a full
  observation id and lands as `ClaimIn.supersedes` — a **recorded**
  correction of an earlier observation, never inferred: the old row stays
  for audit and for `as_of` reads before it, but is no longer current and
  no longer counts as a conflict.
- `ask` and `ask_scope` stay two tools with disjoint descriptions: one
  entity vs. several entities and/or relation hops. `ask_scope`
  defaults to budget 3000 and the server instructions tell agents to
  keep it at `budget<=4000` and expand handles from there (D-064,
  re-derived from the concise wire: 4000 is ~4.7k tokens on the real
  corpus, over 3x under Claude Code's 25k MCP output limit, while the
  old 1500 hint could not carry a 32-CVE answer); that a pack's
  `notes` say what it could not do as asked (an unknown expand
  predicate, with the closest known ones); and that a pack's
  `truncated` list names entities whose observations were only partly
  examined (never conclude absence about those).

**Measuring an agent against LoomCtx** (D-036): `python -m loomctx.agent_eval
--db /data/loomctx.db` runs a real model as an agent over the real MCP
transport with no pre-built scope — it must find the data, choose
`ask_scope` and its `expand_predicates`, and answer with citations. Ground
truth is computed from the store; the score checks the right entities were
named, none were invented, and every cited id was actually seen in a tool
result. Provider from `LOOMCTX_LLM_*`, model override `LOOMCTX_AGENT_MODEL`
(tool-calling required). Results and what they changed: `docs/real-data.md`.
`--models a,b,c --markdown out.md` compares models with billed cost per
run — the scorecard in `docs/models.md`.

Hook up a local agent (stdio, spawned per session — nothing on the host):

```bash
claude mcp add loomctx -- docker compose --project-directory "$PWD" run --rm -T loomctx python -m loomctx.mcp_server
```

Remote agents use streamable HTTP:

```bash
docker compose --profile mcp up -d mcp     # MCP endpoint at 127.0.0.1:8300/mcp
```

With `LOOMCTX_AUTH_FILE` / `LOOMCTX_API_KEYS` set, the HTTP transports require the
same `X-LoomCtx-Key` / `Authorization: Bearer` header as the REST API on every
request, and each tool call is scoped by that key's grants (D-024). stdio is
local trust: the agent that spawned the process already owns the data.

Design rules:
- Every tool result fits the budget and carries citations — an agent can quote LoomCtx
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
POST /v1/path                                    # PathRequest (from, to, via) -> PathPack: connecting edge sequences, cited (D-067)
POST /v1/list                                    # ListRequest (type | of+via, where) -> ListPage: every match, exact total, cited (D-107)
POST /v1/query                                   # QueryRequest (name, params) -> ListPage: a registered named query (D-108)
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

Conventions: JSON everywhere; namespace via `X-LoomCtx-Namespace` header (default
`"default"`); auth via `X-LoomCtx-Key: <key>` or `Authorization: Bearer <key>`
(`LoomCtx(url, namespace, api_key=...)` in the SDK); optional `event_id` on any
envelope makes ingestion idempotent (D-014); `/metrics` and `/readyz` for
operations.

### Keys and scoping (D-013/D-013a)

Generate real keys (hashed at rest, plaintext printed once):

```bash
mkdir -p secrets   # yours, not root's: docker would create a missing mount source as root
docker compose run --rm --user "$(id -u):$(id -g)" -v $PWD/secrets:/secrets loomctx \
  python -m loomctx.keys --file /secrets/keys.json generate \
  --id netsec-shipper --namespace netsec --perms w \
  --entity-types host,ip,user --sources auth-log --expires-days 180
```

Then point both the engine and gateway at it: `LOOMCTX_AUTH_FILE=/secrets/keys.json`
(mounted Secret on k8s). Rotation is hot — rewrite the file, no restarts.

Typical grants:
- **Sender/pipeline device:** `--perms w` (+ `--sources`, `--entity-types`) —
  can put data in, can never read anything back.
- **Operator's agent:** `--perms r` scoped to the namespaces/entity types that
  user may see. The agent keeps the full query surface — ask, expand,
  search, `/v1/answer` — it just operates over that user's slice of the
  world (search and auto-resolution return only in-scope entities).
- **LLM spend:** the provider key normally lives server-side; an agent may
  instead send its own via `X-LoomCtx-LLM-Key` per request.

## 3. Python SDK — `sdk/python/`

A thin, typed, dependency-light client. It contains **no logic** — no retries into
semantics, no client-side ranking — just typed transport, so it can never drift from
the server. Target shape:

```python
from loomctx_sdk import LoomCtx

loomctx = LoomCtx("http://localhost:8000", namespace="netsec")

# write side — a pipeline device pushing telemetry
loomctx.claim(
    subject=("host", "web-01"),
    predicate="logged_in_by",
    object=("user", "jdoe"),
    observed_at="2026-09-01T14:03:00Z",
    source="auth-log",
)
loomctx.document(text=report_text, source="ir-pipeline", filename="IR-4432.txt",
              observed_at="2026-09-02T09:00:00Z")

# read side — an app or agent framework without MCP
pack = loomctx.ask(("host", "web-01"), "who logged in this week?", budget=800)
more = loomctx.expand(pack["handles"][0]["id"])

# scoped: a domain and its contents
pack = loomctx.ask(None, "what changed?", scope={
    "subjects": [{"type": "domain", "key": "corp.local"}],
    "expand": ["member_of"], "depth": 1})

# fact time: which host HELD this ip on Aug 20 (vs. as_of = what we knew then)
pack = loomctx.ask(("ip", "10.0.4.7"), "which host?", valid_at="2026-08-20T00:00:00Z")

# declare the domain once; strict namespaces reject unregistered predicates
loomctx.register_schema(
    entity_types=[{"name": "host"}, {"name": "domain"}],
    predicates=[{"name": "member_of", "object_types": ["domain"], "containment": True}])

# retrieval-grounded LLM answer (server has LOOMCTX_LLM_* configured; entities
# named in the question are auto-resolved)
result = loomctx.answer("what do web-01 and web-02 have in common?")
print(result["answer"], result["model"])
```

### Configuring the answering LLM (server side, D-012)

```bash
# OpenRouter                          # Venice
LOOMCTX_LLM_PROVIDER=openrouter          LOOMCTX_LLM_PROVIDER=venice
LOOMCTX_LLM_API_KEY=sk-or-...            LOOMCTX_LLM_API_KEY=...
LOOMCTX_LLM_MODEL=deepseek/deepseek-v3   LOOMCTX_LLM_MODEL=llama-3.3-70b

# Anthropic                           # Self-hosted (Ollama/vLLM/LM Studio)
LOOMCTX_LLM_PROVIDER=anthropic           LOOMCTX_LLM_BASE_URL=http://my-box:11434/v1
LOOMCTX_LLM_API_KEY=sk-ant-...           LOOMCTX_LLM_MODEL=llama3.1:8b
LOOMCTX_LLM_MODEL=claude-sonnet-5
```

### Batch ingest, bulk loading, and other pipelines (D-034)

`POST /v1/ingest/batch` takes a JSON array or NDJSON of envelopes and reports
each item; both SDKs expose it (`ingest_batch` / `ingestBatch`). Log shippers
post to it directly — see `deploy/integrations/` for Vector and Fluent Bit
configs — and `python -m loomctx.ingest file.jsonl --url …` loads files from
any language. Kafka topics feed `python -m loomctx.kafka_consumer`.

### Go SDK — `sdk/go/` (D-034)

```go
c := loomctx.New("http://localhost:8000", "netsec"); c.APIKey = "loomctxk_..."
res, _ := c.IngestBatch(ctx, loomctx.Claim{...}, loomctx.Document{...})
pack, _ := c.Ask(ctx, &loomctx.EntityRef{Type: "host", Key: "web-01"}, "who logged in?", loomctx.AskOptions{Budget: 800})
```

Its envelopes are tested against `contracts/schemas.json`, the schema the
Go gateway enforces. `docker compose --profile sdk run --rm sdk-go`.

### Every other language — `contracts/openapi.json`

```bash
docker run --rm -v "$PWD:/local" openapitools/openapi-generator-cli:v7.10.0 generate \
  -i /local/contracts/openapi.json -g java -o /local/build/loomctx-java   # csharp, kotlin, rust, php, ruby, swift5 ...
```

CI regenerates the document from the app and proves Java and C# generate
cleanly, so a generated client is always current.

### TypeScript SDK — `sdk/typescript/` (D-026)

Same shape, generated types: `src/contracts.ts` is produced from
`contracts/schemas.json` and CI fails if it drifts. Zero runtime
dependencies (platform `fetch`); Node ≥ 18 or any modern runtime.

```ts
import { LoomCtx, LoomCtxError } from "loomctx-sdk";

const loomctx = new LoomCtx("http://localhost:8000", { namespace: "netsec", apiKey: "loomctxk_..." });
await loomctx.claim({ subject: ["host", "web-01"], predicate: "logged_in_by",
                   object: ["user", "jdoe"], observed_at: "2026-09-01T14:03:00Z", source: "auth-log" });
const pack = await loomctx.ask(["host", "web-01"], "who logged in this week?", { budget: 800 });
const held = await loomctx.ask(["ip", "10.0.4.7"], "which host?", { valid_at: "2026-08-20T00:00:00Z" });
const related = await loomctx.semantic("what looks exploitable?");
```

Build/test/regenerate inside Docker: `docker compose --profile sdk run --rm sdk-ts`
(and `... sdk-ts npm run gen` after a contract change).

## 4. CLI — for humans

What ships today are operator modules, each run inside the image
(`docker compose run --rm loomctx python -m loomctx.<module> ...`):

```bash
python -m loomctx.seed load                 # deterministic demo corpus (592 claims, 5 documents)
python -m loomctx.keys generate ...         # mint/list/revoke/update API keys (D-013a); file defaults to secrets/keys.json
python -m loomctx.lifecycle export|import|purge|redact   # backup, migration, retention (D-016)
python -m loomctx.ingest file.jsonl --url … # bulk loader: NDJSON envelopes over HTTP batches or straight into a store (D-034)
python -m loomctx.connectors.vulns load ... # real data: CISA KEV + NVD + EPSS, cached, idempotent (D-035); --offline reloads from the cache
python -m loomctx.enrich run --once         # drain the enrichment backlog (D-018)
python -m loomctx.enrich resolve [--dry-run] # entity resolution only: spelling tiers + LLM-adjudicated aliases (D-042)
python -m loomctx.agent_eval --db ...       # run a real model as an agent over MCP against the store, scored (D-036); --models a,b for the scorecard
python -m loomctx.schemas [openapi]         # export the JSON Schema / OpenAPI the SDKs and CI check against
python -m loomctx.kafka_consumer            # writer consumer for your Kafka/Redpanda topics (D-034)
python -m loomctx.consumer                  # writer consumer for the NATS scale shape (D-010)
python -m loomctx.loadgen --url ...         # measure ingest throughput (D-011)
```

The human-ergonomic `loomctx ask host:web-01 "..."` front-end (see exactly what
an agent would see) is planned, not built; until then `curl` against
`POST /v1/ask` or the Python SDK is the debugging story.

## Choosing a surface

- Building an agent → **MCP**.
- Building a pipeline/device that pushes data → **SDK** (or raw HTTP from anything).
- Operating, exploring, debugging → **CLI**.
- Building a new surface (Slack bot, Kafka consumer) → write an adapter over HTTP;
  that's the malleability contract (see `concepts.md`).
