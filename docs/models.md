# Which models drive LoomCtx well (D-041)

LoomCtx does not ship a model. It ships an MCP surface and an HTTP API, and
the agent on the other side is whatever a team already runs. So the useful
question is not "which model is best" but **which models, given LoomCtx's
tools and no other help, find the data and answer faithfully** — and at
what cost. This page is the measured answer, and the command that produced
it, so it can be re-run when models change (they change monthly).

## TL;DR

Measured 2026-09-27 on OpenRouter: 36 models attempted, 35 scored, five
full runs each of four tasks (695 scored task-runs, $44), run as GKE Jobs
against the real corpus — seed hosts plus CISA KEV, NVD and EPSS, 542,100
observations, embedded — with no hints beyond the MCP server's own
instructions.

- **Nineteen models pass every task every time.** From a cent per
  four-task run (`google/gemini-2.5-flash`, `openai/gpt-6-luna`) through
  the Anthropic, Google, OpenAI, DeepSeek, Qwen, MiniMax and xAI current
  lines to `anthropic/claude-fable-5.1` at $1.97. Six more miss one run
  in twenty.
- **Single-entity tasks are solved.** Every complete model except
  `llama-4-maverick` (tool-call format, below) passes the lease, conflict
  and OS tasks in at least four runs of five. The two-hop exposure task is
  where models differ, and the misses there are the model's reading — a
  non-KEV CVE listed as part of the exposure, too few of the 32 named —
  not LoomCtx withholding the chain.
- **The faithfulness check holds:** 0 citations to an unseen observation
  in 695 task-runs. Three models named CVE ids that do not exist in the
  store (`qwen3.8-flash` 8 times, `nemotron-3-super` twice,
  `mistral-medium-3-5` once); the check failed those runs.
- **This table replaces the 2026-09-26 one, which undercounted careful
  and reasoning models** (D-089). The harness ran them at a 1,500-token
  output cap on OpenRouter, which hidden thinking spent before an answer,
  and the scorer failed right answers on their wording ("…, not web-01";
  "none are KEV-listed"). `gpt-5.2`, `gemini-3.5-flash` and `qwen3.5-plus`
  were 9/12 there and are 20/20 here.

## Short answer

| If you want… | Use | Why |
| --- | --- | --- |
| one model to start with | **`google/gemini-2.5-flash`** | 20/20, a cent and 22 s per four-task run, the fastest clean pass |
| the cheapest current-generation pass | **`openai/gpt-6-luna`** | 20/20, a cent; `gemini-3.5-flash-lite`, `minimax-m3` and `minimax-m2.7` 20/20 at two cents |
| the model for when answers matter or it is on stage | **`anthropic/claude-sonnet-4.5`** | 20/20 at 35 cents in 13 steps; `claude-sonnet-5`, `claude-opus-5.5`, `claude-opus-4.8` and `claude-fable-5.1` are also 20/20, at 42 cents to $1.97, with no gain on these tasks |
| self-hosted weights | **`z-ai/glm-4.6v`** | 19/20 at two cents |
| to avoid | `meta-llama/llama-4-maverick` via OpenRouter (0/20, tool-call format); `mistral-medium-3-5` (15/20, named a CVE that does not exist) | see the notes under the table |

Model ids age fast. The evidence and the command to re-run it follow.

## How it is measured

`python -m loomctx.agent_eval --models a,b,c --repeat 3 --markdown scorecard.md`
runs each model as an agent over the real MCP transport against the real
corpus (`docs/real-data.md`, embedded with `openai/text-embedding-3-small`
at 512 dimensions). Four tasks, no pre-built scope, no hints beyond the
server's own instructions, a 20-step cap per task:

| Task | What it takes |
| --- | --- |
| **2-hop exposure** | "Is web-01 exposed to anything CISA lists as exploited in the wild?" — discover the schema, resolve the host, `ask_scope` over `runs_software` and `affects`, read the chain, name the CVEs and the software, cite |
| **lease** | which host held 10.0.4.7 on a date — an entity ask with `valid_at` |
| **conflict** | what two scorers say about one CVE's CVSS — read a conflict item, report both sides |
| **os** | which OS web-01 runs — a conflict on the root subject |

Ground truth is computed from the store. Every task requires a faithful
citation: at least one observation id the model saw in a tool result
during that run, and no cited id it did not see (a date such as 20260820
is not taken for an id). Beyond that, a task **passes** when:

- **2-hop exposure** — the answer names at least half of the KEV-listed
  CVEs that reach web-01 (16 of 32 on this corpus; all of them when there
  are four or fewer), no CVE that is not in the store, no real CVE that is
  not KEV-listed for web-01 presented as part of the exposure (naming one
  to rule it out is fine, D-089), and, for each CVE it names, the software it
  reaches web-01 through. The score reports recall and precision.
- **lease** — the first sentence of the answer, asides removed, names the
  host whose lease covers the date and no former holder.
- **conflict** — every value the sources report is named (numbers by
  value, so 17.5 does not count for 7.5).
- **os** — every reported operating system is named.

Cost is what OpenRouter billed, cache discounts included. Calls run at
temperature 0 (dropped for a model that rejects it) with room for 8,000
output tokens per turn, thinking included (D-089). Five full runs per
model, so cells are pass rates. A task the provider failed — rate limit,
5xx, out of credit, an error body — after its retries and one task-level
retry is **not run**: out of the pass rate, never the model's failure, and
a row with any is marked incomplete and ranked last.

## Decision table (2026-09-27, OpenRouter, five full runs per model, 20-step cap)

Per-task cells are passes out of five; steps, tokens, time and cost are
per four-task run. Sorted by pass rate, then cost.

| Model | Passed | 2-hop exposure | lease | conflict | os | Steps/run | Tokens in/out/run | Time/run | Cost/run | Faithful | Not run |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `google/gemini-2.5-flash` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 13 | 44,996/2,172 | 22 s | $0.01 | yes | 0 |
| `openai/gpt-6-luna` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 24.2 | 227,158/5,728 | 69 s | $0.01 | yes | 0 |
| `minimax/minimax-m2.7` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 14 | 90,507/6,470 | 122 s | $0.02 | yes | 0 |
| `google/gemini-3.5-flash-lite` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 21 | 93,652/2,352 | 28 s | $0.02 | yes | 0 |
| `minimax/minimax-m3` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 15.4 | 139,009/9,299 | 77 s | $0.02 | yes | 0 |
| `deepseek/deepseek-v4.1-flash` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 18.2 | 357,567/15,479 | 72 s | $0.05 | yes | 0 |
| `qwen/qwen3.5-plus-20260420` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 19 | 179,767/11,264 | 278 s | $0.07 | yes | 0 |
| `deepseek/deepseek-v4-pro-0813` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 24.4 | 680,244/28,830 | 486 s | $0.10 | yes | 0 |
| `anthropic/claude-haiku-4.5` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 13 | 94,509/2,664 | 42 s | $0.11 | yes | 0 |
| `openai/gpt-6-sol` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 25.6 | 256,754/3,859 | 98 s | $0.19 | yes | 0 |
| `google/gemini-3.8-flash` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 26 | 360,015/15,941 | 172 s | $0.19 | yes | 0 |
| `x-ai/grok-4.7` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 20.2 | 321,775/9,873 | 146 s | $0.27 | yes | 0 |
| `anthropic/claude-sonnet-4.5` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 13.2 | 97,195/4,096 | 104 s | $0.35 | yes | 0 |
| `anthropic/claude-sonnet-5` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 14.8 | 166,039/8,735 | 122 s | $0.42 | yes | 0 |
| `google/gemini-3.5-flash` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 36.6 | 439,004/19,075 | 134 s | $0.43 | yes | 0 |
| `openai/gpt-5.2` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 29 | 544,025/14,581 | 221 s | $0.45 | yes | 0 |
| `anthropic/claude-opus-5.5` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 14.4 | 163,562/5,205 | 93 s | $0.76 | yes | 0 |
| `anthropic/claude-opus-4.8` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 14.2 | 164,307/5,214 | 90 s | $0.95 | yes | 0 |
| `anthropic/claude-fable-5.1` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 14.2 | 160,038/7,339 | 162 s | $1.97 | yes | 0 |
| `mistralai/codestral-2508` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 17 | 117,827/3,700 | 39 s | $0.01 | yes | 0 |
| `z-ai/glm-4.6v` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 14.8 | 89,025/4,332 | 98 s | $0.02 | yes | 0 |
| `z-ai/glm-5.3-flash` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 17.8 | 252,915/23,582 | 524 s | $0.02 | yes | 0 |
| `deepseek/deepseek-chat-v3.1` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 33.2 | 399,929/5,149 | 394 s | $0.07 | yes | 0 |
| `qwen/qwen3.8-max-0902` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 23.6 | 564,643/23,155 | 495 s | $0.52 | yes | 0 |
| `moonshotai/kimi-k3` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 20 | 556,696/15,040 | 186 s | $0.69 | yes | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | 18/20 | 3/5 | 5/5 | 5/5 | 5/5 | 24.2 | 245,427/14,030 | 257 s | $0.03 | no (0 unseen cites, 2 invented) | 0 |
| `qwen/qwen3.8-flash` | 17/20 | 3/5 | 5/5 | 4/5 | 5/5 | 30.6 | 865,422/23,937 | 381 s | $0.04 | no (0 unseen cites, 8 invented) | 0 |
| `amazon/nova-2-lite-v1` | 17/20 | 2/5 | 5/5 | 5/5 | 5/5 | 18.4 | 173,284/3,984 | 37 s | $0.06 | yes | 0 |
| `qwen/qwen3-coder` | 15/20 | 0/5 | 5/5 | 5/5 | 5/5 | 19.2 | 145,273/2,446 | 31 s | $0.04 | yes | 0 |
| `cohere/command-a-plus` | 15/20 | 0/5 | 5/5 | 5/5 | 5/5 | 31.8 | 263,628/6,030 | 60 s | $0.09 | yes | 0 |
| `mistralai/mistral-medium-3-5` | 15/20 | 0/5 | 5/5 | 5/5 | 5/5 | 14.8 | 130,062/2,059 | 34 s | $0.21 | no (0 unseen cites, 1 invented) | 0 |
| `z-ai/glm-5.3` | 15/20 | 0/5 | 5/5 | 5/5 | 5/5 | 15 | 276,396/26,997 | 201 s | $0.23 | yes | 0 |
| `openai/gpt-4o-2024-05-13` | 15/20 | 0/5 | 5/5 | 5/5 | 5/5 | 12 | 47,194/1,344 | 25 s | $0.26 | yes | 0 |
| `meta-llama/llama-4-maverick` ² | 0/20 | 0/5 | 0/5 | 0/5 | 0/5 | 8.2 | 47,804/545 | 33 s | $0.01 | yes | 0 |
| `mistralai/mistral-large` ¹ | 10/15 (incomplete) | 0/5 | 4/4 | 2/2 | 4/4 | 11.8 | 75,680/2,358 | 43 s | $0.05 | yes | 5 |

Not run: tasks the provider failed (rate limit, 5xx, unreachable, an error body) after its retries and one task-level retry — excluded from Passed, never scored as the model's failure.

¹ `mistral-large` and `mistral-small-2603` were rate-limited upstream on
OpenRouter ("temporarily rate-limited upstream") on most calls, in the
main run and again in a retry alone. `mistral-large`'s row pools the first
five *scored* runs of each task across both; `mistral-small-2603` had 2
scored task-runs of 40 attempted and is not listed.

² `llama-4-maverick` makes one real tool call, then writes its next calls
as text in the reply (`[describe_namespace(namespace='netsec')]`), which
reads as a final answer. That is the tool-calling format on OpenRouter's
route for the model, not its reasoning; a provider that parses its native
format may do far better.

## Reading it

**Nineteen clean passes, up from seven.** Two things changed since the
2026-09-26 table. Newer models (GPT-6, Claude Opus 5.5, Sonnet 5 and Fable
5.1, Gemini 3.8, DeepSeek V4, MiniMax M3) joined. And the harness stopped
failing models for it (D-089): at a 1,500-token cap a reasoning model's
hidden thinking ran out before a tool call or an answer, which read as an
empty final answer; and the scorer failed right answers on their wording —
a CVE named to rule it out ("none are KEV-listed"), the former holder
named to reject it ("laptop-17, not web-01"), a sentence ending in a date,
`laptop‑17` with a typographic hyphen. The first 36-model run on the old
harness had 45 empty answers across 16 models and was discarded; every
failure in this table was then read by hand.

**What the remaining misses are.** On the two-hop task: a non-KEV CVE
presented as part of the exposure (`gpt-4o`, `qwen3-coder`,
`nova-2-lite`, one `deepseek-chat-v3.1` run), too few of the 32 KEV CVEs
named (`command-a-plus` names 2 to 15), no citation or an invented CVE
(`mistral-medium-3-5`, `nemotron-3-super`, `qwen3.8-flash`), or the
8,000-token cap (`glm-5.3`, four runs: the one model that still thinks
past it). One `qwen3.8-flash` conflict run asked about a different CVE.
Each is the model's reading of what LoomCtx returned; the same chain was
returned to every model.

**The faithfulness check catches what it should.** In 695 task-runs no
answer cited an id it had not been shown. It also fails a CVE named from
memory — the three "no" rows above — and a correct answer with no citation
fails on purpose. A confident wrong "no" is the one failure citations
cannot catch, which is why packs report partial coverage (`truncated`)
and why a model's *rate* matters more than its best run.

**Cost is what the agent reads, not what it writes.** Input tokens run
45k to 865k per four-task run because every tool result stays in
context. 

## Recommendation in full

- **Default agent model:** `google/gemini-2.5-flash` — 20/20, a cent and
  22 seconds per four-task run.
- **Cheapest current-generation:** `openai/gpt-6-luna` (a cent),
  `google/gemini-3.5-flash-lite` or `minimax/minimax-m3` (two cents).
- **When answers matter or the demo is on stage:**
  `anthropic/claude-sonnet-4.5` — 20/20, 35 cents, fewest steps.
  `claude-sonnet-5`, `claude-opus-5.5`, `claude-opus-4.8` and
  `claude-fable-5.1` are 20/20 too, at 1.2 to six times the cost.
- **Self-hosted weights:** `z-ai/glm-4.6v` — 19/20 at two cents.
- **Not on this evidence:** `meta-llama/llama-4-maverick` through
  OpenRouter (tool calls as text), `mistral-medium-3-5` (15/20, an
  invented CVE).
- **The server-side answering LLM** (`/v1/answer`, `LOOMCTX_LLM_*`) is a
  reader, not an agent: it needs no tool calling, so any model on this
  page works there.

Five runs each; one flipped task is within variance. Re-run before quoting
a number in a talk.

## Retrieval, not models: the other scorecard

This page asks which models can drive LoomCtx's tools. `docs/evaluation.md`
asks the prior question with `python -m loomctx.retrieval_eval`: on the same
store and the same generated questions, does a budgeted context pack beat
handing the model everything, or cosine ranking or the newest facts at
the same token budget? On this corpus, read by `deepseek-chat-v3.1`, it
does at every budget: 77 / 84 / 87 / 96 % against vector's 75 / 76 / 79 /
85 % at 400 / 800 / 1,600 / 3,200 tokens on the 2026-09-27 run on GKE
(earlier runs are recorded in `docs/evaluation.md`, within variance).

## Re-running it

```bash
docker compose exec --user 10001 loomctx python -m loomctx.agent_eval --db /data/loomctx.db \
    --models google/gemini-2.5-flash,anthropic/claude-sonnet-4.5 --repeat 5 --markdown /data/scorecard.md
```

Any OpenAI-compatible endpoint with tool calling works (`LOOMCTX_LLM_*`;
`LOOMCTX_AGENT_MODEL` overrides the model), as does `LOOMCTX_LLM_PROVIDER=anthropic`.
The agent's MCP server needs the embedder the corpus was embedded with
(`LOOMCTX_EMBED_*`). Cost appears only where the provider reports it
(OpenRouter does). A 36-model, five-run table takes about three hours as
six parallel Jobs on a small GKE node pool, each with its own copy of the
corpus, merged afterwards with `scorecard()`. `LOOMCTX_AGENT_MAX_STEPS`
raises the 20-step cap; `LOOMCTX_AGENT_MAX_TOKENS` the 8,000-token output
room per turn.
