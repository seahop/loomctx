# Which models drive Loom well (D-041)

Loom does not ship a model. It ships an MCP surface and an HTTP API, and
the agent on the other side is whatever a team already runs. So the useful
question is not "which model is best" but **which models, given Loom's
tools and no other help, find the data and answer faithfully** — and at
what cost. This page is the measured answer, and the command that produced
it, so it can be re-run when models change (they change monthly).

## TL;DR

Measured 2026-09-24 on OpenRouter: eighteen models, three full runs each
of four tasks (216 task-runs, $13.83 in total) against the real corpus —
seed hosts plus CISA KEV, NVD and EPSS, 542,099 observations, embedded —
under the D-057 scorer, with no hints beyond the server's own
instructions.

- **Two models pass every task every time:** `mistralai/mistral-large`
  (six cents per four-task run) and `anthropic/claude-sonnet-4.5` (81
  cents).
- **The two-hop question is the only discriminator.** Sixteen of the
  eighteen models pass all three single-entity tasks at least two runs in
  three. On the two-hop exposure task only four ever pass (9 passes in 54
  runs).
- **Bigger is not better at the two-hop task.** `claude-opus-4.8` names up
  to 22 of the 32 exposed CVEs but adds CVEs from other products;
  `gpt-5.2` stops after naming zero to two. Both are 9/12.
- **Faithfulness:** no model cited an id it had not been shown, in 216
  runs. Two models named one CVE each from their own memory that is not in
  the store — caught by the check.
- **Cost is what the agent reads**: 25k to 470k input tokens per run.

## Short answer

| If you want… | Use | Why |
| --- | --- | --- |
| one model to start with | **`mistralai/mistral-large`** | 12/12, six cents and 48 s per four-task run; its provider rate-limited it during the run (see below), so plan for retries |
| the model for when answers matter | **`anthropic/claude-sonnet-4.5`** | 12/12 with no rate-limit trouble, 81 cents; reads best |
| cheap single-entity lookups | `google/gemini-2.5-flash` | every single-entity task, one cent and 14 s — but 0/3 on two-hop |
| open weights | `z-ai/glm-4.6v` | 10/12 at four cents, the only open-weights model with a two-hop pass |
| to avoid | `mistralai/mistral-medium-3-5` (5/12, one invented CVE), `mistralai/codestral-2508` (lease 0/3) | misses on single-entity tasks |

Model ids age fast. The evidence and the command to re-run it follow.

## How it is measured

`python -m loom.agent_eval --models a,b,c --repeat 3 --markdown scorecard.md`
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
  not KEV-listed for web-01, and, for each CVE it names, the software it
  reaches web-01 through. The score reports recall and precision.
- **lease** — the first sentence of the answer, asides removed, names the
  host whose lease covers the date and no former holder.
- **conflict** — every value the sources report is named (numbers by
  value, so 17.5 does not count for 7.5).
- **os** — every reported operating system is named.

Cost is what OpenRouter billed, cache discounts included. Calls run at
temperature 0 (dropped for a model that rejects it). Three full runs per
model, so cells are pass rates. A task the provider failed — rate limit,
5xx, out of credit, an error body — after its retries and one task-level
retry is **not run**: out of the pass rate, never the model's failure, and
a row with any is marked incomplete and ranked last.

## Decision table (2026-09-24, OpenRouter, three full runs per model, 20-step cap)

Per-task cells are passes out of three; steps, tokens, time and cost are
per four-task run. Sorted by pass rate, then cost.

| Model | Passed | 2-hop exposure | lease | conflict | os | Steps/run | Tokens in/out/run | Time/run | Cost/run | Faithful |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `mistralai/mistral-large` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 17 | 77,863/2,004 | 48 s | $0.06 | yes |
| `anthropic/claude-sonnet-4.5` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 18.7 | 243,582/4,999 | 126 s | $0.81 | yes |
| `x-ai/grok-4.7` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 26.7 | 472,879/14,791 | 266 s | $0.41 | yes |
| `z-ai/glm-4.6v` | 10/12 | 1/3 | 3/3 | 3/3 | 3/3 | 26.7 | 177,277/4,815 | 146 s | $0.04 | yes |
| `google/gemini-2.5-flash` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 12 | 25,226/815 | 14 s | $0.01 | yes |
| `google/gemini-3.5-flash-lite` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 28.7 | 145,029/2,245 | 39 s | $0.03 | yes |
| `minimax/minimax-m2.7` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 24.7 | 407,524/6,131 | 152 s | $0.04 | no (1 invented) |
| `qwen/qwen3-coder` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 29.7 | 205,283/2,378 | 35 s | $0.05 | yes |
| `deepseek/deepseek-chat-v3.1` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 41.3 | 341,441/4,776 | 326 s | $0.06 | yes |
| `qwen/qwen3.5-plus-20260420` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 22.3 | 236,548/8,455 | 222 s | $0.09 | yes |
| `cohere/command-a-plus` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 37.3 | 272,619/6,402 | 86 s | $0.09 | yes |
| `openai/gpt-4o-2024-05-13` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 13 | 38,671/1,188 | 40 s | $0.21 | yes |
| `anthropic/claude-haiku-4.5` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 18.3 | 248,724/3,785 | 66 s | $0.27 | yes |
| `openai/gpt-5.2` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 30.7 | 427,014/8,705 | 206 s | $0.33 | yes |
| `anthropic/claude-opus-4.8` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 17.3 | 198,182/6,503 | 152 s | $1.15 | yes |
| `google/gemini-3.5-flash` | 8/12 | 0/3 | 3/3 | 3/3 | 2/3 | 36.3 | 297,112/11,440 | 107 s | $0.33 | yes |
| `mistralai/codestral-2508` | 6/12 | 0/3 | 0/3 | 3/3 | 3/3 | 16 | 75,432/1,387 | 24 s | $0.01 | yes |
| `mistralai/mistral-medium-3-5` | 5/12 | 0/3 | 1/3 | 1/3 | 3/3 | 24 | 411,688/3,360 | 79 s | $0.64 | no (1 invented) |

`mistral-large`'s upstream provider answered most of its calls with 429
(temporarily rate-limited) during the eighteen-model run. Each task-run is
independent, so its row is the first three *scored* runs of each task
across three invocations of the same command; the rate-limited attempts
were not run, never scored.

## Reading it

**The two-hop task is the discriminator.** Of 54 exposure runs, 9 passed.
The 45 misses, by first failing rule: 16 named fewer than half of the 32
exposed CVEs (stopped reading the chain early), 13 added a CVE that is
KEV-listed for another product or is not KEV-listed at all, 9 used all 20
steps without answering, 5 named no CVE, and 2 named a CVE that is not in
the store. The single-entity tasks — one ask, one conflict item — are
solved by almost everything with working tool calls.

**Bigger is not better here.** `claude-opus-4.8` found the most (22 of
32 in one run) but padded every answer with two or three CVEs the chain
does not support — an HTTP/2 or Android-kernel KEV entry, an OpenSSL CVE
that is not KEV-listed. `gpt-5.2` answered carefully and briefly: zero to
two CVEs. What passes is reading the chain Loom returns and naming what
it says, no more.

**This is the first table under the strict scorer.** The 2026-09-09
table (commit history) passed the exposure task on naming *any one* KEV
CVE; nine models were 12/12 then. The same corpus-and-task measured before
D-061 (Loom's scope walk could not see most KEV edges on the kernel hub)
gave one exposure pass in the fifteen models that ran; after D-061, nine.

**Faithfulness: 216 task-runs, no unseen citation, two inventions.**
`minimax-m2.7` named `CVE-2022-0586` and `mistral-medium-3-5` named
`CVE-2024-6387` (a real-world OpenSSH CVE), neither in the store — from
memory, and caught because every assertion Loom supports carries an id.
A confident wrong "no" is the one failure citations cannot catch — a
claim of absence cites nothing — which is why packs report partial
coverage (`truncated`) and why a model's *rate* matters more than its
best run.

**Cost is dominated by what the agent reads, not what it writes.** Input
tokens run 25k to 470k per four-task run because every tool result stays
in context; the agent-shaped, budget-honest pack view (D-058) is what
keeps that down.

## Recommendation in full

- **Default agent model:** `mistralai/mistral-large` — 12/12, six cents
  and 48 seconds per four-task run. Its provider rate-limits under load;
  retry, or fall back to Sonnet.
- **When answers matter or the demo is on stage:**
  `anthropic/claude-sonnet-4.5` — 12/12, 81 cents, no provider trouble.
- **Open weights:** `z-ai/glm-4.6v` (10/12, four cents). `qwen3-coder`,
  `qwen3.5-plus` and `deepseek-chat-v3.1` are clean on single-entity
  tasks only.
- **Single-entity lookups on a budget:** `google/gemini-2.5-flash` — one
  cent, 14 seconds, every single-entity task.
- **Not on this evidence:** `mistralai/mistral-medium-3-5` and
  `mistralai/codestral-2508`.
- **The server-side answering LLM** (`/v1/answer`, `LOOM_LLM_*`) is a
  reader, not an agent: it needs no tool calling, so any model on this
  page works there.

Three runs each; a single flipped task is within variance. Re-run before
quoting a number in a talk; this table took about three hours and $14.

## Retrieval, not models: the other scorecard

This page asks which models can drive Loom's tools. `docs/evaluation.md`
asks the prior question with `python -m loom.retrieval_eval`: on the same
store and the same generated questions, does a budgeted context pack beat
handing the model everything, or cosine ranking or the newest facts at
the same token budget? On this corpus, read by `deepseek-chat-v3.1`, it
does at every budget (81 / 84 / 86 / 96 % against vector's 75 / 77 / 79 /
87 % at 400 / 800 / 1,600 / 3,200 tokens).

## Re-running it

```bash
docker compose exec --user 10001 loom python -m loom.agent_eval --db /data/loom.db \
    --models mistralai/mistral-large,anthropic/claude-sonnet-4.5 --repeat 3 --markdown /data/scorecard.md
```

Any OpenAI-compatible endpoint with tool calling works (`LOOM_LLM_*`;
`LOOM_AGENT_MODEL` overrides the model), as does `LOOM_LLM_PROVIDER=anthropic`.
The agent's MCP server needs the embedder the corpus was embedded with
(`LOOM_EMBED_*`). Cost appears only where the provider reports it
(OpenRouter does). `--repeat 3` gives pass rates instead of single
samples; a full eighteen-model, three-run table takes about three hours —
run it detached (`docker compose exec -d … > /data/scorecard.log`).
`LOOM_AGENT_MAX_STEPS` raises the 20-step cap if a model needs more room
to verify.
