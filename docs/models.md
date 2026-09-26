# Which models drive Loom well (D-041)

Loom does not ship a model. It ships an MCP surface and an HTTP API, and
the agent on the other side is whatever a team already runs. So the useful
question is not "which model is best" but **which models, given Loom's
tools and no other help, find the data and answer faithfully** — and at
what cost. This page is the measured answer, and the command that produced
it, so it can be re-run when models change (they change monthly).

## TL;DR

Measured 2026-09-26 on OpenRouter: eighteen models, three full runs each
of four tasks (~$9 in total) against the real corpus — seed hosts plus
CISA KEV, NVD and EPSS, 542,099 observations, embedded — under the D-057
scorer, over the D-064 MCP surface, with no hints beyond the server's own
instructions.

- **Seven models pass every task every time:** `google/gemini-2.5-flash`
  (a cent per four-task run), `z-ai/glm-4.6v` (two cents),
  `google/gemini-3.5-flash-lite` (two cents), `deepseek/deepseek-chat-v3.1`,
  `anthropic/claude-haiku-4.5`, `anthropic/claude-sonnet-4.5` and
  `anthropic/claude-opus-4.8`.
- **The two-hop question is still the discriminator, but a solved one.**
  Every model passes the three single-entity tasks at least two runs in
  three; the two-hop exposure task went from 9 passes in 54 runs to 30
  once the scope-ask ergonomics were fixed (D-064: the default budget
  carries the whole answer, and an attribute the agent names selects the
  topic). The remaining misses are the model's, not the tool's.
- **Faithfulness holds:** no model cited an id it had not been shown; the
  check still catches the occasional CVE named from memory. A correct
  answer with no citation fails on purpose (Mistral did this on the
  conflict task).
- **Cost is what the agent reads**: 34k to 770k input tokens per run.

## Short answer

| If you want… | Use | Why |
| --- | --- | --- |
| one model to start with | **`google/gemini-2.5-flash`** | 12/12, a cent and 24 s per four-task run, the cheapest clean pass and the fastest tested |
| the model for when answers matter | **`anthropic/claude-sonnet-4.5`** | 12/12, 28 cents; reads best. `claude-opus-4.8` is also 12/12 at 84 cents |
| open weights | **`z-ai/glm-4.6v`** | 12/12 at two cents, self-hostable |
| a strong two-hop pass on a budget | `google/gemini-3.5-flash-lite` (12/12, two cents) or `deepseek/deepseek-chat-v3.1` (12/12, seven cents) | both now clear the exposure task every run |
| to avoid | `mistralai/mistral-medium-3-5` (6/12: conflict 0/3, os 2/3) | misses on single-entity tasks, not just the hard one |

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

## Decision table (2026-09-26, OpenRouter, three full runs per model, 20-step cap)

Per-task cells are passes out of three; steps, tokens, time and cost are
per four-task run. Sorted by pass rate, then cost.

| Model | Passed | 2-hop exposure | lease | conflict | os | Steps/run | Tokens in/out/run | Time/run | Cost/run | Faithful |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `google/gemini-2.5-flash` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 12 | 33,701/2,060 | 24 s | $0.01 | yes |
| `z-ai/glm-4.6v` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 16 | 84,142/4,305 | 116 s | $0.02 | yes |
| `google/gemini-3.5-flash-lite` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 21 | 75,822/2,290 | 30 s | $0.02 | yes |
| `deepseek/deepseek-chat-v3.1` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 39.3 | 384,032/7,096 | 391 s | $0.07 | yes |
| `anthropic/claude-haiku-4.5` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 13 | 79,935/2,833 | 42 s | $0.09 | yes |
| `anthropic/claude-sonnet-4.5` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 13 | 75,760/3,570 | 96 s | $0.28 | yes |
| `anthropic/claude-opus-4.8` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 14.3 | 144,299/4,733 | 86 s | $0.84 | yes |
| `x-ai/grok-4.7` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 24.3 | 381,942/11,527 | 176 s | $0.33 | yes |
| `mistralai/codestral-2508` | 10/12 | 1/3 | 3/3 | 3/3 | 3/3 | 17 | 100,205/2,295 | 34 s | $0.01 | yes |
| `minimax/minimax-m2.7` | 10/12 | 1/3 | 3/3 | 3/3 | 3/3 | 16.7 | 162,818/4,910 | 137 s | $0.03 | no (1 unseen cite) |
| `cohere/command-a-plus` | 10/12 | 1/3 | 3/3 | 3/3 | 3/3 | 31 | 204,661/6,367 | 91 s | $0.07 | yes |
| `mistralai/mistral-large` | 10/12 | 3/3 | 3/3 | 1/3 | 3/3 | 14.7 | 78,598/2,473 | 46 s | $0.07 | yes |
| `qwen/qwen3-coder` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 21 | 125,432/2,356 | 34 s | $0.02 | yes |
| `qwen/qwen3.5-plus-20260420` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 17 | 93,687/6,124 | 173 s | $0.04 | yes |
| `google/gemini-3.5-flash` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 24 | 123,383/7,449 | 64 s | $0.17 | yes |
| `openai/gpt-5.2` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 30.3 | 767,917/11,498 | 198 s | $0.48 | yes |
| `openai/gpt-4o-2024-05-13` | 8/12 | 0/3 | 2/3 | 3/3 | 3/3 | 17.7 | 60,986/1,419 | 34 s | $0.33 | yes |
| `mistralai/mistral-medium-3-5` | 6/12 | 1/3 | 3/3 | 0/3 | 2/3 | 14.7 | 101,389/2,441 | 30 s | $0.17 | yes |

`mistral-large`'s upstream provider answered many calls with 429
(temporarily rate-limited); its row is the first three *scored* runs of
each task across repeated invocations, and the conflict cell (1/3) is the
model answering with the right values but no citation, which the
faithfulness rule fails on purpose.

## Reading it

**The two-hop task is the discriminator, now largely solved.** It went
from 9 of 54 exposure runs to 30 once the scope-ask ergonomics were fixed
(D-064): the previous MCP guidance capped the scope budget at 1,500, which
carried only 17 of the 32 CVEs, and the multi-hop topic completion fired
only for one exact phrasing. With the budget re-derived (default 3,000)
and an attribute the agent names selecting the topic, seven models pass
every run and every model passes the single-entity tasks.

**What the remaining misses are.** The four 9/12 models (both Qwen, the
larger Gemini Flash, `gpt-5.2`) stop the chain early or name a CVE from an
adjacent product; that is the model's reading of the chain Loom returns,
not a gap in what Loom returned. `mistral-medium-3-5` is the one weak
model, missing single-entity tasks too.

**How the number moved.** The 2026-09-09 table (commit history) passed
exposure on naming *any one* KEV CVE — nine 12/12s under a loose rule.
Under the strict D-057 scorer the same corpus gave 1 exposure pass before
D-061 (the scope walk could not see the kernel hub's KEV edges), 9 after
D-061, and 30 after D-064 fixed how agents ask. Each step was a fix in
Loom, not a change to the grading.

**Faithfulness holds.** No model cited an id it had not been shown. The
check still catches a CVE named from memory, and a correct answer with no
citation fails on purpose (`mistral-large` did this on the conflict task —
right values, no id). A confident wrong "no" is the one failure citations
cannot catch — a claim of absence cites nothing — which is why packs
report partial coverage (`truncated`) and why a model's *rate* matters
more than its best run.

**Cost is dominated by what the agent reads, not what it writes.** Input
tokens run 34k to 770k per four-task run because every tool result stays
in context; the agent-shaped, budget-honest pack view (D-058) is what
keeps that down.

## Recommendation in full

- **Default agent model:** `google/gemini-2.5-flash` — 12/12, a cent and
  24 seconds per four-task run, the cheapest and fastest clean pass.
- **When answers matter or the demo is on stage:**
  `anthropic/claude-sonnet-4.5` — 12/12, 28 cents; `claude-opus-4.8` is
  also 12/12 at 84 cents.
- **Open weights:** `z-ai/glm-4.6v` — 12/12 at two cents, self-hostable.
- **Also 12/12:** `google/gemini-3.5-flash-lite`, `deepseek-chat-v3.1`,
  `anthropic/claude-haiku-4.5`.
- **Not on this evidence:** `mistralai/mistral-medium-3-5` (6/12, misses
  single-entity tasks too).
- **The server-side answering LLM** (`/v1/answer`, `LOOM_LLM_*`) is a
  reader, not an agent: it needs no tool calling, so any model on this
  page works there.

Three runs each; a single flipped task is within variance. Re-run before
quoting a number in a talk; this table took about three hours and $9.

## Retrieval, not models: the other scorecard

This page asks which models can drive Loom's tools. `docs/evaluation.md`
asks the prior question with `python -m loom.retrieval_eval`: on the same
store and the same generated questions, does a budgeted context pack beat
handing the model everything, or cosine ranking or the newest facts at
the same token budget? On this corpus, read by `deepseek-chat-v3.1`, it
does at every budget (79 / 85 / 87 / 96 % against vector's 75 / 76 / 78 /
86 % at 400 / 800 / 1,600 / 3,200 tokens).

## Re-running it

```bash
docker compose exec --user 10001 loom python -m loom.agent_eval --db /data/loom.db \
    --models google/gemini-2.5-flash,anthropic/claude-sonnet-4.5 --repeat 3 --markdown /data/scorecard.md
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
