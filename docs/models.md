# Which models drive Loom well (D-041)

Loom does not ship a model. It ships an MCP surface and an HTTP API, and
the agent on the other side is whatever a team already runs. So the useful
question is not "which model is best" but **which models, given Loom's
tools and no other help, find the data and answer faithfully** — and at
what cost. This page is the measured answer, and the command that produced
it, so it can be re-run when models change (they change monthly).

## TL;DR

Measured 2026-09-09 on OpenRouter: eighteen models, three full runs each
of four tasks against a real corpus (CISA KEV + NVD + EPSS, 465k
observations), no hints beyond the server's own instructions.

- **Nine models pass every task every time**, from two cents to fifty-eight
  cents per four-task run.
- **Start with `google/gemini-3.5-flash-lite`**: 12/12, two cents, 25
  seconds per run, the fastest model tested.
- **Open weights:** `qwen/qwen3.7-flash` is 12/12 at two cents; `qwen3.7-plus`,
  `deepseek-v4-pro` and `z-ai/glm-5.2` are also clean.
- **When answers matter:** `openai/gpt-5.6-sol` or `anthropic/claude-haiku-4.5`,
  both 12/12. `claude-sonnet-5` is 11/12 and still reads best.
- **Faithfulness:** 216 task-runs, no model invented a citation. Two
  models mangled one hand-copied 32-hex id each (now a 12-hex `cite`
  token), and one model (`glm-5.3-flash`) named two CVEs from its own
  memory that are not in the store — the failure Loom's citations exist
  to expose, caught by the check.
- **The two-hop question is the only discriminator.** Every model with
  working tool calls passed the three single-entity tasks.
- **Cost is what the agent reads, not what it writes**: 70k to 720k input
  tokens per run, so the agent-shaped pack view matters more than any
  prompt tweak.

## Short answer

| If you want… | Use | Why |
| --- | --- | --- |
| one model to start with | **`google/gemini-3.5-flash-lite`** | 12/12, two cents and 25 s per four-task run, the fastest model tested |
| the same, OpenAI | `openai/gpt-5.6-luna` (12/12, three cents) | `gpt-5.4-nano` is a cent but 11/12 |
| the same, open weights | **`qwen/qwen3.7-flash`** (12/12, two cents) or `qwen3.7-plus`, `deepseek-v4-pro`, `z-ai/glm-5.2` (all 12/12) | self-hostable; Qwen flash is the cheapest clean pass |
| the model for when answers matter | **`openai/gpt-5.6-sol`** (12/12) or `anthropic/claude-haiku-4.5` (12/12) | verify and explain; `claude-sonnet-5` is 11/12 with one mangled citation, still the pick for the demo's narrative quality |
| a model to avoid for multi-hop | `z-ai/glm-5.3-flash` (0/3 and invented two CVEs), `moonshotai/kimi-k2.6` (0/3), `google/gemini-3.8-flash` (provider errors in the tool loop), `minimax/minimax-m3` (1/3) | fine for single-entity lookups only |

Model ids age fast — five of these did not exist three months ago. The
evidence and the command to re-run it follow. The corpus gained alias
merges after this table was measured (D-042: the two-hop task now has 29
target CVEs instead of 3), so a re-run will not be identical.

## How it is measured

`python -m loom.agent_eval --models a,b,c --repeat 3 --markdown scorecard.md`
runs each model as an agent over the real MCP transport against the real
corpus (`docs/real-data.md`: the seed hosts plus CISA KEV, NVD and EPSS,
embedded). Four tasks, no pre-built scope, no hints beyond the server's
own instructions:

| Task | What it takes |
| --- | --- |
| **2-hop exposure** | "Is web-01 exposed to anything CISA lists as exploited in the wild?" — discover the schema, resolve the host, `ask_scope` with `expand_predicates=[runs_software, affects]`, read the chain, name the CVEs and the software, cite |
| **lease** | which host held 10.0.4.7 on a date — an entity ask with `valid_at` |
| **conflict** | what two scorers say about one CVE's CVSS — read a conflict item, report both sides |
| **os** | which OS web-01 runs — a conflict on the root subject |

A task **passes** only if the right entities are named, none are invented,
and every id the model cites appeared in a tool result during that run
("faithful"). Ground truth is computed from the store. Cost is what
OpenRouter billed for the run, cache discounts included. Three full runs
per model, so cells are pass rates; a single flipped task is within
run-to-run variance, a 12/12 across three independent runs at a stable
cost is a number you can plan on.

## Decision table (2026-09-09, OpenRouter, three full runs per model, 20-step cap)

Per-task cells are passes out of three; steps, tokens, time and cost are
per four-task run. Sorted by pass rate, then cost. `claude-opus-5` was
left out on cost (about four dollars per run; a single run passed) and
`llama-4-maverick` because it writes tool calls as text through
OpenRouter and cannot use the tools at all.

| Model | Passed | 2-hop exposure | lease | conflict | os | Steps/run | Tokens in/out/run | Time/run | Cost/run | Faithful |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `google/gemini-3.5-flash-lite` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 24 | 121,764/1,561 | 25 s | $0.02 | yes |
| `qwen/qwen3.7-flash` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 28.7 | 616,042/9,291 | 117 s | $0.02 | yes |
| `openai/gpt-5.6-luna` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 22.7 | 260,846/3,370 | 70 s | $0.03 | yes |
| `x-ai/grok-4.3` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 19.7 | 81,592/3,063 | 32 s | $0.06 | yes |
| `qwen/qwen3.7-plus` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 23.7 | 584,689/9,654 | 127 s | $0.09 | yes |
| `deepseek/deepseek-v4-pro` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 23 | 299,897/7,725 | 127 s | $0.10 | yes |
| `z-ai/glm-5.2` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 20.3 | 153,124/5,288 | 74 s | $0.11 | yes |
| `openai/gpt-5.6-sol` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 25.3 | 429,815/4,613 | 122 s | $0.35 | yes |
| `anthropic/claude-haiku-4.5` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 22 | 552,433/4,696 | 77 s | $0.58 | yes |
| `mistralai/mistral-small-2603` | 11/12 | 3/3 | 2/3 | 3/3 | 3/3 | 22 | 131,818/2,258 | 35 s | $0.01 | yes |
| `openai/gpt-5.4-nano` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 20.7 | 68,008/1,556 | 34 s | $0.01 | yes |
| `deepseek/deepseek-v4-flash` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 26 | 351,325/7,995 | 108 s | $0.01 | no (1 unseen cites, 0 invented) |
| `openai/gpt-5.4-mini` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 23.7 | 160,675/1,833 | 46 s | $0.06 | yes |
| `anthropic/claude-sonnet-5` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 21 | 393,012/8,274 | 133 s | $0.87 | no (1 unseen cites, 0 invented) |
| `minimax/minimax-m3` | 10/12 | 1/3 | 3/3 | 3/3 | 3/3 | 21.7 | 327,391/8,616 | 65 s | $0.05 | yes |
| `z-ai/glm-5.3-flash` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 30 | 508,193/6,008 | 224 s | $0.03 | no (0 unseen cites, 2 invented) |
| `moonshotai/kimi-k2.6` | 9/12 | 0/3 | 3/3 | 3/3 | 3/3 | 33.3 | 724,545/9,062 | 216 s | $0.21 | yes |
| `google/gemini-3.8-flash` | 8/12 | 0/3 | 3/3 | 3/3 | 2/3 | 28.3 | 554,428/7,564 | 126 s | $0.17 | yes |

## Reading it

**The two-hop task is the discriminator.** Every model that emits
structured tool calls passed the single-entity tasks (lease, conflict, os)
at one to a few cents; `mistral-small`'s one lease miss was a "no host
held the IP" after reading only an expired lease. What separates the
field is whether a model, told nothing but the server's instructions,
reads `describe_namespace`, calls `ask_scope` with
`expand_predicates=[runs_software, affects]`, and trusts the chain and
the attributed advisory excerpt it gets back.

**Faithfulness: 216 task-runs, two mangled ids, one invention.**
`claude-sonnet-5` and `deepseek-v4-flash` each dropped one character
while hand-copying a 32-hex observation id — an unverifiable citation,
which the check rightly fails; packs now carry a 12-hex `cite` token so
agents copy less. `z-ai/glm-5.3-flash` named `CVE-2023-38408` and
`CVE-2024-6387`, real-world OpenSSH CVEs that are not in the store, from
its own memory ("probe classic KEV entries"). Nothing else across the
eighteen models invented an entity or a citation: the discipline is
Loom's, not the model's — every item carries an id, so an assertion
without one stands out.

**How the misses fail.** Never by running out of steps at the cap; by
answering wrongly with room to spare. `gpt-5.4-nano` credited kernel CVEs
from an `affects` list as KEV-listed in one run (2/3 — one flipped
sample). `gemini-3.8-flash` hit a Google-side "corrupted thought
signature" error on tool round-trips and answered nothing on three
exposure runs — a provider compatibility problem with the OpenAI-style
tool loop, not a retrieval one. `kimi-k2.6` ran out of steps three times
without answering. A confident wrong "no" is the one failure citations
cannot catch — a claim of absence cites nothing — which is why packs
report partial coverage (`truncated`) and why a model's *rate* matters
more than its best run.

**Cost is dominated by what the agent reads, not what it writes.** Input
tokens run 70k to 720k per four-task run because every tool result stays
in context; that is why the agent-shaped pack view (items first, no
nulls, subjects summarized) mattered more than any prompt change.
Semantic ranking adds about 300 ms to the first ask of each question (one
embedding call; repeats are cached); the times above include it.

## Recommendation in full

- **Default agent model for Loom demos and small teams:**
  `google/gemini-3.5-flash-lite` — 12/12, two cents and about 25 seconds
  per four-task run. `openai/gpt-5.6-luna` (12/12, three cents) if you
  want OpenAI; `openai/gpt-5.4-nano` is a cent and 11/12.
- **Open weights, self-hosted:** `qwen/qwen3.7-flash` is the cheapest
  clean pass at two cents; `qwen3.7-plus`, `deepseek/deepseek-v4-pro` and
  `z-ai/glm-5.2` are also 12/12 at nine to eleven cents.
- **When the questions get harder:** `openai/gpt-5.6-sol` (12/12) or
  `anthropic/claude-haiku-4.5` (12/12, 58 cents). `anthropic/claude-sonnet-5`
  is 11/12 — one two-hop miss and one mangled id — and remains the demo
  pick for how its answers read.
- **Not for multi-hop on this evidence:** `z-ai/glm-5.3-flash` (0/3, and
  the only model to invent entities), `moonshotai/kimi-k2.6` (0/3),
  `google/gemini-3.8-flash` (provider errors in the tool loop),
  `minimax/minimax-m3` (1/3). All fine for single-entity lookups.
  `llama-4-maverick` cannot call tools via OpenRouter at all.
- **The server-side answering LLM** (`/v1/answer`, `LOOM_LLM_*`) is a
  reader, not an agent: it needs no tool calling, so any model on this
  page works there.

Three runs each; a single flipped task is within variance. Expect the
table to age — five of these model ids did not exist three months ago.
Re-run before quoting a number in a talk; the eighteen-model, three-run
table cost about twelve dollars and two hours.

## Re-running it

```bash
docker compose exec --user 10001 loom python -m loom.agent_eval --db /data/loom.db \
    --models google/gemini-3.5-flash-lite,anthropic/claude-sonnet-5 --repeat 3 --markdown /data/scorecard.md
```

Any OpenAI-compatible endpoint with tool calling works (`LOOM_LLM_*`;
`LOOM_AGENT_MODEL` overrides the model), as does `LOOM_LLM_PROVIDER=anthropic`.
Cost appears only where the provider reports it (OpenRouter does).
`--repeat 3` gives pass rates instead of single samples; a full
eighteen-model, three-run table takes about two hours — run it detached
(`docker compose exec -d … > /data/scorecard.log`). `LOOM_AGENT_MAX_STEPS`
raises the 20-step cap if a model needs more room to verify.
