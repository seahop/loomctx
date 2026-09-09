# Which models drive Loom well (D-037)

Loom does not ship a model. It ships an MCP surface and an HTTP API, and
the agent on the other side is whatever a team already runs. So the useful
question is not "which model is best" but **which models, given Loom's
tools and no other help, find the data and answer faithfully** — and at
what cost. This page is the measured answer, and the command that produced
it, so it can be re-run when models change (they change monthly).

## How it is measured

`python -m loom.agent_eval --models a,b,c --markdown scorecard.md` runs each
model as an agent over the real MCP transport against the real corpus
(`docs/real-data.md`: the seed hosts plus CISA KEV, NVD and EPSS). Four
tasks, no pre-built scope, no hints beyond the server's own instructions:

| Task | What it takes |
| --- | --- |
| **2-hop exposure** | "Is web-01 exposed to anything CISA lists as exploited in the wild?" — discover the schema, resolve the host, `ask_scope` with `expand_predicates=[runs_software, affects]`, read the chain, name the CVEs and the software, cite |
| **lease** | which host held 10.0.4.7 on a date — an entity ask with `valid_at` |
| **conflict** | what two scorers say about one CVE's CVSS — read a conflict item, report both sides |
| **os** | which OS web-01 runs — a conflict on the root subject |

A task **passes** only if the right entities are named, none are invented,
and every id the model cites appeared in a tool result during that run
("faithful"). Ground truth is computed from the store. Cost is what
OpenRouter billed for the run, cache discounts included. One run per
model — treat single-run differences of one task as noise; the pattern
across tiers is the signal.

## Scorecard (2026-09-09, OpenRouter, one run per model)

| Model | Passed | 2-hop exposure | lease | conflict | os | Steps | Tokens in/out | Time | Cost | Faithful |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `mistralai/mistral-small-2603` | 4/4 | pass | pass | pass | pass | 19 | 88,043/1,559 | 24 s | $0.01 | yes |
| `openai/gpt-5.4-nano` | 4/4 | pass | pass | pass | pass | 20 | 59,203/1,536 | 31 s | $0.01 | yes |
| `google/gemini-3.5-flash-lite` | 4/4 | pass | pass | pass | pass | 24 | 157,777/1,681 | 25 s | $0.03 | yes |
| `openai/gpt-5.6-luna` | 4/4 | pass | pass | pass | pass | 26 | 332,807/3,074 | 69 s | $0.03 | yes |
| `minimax/minimax-m3` | 4/4 | pass | pass | pass | pass | 21 | 281,124/7,637 | 99 s | $0.04 | yes |
| `openai/gpt-5.4-mini` | 4/4 | pass | pass | pass | pass | 23 | 135,947/1,381 | 44 s | $0.05 | yes |
| `x-ai/grok-4.3` | 4/4 | pass | pass | pass | pass | 21 | 95,348/3,374 | 46 s | $0.07 | yes |
| `qwen/qwen3.7-plus` | 4/4 | pass | pass | pass | pass | 23 | 646,957/9,769 | 124 s | $0.10 | yes |
| `deepseek/deepseek-v4-pro` | 4/4 | pass | pass | pass | pass | 24 | 457,741/9,142 | 152 s | $0.13 | yes |
| `z-ai/glm-5.2` | 4/4 | pass | pass | pass | pass | 19 | 342,571/7,404 | 76 s | $0.35 | yes |
| `anthropic/claude-sonnet-5` | 4/4 | pass | pass | pass | pass | 18 | 274,625/6,944 | 148 s | $0.62 | yes |
| `deepseek/deepseek-v4-flash` | 3/4 | fail† | pass | pass | pass | 30 | 496,837/6,802 | 313 s | $0.02 | yes |
| `qwen/qwen3.7-flash` | 3/4 | fail† | pass | pass | pass | 25 | 484,550/6,152 | 83 s | $0.02 | yes |
| `z-ai/glm-5.3-flash` | 3/4 | fail | pass | pass | pass | 17 | 191,427/7,952 | 209 s | $0.03 | yes |
| `google/gemini-3.8-flash` | 3/4 | fail† | pass | pass | pass | 24 | 341,841/7,328 | 127 s | $0.12 | yes |
| `moonshotai/kimi-k2.6` | 3/4 | fail† | pass | pass | pass | 28 | 473,608/7,498 | 159 s | $0.14 | yes |
| `openai/gpt-5.6-sol` | 3/4 | fail† | pass | pass | pass | 26 | 477,473/4,704 | 119 s | $0.34 | yes |
| `anthropic/claude-haiku-4.5` | 3/4 | fail† | pass | pass | pass | 24 | 422,141/3,732 | 58 s | $0.44 | yes |
| `anthropic/claude-opus-5` | 3/4 | fail† | pass | pass | pass | 25 | 680,494/13,150 | 247 s | $3.73 | yes |
| `meta-llama/llama-4-maverick` | 0/4 | fail | fail | fail | fail | 7 | 22,659/539 | 34 s | $0.00 | — |

† ran out of the 14-step cap while still investigating, not a wrong
answer — see the retest below. Cost is the whole four-task run as billed.

## Reading it

**The two-hop task is the discriminator.** Every model that emits
structured tool calls passed the three single-entity tasks (lease,
conflict, os) with faithful citations, at one to a few cents. What
separates the field is whether a model, told nothing but the server's
instructions, reads `describe_namespace`, calls `ask_scope` with
`expand_predicates=[runs_software, affects]`, and trusts the chain it gets
back.

**Faithfulness held across the board.** Twenty models, zero invented CVEs,
zero citations that did not come from a tool result. The cited-id
discipline is Loom's, not the model's: the pack hands every item an
observation id, and no model in this set made one up.

**Fourteen steps under-measures thorough models.** Eight models ran out
of the step cap on the two-hop task while still investigating. Re-run
with a 30-step cap, on the exposure task only:

| Model | 2-hop exposure at 30 steps | Steps | Tokens in/out | Time | Cost |
| --- | --- | --- | --- | --- | --- |
| `openai/gpt-5.6-sol` | **pass** | 10 | 186,280/2,300 | 63 s | $0.15 |
| `anthropic/claude-opus-5` | **pass** | 13 | 803,225/10,996 | 207 s | $4.29 |
| `anthropic/claude-haiku-4.5` | **pass** | 16 | 500,602/3,389 | 98 s | $0.52 |
| `qwen/qwen3.7-flash` | **pass** | 17 | 632,065/6,961 | 85 s | $0.02 |
| `z-ai/glm-5.3-flash` | fail (gave up, 7 steps) | 7 | 110,137/4,798 | 133 s | $0.01 |
| `deepseek/deepseek-v4-flash` | fail (concluded no KEV data exists — false) | 21 | 1,122,130/6,735 | 309 s | $0.05 |
| `google/gemini-3.8-flash` | fail (never reached an answer) | 22 | 799,802/9,586 | 191 s | $0.17 |
| `moonshotai/kimi-k2.6` | fail (never reached an answer) | 17 | 833,125/10,259 | 316 s | $0.25 |

So the capable models were being thorough, not lost: Opus 5 verified
candidates one by one and needed 13 turns; Haiku 4.5 passed in an earlier
run at 13 steps and here at 16 — variance around the cap, not a
capability gap. The harness default is now 20 steps. The four that still
fail do so by answering wrongly or not at all, and one of them
(`deepseek-v4-flash`) asserted a negative it had not checked — the one
failure mode citations cannot catch, since a claim of absence cites nothing.

**Cost is dominated by what the agent reads, not what it writes.** Input
tokens run 60k to 800k per four-task run because every tool result stays
in context; that is why the agent view of packs (D-036) mattered more than
any prompt change. Reasoning models show it most: Opus 5 read 680k tokens
to Sonnet 5's 275k for the same tasks.

**`meta-llama/llama-4-maverick` does not emit structured tool calls through
OpenRouter** — it wrote `[describe_namespace(namespace='netsec')]` as text.
Not a Loom problem, but it means 0/4 here; pick a different Llama serving
path if you need that family.

## Recommendation

- **Default agent model for Loom demos and small teams:**
  `openai/gpt-5.4-nano` or `mistralai/mistral-small-2603` — 4/4, faithful,
  a cent per four-task run, under a minute. `google/gemini-3.5-flash-lite`
  and `openai/gpt-5.4-mini` are the next tier up at three to five cents.
- **When the questions get harder** (deeper scopes, more verification):
  `anthropic/claude-sonnet-5` (4/4, fewest steps of any model at 18) or
  `openai/gpt-5.6-sol`; `anthropic/claude-haiku-4.5` if you want Claude
  at a fifth of the price and can give it twenty steps.
- **Avoid as agents over Loom, on this evidence:** `z-ai/glm-5.3-flash`,
  `deepseek/deepseek-v4-flash`, `google/gemini-3.8-flash`,
  `moonshotai/kimi-k2.6` for multi-hop questions (fine for single-entity
  lookups), and `meta-llama/llama-4-maverick` via OpenRouter at all.
- **The server-side answering LLM** (`/v1/answer`, `LOOM_LLM_*`) is a
  reader, not an agent: it needs no tool calling, so any model in the
  table works there; the cheap 4/4 models are the sensible default.

One run per model; a single flipped task is within run-to-run variance
(Haiku 4.5 passed the two-hop task in two of three runs). Re-run before
quoting a number in a talk, and expect the table to age: five of these
model ids did not exist three months ago.

## Re-running it

```bash
docker compose exec --user 10001 loom python -m loom.agent_eval --db /data/loom.db \
    --models anthropic/claude-haiku-4.5,openai/gpt-5.4-mini --markdown /data/scorecard.md
```

Any OpenAI-compatible endpoint with tool calling works (`LOOM_LLM_*`;
`LOOM_AGENT_MODEL` overrides the model), as does `LOOM_LLM_PROVIDER=anthropic`.
Cost appears only where the provider reports it (OpenRouter does).
