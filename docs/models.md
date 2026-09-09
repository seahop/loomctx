# Which models drive Loom well (D-037)

Loom does not ship a model. It ships an MCP surface and an HTTP API, and
the agent on the other side is whatever a team already runs. So the useful
question is not "which model is best" but **which models, given Loom's
tools and no other help, find the data and answer faithfully** — and at
what cost. This page is the measured answer, and the command that produced
it, so it can be re-run when models change (they change monthly).

## Short answer

| If you want… | Use | Why |
| --- | --- | --- |
| one model to start with | **`google/gemini-3.5-flash-lite`** | 12/12 on both builds, two cents and 25 s per four-task run, the fastest model tested |
| the same, OpenAI | `openai/gpt-5.6-luna` (12/12, three cents) — `gpt-5.4-nano` is a cent but 11/12 on the current build |
| the same, open weights | **`qwen/qwen3.7-flash`** (12/12, two cents) or `qwen3.7-plus`, `deepseek-v4-pro`, `z-ai/glm-5.2` (all 12/12) | self-hostable; Qwen flash is the cheapest clean pass |
| the model for when answers matter | **`openai/gpt-5.6-sol`** (12/12 on both builds) or `anthropic/claude-haiku-4.5` (12/12 now) | verify and explain; `claude-sonnet-5` is 11/12 on this build with a mangled citation, still the pick for the demo's narrative quality |
| a model to avoid for multi-hop | `z-ai/glm-5.3-flash` (0/3 and invented two CVEs), `moonshotai/kimi-k2.6` (0/3), `google/gemini-3.8-flash` (provider errors in the tool loop), `minimax/minimax-m3` (1/3) | fine for single-entity lookups only |

Measured 2026-09-09 on OpenRouter; the evidence and the command to re-run
it follow. Model ids age fast — five of these did not exist three months ago.

## How it is measured

`python -m loom.agent_eval --models a,b,c --repeat 3 --markdown scorecard.md`
runs each model as an agent over the real MCP transport against the real corpus
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
OpenRouter billed for the run, cache discounts included. The decision
table is three full runs per model, so its cells are pass rates; the
screening table below it is one run per model and is kept as provenance,
not as a verdict.

## Decision table (2026-09-09 evening, current build, three full runs per model, 20-step cap)

Eighteen models, three full runs each, on the build with coverage
warnings (D-038), the corpus embedded with attributed excerpts and
keyword fallback (D-039), and passage search in `find_related` (D-040).
Per-task cells are passes out of three; steps, tokens, time and cost are
per four-task run. Sorted by pass rate, then cost. `claude-opus-5` was
left out on cost (about four dollars per run; its one 30-step run on the
previous build passed) and `llama-4-maverick` because it cannot emit tool
calls through OpenRouter.

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

**How to read it.** Nine models are 12/12 on this build, up from seven
on the previous one; `qwen3.7-flash` (two cents), `grok-4.3`, `glm-5.2`
and `claude-haiku-4.5` all moved up, and `deepseek-v4-flash`, which
answered the two-hop question wrongly with room to spare before, named
all three KEV CVEs in one of its runs. What moved them is the surface,
not the models: attributed excerpts and the KEV advisories in the pack
give a reader more to hold on to than a bare `exploited_in_wild True`.

**Faithfulness: 216 task-runs, two mangled ids, one invention.**
`claude-sonnet-5` and `deepseek-v4-flash` each dropped one character
while hand-copying a 32-hex observation id — an unverifiable citation,
which the check rightly fails; packs now carry a 12-hex `cite` token so
agents copy less. `z-ai/glm-5.3-flash` did something no model had done in
the previous 400-odd runs: it named `CVE-2023-38408` and `CVE-2024-6387`,
real-world OpenSSH CVEs that are not in the store, from its own memory
("probe classic KEV entries"). That is the failure Loom's citations exist
to expose, and the check exposed it.

**The remaining misses.** `gpt-5.4-nano` credited kernel CVEs from an
`affects` list as KEV-listed in one run (2/3, down from 3/3 — treat the
two runs as one flipped sample). `mistral-small-2603` passed the two-hop
task three times and then lost a *lease* run by answering "no host held
the IP" after reading only web-01's expired lease. `gemini-3.8-flash`
hit a Google-side "corrupted thought signature" error on tool
round-trips and answered nothing on three exposure runs — a provider
compatibility problem with the OpenAI-style tool loop, not a retrieval
one. `kimi-k2.6` ran out of steps three times without answering.

**Semantic ranking costs about 300 ms on the first ask of each question**
(one embedding call; repeats are cached) and changes the pack's mix
toward conflicts and excerpts; the per-run times above include it.

## Previous build (2026-09-09 morning, keyword ranking, before D-038–D-040)

Kept as provenance. The same fourteen models, three runs each, on the
build *before* coverage warnings, attributed excerpts, passage search and
semantic ranking — the decision table above supersedes it. Per-task cells are passes out
of three; steps, tokens, time and cost are per four-task run. Sorted by
pass rate, then cost. `claude-opus-5` was left out of the repeats on cost
(about four dollars per run); its one 30-step run passed, see below.

| Model | Passed | 2-hop exposure | lease | conflict | os | Steps/run | Tokens in/out per run | Time/run | Cost/run | Faithful |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `openai/gpt-5.4-nano` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 19.3 | 63,889/1,430 | 36 s | $0.01 | yes |
| `google/gemini-3.5-flash-lite` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 24 | 125,341/1,757 | 24 s | $0.02 | yes |
| `openai/gpt-5.6-luna` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 23.7 | 383,315/3,450 | 67 s | $0.03 | yes |
| `qwen/qwen3.7-plus` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 23 | 504,096/8,418 | 119 s | $0.08 | yes |
| `deepseek/deepseek-v4-pro` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 29.7 | 660,343/11,106 | 206 s | $0.17 | yes |
| `openai/gpt-5.6-sol` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 24 | 354,441/3,756 | 110 s | $0.28 | yes |
| `anthropic/claude-sonnet-5` | 12/12 | 3/3 | 3/3 | 3/3 | 3/3 | 20.3 | 280,330/7,117 | 150 s | $0.63 | yes |
| `qwen/qwen3.7-flash` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 28.7 | 572,344/8,273 | 113 s | $0.02 | yes |
| `openai/gpt-5.4-mini` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 22 | 119,882/1,865 | 39 s | $0.05 | yes |
| `x-ai/grok-4.3` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 20.3 | 92,497/2,914 | 36 s | $0.06 | yes |
| `minimax/minimax-m3` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 20.7 | 359,842/7,653 | 138 s | $0.06 | yes |
| `anthropic/claude-haiku-4.5` | 11/12 | 2/3 | 3/3 | 3/3 | 3/3 | 24.7 | 647,539/5,445 | 91 s | $0.67 | yes |
| `mistralai/mistral-small-2603` | 10/12 | 1/3 | 3/3 | 3/3 | 3/3 | 21.7 | 144,695/1,537 | 29 s | $0.01 | yes |
| `z-ai/glm-5.2` | 10/12 | 1/3 | 3/3 | 3/3 | 3/3 | 22.3 | 440,897/8,011 | 114 s | $0.14 | yes |

**How to read it.** Seven models are 12/12: they answered the two-hop
question correctly three times out of three, with the chain cited. The
single-entity tasks are a solved problem for every model on this page
(42/42 each). Faithfulness was 168/168 task-runs: no invented CVE, no
citation that did not come from a tool result.

**How the 2/3 and 1/3 rows failed.** None ran out of steps. Every miss
was a confident wrong answer: either a false negative ("No — web-01 is not
exposed", from `minimax-m3`, `grok-4.3`, `glm-5.2`) or stopping after
listing the software without following `affects` to the CVEs
(`mistral-small-2603` twice, `qwen3.7-flash`, `claude-haiku-4.5`). That is
the failure mode citations cannot catch — a claim of absence cites
nothing — and it is why a model's *rate* matters more than its best run:
`mistral-small-2603` looked like the cheapest 4/4 in screening and is
1/3 on the task that matters.

**What the repeats changed versus screening.** `gpt-5.4-nano` held 3/3 at
a cent; `mistral-small` fell from 4/4 to 10/12; `gpt-5.6-sol` and
`claude-haiku-4.5`, both step-outs in screening, are 3/3 and 2/3 with a
20-step cap; `gpt-5.4-mini` and `grok-4.3` each dropped one two-hop run.
Three runs still is not many — a 2/3 and a 3/3 are one flipped run apart —
but a 12/12 across three independent runs at a stable cost is a number
you can plan on.

## Recommendation in full

- **Default agent model for Loom demos and small teams:**
  `google/gemini-3.5-flash-lite` — 12/12 on both builds, two cents and
  about 25 seconds per four-task run. `openai/gpt-5.6-luna` (12/12, three
  cents) if you want OpenAI; `openai/gpt-5.4-nano` is a cent and was
  12/12 on the previous build, 11/12 on this one.
- **Open weights, self-hosted:** `qwen/qwen3.7-flash` is the cheapest
  clean pass at two cents; `qwen3.7-plus`, `deepseek/deepseek-v4-pro` and
  `z-ai/glm-5.2` are also 12/12 at nine to eleven cents.
- **When the questions get harder:** `openai/gpt-5.6-sol` (12/12 on both
  builds) or `anthropic/claude-haiku-4.5` (12/12 now, 58 cents).
  `anthropic/claude-sonnet-5` is 11/12 here — one two-hop miss and one
  mangled id — and remains the demo pick for how its answers read.
- **Not for multi-hop on this evidence:** `z-ai/glm-5.3-flash` (0/3, and
  the only model to invent entities), `moonshotai/kimi-k2.6` (0/3),
  `google/gemini-3.8-flash` (provider errors in the tool loop),
  `minimax/minimax-m3` (1/3). All fine for single-entity lookups.
  `llama-4-maverick` cannot call tools via OpenRouter at all.
- **The server-side answering LLM** (`/v1/answer`, `LOOM_LLM_*`) is a
  reader, not an agent: any model on this page works there.

Two builds, three runs each; a single flipped task is still within
variance (nano and Sonnet each flipped one). Expect the table to age —
five of these model ids did not exist three months ago. Re-run before
quoting a number in a talk; the eighteen-model, three-run table cost about
twelve dollars and two hours.

## Screening (one run per model, 14-step cap)

Twenty models across price tiers, one run each, to choose the candidates
above. Single-run numbers: a flipped task here is not a verdict.

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

## Reading the screening

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

**Fourteen steps under-measured thorough models.** Eight models ran out
of the screening's step cap on the two-hop task while still investigating.
Re-run with a 30-step cap, on the exposure task only (before the
three-run table above was measured at the new 20-step default):

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
candidates one by one and needed 13 turns; `gpt-5.6-sol` passed in 10 and
went on to 3/3 in the decision table. The harness default is now 20
steps. Haiku 4.5 passed here at 16 steps but is 2/3 in the decision
table, and that miss was a wrong answer at 20 steps, not a step-out — so
for Haiku the cap was part of the story, not all of it. The four that
still fail here do so by answering wrongly or not at all, and one of them
(`deepseek-v4-flash`) asserted a negative it had not checked — the same
failure mode the decision table's misses show, and the one citations
cannot catch, since a claim of absence cites nothing.

**Cost is dominated by what the agent reads, not what it writes.** Input
tokens run 60k to 800k per four-task run because every tool result stays
in context; that is why the agent view of packs (D-036) mattered more than
any prompt change. Reasoning models show it most: Opus 5 read 680k tokens
to Sonnet 5's 275k for the same tasks.

**`meta-llama/llama-4-maverick` does not emit structured tool calls through
OpenRouter** — it wrote `[describe_namespace(namespace='netsec')]` as text.
Not a Loom problem, but it means 0/4 here; pick a different Llama serving
path if you need that family.

## Re-running it

```bash
docker compose exec --user 10001 loom python -m loom.agent_eval --db /data/loom.db \
    --models openai/gpt-5.4-nano,anthropic/claude-sonnet-5 --repeat 3 --markdown /data/scorecard.md
```

Any OpenAI-compatible endpoint with tool calling works (`LOOM_LLM_*`;
`LOOM_AGENT_MODEL` overrides the model), as does `LOOM_LLM_PROVIDER=anthropic`.
Cost appears only where the provider reports it (OpenRouter does).
`--repeat 3` gives pass rates instead of single samples; a full
fourteen-model, three-run table takes about an hour and a half — run it
detached (`docker compose exec -d … > /data/scorecard.log`).
