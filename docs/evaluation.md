# Retrieval evaluation: is a context pack better than the alternatives?

`docs/models.md` measures which *models* can drive LoomCtx. This page measures
LoomCtx itself: on the same store and the same questions, does a budgeted,
cited context pack let a model answer better — and cheaper — than handing
it everything, than cosine ranking or the newest facts at the same token
budget? The harness is `python -m loomctx.retrieval_eval` (hardening row R-6);
it runs in CI against a rule-based reader and live against any model
`LOOMCTX_LLM_*` configures.

## Running it

```bash
# the seed corpus, no model, no network: the rule-based reader
docker compose run --rm loomctx sh -c 'python -m loomctx.seed load --db /tmp/t.db && \
    python -m loomctx.retrieval_eval --db /tmp/t.db --scripted'

# the real corpus (docs/real-data.md) with the configured model, three runs
docker compose exec --user 10001 loomctx python -m loomctx.retrieval_eval --db /data/loomctx.db \
    --runs 3 --out /data/eval/retrieval.md --json /data/eval/retrieval.json

# what would be asked, with the ground truth, and nothing else
docker compose exec loomctx python -m loomctx.retrieval_eval --db /data/loomctx.db --list-questions
```

Options that matter: `--budgets 400,800,1600,3200` (the budgets B of the
`loomctx@B`, `vector@B` and `recency@B` conditions), `--conditions
loomctx,vector,recency,full`, `--families lease,conflict,...`, `--runs N`
(repeat everything, report mean ± standard deviation), `--seed 7` (which
questions get generated), `--per-family 8`, `--reference-time ISO` (the
instant conflict questions are asked at; default derived from the store),
`--full-cap 100000` (a `full` context above this many estimated tokens is
measured but not sent), `--max-cost 1.0` (live calls stop past this many
dollars, where the provider reports cost — OpenRouter does; see below),
`--max-tokens 2048` (completion cap; a reasoning model thinks inside it),
`--reasoning-effort low` (OpenRouter's reasoning effort, for reasoning
models), `--model` (overrides `LOOMCTX_LLM_MODEL`), `--canned FILE` (a JSON
map of question id to reply, for tests). Live calls run at temperature 0
(dropped, once, for a model that rejects the parameter). The table is
printed and written to `--out` (default `eval/retrieval-<date>.md`); every
row is appended to the same path with `.jsonl` *as it completes*, so a
crash or a killed run keeps everything already paid for; `--json` writes
every question, reply and score at the end. The vector baseline needs an
embedder (`LOOMCTX_EMBED_*`; `LOOMCTX_EMBED_PROVIDER=hashing` is the offline one)
and is skipped with a note otherwise; the `loomctx` conditions use the same
embedder when it is set, exactly as the serving engine does. The question
embedding is retried (a stalled embedder used to end a paid run), and a
context that cannot be built is one error row, not a crash.

**Rows that were never answered are not wrong answers.** A `full` context
over `--full-cap`, a row past `--max-cost`, a provider error, an empty
reply, a reply cut at `--max-tokens` (`finish_reason: length`) or a context
that failed to build is recorded with its reason, counted per condition as
*not sent / errored*, and left out of every denominator — it used to score
as a failure, and an empty reply to an abstention question as a correct
`unknown`. When `--max-cost` trips, the scorecard opens with an
**INCOMPLETE** banner, stderr says so, and the process exits with status 3:
the conditions are then compared on different question subsets, so the
table must not be quoted. To size `--max-cost`, run `--scripted` first: its
`Tokens est` column times the number of rows is the input you will pay for.

## The conditions

Every condition renders its context the way `/v1/answer` does
(`answer.render_user_prompt`: one cited line per item inside a delimited
block), sends the same system prompt and the same question to the same
model, and is scored by the same rules.

| Condition | What the model sees |
| --- | --- |
| `loomctx@B` | `build_pack` at budget B, with the question's `as_of` / `valid_at` axis and scope: ranked, conflicts first, chains before the facts they reach, trimmed to B tokens |
| `vector@B` | the observations from the candidate set ranked by cosine of the question against the rendered fact, nothing else, filled to the same budget B |
| `recency@B` | the newest observations from the candidate set, filled to budget B |
| `full` | the whole candidate set, newest first, no time axis: the "just give it everything" baseline — its token count is the honest cost of not retrieving |

**Equal tokens.** The budgeted baselines are filled to B with the pack
builder's own accounting (`context.item_tokens`: the item text plus its
citation), so each row of `vector@B` and `recency@B` holds as much evidence
as `loomctx@B` may. They used to be a fixed top-20 (about 320 tokens) against
packs of up to 3,200, which compared ranking at unequal cost. The table is
budget-major — `loomctx@400`, `vector@400`, `recency@400`, `loomctx@800`, … — so
each group of three is a comparison at the same budget.

**The candidate set is uncapped.** The baselines walk the question's scope
and gather every observation of every entity it reaches, with no per-entity
limit (`walk_scope`, `candidate_observations`). LoomCtx's own condition keeps
the product's behavior: the scope walk and the pack see the newest 1,000
observations per entity (D-038), plus — when the question names an
attribute of the entities behind a hub the cap cut — the hub's edges to
the entities that carry it, whatever their age (D-061: the Linux kernel
product has 2,785 `affects` edges and its KEV entries are the oldest, so
before D-061 all six KEV questions were outside LoomCtx's reach at any
budget). Every question records whether its truth is inside LoomCtx's gather
(`in_loomctx_gather`, computed with the product's own question-aware walk);
the scorecard lists the ones that are not, and `--list-questions` marks
them `OUTSIDE-LOOMCTX-GATHER`. That is a product limitation reported, not
hidden: the pack says so to the reader (a `coverage:` line), but the
answer is not in it.

A scope pack renders siblings the walk reached through one edge that share
the named attribute's value as one item per four (D-061) — `cve:A (date),
cve:B (date) exploited_in_wild True (per cisa-kev, valid from each date);
each affects product:linux:linux_kernel`, citing each fact and each edge —
and the rule-based reader reads such an item back fact by fact.

The baselines get no time filtering on purpose: the question states the
date, and reading validity windows and observation dates out of the text is
what a model without LoomCtx's axes would have to do.

## The question families

Questions are generated from the store with a fixed seed, and every ground
truth is computed from the observations at generation time — the same
discipline as `agent_eval` (D-036): nothing is hard-coded, so the harness
runs unchanged on the seed corpus and on the real one, and a store that
changes changes the answers with it. `--list-questions` shows the set.

| Family | What it tests | Ground truth | Correct answer shape |
| --- | --- | --- | --- |
| **lease** | knowledge update over time: which host held an IP at T. `valid_at` variant (what was true at T) and `as_of` variant (what was known by T). Every other host the address was ever assigned to is a *wrong* answer, not history. Reassigned addresses are chosen first. | the `assigned_to` observation whose validity window covers T; for `as_of`, among those observed by T | `host:<key>`, as a whole token; history in an aside — `laptop-17 (moved from web-01)` — is not graded, a second host outside one is |
| **conflict** | conflict awareness: a scalar predicate where two sources disagree, asked *as of* a reference instant (the newest observation about the sampled entities, or `--reference-time`) so the set does not drift with the wall clock; `loomctx@B` gets the same instant as `as_of` | the distinct values, newest observation per value, at that instant | every value named (numbers by value); the word "conflict" alone never passes |
| **multihop** | with the vulns corpus (`docs/real-data.md`): which KEV-listed CVEs reach a host through `runs_software -> affects` (the two-hop `ask_scope`). On the seed: alert -> host -> domain, and alert -> host -> the users who logged in that day | walked from the store without the pack builder's gather cap | the exact set of ids |
| **abstention** | an entity that does not exist (shaped like ones that do) and a predicate nobody ever recorded on an entity that does. The only right answer is `unknown`; anything else is a hallucination — the failure the category's benchmarks punish and the one citations cannot catch on their own | verified absent from the store | `unknown` |
| **numeric** | a number: a single-valued fact (a port, an EPSS score), the value one named source reported where scorers disagree (CVSS by scorer), or the largest of a series (the biggest invoice — an aggregate the whole series must be present for) | the observation's value | the number, within half a unit in the last decimal place it was recorded with (41234.56 ± 0.005, an EPSS score of 0.00043 ± 0.000005), with a one-part-per-billion floor for float noise |
| **order** | temporal ordering: which of two facts about one entity was observed first, with the dates stripped from the question. Predicates from a snapshot feed — every observation stamped with one day across three or more entities, like EPSS scores — are left out: "the EPSS score is the newest" is guessable without reading a date | `observed_at` | exactly `A` or `B` |

Entities are sampled per type with the seeded generator over the *whole*
population of that type (it used to be the 400 that sort first by key — one
corner of a 40k-CVE id space). On the seed corpus this yields 35 questions
(8 abstention, 6 lease, 6 numeric, 11 order, 2 conflict, 2 multi-hop); with
the vulns corpus loaded the CVE types add conflicts, numeric lookups and
orderings and the multi-hop family becomes the KEV exposure question per
host — 30 and more.

## Why there is no LLM judge

The model answers in a fixed two-line format (`answer: <value>` and
`cites: <tokens>`), and the question says what shape the value takes. That
makes every score a rule: does the key match, is the number within
tolerance, is the set exactly right, did it say `unknown`. A judge model
would add a second opinion whose errors are indistinguishable from the
first model's, cost money per row, and change when its model changes. The
price of rule-based scoring is a strict format: a chatty reply that buries
the value fails, and that is reported as a failure of the model to follow
instructions, which for an agent it is.

## Reading the table

The first table is one row per condition:

- **n** — rows answered and scored; every rate in the row is over these.
- **Not sent / errored** — rows never answered (see above), with the
  reasons listed under the table. Compare conditions only when this is 0
  or the gap is explained (a `full` row over `--full-cap` is the expected
  one).
- **Accuracy** — pass rate over the scored rows (mean ± sd over `--runs`);
  the second table breaks it down per family.
- **Tokens est / provider** — chars/4 over the whole rendered prompt (a
  rough, model-neutral count; the pack builder charges items with its own
  len/3 accounting, D-051), and the model's own prompt token count when it
  reports usage. Compare conditions on *both*: the point of the `full` row
  is its token column.
- **Build p50 / p95 ms** — pack (or baseline context) build latency.
- **Truth in context** — the ground-truth observation ids were among the
  context's citations: was the evidence there at all. A `loomctx@B` row's
  value is retrieval recall under that budget.
- **Support@answer** — the model cited those ids: did it *use* the
  evidence.
- **Unseen cites** — replies citing an id the context did not carry (the
  faithfulness check `agent_eval` defines). Only hex runs with an a-f
  letter, or full 32-hex ids, count as cites: a date like 20260820 is not
  one.
- **Hallucinated (abstention)** — abstention questions answered with
  anything but `unknown`.
- **Abstained (other)** — non-abstention questions answered `unknown`:
  misses, not hallucinations; with the scripted reader they are exactly
  the questions whose evidence the context lacked.
- **Cost** — what the provider billed, where it reports it.

Under the tables, the scorecard lists the questions whose ground truth is
outside LoomCtx's gather (0 on the seed corpus).

**The scripted reader (`--scripted`) is a retrieval-only measurement.** It
answers from the rendered context by rule, cites the lines it used, never
guesses and never answers from memory, so its accuracy is "was the answer
in the context" and a live model's row minus the scripted row is the
reading cost. On the seed corpus with the hashing embedder (35 questions,
none outside LoomCtx's gather, nothing unsent; build after D-062):

| Condition | Accuracy | Tokens est (mean / max) | Truth in context | Abstained (other) |
| --- | --- | --- | --- | --- |
| `loomctx@400` | 94% | 189 / 256 | 93% | 7% |
| `vector@400` | 71% | 195 / 260 | 63% | 33% |
| `recency@400` | 54% | 197 / 264 | 41% | 52% |
| `loomctx@800` | 97% | 281 / 433 | 96% | 4% |
| `vector@800` | 89% | 283 / 450 | 85% | 15% |
| `recency@800` | 69% | 282 / 442 | 59% | 41% |
| `loomctx@1600` | 100% | 411 / 789 | 100% | 0% |
| `vector@1600` | 97% | 418 / 804 | 96% | 4% |
| `recency@1600` | 69% | 415 / 805 | 59% | 37% |
| `loomctx@3200` | 100% | 677 / 1,506 | 100% | 0% |
| `vector@3200` | 100% | 682 / 1,534 | 100% | 0% |
| `recency@3200` | 69% | 680 / 1,526 | 59% | 37% |
| `full` | 100% | 1,187 / 9,800 | 100% | 0% |

At equal tokens the pack's advantage is at small budgets — at 400 tokens
it carries the answer for 93% of questions against 63% for cosine ranking
and 41% for recency — and it narrows as the budget grows until cosine
ranking catches up at 3,200. Recency never does: it drops conflicts and
most orderings at every budget. On a corpus this small `full` is
affordable and a perfect reader gets everything from it, so the pack's
case here is tokens (a third of `full`'s mean at 1,600, for the same
100%). The real corpus is where that stops being true.

## Results on the real corpus (2026-09-24)

The store `docs/real-data.md` builds — seed hosts plus CISA KEV, NVD and
EPSS, 542,099 observations, ~138 adjudicated alias merges — embedded with
`openai/text-embedding-3-small` at 512 dimensions, read live by
`deepseek/deepseek-chat-v3.1`, three runs, seed 7, 53 questions (lease 6,
conflict 9, multihop 6, abstention 8, numeric 12, order 12). Accuracy is
mean over three runs (sd ≤ 2 points everywhere); tokens are the estimator's
mean per prompt.

| Budget | `loomctx@B` | `vector@B` | `recency@B` | LoomCtx tokens / vector tokens |
| --- | --- | --- | --- | --- |
| 400 | **81%** | 75% | 50% | 208 / 208 |
| 800 | **84%** | 77% | 75% | 323 / 309 |
| 1,600 | **86%** | 79% | 75% | 434 / 409 |
| 3,200 | **96%** | 87% | 77% | 611 / 593 |
| `full` | 95% on the 47 questions it could be sent | | | 127,715 mean, 1.87M max |

- **LoomCtx leads at every budget.** At 3,200 tokens it beats handing the
  model everything (`full`: 95%, and six multi-hop questions could not be
  sent at all — their contexts run to 0.9–1.9 million tokens) at about
  half a percent of `full`'s mean prompt.
- **The multi-hop KEV question** ("which CVEs that CISA lists as exploited
  in the wild affect software host:web-01 runs?", roughly 30–44 CVEs per host) is
  answered only by LoomCtx: `loomctx@3200` 15/18, every other condition 0/18.
  Cosine ranking at the same budget has the right facts in context for
  most of these (scripted: 5/6) but a live model does not assemble the
  exact set from them; the pack's grouped, attribute-first rendering
  (D-061) is what makes the set readable.
- **Abstention:** no condition hallucinated on the 24 abstention rows.
  **Abstained (other)** — answering `unknown` to an answerable question —
  is where cosine ranking pays: 13–27% of its rows against LoomCtx's 0–5%.
- **Where LoomCtx still loses a question:** orderings at 400–800 tokens (64%
  and 78%; the pack keeps the two dated facts but not always enough
  context to read which came first), and one 44-CVE multi-hop answer at
  3,200 that the budget cuts short (laptop-17: 41 of 44 named).

**How the numbers moved during the review** (same corpus, same questions;
D-057 scoring throughout):

| Build | loomctx@400 | loomctx@800 | loomctx@1600 | loomctx@3200 | multi-hop @3200 |
| --- | --- | --- | --- | --- | --- |
| before D-061 (live) | 68% | 84% | 86% | 87% | 0/18 — outside LoomCtx's gather |
| after D-061 (scripted) | 62% | 83% | 89% | 100% | 6/6 |
| after D-062 (live, the table above) | **81%** | **84%** | **86%** | **96%** | **15/18** |

Before D-061 the six KEV questions were outside LoomCtx's reach at any budget
(the kernel hub's KEV edges are older than its newest 1,000); before
D-062 a 400-token pack could ship the wrong conflict first, lose every fact
to an excerpt, or spend a third of its budget on one base64 handle.
`vector@B` did not change between builds: its 74 / 77 / 79 / 86% before
and 75 / 77 / 79 / 87% after are run-to-run variance.

The 2026-09-26 rerun (after D-064 and D-065; same reader, seed and
questions) reproduced this table within variance — `loomctx` 79 / 85 / 87 /
96%, `vector` 75 / 76 / 78 / 86%, multi-hop 15/18 at 3,200 — as expected:
D-064 improved how an *agent* phrases a scope ask (its win is in the agent
scorecard, `docs/models.md`: the exposure task went from 9 to 30 passes
across the eighteen models), and this scorecard never has an agent phrase
one — the harness builds each pack itself and the live reader
(`deepseek-chat-v3.1`) only reads it.

The 2026-09-27 run on GKE — the first on the renamed build, the corpus
migrated to `loomctx.db` (schema v8), run as a Job — reproduced it again:
`loomctx` 77 / 84 / 87 / 96 %, `vector` 75 / 76 / 79 / 85 %, `recency`
50 / 75 / 75 / 78 %, multi-hop 15/18 at 3,200, no hallucination on the 24
abstention rows; `full` 98 % on the 47 questions it could send. About
$1.20 of reader calls.

The 2026-09-29 run on GKE — the current engine, after D-091…D-103 (named
packs, sibling walks that keep their chain, core-first ranking, the walk
memo) — reproduced it again: `loomctx` 80 / 85 / 86 / 97 %, `vector`
75 / 77 / 78 / 86 %, `recency` 49 / 75 / 75 / 77 %, multi-hop 15/18 at
3,200 (every other condition 0/18), no hallucination on the 24 abstention
rows; `full` 96 % on the 47 questions it could send; the 3,200-token pack
averaged 614 tokens. About $1.30 of reader calls.

## Caveats

- **One corpus, or two.** The seed is small and synthetic; the vulns corpus
  is real but one domain. A number from this table is about LoomCtx on these
  questions, not a general retrieval benchmark.
- **Generated questions.** They are shaped by what the store contains and
  by the generator's templates; a family can be empty on a store that
  lacks its shape (no reassigned IPs: no `as_of` lease), and the abstention
  predicates are a fixed list checked against the registry.
- **The estimator is not the tokenizer.** Tokens est is chars/4; the
  provider column is the real count and the two differ by model. Budgets
  are enforced on the pack builder's estimate, so a `loomctx@800` prompt may
  bill more than 800 — and so may `vector@800`, which is charged the same way.
- **LoomCtx's gather cap is LoomCtx's.** `loomctx@B` sees the newest 1,000
  observations per entity (and, past a hub's window, only the entities
  carrying an attribute the question names); the baselines see
  everything. Questions whose truth lies beyond that are kept (removing
  them would flatter LoomCtx) and listed under the scorecard; read the
  `loomctx@B` multi-hop cells with that list next to them.
- **Strict format.** A model that answers well but ignores the two-line
  format scores as wrong. Check the JSON before blaming retrieval.
- **The scripted reader is optimistic.** It parses windows and dates
  perfectly and never misreads a conflict; no model is that good, which is
  the point of also running one.
- **Single-sample rows lie.** Use `--runs 3` before quoting a live number;
  the seed table above is deterministic only because the reader is.

## The talk table

```bash
# size the spend first: no network, same questions, same contexts
docker compose exec --user 10001 loomctx python -m loomctx.retrieval_eval --db /data/loomctx.db \
    --scripted --seed 7 --out /data/eval/retrieval-talk-scripted.md
# then the live run, with a ceiling above that estimate (the $1 default
# would stop three runs part-way and the table would be INCOMPLETE)
docker compose exec --user 10001 loomctx python -m loomctx.retrieval_eval --db /data/loomctx.db \
    --runs 3 --seed 7 --max-cost 40 --out /data/eval/retrieval-talk.md --json /data/eval/retrieval-talk.json
```

The run exits with status 3 and an **INCOMPLETE** banner if `--max-cost`
trips; raise it and re-run rather than quoting that table. Rows stream to
`/data/eval/retrieval-talk.jsonl` as they complete. Run it against the
store `docs/real-data.md` builds (seed hosts, CISA KEV, NVD, EPSS,
embedded), with `LOOMCTX_LLM_*` set to the model on the slide and
`LOOMCTX_EMBED_*` to the embedder the corpus was embedded with. Re-run it on
the build being shown: the table describes the code that produced it.
