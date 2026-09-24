# Retrieval evaluation: is a context pack better than the alternatives?

`docs/models.md` measures which *models* can drive Loom. This page measures
Loom itself: on the same store and the same questions, does a budgeted,
cited context pack let a model answer better — and cheaper — than handing
it everything, than a vector top-k, or than the newest facts? The harness is
`python -m loom.retrieval_eval` (hardening row R-6); it runs in CI against a
rule-based reader and live against any model `LOOM_LLM_*` configures.

## Running it

```bash
# the seed corpus, no model, no network: the rule-based reader
docker compose run --rm loom sh -c 'python -m loom.seed load --db /tmp/t.db && \
    python -m loom.retrieval_eval --db /tmp/t.db --scripted'

# the real corpus (docs/real-data.md) with the configured model, three runs
docker compose exec --user 10001 loom python -m loom.retrieval_eval --db /data/loom.db \
    --runs 3 --out /data/eval/retrieval.md --json /data/eval/retrieval.json

# what would be asked, with the ground truth, and nothing else
docker compose exec loom python -m loom.retrieval_eval --db /data/loom.db --list-questions
```

Options that matter: `--budgets 400,800,1600,3200` (the `loom@B` conditions),
`--conditions loom,full,vector,recency`, `--families lease,conflict,...`,
`--k 20` (items for the vector and recency baselines), `--runs N` (repeat
everything, report mean ± standard deviation), `--seed 7` (which questions
get generated), `--per-family 8`, `--full-cap 100000` (a `full` context above
this many estimated tokens is measured but not sent), `--max-cost 1.0`
(live calls stop past this many dollars, where the provider reports cost —
OpenRouter does), `--model` (overrides `LOOM_LLM_MODEL`), `--canned FILE`
(a JSON map of question id to reply, for tests). The table is printed and
written to `--out` (default `eval/retrieval-<date>.md`); `--json` keeps
every question, reply and score. The vector baseline needs an embedder
(`LOOM_EMBED_*`; `LOOM_EMBED_PROVIDER=hashing` is the offline one) and is
skipped with a note otherwise; the `loom` conditions use the same embedder
when it is set, exactly as the serving engine does.

## The conditions

Every condition renders its context the way `/v1/answer` does
(`answer.render_user_prompt`: one cited line per item inside a delimited
block), sends the same system prompt and the same question to the same
model, and is scored by the same rules.

| Condition | What the model sees |
| --- | --- |
| `loom@B` | `build_pack` at budget B, with the question's `as_of` / `valid_at` axis and scope: ranked, conflicts first, chains before the facts they reach, trimmed to B tokens |
| `full` | every observation about the question's entities (the subject, or everything the scope reaches), newest first, no time axis: the "just give it everything" baseline — its token count is the honest cost of not retrieving |
| `vector` | the top-k observations from the same candidate set by cosine of the question against the rendered fact, nothing else |
| `recency` | the newest k observations from the same candidate set |

The baselines get no time filtering on purpose: the question states the
date, and reading validity windows and observation dates out of the text is
what a model without Loom's axes would have to do.

## The question families

Questions are generated from the store with a fixed seed, and every ground
truth is computed from the observations at generation time — the same
discipline as `agent_eval` (D-036): nothing is hard-coded, so the harness
runs unchanged on the seed corpus and on the real one, and a store that
changes changes the answers with it. `--list-questions` shows the set.

| Family | What it tests | Ground truth | Correct answer shape |
| --- | --- | --- | --- |
| **lease** | knowledge update over time: which host held an IP at T. `valid_at` variant (what was true at T) and `as_of` variant (what was known by T). Every other host the address was ever assigned to is a *wrong* answer, not history. Reassigned addresses are chosen first. | the `assigned_to` observation whose validity window covers T; for `as_of`, among those observed by T | `host:<key>` |
| **conflict** | conflict awareness: a scalar predicate where two sources currently disagree | the distinct values, newest observation per value | both values, or `conflicting: a \| b` |
| **multihop** | with the vulns corpus (`docs/real-data.md`): which KEV-listed CVEs reach a host through `runs_software -> affects` (the two-hop `ask_scope`). On the seed: alert -> host -> domain, and alert -> host -> the users who logged in that day | walked from the store without the pack builder's gather cap | the exact set of ids |
| **abstention** | an entity that does not exist (shaped like ones that do) and a predicate nobody ever recorded on an entity that does. The only right answer is `unknown`; anything else is a hallucination — the failure the category's benchmarks punish and the one citations cannot catch on their own | verified absent from the store | `unknown` |
| **numeric** | a number: a single-valued fact (a port, an EPSS score), the value one named source reported where scorers disagree (CVSS by scorer), or the largest of a series (the biggest invoice — an aggregate the whole series must be present for) | the observation's value | the number, within half a cent |
| **order** | temporal ordering: which of two facts about one entity was observed first, with the dates stripped from the question | `observed_at` | `A` or `B` |

On the seed corpus this yields 35 questions (8 abstention, 6 lease, 6
numeric, 11 order, 2 conflict, 2 multi-hop); with the vulns corpus loaded
the CVE types add conflicts, numeric lookups and orderings and the multi-hop
family becomes the KEV exposure question per host — 30 and more.

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

- **Accuracy** — pass rate over all questions (mean ± sd over `--runs`);
  the second table breaks it down per family.
- **Tokens est / provider** — chars/4 over the whole rendered prompt (the
  estimator the pack builder budgets with), and the model's own prompt
  token count when it reports usage. Compare conditions on *both*: the
  point of the `full` row is its token column.
- **Build p50 / p95 ms** — pack (or baseline context) build latency.
- **Support@pack** — the ground-truth observation ids were among the
  context's citations: was the evidence there at all. A `loom@B` row's
  support is retrieval recall under that budget.
- **Support@answer** — the model cited those ids: did it *use* the
  evidence.
- **Unseen cites** — replies citing an id the context did not carry (the
  faithfulness check `agent_eval` defines).
- **Hallucinated (abstention)** — abstention questions answered with
  anything but `unknown`.
- **Abstained (other)** — non-abstention questions answered `unknown`:
  misses, not hallucinations; with the scripted reader they are exactly
  the questions whose evidence the context lacked.
- **Cost** — what the provider billed, where it reports it.

**The scripted reader (`--scripted`) is a retrieval-only measurement.** It
answers from the rendered context by rule, cites the lines it used, never
guesses and never answers from memory, so its accuracy is "was the answer
in the context" and a live model's row minus the scripted row is the
reading cost. On the seed corpus with the hashing embedder:

| Condition | Accuracy | Tokens est (mean / max) | Support@pack | Abstained (other) |
| --- | --- | --- | --- | --- |
| `loom@400` | 80% | 332 / 664 | 74% | 26% |
| `loom@800` | 94% | 469 / 1,043 | 93% | 7% |
| `loom@1600` | 100% | 746 / 1,794 | 100% | 0% |
| `loom@3200` | 100% | 1,005 / 3,296 | 100% | 0% |
| `full` | 100% | 1,185 / 9,800 | 100% | 0% |
| `vector` (k=20) | 86% | 322 / 562 | 81% | 19% |
| `recency` (k=20) | 69% | 319 / 552 | 59% | 41% |

What it says: on a small corpus `full` is affordable and a perfect reader
gets everything right from it, so the pack's case at this scale is tokens
(a third of `full` at 1,600 for the same accuracy) and the two baselines
lose where ranking matters — recency drops half the conflicts and
multi-hop chains, cosine-only drops half the orderings. On the real corpus
`full` for a multi-hop question is the whole history of every CVE behind a
host's products, which is why the harness measures it and refuses to send
it past `--full-cap`. A live model adds the reading cost: the interesting
rows there are abstention (does a model with everything in front of it
still answer from memory?) and the `as_of` leases (does it read observation
dates when Loom has not already applied them?).

## Caveats

- **One corpus, or two.** The seed is small and synthetic; the vulns corpus
  is real but one domain. A number from this table is about Loom on these
  questions, not a general retrieval benchmark.
- **Generated questions.** They are shaped by what the store contains and
  by the generator's templates; a family can be empty on a store that
  lacks its shape (no reassigned IPs: no `as_of` lease), and the abstention
  predicates are a fixed list checked against the registry.
- **The estimator is not the tokenizer.** Tokens est is chars/4; the
  provider column is the real count and the two differ by model. Budgets
  are enforced on the estimate, so a `loom@800` prompt may bill more than
  800.
- **Strict format.** A model that answers well but ignores the two-line
  format scores as wrong. Check the JSON before blaming retrieval.
- **The scripted reader is optimistic.** It parses windows and dates
  perfectly and never misreads a conflict; no model is that good, which is
  the point of also running one.
- **Single-sample rows lie.** Use `--runs 3` before quoting a live number;
  the seed table above is deterministic only because the reader is.

## The talk table

```bash
docker compose exec --user 10001 loom python -m loom.retrieval_eval --db /data/loom.db \
    --runs 3 --seed 7 --out /data/eval/retrieval-talk.md --json /data/eval/retrieval-talk.json
```

against the store `docs/real-data.md` builds (seed hosts, CISA KEV, NVD,
EPSS, embedded), with `LOOM_LLM_*` set to the model on the slide and
`LOOM_EMBED_*` to the embedder the corpus was embedded with. Re-run it on
the build being shown: the table describes the code that produced it.
