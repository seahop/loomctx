# Future work: efficiency after the scale run

Rewritten 2026-10-14, after the full 10k/500k AD scorecard (`docs/models.md`).
The first version of this file (2026-09-29) asked whether LoomCtx holds up at
half a million objects. It does, and the answer reshapes what comes next.
These are **post-talk** items (the talk is 2026-10-21; until then the only
work is merging `scale-xl` once the GKE test lanes and the retrieval
scorecard pass). Each item gives the problem, the evidence, a design that
fits the architecture, and how to know it worked.

House rules still apply to all of it (`CLAUDE.md`):
- Docker only; run test suites on GKE (`secrets/gke/run-tests.sh TAG`, local
  and gitignored).
- No SQL outside `src/loomctx/store/`; new storage goes behind `GraphStore`
  (`store/base.py`), implemented for **both** SQLite and Postgres.
- A contract change gets a `docs/decisions.md` entry and regenerated
  `contracts/` (`python -m loomctx.schemas`; `… schemas openapi`); CI
  drift-checks them. Regenerate the TS SDK types too.
- Every derived fact carries citations. Domain specifics go in the schema
  registry, never in core code.
- `ad_eval` must stay 11/11. After any read-path or tool-surface change,
  re-run the AD audits (`agent_eval_ext`: the five standard audits are the
  headline, the three harder ones are reported separately, both with and
  without named queries) and the retrieval scorecard (`retrieval_eval`), and
  read every changed verdict by hand. No change is accepted on cost or speed
  alone if the standard audits' pass rate drops.
- **Named queries are a shortcut, never a requirement.** A person must be
  able to ask about any data with the general tools (`ask`, `ask_scope`,
  `find_path`, `list_entities`) and get something useful and true back. So
  the **queries-off** result is the floor: every change must hold or raise
  it, and an improvement that only shows up with named queries on doesn't
  count as a fix for general questions.

---

## Where we stand

**Done since 2026-09-29** (designs and measurements in `docs/decisions.md`):

| Was | Status |
| --- | --- |
| 0. Measure a 500k-object directory | Done. 370,000 users, 55,000 groups, 75,000 computers, 6.5M facts (D-104). |
| 2. List mode for large answer sets | Done, D-107 (`list_entities`, `POST /v1/list`); `within` filters, routes and paging, D-110. |
| 3. Named queries in the registry | Done, D-108 (`run_query`, `POST /v1/query`; LDAP registers seven). |
| 4. Schema-drafting helper | Done, D-106 (`python -m loomctx.registry draft`). |
| 7. Harder benchmark tier | First cut, D-113 (access, local admin, Kerberoastable admins). |
| Faster bulk import | Done, D-105: 10k 173 s → 39 s, 500k 2 h 18 m → 49 min. |
| 500k latency tails | Fixed, D-111 and its addenda: SQL-ranked filters, the label-index pin, `contains` seeded from the index. |

**What the 2026-10-14 run measured** (35 models × 5, one build, named queries
on unless noted):

| | 10,000 accounts | 500,000 objects |
| --- | --- | --- |
| Standard audits passed | 93% | 92% |
| Standard, named queries off | 90% | 90% |
| Harder audits passed | 81% | 81% |
| Median time per standard audit | 21 s | 23 s |
| Agent steps per standard audit | 5.7 | 5.7 |
| Input tokens per standard audit | 58.5k | 58.9k |

Accuracy, steps and tokens are flat across 37× the data, so read-path scale
is no longer the bottleneck. What remains is:

- what an agent pays per question (input tokens);
- a few slow listings over very large groups;
- the scale shape that has never been measured (Postgres);
- the size of the store.

The items below are ordered by how much each buys.

---

## 1. Cut what an agent reads on every turn (biggest cost lever)

**Evidence.** Agents pay mostly for input, and at 500k a standard audit
reads ~59k input tokens. In the 500k transcripts (named queries on, 1,371
runs, 7.7 tool calls a run), the tool results add up to only ~20k characters
a run (median), about 5k tokens. The rest is resent on every turn:

- the tool definitions: 14 tools, 18,263 characters of names, descriptions
  and input schemas, about 4.6k tokens;
- the server instructions: 2,590 characters;
- the growing history.

Over ~6 turns that fixed prefix alone is roughly half of an audit's input.

Largest definitions:

| Tool | Characters |
| --- | --- |
| `list_entities` | 2,877 |
| `ask_scope` | 2,354 |
| `find_path` | 2,276 |
| `record_claim` | 2,123 |
| `purple_report` | 1,341 |

`record_claim`, `purple_report` and `answer` together are 23% of the
definitions and are almost never called in read-only audits (`answer` 0.01
calls a run, the other two never).

**Design.**
- **Tool profiles.** `LOOMCTX_MCP_TOOLS=read` (the default for a read-only
  key) exposes the eleven read tools; `full` adds `record_claim`, `answer`
  and `purple_report`. A read-only key already cannot write; this makes the
  advertised surface follow it, so a read-only agent never pays for the
  write tools' schemas.
- **Shorter descriptions, same meaning.** Move worked examples and edge
  cases out of tool descriptions into the server instructions, said once.
  Collapse repeated parameter docs (`namespace`, `budget`, `as_of`,
  `valid_at` appear in most tools) into one shared sentence. Target: ≤10k
  characters for the read profile.
- **Careful: wording moves accuracy.** D-064's phrasing change took one task
  from 9 to 30 passes across 18 models. So every cut is A/B-tested on the
  five standard audits at 10k, 35 models × 3, before it ships, and reverted
  if the pass rate drops by more than run-to-run noise (~1 point).

**Done when.** Input tokens per standard audit drop by ≥25% (59k → ≤44k)
with the standard pass rate unchanged.

---

## 2. A tiered `describe_namespace`

**Evidence.** `describe_namespace` is **39% of everything agents read from
tools** at 500k: 9.8k characters a call, called in 89% of runs, usually
first or second. It lists every type, every predicate with counts and
object types, every named query and every not-collected topic, and most of
that is irrelevant to the question being asked.

**Design.**
- The default response becomes a summary:
  - entity types with counts;
  - the ten most-used predicates per type;
  - named queries by name and one line each;
  - not-collected topics by name;
  - a total for what was left out.
  Target: under 2.5k characters.
- `describe_namespace(namespace, type="user")` or `predicate="member_of"`
  returns the full detail for just that slice, in the format it has today.
- Contract: the response keeps its shape, and the summary sets a
  `truncated`-style field saying what to ask for next. This needs a
  decisions entry.

**Done when.** `describe_namespace` drops below 10% of tool output with no
loss on the standard audits (the agents that need a predicate should ask for
its slice).

---

## 3. Measure Postgres at 500k (the scale shape nobody has run)

**Evidence.** Every 500k measurement so far ran on SQLite, one file per
engine. The shape we tell people to deploy at scale is Postgres with
pgvector on CloudNativePG (`deploy/k8s`, `scale-pg-ha`), validated only on
the 542k-observation vulnerability corpus (83 ms p50 asks, 186 asks/s,
2026-09-27). The SQLite-specific fixes (statistics, the `INDEXED BY` pin,
D-104 and D-111) have Postgres counterparts that have only been run by
unit tests.

**Do.**
- Load `xl2` into CNPG through the bulk path (D-105) and record the import
  time. Postgres should use `COPY`; if it doesn't yet, that is part of item
  6.
- Replay the 500k tool calls from the full run against it (item 4's
  harness) and run the model-free probe (`secrets/gke/final_probe.py`).
- Run one slice of the scorecard (8 models × 3, standard audits) to confirm
  accuracy is the same as on SQLite.

**Done when.** p95 per tool at 500k on Postgres is within 2× of SQLite on
one node, with the same probe answers. Any plan regressions get the
Postgres counterpart of the SQLite fix.

---

## 4. A replay benchmark as a standing check (no LLM spend)

**Evidence.** The full run's worst calls (minutes to an hour) were I/O
contention on shared nodes plus one slow path. Replaying the 60 slowest
distinct calls on one machine took ≤8.8 s each after the fix; the model-free
probe found four inexact answers at the old 200,000 candidate cap. Both were
cheap to run and found real bugs, but they are one-off scripts in
`secrets/gke/stores/`.

**Design.**
- `python -m loomctx.replay TRANSCRIPTS STORE` replays recorded MCP calls
  in process and reports p50/p95/max per tool, and any call whose answer
  changed since the last baseline (by row keys and totals, not text).
- Keep a pinned corpus: the full run's distinct calls at 10k and 500k, plus
  the probe cases.
- Run it as a GKE Job on each candidate build, one store per node, so
  contention doesn't pollute the numbers.

**Done when.** A build that slows any replayed call past 10 s at 500k, or
changes an answer, is flagged before a model run is spent on it.

---

## 5. The remaining slow listings: precomputed membership

**Evidence.** From the model-free probe at 500k on today's build (one node):

| Listing | Time | Result |
| --- | --- | --- |
| Members of the largest group, nested | 7.3 s | 324,958 rows, exact |
| Enabled members of the largest group | 11.5 s | exact |
| Enabled Domain Admins (`within`) | 3.5 s | 16 |
| `kerberoastable_users` | 4.5 s | 14,036 |
| `asrep_roastable_users` | 3.9 s | **0** |

Agents mostly ask the small questions (the audits' median call is
sub-second), but the big ones are realistic, and returning zero rows in
3.9 s says that query scans when it should short-circuit. Look at that
first; it is probably a missing seed path, not a design problem.

**Design** (the 2026-09-29 item 1, still the right shape):
- Registry: `transitive: bool` on `PredicateDef`; LDAP, Entra and Okta mark
  `member_of`. It is a contract change, needs a decisions entry, and stays
  domain-agnostic: the engine closes any predicate marked transitive.
- Storage: a derived table, **not** observations (a closure is computed, not
  attested). Model it on dossiers (`put_dossier`, `dossier_candidates`,
  `refresh_dossiers`). Each row holds:
  - subject, predicate, the reached object and the hop count;
  - the observation ids along the chain (its citations);
  - the chain's validity window.
  Index it on (namespace, predicate, object) for "who reaches X". This is a
  schema version bump on both backends.
- Maintenance: an enrichment job in `tick()` recomputes closures for
  subjects whose transitive edges changed since a watermark. Supersession
  or redaction of an edge invalidates every row that cites it. Cycles are
  legal in AD, so use a visited set. Cap rows per subject and report the
  cap like `_record_scope_cap`.
- Read path: list mode's `within` filters and `of` walks over a transitive
  predicate read the closure when the request is current (`valid_at` and
  `as_of` unset). Time-travel requests keep the walk. `ask_scope` and
  `find_path` can use it the same way. Routes on rows still show the chain,
  cited.

**Done when.** "Enabled Domain Admins" and "enabled members of X" are under
1 s at p95 at 500k, `ad_eval` stays 11/11, and a membership removal drops
the derived rows on the next tick.

---

## 6. A smaller store and a faster import

**Evidence.** The 500k SQLite store is 7.5 GB for 6.5M facts, about
1.15 KB a fact. The `observations` table is 3.2 GB; indexes are the rest:

| Index | Size | Note |
| --- | --- | --- |
| `idx_obs_event` | 0.85 GB | the idempotency key; the event id averages 88 bytes |
| `idx_obs_subject` | 0.48 GB | |
| `idx_obs_subject_recorded` | 0.48 GB | likely covers `idx_obs_subject`'s queries |
| `idx_obs_object` | 0.40 GB | |
| `idx_obs_recorded` | 0.27 GB | |

Ids are 32-character text in every row and every index (`id`,
`subject_id`, `object_entity_id`), and timestamps are ISO strings. The
import runs at ~2,200 facts/s (49 min at 500k), 2.8× faster than before
D-105 but still the one cost that grows with the data.

**Design.**
- Store a 16-byte digest of `event_id` for idempotency; keep the original
  only where provenance needs it.
- Check every query plan that uses `idx_obs_subject`; drop it if
  `idx_obs_subject_recorded` serves them.
- Next, the larger change (schema v10, with a migration): integer surrogate
  keys for observations and entities, with the text ids kept as unique
  external handles; integer epoch timestamps.
- Import: parse and build claims in parallel workers feeding one writer;
  `COPY` on Postgres; indexes built after a bulk load at any size (today
  only into an empty store).

**Done when.**
- The 500k store is under 4 GB.
- The 500k import is under 15 minutes.
- Read latency is unchanged in the replay benchmark (item 4).

---

## 7. Concurrency at 500k

**Evidence.** Every 500k measurement ran one agent per store at a time. The
Kubernetes numbers (186 asks/s) are from the 542k-observation vuln corpus
with short asks. A shared deployment serves many agents at once.

**Do.** Replay the 500k calls (item 4) at concurrency 8, 32 and 128 against:
- one engine on SQLite;
- the autoscaled engines on Postgres (item 3).

Record p95 per tool and throughput, and watch for lock contention on SQLite
writes during reads (enrichment running).

**Done when.** The numbers are in `deploy/README.md` with a sizing note
(agents per engine at 500k).

---

## 8. General questions first: the coverage and nested-groups gap

**Evidence.** At 500k, coverage fails 22 times with named queries on and 12
with them off, and nested groups 14 against 9. Reading those runs, **most of
the gap is not `run_query`**: the extra failures mostly never called it.

| Cause | Runs | What happened |
| --- | --- | --- |
| Llama 4 Maverick | +5 coverage, +4 groups | Writes tool calls as plain text on OpenRouter's route, so it fails either way and the arms differ by chance |
| Gemini 2.5 Flash | +4 groups | Guessed `user:mreyes@corp.local`; `list_entities` said "not on record" and it stopped. Fixed after the run: `of` resolves names (D-111 addendum) |
| Qwen3-Coder | +3 coverage | Used `ask`, invented "Domain Users" and "Backup Operators" from the account's name, and cited the account's real `enabled` and `sam` facts as support. The data has no membership for it; the scorer was right |
| GLM-4.6V | +4 groups | `ask_scope` over `member_of` at the default depth reached 3 of 5 groups. The pack said "the walk stopped at depth 1 … depth=2 walks one hop further"; the model ignored it |

Two models went the other way (GLM-5.3 Flash −5 and Command A+ −3 on
groups with queries on), which is why the net gap is smaller than the sum.

**Do.**
- **Containment walks follow the chain.** For a predicate registered as
  containment (`member_of`, `contains`), `ask_scope` should walk to the end
  of the chain by default, within the existing caps, instead of one hop.
  Where a cap or an explicit depth stops it, the note should say how much
  is left ("member_of continues 3 more levels, 3 more groups"), not just
  that it continues. A count is harder to ignore than a hint.
- **Citations must support the claim.** Qwen3-Coder's answer cited real
  observations that say nothing about membership. The faithfulness check
  (seen, not invented) cannot catch that. Add a scorer check that each
  claimed membership's citation is a `member_of` row, and report it. It is
  a failure of the model, not the engine, but it belongs in the published
  numbers.
- Re-run coverage and groups on the fixed build, queries off first (the
  floor), then on.

**Done when.** Queries-off coverage and groups are at or above their
queries-on results, and the GLM-4.6V-style partial walk can't happen on a
default `ask_scope`.

---

## 9. Benchmarks that hold us honest

- **The rest of the harder tier** (from the old item 7): cross-source joins
  (an identity's AD groups against its Entra/Okta roles; a vulnerable host
  reachable by an account with an ACE path) and time (who was a Domain Admin
  on a past date, `as_of`). Keep them reported apart from the standard five.
- **Non-synthetic directory data.** Everything at 500k is generated. Export
  a public lab (for example GOAD, Game of Active Directory) through the LDAP
  connector and run the standard audits' question types against it with
  hand-written truth. It is small, but it is real AD with real quirks.
- **A cost column per model at 500k on the site**, from the same runs.

---

## 10. Carried over, unchanged

- **Entity resolution review queue** (was item 5): hold low-confidence
  adjudications as proposed merges for a person to approve; extend hard
  identifiers (MAC, cloud instance id, certificate fingerprint) to hosts.
- **Theme summaries over documents** (was item 6): optional, LLM at
  enrichment only, and only if users ask.

---

## Suggested order

1. **Before the talk:** merge `scale-xl` after the GKE test lanes and the
   retrieval scorecard pass. Nothing else.
2. **Items 1 and 2** first. They are cheap, they cut what every agent pays
   on every question, and they are measured on the standard audits.
3. **Item 4**, so every later change is checked for speed and answers
   without spending on models.
4. **Item 3** (Postgres at 500k), then **item 7** (concurrency) on top of
   it. Together they turn "it scales" into a sizing guide. Postgres is what
   a scale deployment runs, so its numbers are the ones to publish; if time
   allows, its model-free half (load, replay, probe) can run before the
   talk.
5. **Item 6** (store size and import), then **item 5** (precomputed
   membership) if the replay benchmark still shows the large listings above
   target.
6. **Item 8** right after items 1 and 2: the containment-walk fix is
   small and serves every general question. Then **item 9**. Item 10 only
   on demand.
