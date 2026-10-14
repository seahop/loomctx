# Which models drive LoomCtx well (D-041)

LoomCtx does not ship a model. It ships an MCP surface and an HTTP API, and
the agent on the other side is whatever a team already runs. So the useful
question is not "which model is best" but **which models, given LoomCtx's
tools and no other help, find the data and answer faithfully** — and at
what cost. This page is the measured answer, and the command that produced
it, so it can be re-run when models change (they change monthly).

## TL;DR

Measured 2026-09-28 on OpenRouter: 36 models attempted, 35 scored, five
full runs each of four tasks (686 scored task-runs, $46), run as GKE Jobs
against the real corpus — seed hosts plus CISA KEV, NVD and EPSS, 542,100
observations, embedded — with no hints beyond the MCP server's own
instructions. A second scorecard, eight Active Directory audits on 10,000- and
500,000-object forests (2026-10-14), is below ([Active Directory audits](#active-directory-audits)).

- **Fifteen models pass every task every time.** From a cent per
  four-task run (`google/gemini-2.5-flash`, `openai/gpt-6-luna`) through
  the Anthropic, Google, OpenAI, DeepSeek, Qwen and MiniMax current lines
  to `anthropic/claude-fable-5.1` at $2.36. Nine more miss one run in
  twenty.
- **Single-entity tasks are solved.** Every complete model except
  `llama-4-maverick` (tool-call format, below) passes the lease, conflict
  and OS tasks in at least four runs of five. The two-hop exposure task is
  where models differ, and the misses there are the model's reading — a
  non-KEV CVE listed as part of the exposure, too few of the 32 named, a
  CVE from memory — or its generation (an empty reply, the step or output
  cap), not LoomCtx withholding the chain.
- **Against the 2026-09-27 table** (same corpus, earlier engine): lease,
  conflict and OS are unchanged (165 / 165 / 164 of 170 against 165 / 164 /
  165); exposure is 122 of 170 against 127. The five-run difference is
  scattered single runs — an empty completion, an output-cap stop, a step-cap
  stop, a CVE named from memory — not a pack change: every exposure walk
  returned the same chain at the same size. Four of the nineteen models that
  were 20/20 there lost one exposure run each here.
- **The faithfulness check holds:** 5 citations to an unseen observation in
  686 task-runs (`gemini-3.5-flash` 4, `minimax-m2.7` 1), each failing its
  run. Six models named CVE ids that do not exist in the store; the check
  failed those runs.

## Short answer

| If you want… | Use | Why |
| --- | --- | --- |
| one model to start with | **`openai/gpt-6-luna`** | 20/20 here and 40/40 on the eight AD audits at both sizes, about a cent a run |
| the fastest cheap pass | **`google/gemini-2.5-flash`** on simple lookups | 20/20 here at a cent and 21 s, but 19/40 on the AD audits: not for set-valued or combined questions |
| the model for when answers matter or it is on stage | **`anthropic/claude-sonnet-4.5`** | 20/20 and 40/40 at both AD sizes; `claude-sonnet-5`, `claude-opus-4.8` and `claude-haiku-4.5` are 40/40 at 500k too |
| self-hosted weights | **`deepseek/deepseek-v4.1-flash`** | open weights, 20/20 and 40/40 on the AD audits at 500k, a few cents on OpenRouter |
| to avoid | `meta-llama/llama-4-maverick` via OpenRouter (0/20, tool-call format); `gpt-4o`, `qwen3-coder`, `nova-2-lite` (0/5 on the two-hop task) | see the notes under the table |

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

## Decision table (2026-09-28, OpenRouter, five full runs per model, 20-step cap)

Per-task cells are passes out of five; steps, tokens, time and cost are
per four-task run. Sorted by pass rate, then cost.

| Model | Passed | 2-hop exposure | lease | conflict | os | Steps/run | Tokens in/out/run | Time/run | Cost/run | Faithful | Not run |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `google/gemini-2.5-flash` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 11 | 39,034/1,953 | 21 s | $0.01 | yes | 0 |
| `openai/gpt-6-luna` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 25.4 | 276,116/7,625 | 139 s | $0.01 | yes | 0 |
| `google/gemini-3.5-flash-lite` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 20.8 | 90,188/2,354 | 30 s | $0.02 | yes | 0 |
| `minimax/minimax-m3` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 15.8 | 157,477/9,165 | 258 s | $0.03 | yes | 0 |
| `qwen/qwen3.8-flash` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 26.6 | 569,799/21,167 | 329 s | $0.03 | yes | 0 |
| `deepseek/deepseek-v4.1-flash` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 21.8 | 399,101/17,242 | 134 s | $0.04 | yes | 0 |
| `anthropic/claude-haiku-4.5` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 13 | 100,111/2,793 | 47 s | $0.11 | yes | 0 |
| `openai/gpt-6-sol` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 24.6 | 211,187/3,495 | 105 s | $0.16 | yes | 0 |
| `google/gemini-3.8-flash` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 26.2 | 371,220/16,011 | 206 s | $0.20 | yes | 0 |
| `anthropic/claude-sonnet-4.5` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 13 | 95,221/3,781 | 102 s | $0.34 | yes | 0 |
| `openai/gpt-5.2` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 25.4 | 353,609/12,607 | 211 s | $0.35 | yes | 0 |
| `anthropic/claude-sonnet-5` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 14.6 | 185,989/9,524 | 146 s | $0.47 | yes | 0 |
| `anthropic/claude-opus-5.5` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 14.2 | 196,108/5,492 | 112 s | $0.89 | yes | 0 |
| `anthropic/claude-opus-4.8` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 14.2 | 173,702/5,366 | 100 s | $1.00 | yes | 0 |
| `anthropic/claude-fable-5.1` | 20/20 | 5/5 | 5/5 | 5/5 | 5/5 | 15 | 196,731/7,768 | 191 s | $2.36 | yes | 0 |
| `mistralai/codestral-2508` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 16.2 | 116,151/2,838 | 34 s | $0.01 | yes | 0 |
| `z-ai/glm-5.3-flash` ³ | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 17.8 | 227,848/22,751 | 432 s | $0.02 | no (0 unseen cites, 2 invented) | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 25 | 293,638/18,714 | 1005 s | $0.03 | no (0 unseen cites, 1 invented) | 0 |
| `deepseek/deepseek-chat-v3.1` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 21 | 161,121/3,097 | 408 s | $0.04 | yes | 0 |
| `qwen/qwen3.5-plus-20260420` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 17 | 144,009/14,277 | 301 s | $0.07 | yes | 0 |
| `x-ai/grok-4.7` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 21.4 | 336,247/12,380 | 184 s | $0.33 | no (0 unseen cites, 2 invented) | 0 |
| `qwen/qwen3.8-max-0902` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 22.8 | 475,177/19,982 | 486 s | $0.43 | no (0 unseen cites, 10 invented) | 0 |
| `moonshotai/kimi-k3` | 19/20 | 4/5 | 5/5 | 5/5 | 5/5 | 18.6 | 343,393/18,851 | 448 s | $0.56 | no (0 unseen cites, 3 invented) | 0 |
| `minimax/minimax-m2.7` | 18/20 | 4/5 | 5/5 | 5/5 | 4/5 | 15.4 | 120,685/5,795 | 126 s | $0.02 | no (1 unseen cites, 0 invented) | 0 |
| `deepseek/deepseek-v4-pro-0813` | 18/20 | 3/5 | 5/5 | 5/5 | 5/5 | 21.6 | 515,725/12,636 | 379 s | $0.16 | yes | 0 |
| `mistralai/mistral-medium-3-5` | 18/20 | 3/5 | 5/5 | 5/5 | 5/5 | 15 | 126,813/2,616 | 51 s | $0.21 | no (0 unseen cites, 1 invented) | 0 |
| `google/gemini-3.5-flash` | 18/20 | 3/5 | 5/5 | 5/5 | 5/5 | 34.2 | 376,351/16,054 | 140 s | $0.40 | no (4 unseen cites, 0 invented) | 0 |
| `z-ai/glm-4.6v` | 16/20 | 1/5 | 5/5 | 5/5 | 5/5 | 15.6 | 99,087/3,827 | 111 s | $0.02 | yes | 0 |
| `cohere/command-a-plus` | 16/20 | 1/5 | 5/5 | 5/5 | 5/5 | 31.6 | 296,614/6,197 | 77 s | $0.10 | yes | 0 |
| `qwen/qwen3-coder` | 15/20 | 0/5 | 5/5 | 5/5 | 5/5 | 19 | 145,563/2,371 | 37 s | $0.05 | yes | 0 |
| `amazon/nova-2-lite-v1` | 15/20 | 0/5 | 5/5 | 5/5 | 5/5 | 20.4 | 238,676/5,279 | 58 s | $0.08 | yes | 0 |
| `z-ai/glm-5.3` | 15/20 | 0/5 | 5/5 | 5/5 | 5/5 | 14.6 | 139,565/25,511 | 285 s | $0.22 | yes | 0 |
| `openai/gpt-4o-2024-05-13` | 15/20 | 0/5 | 5/5 | 5/5 | 5/5 | 14.8 | 62,196/1,147 | 43 s | $0.33 | yes | 0 |
| `meta-llama/llama-4-maverick` ² | 0/20 | 0/5 | 0/5 | 0/5 | 0/5 | 8 | 47,284/1,939 | 145 s | $0.01 | yes | 0 |
| `mistralai/mistral-large` ¹ | 4/5 (incomplete) | 4/5 | not run | not run | not run | 7 | 35,751/1,755 | 41 s | $0.03 | yes | 15 |

Not run: tasks the provider failed (rate limit, 5xx, unreachable, an error body) after its retries and one task-level retry — excluded from Passed, never scored as the model's failure.

¹ `mistral-large` and `mistral-small-2603` were rate-limited upstream on
OpenRouter ("temporarily rate-limited upstream") on most calls; only
`mistral-large`'s exposure runs were scored (15 of its 20 task-runs not
run), and `mistral-small-2603` had 1 scored task-run of 20 and is not
listed.

³ **`glm-5.3-flash` is slow.** It averaged 432 s per four-task run here
and 894 s per five-audit run on the AD scorecard, where a single task took
34 seconds to over twelve minutes (median 139 s, against 5 s for
`gemini-2.5-flash`). Its AD xdomain, groups and delegation rows come from
a separate re-run. Read its timing as rough and, whatever it scores, treat
it as a poor fit for an agent someone is waiting on.
`nemotron-3-super` (1,005 s per run), `qwen3.8-max` (486 s), `kimi-k3`
(448 s) and `deepseek-chat-v3.1` (408 s) are in the same slow tier; the
fastest clean passes take 21–50 s (`gemini-2.5-flash`, `gemini-3.5-flash-lite`,
`claude-haiku-4.5`).

² `llama-4-maverick` makes one real tool call, then writes its next calls
as text in the reply (`[describe_namespace(namespace='netsec')]`), which
reads as a final answer. That is the tool-calling format on OpenRouter's
route for the model, not its reasoning; a provider that parses its native
format may do far better.

## Reading it

**What the misses are.** On the two-hop task: a non-KEV CVE presented as
part of the exposure (`gpt-4o`, `qwen3-coder`, `codestral`, `glm-4.6v`;
`nova-2-lite` lists up to 155 CVEs), too few of the 32 KEV CVEs named
(`command-a-plus`, `minimax-m2.7`, one `deepseek-v4-pro` run), a CVE named
from memory that is not in the store (`grok-4.7` naming regreSSHion; the
"invented" counts in the table), or generation — the 8,000-token output cap
(`glm-5.3`, `qwen3.5-plus`), the step cap, an empty completion. Each is the
model's reading or writing of what LoomCtx returned; the same chain was
returned to every model.

**The scorer was read against these answers too** (D-103). Three
`claude-opus-5.5` answers named OpenSSH and nginx CVEs to rule them out
("I saw no KEV entries for them. Their CVEs appear only with NVD or EPSS
data, such as CVE-2026-3497") and failed as if they had claimed them; the
exclusion one sentence away, before or after, and "not in the catalogue"
now count, as a sentence naming the CVE already did (D-089). No answer in
the 2026-09-27 run changes under the fix.

**The faithfulness check catches what it should.** A confident wrong "no"
is the one failure citations cannot catch, which is why packs report
partial coverage (`truncated`) and why a model's *rate* matters more than
its best run.

**Cost is what the agent reads, not what it writes.** Input tokens run
39k to 570k per four-task run because every tool result stays in
context.

## Recommendation in full

- **Default agent model:** `openai/gpt-6-luna` — 20/20, and 40/40 on the
  eight AD audits at 10k and 500k, about a cent a run.
- **Cheapest fast pass on simple lookups:** `google/gemini-2.5-flash` (a
  cent, 21 seconds, 20/20 on the core tasks) — but 19/40 on the AD audits,
  so not for set-valued or combined questions.
- **When answers matter or the demo is on stage:**
  `anthropic/claude-sonnet-4.5` — 20/20 and 40/40 on the AD audits at
  both sizes. `claude-sonnet-5` and `claude-opus-4.8` are too;
  `claude-fable-5.1` misses the Kerberoastable-admins audit (35/40).
- **Self-hosted weights:** `deepseek/deepseek-v4.1-flash` — 20/20 and
  40/40 on the AD audits at 500k, at a few cents.
- **Not on this evidence:** `meta-llama/llama-4-maverick` through
  OpenRouter (tool calls as text); `gpt-4o`, `qwen3-coder` and
  `nova-2-lite` for multi-hop questions (0/5 on the two-hop task);
  `glm-5.3-flash` for anything interactive (seven to fifteen minutes a
  run, footnote ³).
- **The server-side answering LLM** (`/v1/answer`, `LOOMCTX_LLM_*`) is a
  reader, not an agent: it needs no tool calling, so any model on this
  page works there.

Five runs each; one flipped task is within variance. Re-run before quoting
a number in a talk.

## Active Directory audits

The four tasks above run over one host and its software. Directory
questions are different work: identity data is wide (accounts, groups
nested several levels, a forest of domains), and the answer is usually a
*set* — every account, every group, every server — where a missed member
is a wrong answer. So a second scorecard (`python -m
loomctx.agent_eval_ext`) asks eight audits of the synthetic `ad_gen`
forest: `corp.local` with a `dev.local` child domain and two external
trusts, imported through the LDAP connector as one forest-wide export,
plus a second domain (`lab.local`) exported without group membership. It
ran at two sizes: 370,000 users, 55,000 groups and 75,000 computers
(6,502,512 observations, "500k"), and 10,000 users, 1,500 groups and
2,000 computers (175,560 observations, "10k"). The data is synthetic.

| Task | The question | Passes when |
| --- | --- | --- |
| **xdomain** | Which `dev.local` accounts are effective members of `corp.local`'s Domain Admins, directly or through nested groups, and is each enabled? | all five named (one direct, one through a parent group, three through a nested child group), the disabled one called disabled, no non-member presented as one |
| **coverage** | Which groups does a `lab.local` account belong to? | the answer says membership was not collected for that domain (the connector records it as a coverage gap, D-082); a confident "none" or a guessed group fails |
| **groups** | Every group `mreyes` belongs to, direct and nested | the two direct and three nested groups (the last four levels up), not a group nested *into* one of them or a sibling |
| **delegation** | Which computer accounts other than domain controllers are trusted for unconstrained delegation? | the three servers; a domain controller or the server with *constrained* delegation presented as a finding fails |
| **trusts** | Each domain `corp.local` trusts: direction, transitive, SID filtering | every partner with all three properties as the export states them |
| **access** | Which Domain Admins (nested) hold rights over workstation WS-AUDIT01, and through what? | both admins named with their grant (one through a group holding GenericAll, one through a direct WriteDacl); the operator who is no admin and the admin with no grant not presented as findings |
| **localadmin** | Who is local administrator on WS-AUDIT01? | the answer says local group membership is not in an AD export (declared by the connector, D-110); presenting accounts as its local admins fails. The one audit that may pass without a citation |
| **kerberoast** | Which enabled Domain Admins, nested included, are Kerberoastable? | the nested admin with an SPN; the disabled admin with one and the non-admin service account with one not presented as findings |

The last three (D-113) combine conditions or ask what the export cannot
say. Same harness, caps and faithfulness rule as above (a cited
observation the model saw, none it did not, no answer without a citation
except as noted), five runs of each audit per model, rule-scored. Every
failure was read by hand before these numbers were taken; scorer misses
were fixed, every run re-scored, and each verdict that changed read again.
Run 2026-10-14 on one build, both forests rebuilt from seed 7, as GKE Jobs.

| Condition | All 8 | First 5 | Harder 3 | Perfect (40/40) | Median audit | Spend |
| --- | --- | --- | --- | --- | --- | --- |
| 500k, named queries on | 1209/1371 (88%) | 795/860 (92%) | 414/511 (81%) | 13 | 27 s | $113.68 |
| 10k, named queries on | 1207/1370 (88%) | 794/857 (93%) | 413/513 (81%) | 11 | 25 s | $114.31 |
| 500k, named queries off | 1165/1368 (85%) | 770/855 (90%) | 395/513 (77%) | 9 | 30 s | $111.82 |
| 10k, named queries off | 1162/1366 (85%) | 772/856 (90%) | 390/510 (76%) | 13 | 26 s | $108.32 |

Fifty times the data costs nothing in accuracy, steps or spend. Named
queries (D-108) are worth about three points overall: 6-12 points on
xdomain, delegation and kerberoast, against 3-6 points lost on coverage and
groups at 500k. With them hidden the agent builds each listing itself.

Per model, 500k with named queries on unless the column says otherwise.
Per-audit cells are passes out of five; time and cost are per eight-audit
run. Sorted by pass rate, then cost to two significant figures, then time;
incomplete rows last.

| Model | 500k | 10k | 500k, no named queries | Admins | Coverage | Groups | Delegation | Trusts | Access | Local admin | Kerberoast | Time / 8 audits | Cost / 8 audits | Not run |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `openai/gpt-6-luna` | 40/40 | 40/40 | 39/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 170 s | $0.01 | 0 |
| `deepseek/deepseek-v4.1-flash` | 40/40 | 39/40 | 40/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 239 s | $0.05 | 0 |
| `z-ai/glm-5.3-flash` | 40/40 | 40/40 | 35/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 413 s | $0.05 | 0 |
| `minimax/minimax-m2.7` | 40/40 | 37/40 | 37/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 573 s | $0.07 | 0 |
| `openai/gpt-6-sol` | 40/40 | 40/40 | 40/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 145 s | $0.24 | 0 |
| `anthropic/claude-haiku-4.5` | 40/40 | 40/40 | 35/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 141 s | $0.53 | 0 |
| `x-ai/grok-4.7` | 40/40 | 40/40 | 40/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 324 s | $0.59 | 0 |
| `moonshotai/kimi-k3` | 40/40 | 40/40 | 40/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 362 s | $0.66 | 0 |
| `openai/gpt-5.2` | 40/40 | 36/40 | 36/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 531 s | $0.85 | 0 |
| `anthropic/claude-sonnet-5` | 40/40 | 40/40 | 40/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 206 s | $1.07 | 0 |
| `anthropic/claude-sonnet-4.5` | 40/40 | 40/40 | 40/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 281 s | $2.00 | 0 |
| `anthropic/claude-opus-5.5` | 40/40 | 37/40 | 34/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 469 s | $2.25 | 0 |
| `anthropic/claude-opus-4.8` | 40/40 | 40/40 | 39/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 211 s | $2.74 | 0 |
| `minimax/minimax-m3` | 39/40 | 40/40 | 39/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 4/5 | 295 s | $0.07 | 0 |
| `deepseek/deepseek-chat-v3.1` | 39/40 | 39/40 | 39/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 4/5 | 5/5 | 761 s | $0.18 | 0 |
| `qwen/qwen3.5-plus-20260420` | 39/40 | 40/40 | 39/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 4/5 | 5/5 | 5/5 | 642 s | $0.23 | 0 |
| `deepseek/deepseek-v4-pro-0813` | 39/40 | 39/40 | 40/40 | 5/5 | 5/5 | 4/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 593 s | $0.27 | 0 |
| `z-ai/glm-5.3` | 39/40 | 37/40 | 35/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 4/5 | 559 s | $0.34 | 0 |
| `mistralai/mistral-medium-3-5` | 39/40 | 36/40 | 40/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 4/5 | 5/5 | 5/5 | 206 s | $1.09 | 0 |
| `qwen/qwen3.8-max-0902` | 38/40 | 39/40 | 40/40 | 5/5 | 4/5 | 5/5 | 5/5 | 5/5 | 5/5 | 4/5 | 5/5 | 1118 s | $0.87 | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | 37/40 | 39/40 | 34/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 3/5 | 4/5 | 5/5 | 1187 s | $0.08 | 0 |
| `google/gemini-3.8-flash` | 37/40 | 36/40 | 38/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 2/5 | 5/5 | 5/5 | 548 s | $0.59 | 0 |
| `google/gemini-3.5-flash-lite` | 36/40 | 38/40 | 36/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 2/5 | 5/5 | 4/5 | 94 s | $0.06 | 0 |
| `openai/gpt-4o-2024-05-13` | 35/40 | 28/40 | 20/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 0/5 | 89 s | $1.07 | 0 |
| `anthropic/claude-fable-5.1` | 35/40 | 34/40 | 35/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 0/5 | 264 s | $4.98 | 0 |
| `cohere/command-a-plus` | 34/40 | 34/40 | 26/40 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 2/5 | 3/5 | 4/5 | 435 s | $0.30 | 0 |
| `qwen/qwen3.8-flash` | 33/40 | 39/40 | 37/40 | 5/5 | 3/5 | 5/5 | 3/5 | 4/5 | 5/5 | 4/5 | 4/5 | 890 s | $0.06 | 0 |
| `amazon/nova-2-lite-v1` | 33/40 | 33/40 | 24/40 | 4/5 | 5/5 | 5/5 | 5/5 | 5/5 | 2/5 | 2/5 | 5/5 | 68 s | $0.14 | 0 |
| `z-ai/glm-4.6v` | 30/40 | 31/40 | 32/40 | 2/5 | 5/5 | 1/5 | 5/5 | 5/5 | 3/5 | 4/5 | 5/5 | 378 s | $0.05 | 0 |
| `qwen/qwen3-coder` | 30/40 | 32/40 | 33/40 | 5/5 | 1/5 | 5/5 | 5/5 | 5/5 | 2/5 | 2/5 | 5/5 | 95 s | $0.09 | 0 |
| `google/gemini-3.5-flash` | 29/40 | 33/40 | 34/39 | 5/5 | 0/5 | 5/5 | 5/5 | 5/5 | 1/5 | 3/5 | 5/5 | 1197 s | $1.05 | 0 |
| `google/gemini-2.5-flash` | 19/40 | 22/40 | 21/40 | 2/5 | 5/5 | 1/5 | 5/5 | 5/5 | 0/5 | 1/5 | 0/5 | 137 s | $0.02 | 0 |
| `mistralai/codestral-2508` | 19/40 | 18/40 | 12/40 | 5/5 | 0/5 | 5/5 | 1/5 | 5/5 | 0/5 | 0/5 | 3/5 | 201 s | $0.02 | 0 |
| `meta-llama/llama-4-maverick` | 0/40 | 4/40 | 9/40 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 1100 s | $0.01 | 0 |
| `mistralai/mistral-large` | 10/11 (incomplete) | 7/10 | 7/9 | 2/2 | 1/1 | — | 4/4 | 3/3 | — | 0/1 | — | 21 s | $0.06 | 29 |

`mistral-large` was rate-limited upstream (11 of 40 task-runs scored).

**What the misses are.** On the first five, as before: a set stopped short
(an admin or a nested group missed, the disabled account not flagged), and
on coverage, "no groups" for a domain whose membership was never exported.
On the harder three: an operator or an idle admin put forward on access, a
decoy (the disabled admin, the service account) listed on kerberoast, and
accounts presented as local admins. Some models fail one harder audit
outright (`claude-fable-5.1` and `gpt-4o` 0/5 on kerberoast,
`gemini-3.8-flash` and `gemini-3.5-flash-lite` 2/5 on access).

**`gemini-2.5-flash` drops from the picks.** It was 25/25 on the five
audits of 2026-09-28's plainer forest; here it is 19/40. Four of its five
groups failures (named queries on) were one call with a guessed handle
(`user:mreyes@corp.local`) and "not on record" taken as the answer; `of`
now resolves a name (D-111 addendum), after this run. The rest are real
misses on xdomain and all three harder audits.

The 2026-09-28 five-audit table (10,000 accounts, an earlier engine) is in
this file's history.

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
