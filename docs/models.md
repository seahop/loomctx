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
instructions. A second scorecard, five Active Directory audits on a
10,000-account forest, is below ([Active Directory audits](#active-directory-audits)).

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
| one model to start with | **`google/gemini-2.5-flash`** | 20/20 here and 25/25 on the AD audits, a cent and 21 s per four-task run, the fastest clean pass |
| the cheapest current-generation pass | **`openai/gpt-6-luna`** | 20/20 and 25/25 at a cent; `gemini-3.5-flash-lite`, `minimax-m3`, `qwen3.8-flash` and `deepseek-v4.1-flash` are 20/20 at two to four cents |
| the model for when answers matter or it is on stage | **`anthropic/claude-sonnet-4.5`** | 20/20 and 25/25, 34 cents in 13 steps; `claude-sonnet-5`, `claude-opus-5.5` and `claude-fable-5.1` are also perfect on both, at 47 cents to $2.36, with no gain on these tasks |
| self-hosted weights | **`deepseek/deepseek-v4.1-flash`** | open weights, 20/20 and 25/25 at four cents on OpenRouter |
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

- **Default agent model:** `google/gemini-2.5-flash` — 20/20 and 25/25 on
  the AD audits, a cent and 21 seconds per four-task run.
- **Cheapest current-generation:** `openai/gpt-6-luna` (a cent, perfect on
  both), `google/gemini-3.5-flash-lite` or `minimax/minimax-m3` (two to
  three cents).
- **When answers matter or the demo is on stage:**
  `anthropic/claude-sonnet-4.5` — 20/20 and 25/25, 34 cents, fewest steps.
  `claude-sonnet-5`, `claude-opus-5.5` and `claude-fable-5.1` are perfect
  on both too, at 1.4 to seven times the cost.
- **Self-hosted weights:** `deepseek/deepseek-v4.1-flash` — perfect on
  both at four cents.
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
questions are different work: identity data is wide (thousands of
accounts, groups nested several levels, a forest of domains), and the
answer is usually a *set* — every account, every group, every server —
where a missed member is a wrong answer. So a second scorecard
(`python -m loomctx.agent_eval_ext`) asks five routine audits of the
synthetic `ad_gen` forest: `corp.local` with a `dev.local` child domain
and two external trusts — 10,000 users, 1,500 groups, 2,000 computers,
137,633 observations — imported through the LDAP connector as one
forest-wide export, plus a second domain (`lab.local`) exported without
group membership.

| Task | The question | Passes when |
| --- | --- | --- |
| **xdomain** | Which `dev.local` accounts are effective members of `corp.local`'s Domain Admins, directly or through nested groups, and is each enabled? | all five named (one direct, one through a parent group, three through a nested child group), the disabled one called disabled, no non-member presented as one |
| **coverage** | Which groups does a `lab.local` account belong to? | the answer says membership was not collected for that domain (the connector records it as a coverage gap, D-082); a confident "none" or a guessed group fails |
| **groups** | Every group `mreyes` belongs to, direct and nested | the two direct and three nested groups (the last four levels up), not a group nested *into* one of them or a sibling |
| **delegation** | Which computer accounts other than domain controllers are trusted for unconstrained delegation? | the three servers among 2,000 computers; a domain controller or the server with *constrained* delegation presented as a finding fails |
| **trusts** | Each domain `corp.local` trusts: direction, transitive, SID filtering | every partner with all three properties as the export states them |

Same harness, caps and faithfulness rule as above (a cited observation
the model saw, none it did not, no answer without a citation), five runs
of each task per model, rule-scored, and every failure was read by hand
before these numbers were taken — scorer misses on formatting (bold
lead-ins, tables without pipes, a finding split across a heading and its
bullets) were fixed and every run re-scored, with each verdict that
changed read again.

| Model | Passed | xdomain | coverage | groups | delegation | trusts | Time/run | Cost/run | Not run |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `google/gemini-2.5-flash` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 42 s | $0.01 | 0 |
| `openai/gpt-6-luna` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 226 s | $0.01 | 0 |
| `minimax/minimax-m3` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 479 s | $0.05 | 0 |
| `z-ai/glm-5.3-flash` ³ | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 894 s | $0.05 | 0 |
| `deepseek/deepseek-v4.1-flash` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 254 s | $0.07 | 0 |
| `minimax/minimax-m2.7` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 203 s | $0.08 | 0 |
| `deepseek/deepseek-v4-pro-0813` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 367 s | $0.14 | 0 |
| `qwen/qwen3.5-plus-20260420` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 384 s | $0.18 | 0 |
| `openai/gpt-6-sol` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 147 s | $0.20 | 0 |
| `anthropic/claude-haiku-4.5` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 131 s | $0.48 | 0 |
| `mistralai/mistral-medium-3-5` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 95 s | $0.62 | 0 |
| `moonshotai/kimi-k3` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 531 s | $0.73 | 0 |
| `x-ai/grok-4.7` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 342 s | $0.80 | 0 |
| `anthropic/claude-sonnet-4.5` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 164 s | $0.84 | 0 |
| `anthropic/claude-sonnet-5` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 266 s | $0.94 | 0 |
| `qwen/qwen3.8-max-0902` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 1514 s | $1.35 | 0 |
| `anthropic/claude-opus-5.5` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 232 s | $2.22 | 0 |
| `anthropic/claude-opus-4.8` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 227 s | $2.81 | 0 |
| `anthropic/claude-fable-5.1` | 25/25 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 333 s | $5.42 | 0 |
| `qwen/qwen3.8-flash` | 24/25 | 5/5 | 4/5 | 5/5 | 5/5 | 5/5 | 768 s | $0.07 | 0 |
| `openai/gpt-5.2` | 24/25 | 5/5 | 4/5 | 5/5 | 5/5 | 5/5 | 364 s | $0.60 | 0 |
| `google/gemini-3.5-flash-lite` | 23/25 | 3/5 | 5/5 | 5/5 | 5/5 | 5/5 | 75 s | $0.05 | 0 |
| `qwen/qwen3-coder` | 22/25 | 5/5 | 5/5 | 5/5 | 2/5 | 5/5 | 78 s | $0.10 | 0 |
| `deepseek/deepseek-chat-v3.1` | 20/25 | 3/5 | 4/5 | 5/5 | 3/5 | 5/5 | 798 s | $0.21 | 0 |
| `z-ai/glm-5.3` | 20/25 | 5/5 | 5/5 | 5/5 | 0/5 | 5/5 | 326 s | $0.41 | 0 |
| `openai/gpt-4o-2024-05-13` | 20/25 | 0/5 | 5/5 | 5/5 | 5/5 | 5/5 | 88 s | $0.74 | 0 |
| `mistralai/codestral-2508` | 15/25 | 0/5 | 0/5 | 5/5 | 5/5 | 5/5 | 70 s | $0.01 | 0 |
| `z-ai/glm-4.6v` | 15/25 | 1/5 | 4/5 | 0/5 | 5/5 | 5/5 | 210 s | $0.05 | 0 |
| `amazon/nova-2-lite-v1` | 15/25 | 1/5 | 5/5 | 1/5 | 3/5 | 5/5 | 82 s | $0.17 | 0 |
| `cohere/command-a-plus` | 15/25 | 1/5 | 4/5 | 3/5 | 2/5 | 5/5 | 166 s | $0.26 | 0 |
| `google/gemini-3.8-flash` | 15/25 | 0/5 | 5/5 | 4/5 | 1/5 | 5/5 | 404 s | $0.46 | 0 |
| `google/gemini-3.5-flash` | 10/25 | 2/5 | 1/5 | 5/5 | 1/5 | 1/5 | 384 s | $1.07 | 0 |
| `meta-llama/llama-4-maverick` | 0/25 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 41 s | $0.01 | 0 |
| `mistralai/mistral-large` | 6/6 (incomplete) | not run | not run | 4/4 | 1/1 | 1/1 | 24 s | $0.05 | 19 |
| `nvidia/nemotron-3-super-120b-a12b` | 23/23 (incomplete) | 4/4 | 5/5 | 4/4 | 5/5 | 5/5 | 1284 s | $0.05 | 2 |

Per-task cells are passes out of five; time and cost are per five-audit
run. Sorted by pass rate, then cost to two significant figures, then time
(a faster model outranks one a fraction of a cent cheaper); incomplete
rows last. The runs are from 2026-09-28. Seven models' xdomain, groups and
delegation rows are a re-run on the engine with D-101 (a sibling walk that
kept its chain): those three tasks are the ones whose walks go sideways
through groups and OUs, and the first run exposed the bug there (Haiku,
for one, went from 0/5 to 5/5 on xdomain). Their coverage and trusts rows
are the first run. `mistral-large` was rate-limited upstream and has 6
scored task-runs of 25; `nemotron-3-super` lost two to rate limits.

**What the misses are.** Four kinds, in this order of frequency: a set
stopped short (four of five admins, a nested group missed, the disabled
account not flagged — most of the xdomain misses); the 20-step cap, from
walking OUs or groups one at a time instead of asking over the scope
(`gemini-3.5-flash` and `gemini-3.8-flash` on delegation, most of the
delegation misses); the faithfulness rule — 27 of 854 scored runs cited nothing, or cited a
shortened id; and on the
coverage task, "no groups" for a domain whose membership was never
exported. `glm-5.3` fails delegation on the 8,000-token output cap. The
engine returns the same packs to every model; the spread is how models
use them.

**It confirms the picks above.** Every model in the short answer —
`gemini-2.5-flash`, `gpt-6-luna`, `deepseek-v4.1-flash`,
`claude-sonnet-4.5`, and the Sonnet 5, Opus and Fable lines — is 25/25
here too; nineteen models are. Some that are perfect on the core tasks
miss here (`gemini-3.8-flash` 15/25 on the step cap, `qwen3.8-flash` and
`gpt-5.2` one coverage run each, `gemini-3.5-flash-lite` two xdomain
runs), and several that miss once there are perfect here
(`minimax-m2.7`, `deepseek-v4-pro`, `qwen3.5-plus`, `mistral-medium-3-5`,
`grok-4.7`, `kimi-k3`, `qwen3.8-max`, `glm-5.3-flash`) — the case for
trying a model on your own data before trusting it.

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
