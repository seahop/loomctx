# Demo script (conference, end of October 2026)

Three acts, about twelve minutes, one laptop, nothing on the host but
Docker. Every number and question below has been run; the fallbacks are
real files, not hopes.

**The one sentence.** Loom absorbs facts about entities over time, from
structured claims and documents, and hands an agent a token-budgeted,
cited, question-scoped context pack — conflicts first, provenance always,
and it says when it did not look at everything.

## Before the talk (5 minutes, once — measured 142 s from a fresh clone)

```bash
git clone https://github.com/seahop/Loom && cd Loom
docker compose up -d --build loom                                          # 26 s uncached build + 6 s up
docker compose exec loom python -m loom.seed load                          # 591 claims, 5 docs
docker compose exec --user 10001 loom python -m loom.connectors.vulns load \
    --db /data/loom.db --bridge-seed-hosts                                 # 110 s incl. feed download, ~525k envelopes
docker compose exec loom python -m loom.enrich resolve                     # alias pass (D-042): KEV keys onto CPE keys, ~3 cents, 27 min of LLM calls — start it first, it can overlap
claude mcp add loom -- docker compose --project-directory "$PWD" run --rm -T loom python -m loom.mcp_server
# or, without touching your Claude Code config: claude --mcp-config demo/mcp.json --strict-mcp-config
```

Set `LOOM_MCP_NAMESPACE=netsec` in `.env` if you want the agent to skip
the namespace argument. Check `curl -s localhost:8000/readyz` says
`ready`, open a terminal with `claude` in the repo, and keep a second
terminal for `curl`. Put the fallback files (below) on the desktop.

## Act 1 — the shape of the thing (3 min, seed data, `curl`)

*"Which host held 10.0.4.7 on August 20th?"* — the bitemporal star:

```bash
curl -s localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace":"netsec","subject":{"type":"ip","key":"10.0.4.7"},
  "question":"which host was assigned this ip?","valid_at":"2026-08-20T00:00:00Z","budget":600}' | python3 -m json.tool
```

Point at: `laptop-17` (not `web-01`, which held it until Aug 10), every
item's `citations`, and `budget`. Say: *the agent asked for 600 tokens and
got the most relevant cited facts that fit; anything cut becomes a handle
it can pull deeper — you will see those on the next call.*

*"What OS does web-01 run?"* — conflicts ship first:

```bash
curl -s localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace":"netsec","subject":{"type":"host","key":"web-01"},
  "question":"what operating system does this run?","budget":400}' | python3 -m json.tool | head -30
```

Point at: item 0 is `kind: conflict`, two sources, two citations; the
`handles` list at the bottom (77 more logins, each a thread). Say: *Loom
never picks a side silently. The agent sees the disagreement before it
sees anything else, and gets handles for what did not fit.*

## Act 2 — real data (3 min, the vulnerability corpus, `curl`)

Say: *everything so far was seed data we wrote. This is CISA KEV, NVD and
EPSS, 465,000 observations loaded by one command this morning.*

*"How severe is CVE-2026-0544?"* — a real, unplanted disagreement:

```bash
curl -s localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace":"netsec","subject":{"type":"cve","key":"CVE-2026-0544"},
  "question":"how severe is this?","budget":800}' | python3 -m json.tool | head -40
```

Point at: NIST says 9.8, the CNA says 5.5, conflict first, both cited.
Say: *8,552 CVEs this year have two scorers who disagree. Nobody planted
that.*

*"Everything about the Linux kernel"* — the honest pack:

```bash
curl -s localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace":"netsec","subject":{"type":"product","key":"linux:linux_kernel"},
  "question":"exploited in the wild","budget":800}' | python3 -c "import json,sys; p=json.load(sys.stdin); print(json.dumps(p['truncated'], indent=1)); print(p['handles'][0]['hint'])"
```

Point at: `truncated: 1,000 of 2,747` and the single handle for the rest.
Say: *when Loom did not look at everything, it says so. An agent cannot
honestly answer "no" from this pack.*

## Act 3 — an agent on its own (5 min, Claude Code over MCP)

In the `claude` terminal, type exactly:

> Is host web-01 exposed to any vulnerability that CISA lists as exploited in the wild? Work out what software it runs and which of those products have such CVEs. Name the CVEs and the software, and cite observation ids. Namespace is netsec.

Narrate the tool calls as they scroll: `describe_namespace` (*it learns
the schema — Loom is domain-agnostic, the domain is data*), `find_entity`
(*names to handles*), `ask_scope` with `expand_predicates` (*two hops:
host → software ← CVE, in one call*), `ask` on each candidate CVE (*it
verifies*), `find_related` (*meaning-based search over the advisories*),
then the answer.

Rehearsed 2026-09-10 with Claude Code (the account's default model,
`claude-fable-5-1`): 22 tool calls, 151 seconds, $4.53, and an answer
that named all three KEV CVEs — kernel `CVE-2026-53362` and
`CVE-2026-31431`, Heartbleed `CVE-2014-0160` via OpenSSL — each with the
`affects` link and the KEV observation id, nineteen citations all
verifiable, nothing invented. Then it found something we had not planted:
*"the kernel is double-keyed — the KEV connector files kernel entries
under `linux:kernel`, NVD and the inventory use `linux:linux_kernel`;
about 25 more kernel KEV CVEs hang off the KEV key and never reach web-01
through the graph"*, and verified three of them directly. That was the
entity-resolution seam from `docs/real-data.md`, discovered live by the
agent — and since closed (D-042): the alias is merged, and web-01 now
reaches 29 KEV CVEs instead of 3, so expect a longer list with the kernel
entries at the top. If a new seam shows up on stage, let it: *the agent
just found a data quality problem in a public feed, with citations.*
Transcripts: before the merge `demo/act3-claude-code.json` (3 CVEs, the
seam discovered); after it `demo/act3-claude-code-after-aliases.json`
(30 CVEs named, 40 citations all verifiable, 26 tool calls, 175 s). Cheaper models do this in 20 to 30 tool
calls for a few cents (`docs/models.md`).

If time allows, ask a follow-up that uses write-back:

> Record that web-01 was triaged by user jdoe today, source agent-writeback, namespace netsec. Then ask about web-01 again with the question "who triaged this host?" and show me the new fact with its citation.

Rehearsed: 3 tool calls, 23 seconds, $0.43; it records `host:web-01
triaged_by user:jdoe` as an edge to the existing user entity, re-asks,
and shows the new fact ranked first after the standing OS conflict, with
its `cite` token. Transcript: `demo/act3-writeback-claude-code.json`.

## Close (1 min)

- Same contract on a laptop and on Kubernetes with Postgres HA, JetStream,
  and a Go ingest tier — every dial opt-in (`docs/infrastructure.md`).
- Pipelines tie in without code: batch API, Fluent Bit, Vector, Kafka,
  SDKs in Python, TypeScript, Go, OpenAPI for the rest.
- `docs/models.md`: which models drive it well, measured, with cost.
- Repo, Apache-2.0, `v0.1.0`.

## Fallbacks

| If | Then |
| --- | --- |
| The venue network is down | Acts 1 and 2 need no network. For Act 3 use the local Claude Code session if it is authenticated, else open the saved transcripts `demo/act3-claude-code.json` (the rehearsal) or `demo/agent-transcript.json` (a Sonnet 5 `agent_eval` run) and walk through them |
| The connector load was skipped | Act 2 falls back to the seed data: `initech` contract-owner conflict in `procurement`, and the incident report document `IR-4432` |
| Claude Code misbehaves | `docker compose exec loom python -m loom.agent_eval --db /data/loom.db --tasks exposure` prints the same tool sequence and answer with the configured model in ~40 s |
| Someone asks "what if the model lies?" | Every item carries an observation id; 168 of 168 task-runs across fourteen models cited only ids they had seen. The one thing citations cannot catch is a confident "no" — which is why `truncated` exists |
| Someone asks "how fast / how big?" | Single-entity ask 2–5 ms on 465k observations; two-hop scope over 1,077 entities 0.5 s; fresh clone to loaded real corpus in 142 s; measured numbers in `docs/real-data.md`, capacity table in `deploy/README.md` |

## Rehearsal checklist

- [x] Fresh clone, uncached build, seed, first cited answer, connector: 142 s total (2026-09-09, laptop)
- [x] All four `curl` commands above return what the script says (verified 2026-09-09 against the loaded corpus)
- [x] Act 3 run with Claude Code on the current build (2026-09-10); transcripts saved in `demo/`
- [ ] Act 3 re-run the morning of the talk
- [ ] `claude mcp list` shows `loom` connected (or pass `--mcp-config demo/mcp.json --strict-mcp-config`)
- [ ] Fallback files on the desktop; slides have the two diagrams from `docs/infrastructure.md`
