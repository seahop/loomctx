# Demo script (conference, mid-October 2026)

Three acts, about twelve minutes, one laptop, nothing on the host but
Docker. Every number and question below has been run; the fallbacks are
real files, not hopes. Numbers marked *re-verify on the frozen volume*
come from the 2026-09-09/11 corpus and must be re-read from the volume
you actually freeze (below) — the feeds move daily.

**The one sentence.** Loom absorbs facts about entities over time, from
structured claims and documents, and hands an agent a token-budgeted,
cited, question-scoped context pack — conflicts first, provenance always,
and it says when it did not look at everything.

## Before the talk (the night before: ~35 minutes of wall clock plus the provider, then freeze the volume)

The fresh-clone-to-first-answer path is about two and a half minutes
(measured 142 s on 2026-09-09: 26 s uncached build, 6 s up, seed, 110 s
connector incl. feed download). The alias pass on top is **27 minutes of
LLM calls** (D-042). Do all of it the evening before, on a volume you
then never write to again; the morning of the talk is for `readyz` and a
rehearsal, not for loading.

```bash
git clone https://github.com/seahop/Loom && cd Loom
docker compose up -d --build loom
docker compose exec loom python -m loom.seed load                          # prints: loaded 592 claims and 5 documents
docker compose exec --user 10001 loom python -m loom.connectors.vulns load \
    --db /data/loom.db --bridge-seed-hosts                                 # ~110 s incl. feed download, ~525k envelopes (re-verify on the frozen volume)
docker compose exec -e LOOM_LLM_MODEL=google/gemini-3.5-flash-lite loom \
    python -m loom.enrich resolve                                          # alias pass (D-042): ~283 adjudications, ~3 cents, ~27 min — start it, go and eat
```

**Pin the judge.** The alias pass is LLM-adjudicated; D-042's 58 merges,
"web-01 reaches 29 KEV CVEs", and the whole Act 3 answer were measured
with `google/gemini-3.5-flash-lite` as the judge (12/12 on the scorecard,
the fastest model tested — `docs/models.md`). A different judge produces
a different merge set, and every number in Acts 2 and 3 moves with it.
`LOOM_LLM_PROVIDER` / `LOOM_LLM_API_KEY` come from `.env` as usual; only
the model is overridden for this one command.

**Freeze the corpus.** Once the alias pass has printed its counts:

```bash
docker compose exec loom python -m loom.lifecycle export --out /data/demo-frozen.jsonl   # --db defaults to LOOM_DB (/data/loom.db)
docker cp "$(docker compose ps -q loom)":/data/demo-frozen.jsonl ~/Desktop/demo-frozen.jsonl
docker compose stop loom && docker compose start loom      # proves the volume comes back
```

From here on the volume is read-only by policy: no `seed load`, no
connector run, no `enrich`. If it is ever lost, the restore is
`docker compose exec loom python -m loom.lifecycle import --path /data/demo-frozen.jsonl`
on a fresh volume (the export carries tombstones and aliases too, H-B4). If
you must re-run the connector on the day, add `--offline`: it loads
from the feed cache without touching the network, so the venue's Wi-Fi
is not on the critical path.

Then the agent side:

```bash
claude mcp add loom -- docker compose --project-directory "$PWD" run --rm -T loom python -m loom.mcp_server
# or, without touching your Claude Code config: claude --mcp-config demo/mcp.json --strict-mcp-config
```

Set `LOOM_MCP_NAMESPACE=netsec` in `.env` if you want the agent to skip
the namespace argument (compose passes it to the stdio server and the
`mcp` profile). Check `curl -s localhost:8000/readyz` says `ready`, open
a terminal with `claude` in the repo, and keep a second terminal for
`curl`. Put the fallback files (below) on the desktop.

## Act 1 — the shape of the thing (3 min, seed data, `curl`)

*"Which host held 10.0.4.7 on August 20th?"* — the bitemporal star:

```bash
curl -s localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace":"netsec","subject":{"type":"ip","key":"10.0.4.7"},
  "question":"which host was assigned this ip?","valid_at":"2026-08-20T00:00:00Z","budget":600}' | python3 -m json.tool
```

Point at: `laptop-17` (not `web-01`, which held it until Aug 10), every
item's `citations`, `budget` (600) and `charged_tokens` (47 — the pack
spent only what the answer needed). Say: *the agent asked for 600 tokens and
got the most relevant cited facts that fit, and Loom reports what it actually
spent; anything cut becomes a handle it can pull deeper.*

*"What OS does web-01 run?"* — conflicts ship first:

```bash
curl -s localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace":"netsec","subject":{"type":"host","key":"web-01"},
  "question":"what operating system does this run?","budget":400}' | python3 -m json.tool | head -30
```

Point at: item 0 is `kind: conflict`, two sources, two citations; the
`handles` list at the bottom (`74 more 'logged_in_by' observations`, with
`omitted_handles: 4` — web-01 has 77 logins in the seed, and at budget 400
`charged_tokens` is 378; verified 2026-09-24 on the seeded engine). Say:
*Loom never picks a side
silently. The agent sees the disagreement before it sees anything else,
and gets handles for what did not fit.*

## Act 2 — real data (3 min, the vulnerability corpus, `curl`)

Say: *everything so far was seed data we wrote. This is CISA KEV, NVD and
EPSS, 465,000 observations loaded by one command last night.* (465k was
the 2026-09-09 load; re-verify on the frozen volume with
`curl -s localhost:8000/readyz` and the connector's printed counts.)

*"How severe is CVE-2026-0544?"* — a real, unplanted disagreement:

```bash
curl -s localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace":"netsec","subject":{"type":"cve","key":"CVE-2026-0544"},
  "question":"how severe is this?","budget":800}' | python3 -m json.tool | head -40
```

Point at: NIST says 9.8, the CNA says 5.5, conflict first, both cited
(re-verify on the frozen volume: NVD re-scores, and this CVE may have
been reconciled since). Say: *8,552 CVEs this year have two scorers who
disagree (2026-09-09 count; re-verify). Nobody planted that.*

*"Everything about the Linux kernel"* — the honest pack:

```bash
curl -s localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace":"netsec","subject":{"type":"product","key":"linux:linux_kernel"},
  "question":"exploited in the wild","budget":800}' | python3 -c "import json,sys; p=json.load(sys.stdin); print(json.dumps(p['truncated'], indent=1)); print(p['handles'][0]['hint'] if p['handles'] else '(no handles)')"
```

Point at: `truncated: 1,000 of 2,747` (re-verify on the frozen volume —
the total grows with every NVD day) and the single handle for the rest.
Say: *when Loom did not look at everything, it says so. An agent cannot
honestly answer "no" from this pack.*

## Act 3 — an agent on its own (5 min, Claude Code over MCP)

In the `claude` terminal, type exactly:

> Is host web-01 exposed to any vulnerability that CISA lists as exploited in the wild? Work out what software it runs and which of those products have such CVEs. Name the CVEs and the software, and cite observation ids. Namespace is netsec. Use budget 1500 for scope asks.

The last sentence is deliberate. In the 2026-09-11 rehearsal the agent's
first `ask_scope` came back larger than Claude Code's inline tool-result
limit, so the CLI spilled it to a file on disk and the agent spent 7 of
its 26 calls running `grep` and `Read` over its own tool output
(`demo/act3-after-aliases.md` shows them). Correct, but not the story;
a 1,500-token scope pack stays inline and the handles do the rest.
Rehearse with the sentence in; if the agent still spills, say so on
stage — *the pack was bigger than the agent's inbox, so it asked for
less* — and move on.

Narrate the tool calls as they scroll: `describe_namespace` (*it learns
the schema — Loom is domain-agnostic, the domain is data*), `find_entity`
(*names to handles*), `ask_scope` with `expand_predicates` (*two hops:
host → software ← CVE, in one call*), `ask` on each candidate CVE (*it
verifies*), `find_related` (*meaning-based search over the advisories*),
then the answer.

What to expect (rehearsed 2026-09-11 with Claude Code, the account's
default model `claude-fable-5-1`, after the alias merges): 26 tool calls,
173 seconds, $4.84, and an answer naming **30 KEV CVEs** across the
kernel and OpenSSL — `CVE-2014-0160` (Heartbleed) and the kernel entries
at the top — with 40 citations, every one an observation id the agent
had actually seen, nothing invented. It also reports the standing
`runs_os` conflict on web-01 before it answers, unprompted. (Re-verify on
the frozen volume: KEV adds kernel entries most weeks.)

The seam, as an anecdote (tell it while the calls scroll): in the first
rehearsal, a day earlier, the same question produced only three CVEs and
then the agent said something we had not planted — *"the kernel is
double-keyed: the KEV connector files kernel entries under
`linux:kernel`, NVD and the inventory use `linux:linux_kernel`; about 25
more kernel KEV CVEs hang off the KEV key and never reach web-01 through
the graph"* — and verified three of them directly. That was the
entity-resolution seam from `docs/real-data.md`, found live by an agent
with citations. D-042 closed it: the alias pass you ran last night is
what merged the two keys, which is why tonight's answer is 30 CVEs, not
3. If a new seam shows up on stage, let it: *the agent just found a data
quality problem in a public feed, with citations.*

Transcripts: `demo/act3-after-aliases.md` (30 CVEs, 26 calls) and
`demo/act3-before-aliases.md` (3 CVEs, the seam discovered); the JSON
beside each carries the full arguments. Cheaper models do this in 20 to
30 tool calls for a few cents (`docs/models.md`).

If time allows, ask a follow-up that uses write-back:

> Record that web-01 was triaged by user jdoe today, source agent-writeback, namespace netsec. Then ask about web-01 again with the question "who triaged this host?" and show me the new fact with its citation.

Rehearsed 2026-09-10: 3 tool calls, 23 seconds, $0.43; it records `host:web-01
triaged_by user:jdoe` as an edge to the existing user entity, re-asks,
and shows the new fact ranked first after the standing OS conflict, with
its `cite` token. Transcript: `demo/act3-writeback-claude-code.json`.
(This one writes to the volume; it is the only write the day allows, and
`demo-frozen.jsonl` does not include it.)

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
| The venue network is down | Acts 1 and 2 need no network. For Act 3 use the local Claude Code session if it is authenticated, else open `demo/act3-after-aliases.md` (the rehearsal, tool calls then the verbatim answer), `demo/act3-before-aliases.md` (the seam) or `demo/agent-transcript.json` (a Sonnet 5 `agent_eval` run) and walk through them |
| The connector load was skipped | Act 2 falls back to the seed data: `initech` contract-owner conflict in `procurement`, and the incident report document `IR-4432` |
| Claude Code misbehaves | `docker compose exec loom python -m loom.agent_eval --db /data/loom.db --tasks exposure` prints the same tool sequence and answer with the configured model in ~40 s |
| Someone asks "what if the model lies?" | Every item carries an observation id; 216 of 216 task-runs across eighteen models cited only ids they had seen (`docs/models.md`). The one thing citations cannot catch is a confident "no" — which is why `truncated` exists |
| Someone asks "how fast / how big?" | Single-entity ask 2–5 ms on 465k observations; two-hop scope over 1,077 entities 0.5 s; fresh clone to loaded real corpus in 142 s (all laptop, generator co-located; `docs/real-data.md`); real nodes: 421/s load, 202/s ingest, 186/s ask on GKE (`deploy/README.md`) |

## Rehearsal checklist

Dated: every line below was true on the date shown, and the 2026-09-23
fix batch (dependency lock, compose passthroughs, consumer validation,
new pod posture) means each must be re-run on the current build before
the talk.

- [x] Fresh clone, uncached build, seed, first cited answer, connector: 142 s total (2026-09-09, laptop)
- [x] Both Act 1 `curl` commands return what the script says (2026-09-23, seeded engine on the current build: laptop-17 + charged_tokens 47, conflict first + charged_tokens 378, 77 logins / "74 more" handle)
- [x] Both Act 2 `curl` commands return what the script says (2026-09-09 corpus) — **re-run on the frozen volume**
- [x] Act 3 run with Claude Code (2026-09-10 before aliases, 2026-09-11 after); transcripts saved in `demo/`
- [ ] Night-before load on the current build, alias pass with the pinned judge, `demo-frozen.jsonl` exported and copied off
- [ ] Act 2 numbers re-read from the frozen volume and edited into this file
- [ ] Act 3 re-run on the frozen volume with the "budget 1500" sentence; confirm no `Read`/`grep` over tool-result files in the transcript
- [ ] Act 3 re-run the morning of the talk (no writes to the volume other than the write-back follow-up)
- [ ] `claude mcp list` shows `loom` connected (or pass `--mcp-config demo/mcp.json --strict-mcp-config`)
- [ ] Fallback files on the desktop; slides have the two diagrams from `docs/infrastructure.md`
