# Real data: the vulnerability-intelligence connector (D-035)

Everything before this page was tested against a corpus we wrote knowing
the answers (~590 seed claims, 5 documents). This is the first data Loom
did not author: three public, keyless feeds, one command, loaded next to
the seed hosts so the demo can ask a real question about them.

| Feed | What it contributes | Source tag |
| --- | --- | --- |
| [NVD 2.0 yearly feeds](https://nvd.nist.gov/vuln/data-feeds) | per CVE: `status`, trimmed `summary`, one `cvss_score` + `has_severity` **per scorer**, `has_weakness` → cwe, `affects` → product (from vulnerable CPEs), product `made_by` vendor | `nvd`, `nvd:<scorer>` |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `exploited_in_wild`, `ransomware_campaign_use`, `affects` (freehand vendor/product), `has_weakness`, and the advisory text as a **document** per entry | `cisa-kev` |
| [FIRST EPSS](https://www.first.org/epss/) | `epss_score`, `epss_percentile` for the CVEs already present | `first-epss` |

Everything lands in one namespace (`netsec` by default). Every envelope
has a deterministic `event_id` that embeds the record's own modification
stamp, so a re-run dedupes and a record NVD has re-scored records a *new*
observation: the namespace accumulates real history, and `as_of` questions
mean something.

## Run it

```bash
docker compose up -d loom
docker compose exec loom python -m loom.seed load                     # the demo hosts
docker compose exec --user 10001 loom python -m loom.connectors.vulns load \
    --db /data/loom.db --bridge-seed-hosts                             # ~2 minutes
```

`--bridge-seed-hosts` adds `runs_software` edges from the seed hosts to
common products (kernel, nginx, openssh, postgresql, chrome, …) so the
demo question is a two-hop traversal. Other forms:

```bash
python -m loom.connectors.vulns load --url http://loom:8000 --key loomk_…   # through the batch API
python -m loom.connectors.vulns emit --years 2026,2025 > vulns.jsonl        # NDJSON for loom.ingest
python -m loom.connectors.vulns pull                                        # refresh the cache only
python -m loom.connectors.vulns schema                                      # the registry it declares
```

Flags: `--years` (default: this year), `--sources kev,nvd,epss`, `--epss
known|all|none`, `--cache DIR` (default `/data/feeds`, or `$LOOM_FEED_CACHE`),
`--offline`. Feeds are fetched with conditional GETs and streamed
(`ijson`), never held in memory. On Kubernetes,
`deploy/k8s/jobs/vulns-refresh.yaml` runs it nightly against the engine.

Run the connector as the engine's uid (`--user 10001` in compose) so the
SQLite WAL files it creates stay writable by the engine.

## The demo questions

```bash
# 1. A real cross-scorer conflict, first in the pack (NIST 9.8 vs the CNA 5.5)
curl -s localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace":"netsec","subject":{"type":"cve","key":"CVE-2026-0544"},
  "question":"how severe is this?","budget":1200}'

# 2. A KEV entry: the exploited-in-the-wild flag ranks first for this question
curl -s localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace":"netsec","subject":{"type":"cve","key":"CVE-2026-2441"},
  "question":"is this exploited in the wild?","budget":1200}'

# 3. The two-hop question: host -> software <- CVE, the chain shipped as relations
curl -s localhost:8000/v1/answer -H 'content-type: application/json' -d '{
  "namespace":"netsec",
  "scope":{"subjects":[{"type":"host","key":"web-01"}],"expand":["runs_software","affects"],"depth":2},
  "question":"Is web-01 exposed to anything actively exploited in the wild? Which CVE, which software, and cite.",
  "budget":3000}'
```

## What the first run measured (2026-09-08, laptop, SQLite, one container)

| | |
| --- | --- |
| Feeds pulled | KEV 1.7 MB, EPSS 2.6 MB, NVD 2026 27.6 MB (gz) — 20 s |
| Envelopes | 511,554 claims + 1,699 documents (NVD 394,300 · EPSS 108,796 · KEV 10,131 · bridge 29) |
| First load, direct to store | 81 s → **6,300 envelopes/s**, 0 rejected |
| Idempotent re-run | 25 s (20,000/s), nothing new recorded |
| Loader peak RSS | 104 MB |
| Store after load | 344 MB; 465,070 observations in `netsec` |
| CVEs / products / KEV documents | 53,666 / 6,612 / 1,699 |
| **Cross-scorer CVSS conflicts** | **8,552 CVEs** where two scorers disagree (of 10,147 scored twice) — none planted |
| Single-entity ask, after fixes | CVE 2 ms · host 4 ms · product hub 12–40 ms (p50–max, 15 samples each) |
| Two-hop scope, web-01 (1,077 entities reached) | 0.5 s |
| Two-hop scope, laptop-17 (2,448 reached) | 1.1 s |

The generator and the engine shared one laptop; the point is the relative
numbers and the shape of the packs, not capacity.

## What it exposed — and what changed

Six core fixes came out of the first afternoon with real data. Each has a
regression test; the design notes are under D-035 in `decisions.md`.

1. **The read path scanned the namespace.** `observations_for` asked for
   `subject_id = ? OR object_entity_id = ?`; SQLite planned the OR as a scan
   of every row in the namespace — 229 ms per call at 465k rows, invisible
   at 590. A 1,000-subject scope took 262 s and timed out. Both stores now
   run two indexed halves merged with `UNION ALL`: 0.1 ms per call, the
   scope 0.5 s. Every ask in the product got ~100× faster at this size.
2. **Conflict detection was quadratic on scopes** (every observation scanned
   once per subject: 20 s of model comparisons). Grouped once.
3. **8,234 expansion handles on one pack.** Capped at 32 in priority order;
   the new `omitted_handles` field says how many were left.
4. **965 one-observation handles on a hub.** Edges pointing *into* a pack
   subject from outside the pack now aggregate into one `pointing at`
   thread — "965 more 'affects' observations pointing at product:linux:linux_kernel".
5. **Conflicts flooded wide scopes.** The web-01 pack was 53 conflicts and
   zero facts, and the answering model correctly said it could not answer.
   Conflicts keep priority but take at most half the budget; the overflow
   is still signalled as conflict handles.
6. **Facts arrived without their chain.** After (5) the pack held "CVE-X
   exploited_in_wild" but fresher EPSS rows had outranked "web-01 runs
   nginx" and "CVE-X affects nginx", and the model again refused to connect
   the dots — rightly. A fact about an entity a scope reached now ships
   with the edges it was reached through, as `relation` items just before
   it. With that, the answer names web-01's nginx, the CVE affecting it, the
   two scorers' disagreement, and cites every step.

What the answering model did *not* do, recorded for honesty: it leaned on
EPSS percentiles for "actively exploited" rather than the explicit KEV
facts that were also in the pack — the rendered text `exploited_in_wild
True (per cisa-kev)` reads less naturally than a score. A friendlier
rendering of boolean facts is a small follow-up.

## An agent on its own (D-036, 2026-09-09)

`/v1/answer` tests a model as a reader of a pack Loom built. The demo's
promise is an agent that finds the data itself, so
`python -m loom.agent_eval --db /data/loom.db` runs a real model over the
real MCP transport (stdio) with four tasks and no pre-built scope. Ground
truth is computed from the store; a task passes only if the right entities
are named, none are invented, and every cited id was seen in a tool result
during that run.

| Run | Model | Surface | exposure (2-hop) | lease | conflict | os |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | deepseek-chat-v3.1 | as shipped | FAIL — dropped `namespace` after 2 calls, 12 steps against an empty namespace, 130k tokens | PASS | PASS | PASS* |
| 2 | deepseek-chat-v3.1 | + `list_namespaces` / `describe_namespace`, empty-namespace error | FAIL — right `ask_scope` on the first try, but the 69k-char result was mostly the 1,077-entity subject list and held no KEV fact | PASS | PASS | PASS |
| 4 | deepseek-chat-v3.1 | + agent pack view, subject-name ranking fix, compact handles | FAIL — called `ask_scope` without `expand_predicates`, reached products only | PASS | PASS | PASS |
| 5 | claude-haiku-4.5 | same as run 4 | **PASS** — 2 of 3 KEV CVEs named, 0 invented, 6/6 citations faithful, 13 steps, 50 s | PASS 7 s | PASS 9 s | PASS 8 s |

\* run 1's os "failure" was the scorer wanting `ubuntu-22.04` verbatim; the agent had written "Ubuntu 22.04".

What the runs changed in the MCP surface, each with a test:

- **Orientation tools.** `list_namespaces` (entity counts by type) and
  `describe_namespace` (entity types, registered predicates with
  descriptions and containment, a multi-hop hint). Before them, an agent
  had no way to learn that `affects` or `exploited_in_wild` existed.
- **An empty namespace is an error, not an empty list.** Run 1 lost twelve
  steps to a dropped argument; now the tool says which namespaces hold
  data. `LOOM_MCP_NAMESPACE` makes the argument optional for a single-team
  server.
- **The agent view of a pack.** Items first, no null citation fields,
  reached subjects summarized (20 shown + a total). The same two-hop pack
  went from 69k to 18k chars, and handle ids from 131 to 83 chars.
- **Naming the subject is not the topic.** "Is web-01 exposed to anything
  exploited?" made every recent login *about web-01* match as many question
  words as the KEV fact two hops away, and recency did the rest; the pack
  held no `exploited_in_wild` fact at all. The root subjects' own name
  tokens are now excluded from relevance. After the fix the default-budget
  pack carries `host:web-01 runs_software linux_kernel` → `CVE-2026-53362
  affects linux_kernel` → `CVE-2026-53362 exploited_in_wild True`.

Twenty models measured the same way, with cost: `docs/models.md`.

What is honest about the remaining gap: the surface now delivers the
answer in one correctly formed call, and a capable small model makes that
call; a weaker tool-calling model still omits `expand_predicates` despite
the hint, and then wanders one CVE at a time. Haiku also did something the
single-shot answer had not: it checked a high-EPSS CVE and correctly ruled
it out because no KEV fact existed for it.

## What is still open (roadmap phase 8)

- ~~Hub truncation is silent.~~ Fixed (D-038): packs carry `truncated`
  (the kernel: 1,000 of 2,740 gathered), the MCP view warns, and the
  answering prompt says so. The limit itself stays; the point is that a
  reader can no longer conclude absence from a partial gather.
- **Entity resolution on real keys.** KEV names products freehand ("NGINX
  Open Source"); NVD keys them by CPE (`nginx:nginx`, and since the F5 era
  `f5:nginx_open_source`; `haxx:curl` vs `curl:curl`). Only 91 of 708 KEV
  product keys match a CPE key in this load. The connector deliberately does
  not paper over that — it is the resolution worker's job (D-023) and the
  demo should show the seam rather than hide it.
- ~~KEV documents are loaded but not embedded.~~ Done (D-039): see
  "Documents" below.
- **Only this year's NVD feed by default.** `--years 2026,2025,…` widens
  it; every year adds ~400k claims and ~25 MB of download.

## Writing your own connector

`src/loom/connectors/vulns.py` is the pattern: a `pull` step with a cache
and conditional GETs, pure `*_envelopes()` mappers from a source record to
`ClaimIn`/`DocumentIn` (unit-tested on trimmed real shapes), a `schema()`
registration for the namespace, and `load` that streams through
`loom.ingest`. The engine learns nothing about your domain; the schema
registration carries it.
