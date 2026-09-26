# Measuring AD reachability (a capability benchmark)

The AD analogue of the KEV multi-hop retrieval benchmark
([evaluation.md](evaluation.md)). It asks one question of the raw-LDAP
connector ([interop.md](interop.md#raw-ldap--ldif-active-directory--loom)):
when a real reachability chain exists in a directory — a low-privilege
principal to a high-value target, threading **membership → ACL → (cross-domain)
trust** — does Loom's ordinary scope walk **surface the full chain with every
edge cited**, and how much of the store does it have to sort through to do it?

>
> **Status (2026-09-26): numbers are withdrawn pending a blind
> re-measurement (S-51).** The connector's decoding gaps (S-50) have been
> fixed (D-074), but the benchmark itself is not a fair test:
>
> - **Recall is not blind.** The walk was given the planted chain's own
>   `expand` predicates and its exact depth (`ad_eval.build_chain_packs`), so
>   the 100% recall overstates what a blind walk (a fixed generic predicate
>   set, the standard depth cap) would find.
> - **Decoy-exclusion and edge-precision are tautological as computed** and
>   are **withdrawn**: a trust edge always carries its `transitive` /
>   `sid_filtering` attrs, so "disqualifier cited" was always true, a walk
>   that found nothing also scored "excluded", and precision could only drop
>   if a decoy leaked, which it could not.
> - The **~2.5% / <1% "gathered"** figure reflects the generator's uniform
>   density (no large hub groups), not hub pressure.
>

It is **synthetic and object-level only**. `loom.connectors.ad_gen`
generates a directory, plants known chains, and buries them in dense benign
noise; `loom.ad_eval` loads it through the connector and scores retrieval
with a **scripted reader** (no LLM, no cost). It computes no path *ranking*
and emits no exploitation guidance: the truth sidecar already names each
chain's edges, and the metric is only "present + cited?". This measures
Loom, not an attacker.

## Generate → import → score

```bash
# a deterministic directory + a truth sidecar (chains and decoys)
python -m loom.connectors.ad_gen --seed 7 --scale medium --out corp.ldif --truth corp.truth.json

# load it through the ordinary raw-LDAP connector
python -m loom.connectors.ldap import corp.ldif --namespace ad --db /data/ad.db

# score (scripted reader; no network)
python -m loom.ad_eval --db /data/ad.db --truth corp.truth.json --namespace ad

# or all three in one shot into a scratch store
python -m loom.ad_eval --db /data/ad.db --generate --scale medium --seed 7
```

An optional `--live` runs a cheap model (`--model`, e.g. a
`google/gemini-2.5-flash` via an `--env-file` of `LOOM_LLM_*`) over a few
chains to confirm an agent assembles and cites the chain; it is capped at
`--max-cost` and is never the headline.

## What the generator plants

Domains are obviously fake: `corp.local` (root), `dev.local` (a
bidirectional, transitive child-domain trust the good cross-domain chains
cross), and two external partners used only by decoy trusts —
`partner.local` (non-transitive) and `fabrikam.local` (SID-filtered /
quarantined). Everything — SIDs, names, memberships, ACLs — is drawn from
one seeded RNG in a fixed order, so a `(seed, scale)` is byte-reproducible.
The SD/ACE bytes on the ACL edges are real self-relative Security
Descriptors the connector's own parser decodes (the generator imports the
connector's right/GUID/ACE constants rather than duplicating them).

| Scale | users | groups | computers | nesting depth |
| --- | --- | --- | --- | --- |
| `small` | ~500 | ~100 | ~150 | 3 |
| `medium` | ~3,000 | ~600 | ~800 | 3–5 |
| `large` | ~10,000 | ~1,500 | ~2,000 | 3–5 |

Dense benign edges — every object's `contains` parentage, 1–4 group
memberships per user with nested groups, and benign ACLs over a slice of
principals — so the planted signal is a **small fraction of all edges**.

**Chains** (per truth record: start, target, the ordered
`(subject, predicate, object)` edges): 2-hop (`member_of` → `has_ace`),
3-hop (`member_of` → `member_of` → `has_ace`) and 4-hop cross-domain
(`member_of` → `member_of` → `has_ace` on the domain → `trusts` dev.local).
Rights vary over GenericAll / WriteDacl / ForceChangePassword / AddMember.

**Decoys** — chains that look like they connect but dead-end, so a correct
answer must exclude them: a **non-transitive** trust, a **SID-filtered**
trust, and a **disabled** start account. Each decoy's truth record names its
disqualifying fact.

## The metrics

Scored per hop-length bucket and per token budget (1500 / 3000 / 4000):

- **path-recall** — planted chains whose *every* edge is present in the pack
  **and cited** (a citation with a real observation id). The headline.
- **edge-precision** — of the edges in a "connects" verdict, the fraction on
  a genuine chain; a decoy wrongly reported connecting drops it.
- **decoy-exclusion** — the dead-end's disqualifying fact (the trust's
  `transitive` / `sid_filtering` attr, or the start's `enabled = false`) was
  itself surfaced and cited, so a reader has the evidence to reject it.
- **entities gathered vs total** — the mean entities the scope walk pulled
  per chain against the whole store: the "sorted through this much" number.
- **truncated** — walks the D-058 scope cap / D-061 hub completion touched.
- **build_pack latency** p50/p95, and **pack tokens** charged.

A 4-hop chain is walked in two asks re-anchored at the deepest chain node
the first reached (`ScopeSpec.depth` caps at 3, D-046) — what an agent does
following a pack's reached entities. Node account-status is a subject-scoped
ask per principal (a broad path walk ranks that scalar out), the way a
reader validates that each account on a lead is live.

## Results — `medium`, seed 7 (executed 2026-09-26)

Directory: 4,429 objects (3,017 users / 601 groups / 800 computers, 4 DCs),
**31,430 observations**, 4,429 entities, 8,702 raw membership+ACL edges.
Planted: 11 chains + 6 decoys. Ingest through the connector: 31,430
observations in 2.9 s = **10,683 obs/s** (1,505 objects/s). SQLite store,
scripted reader.

| Budget | 2-hop recall | 3-hop recall | 4-hop recall | All recall | Edge precision | Decoy excluded | Entities gathered / total | Truncated | Build p50/p95 ms | Pack tokens |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1500 | 100% (4/4) | 100% (4/4) | 100% (3/3) | 100% (11/11) | 100% | 100% (6/6) | 113 / 4,429 | 0 | 130 / 218 | 2,387 |
| 3000 | 100% (4/4) | 100% (4/4) | 100% (3/3) | 100% (11/11) | 100% | 100% (6/6) | 113 / 4,429 | 0 | 122 / 201 | 4,159 |
| 4000 | 100% (4/4) | 100% (4/4) | 100% (3/3) | 100% (11/11) | 100% | 100% (6/6) | 113 / 4,429 | 0 | 151 / 241 | 5,317 |

Decoy exclusion by dead-end kind (disqualifier surfaced + cited): 100% (2/2)
for each of `disabled_principal`, `non_transitive_trust`,
`sid_filtered_trust` at every budget.

**Reading it.** Loom surfaces and cites the whole chain for every planted
lead — 2-, 3- and 4-hop, single- and cross-domain — while the walk pulls
~113 of 4,429 entities (≈2.5% of the store, a small fraction of the 31k
observations) and builds in ~0.1–0.25 s. Every decoy is excludable because
its disqualifying fact ships cited alongside the apparent path. This is
retrieval only (no LLM); it says the evidence and citations are there for a
reader to assemble and check the path — not how to use one.

## Results — `large`, seed 7 (executed 2026-09-26)

Directory: **13,529 objects** (10,017 users / 1,501 groups / 2,000
computers, 10 DCs), **97,812 observations**, 28,311 raw edges. Same 11
planted chains + 6 decoys. Ingest **6,348 obs/s**. SQLite, scripted reader.

| Budget | All recall | Edge precision | Decoy excluded | Entities gathered / total | Truncated | Build p50/p95 ms | Pack tokens |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1500 | 100% (11/11) | 100% | 100% (6/6) | 131 / 13,529 | 0 | 198 / 398 | 2,377 |
| 3000 | 100% (11/11) | 100% | 100% (6/6) | 131 / 13,529 | 0 | 277 / 341 | 4,140 |
| 4000 | 100% (11/11) | 100% | 100% (6/6) | 131 / 13,529 | 0 | 258 / 449 | 5,307 |

**Scaling.** The directory tripled (4.4k → 13.5k objects, 31k → 98k
observations) but the targeted walk still pulls ~131 entities per chain —
now **under 1 %** of the store — and build latency stays ~0.2–0.28 s. A
scope walk that starts at the principal and follows named predicates does
not get slower as the surrounding directory grows, only as the path
lengthens; recall, precision and decoy-exclusion stay at 100 %.

## A live reader (illustrative, not a headline)

`--live` runs a cheap model over the packs to confirm the path is not just
present but *assemblable*. On `large`, `google/gemini-2.5-flash` over 5
cases assembled and cited the chain in **3 of 5** for $0.011. The two
misses were a 2-hop and a 3-hop case (not the 4-hop ones): retrieval was
perfect — the cited chain to the asked target was in every pack — but the
model reported a path to a *different* reachable target than the one named
in the question, stopping at the first high-value node it reached. That is
a reader-following limitation on a busy directory, not a retrieval gap, and
it tracks the agent scorecard (`docs/models.md`), where stronger models
clear the analogous multi-hop task and cheaper ones vary. Five cases is a
smoke, not a metric; the scripted tables above are the measured result.
