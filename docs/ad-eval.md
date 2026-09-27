# Measuring AD reachability (a capability benchmark)

The AD analogue of the KEV multi-hop retrieval benchmark
([evaluation.md](evaluation.md)). It asks one question of the raw-LDAP
connector ([interop.md](interop.md#raw-ldap--ldif-active-directory--loom)):
when a real reachability chain exists in a directory — a low-privilege
principal to a high-value target, threading **membership → ACL → (cross-domain)
trust** — does Loom's ordinary scope walk **surface the full chain with every
edge cited**, and how much of the store does it have to sort through to do it?

> **Status (2026-09-26): measured blind (D-078, closes S-51).** The first
> run (D-066) handed the walk each planted chain's predicates, depth and
> interior anchors, and scored decoys in a way a walk that found nothing
> also passed; those numbers are withdrawn. The tables below are blind: the
> walk knows only the start and the target the question names.

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

# blind (the headline): only the two named endpoints are known
python -m loom.ad_eval --db /data/ad.db --generate --scale medium --seed 7 --blind
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

## The metrics (blind)

Scored per hop-length bucket and per token budget (1500 / 3000 / 4000).
Every walk knows only the start and the target:

- **scope walk** — one ask anchored at each endpoint over the fixed
  predicate set `member_of, has_ace, trusts, contains, can_delegate_to,
  rbcd_from` at the depth cap (3), plus an account-status ask on the start.
- **find_path** — start → target over the same set at the default depth
  (4); a path's `node_status` (an account's `enabled`) counts as cited
  evidence.
- **recall** — planted chains whose *every* edge came back **cited** (a
  citation with a real observation id).
- **decoys** — each lands in one outcome: *evidenced* (the apparent path
  and its disqualifying fact — the trust's `transitive` / `sid_filtering`
  attr, or the start's `enabled = false` — both came back cited, so a
  reader can reject it), *not surfaced*, or *leaked* (the path without its
  disqualifier). A trust edge always carries its attrs, so for trust decoys
  evidenced == surfaced: a property of the connector's data model, not a
  retrieval score. No precision figure is given.
- **entities gathered vs total**, **truncated** walks, **build latency**
  p50/p95 and **pack tokens**.

## Results — blind, seed 7 (2026-09-26, after D-080/D-081)

Scope walk (two endpoint asks + the start's account-status ask):

| Scale / store | Observations | All recall at 1,500 / at 3,000+ | Decoys evidenced / not surfaced / leaked | Entities gathered / total | Build p50 / p95 at 3,000 |
| --- | --- | --- | --- | --- | --- |
| medium, SQLite (laptop) | 31,433 | 11/11 · 11/11 | 6 / 0 / 0 | 920 / 4,429 | 0.58 s / 2.4 s |
| large, SQLite (laptop) | 97,815 | 11/11 · 11/11 | 6 / 0 / 0 | 979 / 13,529 | 1.3 s / 2.9 s |
| medium, Postgres (GKE) | 31,433 | 9/11 · 11/11 | 6 / 0 / 0 | 918 / 4,429 | 0.76 s / 3.5 s |
| large, Postgres (GKE) | 97,815 | 11/11 · 11/11 | 6 / 0 / 0 | 979 / 13,529 | 1.35 s / 5.7 s |

find_path (start → target, default depth 4):

| Scale / store | All recall at 1,500 / at 3,000+ | Decoys evidenced / not surfaced / leaked | p50 |
| --- | --- | --- | --- |
| medium, SQLite | 11/11 · 11/11 | 6 / 0 / 0 | 0.10 s |
| large, SQLite | 10/11 · 11/11 | 6 / 0 / 0 | 0.12 s |
| medium, Postgres (GKE) | 10/11 · 11/11 | 6 / 0 / 0 | 0.15 s |
| large, Postgres (GKE) | 9/11 · 11/11 | 6 / 0 / 0 | 0.20 s |

(GKE: a toolbox pod against the `scale-pg-ha` Postgres, 3 instances at
1 GiB, the store loaded directly into a fresh namespace and asked at once.
Where recall misses at 1,500 tokens it is a 4-hop chain that did not fit
the budget; from 3,000 every chain comes back.)

**Reading it.** Recall survives blinding: every planted chain, the
cross-domain 4-hop ones included, comes back fully cited from 3,000 tokens,
by the endpoint asks and by find_path alike. What blinding first exposed
was the cost. The initial blind run gathered about half the directory
(2,108 of 4,429 entities) at 4–11 s per ask, because a walk climbed to an
OU or group and came back down to all its contents; find_path could not
return 4-hop chains at all and returned the disabled-account decoys without
the `enabled = false` that disqualifies them. D-080 stopped the walk turning
back along the predicate that reached an entity, made find_path search from
both ends to depth 6, and added `node_status` so a path through a disabled
account comes back flagged; D-081 fixed the Postgres planner statistics
that made a freshly loaded namespace ~50× slower. The D-066 figure of
~2.5 % gathered in ~0.2 s was still a product of being told the chain: a
blind walk gathers ~20 % of the medium directory (7 % of large) in about a
second.

## A live reader (illustrative, not a headline)

(Run on the D-066 non-blind packs; not re-run blind.)

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
smoke, not a metric; the blind scripted tables above are the measured result.
