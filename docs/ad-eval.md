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
- **find_path** — start → target over the same set at the default depth.
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

## Results — blind, seed 7 (2026-09-26)

Scope walk:

| Scale / store | Observations | Budget | Recall 2 / 3 / 4-hop | Decoys evidenced / not surfaced / leaked | Entities gathered / total | Build p50 / p95 |
| --- | --- | --- | --- | --- | --- | --- |
| medium, SQLite (laptop) | 31,433 | 1500 | 4/4 · 4/4 · 3/3 | 6 / 0 / 0 | 2,108 / 4,429 | 4.2 s / 8.8 s |
| medium, SQLite (laptop) | 31,433 | 4000 | 4/4 · 4/4 · 3/3 | 6 / 0 / 0 | 2,108 / 4,429 | 5.9 s / 10.7 s |
| large, SQLite (laptop) | 97,815 | 1500 | 4/4 · 4/4 · 3/3 | 6 / 0 / 0 | 2,497 / 13,529 | 6.3 s / 7.2 s |
| large, SQLite (laptop) | 97,815 | 4000 | 4/4 · 4/4 · 3/3 | 6 / 0 / 0 | 2,497 / 13,529 | 7.5 s / 9.0 s |
| medium, Postgres (GKE) | 31,433 | 1500 | 4/4 · 4/4 · **0/3** | 6 / 0 / 0 | 2,273 / 4,429 | 6.3 s / 6.8 s |
| medium, Postgres (GKE) | 31,433 | 4000 | 4/4 · 4/4 · 3/3 | 6 / 0 / 0 | 2,273 / 4,429 | 6.4 s / 6.9 s |
| large, Postgres (GKE) | 97,815 | 1500 | 4/4 · 4/4 · 3/3 | 6 / 0 / 0 | 2,517 / 13,529 | 10.0 s / 10.8 s |
| large, Postgres (GKE) | 97,815 | 4000 | 4/4 · 4/4 · 3/3 | 6 / 0 / 0 | 2,517 / 13,529 | 10.8 s / 11.5 s |

find_path (the same at every budget):

| Scale | Recall 2 / 3 / 4-hop | Decoys evidenced / not surfaced / leaked | p50 |
| --- | --- | --- | --- |
| medium, SQLite | 4/4 · 4/4 · 0/3 | 4 / 0 / 2 | 1.0–1.2 s |
| large, SQLite | 4/4 · 4/4 · 0/3 | 4 / 0 / 2 | 1.2–1.3 s |
| medium, Postgres (GKE) | 4/4 · 4/4 · 0/3 | 4 / 0 / 2 | 1.2–1.3 s |
| large, Postgres (GKE) | 4/4 · 4/4 · 0/3 | 4 / 0 / 2 | 1.1–1.8 s |

(Laptop timings were taken under heavy unrelated host load. The GKE rows
ran from a toolbox pod against the `scale-pg-ha` Postgres (3 instances,
1 GiB each), the engine's own read path; the store was loaded directly, not
through the gateway.)

**Reading it.** Recall survives blinding — every planted chain, including
the cross-domain 4-hop ones, comes back fully cited from the two endpoint
asks — but the cost does not. With `contains` in a generic predicate set
the walk climbs to the OU / domain and back down, gathering about half the
directory (2,108 of 4,429 entities; 2,497 of 13,529 at large, where the
scope cap stops it) at several seconds per ask — 6 s on the medium directory and 10–11 s on the
large one against Postgres. On Postgres at 1,500 tokens the medium
directory's 4-hop chains did not fit (0/3; 3/3 from 3,000 up): the budget,
not the walk, is the limit there. The D-066 figure of ~2.5 %
gathered in ~0.2 s was a product of being told the chain. find_path finds
every 2- and 3-hop chain but no 4-hop one (its depth is capped at 3,
S-58), and returns the disabled-account decoys' paths without the
`enabled = false` that disqualifies them (the scope walk's account-status
ask does surface it). Trust decoys come back with their `transitive` /
`sid_filtering` attrs on the cited edge either way.

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
