# Performance history

Speed numbers from every measured run, in one place, so a regression shows up
against the run before it. Accuracy lives with each scorecard
(`docs/evaluation.md`, `docs/models.md`); this file is only about time and
size. Add a row after each run, with the build, the hardware and where the
raw output is. Compare rows only on the same setup: a GKE job and a laptop
are different machines, and nodes shared by several stores are slower than a
node with one.

## Retrieval: pack build (the read path, no LLM)

The retrieval scorecard (`python -m loomctx.retrieval_eval`) times building
each context, on the real vulnerability corpus (542,100 observations), 53
questions × 3 runs per condition. One GKE job, 1 vCPU requested.

LoomCtx pack build, p50 / p95, by token budget:

| Run | Build | 400 | 800 | 1,600 | 3,200 |
| --- | --- | --- | --- | --- | --- |
| 2026-09-29 | `main` after D-091…D-103 | 12 ms / 3,206 ms | 5 ms / 3,218 ms | 5 ms / 3,033 ms | 5 ms / 3,092 ms |
| 2026-10-14 | `scale-xl` ca15cbb | 6 ms / 538 ms | 3 ms / 171 ms | 3 ms / 164 ms | 3 ms / 171 ms |

The vector baseline on the same runs (cosine ranking over the same
candidates), for scale: 292–583 ms / 4.2–8.8 s on 2026-09-29, and
388–776 ms / 2.8–5.9 s on 2026-10-14.

Earlier runs (2026-09-24, 2026-09-27) recorded build time in a format that
didn't carry over; their accuracy is in `docs/evaluation.md`.

## Agents over MCP: time per tool call

From the agent transcripts: each tool call's MCP round trip, every model,
named queries on. The 2026-10-14 full run (build eecdff9), 10k forest on
the scale pool, 500k forest on `evalmem` with two 7.5 GB stores per node.

| Tool | 10k p50 / p95 | 500k p50 / p95 |
| --- | --- | --- |
| `ask` | 321 ms / 508 ms | 518 ms / 1,015 ms |
| `ask_scope` | 379 ms / 1,355 ms | 716 ms / 4,570 ms |
| `list_entities` | 20 ms / 261 ms | 270 ms / 4,669 ms |
| `run_query` | 21 ms / 257 ms | 32 ms / 4,169 ms |
| `find_path` | 17 ms / 117 ms | 24 ms / 439 ms |
| `find_entity` | 8 ms / 24 ms | 8 ms / 416 ms |
| `describe_namespace` | 14 ms / 34 ms | 15 ms / 423 ms |
| `get_observations` | 6 ms / 34 ms | 6 ms / 29 ms |
| `expand` | 6 ms / 64 ms | 7 ms / 57 ms |

**Tails at 500k.** That run's worst calls took minutes to 52 minutes. Two
causes: I/O contention (two stores per node) and a slow `contains` path,
fixed in 482e25e. Replaying the 60 slowest distinct calls on one machine
with the fix: every call ≤ 8.8 s.

## 500k listings, no models (one machine, after 482e25e)

The model-free probe (`secrets/gke/final_probe.py`; locally gitignored) on
the 500k store, one machine, cold:

| Case | Time | Rows |
| --- | --- | --- |
| members of the largest group (324,958), nested | 7.3 s | 324,958, exact |
| enabled members of that group | 11.5 s | 324,958, exact |
| members of a 109,639 group | 2.9 s | exact |
| enabled Domain Admins (`within`) | 3.5 s | 16 |
| Domain Admins with rights over a computer (`paths`) | 0.7 s | 2 |
| `kerberoastable_users` | 4.5 s | 14,036 |
| `asrep_roastable_users` | 3.9 s | 0 (should short-circuit; future-work item 5) |
| `unconstrained_delegation_hosts`, `domain_trusts`, `account_groups` | ≤ 12 ms | 3, 3, 8 |
| all computers (type listing) | 0.27 s | 75,005 |

Before the fix, on the shared GKE node, the two largest listings stopped at
the 200,000-candidate cap (inexact) after 56 s and 29 s.

## Imports

Through the LDAP connector, as a user loads data:

| Store | Data | Before | After |
| --- | --- | --- | --- |
| SQLite, GKE job | 10k forest (175,560 facts) | 173 s | 39 s (D-105) |
| SQLite, GKE job | 500k forest (6.5M facts) | 8,296 s | 2,945 s (D-105) |
| Postgres, same host (laptop) | 10k forest | 109 s | 65 s (87c050a) |
| Postgres, separate node (GKE, pd-ssd) | 500k forest | ~283 facts/s, ~6.5 h (ca15cbb) | measured after the 2026-10-14 sweep |

Over a network, Postgres writes were bound by round trips (four to six
statements per fact) until 87c050a batched them (D-105 addendum).

## Store size

| Store | Facts | Size |
| --- | --- | --- |
| SQLite, 500k forest | 6,502,512 | 7.5 GB (table 3.2 GB; `idx_obs_event` 0.85 GB) |
| SQLite, vulnerability corpus | 542,100 | 3.9 GB, embedded |

Reducing this is future-work item 6.

## Kubernetes (2026-09-27, GKE, auth on, real corpus)

| Measure | Value |
| --- | --- |
| Asks, p50 | 83 ms |
| Ask throughput | 186 / s |
| Ingest through the gateway | 237 / s |
| Postgres failover (primary deleted under load) | 15 s, 0 of 233 writes lost |

## Pending

- Postgres at 500k: the replay sample (643 recorded calls) and the probe,
  on Postgres and SQLite on the same build and hardware, with the database
  idle, then the model sweep's tool latencies with 16 agents sharing one
  database (the 2026-10-14 run).
- The batched Postgres writer's 500k import, same machine.
- A standing replay benchmark on each candidate build (future-work item 4).
  When it exists, it writes its table here.
