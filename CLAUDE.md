# LoomCtx — context engine for AI agents

Absorbs data about entities over time (structured claims + documents) and serves
agents token-budgeted, cited, question-scoped "context packs".

## Orientation order for a fresh session

1. `docs/roadmap.md` — what is done / stubbed / next (keep its status markers updated)
   and `docs/hardening.md` — the verified issue lists from the 2026-09-08 and 2026-09-23 reviews
   (flip its status markers as items land)
2. `docs/decisions.md` — constraints and choices (append new decisions there);
   `docs/future-work.md` — the planned post-talk work, with designs
3. `docs/architecture.md` — the design
4. Code: `src/loomctx/contracts.py` → `src/loomctx/store/sqlite.py` → `src/loomctx/api/http.py`

## Hard rules

- **Docker-only.** Never install packages or run project code on the host. Build and
  run everything via `docker compose ...` (tests: `docker compose run --rm test`).
- Contracts in `src/loomctx/contracts.py` are the API; all surfaces serialize exactly
  those shapes. Contract changes get a decisions.md entry.
- Persistence only through the `GraphStore` interface (`src/loomctx/store/`). No SQL
  outside that package.
- Observations are append-only; reads always take a token budget; every derived fact
  carries citations. Domain specifics go in the schema registry, never core code.

## Secrets / .env

`.env` (gitignored + dockerignored) holds LOOMCTX_LLM_* credentials; compose
reads it automatically and passes values to loomctx/mcp/test services. NEVER
commit, print, or paste `.env` contents anywhere (public repo!). When it is
filled in, the real-provider e2e test runs:

```bash
docker compose run --rm test pytest -q -s tests/test_e2e_answer.py
```

(it skips cleanly when .env is absent). Template: `.env.example`.

## Verify

```bash
docker compose build && docker compose run --rm test
```

## Demo rehearsal (deterministic seed data)

```bash
docker compose up -d --build loomctx
docker compose exec loomctx python -m loomctx.seed load
# then POST /v1/ask — planted demo moments: ip 10.0.4.7 lease reassignment,
# web-01 runs_os conflict, initech contract_owner conflict (src/loomctx/seed.py)
```

## Deadline

Conference demo + presentation on 2026-10-21 (confirmed 2026-09-29; the site and docs say "late October" for the release). Repo is meant to be public
(github.com/seahop/loomctx; still private as of 2026-09-24 — flip repo AND GHCR
package visibility before the talk) — keep `main` green and presentable. k8s manifests in
`deploy/k8s`; CI publishes the image to ghcr.io/seahop/loomctx on main.
