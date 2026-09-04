# Loom (working name) — context engine for AI agents

Absorbs data about entities over time (structured claims + documents) and serves
agents token-budgeted, cited, question-scoped "context packs".

## Orientation order for a fresh session

1. `docs/roadmap.md` — what is done / stubbed / next (keep its status markers updated)
2. `docs/decisions.md` — constraints and choices (append new decisions there)
3. `docs/architecture.md` — the design
4. Code: `src/loom/contracts.py` → `src/loom/store/sqlite.py` → `src/loom/api/http.py`

## Hard rules

- **Docker-only.** Never install packages or run project code on the host. Build and
  run everything via `docker compose ...` (tests: `docker compose run --rm test`).
- Contracts in `src/loom/contracts.py` are the API; all surfaces serialize exactly
  those shapes. Contract changes get a decisions.md entry.
- Persistence only through the `GraphStore` interface (`src/loom/store/`). No SQL
  outside that package.
- Observations are append-only; reads always take a token budget; every derived fact
  carries citations. Domain specifics go in the schema registry, never core code.

## Secrets / .env

`.env` (gitignored + dockerignored) holds LOOM_LLM_* credentials; compose
reads it automatically and passes values to loom/mcp/test services. NEVER
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
docker compose up -d --build loom
docker compose exec loom python -m loom.seed load
# then POST /v1/ask — planted demo moments: ip 10.0.4.7 lease reassignment,
# web-01 runs_os conflict, initech contract_owner conflict (src/loom/seed.py)
```

## Deadline

Conference demo + presentation end of October 2026. Repo is public
(github.com/seahop/Loom) — keep `main` green and presentable. k8s manifests in
`deploy/k8s`; CI publishes the image to ghcr.io/seahop/loom on main.
