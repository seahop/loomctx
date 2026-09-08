# Contributing to Loom

Thanks for looking. Loom is small and opinionated; the fastest way to be
useful is to read `docs/architecture.md` and `docs/decisions.md` first —
most "why is it like this?" questions are answered there, and new choices
get a numbered entry in `decisions.md` rather than a comment.

## Ground rules (from `CLAUDE.md` / `docs/decisions.md`)

- **Docker-only.** Build and run everything through `docker compose`;
  nothing installs on the host. Tests: `docker compose run --rm test`.
- **Contracts are the API.** `src/loom/contracts.py` is the source of
  truth; `contracts/schemas.json` and `contracts/openapi.json` are generated
  from it (`python -m loom.schemas`, `python -m loom.schemas openapi`) and CI
  fails if either drifts — as do the TypeScript SDK's generated types
  (`docker compose --profile sdk run --rm sdk-ts npm run gen`). A contract
  change is a decision, not a refactor — add a `D-xxx` entry.
- **Persistence only through `GraphStore`** (`src/loom/store/`). New store
  behavior lands in `tests/test_store.py` first, which runs against both
  SQLite and Postgres; the two backends must stay behaviorally identical.
- **Provenance is mandatory.** Every pack item cites something; every
  observation names its source. Don't add a code path that emits an
  uncited item.
- **Domain-agnostic core.** Domain knowledge belongs in the schema
  registry / seed data, never in core code.

## Workflow

1. Branch from `main`. Keep `main` green — the repo is public and CI
   publishes images from it.
2. `docker compose build && docker compose run --rm test`. For store
   changes also run the Postgres lane:
   ```bash
   docker compose --profile pg up -d --wait postgres
   docker compose run --rm -e LOOM_TEST_POSTGRES_URL=postgresql://loom:loom@postgres:5432/loom \
     test pytest -q tests/test_store.py
   ```
   Gateway changes: `docker compose --profile scale build gateway` runs
   `go vet` and `go test` inside the build.
3. If you touched retrieval, look at the scorecard
   (`pytest -q -s tests/test_quality.py`) — ranking changes ship with
   before/after evidence.
4. Update `docs/roadmap.md` status markers and, for review-found issues,
   `docs/hardening.md`.
5. Open a PR. Describe the *decision* as much as the diff.

## Reporting security issues

See `SECURITY.md` — please don't open public issues for vulnerabilities.
