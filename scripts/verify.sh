#!/usr/bin/env bash
# What CI runs, locally, before you commit: the suite with every provider
# variable blanked (CI has none), the contract drift checks and the lint job.
# Docker-only.
#   scripts/verify.sh            # suite + drift + lint
#   scripts/verify.sh --pg       # also the Postgres store lane
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose build loomctx >/dev/null
echo "== test suite (CI conditions: no LOOMCTX_LLM_* / LOOMCTX_EMBED_*)"
out=$(docker compose run --rm -T \
  -e LOOMCTX_LLM_PROVIDER= -e LOOMCTX_LLM_MODEL= -e LOOMCTX_LLM_API_KEY= -e LOOMCTX_LLM_BASE_URL= \
  -e LOOMCTX_EMBED_PROVIDER= -e LOOMCTX_EMBED_MODEL= -e LOOMCTX_EMBED_API_KEY= -e LOOMCTX_EMBED_DIM= \
  test 2>&1) || { echo "$out" | grep -E "^FAILED|^ERROR|passed|failed|error" | tail -20; echo "== test suite FAILED"; exit 1; }
echo "$out" | grep -E "passed|failed" | tail -1

echo "== contracts in sync"
docker compose run --rm -T loomctx python -m loomctx.schemas | diff -q - contracts/schemas.json >/dev/null \
  && echo "schemas.json ok" || { echo "schemas.json DRIFTED: docker compose run --rm -T loomctx python -m loomctx.schemas > contracts/schemas.json"; exit 1; }
docker compose run --rm -T loomctx python -m loomctx.schemas openapi | diff -q - contracts/openapi.json >/dev/null \
  && echo "openapi.json ok" || { echo "openapi.json DRIFTED: docker compose run --rm -T loomctx python -m loomctx.schemas openapi > contracts/openapi.json"; exit 1; }
docker compose --profile sdk run --rm -T sdk-ts npm run gen >/dev/null 2>&1
git diff --quiet -- sdk/typescript/src/contracts.ts && echo "contracts.ts ok" || { echo "contracts.ts drifted (regenerated; commit it)"; exit 1; }

echo "== lint (ruff: syntax errors + pyflakes — pyproject.toml [tool.ruff]; same pinned image as CI)"
docker run --rm -v "$PWD:/w:ro" -w /w \
  ghcr.io/astral-sh/ruff:0.16.8@sha256:ec3c84a063840fc9a678004f4d958ea4e1e79de1ee3f94dc0f0df3a4a3a1f1a7 \
  check --no-cache --quiet . && echo "ruff ok" || { echo "ruff found errors"; exit 1; }

if [[ "${1:-}" == "--pg" ]]; then
  echo "== Postgres store lane"
  docker compose --profile pg up -d --wait postgres >/dev/null
  docker compose run --rm -T -e LOOMCTX_TEST_POSTGRES_URL=postgresql://loomctx:loomctx@postgres:5432/loomctx \
    test pytest -q tests/test_store.py 2>&1 | tail -1
  docker compose --profile pg stop postgres >/dev/null; docker compose --profile pg rm -f postgres >/dev/null
fi
echo "== ok"
