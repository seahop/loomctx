#!/usr/bin/env bash
# What CI runs, locally, before you commit: the suite with every provider
# variable blanked (CI has none), and the contract drift checks. Docker-only.
#   scripts/verify.sh            # suite + drift
#   scripts/verify.sh --pg       # also the Postgres store lane
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose build loom >/dev/null
echo "== test suite (CI conditions: no LOOM_LLM_* / LOOM_EMBED_*)"
out=$(docker compose run --rm -T \
  -e LOOM_LLM_PROVIDER= -e LOOM_LLM_MODEL= -e LOOM_LLM_API_KEY= -e LOOM_LLM_BASE_URL= \
  -e LOOM_EMBED_PROVIDER= -e LOOM_EMBED_MODEL= -e LOOM_EMBED_API_KEY= -e LOOM_EMBED_DIM= \
  test 2>&1) || { echo "$out" | grep -E "^FAILED|^ERROR|passed|failed|error" | tail -20; echo "== test suite FAILED"; exit 1; }
echo "$out" | grep -E "passed|failed" | tail -1

echo "== contracts in sync"
docker compose run --rm -T loom python -m loom.schemas | diff -q - contracts/schemas.json && echo "schemas.json ok"
docker compose run --rm -T loom python -m loom.schemas openapi | diff -q - contracts/openapi.json && echo "openapi.json ok"
docker compose --profile sdk run --rm -T sdk-ts npm run gen >/dev/null 2>&1
git diff --quiet -- sdk/typescript/src/contracts.ts && echo "contracts.ts ok" || { echo "contracts.ts drifted (regenerated; commit it)"; exit 1; }

if [[ "${1:-}" == "--pg" ]]; then
  echo "== Postgres store lane"
  docker compose --profile pg up -d --wait postgres >/dev/null
  docker compose run --rm -T -e LOOM_TEST_POSTGRES_URL=postgresql://loom:loom@postgres:5432/loom \
    test pytest -q tests/test_store.py 2>&1 | tail -1
  docker compose --profile pg stop postgres >/dev/null; docker compose --profile pg rm -f postgres >/dev/null
fi
echo "== ok"
