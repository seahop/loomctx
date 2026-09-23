#!/usr/bin/env bash
# Regenerate requirements.lock from pyproject.toml (every extra, every
# supported interpreter) without installing anything on the host. Run it
# after any dependency edit: the Dockerfile installs from the lock, so a
# change here is what actually changes the image.
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD:/w" -w /w ghcr.io/astral-sh/uv:python3.12-bookworm-slim \
  uv pip compile pyproject.toml --all-extras --universal --python-version 3.12 -o requirements.lock
echo "wrote requirements.lock ($(grep -c '==' requirements.lock) pins)"
