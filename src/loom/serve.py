"""Engine process entrypoint: uvicorn with `LOOM_WORKERS` worker processes.

Default 1 — the right number for the SQLite shape (one writer) and for a
small team. On the Postgres shapes each worker gets its own connection pool
(`LOOM_DB_POOL`), so `LOOM_WORKERS=2..4` multiplies a pod's concurrency
before you reach for more pods (D-028). Every worker is a full copy of the
app: auth hot-reload, registry cache, and the query-embedding cache are
per process.
"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    workers = max(1, int(os.environ.get("LOOM_WORKERS", "") or 1))
    uvicorn.run(
        "loom.api.http:app",
        host=os.environ.get("LOOM_HOST", "0.0.0.0"),
        port=int(os.environ.get("LOOM_PORT", "") or 8000),
        workers=workers,
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
