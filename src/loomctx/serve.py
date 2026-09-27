"""Engine process entrypoint: uvicorn with `LOOMCTX_WORKERS` worker processes.

Default 1 — the right number for the SQLite shape (one writer) and for a
small team. On the Postgres shapes each worker gets its own connection pool
(`LOOMCTX_DB_POOL`), so `LOOMCTX_WORKERS=2..4` multiplies a pod's concurrency
before you reach for more pods (D-028). Every worker is a full copy of the
app: auth hot-reload, registry cache, and the query-embedding cache are
per process.
"""

from __future__ import annotations

import os

import uvicorn


def _int_env(name: str, default: int) -> int:
    """Kubernetes injects `<SERVICE>_PORT=tcp://ip:port` for every Service —
    a Service named `loomctx` sets LOOMCTX_PORT — so listen settings use names no
    Service can collide with, and anything non-numeric falls back."""
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def main() -> None:
    uvicorn.run(
        "loomctx.api.http:app",
        host=os.environ.get("LOOMCTX_HTTP_HOST", "0.0.0.0"),
        port=_int_env("LOOMCTX_HTTP_PORT", 8000),
        workers=max(1, _int_env("LOOMCTX_WORKERS", 1)),
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
