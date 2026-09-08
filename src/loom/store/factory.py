"""Store selection by connection string (D-011).

LOOM_DB is either a file path (SQLite, the default) or a postgres:// /
postgresql:// URL. Nothing else in the system knows or cares which backend
is behind the interface.
"""

from __future__ import annotations

import os

from .base import GraphStore


def store_from_url(url: str, read_url: str | None = None) -> GraphStore:
    if url.startswith(("postgres://", "postgresql://")):
        from .postgres import PostgresStore

        # LOOM_DB_READ (D-028): a replica DSN for the read path; pool size
        # is LOOM_DB_POOL. Both are optional dials — unset means one primary.
        return PostgresStore(url, read_dsn=read_url or os.environ.get("LOOM_DB_READ") or None)
    from .sqlite import SqliteStore

    return SqliteStore(url)


def store_from_env() -> GraphStore:
    """LOOM_DB, plus — when LOOM_SHARDS is set (D-032) — a namespace ->
    connection-string map, inline JSON or a path to a JSON file, e.g.
    {"acme": "postgresql://.../acme", "globex": "/data/globex.db"}."""
    default = store_from_url(os.environ.get("LOOM_DB", "loom.db"))
    raw = os.environ.get("LOOM_SHARDS", "").strip()
    if not raw:
        return default
    import json
    from .sharded import ShardedStore

    mapping = json.loads(open(raw).read() if not raw.startswith("{") else raw)
    if not isinstance(mapping, dict):
        raise ValueError("LOOM_SHARDS must be a JSON object of namespace -> url")
    by_url: dict[str, GraphStore] = {os.environ.get("LOOM_DB", "loom.db"): default}
    shards: dict[str, GraphStore] = {}
    for namespace, url in mapping.items():
        if url not in by_url:
            by_url[url] = store_from_url(url)
        shards[str(namespace)] = by_url[url]
    return ShardedStore(default, shards)
