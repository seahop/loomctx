"""Store selection by connection string (D-011).

LOOM_DB is either a file path (SQLite, the default) or a postgres:// /
postgresql:// URL. Nothing else in the system knows or cares which backend
is behind the interface.
"""

from __future__ import annotations

import os
from typing import Any

from .base import GraphStore

# `read_url` left at this sentinel means "whatever LOOM_DB_READ says"; an
# explicit None means "no replica" — a shard must not inherit the default
# database's replica, which serves a different cluster.
_FROM_ENV: Any = object()


def store_from_url(url: str, read_url: str | None = _FROM_ENV) -> GraphStore:
    if url.startswith(("postgres://", "postgresql://")):
        from .postgres import PostgresStore

        # LOOM_DB_READ (D-028): a replica DSN for the read path; pool size
        # is LOOM_DB_POOL. Both are optional dials — unset means one primary.
        if read_url is _FROM_ENV:
            read_url = os.environ.get("LOOM_DB_READ") or None
        return PostgresStore(url, read_dsn=read_url or None)
    from .sqlite import SqliteStore

    # LOOM_DB_READERS: read connections per process beside the one writer
    # (R-9); the store's default applies when unset
    raw = os.environ.get("LOOM_DB_READERS", "").strip()
    return SqliteStore(url, readers=int(raw) if raw.isdigit() else None)


def shard_specs(raw: str) -> dict[str, tuple[str, str | None]]:
    """Parse LOOM_SHARDS (inline JSON or a file path) into
    namespace -> (dsn, read_dsn). A value is either a connection string or
    {"dsn": ..., "read": ...}; `read` is that shard's own replica and is
    the only way a shard gets one (LOOM_DB_READ belongs to LOOM_DB)."""
    import json

    mapping = json.loads(raw if raw.startswith(("{", "[")) else open(raw).read())
    if not isinstance(mapping, dict):
        raise ValueError("LOOM_SHARDS must be a JSON object of namespace -> url")
    specs: dict[str, tuple[str, str | None]] = {}
    for namespace, value in mapping.items():
        if isinstance(value, str):
            specs[str(namespace)] = (value, None)
        elif isinstance(value, dict) and isinstance(value.get("dsn"), str):
            read = value.get("read")
            if read is not None and not isinstance(read, str):
                raise ValueError(f"LOOM_SHARDS[{namespace!r}].read must be a string")
            specs[str(namespace)] = (value["dsn"], read or None)
        else:
            raise ValueError(f"LOOM_SHARDS[{namespace!r}] must be a url or {{\"dsn\": ..., \"read\": ...}}")
    return specs


def store_from_env() -> GraphStore:
    """LOOM_DB, plus — when LOOM_SHARDS is set (D-032) — a namespace ->
    connection-string map, inline JSON or a path to a JSON file, e.g.
    {"acme": "postgresql://.../acme", "globex": "/data/globex.db",
     "initech": {"dsn": "postgresql://.../initech", "read": "postgresql://replica/initech"}}."""
    default_url = os.environ.get("LOOM_DB", "loom.db")
    default = store_from_url(default_url)
    raw = os.environ.get("LOOM_SHARDS", "").strip()
    if not raw:
        return _with_offload(default)
    from .sharded import ShardedStore

    by_url: dict[tuple[str, str | None], GraphStore] = {}
    shards: dict[str, GraphStore] = {}
    for namespace, (url, read) in shard_specs(raw).items():
        if url == default_url and read is None:
            shards[namespace] = default   # the same database: share the store
            continue
        if (url, read) not in by_url:
            by_url[(url, read)] = store_from_url(url, read_url=read)
        shards[namespace] = by_url[(url, read)]
    return _with_offload(ShardedStore(default, shards))


def _with_offload(store: GraphStore) -> GraphStore:
    """Artifact offload (D-033) when LOOM_BLOB_THRESHOLD + a blob backend
    are configured; the store is returned untouched otherwise."""
    from .blobs import BlobOffloadStore, blobs_from_env, threshold_from_env

    threshold = threshold_from_env()
    blobs = blobs_from_env() if threshold else None
    if threshold and blobs is not None:
        return BlobOffloadStore(store, blobs, threshold)
    return store
