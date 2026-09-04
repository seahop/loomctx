"""Store selection by connection string (D-011).

LOOM_DB is either a file path (SQLite, the default) or a postgres:// /
postgresql:// URL. Nothing else in the system knows or cares which backend
is behind the interface.
"""

from __future__ import annotations

import os

from .base import GraphStore


def store_from_url(url: str) -> GraphStore:
    if url.startswith(("postgres://", "postgresql://")):
        from .postgres import PostgresStore

        return PostgresStore(url)
    from .sqlite import SqliteStore

    return SqliteStore(url)


def store_from_env() -> GraphStore:
    return store_from_url(os.environ.get("LOOM_DB", "loom.db"))
