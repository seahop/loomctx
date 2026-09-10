"""Server-backed GraphStore: Postgres (D-008, D-011, D-014, D-016).

The scaling lane: multiple engine replicas and writer consumers share one
Postgres. Column shapes, idempotent-ingest semantics (event_id dedupe),
tombstone redaction, and lifecycle operations are identical to the SQLite
store — the shared contract tests enforce it.

Every public method runs inside `_tx()`: borrow a connection from the pool,
commit on success, ROLLBACK on any exception. A failed statement can never
leave a connection in "current transaction is aborted" (hardening H-B1).

Concurrency (D-028): a `psycopg_pool` of `LOOM_DB_POOL` connections per
process (default 4) so an engine pod serves that many queries at once;
`LOOM_DB_READ` optionally names a read-replica DSN — packs, searches, and
exports go there, ingest and the worker's backlog queries stay on the
primary. Reads from a replica may lag by replication delay; observations
are append-only and `as_of` makes staleness explicit, so that is safe.

Selected purely by connection string — set LOOM_DB=postgresql://... and
nothing else changes. Requires the `postgres` extra (psycopg + pool).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Iterator

from .. import metrics
from ..contracts import (
    Artifact, ClaimIn, DocumentIn, Entity, EntityRef, Observation,
    SchemaRegistration,
)
from . import common

log = logging.getLogger("loom.store")
from .base import GraphStore

_SCHEMA = """
CREATE TABLE IF NOT EXISTS loom_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schemas (
    namespace         TEXT PRIMARY KEY,
    registration_json TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entities (
    id          TEXT PRIMARY KEY,
    namespace   TEXT NOT NULL,
    type        TEXT NOT NULL,
    key         TEXT NOT NULL,
    provisional BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TEXT NOT NULL,
    norm_key    TEXT NOT NULL DEFAULT '',
    dossier_claimed_until TEXT,
    UNIQUE (namespace, type, key)
);

CREATE TABLE IF NOT EXISTS aliases (
    namespace TEXT NOT NULL,
    alias     TEXT NOT NULL,
    entity_id TEXT NOT NULL REFERENCES entities (id),
    PRIMARY KEY (namespace, alias)
);

CREATE TABLE IF NOT EXISTS observations (
    id               TEXT PRIMARY KEY,
    namespace        TEXT NOT NULL,
    event_id         TEXT,
    subject_id       TEXT NOT NULL REFERENCES entities (id),
    predicate        TEXT NOT NULL,
    object_json      TEXT NOT NULL,
    object_entity_id TEXT REFERENCES entities (id),
    observed_at      TEXT NOT NULL,
    valid_from       TEXT,
    valid_to         TEXT,
    recorded_at      TEXT NOT NULL,
    source           TEXT NOT NULL,
    confidence       DOUBLE PRECISION NOT NULL,
    provenance_json  TEXT,
    attrs_json       TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS artifacts (
    id                TEXT PRIMARY KEY,
    namespace         TEXT NOT NULL,
    event_id          TEXT,
    filename          TEXT,
    content_type      TEXT NOT NULL,
    text              TEXT,
    content_b64       TEXT,
    source            TEXT NOT NULL,
    observed_at       TEXT NOT NULL,
    recorded_at       TEXT NOT NULL,
    extraction_status TEXT NOT NULL DEFAULT 'pending',
    extraction_attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   TEXT,
    extract_claimed_by    TEXT,
    extract_claimed_until TEXT,
    chunk_claimed_until   TEXT,
    attrs_json        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tombstones (
    observation_id TEXT PRIMARY KEY,
    namespace      TEXT NOT NULL,
    reason         TEXT NOT NULL,
    recorded_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS embeddings (
    ref_id    TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    model     TEXT NOT NULL,
    vector    BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS dossiers (
    namespace         TEXT NOT NULL,
    entity_id         TEXT NOT NULL,
    brief             TEXT NOT NULL,
    observation_count INTEGER NOT NULL,
    observation_ids   TEXT NOT NULL DEFAULT '[]',
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (namespace, entity_id)
);

CREATE TABLE IF NOT EXISTS doc_chunks (
    id          TEXT PRIMARY KEY,
    namespace   TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    span_start  INTEGER NOT NULL,
    span_end    INTEGER NOT NULL,
    text        TEXT NOT NULL,
    vector      BYTEA NOT NULL,
    model       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_obs_prov_artifact
    ON observations (namespace, ((provenance_json::jsonb ->> 'artifact_id')));

CREATE INDEX IF NOT EXISTS idx_chunk_artifact
    ON doc_chunks (namespace, artifact_id);

ALTER TABLE observations ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE artifacts    ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE dossiers     ADD COLUMN IF NOT EXISTS observation_ids TEXT NOT NULL DEFAULT '[]';
ALTER TABLE doc_chunks   ADD COLUMN IF NOT EXISTS model TEXT NOT NULL DEFAULT '';
ALTER TABLE entities     ADD COLUMN IF NOT EXISTS norm_key TEXT NOT NULL DEFAULT '';
ALTER TABLE artifacts    ADD COLUMN IF NOT EXISTS extraction_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE artifacts    ADD COLUMN IF NOT EXISTS next_attempt_at TEXT;
ALTER TABLE artifacts    ADD COLUMN IF NOT EXISTS extract_claimed_by TEXT;
ALTER TABLE artifacts    ADD COLUMN IF NOT EXISTS extract_claimed_until TEXT;
ALTER TABLE artifacts    ADD COLUMN IF NOT EXISTS chunk_claimed_until TEXT;
ALTER TABLE entities     ADD COLUMN IF NOT EXISTS dossier_claimed_until TEXT;

CREATE INDEX IF NOT EXISTS idx_obs_subject
    ON observations (namespace, subject_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_obs_object
    ON observations (namespace, object_entity_id, observed_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_obs_event
    ON observations (namespace, event_id) WHERE event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_art_event
    ON artifacts (namespace, event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_obs_recorded ON observations (recorded_at);
CREATE INDEX IF NOT EXISTS idx_art_status ON artifacts (extraction_status, recorded_at);
CREATE INDEX IF NOT EXISTS idx_chunk_by_artifact ON doc_chunks (artifact_id);
CREATE INDEX IF NOT EXISTS idx_entity_key ON entities (namespace, key);
CREATE INDEX IF NOT EXISTS idx_entity_norm ON entities (namespace, norm_key);
"""

SCHEMA_VERSION = 3  # keep in step with sqlite.py (v3: packed vectors, D-039)

_NOT_TOMBSTONED = (
    " AND NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.observation_id = o.id)"
)

_OBS_SELECT = (
    "SELECT o.*, e.type AS subj_type, e.key AS subj_key"
    " FROM observations o JOIN entities e ON e.id = o.subject_id"
)
# the same projection plus the entity an observation was fetched FOR, so a
# batched gather can partition per entity (D-043)
_OBS_SELECT_ENT = (
    "SELECT o.*, e.type AS subj_type, e.key AS subj_key, {ent} AS ent"
    " FROM observations o JOIN entities e ON e.id = o.subject_id"
)

_OBS_INSERT = (
    "INSERT INTO observations (id, namespace, event_id, subject_id, predicate,"
    " object_json, object_entity_id, observed_at, valid_from, valid_to,"
    " recorded_at, source, confidence, provenance_json, attrs_json)"
    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)

_ON_EVENT_CONFLICT = (
    " ON CONFLICT (namespace, event_id) WHERE event_id IS NOT NULL DO NOTHING"
)

# Replicas start concurrently; serialize the idempotent DDL so two of them
# don't race on CREATE TABLE IF NOT EXISTS (pg_type uniqueness errors).
_SCHEMA_LOCK_ID = 0x4C4F4F4D  # "LOOM"
_DEADLOCK_BACKOFF = (0.2, 0.6, 1.5)


def retry_on_deadlock(fn, backoff: tuple[float, ...] = _DEADLOCK_BACKOFF):
    """Run a whole transaction again when Postgres aborts it as the loser
    of a deadlock or a serialization conflict: the transaction rolled back
    entirely and every write here is idempotent by event_id, so a retry is
    safe. Bounded; the last failure propagates (D-043)."""
    import time as _time
    from psycopg import errors
    for attempt, delay in enumerate(backoff + (None,)):
        try:
            return fn()
        except (errors.DeadlockDetected, errors.SerializationFailure) as exc:
            if delay is None:
                raise
            log.warning("transaction lost a deadlock/serialization race (%s); retry %d in %.1fs",
                        exc.__class__.__name__, attempt + 1, delay)
            _time.sleep(delay)


class PostgresStore(GraphStore):
    _CONNECT_WAIT_SECONDS = 180.0   # an operator bootstrapping a cluster takes ~2 min
    _DEFAULT_POOL = 4

    def __init__(self, dsn: str, read_dsn: str | None = None,
                 pool_size: int | None = None):
        import psycopg
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self._psycopg = psycopg
        self._local = threading.local()   # the connection borrowed by _tx()
        size = pool_size or int(os.environ.get("LOOM_DB_POOL", "") or self._DEFAULT_POOL)

        def pool(url: str) -> ConnectionPool:
            # Postgres may still be starting when a replica boots (k8s and
            # compose ordering are best-effort): wait for a bounded time
            # instead of crash-looping — the same courtesy the NATS clients
            # extend. check= drops connections the server closed.
            p = ConnectionPool(url, min_size=1, max_size=max(1, size), open=False,
                               kwargs={"row_factory": dict_row},
                               check=ConnectionPool.check_connection)
            p.open(wait=True, timeout=self._CONNECT_WAIT_SECONDS)
            return p

        self._pool = pool(dsn)
        self._read_pool = pool(read_dsn) if read_dsn and read_dsn != dsn else None
        self._vec_tables: dict[str, int] = {}
        self._vec = self._load_vec()
        if self._schema_current():
            # An up-to-date database gets no DDL on open. The idempotent
            # ALTER TABLE ... IF NOT EXISTS / CREATE INDEX IF NOT EXISTS
            # statements still take AccessExclusive locks, and on GKE a
            # pod opening the store deadlocked a bulk loader mid-batch
            # (D-043). Only a fresh or outdated database is migrated.
            with self._tx():
                self._refresh_vec_tables()
        else:
            with self._tx():
                self._x("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK_ID,))
                self._x(_SCHEMA)
                with self._conn.cursor() as cur:
                    self._migrate(cur)
                self._refresh_vec_tables()

    def _schema_current(self) -> bool:
        try:
            with self._tx(read=False):
                rows = self._q("SELECT value FROM loom_meta WHERE key = 'schema_version'")
            return bool(rows) and int(rows[0]["value"]) == SCHEMA_VERSION
        except Exception:  # noqa: BLE001 — no loom_meta yet: a fresh database
            return False

    @property
    def _conn(self):
        """The connection this thread borrowed in `_tx()`."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            raise RuntimeError("store used outside a _tx() block")
        return conn

    # ------------------------------------------------- vector index (D-025)

    def _load_vec(self) -> bool:
        try:
            with self._tx():
                self._x("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK_ID,))
                self._x("CREATE EXTENSION IF NOT EXISTS vector")
            return True
        except self._psycopg.Error as exc:
            logging.getLogger("loom.store").info(
                "pgvector unavailable (%s): vector search uses exact scans", exc)
            return False

    def vector_backend(self) -> str:
        return "pgvector" if self._vec else "exact"

    def _refresh_vec_tables(self) -> None:
        for row in self._q("SELECT key, value FROM loom_meta WHERE key LIKE 'vec:%%'"):
            self._vec_tables[row["key"][4:]] = int(row["value"])

    def _has_index(self, name: str) -> bool:
        if not self._vec:
            return False
        if name not in self._vec_tables:
            self._refresh_vec_tables()
        return name in self._vec_tables

    def _vec_table(self, kind: str, model: str, dim: int) -> str:
        name = common.vec_table(kind, model, dim)
        if name not in self._vec_tables:
            self._refresh_vec_tables()
        if name not in self._vec_tables:
            self._x(f"CREATE TABLE IF NOT EXISTS {name} (ref_id TEXT PRIMARY KEY,"
                    f" namespace TEXT NOT NULL, artifact_id TEXT NOT NULL DEFAULT '',"
                    f" embedding vector({dim}) NOT NULL)")
            self._x(f"CREATE INDEX IF NOT EXISTS {name}_hnsw ON {name}"
                    " USING hnsw (embedding vector_cosine_ops)")
            self._x(f"CREATE INDEX IF NOT EXISTS {name}_ns ON {name} (namespace, artifact_id)")
            self._x("INSERT INTO loom_meta (key, value) VALUES (%s, %s)"
                    " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    (f"vec:{name}", str(dim)))
            self._vec_tables[name] = dim
        return name

    @staticmethod
    def _vlit(vec: list[float]) -> str:
        return "[" + ",".join(repr(float(x)) for x in vec) + "]"

    def _vec_upsert(self, kind: str, model: str, namespace: str,
                    rows: list[tuple[str, str | None, list[float]]]) -> int:
        if not self._vec or not rows:
            return 0
        written = 0
        by_dim: dict[int, list] = {}
        for rid, aid, vec in rows:
            by_dim.setdefault(len(vec), []).append((rid, aid, vec))
        for dim, group in by_dim.items():
            name = self._vec_table(kind, model, dim)
            with self._conn.cursor() as cur:
                cur.executemany(
                    f"INSERT INTO {name} (ref_id, namespace, artifact_id, embedding)"
                    " VALUES (%s, %s, %s, %s::vector) ON CONFLICT (ref_id) DO UPDATE SET"
                    " namespace = EXCLUDED.namespace, artifact_id = EXCLUDED.artifact_id,"
                    " embedding = EXCLUDED.embedding",
                    [(rid, namespace, aid or "", self._vlit(vec)) for rid, aid, vec in group])
            written += len(group)
        return written

    def nearest_observations(
        self, namespace: str, model: str, query: list[float], limit: int = 20
    ) -> list[tuple[str, float]]:
        name = common.vec_table("vobs", model, len(query))
        with self._tx(read=True):
            if self._has_index(name):
                rows = self._q(
                    f"SELECT ref_id, 1 - (embedding <=> %s::vector) AS score FROM {name} v"
                    " WHERE namespace = %s AND NOT EXISTS"
                    "   (SELECT 1 FROM tombstones t WHERE t.observation_id = v.ref_id)"
                    " ORDER BY embedding <=> %s::vector LIMIT %s",
                    (self._vlit(query), namespace, self._vlit(query), limit))
                return [(r["ref_id"], float(r["score"])) for r in rows]
            rows = self._q(
                "SELECT e.ref_id, e.vector FROM embeddings e"
                " WHERE e.namespace = %s AND e.model = %s AND NOT EXISTS"
                "   (SELECT 1 FROM tombstones t WHERE t.observation_id = e.ref_id)",
                (namespace, model))
            scored = common.cosines(query, {r["ref_id"]: common.unpack_vector(r["vector"]) for r in rows})
        return common.top_k(scored, limit)

    def nearest_chunks(
        self, namespace: str, model: str, query: list[float], limit: int = 20,
        artifact_ids: list[str] | None = None,
    ) -> list[tuple[dict, float]]:
        if artifact_ids is not None and not artifact_ids:
            return []
        name = common.vec_table("vchk", model, len(query))
        with self._tx(read=True):
            if self._has_index(name):
                sql = (f"SELECT ref_id, 1 - (embedding <=> %s::vector) AS score FROM {name}"
                       " WHERE namespace = %s")
                params: tuple = (self._vlit(query), namespace)
                if artifact_ids is not None:
                    sql += " AND artifact_id = ANY(%s)"
                    params += (list(artifact_ids),)
                sql += " ORDER BY embedding <=> %s::vector LIMIT %s"
                params += (self._vlit(query), limit)
                best = [(r["ref_id"], float(r["score"])) for r in self._q(sql, params)]
            else:
                sql = "SELECT id, vector FROM doc_chunks WHERE namespace = %s AND model = %s"
                params = (namespace, model)
                if artifact_ids is not None:
                    sql += " AND artifact_id = ANY(%s)"
                    params += (list(artifact_ids),)
                rows = self._q(sql, params)
                best = common.top_k(
                    common.cosines(query, {r["id"]: common.unpack_vector(r["vector"]) for r in rows}), limit)
            if not best:
                return []
            rows = self._q(
                "SELECT c.id, c.artifact_id, c.seq, c.span_start, c.span_end,"
                " c.text, c.vector, a.source, a.observed_at"
                " FROM doc_chunks c JOIN artifacts a ON a.id = c.artifact_id"
                " WHERE c.id = ANY(%s)", ([cid for cid, _ in best],))
        by_id = {r["id"]: common.row_to_chunk(r) for r in rows}
        return [(by_id[cid], s) for cid, s in best if cid in by_id]

    def ensure_vector_index(self, model: str) -> dict:
        out = {"backend": self.vector_backend(), "observations": 0, "chunks": 0}
        if not self._vec:
            return out
        with self._tx():
            self._refresh_vec_tables()
            for kind, key, sql in (
                ("vobs", "observations",
                 "SELECT ref_id AS id, namespace, NULL AS artifact_id, vector"
                 " FROM embeddings WHERE model = %s"),
                ("vchk", "chunks",
                 "SELECT id, namespace, artifact_id, vector FROM doc_chunks WHERE model = %s"),
            ):
                have: set[str] = set()
                for name in self._vec_tables:
                    if name.startswith(f"{kind}_"):
                        have |= {r["ref_id"] for r in self._q(f"SELECT ref_id FROM {name}")}
                by_ns: dict[str, list] = {}
                for r in self._q(sql, (model,)):
                    if r["id"] not in have:
                        by_ns.setdefault(r["namespace"], []).append(
                            (r["id"], r["artifact_id"], common.unpack_vector(r["vector"])))
                for ns, rows in by_ns.items():
                    out[key] += self._vec_upsert(kind, model, ns, rows)
        return out

    def observations_by_ids(self, namespace: str, ids: list[str]) -> list[Observation]:
        if not ids:
            return []
        with self._tx(read=True):
            rows = self._q(
                _OBS_SELECT + " WHERE o.namespace = %s AND o.id = ANY(%s)" + _NOT_TOMBSTONED,
                (namespace, list(ids)))
        return [common.row_to_observation(r) for r in rows]

    def _migrate(self, cur) -> None:
        """One-shot versioned steps (H-B12); idempotent DDL lives in _SCHEMA."""
        cur.execute("SELECT value FROM loom_meta WHERE key = 'schema_version'")
        row = cur.fetchone()
        current = int(row["value"]) if row else 0
        if current < 2:
            cur.execute(
                "UPDATE entities SET norm_key ="
                " regexp_replace(lower(key), '[^a-z0-9]+', '', 'g')"
                " WHERE norm_key = ''")
        if current < 3:
            # v3 (D-039): vectors as packed float32 in BYTEA. Legacy JSON text
            # is carried over byte-for-byte and still decodes; only a TEXT
            # column is altered, so a fresh database is untouched.
            for table in ("embeddings", "doc_chunks"):
                cur.execute(
                    "SELECT data_type FROM information_schema.columns"
                    " WHERE table_name = %s AND column_name = 'vector'", (table,))
                row = cur.fetchone()
                if row and row["data_type"] == "text":
                    cur.execute(f"ALTER TABLE {table} ALTER COLUMN vector TYPE BYTEA"
                                " USING convert_to(vector, 'UTF8')")
        cur.execute(
            "INSERT INTO loom_meta (key, value) VALUES ('schema_version', %s)"
            " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            (str(SCHEMA_VERSION),))

    def schema_version(self) -> int:
        with self._tx(read=True):
            rows = self._q("SELECT value FROM loom_meta WHERE key = 'schema_version'")
        return int(rows[0]["value"]) if rows else 0

    def _q(self, sql: str, params: tuple = ()) -> list:
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            if cur.description is None:
                return []
            return cur.fetchall()

    def _x(self, sql: str, params: tuple = ()) -> int:
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount

    @contextmanager
    def _tx(self, read: bool = False):
        """One transaction on a pooled connection: commit on success,
        rollback on any error (H-B1). `read=True` borrows from the replica
        pool when LOOM_DB_READ is set. Nested calls share the outer
        transaction. Broken connections are discarded by the pool (H-E5)."""
        if getattr(self._local, "conn", None) is not None:
            yield
            return
        pool = self._read_pool if (read and self._read_pool is not None) else self._pool
        with pool.connection() as conn:   # commits, or rolls back on exception
            self._local.conn = conn
            try:
                yield
            finally:
                self._local.conn = None

    # ------------------------------------------------------------ public API

    def upsert_entity(self, namespace: str, ref: EntityRef) -> Entity:
        with self._tx():
            return self._upsert_entity(namespace, ref)

    def get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        with self._tx(read=True):
            return self._resolve_entity(namespace, ref)

    def add_alias(self, namespace: str, alias: EntityRef, into: EntityRef) -> None:
        with self._tx():
            target = self._get_entity(namespace, into)
            if target is None:
                return
            self._put_alias(namespace, f"{alias.type}:{alias.key}", target.id)

    def merge_entities(
        self, namespace: str, from_ref: EntityRef, into_ref: EntityRef
    ) -> bool:
        with self._tx():
            src = self._get_entity(namespace, from_ref)
            dst = self._get_entity(namespace, into_ref)
            if src is None or dst is None or src.id == dst.id:
                return False
            self._x("UPDATE observations SET subject_id = %s WHERE subject_id = %s",
                    (dst.id, src.id))
            self._x("UPDATE observations SET object_entity_id = %s, object_json = %s"
                    " WHERE object_entity_id = %s",
                    (dst.id, json.dumps({"type": dst.type, "key": dst.key}), src.id))
            self._x("UPDATE aliases SET entity_id = %s WHERE entity_id = %s",
                    (dst.id, src.id))
            self._put_alias(namespace, f"{src.type}:{src.key}", dst.id)
            self._x("DELETE FROM dossiers WHERE namespace = %s AND entity_id IN (%s, %s)",
                    (namespace, src.id, dst.id))
            self._x("DELETE FROM entities WHERE id = %s", (src.id,))
            return True

    def fuzzy_merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        with self._tx():
            rows = self._q(
                "SELECT namespace, norm_key FROM entities WHERE norm_key <> ''"
                + (" AND namespace = %s" if namespace else "")
                + " GROUP BY namespace, norm_key HAVING COUNT(DISTINCT key) > 1"
                " ORDER BY namespace, norm_key LIMIT %s",
                ((namespace, limit) if namespace else (limit,)),
            )
            groups = []
            for row in rows:
                members = self._q(
                    "SELECT * FROM entities WHERE namespace = %s AND norm_key = %s"
                    " ORDER BY created_at, type, key",
                    (row["namespace"], row["norm_key"]),
                )
                groups.append([common.row_to_entity(m) for m in members])
        return groups

    # ------------------------------------------------ schema registry (D-024)

    def put_schema(self, registration: SchemaRegistration) -> SchemaRegistration:
        with self._tx():
            rows = self._q(
                "SELECT registration_json FROM schemas WHERE namespace = %s",
                (registration.namespace,),
            )
            merged = common.merge_schema(
                common.row_to_schema(rows[0]) if rows else None, registration)
            self._x(
                "INSERT INTO schemas (namespace, registration_json, updated_at)"
                " VALUES (%s, %s, %s) ON CONFLICT (namespace) DO UPDATE SET"
                " registration_json = EXCLUDED.registration_json,"
                " updated_at = EXCLUDED.updated_at",
                (merged.namespace, merged.model_dump_json(),
                 common.iso(common.now())),
            )
            return merged

    def get_schema(self, namespace: str) -> SchemaRegistration | None:
        with self._tx(read=True):
            rows = self._q(
                "SELECT registration_json FROM schemas WHERE namespace = %s",
                (namespace,),
            )
        return common.row_to_schema(rows[0]) if rows else None

    def merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        with self._tx():
            rows = self._q(
                "SELECT namespace, key FROM entities"
                + (" WHERE namespace = %s" if namespace else "")
                + " GROUP BY namespace, key HAVING COUNT(DISTINCT type) > 1"
                " ORDER BY namespace, key LIMIT %s",
                ((namespace, limit) if namespace else (limit,)),
            )
            groups = []
            for row in rows:
                members = self._q(
                    "SELECT * FROM entities WHERE namespace = %s AND key = %s"
                    " ORDER BY created_at, type",
                    (row["namespace"], row["key"]),
                )
                groups.append([common.row_to_entity(m) for m in members])
        return groups

    def search_entities(
        self, namespace: str, query: str, limit: int = 10,
        types: tuple[str, ...] | None = None,
    ) -> list[Entity]:
        lowered = query.lower()
        type_sql, type_args = "", ()
        if types is not None:
            type_sql, type_args = " AND type = ANY(%s)", (list(types),)
        with self._tx(read=True):
            rows = self._q(
                "SELECT * FROM entities WHERE namespace = %s"
                "   AND (LOWER(key) = %s OR LOWER(key) LIKE %s ESCAPE '\\')"
                + type_sql
                + " ORDER BY (LOWER(key) != %s), type, key LIMIT %s",
                (namespace, lowered, common.like_pattern(query), *type_args,
                 lowered, limit),
            )
        return [common.row_to_entity(r) for r in rows]

    def count_observations(self, namespace: str, ref: EntityRef) -> int:
        with self._tx(read=True):
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return 0
            rows = self._q(
                "SELECT (SELECT COUNT(*) FROM observations o WHERE o.namespace = %s"
                "          AND o.subject_id = %s" + _NOT_TOMBSTONED + ")"
                "     + (SELECT COUNT(*) FROM observations o WHERE o.namespace = %s"
                "          AND o.object_entity_id = %s AND o.subject_id <> %s" + _NOT_TOMBSTONED + ")"
                " AS n",
                (namespace, entity.id, namespace, entity.id, entity.id),
            )
        return int(rows[0]["n"])

    def subjects_citing(
        self, namespace: str, artifact_ids: list[str],
        allowed_types: tuple[str, ...] | None = None, per_artifact: int = 5,
    ) -> dict[str, list[EntityRef]]:
        if not artifact_ids:
            return {}
        type_sql, type_args = "", ()
        if allowed_types is not None:
            if not allowed_types:
                return {}
            type_sql = " AND s.type = ANY(%s) AND (ob.id IS NULL OR ob.type = ANY(%s))"
            type_args = (list(allowed_types), list(allowed_types))
        with self._tx(read=True):
            rows = self._q(
                "SELECT DISTINCT (o.provenance_json::jsonb ->> 'artifact_id') AS aid,"
                " s.type AS stype, s.key AS skey"
                " FROM observations o JOIN entities s ON s.id = o.subject_id"
                " LEFT JOIN entities ob ON ob.id = o.object_entity_id"
                " WHERE o.namespace = %s"
                "   AND (o.provenance_json::jsonb ->> 'artifact_id') = ANY(%s)"
                + _NOT_TOMBSTONED + type_sql + " ORDER BY aid, stype, skey",
                (namespace, list(artifact_ids), *type_args),
            )
        out: dict[str, list[EntityRef]] = {}
        for r in rows:
            lst = out.setdefault(r["aid"], [])
            if len(lst) < per_artifact:
                lst.append(EntityRef(type=r["stype"], key=r["skey"]))
        return out

    def artifact_cited_within(
        self, namespace: str, artifact_id: str, allowed_types: tuple[str, ...]
    ) -> bool:
        if not allowed_types:
            return False
        with self._tx(read=True):
            rows = self._q(
                "SELECT 1 FROM observations o"
                " JOIN entities s ON s.id = o.subject_id"
                " LEFT JOIN entities ob ON ob.id = o.object_entity_id"
                " WHERE o.namespace = %s"
                "   AND (o.provenance_json::jsonb ->> 'artifact_id') = %s"
                "   AND s.type = ANY(%s)"
                "   AND (ob.id IS NULL OR ob.type = ANY(%s))"
                + _NOT_TOMBSTONED
                + " LIMIT 1",
                (namespace, artifact_id, list(allowed_types), list(allowed_types)),
            )
        return bool(rows)

    def record_claim(self, claim: ClaimIn) -> Observation:
        return self.record_claims([claim])[0]

    def record_claims(self, claims: list[ClaimIn]) -> list[Observation]:
        def once() -> list[Observation]:
            with self._tx():
                return [self._record_claim(c) for c in claims]
        return retry_on_deadlock(once)

    def observations_for(
        self, namespace: str, ref: EntityRef, limit: int = 100
    ) -> list[Observation]:
        with self._tx(read=True):
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return []
            # same two-index UNION as the SQLite store (D-035): a per-side
            # index range each, never a namespace scan
            rows = self._q(
                "SELECT * FROM (" + _OBS_SELECT
                + " WHERE o.namespace = %s AND o.subject_id = %s" + _NOT_TOMBSTONED
                + " ORDER BY o.observed_at DESC LIMIT %s) s"
                " UNION ALL SELECT * FROM (" + _OBS_SELECT
                + " WHERE o.namespace = %s AND o.object_entity_id = %s"
                "   AND o.subject_id <> %s" + _NOT_TOMBSTONED
                + " ORDER BY o.observed_at DESC LIMIT %s) t"
                " ORDER BY observed_at DESC LIMIT %s",
                (namespace, entity.id, limit, namespace, entity.id, entity.id, limit, limit),
            )
            return [common.row_to_observation(r) for r in rows]

    _MANY_CHUNK = 400

    def _resolve_many(self, namespace: str, refs: list[EntityRef]) -> dict[str, list[EntityRef]]:
        out: dict[str, list[EntityRef]] = {}
        for start in range(0, len(refs), self._MANY_CHUNK):
            chunk = refs[start:start + self._MANY_CHUNK]
            rows = self._q(
                "SELECT id, type, key FROM entities WHERE namespace = %s"
                " AND (type, key) IN (SELECT unnest(%s::text[]), unnest(%s::text[]))",
                (namespace, [r.type for r in chunk], [r.key for r in chunk]))
            found = {(r["type"], r["key"]): r["id"] for r in rows}
            missing = [r for r in chunk if (r.type, r.key) not in found]
            for r in chunk:
                if (r.type, r.key) in found:
                    out.setdefault(found[(r.type, r.key)], []).append(r)
            if missing:
                arows = self._q(
                    "SELECT alias, entity_id FROM aliases WHERE namespace = %s AND alias = ANY(%s)",
                    (namespace, [f"{r.type}:{r.key}" for r in missing]))
                by_alias = {r["alias"]: r["entity_id"] for r in arows}
                for r in missing:
                    eid = by_alias.get(f"{r.type}:{r.key}")
                    if eid:
                        out.setdefault(eid, []).append(r)
        return out

    def observations_for_many(
        self, namespace: str, refs: list[EntityRef], limit: int = 100
    ) -> dict[tuple[str, str], list[Observation]]:
        result: dict[tuple[str, str], list[Observation]] = {}
        if not refs:
            return result
        with self._tx(read=True):
            owners = self._resolve_many(namespace, refs)
            ids = list(owners)
            for start in range(0, len(ids), self._MANY_CHUNK):
                chunk = ids[start:start + self._MANY_CHUNK]
                rows = self._q(
                    "WITH hits AS ("
                    + _OBS_SELECT_ENT.format(ent="o.subject_id") +
                    " WHERE o.namespace = %s AND o.subject_id = ANY(%s)" + _NOT_TOMBSTONED +
                    " UNION ALL "
                    + _OBS_SELECT_ENT.format(ent="o.object_entity_id") +
                    " WHERE o.namespace = %s AND o.object_entity_id = ANY(%s)"
                    "   AND o.subject_id <> o.object_entity_id" + _NOT_TOMBSTONED +
                    "), ranked AS (SELECT *, row_number() OVER (PARTITION BY ent ORDER BY observed_at DESC) AS rn FROM hits)"
                    " SELECT * FROM ranked WHERE rn <= %s ORDER BY ent, observed_at DESC",
                    (namespace, chunk, namespace, chunk, limit),
                )
                for row in rows:
                    obs = common.row_to_observation(row)
                    for ref in owners[row["ent"]]:
                        result.setdefault((ref.type, ref.key), []).append(obs)
        return result

    def store_artifact(self, doc: DocumentIn) -> Artifact:
        return retry_on_deadlock(lambda: self._store_artifact(doc))

    def _store_artifact(self, doc: DocumentIn) -> Artifact:
        with self._tx():
            if doc.event_id is not None:
                existing = self._artifact_by_event(doc.namespace, doc.event_id)
                if existing is not None:
                    metrics.INGEST_DEDUPED.inc()
                    return existing
            artifact = Artifact(
                id=uuid.uuid4().hex,
                namespace=doc.namespace,
                event_id=doc.event_id,
                filename=doc.filename,
                content_type=doc.content_type,
                text=doc.text,
                content_b64=doc.content_b64,
                source=doc.source,
                observed_at=doc.observed_at,
                recorded_at=common.now(),
                attrs=doc.attrs,
            )
            inserted = self._insert_artifact(artifact, suffix=_ON_EVENT_CONFLICT)
            if not inserted:  # lost the race to another writer (H-B2)
                metrics.INGEST_DEDUPED.inc()
                return self._artifact_by_event(doc.namespace, doc.event_id)
        return artifact

    def artifact_by_event(self, namespace: str, event_id: str) -> Artifact | None:
        with self._tx():
            return self._artifact_by_event(namespace, event_id)

    def get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        with self._tx(read=True):
            return self._get_artifact(namespace, artifact_id)

    def ping(self) -> bool:
        try:
            with self._tx():
                self._q("SELECT 1")
            if self._read_pool is not None:
                with self._tx(read=True):
                    self._q("SELECT 1")
            return True
        except Exception:  # noqa: BLE001 — pool timeouts are not psycopg errors
            return False

    # ----------------------------------------------------- enrichment (D-018)

    def put_embeddings(
        self, namespace: str, model: str,
        items: list[tuple[str, list[float]]],
    ) -> None:
        with self._tx():
            with self._conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO embeddings (ref_id, namespace, model, vector)"
                    " VALUES (%s, %s, %s, %s)"
                    " ON CONFLICT (ref_id) DO UPDATE SET namespace ="
                    " EXCLUDED.namespace, model = EXCLUDED.model,"
                    " vector = EXCLUDED.vector",
                    [(ref_id, namespace, model, common.pack_vector(vec))
                     for ref_id, vec in items],
                )
            self._vec_upsert("vobs", model, namespace,
                             [(ref_id, None, vec) for ref_id, vec in items])

    def embeddings_for(
        self, namespace: str, ref_ids: list[str], model: str
    ) -> dict[str, list[float]]:
        if not ref_ids:
            return {}
        with self._tx(read=True):
            rows = self._q(
                "SELECT ref_id, vector FROM embeddings"
                " WHERE namespace = %s AND model = %s AND ref_id = ANY(%s)",
                (namespace, model, ref_ids),
            )
        return {r["ref_id"]: common.unpack_vector(r["vector"]) for r in rows}

    # hex value of the id's last character, 0..15: the shard key (D-031)
    _SHARD_EXPR = "(position(right(o.id, 1) in '0123456789abcdef') - 1)"

    def observations_without_embeddings(
        self, model: str, limit: int = 128, shard: tuple[int, int] | None = None
    ) -> list[Observation]:
        shard_sql, shard_args = "", ()
        if shard is not None and shard[1] > 1:
            shard_sql, shard_args = f" AND {self._SHARD_EXPR} %% %s = %s", (shard[1], shard[0])
        with self._tx():
            rows = self._q(
                _OBS_SELECT
                + " WHERE NOT EXISTS (SELECT 1 FROM embeddings em"
                "   WHERE em.ref_id = o.id AND em.model = %s)"
                + _NOT_TOMBSTONED + shard_sql
                + " ORDER BY o.recorded_at LIMIT %s",
                (model, *shard_args, limit),
            )
            return [common.row_to_observation(r) for r in rows]

    def pending_artifacts(
        self, limit: int = 4, now: datetime | None = None,
        lease: tuple[str, float] | None = None,
    ) -> list[Artifact]:
        moment = now or common.now()
        now_iso = common.iso(moment)
        with self._tx():
            if lease is None:
                rows = self._q(
                    "SELECT * FROM artifacts WHERE extraction_status = 'pending'"
                    " AND (next_attempt_at IS NULL OR next_attempt_at <= %s)"
                    " ORDER BY recorded_at LIMIT %s",
                    (now_iso, limit),
                )
            else:
                worker, seconds = lease
                until = common.iso(moment + timedelta(seconds=seconds))
                # SKIP LOCKED: concurrent claimers never block on or take the
                # same rows (D-031). A MATERIALIZED CTE is required: with the
                # subquery inline under IN (...) the planner re-evaluates it
                # per row and the LIMIT is not honoured (observed: LIMIT 2
                # claimed 3 rows).
                rows = self._q(
                    "WITH picked AS MATERIALIZED (SELECT id FROM artifacts"
                    "   WHERE extraction_status = 'pending'"
                    "   AND (next_attempt_at IS NULL OR next_attempt_at <= %s)"
                    "   AND (extract_claimed_until IS NULL OR extract_claimed_until < %s)"
                    "   ORDER BY recorded_at LIMIT %s FOR UPDATE SKIP LOCKED)"
                    " UPDATE artifacts a SET extract_claimed_by = %s, extract_claimed_until = %s"
                    " FROM picked WHERE a.id = picked.id RETURNING a.*",
                    (now_iso, now_iso, limit, worker, until),
                )
        return sorted((common.row_to_artifact(r) for r in rows), key=lambda a: a.recorded_at)

    def defer_extraction(
        self, namespace: str, artifact_id: str, attempts: int, next_attempt_at: datetime
    ) -> None:
        with self._tx():
            self._x(
                "UPDATE artifacts SET extraction_attempts = %s, next_attempt_at = %s,"
                " extract_claimed_until = NULL WHERE namespace = %s AND id = %s",
                (attempts, common.iso(next_attempt_at), namespace, artifact_id),
            )

    def set_extraction_status(
        self, namespace: str, artifact_id: str, status: str
    ) -> None:
        with self._tx():
            self._x(
                "UPDATE artifacts SET extraction_status = %s, extract_claimed_until = NULL"
                " WHERE namespace = %s AND id = %s",
                (status, namespace, artifact_id),
            )

    _NEEDS_CHUNKS = (
        "a.text IS NOT NULL"
        # blank docs would re-queue forever (H-D4); TRIM alone strips only
        # spaces, so name the whitespace set explicitly
        " AND BTRIM(a.text, E' \\t\\n\\r') <> ''"
        " AND NOT EXISTS (SELECT 1 FROM doc_chunks c"
        "   WHERE c.artifact_id = a.id AND c.model = %s)"
    )

    def artifacts_needing_chunks(
        self, model: str, limit: int = 4, lease: tuple[str, float] | None = None
    ) -> list[Artifact]:
        with self._tx():
            if lease is None:
                rows = self._q(
                    f"SELECT * FROM artifacts a WHERE {self._NEEDS_CHUNKS}"
                    " ORDER BY a.recorded_at LIMIT %s", (model, limit))
            else:
                moment = common.now()
                until = common.iso(moment + timedelta(seconds=lease[1]))
                rows = self._q(
                    "WITH picked AS MATERIALIZED"
                    f" (SELECT a.id FROM artifacts a WHERE {self._NEEDS_CHUNKS}"
                    "   AND (a.chunk_claimed_until IS NULL OR a.chunk_claimed_until < %s)"
                    "   ORDER BY a.recorded_at LIMIT %s FOR UPDATE SKIP LOCKED)"
                    " UPDATE artifacts a SET chunk_claimed_until = %s"
                    " FROM picked WHERE a.id = picked.id RETURNING a.*",
                    (model, common.iso(moment), limit, until))
        return sorted((common.row_to_artifact(r) for r in rows), key=lambda a: a.recorded_at)

    def put_doc_chunks(
        self, namespace: str, artifact_id: str, model: str,
        chunks: list[tuple[int, int, int, str, list[float]]],
    ) -> None:
        with self._tx():
            with self._conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO doc_chunks (id, namespace, artifact_id, seq,"
                    " span_start, span_end, text, vector, model)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    " ON CONFLICT (id) DO UPDATE SET namespace = EXCLUDED.namespace,"
                    " span_start = EXCLUDED.span_start, span_end = EXCLUDED.span_end,"
                    " text = EXCLUDED.text, vector = EXCLUDED.vector,"
                    " model = EXCLUDED.model",
                    [(f"{artifact_id}:{model}:{seq}", namespace, artifact_id, seq,
                      start, end, text, common.pack_vector(vec), model)
                     for seq, start, end, text, vec in chunks],
                )
            self._vec_upsert("vchk", model, namespace,
                             [(f"{artifact_id}:{model}:{seq}", artifact_id, vec)
                              for seq, _, _, _, vec in chunks])
            self._x("UPDATE artifacts SET chunk_claimed_until = NULL WHERE id = %s",
                    (artifact_id,))

    def doc_chunks_for_artifacts(
        self, namespace: str, artifact_ids: list[str], model: str
    ) -> list[dict]:
        if not artifact_ids:
            return []
        with self._tx(read=True):
            rows = self._q(
                "SELECT c.artifact_id, c.seq, c.span_start, c.span_end,"
                " c.text, c.vector, a.source, a.observed_at"
                " FROM doc_chunks c JOIN artifacts a ON a.id = c.artifact_id"
                " WHERE c.namespace = %s AND c.model = %s"
                " AND c.artifact_id = ANY(%s)",
                (namespace, model, artifact_ids),
            )
        return [common.row_to_chunk(r) for r in rows]

    def doc_chunks_by_seq(
        self, namespace: str, artifact_id: str, model: str, seqs: list[int]
    ) -> list[dict]:
        if not seqs:
            return []
        with self._tx(read=True):
            rows = self._q(
                "SELECT c.artifact_id, c.seq, c.span_start, c.span_end,"
                " c.text, c.vector, a.source, a.observed_at"
                " FROM doc_chunks c JOIN artifacts a ON a.id = c.artifact_id"
                " WHERE c.namespace = %s AND c.artifact_id = %s AND c.model = %s"
                " AND c.seq = ANY(%s) ORDER BY c.seq",
                (namespace, artifact_id, model, list(seqs)),
            )
        return [common.row_to_chunk(r) for r in rows]

    def get_dossier(self, namespace: str, ref: EntityRef) -> dict | None:
        with self._tx(read=True):
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return None
            rows = self._q(
                "SELECT brief, observation_count, observation_ids, updated_at"
                " FROM dossiers WHERE namespace = %s AND entity_id = %s",
                (namespace, entity.id),
            )
        if not rows:
            return None
        return common.row_to_dossier(rows[0])

    def put_dossier(
        self, namespace: str, ref: EntityRef, brief: str,
        observation_count: int, observation_ids: list[str],
    ) -> None:
        with self._tx():
            entity = self._resolve_entity(namespace, ref) or self._upsert_entity(
                namespace, ref
            )
            self._x(
                "INSERT INTO dossiers (namespace, entity_id, brief,"
                " observation_count, observation_ids, updated_at)"
                " VALUES (%s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (namespace, entity_id) DO UPDATE SET"
                " brief = EXCLUDED.brief,"
                " observation_count = EXCLUDED.observation_count,"
                " observation_ids = EXCLUDED.observation_ids,"
                " updated_at = EXCLUDED.updated_at",
                (namespace, entity.id, brief, observation_count,
                 json.dumps(list(observation_ids)), common.iso(common.now())),
            )
            self._x("UPDATE entities SET dossier_claimed_until = NULL WHERE id = %s",
                    (entity.id,))

    def dossier_candidates(
        self, min_new: int = 20, min_total: int = 5, limit: int = 4,
        lease: tuple[str, float] | None = None,
    ) -> list[tuple[str, EntityRef, int]]:
        moment = common.now()
        with self._tx():
            rows = self._q(
                "SELECT e.namespace, e.type, e.key, e.id AS eid, COUNT(o.id) AS fresh"
                " FROM entities e"
                " JOIN observations o ON o.subject_id = e.id"
                "   AND NOT EXISTS (SELECT 1 FROM tombstones t"
                "                   WHERE t.observation_id = o.id)"
                " LEFT JOIN dossiers d ON d.namespace = e.namespace"
                "   AND d.entity_id = e.id"
                " WHERE (d.updated_at IS NULL OR o.recorded_at > d.updated_at)"
                "   AND (e.dossier_claimed_until IS NULL OR e.dossier_claimed_until < %s)"
                " GROUP BY e.id, d.observation_count"
                " HAVING (d.observation_count IS NULL AND COUNT(o.id) >= %s)"
                "     OR (d.observation_count IS NOT NULL AND COUNT(o.id) >= %s)"
                " ORDER BY COUNT(o.id) DESC, e.created_at LIMIT %s",
                (common.iso(moment), min_total, min_new, limit),
            )
            out = []
            for r in rows:
                if lease is not None:
                    claimed = self._x(
                        "UPDATE entities SET dossier_claimed_until = %s WHERE id = %s"
                        " AND (dossier_claimed_until IS NULL OR dossier_claimed_until < %s)",
                        (common.iso(moment + timedelta(seconds=lease[1])), r["eid"],
                         common.iso(moment)))
                    if not claimed:
                        continue
                total = self._q(
                    "SELECT COUNT(*) AS n FROM observations o WHERE o.subject_id = %s"
                    + _NOT_TOMBSTONED, (r["eid"],))[0]["n"]
                out.append((r["namespace"], EntityRef(type=r["type"], key=r["key"]),
                            int(total)))
        return out

    # ------------------------------------------------------ lifecycle (D-016)

    def redact(self, namespace: str, observation_id: str, reason: str) -> bool:
        with self._tx():
            rows = self._q(
                "SELECT 1 FROM observations WHERE id = %s AND namespace = %s",
                (observation_id, namespace),
            )
            if not rows:
                return False
            self._put_tombstone(namespace, observation_id, reason, common.now())
            self._x(
                "DELETE FROM dossiers WHERE namespace = %s AND observation_ids LIKE %s",
                (namespace, f'%"{observation_id}"%'),
            )
            return True

    def purge_older_than(self, namespace: str, before: datetime) -> int:
        cutoff = common.iso(before)
        with self._tx():
            removed = self._x(
                "DELETE FROM observations WHERE namespace = %s AND observed_at < %s",
                (namespace, cutoff),
            )
            removed += self._x(
                "DELETE FROM artifacts WHERE namespace = %s AND observed_at < %s",
                (namespace, cutoff),
            )
            self._x("DELETE FROM tombstones WHERE observation_id NOT IN"
                    " (SELECT id FROM observations)")
            self._x("DELETE FROM embeddings WHERE ref_id NOT IN"
                    " (SELECT id FROM observations)")
            self._x("DELETE FROM doc_chunks WHERE artifact_id NOT IN"
                    " (SELECT id FROM artifacts)")
            self._x(
                "DELETE FROM dossiers WHERE namespace = %s AND entity_id NOT IN"
                " (SELECT subject_id FROM observations WHERE namespace = %s)",
                (namespace, namespace),
            )
        return removed

    _PAGE = 1000

    def _pages(self, sql: str, params: tuple, order_cols: tuple[str, str]):
        """Keyset-paged streaming (H-E4): bounded memory, lock per page."""
        last = ("", "")
        while True:
            with self._tx(read=True):
                rows = self._q(
                    sql + f" AND ({order_cols[0]}, {order_cols[1]}) > (%s, %s)"
                    f" ORDER BY {order_cols[0]}, {order_cols[1]} LIMIT %s",
                    (*params, *last, self._PAGE),
                )
            if not rows:
                return
            yield from rows
            tail = rows[-1]
            last = (tail[order_cols[0].split(".")[-1]], tail["id"])

    def iter_observations(
        self, namespace: str | None = None
    ) -> Iterator[Observation]:
        sql = _OBS_SELECT + " WHERE 1=1" + (" AND o.namespace = %s" if namespace else "")
        for row in self._pages(sql, (namespace,) if namespace else (),
                               ("o.recorded_at", "o.id")):
            yield common.row_to_observation(row)

    def namespace_summary(self) -> dict[str, dict[str, int]]:
        with self._tx(read=True):
            rows = self._q("SELECT namespace, type, COUNT(*) AS n FROM entities"
                           " GROUP BY namespace, type ORDER BY namespace, type")
        out: dict[str, dict[str, int]] = {}
        for r in rows:
            out.setdefault(r["namespace"], {})[r["type"]] = int(r["n"])
        return out

    def iter_entities(self, namespace: str | None = None) -> Iterator[Entity]:
        sql = "SELECT * FROM entities WHERE 1=1" + (" AND namespace = %s" if namespace else "")
        for row in self._pages(sql, (namespace,) if namespace else (),
                               ("created_at", "id")):
            yield common.row_to_entity(row)

    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]:
        sql = "SELECT * FROM artifacts WHERE 1=1" + (" AND namespace = %s" if namespace else "")
        for row in self._pages(sql, (namespace,) if namespace else (),
                               ("recorded_at", "id")):
            yield common.row_to_artifact(row)

    def iter_aliases(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx():
            rows = self._q(
                "SELECT a.namespace, a.alias, e.type, e.key"
                " FROM aliases a JOIN entities e ON e.id = a.entity_id"
                + (" WHERE a.namespace = %s" if namespace else "")
                + " ORDER BY a.namespace, a.alias",
                (namespace,) if namespace else (),
            )
        for r in rows:
            yield {"namespace": r["namespace"], "alias": r["alias"],
                   "canonical": {"type": r["type"], "key": r["key"]}}

    def iter_tombstones(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx():
            rows = self._q(
                "SELECT * FROM tombstones"
                + (" WHERE namespace = %s" if namespace else "")
                + " ORDER BY recorded_at, observation_id",
                (namespace,) if namespace else (),
            )
        for r in rows:
            yield {"namespace": r["namespace"],
                   "observation_id": r["observation_id"],
                   "reason": r["reason"], "recorded_at": r["recorded_at"]}

    def restore_observation(self, obs: Observation) -> None:
        with self._tx():
            subject = self._upsert_entity(obs.namespace, obs.subject)
            object_entity_id = None
            if isinstance(obs.object, EntityRef):
                object_entity_id = self._upsert_entity(obs.namespace, obs.object).id
                object_json = json.dumps(obs.object.model_dump())
            else:
                object_json = json.dumps(obs.object)
            # targetless ON CONFLICT covers the id PK and the event_id index
            self._x(
                _OBS_INSERT + " ON CONFLICT DO NOTHING",
                self._obs_row(obs, subject.id, object_json, object_entity_id),
            )

    def restore_artifact(self, artifact: Artifact) -> None:
        with self._tx():
            self._insert_artifact(artifact, suffix=" ON CONFLICT DO NOTHING")

    def restore_entity(self, entity: Entity) -> None:
        with self._tx():
            self._x(
                "INSERT INTO entities (id, namespace, type, key, provisional,"
                " created_at, norm_key) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (namespace, type, key) DO NOTHING",
                (uuid.uuid4().hex, entity.namespace, entity.type, entity.key,
                 bool(entity.provisional), common.iso(entity.created_at),
                 common.norm_key(entity.key)),
            )

    def restore_alias(self, namespace: str, alias: str, canonical: EntityRef) -> None:
        with self._tx():
            target = self._upsert_entity(namespace, canonical)
            self._put_alias(namespace, alias, target.id)

    def restore_tombstone(
        self, namespace: str, observation_id: str, reason: str, recorded_at: datetime
    ) -> None:
        with self._tx():
            self._put_tombstone(namespace, observation_id, reason, recorded_at)

    def wipe(self) -> None:
        with self._tx():
            for table in ("tombstones", "embeddings", "dossiers", "doc_chunks",
                          "observations", "aliases", "artifacts", "entities",
                          "schemas", *self._vec_tables):
                self._x(f"DELETE FROM {table}")

    def close(self) -> None:
        self._pool.close()
        if self._read_pool is not None:
            self._read_pool.close()

    # ------------------------------------------------- internals (no commit)

    def _get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        """Exact (type, key) match only — used by writes and merges."""
        rows = self._q(
            "SELECT * FROM entities"
            " WHERE namespace = %s AND type = %s AND key = %s",
            (namespace, ref.type, ref.key),
        )
        return common.row_to_entity(rows[0]) if rows else None

    def _resolve_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        """Exact match, else follow an alias record from a prior merge."""
        direct = self._get_entity(namespace, ref)
        if direct is not None:
            return direct
        rows = self._q(
            "SELECT e.* FROM aliases a JOIN entities e ON e.id = a.entity_id"
            " WHERE a.namespace = %s AND a.alias = %s",
            (namespace, f"{ref.type}:{ref.key}"),
        )
        return common.row_to_entity(rows[0]) if rows else None

    def _get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        rows = self._q(
            "SELECT * FROM artifacts WHERE namespace = %s AND id = %s",
            (namespace, artifact_id),
        )
        return common.row_to_artifact(rows[0]) if rows else None

    def _resolve_provenance(self, claim: ClaimIn):
        """artifact_event_id -> artifact_id at write time (D-039); a
        reference to a document that was never ingested is an error, never
        a silently dropped citation."""
        prov = claim.provenance
        if prov is None or prov.artifact_id:
            return prov
        found = self._artifact_by_event(claim.namespace, prov.artifact_event_id)
        if found is None:
            raise ValueError(f"provenance.artifact_event_id {prov.artifact_event_id!r} does not name a "
                             f"document in namespace {claim.namespace!r}; ingest the document first")
        return prov.model_copy(update={"artifact_id": found.id})

    def _artifact_by_event(self, namespace: str, event_id: str) -> Artifact | None:
        rows = self._q(
            "SELECT * FROM artifacts WHERE namespace = %s AND event_id = %s",
            (namespace, event_id),
        )
        return common.row_to_artifact(rows[0]) if rows else None

    def _upsert_entity(self, namespace: str, ref: EntityRef) -> Entity:
        existing = self._get_entity(namespace, ref)
        if existing is not None:
            return existing
        entity = Entity(
            id=uuid.uuid4().hex,
            namespace=namespace,
            type=ref.type,
            key=ref.key,
            created_at=common.now(),
        )
        self._x(
            "INSERT INTO entities (id, namespace, type, key, provisional,"
            " created_at, norm_key) VALUES (%s, %s, %s, %s, FALSE, %s, %s)"
            " ON CONFLICT (namespace, type, key) DO NOTHING",
            (entity.id, namespace, ref.type, ref.key,
             common.iso(entity.created_at), common.norm_key(ref.key)),
        )
        # A concurrent writer may have won the ON CONFLICT race; re-read.
        return self._get_entity(namespace, ref) or entity

    def _put_alias(self, namespace: str, alias: str, entity_id: str) -> None:
        self._x(
            "INSERT INTO aliases (namespace, alias, entity_id)"
            " VALUES (%s, %s, %s) ON CONFLICT (namespace, alias)"
            " DO UPDATE SET entity_id = EXCLUDED.entity_id",
            (namespace, alias, entity_id),
        )

    def _put_tombstone(
        self, namespace: str, observation_id: str, reason: str, recorded_at: datetime
    ) -> None:
        self._x(
            "INSERT INTO tombstones (observation_id, namespace, reason,"
            " recorded_at) VALUES (%s, %s, %s, %s)"
            " ON CONFLICT (observation_id) DO UPDATE SET reason ="
            " EXCLUDED.reason, recorded_at = EXCLUDED.recorded_at",
            (observation_id, namespace, reason, common.iso(recorded_at)),
        )

    def _existing_by_event(self, namespace: str, event_id: str) -> Observation | None:
        rows = self._q(
            _OBS_SELECT + " WHERE o.namespace = %s AND o.event_id = %s",
            (namespace, event_id),
        )
        if not rows:
            return None
        obs = common.row_to_observation(rows[0])
        tomb = self._q("SELECT 1 FROM tombstones WHERE observation_id = %s",
                       (obs.id,))
        return common.redacted_view(obs) if tomb else obs

    def _record_claim(self, claim: ClaimIn) -> Observation:
        if claim.event_id is not None:
            existing = self._existing_by_event(claim.namespace, claim.event_id)
            if existing is not None:
                metrics.INGEST_DEDUPED.inc()
                return existing

        subject = self._upsert_entity(claim.namespace, claim.subject)
        object_entity_id = None
        if isinstance(claim.object, EntityRef):
            object_entity_id = self._upsert_entity(claim.namespace, claim.object).id
            object_json = json.dumps(claim.object.model_dump())
        else:
            object_json = json.dumps(claim.object)

        obs = Observation(
            id=uuid.uuid4().hex,
            namespace=claim.namespace,
            event_id=claim.event_id,
            subject=claim.subject,
            predicate=claim.predicate,
            object=claim.object,
            observed_at=claim.observed_at,
            valid_from=claim.valid_from,
            valid_to=claim.valid_to,
            recorded_at=common.now(),
            source=claim.source,
            confidence=claim.confidence,
            provenance=self._resolve_provenance(claim),
            attrs=claim.attrs,
        )
        inserted = self._x(
            _OBS_INSERT + _ON_EVENT_CONFLICT,
            self._obs_row(obs, subject.id, object_json, object_entity_id),
        )
        if inserted == 0:  # another writer landed this event_id first (H-B2)
            metrics.INGEST_DEDUPED.inc()
            return self._existing_by_event(claim.namespace, claim.event_id)
        return obs

    @staticmethod
    def _obs_row(obs: Observation, subject_id: str, object_json: str,
                 object_entity_id: str | None) -> tuple:
        return (
            obs.id, obs.namespace, obs.event_id, subject_id, obs.predicate,
            object_json, object_entity_id, common.iso(obs.observed_at),
            common.iso(obs.valid_from), common.iso(obs.valid_to),
            common.iso(obs.recorded_at), obs.source, obs.confidence,
            json.dumps(obs.provenance.model_dump()) if obs.provenance else None,
            json.dumps(obs.attrs),
        )

    def _insert_artifact(self, artifact: Artifact, suffix: str = "") -> bool:
        return self._x(
            "INSERT INTO artifacts (id, namespace, event_id, filename,"
            " content_type, text, content_b64, source, observed_at, recorded_at,"
            " extraction_status, extraction_attempts, attrs_json)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)" + suffix,
            (
                artifact.id, artifact.namespace, artifact.event_id,
                artifact.filename, artifact.content_type, artifact.text,
                artifact.content_b64, artifact.source,
                common.iso(artifact.observed_at), common.iso(artifact.recorded_at),
                artifact.extraction_status, artifact.extraction_attempts,
                json.dumps(artifact.attrs),
            ),
        ) > 0
