"""Server-backed GraphStore: Postgres (D-008, D-011, D-014, D-016).

The scaling lane: multiple engine replicas and writer consumers share one
Postgres. Column shapes, idempotent-ingest semantics (event_id dedupe),
tombstone redaction, and lifecycle operations are identical to the SQLite
store — the shared contract tests enforce it.

Every public method runs inside `_tx()`: borrow a connection from the pool,
commit on success, ROLLBACK on any exception. A failed statement can never
leave a connection in "current transaction is aborted" (hardening H-B1).

Concurrency (D-028): a `psycopg_pool` of `LOOMCTX_DB_POOL` connections per
process (default 4) so an engine pod serves that many queries at once;
`LOOMCTX_DB_READ` optionally names a read-replica DSN — packs, searches, and
exports go there, ingest and the worker's backlog queries stay on the
primary. Reads from a replica may lag by replication delay; observations
are append-only and `as_of` makes staleness explicit, so that is safe.

Selected purely by connection string — set LOOMCTX_DB=postgresql://... and
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

log = logging.getLogger("loomctx.store")
from .base import GraphStore

_SCHEMA = """
CREATE TABLE IF NOT EXISTS loomctx_meta (
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
    dossier_claimed_by    TEXT,
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
    attrs_json       TEXT NOT NULL DEFAULT '{}',
    supersedes       TEXT
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
    chunk_claimed_by      TEXT,
    attrs_json        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tombstones (
    observation_id TEXT PRIMARY KEY,
    namespace      TEXT NOT NULL,
    reason         TEXT NOT NULL,
    recorded_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resolution_declines (
    namespace  TEXT NOT NULL,
    a          TEXT NOT NULL,
    b          TEXT NOT NULL,
    reason     TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    PRIMARY KEY (namespace, a, b)
);

-- merge reversal log (schema v5): see sqlite.py for the column semantics
CREATE TABLE IF NOT EXISTS merge_log (
    id                 TEXT PRIMARY KEY,
    namespace          TEXT NOT NULL,
    from_type          TEXT NOT NULL,
    from_key           TEXT NOT NULL,
    into_type          TEXT NOT NULL,
    into_key           TEXT NOT NULL,
    from_id            TEXT NOT NULL,
    from_provisional   BOOLEAN NOT NULL DEFAULT FALSE,
    from_created_at    TEXT NOT NULL,
    prior_aliases_json TEXT NOT NULL DEFAULT '[]',
    recorded_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS merge_log_observations (
    merge_id               TEXT NOT NULL REFERENCES merge_log (id),
    observation_id         TEXT NOT NULL,
    prior_subject_id       TEXT,
    prior_object_entity_id TEXT,
    prior_object_json      TEXT,
    PRIMARY KEY (merge_id, observation_id)
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
ALTER TABLE entities     ADD COLUMN IF NOT EXISTS dossier_claimed_by TEXT;
ALTER TABLE artifacts    ADD COLUMN IF NOT EXISTS chunk_claimed_by TEXT;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS supersedes TEXT;

CREATE INDEX IF NOT EXISTS idx_obs_subject
    ON observations (namespace, subject_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_obs_object
    ON observations (namespace, object_entity_id, observed_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_obs_event
    ON observations (namespace, event_id) WHERE event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_art_event
    ON artifacts (namespace, event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_obs_recorded ON observations (recorded_at);
CREATE INDEX IF NOT EXISTS idx_obs_id_pattern ON observations (id text_pattern_ops);
CREATE INDEX IF NOT EXISTS idx_art_status ON artifacts (extraction_status, recorded_at);
CREATE INDEX IF NOT EXISTS idx_chunk_by_artifact ON doc_chunks (artifact_id);
CREATE INDEX IF NOT EXISTS idx_entity_key ON entities (namespace, key);
CREATE INDEX IF NOT EXISTS idx_entity_norm ON entities (namespace, norm_key);
CREATE INDEX IF NOT EXISTS idx_entity_lower_key ON entities (namespace, lower(key) text_pattern_ops);
-- label search (v9, D-091): scalar values by predicate, lower-cased JSON
-- text capped at 200 characters (a B-tree entry has a size ceiling)
CREATE INDEX IF NOT EXISTS idx_obs_label
    ON observations (namespace, predicate, lower(left(object_json, 200)) text_pattern_ops)
    WHERE object_entity_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_merge_from ON merge_log (namespace, from_type, from_key);
CREATE INDEX IF NOT EXISTS idx_obs_supersedes
    ON observations (namespace, supersedes) WHERE supersedes IS NOT NULL;
-- worker tick scans (R-9): see sqlite.py
CREATE INDEX IF NOT EXISTS idx_obs_subject_recorded ON observations (subject_id, recorded_at);
-- the entity foreign keys' child columns, leading (v8, S-63): deleting a
-- merged-away entity checks nothing still points at it, and without these
-- the object-side and alias checks scanned the whole table per merge
CREATE INDEX IF NOT EXISTS idx_obs_object_entity ON observations (object_entity_id)
    WHERE object_entity_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alias_entity ON aliases (entity_id);
CREATE INDEX IF NOT EXISTS idx_art_recorded ON artifacts (recorded_at);
CREATE INDEX IF NOT EXISTS idx_entity_dossier_lease
    ON entities (dossier_claimed_until) WHERE dossier_claimed_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_entity_created ON entities (namespace, created_at);
-- analyze after a bounded change, not a tenth of the table (v7, D-081): a new
-- namespace loaded into a million-row store was planned without statistics
-- for it (44 s per ask, 0.5 s after ANALYZE) until a tenth had changed
ALTER TABLE observations SET (autovacuum_analyze_scale_factor = 0.01,
                              autovacuum_analyze_threshold = 5000);
ALTER TABLE entities SET (autovacuum_analyze_scale_factor = 0.01,
                          autovacuum_analyze_threshold = 5000);
"""

# search_entities: a half-open range with the text_pattern_ops operators —
# byte-wise, collation-free comparisons, so the expression index is used
# and the semantics match the SQLite store's BINARY range exactly.
_SEARCH_SQL = (
    "SELECT * FROM entities WHERE namespace = %s"
    "   AND lower(key) ~>=~ %s AND lower(key) ~<~ %s"
)
_PREFIX_END = "\U0010ffff"
# label search (D-091): the indexed expression, verbatim, so the index applies
_LABEL_SQL = (
    "SELECT e.*, bool_and(lower(left(o.object_json, 200)) <> %s) AS inexact"
    " FROM observations o JOIN entities e ON e.id = o.subject_id"
    " WHERE o.namespace = %s AND o.object_entity_id IS NULL AND o.predicate = ANY(%s)"
    "   AND lower(left(o.object_json, 200)) ~>=~ %s AND lower(left(o.object_json, 200)) ~<~ %s"
)

SCHEMA_VERSION = 9  # keep in step with sqlite.py (v6: observations.supersedes, D-050; tick-scan indexes, R-9; hex norm_key; v7: analyze thresholds, D-081; v8: FK child indexes, S-63; v9: label index, D-091)

_NOT_TOMBSTONED = (
    " AND NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.observation_id = o.id)"
)


def _observed_before(mark: str, before) -> tuple[str, tuple]:
    """SQL fragment + args bounding observed_at (the `as_of` axis, D-046);
    empty when no bound. observed_at is stored as UTC ISO text (D-022), so a
    normalized string compares correctly."""
    if before is None:
        return "", ()
    return f" AND o.observed_at <= {mark}", (common.iso(before),)

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

# tick scans from a high-water mark (R-9): see sqlite.py for the semantics
_EMBED_BACKLOG_SQL = (
    _OBS_SELECT
    + " WHERE o.recorded_at >= %s"
    " AND NOT EXISTS (SELECT 1 FROM embeddings em WHERE em.ref_id = o.id AND em.model = %s)"
    + _NOT_TOMBSTONED + "{shard}"
    " ORDER BY o.recorded_at LIMIT %s"
)

_DOSSIER_SQL = (
    "WITH touched AS ("
    "  SELECT DISTINCT o.subject_id AS eid FROM observations o WHERE o.recorded_at >= %s"
    "  UNION SELECT id FROM entities WHERE dossier_claimed_until IS NOT NULL)"
    " SELECT e.namespace, e.type, e.key, e.id AS eid, COUNT(o.id) AS fresh"
    " FROM touched t JOIN entities e ON e.id = t.eid"
    " JOIN observations o ON o.subject_id = e.id"
    "   AND NOT EXISTS (SELECT 1 FROM tombstones t2 WHERE t2.observation_id = o.id)"
    " LEFT JOIN dossiers d ON d.namespace = e.namespace AND d.entity_id = e.id"
    " WHERE (d.updated_at IS NULL OR o.recorded_at > d.updated_at)"
    "   AND (e.dossier_claimed_until IS NULL OR e.dossier_claimed_until < %s)"
    " GROUP BY e.id, d.observation_count"
    " HAVING (d.observation_count IS NULL AND COUNT(o.id) >= %s AND COUNT(DISTINCT o.predicate) >= 2)"
    "     OR (d.observation_count IS NOT NULL AND COUNT(o.id) >= %s)"
    " ORDER BY COUNT(DISTINCT o.predicate) * COUNT(DISTINCT o.source) DESC, COUNT(o.id) DESC,"
    "          e.created_at LIMIT %s"
)

_OBS_INSERT = (
    "INSERT INTO observations (id, namespace, event_id, subject_id, predicate,"
    " object_json, object_entity_id, observed_at, valid_from, valid_to,"
    " recorded_at, source, confidence, provenance_json, attrs_json, supersedes)"
    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)

_ON_EVENT_CONFLICT = (
    " ON CONFLICT (namespace, event_id) WHERE event_id IS NOT NULL DO NOTHING"
)

# Replicas start concurrently; serialize the idempotent DDL so two of them
# don't race on CREATE TABLE IF NOT EXISTS (pg_type uniqueness errors).
_SCHEMA_LOCK_ID = 0x4C4F4F4D  # "LOOMCTX"
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
        self._ticks: dict[str, int] = {}   # tick-scan calls per mark (R-9)
        size = pool_size or int(os.environ.get("LOOMCTX_DB_POOL", "") or self._DEFAULT_POOL)

        def pool(url: str) -> ConnectionPool:
            # Postgres may still be starting when a replica boots (k8s and
            # compose ordering are best-effort): wait for a bounded time
            # instead of crash-looping — the same courtesy the NATS clients
            # extend. check= drops connections the server closed.
            # connect_timeout + TCP keepalives (D-043): during a Postgres
            # failover the primary's address vanishes; without these a new
            # connection hangs in TCP for ~2 minutes and a held one waits
            # for the kernel — the operator promoted a replica in 11 s.
            p = ConnectionPool(url, min_size=1, max_size=max(1, size), open=False,
                               kwargs={"row_factory": dict_row, "connect_timeout": 5,
                                       "keepalives": 1, "keepalives_idle": 15,
                                       "keepalives_interval": 5, "keepalives_count": 3},
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
        """True when no DDL is needed: the database is at this build's
        version — or a newer one (an older image opening a newer database
        serves what it understands, runs no DDL and never writes the
        version down, H-B12)."""
        try:
            with self._tx(read=False):
                rows = self._q("SELECT value FROM loomctx_meta WHERE key = 'schema_version'")
        except Exception:  # noqa: BLE001 — no loomctx_meta yet: a fresh database
            return False
        if not rows:
            return False
        current = int(rows[0]["value"])
        if current > SCHEMA_VERSION:
            log.warning("postgres: schema version %d is newer than this build's %d;"
                        " running without migrations — upgrade the image", current, SCHEMA_VERSION)
        return current >= SCHEMA_VERSION

    @property
    def _conn(self):
        """The connection this thread borrowed in `_tx()`."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            raise RuntimeError("store used outside a _tx() block")
        return conn

    # ------------------------------------------------- vector index (D-025)

    _iterative_scan = False   # pgvector >= 0.8: hnsw.iterative_scan exists

    def _load_vec(self) -> bool:
        try:
            with self._tx():
                self._x("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK_ID,))
                self._x("CREATE EXTENSION IF NOT EXISTS vector")
                rows = self._q("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
        except self._psycopg.Error as exc:
            logging.getLogger("loomctx.store").info(
                "pgvector unavailable (%s): vector search uses exact scans", exc)
            return False
        try:
            major, minor = (int(x) for x in rows[0]["extversion"].split(".")[:2])
            self._iterative_scan = (major, minor) >= (0, 8)
        except (IndexError, ValueError, KeyError):  # unparseable version: stay conservative
            self._iterative_scan = False
        return True

    def _tune_hnsw(self, limit: int) -> None:
        """HNSW post-filters WHERE namespace = ...: with the default
        ef_search (40) every candidate can come from the majority tenant
        and a small namespace gets a short or empty answer. Widen the
        candidate set per query (SET LOCAL: this transaction only) and,
        on pgvector >= 0.8, let the scan keep going until the filter is
        satisfied. Callers still fall back to an exact scan when the index
        returns fewer than `limit` rows."""
        self._x(f"SET LOCAL hnsw.ef_search = {min(1000, max(limit * 4, 100))}")
        if self._iterative_scan:
            self._x("SET LOCAL hnsw.iterative_scan = 'relaxed_order'")

    def vector_backend(self) -> str:
        return "pgvector" if self._vec else "exact"

    def _refresh_vec_tables(self) -> None:
        for row in self._q("SELECT key, value FROM loomctx_meta WHERE key LIKE 'vec:%%'"):
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
            self._x("INSERT INTO loomctx_meta (key, value) VALUES (%s, %s)"
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
                self._tune_hnsw(limit)
                rows = self._q(
                    f"SELECT ref_id, 1 - (embedding <=> %s::vector) AS score FROM {name} v"
                    " WHERE namespace = %s AND NOT EXISTS"
                    "   (SELECT 1 FROM tombstones t WHERE t.observation_id = v.ref_id)"
                    " ORDER BY embedding <=> %s::vector LIMIT %s",
                    (self._vlit(query), namespace, self._vlit(query), limit))
                hits = sorted(((r["ref_id"], float(r["score"])) for r in rows), key=lambda h: -h[1])
                if len(hits) >= limit:
                    return hits
                # the post-filter starved the index: scan exactly, like the SQLite store
            rows = self._q(
                "SELECT e.ref_id, e.vector FROM embeddings e"
                " WHERE e.namespace = %s AND e.model = %s AND NOT EXISTS"
                "   (SELECT 1 FROM tombstones t WHERE t.observation_id = e.ref_id)",
                (namespace, model))
            scored = common.cosines(query, {r["ref_id"]: common.unpack_array(r["vector"]) for r in rows})
        return common.top_k(scored, limit)

    def nearest_chunks(
        self, namespace: str, model: str, query: list[float], limit: int = 20,
        artifact_ids: list[str] | None = None,
    ) -> list[tuple[dict, float]]:
        if artifact_ids is not None and not artifact_ids:
            return []
        name = common.vec_table("vchk", model, len(query))
        with self._tx(read=True):
            best: list[tuple[str, float]] = []
            indexed = self._has_index(name)
            if indexed:
                sql = (f"SELECT ref_id, 1 - (embedding <=> %s::vector) AS score FROM {name}"
                       " WHERE namespace = %s")
                params: tuple = (self._vlit(query), namespace)
                if artifact_ids is not None:
                    # Restricted to the cited documents (D-058): an exact
                    # distance sort over their rows, fetched through the
                    # (namespace, artifact_id) index — `+ 0` keeps the
                    # planner off the HNSW order, whose post-filter starved
                    # on nearly every ask and fell through to decoding every
                    # chunk of every cited artifact in Python.
                    sql += " AND artifact_id = ANY(%s) ORDER BY (embedding <=> %s::vector) + 0 LIMIT %s"
                    params += (list(artifact_ids), self._vlit(query), limit)
                else:
                    self._tune_hnsw(limit)
                    sql += " ORDER BY embedding <=> %s::vector LIMIT %s"
                    params += (self._vlit(query), limit)
                best = sorted(((r["ref_id"], float(r["score"])) for r in self._q(sql, params)),
                              key=lambda h: -h[1])
            # short of `limit`: fewer chunks exist (done), or there is no
            # index / it lags the chunk table the worker backfills it from
            if len(best) < limit and (not indexed or artifact_ids is None
                                      or self._chunk_count(namespace, model, artifact_ids) > len(best)):
                sql = "SELECT id, vector FROM doc_chunks WHERE namespace = %s AND model = %s"
                params = (namespace, model)
                if artifact_ids is not None:
                    sql += " AND artifact_id = ANY(%s)"
                    params += (list(artifact_ids),)
                rows = self._q(sql, params)
                best = common.top_k(
                    common.cosines(query, {r["id"]: common.unpack_array(r["vector"]) for r in rows}), limit)
            if not best:
                return []
            rows = self._q(
                "SELECT c.id, c.artifact_id, c.seq, c.span_start, c.span_end,"
                " c.text, c.vector, a.source, a.observed_at"
                " FROM doc_chunks c JOIN artifacts a ON a.id = c.artifact_id"
                " WHERE c.id = ANY(%s)", ([cid for cid, _ in best],))
        by_id = {r["id"]: common.row_to_chunk(r) for r in rows}
        return [(by_id[cid], s) for cid, s in best if cid in by_id]

    def _chunk_count(self, namespace: str, model: str, artifact_ids: list[str]) -> int:
        return int(self._q(
            "SELECT COUNT(*) AS n FROM doc_chunks WHERE namespace = %s AND model = %s"
            " AND artifact_id = ANY(%s)", (namespace, model, list(artifact_ids)))[0]["n"])

    def ensure_vector_index(self, model: str) -> dict:
        out = {"backend": self.vector_backend(), "observations": 0, "chunks": 0}
        if not self._vec:
            return out
        # anti-join in SQL, streamed in chunks, skipped when counts match —
        # the set-diff-in-Python version OOM-killed the worker on GKE (D-043)
        with self._tx():
            self._refresh_vec_tables()
            for kind, key, table, id_col, art_col in (
                ("vobs", "observations", "embeddings", "ref_id", "NULL"),
                ("vchk", "chunks", "doc_chunks", "id", "artifact_id"),
            ):
                vec_tables = common.vec_tables_for(kind, model, self._vec_tables)   # this model only
                total = self._q(f"SELECT COUNT(*) AS n FROM {table} WHERE model = %s", (model,))[0]["n"]
                indexed = sum(self._q(f"SELECT COUNT(*) AS n FROM {n}")[0]["n"] for n in vec_tables)
                if total <= indexed:
                    continue
                not_in = " AND ".join(f"NOT EXISTS (SELECT 1 FROM {n} v WHERE v.ref_id = t.{id_col})"
                                      for n in vec_tables) or "TRUE"
                last = ""
                while True:
                    rows = self._q(
                        f"SELECT t.{id_col} AS id, t.namespace, {art_col} AS artifact_id, t.vector"
                        f" FROM {table} t WHERE t.model = %s AND t.{id_col} > %s AND {not_in}"
                        f" ORDER BY t.{id_col} LIMIT 1000", (model, last))
                    if not rows:
                        break
                    by_ns: dict[str, list] = {}
                    for r in rows:
                        by_ns.setdefault(r["namespace"], []).append(
                            (r["id"], r["artifact_id"], common.unpack_vector(r["vector"])))
                    for ns, batch in by_ns.items():
                        out[key] += self._vec_upsert(kind, model, ns, batch)
                    last = rows[-1]["id"]
        return out

    def observations_by_ids(self, namespace: str, ids: list[str]) -> list[Observation]:
        if not ids:
            return []
        with self._tx(read=True):
            rows = self._q(
                _OBS_SELECT + " WHERE o.namespace = %s AND o.id = ANY(%s)" + _NOT_TOMBSTONED,
                (namespace, list(ids)))
        return [common.row_to_observation(r) for r in rows]

    def superseded_ids(self, namespace: str, ids: list[str]) -> set[str]:
        if not ids:
            return set()
        with self._tx(read=True):
            rows = self._q(
                "SELECT DISTINCT o.supersedes AS sid FROM observations o"
                " WHERE o.namespace = %s AND o.supersedes = ANY(%s)" + _NOT_TOMBSTONED,
                (namespace, list(ids)))
        return {r["sid"] for r in rows}

    def corrections_of(
        self, namespace: str, ids: list[str], observed_before: datetime | None = None,
    ) -> list[Observation]:
        if not ids:
            return []
        before_sql, before_args = _observed_before("%s", observed_before)
        with self._tx(read=True):
            rows = self._q(
                _OBS_SELECT + " WHERE o.namespace = %s AND o.supersedes = ANY(%s)"
                + _NOT_TOMBSTONED + before_sql, (namespace, list(ids), *before_args))
        return [common.row_to_observation(r) for r in rows]

    def resolve_refs(
        self, namespace: str, refs: list[EntityRef],
    ) -> dict[tuple[str, str], EntityRef]:
        out: dict[tuple[str, str], EntityRef] = {}
        if not refs:
            return out
        with self._tx(read=True):
            owners = self._resolve_many(namespace, refs)
            if not owners:
                return out
            rows = self._q("SELECT id, type, key FROM entities WHERE id = ANY(%s)", (list(owners),))
        for r in rows:
            canonical = EntityRef(type=r["type"], key=r["key"])
            for ref in owners[r["id"]]:
                out[(ref.type, ref.key)] = canonical
        return out

    _PREFIX_CAP = 20

    def observations_by_prefix(self, namespace: str, prefix: str) -> list[Observation]:
        if not prefix:
            return []
        lo, hi = common.prefix_bounds(prefix)
        with self._tx(read=True):
            # byte-wise operators + the text_pattern_ops index: the database's
            # collation (en_US in the stock image) would otherwise order
            # punctuation differently from SQLite's BINARY range
            rows = self._q(
                _OBS_SELECT + " WHERE o.namespace = %s AND o.id ~>=~ %s"
                + (" AND o.id ~<~ %s" if hi is not None else "") + _NOT_TOMBSTONED
                + " ORDER BY o.id COLLATE \"C\" LIMIT %s",
                (namespace, lo, *((hi,) if hi is not None else ()), self._PREFIX_CAP))
        return [common.row_to_observation(r) for r in rows]

    def refresh_statistics(self) -> None:
        """ANALYZE the two big tables: a bulk load's rows are planned blind
        until autovacuum next analyzes them (D-081)."""
        with self._tx():
            self._x("ANALYZE observations")
            self._x("ANALYZE entities")

    def _migrate(self, cur) -> None:
        """One-shot versioned steps (H-B12); idempotent DDL lives in _SCHEMA."""
        cur.execute("SELECT value FROM loomctx_meta WHERE key = 'schema_version'")
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
        if current < 5:
            # v5: numeric keys keep their punctuation in norm_key; recompute
            # the rows that can differ, in Python, where the rule lives.
            cur.execute("SELECT id, key, norm_key FROM entities WHERE key ~ '[.:/-]'")
            changed = [(nk, r["id"]) for r in cur.fetchall()
                       if (nk := common.norm_key(r["key"])) != r["norm_key"]]
            if changed:
                cur.executemany("UPDATE entities SET norm_key = %s WHERE id = %s", changed)
        if current < 6:
            # v6: colon-structured hex keys keep their separators (see common.norm_key)
            cur.execute("SELECT id, key, norm_key FROM entities WHERE position(':' in key) > 0")
            changed = [(nk, r["id"]) for r in cur.fetchall()
                       if (nk := common.norm_key(r["key"])) != r["norm_key"]]
            if changed:
                cur.executemany("UPDATE entities SET norm_key = %s WHERE id = %s", changed)
        if current < SCHEMA_VERSION:   # never written down (H-B12)
            cur.execute(
                "INSERT INTO loomctx_meta (key, value) VALUES ('schema_version', %s)"
                " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                (str(SCHEMA_VERSION),))

    def schema_version(self) -> int:
        with self._tx(read=True):
            rows = self._q("SELECT value FROM loomctx_meta WHERE key = 'schema_version'")
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
        pool when LOOMCTX_DB_READ is set. Nested calls share the outer
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
            target = self._resolve_entity(namespace, into)   # `into` may itself be an alias by now
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
            self._log_merge(namespace, src, dst)
            self._x("UPDATE observations SET subject_id = %s WHERE namespace = %s AND subject_id = %s",
                    (dst.id, namespace, src.id))
            self._x("UPDATE observations SET object_entity_id = %s, object_json = %s"
                    " WHERE namespace = %s AND object_entity_id = %s",
                    (dst.id, json.dumps({"type": dst.type, "key": dst.key}), namespace, src.id))
            self._x("UPDATE aliases SET entity_id = %s WHERE namespace = %s AND entity_id = %s",
                    (dst.id, namespace, src.id))
            self._put_alias(namespace, f"{src.type}:{src.key}", dst.id)
            self._x("DELETE FROM dossiers WHERE namespace = %s AND entity_id IN (%s, %s)",
                    (namespace, src.id, dst.id))
            self._x("DELETE FROM entities WHERE id = %s", (src.id,))
            self._hwm_reset(self._DOSSIER_HWM)
            return True

    def _log_merge(self, namespace: str, src: Entity, dst: Entity) -> None:
        """What merge_entities is about to change, so unmerge can put it
        back (D-019: reversible & lossless); see sqlite.py."""
        touched = self._q(
            "SELECT id, subject_id, object_entity_id, object_json FROM observations"
            " WHERE namespace = %s AND subject_id = %s"
            " UNION SELECT id, subject_id, object_entity_id, object_json FROM observations"
            " WHERE namespace = %s AND object_entity_id = %s",
            (namespace, src.id, namespace, src.id))
        aliases = [r["alias"] for r in self._q(
            "SELECT alias FROM aliases WHERE namespace = %s AND entity_id = %s", (namespace, src.id))]
        merge_id = uuid.uuid4().hex
        self._x(
            "INSERT INTO merge_log (id, namespace, from_type, from_key, into_type, into_key,"
            " from_id, from_provisional, from_created_at, prior_aliases_json, recorded_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (merge_id, namespace, src.type, src.key, dst.type, dst.key, src.id,
             bool(src.provisional), common.iso(src.created_at), json.dumps(aliases),
             common.iso(common.now())))
        if touched:
            with self._conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO merge_log_observations (merge_id, observation_id, prior_subject_id,"
                    " prior_object_entity_id, prior_object_json) VALUES (%s, %s, %s, %s, %s)",
                    [(merge_id, r["id"],
                      src.id if r["subject_id"] == src.id else None,
                      src.id if r["object_entity_id"] == src.id else None,
                      r["object_json"] if r["object_entity_id"] == src.id else None)
                     for r in touched])

    def unmerge(self, namespace: str, alias: EntityRef) -> bool:
        with self._tx():
            rows = self._q(
                "SELECT * FROM merge_log WHERE namespace = %s AND from_type = %s AND from_key = %s"
                " ORDER BY recorded_at DESC, id DESC LIMIT 1",
                (namespace, alias.type, alias.key))
            if not rows:
                return False
            m = rows[0]
            from_ref = EntityRef(type=m["from_type"], key=m["from_key"])
            self._x(
                "INSERT INTO entities (id, namespace, type, key, provisional, created_at, norm_key)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (m["from_id"], namespace, from_ref.type, from_ref.key,
                 bool(m["from_provisional"]), m["from_created_at"], common.norm_key(from_ref.key)))
            src = self._get_entity(namespace, from_ref) or self._upsert_entity(namespace, from_ref)
            # only rows still on the merge target move back (chained merges;
            # see sqlite.py)
            dst = self._resolve_entity(namespace, EntityRef(type=m["into_type"], key=m["into_key"]))
            hold = dst.id if dst else None
            moved = self._q("SELECT * FROM merge_log_observations WHERE merge_id = %s", (m["id"],))
            with self._conn.cursor() as cur:
                subj = [(src.id, r["observation_id"], hold, hold)
                        for r in moved if r["prior_subject_id"] is not None]
                if subj:
                    cur.executemany("UPDATE observations SET subject_id = %s WHERE id = %s"
                                    " AND (%s::text IS NULL OR subject_id = %s)", subj)
                obj = [(src.id, r["prior_object_json"] or json.dumps({"type": src.type, "key": src.key}),
                        r["observation_id"], hold, hold)
                       for r in moved if r["prior_object_entity_id"] is not None]
                if obj:
                    cur.executemany(
                        "UPDATE observations SET object_entity_id = %s, object_json = %s WHERE id = %s"
                        " AND (%s::text IS NULL OR object_entity_id = %s)", obj)
                back = [(src.id, namespace, a) for a in json.loads(m["prior_aliases_json"] or "[]")]
                if back:
                    cur.executemany(
                        "UPDATE aliases SET entity_id = %s WHERE namespace = %s AND alias = %s", back)
            self._x("DELETE FROM aliases WHERE namespace = %s AND alias = %s",
                    (namespace, f"{from_ref.type}:{from_ref.key}"))
            self._x("DELETE FROM dossiers WHERE namespace = %s AND entity_id IN (%s, %s)",
                    (namespace, src.id, dst.id if dst else src.id))
            self._x("DELETE FROM merge_log_observations WHERE merge_id = %s", (m["id"],))
            self._x("DELETE FROM merge_log WHERE id = %s", (m["id"],))
            self._hwm_reset(self._DOSSIER_HWM)
            return True

    def iter_merges(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx():
            parents = self._q(
                "SELECT * FROM merge_log" + (" WHERE namespace = %s" if namespace else "")
                + " ORDER BY recorded_at, id", (namespace,) if namespace else ())
            records = []
            for m in parents:
                kids = self._q("SELECT * FROM merge_log_observations WHERE merge_id = %s"
                               " ORDER BY observation_id", (m["id"],))
                records.append(common.merge_record(m, kids))
        yield from records

    def restore_merge(self, record: dict) -> None:
        parent, children = common.merge_rows(record)
        with self._tx():
            self._x(
                "INSERT INTO merge_log (id, namespace, from_type, from_key, into_type,"
                " into_key, from_id, from_provisional, from_created_at, prior_aliases_json,"
                " recorded_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (id) DO NOTHING", parent)
            if children:
                with self._conn.cursor() as cur:
                    cur.executemany(
                        "INSERT INTO merge_log_observations (merge_id, observation_id,"
                        " prior_subject_id, prior_object_entity_id, prior_object_json)"
                        " VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING", children)

    def shared_identifier_groups(self, namespace, since=None, limit=200, predicate="identified_by",
                                 kinds=None):
        """Identifier entities pointed at by two or more distinct entities,
        among those an edge recorded after `since` touched; tombstoned edges
        do not count; `kinds` keeps identifiers keyed `<kind>:...` (D-083).
        Stepwise, each step on an index, never one planner-dependent join:
        a combined query ran 87 min on a freshly loaded namespace (S-63)."""
        live = "NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.observation_id = o.id)"
        with self._tx(read=True):
            if since is not None:
                touched = {r["object_entity_id"] for r in self._q(
                    "SELECT DISTINCT object_entity_id FROM observations"
                    " WHERE recorded_at > {p} AND namespace = {p} AND predicate = {p}"
                    " AND object_entity_id IS NOT NULL".format(p='%s'),
                    (common.iso(since), namespace, predicate))}
            else:
                touched = {r["object_entity_id"] for r in self._q(
                    "SELECT DISTINCT object_entity_id FROM observations"
                    " WHERE namespace = {p} AND predicate = {p} AND object_entity_id IS NOT NULL".format(p='%s'),
                    (namespace, predicate))}
            ids = sorted(touched)
            holders: dict[str, set[str]] = {}
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                marks = ",".join(['%s'] * len(chunk))
                for r in self._q(
                        "SELECT o.object_entity_id AS ident, o.subject_id FROM observations o"
                        " WHERE o.object_entity_id IN (" + marks + ") AND o.namespace = {p}"
                        " AND o.predicate = {p} AND ".format(p='%s') + live,
                        (*chunk, namespace, predicate)):
                    holders.setdefault(r["ident"], set()).add(r["subject_id"])
            multi = sorted(i for i, subs in holders.items() if len(subs) > 1)
            rows: dict[str, Entity] = {}
            wanted = {f"{k}:" for k in kinds} if kinds else None
            out = []
            for start in range(0, len(multi), 500):
                chunk = multi[start:start + 500]
                marks = ",".join(['%s'] * len(chunk))
                idents = {r["id"]: common.row_to_entity(r) for r in self._q(
                    "SELECT * FROM entities WHERE id IN (" + marks + ")", tuple(chunk))}
                keep = [i for i in chunk if i in idents and (
                    wanted is None or any(idents[i].key.startswith(w) for w in wanted))]
                subjects = sorted({s for i in keep for s in holders[i]} - set(rows))
                for s_start in range(0, len(subjects), 500):
                    s_chunk = subjects[s_start:s_start + 500]
                    s_marks = ",".join(['%s'] * len(s_chunk))
                    for r in self._q("SELECT * FROM entities WHERE id IN (" + s_marks + ")", tuple(s_chunk)):
                        rows[r["id"]] = common.row_to_entity(r)
                for i in keep:
                    members = sorted((rows[s] for s in holders[i] if s in rows), key=lambda e: (e.type, e.key))
                    if len(members) > 1:
                        out.append((idents[i], members))
                    if len(out) >= limit:
                        return out
        return out

    def rank_facts(self, namespace, refs):
        """One query per chunk (S-63): each entity's structured and total
        observation counts, subject and object side, and its creation time."""
        out = {}
        uniq = list({(r.type, r.key): r for r in refs}.values())
        doc = "o.source LIKE 'doc:%%' OR o.attrs_json LIKE '%%\"extracted\": true%%'"
        for start in range(0, len(uniq), 400):
            chunk = uniq[start:start + 400]
            pairs = " OR ".join(["(type = {p} AND key = {p})"] * len(chunk))
            sql = ("WITH e AS (SELECT id, type, key, created_at FROM entities"
                   " WHERE namespace = {p} AND (" + pairs + "))"
                   " SELECT e.type, e.key, e.created_at,"
                   " (SELECT count(*) FROM observations o WHERE o.subject_id = e.id) AS s_all,"
                   " (SELECT count(*) FROM observations o WHERE o.subject_id = e.id AND (" + doc + ")) AS s_doc,"
                   " (SELECT count(*) FROM observations o WHERE o.object_entity_id = e.id) AS o_all,"
                   " (SELECT count(*) FROM observations o WHERE o.object_entity_id = e.id AND (" + doc + ")) AS o_doc"
                   " FROM e")
            args = [namespace, *(x for r in chunk for x in (r.type, r.key))]
            with self._tx(read=True):
                rows = self._q(sql.format(p="%s"), tuple(args))
            for r in rows:
                total = int(r["s_all"]) + int(r["o_all"])
                structured = total - int(r["s_doc"]) - int(r["o_doc"])
                out[(r["type"], r["key"])] = (structured, total, common.parse(r["created_at"]))
        return out

    def fuzzy_merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        with self._tx():
            # a group every differing pair of which was declined is settled
            # and must not occupy the limit (S-26; see sqlite.py). Grouped
            # first, then the pair/decline test inside each group only.
            side = "(e{n}.type || ':' || e{n}.key) COLLATE \"C\""
            s1, s2 = side.format(n=1), side.format(n=2)
            rows = self._q(
                "WITH multi AS (SELECT namespace, norm_key FROM entities"
                " WHERE norm_key <> ''" + (" AND namespace = %s" if namespace else "")
                + " GROUP BY namespace, norm_key HAVING COUNT(DISTINCT key) > 1)"
                " SELECT m.namespace, m.norm_key FROM multi m WHERE EXISTS ("
                "  SELECT 1 FROM entities e1 JOIN entities e2"
                "   ON e2.namespace = e1.namespace AND e2.norm_key = e1.norm_key"
                "   AND e2.key <> e1.key"
                "  WHERE e1.namespace = m.namespace AND e1.norm_key = m.norm_key"
                "  AND NOT EXISTS (SELECT 1 FROM resolution_declines d"
                "   WHERE d.namespace = e1.namespace"
                f"    AND d.a = LEAST({s1}, {s2}) AND d.b = GREATEST({s1}, {s2})))"
                " ORDER BY m.namespace, m.norm_key LIMIT %s",
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

    def iter_schemas(self, namespace: str | None = None) -> Iterator[SchemaRegistration]:
        with self._tx(read=True):
            rows = self._q(
                "SELECT registration_json FROM schemas"
                + (" WHERE namespace = %s" if namespace else "") + " ORDER BY namespace",
                (namespace,) if namespace else ())
        for r in rows:
            yield common.row_to_schema(r)

    def merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        with self._tx():
            # fully declined groups are settled and must not occupy the
            # limit (D-058; see sqlite.py). Declines store the pair sorted
            # by code point, hence the "C" collation in the comparison.
            side = "(e{n}.type || ':' || e{n}.key) COLLATE \"C\""
            s1, s2 = side.format(n=1), side.format(n=2)
            rows = self._q(
                "SELECT DISTINCT e1.namespace, e1.key FROM entities e1"
                " JOIN entities e2 ON e2.namespace = e1.namespace AND e2.key = e1.key"
                "  AND e2.type <> e1.type"
                " WHERE TRUE" + (" AND e1.namespace = %s" if namespace else "")
                + " AND NOT EXISTS (SELECT 1 FROM resolution_declines d"
                "   WHERE d.namespace = e1.namespace"
                f"    AND d.a = LEAST({s1}, {s2}) AND d.b = GREATEST({s1}, {s2}))"
                " ORDER BY e1.namespace, e1.key LIMIT %s",
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
        labels: tuple[str, ...] = (),
    ) -> list[Entity]:
        lowered = query.lower()
        type_sql, type_args = "", ()
        if types is not None:
            type_sql, type_args = " AND type = ANY(%s)", (list(types),)
        with self._tx(read=True):
            rows = self._q(
                _SEARCH_SQL + type_sql + " ORDER BY (lower(key) <> %s), type, key LIMIT %s",
                (namespace, lowered, lowered + _PREFIX_END, *type_args, lowered, limit),
            )
            label_rows = []
            if labels and lowered:
                exact = json.dumps(lowered)                 # '"domain admins"', as stored lower-cased
                start = exact[:-1]
                label_rows = self._q(
                    _LABEL_SQL + type_sql.replace("type =", "e.type =")
                    + " GROUP BY e.id ORDER BY inexact, e.type, e.key LIMIT %s",
                    (exact, namespace, list(labels), start, start + _PREFIX_END, *type_args, limit),
                )
        return common.merge_search(rows, label_rows, lowered, limit)

    def count_observations(
        self, namespace: str, ref: EntityRef, observed_before: datetime | None = None,
        allowed_types: tuple[str, ...] | None = None,
    ) -> int:
        with self._tx(read=True):
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return 0
            before_sql, before_args = _observed_before("%s", observed_before)
            # a type-scoped caller's count: the far end of each half must be
            # in its types too (see sqlite.py)
            subj_types, obj_types, type_args = "", "", ()
            if allowed_types is not None:
                if not allowed_types:
                    return 0
                subj_types = (" AND (o.object_entity_id IS NULL OR EXISTS (SELECT 1 FROM entities x"
                              " WHERE x.id = o.object_entity_id AND x.type = ANY(%s)))")
                obj_types = " AND EXISTS (SELECT 1 FROM entities x WHERE x.id = o.subject_id AND x.type = ANY(%s))"
                type_args = (list(allowed_types),)
            rows = self._q(
                "SELECT (SELECT COUNT(*) FROM observations o WHERE o.namespace = %s"
                "          AND o.subject_id = %s" + _NOT_TOMBSTONED + before_sql + subj_types + ")"
                "     + (SELECT COUNT(*) FROM observations o WHERE o.namespace = %s"
                "          AND o.object_entity_id = %s AND o.subject_id <> %s" + _NOT_TOMBSTONED
                + before_sql + obj_types + ")"
                " AS n",
                (namespace, entity.id, *before_args, *type_args,
                 namespace, entity.id, entity.id, *before_args, *type_args),
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
            # the per-artifact cut happens in SQL (see sqlite.py)
            rows = self._q(
                "WITH cited AS ("
                " SELECT DISTINCT (o.provenance_json::jsonb ->> 'artifact_id') AS aid,"
                " s.type AS stype, s.key AS skey"
                " FROM observations o JOIN entities s ON s.id = o.subject_id"
                " LEFT JOIN entities ob ON ob.id = o.object_entity_id"
                " WHERE o.namespace = %s"
                "   AND (o.provenance_json::jsonb ->> 'artifact_id') = ANY(%s)"
                + _NOT_TOMBSTONED + type_sql + "),"
                " ranked AS (SELECT *, row_number() OVER (PARTITION BY aid ORDER BY stype, skey) AS rn"
                "            FROM cited)"
                " SELECT aid, stype, skey FROM ranked WHERE rn <= %s ORDER BY aid, stype, skey",
                (namespace, list(artifact_ids), *type_args, per_artifact),
            )
        out: dict[str, list[EntityRef]] = {}
        for r in rows:
            out.setdefault(r["aid"], []).append(EntityRef(type=r["stype"], key=r["skey"]))
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
        self, namespace: str, ref: EntityRef, limit: int = 100,
        observed_before: datetime | None = None,
    ) -> list[Observation]:
        with self._tx(read=True):
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return []
            before_sql, before_args = _observed_before("%s", observed_before)
            # same two-index UNION as the SQLite store (D-035): a per-side
            # index range each, never a namespace scan; the as_of bound
            # rides the same index (D-046)
            rows = self._q(
                "SELECT * FROM (" + _OBS_SELECT
                + " WHERE o.namespace = %s AND o.subject_id = %s" + _NOT_TOMBSTONED + before_sql
                + " ORDER BY o.observed_at DESC LIMIT %s) s"
                " UNION ALL SELECT * FROM (" + _OBS_SELECT
                + " WHERE o.namespace = %s AND o.object_entity_id = %s"
                "   AND o.subject_id <> %s" + _NOT_TOMBSTONED + before_sql
                + " ORDER BY o.observed_at DESC LIMIT %s) t"
                " ORDER BY observed_at DESC LIMIT %s",
                (namespace, entity.id, *before_args, limit,
                 namespace, entity.id, entity.id, *before_args, limit, limit),
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

    def _many_query(self, namespace: str, ids: list[str], limit: int,
                    observed_before: datetime | None,
                    predicates: list[str] | None = None) -> tuple[str, tuple]:
        """The `hits` body of the batched gather and its parameters: a
        LATERAL per side, so every entity contributes its newest `limit`
        rows of each side from its own index range instead of every edge
        (R-9; see sqlite.py). The as_of bound rides each range (D-046), and
        so does a predicate filter (D-061)."""
        before_sql, before_args = _observed_before("%s", observed_before)
        pred_sql, pred_args = "", ()
        if predicates is not None:
            pred_sql, pred_args = " AND o.predicate = ANY(%s)", (list(predicates),)
        sql = (
            "SELECT s.* FROM unnest(%s::text[]) AS ids(eid) CROSS JOIN LATERAL ("
            + _OBS_SELECT_ENT.format(ent="o.subject_id")
            + " WHERE o.namespace = %s AND o.subject_id = ids.eid" + _NOT_TOMBSTONED + before_sql
            + pred_sql + " ORDER BY o.observed_at DESC LIMIT %s) s"
            " UNION ALL "
            "SELECT t.* FROM unnest(%s::text[]) AS ids(eid) CROSS JOIN LATERAL ("
            + _OBS_SELECT_ENT.format(ent="o.object_entity_id")
            + " WHERE o.namespace = %s AND o.object_entity_id = ids.eid AND o.subject_id <> ids.eid"
            + _NOT_TOMBSTONED + before_sql + pred_sql
            + " ORDER BY o.observed_at DESC LIMIT %s) t"
        )
        return sql, (list(ids), namespace, *before_args, *pred_args, limit,
                     list(ids), namespace, *before_args, *pred_args, limit)

    def observations_for_many(
        self, namespace: str, refs: list[EntityRef], limit: int = 100,
        observed_before: datetime | None = None,
        predicates: list[str] | None = None,
    ) -> dict[tuple[str, str], list[Observation]]:
        result: dict[tuple[str, str], list[Observation]] = {}
        if not refs or (predicates is not None and not predicates):
            return result
        with self._tx(read=True):
            owners = self._resolve_many(namespace, refs)
            ids = list(owners)
            for start in range(0, len(ids), self._MANY_CHUNK):
                chunk = ids[start:start + self._MANY_CHUNK]
                hits, params = self._many_query(namespace, chunk, limit, observed_before, predicates)
                rows = self._q(
                    "WITH hits AS (" + hits + "),"
                    " ranked AS (SELECT *, row_number() OVER (PARTITION BY ent ORDER BY observed_at DESC) AS rn FROM hits)"
                    " SELECT * FROM ranked WHERE rn <= %s ORDER BY ent, observed_at DESC",
                    (*params, limit),
                )
                for row in rows:
                    obs = common.row_to_observation(row)
                    for ref in owners[row["ent"]]:
                        result.setdefault((ref.type, ref.key), []).append(obs)
        return result

    def edges_to_carriers(
        self, namespace: str, hubs: list[EntityRef], via: list[str], predicates: list[str],
        limit: int = 10_000, observed_before: datetime | None = None,
    ) -> list[tuple[tuple[str, str], str, str]]:
        """One join per hub side (D-061; see sqlite.py): the hub's newest
        `limit` edges on `via` from its own index range, each far end's rows
        on `predicates` from the subject index. Only id pairs come back."""
        out: list[tuple[tuple[str, str], str, str]] = []
        if not hubs or not via or not predicates:
            return out
        with self._tx(read=True):
            owners = self._resolve_many(namespace, hubs)
            for eid, refs in owners.items():
                rows: list = []
                for inbound in (True, False):
                    rows += self._q(*self._carriers_query(namespace, eid, inbound, via, predicates,
                                                          limit, observed_before))
                rows.sort(key=lambda r: (r["at"], r["edge_id"]), reverse=True)
                for ref in refs:
                    out.extend(((ref.type, ref.key), r["edge_id"], r["attr_id"]) for r in rows)
        return out

    @staticmethod
    def _carriers_query(namespace: str, eid: str, inbound: bool, via: list[str], predicates: list[str],
                        limit: int, observed_before: datetime | None) -> tuple[str, tuple]:
        """The join for one hub side: the hub's edges from their own index
        range, then — LATERAL, so the planner cannot hash the namespace's
        rows on the predicate instead — an index probe per far end."""
        before_sql, before_args = _observed_before("%s", observed_before)
        attr_before = before_sql.replace("o.observed_at", "a.observed_at")
        if inbound:
            where, far = "o.object_entity_id = %s AND o.subject_id <> %s", "o.subject_id"
        else:
            where, far = ("o.subject_id = %s AND o.object_entity_id IS NOT NULL AND o.object_entity_id <> %s",
                          "o.object_entity_id")
        sql = ("SELECT e.id AS edge_id, e.observed_at AS at, a.id AS attr_id FROM ("
               f"SELECT o.id, o.observed_at, {far} AS far FROM observations o"
               f" WHERE o.namespace = %s AND {where} AND o.predicate = ANY(%s)"
               + _NOT_TOMBSTONED + before_sql + " ORDER BY o.observed_at DESC LIMIT %s) e"
               " CROSS JOIN LATERAL (SELECT a.id FROM observations a"
               " WHERE a.namespace = %s AND a.subject_id = e.far"
               " AND a.predicate = ANY(%s) AND a.id <> e.id"
               " AND NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.observation_id = a.id)"
               + attr_before + ") a")
        return sql, (namespace, eid, eid, list(via), *before_args, limit,
                     namespace, list(predicates), *before_args)

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
        return {r["ref_id"]: common.unpack_array(r["vector"]) for r in rows}

    # hex value of the id's last character, 0..15: the shard key (D-031)
    _SHARD_EXPR = "(position(right(o.id, 1) in '0123456789abcdef') - 1)"

    def observations_without_embeddings(
        self, model: str, limit: int = 128, shard: tuple[int, int] | None = None
    ) -> list[Observation]:
        shard_sql, shard_args = "", ()
        if shard is not None and shard[1] > 1:
            shard_sql, shard_args = f" AND {self._SHARD_EXPR} %% %s = %s", (shard[1], shard[0])
        key = f"hwm:embed:{model}:{shard[0]}/{shard[1]}" if shard_sql else f"hwm:embed:{model}:0/1"
        with self._tx():
            start = self._hwm_start(key)
            rows = self._q(
                _EMBED_BACKLOG_SQL.format(shard=shard_sql),
                (start, model, *shard_args, limit),
            )
            self._hwm_advance(key, "observations", rows[0]["recorded_at"] if rows else None)
            return [common.row_to_observation(r) for r in rows]

    # tick-scan high-water marks (R-9): the semantics are documented in
    # sqlite.py; the marks live in loomctx_meta on the primary
    _HWM_SLACK = 1000
    _RESCAN_EVERY = 16

    def _hwm_start(self, key: str) -> str:
        n = self._ticks.get(key, 0)
        self._ticks[key] = n + 1
        if n % self._RESCAN_EVERY == 0:
            return ""
        rows = self._q("SELECT value FROM loomctx_meta WHERE key = %s", (key,))
        return rows[0]["value"] if rows else ""

    def _hwm_advance(self, key: str, table: str, top: str | None) -> None:
        if top is None:
            top = self._q(f"SELECT MAX(recorded_at) AS m FROM {table}")[0]["m"]
            if top is None:
                return
        rows = self._q(
            f"SELECT recorded_at FROM {table} WHERE recorded_at <= %s"
            " ORDER BY recorded_at DESC LIMIT 1 OFFSET %s", (top, self._HWM_SLACK))
        if not rows:
            return
        self._x("INSERT INTO loomctx_meta (key, value) VALUES (%s, %s)"
                " ON CONFLICT (key) DO UPDATE SET value = GREATEST(loomctx_meta.value, EXCLUDED.value)",
                (key, rows[0]["recorded_at"]))

    def _hwm_reset(self, key: str) -> None:
        self._x("DELETE FROM loomctx_meta WHERE key = %s", (key,))

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

    # lease ownership (D-031): see sqlite.py
    # a worker releases only its own lease; an unleased artifact has no owner (D-049)
    _OWNS_EXTRACT = " AND (%s::text IS NULL OR extract_claimed_by IS NULL OR extract_claimed_by = %s)"

    def defer_extraction(
        self, namespace: str, artifact_id: str, attempts: int, next_attempt_at: datetime,
        worker_id: str | None = None,
    ) -> bool:
        with self._tx():
            return self._x(
                "UPDATE artifacts SET extraction_attempts = %s, next_attempt_at = %s,"
                " extract_claimed_until = NULL WHERE namespace = %s AND id = %s" + self._OWNS_EXTRACT,
                (attempts, common.iso(next_attempt_at), namespace, artifact_id, worker_id, worker_id),
            ) > 0

    def set_extraction_status(
        self, namespace: str, artifact_id: str, status: str, worker_id: str | None = None,
    ) -> bool:
        with self._tx():
            return self._x(
                "UPDATE artifacts SET extraction_status = %s, extract_claimed_until = NULL"
                " WHERE namespace = %s AND id = %s" + self._OWNS_EXTRACT,
                (status, namespace, artifact_id, worker_id, worker_id),
            ) > 0

    def extend_extraction_lease(
        self, namespace: str, artifact_id: str, worker_id: str, seconds: float
    ) -> bool:
        with self._tx():
            return self._x(
                "UPDATE artifacts SET extract_claimed_until = %s WHERE namespace = %s AND id = %s"
                " AND extract_claimed_by = %s AND extraction_status = 'pending'",
                (common.iso(common.now() + timedelta(seconds=seconds)), namespace, artifact_id, worker_id),
            ) > 0

    _NEEDS_CHUNKS = (
        "a.recorded_at >= %s AND a.text IS NOT NULL"   # from the high-water mark (R-9)
        # blank docs would re-queue forever (H-D4); TRIM alone strips only
        # spaces, so name the whitespace set explicitly
        " AND BTRIM(a.text, E' \\t\\n\\r') <> ''"
        " AND NOT EXISTS (SELECT 1 FROM doc_chunks c"
        "   WHERE c.artifact_id = a.id AND c.model = %s)"
    )

    def artifacts_needing_chunks(
        self, model: str, limit: int = 4, lease: tuple[str, float] | None = None
    ) -> list[Artifact]:
        key = f"hwm:chunks:{model}"
        with self._tx():
            start = self._hwm_start(key)
            if lease is None:
                rows = self._q(
                    f"SELECT * FROM artifacts a WHERE {self._NEEDS_CHUNKS}"
                    " ORDER BY a.recorded_at LIMIT %s", (start, model, limit))
            else:
                moment = common.now()
                until = common.iso(moment + timedelta(seconds=lease[1]))
                rows = self._q(
                    "WITH picked AS MATERIALIZED"
                    f" (SELECT a.id FROM artifacts a WHERE {self._NEEDS_CHUNKS}"
                    "   AND (a.chunk_claimed_until IS NULL OR a.chunk_claimed_until < %s)"
                    "   ORDER BY a.recorded_at LIMIT %s FOR UPDATE SKIP LOCKED)"
                    " UPDATE artifacts a SET chunk_claimed_until = %s, chunk_claimed_by = %s"
                    " FROM picked WHERE a.id = picked.id RETURNING a.*",
                    (start, model, common.iso(moment), limit, until, lease[0]))
            self._hwm_advance(key, "artifacts", min((r["recorded_at"] for r in rows), default=None))
        return sorted((common.row_to_artifact(r) for r in rows), key=lambda a: a.recorded_at)

    def put_doc_chunks(
        self, namespace: str, artifact_id: str, model: str,
        chunks: list[tuple[int, int, int, str, list[float]]],
        worker_id: str | None = None,
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
            self._x("UPDATE artifacts SET chunk_claimed_until = NULL WHERE id = %s"
                    " AND (%s::text IS NULL OR chunk_claimed_by IS NULL OR chunk_claimed_by = %s)",
                    (artifact_id, worker_id, worker_id))

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
        worker_id: str | None = None,
    ) -> bool:
        with self._tx():
            entity = self._resolve_or_create(namespace, ref)
            if worker_id is not None:
                holder = self._q("SELECT dossier_claimed_by FROM entities WHERE id = %s", (entity.id,))
                if not holder or holder[0]["dossier_claimed_by"] not in (None, worker_id):
                    return False   # re-claimed by another worker: its brief is the one to land
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
            return True

    _DOSSIER_HWM = "hwm:dossier"

    def dossier_candidates(
        self, min_new: int = 20, min_total: int = 5, limit: int = 4,
        lease: tuple[str, float] | None = None,
    ) -> list[tuple[str, EntityRef, int]]:
        moment = common.now()
        with self._tx():
            # incremental over the entities touched since the mark (see
            # sqlite.py); the mark advances only on a tick that did not
            # fill its limit
            start = self._hwm_start(self._DOSSIER_HWM)
            rows = self._q(_DOSSIER_SQL, (start, common.iso(moment), min_total, min_new, limit))
            if len(rows) < limit:
                self._hwm_advance(self._DOSSIER_HWM, "observations", None)
            out = []
            for r in rows:
                if lease is not None:
                    claimed = self._x(
                        "UPDATE entities SET dossier_claimed_until = %s, dossier_claimed_by = %s WHERE id = %s"
                        " AND (dossier_claimed_until IS NULL OR dossier_claimed_until < %s)",
                        (common.iso(moment + timedelta(seconds=lease[1])), lease[0], r["eid"],
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
            self._drop_briefs_citing(namespace, observation_id)
            self._hwm_reset(self._DOSSIER_HWM)   # a dropped brief is rebuilt next tick
            return True

    def _drop_briefs_citing(self, namespace: str, observation_id: str) -> None:
        """A brief synthesized from a redacted observation may still be
        quoting it (H-D8) — on redact and on a restored tombstone (D-058)."""
        if self._x("DELETE FROM dossiers WHERE namespace = %s AND observation_ids LIKE %s",
                   (namespace, f'%"{observation_id}"%')):
            self._hwm_reset(self._DOSSIER_HWM)

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
            if self._vec:   # ANN rows whose source row is gone (see sqlite.py)
                self._refresh_vec_tables()
                for name in self._vec_tables:
                    source = "observations" if name.startswith("vobs_") else "doc_chunks"
                    self._x(f"DELETE FROM {name} v WHERE v.namespace = %s AND NOT EXISTS"
                            f" (SELECT 1 FROM {source} s WHERE s.id = v.ref_id)", (namespace,))
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

    def relation_summary(self, namespace: str) -> list[tuple[str, str, str | None, int]]:
        key = common.SUMMARY_KEY.format(namespace=namespace)
        with self._tx(read=True):
            m = self._q("SELECT (SELECT max(recorded_at) FROM observations)::text AS a,"
                        " (SELECT count(*) FROM tombstones) AS b, (SELECT count(*) FROM merge_log) AS c")[0]
            marker = f"{m['a']}|{m['b']}|{m['c']}"
            cached = self._q("SELECT value FROM loomctx_meta WHERE key = %s", (key,))
        hit = common.cached_summary(cached[0]["value"] if cached else None, marker)
        if hit is not None:
            return hit
        sql = ("SELECT s.type AS stype, o.predicate AS predicate, e.type AS otype, COUNT(*) AS n"
               " FROM observations o JOIN entities s ON s.id = o.subject_id"
               " LEFT JOIN entities e ON e.id = o.object_entity_id"
               " WHERE o.namespace = %s"
               " AND NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.observation_id = o.id)"
               " GROUP BY s.type, o.predicate, e.type")
        with self._tx(read=True):
            rows = self._q(sql, (namespace,))
        out = sorted(((r["stype"], r["predicate"], r["otype"], int(r["n"])) for r in rows),
                     key=lambda r: (-r[3], r[0], r[1], r[2] or ""))
        try:
            with self._tx():
                self._x("INSERT INTO loomctx_meta (key, value) VALUES (%s, %s)"
                        " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                        (key, common.summary_value(marker, out)))
        except Exception:  # noqa: BLE001 — a read replica still answers; it just can't remember
            pass
        return out

    def namespace_summary(self) -> dict[str, dict[str, int]]:
        with self._tx(read=True):
            rows = self._q("SELECT namespace, type, COUNT(*) AS n FROM entities"
                           " GROUP BY namespace, type ORDER BY namespace, type")
        out: dict[str, dict[str, int]] = {}
        for r in rows:
            out.setdefault(r["namespace"], {})[r["type"]] = int(r["n"])
        return out

    def iter_entities(
        self, namespace: str | None = None, since: datetime | None = None
    ) -> Iterator[Entity]:
        sql = ("SELECT * FROM entities WHERE 1=1" + (" AND namespace = %s" if namespace else "")
               + (" AND created_at >= %s" if since else ""))
        params = (*((namespace,) if namespace else ()), *((common.iso(since),) if since else ()))
        for row in self._pages(sql, params, ("created_at", "id")):
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

    def remember_decline(self, namespace: str, a: str, b: str, reason: str,
                         decided_at: datetime | None = None) -> None:
        a, b = sorted((a, b))
        with self._tx():
            self._x(
                "INSERT INTO resolution_declines (namespace, a, b, reason, decided_at)"
                " VALUES (%s, %s, %s, %s, %s) ON CONFLICT (namespace, a, b) DO UPDATE SET"
                " reason = EXCLUDED.reason, decided_at = EXCLUDED.decided_at",
                (namespace, a, b, reason[:500], common.iso(decided_at or common.now())))

    def forget_decline(self, namespace: str, a: str, b: str) -> bool:
        a, b = sorted((a, b))
        with self._tx():
            return self._x(
                "DELETE FROM resolution_declines WHERE namespace = %s AND a = %s AND b = %s",
                (namespace, a, b)) > 0

    def iter_declines(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx(read=True):
            rows = self._q(
                "SELECT * FROM resolution_declines"
                + (" WHERE namespace = %s" if namespace else "") + " ORDER BY namespace, a, b",
                (namespace,) if namespace else ())
        for r in rows:
            yield {"namespace": r["namespace"], "a": r["a"], "b": r["b"],
                   "reason": r["reason"], "decided_at": r["decided_at"]}

    def declined_pairs(self, namespace: str) -> set[tuple[str, str]]:
        with self._tx(read=True):
            rows = self._q("SELECT a, b FROM resolution_declines WHERE namespace = %s", (namespace,))
        return {(r["a"], r["b"]) for r in rows}

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
            subject = self._resolve_or_create(obs.namespace, obs.subject)
            object_entity_id = None
            if isinstance(obs.object, EntityRef):
                target = self._resolve_or_create(obs.namespace, obs.object)
                object_entity_id = target.id
                object_json = json.dumps({"type": target.type, "key": target.key})
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
            self._drop_briefs_citing(namespace, observation_id)

    def wipe(self) -> None:
        with self._tx():
            for table in ("tombstones", "embeddings", "dossiers", "doc_chunks",
                          "merge_log_observations", "merge_log", "observations",
                          "aliases", "artifacts", "entities", "schemas",
                          "resolution_declines", *self._vec_tables):
                self._x(f"DELETE FROM {table}")
            self._x("DELETE FROM loomctx_meta WHERE key LIKE 'hwm:%%'")
            self._ticks.clear()

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

    def _resolve_or_create(self, namespace: str, ref: EntityRef) -> Entity:
        """The entity a write should attach to: the exact node, else the
        canonical one an alias points at, else a new node."""
        return self._resolve_entity(namespace, ref) or self._upsert_entity(namespace, ref)

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

        # A ref that was merged away resolves to its canonical entity: a
        # claim naming the old `ip_address:10.0.4.7` lands on `ip:10.0.4.7`
        # instead of resurrecting the folded node beside its alias.
        subject = self._resolve_or_create(claim.namespace, claim.subject)
        object_entity_id = None
        obj = claim.object
        if isinstance(claim.object, EntityRef):
            target = self._resolve_or_create(claim.namespace, claim.object)
            object_entity_id = target.id
            obj = EntityRef(type=target.type, key=target.key)
            object_json = json.dumps(obj.model_dump())
        else:
            object_json = json.dumps(claim.object)

        obs = Observation(
            id=uuid.uuid4().hex,
            namespace=claim.namespace,
            event_id=claim.event_id,
            subject=EntityRef(type=subject.type, key=subject.key),
            predicate=claim.predicate,
            object=obj,
            observed_at=claim.observed_at,
            valid_from=claim.valid_from,
            valid_to=claim.valid_to,
            recorded_at=common.now(),
            source=claim.source,
            confidence=claim.confidence,
            provenance=self._resolve_provenance(claim),
            supersedes=claim.supersedes,
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
            json.dumps(obs.attrs), obs.supersedes,
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
