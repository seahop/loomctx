"""Default GraphStore: SQLite, single file, zero ops (D-002, D-011, D-014, D-016).

Tuned for "decent input in a singular setup": WAL journal + synchronous=NORMAL
(one fsync per transaction, safe under WAL), batched claim writes committed as
a single transaction, and a busy timeout + process-internal lock so the engine
and the scale-shape writer consumer can share the file. Edges are observations
whose object is an entity, so the graph is queryable from either end.

Every public method runs inside `_tx()`: lock, commit on success, ROLLBACK on
any exception — a failing statement can never leave half a batch behind for
the next unrelated commit to persist (hardening H-B1). Writes serialize on
one connection; the read-only methods borrow from a small pool of read
connections (`_tx(read=True)`), which WAL lets run beside the writer and
each other instead of queueing on its lock (R-9).

Ingest is idempotent: an envelope carrying an event_id is deduplicated on
(namespace, event_id) — a cheap pre-check for replays, backed by
`ON CONFLICT DO NOTHING` on the partial unique index so two writer processes
racing on the same event_id both get the one stored row (H-B2). Redaction is
a tombstone — the row stays for audit but never appears in reads, including
the dedupe return path (H-B3). Timestamps are stored as UTC ISO text so
lexical ORDER BY is chronological (H-B5). Startup runs capability-based
migrations so existing database files gain new columns/tables in place.
"""

from __future__ import annotations

import json
import logging
import queue
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

from .. import metrics
from ..contracts import (
    Artifact, ClaimIn, DocumentIn, Entity, EntityRef, Observation,
    SchemaRegistration,
)
from . import common
from .base import GraphStore

_TABLES = """
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
    provisional INTEGER NOT NULL DEFAULT 0,
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
    confidence       REAL NOT NULL,
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

-- What a merge changed, so unmerge can put it back exactly (D-019's
-- "reversible & lossless", made real in schema v5). One parent row per
-- merge; one child row per observation it repointed, recording which
-- side(s) named the folded entity and the object ref as rendered before.
CREATE TABLE IF NOT EXISTS merge_log (
    id                 TEXT PRIMARY KEY,
    namespace          TEXT NOT NULL,
    from_type          TEXT NOT NULL,
    from_key           TEXT NOT NULL,
    into_type          TEXT NOT NULL,
    into_key           TEXT NOT NULL,
    from_id            TEXT NOT NULL,
    from_provisional   INTEGER NOT NULL DEFAULT 0,
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
    vector    TEXT NOT NULL
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
    vector      TEXT NOT NULL,
    model       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_chunk_artifact
    ON doc_chunks (namespace, artifact_id);
"""

_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_obs_subject
    ON observations (namespace, subject_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_obs_object
    ON observations (namespace, object_entity_id, observed_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_obs_event
    ON observations (namespace, event_id) WHERE event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_art_event
    ON artifacts (namespace, event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_obs_recorded ON observations (recorded_at);
CREATE INDEX IF NOT EXISTS idx_obs_prov_artifact
    ON observations (namespace, json_extract(provenance_json, '$.artifact_id'));
CREATE INDEX IF NOT EXISTS idx_art_status ON artifacts (extraction_status, recorded_at);
CREATE INDEX IF NOT EXISTS idx_chunk_by_artifact ON doc_chunks (artifact_id);
CREATE INDEX IF NOT EXISTS idx_entity_key ON entities (namespace, key);
CREATE INDEX IF NOT EXISTS idx_entity_norm ON entities (namespace, norm_key);
CREATE INDEX IF NOT EXISTS idx_entity_lower_key ON entities (namespace, lower(key));
CREATE INDEX IF NOT EXISTS idx_merge_from ON merge_log (namespace, from_type, from_key);
CREATE INDEX IF NOT EXISTS idx_obs_supersedes
    ON observations (namespace, supersedes) WHERE supersedes IS NOT NULL;
-- worker tick scans (R-9): recorded_at ranges from a high-water mark, and a
-- per-subject lookup that does not need the namespace
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
-- label search (v9, D-091): scalar values by predicate, lower-cased JSON
-- text capped at 200 characters, so an entity keyed by an opaque id is
-- found by the value of a label predicate (a sAMAccountName, a displayName)
CREATE INDEX IF NOT EXISTS idx_obs_label
    ON observations (namespace, predicate, lower(substr(object_json, 1, 200)))
    WHERE object_entity_id IS NULL;
"""

# search_entities: a half-open range on the indexed expression (the LIKE
# optimization does not apply to expression indexes). BINARY collation
# compares UTF-8 bytes, which orders by code point, so prefix + U+10FFFF
# bounds every key that starts with the prefix. Exact matches sort first.
_SEARCH_SQL = (
    "SELECT * FROM entities WHERE namespace = ?"
    "   AND lower(key) >= ? AND lower(key) < ?"
)
_PREFIX_END = "\U0010ffff"
# label search (D-091): the indexed expression, verbatim, so the index applies
_LABEL_SQL = (
    "SELECT e.*, min(lower(substr(o.object_json, 1, 200)) != ?) AS inexact"
    " FROM observations o JOIN entities e ON e.id = o.subject_id"
    " WHERE o.namespace = ? AND o.object_entity_id IS NULL AND o.predicate IN ({preds})"
    "   AND lower(substr(o.object_json, 1, 200)) >= ? AND lower(substr(o.object_json, 1, 200)) < ?"
)

# Versioned migrations (H-B12): capability checks add columns idempotently;
# anything that must run exactly once (a backfill) is keyed by version here.
# v3: packed vectors (D-039); v4: resolution_declines (D-044); v5: merge_log,
# lease owners, lower(key) index, numeric norm_key rule (recompute);
# v6: observations.supersedes (D-050); tick-scan indexes and high-water marks
# (R-9); hex/colon norm_key rule (recompute keys carrying ':')
SCHEMA_VERSION = 9  # v7 (D-081) changes Postgres storage settings only; v8: FK child indexes (S-63); v9: label index (D-091)

# Columns added after their table's first release: added on open when missing
_WANTED_COLUMNS = {
    "observations": [("event_id", "TEXT"), ("supersedes", "TEXT")],
    "artifacts": [("event_id", "TEXT"),
                  ("extraction_attempts", "INTEGER NOT NULL DEFAULT 0"),
                  ("next_attempt_at", "TEXT"),
                  ("extract_claimed_by", "TEXT"),
                  ("extract_claimed_until", "TEXT"),
                  ("chunk_claimed_until", "TEXT"),
                  ("chunk_claimed_by", "TEXT")],
    "dossiers": [("observation_ids", "TEXT NOT NULL DEFAULT '[]'")],
    "doc_chunks": [("model", "TEXT NOT NULL DEFAULT ''")],
    "entities": [("norm_key", "TEXT NOT NULL DEFAULT ''"),
                 ("dossier_claimed_until", "TEXT"),
                 ("dossier_claimed_by", "TEXT")],
}

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

# The enrichment backlog (D-018/D-031), scanned from a high-water mark (R-9)
_EMBED_BACKLOG_SQL = (
    _OBS_SELECT
    + " WHERE o.recorded_at >= ?"
    " AND NOT EXISTS (SELECT 1 FROM embeddings em WHERE em.ref_id = o.id AND em.model = ?)"
    + _NOT_TOMBSTONED + "{shard}"
    " ORDER BY o.recorded_at LIMIT ?"
)

# Dossier candidacy (H-E2, D-044), incremental (R-9): only entities with a
# row recorded since the mark — or holding a dossier lease, expired or not,
# so a failed build is re-offered once its lease lapses — are evaluated.
# Richness over volume: several predicates from several senders outrank a
# one-predicate firehose, which gets no brief.
_DOSSIER_SQL = (
    "WITH touched AS ("
    "  SELECT DISTINCT o.subject_id AS eid FROM observations o WHERE o.recorded_at >= ?"
    "  UNION SELECT id FROM entities WHERE dossier_claimed_until IS NOT NULL)"
    " SELECT e.namespace, e.type, e.key, e.id AS eid, COUNT(o.id) AS fresh,"
    "        d.observation_count AS have,"
    "        COUNT(DISTINCT o.predicate) AS preds, COUNT(DISTINCT o.source) AS srcs"
    " FROM touched t JOIN entities e ON e.id = t.eid"
    " JOIN observations o ON o.subject_id = e.id"
    "   AND NOT EXISTS (SELECT 1 FROM tombstones t2 WHERE t2.observation_id = o.id)"
    " LEFT JOIN dossiers d ON d.namespace = e.namespace AND d.entity_id = e.id"
    " WHERE (d.updated_at IS NULL OR o.recorded_at > d.updated_at)"
    "   AND (e.dossier_claimed_until IS NULL OR e.dossier_claimed_until < ?)"
    " GROUP BY e.id"
    " HAVING (have IS NULL AND fresh >= ? AND preds >= 2) OR (have IS NOT NULL AND fresh >= ?)"
    " ORDER BY preds * srcs DESC, fresh DESC, e.created_at LIMIT ?"
)

_OBS_INSERT = (
    "INSERT INTO observations (id, namespace, event_id, subject_id, predicate,"
    " object_json, object_entity_id, observed_at, valid_from, valid_to,"
    " recorded_at, source, confidence, provenance_json, attrs_json, supersedes)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

# Tier-1 merge candidates (D-019): keys shared across types, less the groups
# whose every cross-type pair has a remembered decline (D-044) — those are
# settled, and must not occupy the limit (D-058). A decline stores its pair
# as sorted "type:key" strings; BINARY order is Python's code-point order.
_PAIR_SIDE = "e{n}.type || ':' || e{n}.key"
# Multi-type keys first (an index-ordered GROUP BY), then the pair/decline
# test only inside those few groups: a direct self-join let the planner
# match e2 on namespace alone — 74k × 74k comparisons on the vulns corpus.
_MERGE_CANDIDATES_SQL = (
    "WITH multi AS (SELECT namespace, key FROM entities e1 WHERE 1 = 1 {ns}"
    "  GROUP BY namespace, key HAVING COUNT(DISTINCT type) > 1)"
    " SELECT m.namespace, m.key FROM multi m WHERE EXISTS ("
    "  SELECT 1 FROM entities e1 INDEXED BY idx_entity_key JOIN entities e2 INDEXED BY idx_entity_key"
    "   ON e2.namespace = e1.namespace AND e2.key = e1.key AND e2.type <> e1.type"
    "  WHERE e1.namespace = m.namespace AND e1.key = m.key"
    "  AND NOT EXISTS (SELECT 1 FROM resolution_declines d"
    "   WHERE d.namespace = e1.namespace"
    f"    AND d.a = min({_PAIR_SIDE.format(n=1)}, {_PAIR_SIDE.format(n=2)})"
    f"    AND d.b = max({_PAIR_SIDE.format(n=1)}, {_PAIR_SIDE.format(n=2)})))"
    " ORDER BY m.namespace, m.key LIMIT ?"
)

# Tier-2 (fuzzy, D-024) candidates in the same shape: normalized keys that
# several raw keys share, less the groups whose every pair of differing raw
# keys has a remembered decline (S-26). Same-key pairs inside a group are
# tier 1's business (above), so they neither keep a group open nor settle it.
_FUZZY_CANDIDATES_SQL = (
    "WITH multi AS (SELECT namespace, norm_key FROM entities e1"
    "  WHERE norm_key <> '' {ns}"
    "  GROUP BY namespace, norm_key HAVING COUNT(DISTINCT key) > 1)"
    " SELECT m.namespace, m.norm_key FROM multi m WHERE EXISTS ("
    "  SELECT 1 FROM entities e1 INDEXED BY idx_entity_norm JOIN entities e2 INDEXED BY idx_entity_norm"
    "   ON e2.namespace = e1.namespace AND e2.norm_key = e1.norm_key AND e2.key <> e1.key"
    "  WHERE e1.namespace = m.namespace AND e1.norm_key = m.norm_key"
    "  AND NOT EXISTS (SELECT 1 FROM resolution_declines d"
    "   WHERE d.namespace = e1.namespace"
    f"    AND d.a = min({_PAIR_SIDE.format(n=1)}, {_PAIR_SIDE.format(n=2)})"
    f"    AND d.b = max({_PAIR_SIDE.format(n=1)}, {_PAIR_SIDE.format(n=2)})))"
    " ORDER BY m.namespace, m.norm_key LIMIT ?"
)

_ON_EVENT_CONFLICT = (
    " ON CONFLICT (namespace, event_id) WHERE event_id IS NOT NULL DO NOTHING"
)


class SqliteStore(GraphStore):
    _READERS = 4   # read connections per store (LOOMCTX_DB_READERS in the factory)

    def __init__(self, path: str | Path, readers: int | None = None):
        # Re-entrant: a public method that calls another public method
        # (unmerge -> dossier drop, lifecycle helpers, ...) must not deadlock
        # on its own lock; `_tx` commits only at the outermost level.
        self._lock = threading.RLock()
        self._depth = 0
        self._owner: int | None = None      # the thread inside the write transaction
        self._bulk: float | None = None     # inside bulk_load: when it last committed
        self._local = threading.local()     # the read connection a thread borrowed
        self._ticks: dict[str, int] = {}   # tick-scan calls per mark (R-9)
        self._path = str(path)
        self._writer = sqlite3.connect(self._path, check_same_thread=False)
        self._writer.row_factory = sqlite3.Row
        self._writer.execute("PRAGMA journal_mode=WAL")
        self._writer.execute("PRAGMA synchronous=NORMAL")
        # 15 s: several enrichment workers writing 512-vector batches can
        # hold the write lock past 5 s (D-039)
        self._writer.execute("PRAGMA busy_timeout=15000")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS loomctx_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        current = self._meta_version()
        if current > SCHEMA_VERSION:
            # An older image opening a newer file: serve what it understands,
            # run no DDL, and never write the version down (H-B12) — the next
            # up-to-date open must still see what was actually applied.
            logging.getLogger("loomctx.store").warning(
                "sqlite: schema version %d is newer than this build's %d;"
                " running without migrations — upgrade the image", current, SCHEMA_VERSION)
        else:
            self._conn.executescript(_TABLES)
            self._migrate()
            self._conn.executescript(_INDEXES)
        self._vec_tables: dict[str, int] = {}   # ANN table name -> dimension
        self._vec = self._load_vec()
        # Referential integrity is per-connection in SQLite (H-B10). Old
        # files may hold dangling rows from before this was on; report,
        # don't refuse to start. Checked when a migration ran, not on every
        # open: the check walks every reference (23 s at 6.5M observations)
        # and every MCP session opens the store anew; a file already at this
        # version has had it, and enforced writes keep it clean (D-104).
        self._conn.execute("PRAGMA foreign_keys=ON")
        dangling = (self._conn.execute("PRAGMA foreign_key_check").fetchall()
                    if current < SCHEMA_VERSION else [])
        if dangling:
            logging.getLogger("loomctx.store").warning(
                "sqlite: %d row(s) violate foreign keys (pre-existing data);"
                " reads skip them, a lifecycle export/import cleans them",
                len(dangling))
        # Readers (R-9): WAL serves any number of readers beside one writer,
        # but every read used to queue on the writer's lock. A memory
        # database is private to its connection, so it gets none.
        if readers is None:
            readers = self._READERS
        if self._path == ":memory:":
            readers = 0
        self._readers = [self._open_reader() for _ in range(max(0, readers))]
        self._reader_pool: queue.LifoQueue | None = None
        if self._readers:
            self._reader_pool = queue.LifoQueue()
            for conn in self._readers:
                self._reader_pool.put(conn)

    def _open_reader(self) -> sqlite3.Connection:
        # autocommit mode: `_tx(read=True)` brackets its statements in an
        # explicit BEGIN/COMMIT so a multi-statement read sees one snapshot
        conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=15000")
        if self._vec:
            self._load_vec_extension(conn)
        return conn

    @property
    def _conn(self) -> sqlite3.Connection:
        """The connection for the current statement: the writer while this
        thread is inside a write transaction (or outside any), otherwise
        the read connection it borrowed in `_tx(read=True)`."""
        if self._owner == threading.get_ident():
            return self._writer
        reader = getattr(self._local, "reader", None)
        return reader if reader is not None else self._writer

    def _migrate(self) -> None:
        """Bring pre-existing database files up to the current shape:
        idempotent column adds first, then one-shot versioned steps.

        Two processes opening one old file at once (the engine and a
        worker after an image roll) both saw a column missing and the
        second ALTER died on "duplicate column name". The work now runs
        under BEGIN IMMEDIATE — one migrator at a time; the second re-reads
        the shape inside the lock and finds nothing left to do — and a
        duplicate column is tolerated regardless. An up-to-date file is
        detected before the lock, so opening it takes no write lock (D-039)."""
        if not self._migration_due():
            return
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._migrate_locked()
        except BaseException:
            self._conn.rollback()
            raise
        self._conn.commit()

    def _missing_columns(self) -> list[tuple[str, str, str]]:
        out = []
        for table, columns in _WANTED_COLUMNS.items():
            have = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            out += [(table, name, ddl) for name, ddl in columns if name not in have]
        return out

    def _migration_due(self) -> bool:
        return self._meta_version() < SCHEMA_VERSION or bool(self._missing_columns())

    def _migrate_locked(self) -> None:
        for table, name, ddl in self._missing_columns():
            try:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
        current = self._meta_version()
        if current < 2:
            # v2: backfill normalized keys for fuzzy resolution (D-024)
            rows = self._conn.execute(
                "SELECT id, key FROM entities WHERE norm_key = ''").fetchall()
            self._conn.executemany(
                "UPDATE entities SET norm_key = ? WHERE id = ?",
                [(common.norm_key(r["key"]), r["id"]) for r in rows])
        if current < 5:
            # v5: numeric keys keep their punctuation in norm_key (10.0.4.7
            # no longer collides with 100.4.7); recompute the rows that can
            # differ — only keys carrying `. : / -` — in Python, the one
            # place the rule is defined.
            rows = self._conn.execute(
                "SELECT id, key, norm_key FROM entities WHERE instr(key, '.') > 0"
                " OR instr(key, ':') > 0 OR instr(key, '/') > 0 OR instr(key, '-') > 0").fetchall()
            self._conn.executemany(
                "UPDATE entities SET norm_key = ? WHERE id = ?",
                [(nk, r["id"]) for r in rows if (nk := common.norm_key(r["key"])) != r["norm_key"]])
        if current < 6:
            # v6: colon-structured hex keys (IPv6, MAC) keep their separators
            # too; only keys carrying ':' can differ.
            rows = self._conn.execute(
                "SELECT id, key, norm_key FROM entities WHERE instr(key, ':') > 0").fetchall()
            self._conn.executemany(
                "UPDATE entities SET norm_key = ? WHERE id = ?",
                [(nk, r["id"]) for r in rows if (nk := common.norm_key(r["key"])) != r["norm_key"]])
        if current < SCHEMA_VERSION:
            self._conn.execute(
                "INSERT OR REPLACE INTO loomctx_meta (key, value) VALUES"
                " ('schema_version', ?)", (str(SCHEMA_VERSION),))

    def _meta_version(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM loomctx_meta WHERE key = 'schema_version'").fetchone()
        return int(row["value"]) if row else 0

    def schema_version(self) -> int:
        with self._tx(read=True):
            return self._meta_version()

    # ------------------------------------------------- vector index (D-025)

    @staticmethod
    def _load_vec_extension(conn: sqlite3.Connection) -> None:
        import sqlite_vec
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)

    def _load_vec(self) -> bool:
        try:
            self._load_vec_extension(self._writer)
        except Exception as exc:  # noqa: BLE001 — any failure means "no ANN"
            logging.getLogger("loomctx.store").info(
                "sqlite-vec unavailable (%s): vector search uses exact scans", exc)
            return False
        for row in self._conn.execute(
                "SELECT key, value FROM loomctx_meta WHERE key LIKE 'vec:%'"):
            self._vec_tables[row["key"][4:]] = int(row["value"])
        return True

    def vector_backend(self) -> str:
        return "sqlite-vec" if self._vec else "exact"

    def _vec_table(self, kind: str, model: str, dim: int) -> str:
        """The vec0 table for (kind, model, dim), created on first use."""
        name = common.vec_table(kind, model, dim)
        if name not in self._vec_tables:
            self._conn.execute(
                f"CREATE VIRTUAL TABLE IF NOT EXISTS {name} USING vec0("
                f" ref_id TEXT PRIMARY KEY, namespace TEXT PARTITION KEY,"
                f" artifact_id TEXT, embedding float[{dim}] distance_metric=cosine)")
            self._conn.execute(
                "INSERT OR REPLACE INTO loomctx_meta (key, value) VALUES (?, ?)",
                (f"vec:{name}", str(dim)))
            self._vec_tables[name] = dim
        return name

    def _vec_upsert(self, kind: str, model: str, namespace: str,
                    rows: list[tuple[str, str | None, list[float]]]) -> int:
        """rows: (ref_id, artifact_id|None, vector), grouped by dimension.
        Returns rows written; 0 without the extension."""
        if not self._vec or not rows:
            return 0
        written = 0
        by_dim: dict[int, list] = {}
        for rid, aid, vec in rows:
            by_dim.setdefault(len(vec), []).append((rid, aid, vec))
        for dim, group in by_dim.items():
            name = self._vec_table(kind, model, dim)
            self._conn.executemany(f"DELETE FROM {name} WHERE ref_id = ?",
                                   [(rid,) for rid, _, _ in group])
            self._conn.executemany(
                f"INSERT INTO {name} (ref_id, namespace, artifact_id, embedding)"
                " VALUES (?, ?, ?, ?)",
                [(rid, namespace, aid or "", common.raw_f32(vec)) for rid, aid, vec in group])
            written += len(group)
        return written

    def _refresh_vec_tables(self) -> None:
        """Another process (the worker) may have created index tables since
        this connection opened; loomctx_meta is the shared registry."""
        for row in self._conn.execute(
                "SELECT key, value FROM loomctx_meta WHERE key LIKE 'vec:%'"):
            self._vec_tables[row["key"][4:]] = int(row["value"])

    def _vec_query(self, kind: str, model: str, namespace: str,
                   query: list[float], k: int,
                   artifact_ids: list[str] | None = None) -> list[tuple[str, str, float]] | None:
        """(ref_id, artifact_id, cosine) via the ANN index, best first; None
        when no index fits this (model, dimension) so callers scan exactly.
        `artifact_ids` filters inside the KNN (a vec0 metadata column), so
        the k nearest are the k nearest *among those artifacts*."""
        name = common.vec_table(kind, model, len(query))
        if name not in self._vec_tables:
            self._refresh_vec_tables()
        if name not in self._vec_tables:
            return None
        sql = (f"SELECT ref_id, artifact_id, distance FROM {name}"
               " WHERE embedding MATCH ? AND k = ? AND namespace = ?")
        params: tuple = (json.dumps(query), k, namespace)
        if artifact_ids is not None:
            sql += " AND artifact_id IN (SELECT value FROM json_each(?))"
            params += (json.dumps(artifact_ids),)
        try:
            rows = self._conn.execute(sql + " ORDER BY distance", params).fetchall()
        except sqlite3.OperationalError:
            if artifact_ids is None:
                raise
            return None  # an index without metadata filtering (sqlite-vec < 0.1.6): scan exactly
        return [(r["ref_id"], r["artifact_id"], 1.0 - float(r["distance"])) for r in rows]

    def nearest_observations(
        self, namespace: str, model: str, query: list[float], limit: int = 20
    ) -> list[tuple[str, float]]:
        with self._tx(read=True):
            hits = self._vec_query("vobs", model, namespace, query, limit * 2) if self._vec else None
            if hits is not None:
                scored = {rid: s for rid, _, s in hits}
            else:  # exact scan over the namespace's vectors
                rows = self._conn.execute(
                    "SELECT ref_id, vector FROM embeddings WHERE namespace = ? AND model = ?",
                    (namespace, model)).fetchall()
                scored = common.cosines(
                    query, {r["ref_id"]: common.unpack_array(r["vector"]) for r in rows})
            if not scored:
                return []
            marks = ",".join("?" * len(scored))
            tomb = {r["observation_id"] for r in self._conn.execute(
                f"SELECT observation_id FROM tombstones WHERE observation_id IN ({marks})",
                tuple(scored)).fetchall()}
        return common.top_k({k: v for k, v in scored.items() if k not in tomb}, limit)

    def nearest_chunks(
        self, namespace: str, model: str, query: list[float], limit: int = 20,
        artifact_ids: list[str] | None = None,
    ) -> list[tuple[dict, float]]:
        wanted = sorted(set(artifact_ids)) if artifact_ids is not None else None
        if wanted is not None and not wanted:
            return []
        with self._tx(read=True):
            # The artifact filter runs inside the KNN (D-058): the k nearest
            # among the cited documents. Filtering the namespace's nearest
            # afterwards starved on nearly every ask and fell through to
            # decoding every chunk vector of every cited artifact in Python.
            hits = self._vec_query("vchk", model, namespace, query, limit, wanted) if self._vec else None
            scored = {cid: s for cid, _, s in hits or []}
            # short of `limit`: fewer chunks exist (done), or there is no
            # index / it lags the chunk table the worker backfills it from
            if len(scored) < limit and (hits is None or self._chunk_count(namespace, model, wanted) > len(scored)):
                sql = "SELECT id, vector FROM doc_chunks WHERE namespace = ? AND model = ?"
                params: tuple = (namespace, model)
                if wanted is not None:
                    sql += " AND artifact_id IN (SELECT value FROM json_each(?))"
                    params += (json.dumps(wanted),)
                rows = self._conn.execute(sql, params).fetchall()
                scored = common.cosines(query, {r["id"]: common.unpack_array(r["vector"]) for r in rows})
            best = common.top_k(scored, limit)
            if not best:
                return []
            marks = ",".join("?" * len(best))
            rows = self._conn.execute(
                "SELECT c.id, c.artifact_id, c.seq, c.span_start, c.span_end,"
                " c.text, c.vector, a.source, a.observed_at"
                " FROM doc_chunks c JOIN artifacts a ON a.id = c.artifact_id"
                f" WHERE c.id IN ({marks})", tuple(cid for cid, _ in best)).fetchall()
        by_id = {r["id"]: common.row_to_chunk(r) for r in rows}
        return [(by_id[cid], s) for cid, s in best if cid in by_id]

    def _chunk_count(self, namespace: str, model: str, artifact_ids: list[str] | None) -> int:
        sql = "SELECT COUNT(*) AS n FROM doc_chunks WHERE namespace = ? AND model = ?"
        params: tuple = (namespace, model)
        if artifact_ids is not None:
            sql += " AND artifact_id IN (SELECT value FROM json_each(?))"
            params += (json.dumps(artifact_ids),)
        return int(self._conn.execute(sql, params).fetchone()["n"])

    def ensure_vector_index(self, model: str) -> dict:
        out = {"backend": self.vector_backend(), "observations": 0, "chunks": 0}
        if not self._vec:
            return out
        # The backfill used to load every indexed id into a set and then
        # every vector row into memory to diff them — a 400 MB spike per
        # tick at 200k vectors that OOM-killed the worker every few minutes
        # on GKE (D-043). Now: the diff is an anti-join in SQL, rows stream
        # in chunks, and a table whose count already matches is skipped.
        with self._tx():
            self._refresh_vec_tables()
            for kind, key, table, id_col, art_col in (
                ("vobs", "observations", "embeddings", "ref_id", "NULL"),
                ("vchk", "chunks", "doc_chunks", "id", "artifact_id"),
            ):
                # exactly this model's tables (one per dimension seen) — a
                # bare `{kind}_` prefix matched every model, so a model whose
                # index did not exist yet was skipped as "already indexed"
                vec_tables = common.vec_tables_for(kind, model, list(self._vec_tables))
                total = self._conn.execute(
                    f"SELECT COUNT(*) AS n FROM {table} WHERE model = ?", (model,)).fetchone()["n"]
                indexed = sum(self._conn.execute(f"SELECT COUNT(*) AS n FROM {n}").fetchone()["n"]
                              for n in vec_tables)
                if total <= indexed:
                    continue
                not_in = " AND ".join(f"t.{id_col} NOT IN (SELECT ref_id FROM {n})" for n in vec_tables) or "1=1"
                last = ""
                while True:
                    rows = self._conn.execute(
                        f"SELECT t.{id_col} AS id, t.namespace, {art_col} AS artifact_id, t.vector"
                        f" FROM {table} t WHERE t.model = ? AND t.{id_col} > ? AND {not_in}"
                        f" ORDER BY t.{id_col} LIMIT 1000", (model, last)).fetchall()
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
        out: list[Observation] = []
        with self._tx(read=True):
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                rows = self._conn.execute(
                    # `+o.namespace`: a bare namespace term let the planner
                    # walk the namespace's idx_obs_prov_artifact range instead
                    # of the primary key — 255 ms vs 4 ms per 500 ids on the
                    # 542k-row vulns corpus (D-061)
                    _OBS_SELECT + f" WHERE +o.namespace = ? AND o.id IN ({','.join('?' * len(chunk))})"
                    + _NOT_TOMBSTONED, (namespace, *chunk)).fetchall()
                out.extend(common.row_to_observation(r) for r in rows)
        return out

    def superseded_ids(self, namespace: str, ids: list[str]) -> set[str]:
        if not ids:
            return set()
        out: set[str] = set()
        with self._tx(read=True):
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                rows = self._conn.execute(
                    "SELECT DISTINCT o.supersedes AS sid FROM observations o"
                    f" WHERE o.namespace = ? AND o.supersedes IN ({','.join('?' * len(chunk))})"
                    + _NOT_TOMBSTONED, (namespace, *chunk)).fetchall()
                out.update(r["sid"] for r in rows)
        return out

    def corrections_of(
        self, namespace: str, ids: list[str], observed_before: datetime | None = None,
    ) -> list[Observation]:
        if not ids:
            return []
        before_sql, before_args = _observed_before("?", observed_before)
        out: list[Observation] = []
        with self._tx(read=True):
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                rows = self._conn.execute(
                    _OBS_SELECT + " WHERE o.namespace = ?"
                    f" AND o.supersedes IN ({','.join('?' * len(chunk))})"
                    + _NOT_TOMBSTONED + before_sql, (namespace, *chunk, *before_args)).fetchall()
                out.extend(common.row_to_observation(r) for r in rows)
        return out

    def resolve_refs(
        self, namespace: str, refs: list[EntityRef],
    ) -> dict[tuple[str, str], EntityRef]:
        out: dict[tuple[str, str], EntityRef] = {}
        if not refs:
            return out
        with self._tx(read=True):
            owners = self._resolve_many(namespace, refs)
            ids = list(owners)
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                for r in self._conn.execute(
                        f"SELECT id, type, key FROM entities WHERE id IN ({','.join('?' * len(chunk))})",
                        tuple(chunk)).fetchall():
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
            rows = self._conn.execute(
                # `+o.namespace`: keep the planner on the primary-key range;
                # it once took the namespace index and scanned every row
                _OBS_SELECT + " WHERE +o.namespace = ? AND o.id >= ?"
                + (" AND o.id < ?" if hi is not None else "") + _NOT_TOMBSTONED
                + " ORDER BY o.id LIMIT ?",
                (namespace, lo, *((hi,) if hi is not None else ()), self._PREFIX_CAP)).fetchall()
        return [common.row_to_observation(r) for r in rows]

    @contextmanager
    def _tx(self, read: bool = False):
        """One transaction. The default takes the process lock and the
        writer: commit on success, rollback on error so a failure never
        leaks partial writes into a later commit (H-B1); nested entries (a
        public method calling another) join the outer transaction, and only
        the outermost commits or rolls back. `read=True` borrows a pooled
        read connection instead, so reads run beside the writer and each
        other (WAL) — unless this thread is inside a write transaction (the
        read joins it and sees its uncommitted rows) or already holds a
        reader (it joins that snapshot)."""
        me = threading.get_ident()
        if read and self._reader_pool is not None and self._owner != me:
            if getattr(self._local, "reader", None) is not None:
                yield
                return
            conn = self._reader_pool.get()
            self._local.reader = conn
            try:
                conn.execute("BEGIN")
                try:
                    yield
                except BaseException:
                    conn.rollback()
                    raise
                else:
                    conn.commit()
            finally:
                self._local.reader = None
                self._reader_pool.put(conn)
            return
        with self._lock:
            if self._depth == 0:
                self._owner = me
            self._depth += 1
            # inside a bulk load (depth 1 is the load itself) each outermost
            # write call is a savepoint in the load's longer transaction
            call = self._bulk is not None and self._depth == 2 and not read
            if call:
                if not self._writer.in_transaction:
                    self._writer.execute("BEGIN")
                self._writer.execute("SAVEPOINT loomctx_call")
            try:
                yield
            except BaseException:
                if self._depth == 1:
                    self._writer.rollback()
                elif call:
                    self._undo_call()
                raise
            else:
                if self._depth == 1:
                    self._writer.commit()
                elif call:
                    self._writer.execute("RELEASE loomctx_call")
                    if time.monotonic() - self._bulk >= self._BULK_COMMIT_SECONDS:
                        self._writer.commit()
                        self._bulk = time.monotonic()
            finally:
                self._depth -= 1
                if self._depth == 0:
                    self._owner = None

    def _undo_call(self) -> None:
        """Roll back the failed write call of a bulk load, keeping the
        calls before it."""
        try:
            if self._writer.in_transaction:
                self._writer.execute("ROLLBACK TO loomctx_call")
                self._writer.execute("RELEASE loomctx_call")
        except sqlite3.Error:
            # an error SQLite answers by rolling back the whole transaction
            # (a full disk, an I/O error) took the load's uncommitted calls
            # with it; there is nothing left to undo
            pass

    # Bulk loads (D-105). A 256 MiB page cache keeps the hot index pages of a
    # multi-million-row store in memory (the default 2 MB re-read them from
    # the OS on every insert); a 20,000-page WAL checkpoint interval writes a
    # hot page back once per ~80 MB of log, not once per batch; and a commit
    # every 5 s, not per 500-line batch, writes a dirty index page once per
    # commit instead of once per batch that touched it (on a 6.5M-row store
    # 5 s beat 1 s by a fifth; a 1 GiB cache bought nothing more). Another
    # writer waits up to about that long, well inside its 15 s busy timeout.
    _BULK_CACHE_KIB = 256 * 1024
    _BULK_WAL_PAGES = 20_000
    _BULK_COMMIT_SECONDS = 5.0
    # The observation indexes no write path reads (dedupe uses idx_obs_event,
    # resolution the entity indexes; these serve queries, merges' foreign-key
    # checks and worker scans). Each takes a random-page insert per row: on
    # a 6.5M-row store they were three quarters of the bytes a load wrote.
    # A load into a store with no observations yet builds them once at the
    # end, by sort, instead. They are derived: what is stored is unchanged,
    # and a load that dies before the end leaves them to the next open,
    # which creates any missing index (`_INDEXES`).
    _BULK_DEFERRED_INDEXES = (
        "idx_obs_subject", "idx_obs_object", "idx_obs_recorded", "idx_obs_prov_artifact",
        "idx_obs_supersedes", "idx_obs_subject_recorded", "idx_obs_object_entity", "idx_obs_label",
    )

    @contextmanager
    def bulk_load(self) -> Iterator[None]:
        """GraphStore.bulk_load: hold the writer for the run, make each write
        call a savepoint in a transaction committed every few seconds, and
        raise the page cache and checkpoint interval — all restored, and the
        last calls committed, on the way out (an error included: the calls
        that succeeded stay, the failed one was rolled back to its
        savepoint, exactly as when every call committed on its own). Into
        an empty store the query-only observation indexes are built at the
        end instead of row by row."""
        with self._lock:
            if self._depth:     # already inside a transaction on this thread: join it
                yield
                return
            writer = self._writer
            cache = writer.execute("PRAGMA cache_size").fetchone()[0]
            wal = writer.execute("PRAGMA wal_autocheckpoint").fetchone()[0]
            writer.execute(f"PRAGMA cache_size=-{self._BULK_CACHE_KIB}")
            writer.execute(f"PRAGMA wal_autocheckpoint={self._BULK_WAL_PAGES}")
            deferred = self._defer_indexes()
            self._owner, self._depth = threading.get_ident(), 1
            self._bulk = time.monotonic()
            try:
                yield
            finally:
                self._bulk = None
                try:
                    if writer.in_transaction:
                        writer.commit()
                finally:
                    self._depth, self._owner = 0, None
                    try:
                        if deferred:    # what every open runs: creates the missing ones
                            writer.executescript(_INDEXES)
                    finally:
                        writer.execute(f"PRAGMA cache_size={int(cache)}")
                        writer.execute(f"PRAGMA wal_autocheckpoint={int(wal)}")
                        writer.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()

    def _defer_indexes(self) -> bool:
        """Drop the deferrable observation indexes when the store has no
        observations (and this build runs its own DDL); whether it did."""
        writer = self._writer
        if (self._meta_version() > SCHEMA_VERSION
                or writer.execute("SELECT 1 FROM observations LIMIT 1").fetchone() is not None):
            return False
        for name in self._BULK_DEFERRED_INDEXES:
            writer.execute(f"DROP INDEX IF EXISTS {name}")
        writer.commit()
        return True

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
            self._conn.execute(
                "UPDATE observations SET subject_id = ? WHERE namespace = ? AND subject_id = ?",
                (dst.id, namespace, src.id),
            )
            # object side: repoint the edge AND its rendered ref, so both ends
            # of a merged edge read as the canonical entity (H-B6)
            self._conn.execute(
                "UPDATE observations SET object_entity_id = ?, object_json = ?"
                " WHERE namespace = ? AND object_entity_id = ?",
                (dst.id, json.dumps({"type": dst.type, "key": dst.key}), namespace, src.id),
            )
            # existing aliases pointing at the source follow it to the target
            self._conn.execute(
                "UPDATE aliases SET entity_id = ? WHERE namespace = ? AND entity_id = ?",
                (dst.id, namespace, src.id),
            )
            self._put_alias(namespace, f"{src.type}:{src.key}", dst.id)
            # the folded node's brief described a partial view; drop it and
            # let the canonical's rebuild when the new facts accumulate
            self._conn.execute(
                "DELETE FROM dossiers WHERE namespace = ? AND entity_id IN (?, ?)",
                (namespace, src.id, dst.id),
            )
            self._conn.execute("DELETE FROM entities WHERE id = ?", (src.id,))
            self._hwm_reset(self._DOSSIER_HWM)
            return True

    def _log_merge(self, namespace: str, src: Entity, dst: Entity) -> None:
        """Record what merge_entities is about to change — the folded
        entity's row, the observations that name it (which side, and the
        object ref as rendered), the aliases that point at it — so unmerge
        can put every one of them back (D-019: reversible & lossless)."""
        touched = self._conn.execute(
            "SELECT id, subject_id, object_entity_id, object_json FROM observations"
            " WHERE namespace = ? AND subject_id = ?"
            " UNION SELECT id, subject_id, object_entity_id, object_json FROM observations"
            " WHERE namespace = ? AND object_entity_id = ?",
            (namespace, src.id, namespace, src.id)).fetchall()
        aliases = [r["alias"] for r in self._conn.execute(
            "SELECT alias FROM aliases WHERE namespace = ? AND entity_id = ?", (namespace, src.id))]
        merge_id = uuid.uuid4().hex
        self._conn.execute(
            "INSERT INTO merge_log (id, namespace, from_type, from_key, into_type, into_key,"
            " from_id, from_provisional, from_created_at, prior_aliases_json, recorded_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (merge_id, namespace, src.type, src.key, dst.type, dst.key, src.id,
             int(src.provisional), common.iso(src.created_at), json.dumps(aliases),
             common.iso(common.now())))
        self._conn.executemany(
            "INSERT INTO merge_log_observations (merge_id, observation_id, prior_subject_id,"
            " prior_object_entity_id, prior_object_json) VALUES (?, ?, ?, ?, ?)",
            [(merge_id, r["id"],
              src.id if r["subject_id"] == src.id else None,
              src.id if r["object_entity_id"] == src.id else None,
              r["object_json"] if r["object_entity_id"] == src.id else None)
             for r in touched])

    def unmerge(self, namespace: str, alias: EntityRef) -> bool:
        with self._tx():
            m = self._conn.execute(
                "SELECT * FROM merge_log WHERE namespace = ? AND from_type = ? AND from_key = ?"
                " ORDER BY recorded_at DESC, id DESC LIMIT 1",
                (namespace, alias.type, alias.key)).fetchone()
            if m is None:
                return False
            from_ref = EntityRef(type=m["from_type"], key=m["from_key"])
            # 1. the folded node again, with its original id and creation
            #    record when nothing has taken them since
            self._conn.execute(
                "INSERT OR IGNORE INTO entities (id, namespace, type, key, provisional,"
                " created_at, norm_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (m["from_id"], namespace, from_ref.type, from_ref.key,
                 int(m["from_provisional"]), m["from_created_at"], common.norm_key(from_ref.key)))
            src = self._get_entity(namespace, from_ref) or self._upsert_entity(namespace, from_ref)
            # 2. exactly the observations that merge moved, each side it
            #    moved — but only rows still on the merge target: in a chain
            #    A->B->C an earlier unmerge of A already took A's rows back,
            #    and B's log (which lists them, they were B's then) must not
            #    steal them. `hold` is the target's current node (aliases
            #    followed); None only if it vanished, then unconditional.
            dst = self._resolve_entity(namespace, EntityRef(type=m["into_type"], key=m["into_key"]))
            hold = dst.id if dst else None
            moved = self._conn.execute(
                "SELECT * FROM merge_log_observations WHERE merge_id = ?", (m["id"],)).fetchall()
            self._conn.executemany(
                "UPDATE observations SET subject_id = ? WHERE id = ? AND (? IS NULL OR subject_id = ?)",
                [(src.id, r["observation_id"], hold, hold)
                 for r in moved if r["prior_subject_id"] is not None])
            self._conn.executemany(
                "UPDATE observations SET object_entity_id = ?, object_json = ?"
                " WHERE id = ? AND (? IS NULL OR object_entity_id = ?)",
                [(src.id, r["prior_object_json"] or json.dumps({"type": src.type, "key": src.key}),
                  r["observation_id"], hold, hold)
                 for r in moved if r["prior_object_entity_id"] is not None])
            # 3. aliases that had named it name it again; its own alias goes
            self._conn.executemany(
                "UPDATE aliases SET entity_id = ? WHERE namespace = ? AND alias = ?",
                [(src.id, namespace, a) for a in json.loads(m["prior_aliases_json"] or "[]")])
            self._conn.execute("DELETE FROM aliases WHERE namespace = ? AND alias = ?",
                               (namespace, f"{from_ref.type}:{from_ref.key}"))
            # 4. both briefs described the merged view
            self._conn.execute(
                "DELETE FROM dossiers WHERE namespace = ? AND entity_id IN (?, ?)",
                (namespace, src.id, dst.id if dst else src.id))
            # 5. the log rows: the merge no longer happened
            self._conn.execute("DELETE FROM merge_log_observations WHERE merge_id = ?", (m["id"],))
            self._conn.execute("DELETE FROM merge_log WHERE id = ?", (m["id"],))
            self._hwm_reset(self._DOSSIER_HWM)
            return True

    def iter_merges(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx(read=True):
            parents = self._conn.execute(
                "SELECT * FROM merge_log" + (" WHERE namespace = ?" if namespace else "")
                + " ORDER BY recorded_at, id", (namespace,) if namespace else ()).fetchall()
            records = []
            for m in parents:
                kids = self._conn.execute(
                    "SELECT * FROM merge_log_observations WHERE merge_id = ?"
                    " ORDER BY observation_id", (m["id"],)).fetchall()
                records.append(common.merge_record(m, kids))
        yield from records

    def restore_merge(self, record: dict) -> None:
        parent, children = common.merge_rows(record)
        with self._tx():
            self._conn.execute(
                "INSERT OR IGNORE INTO merge_log (id, namespace, from_type, from_key, into_type,"
                " into_key, from_id, from_provisional, from_created_at, prior_aliases_json,"
                " recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (*parent[:7], int(parent[7]), *parent[8:]))
            self._conn.executemany(
                "INSERT OR IGNORE INTO merge_log_observations (merge_id, observation_id,"
                " prior_subject_id, prior_object_entity_id, prior_object_json)"
                " VALUES (?, ?, ?, ?, ?)", children)

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
                touched = {r["object_entity_id"] for r in self._conn.execute(
                    "SELECT DISTINCT object_entity_id FROM observations"
                    " WHERE recorded_at > {p} AND namespace = {p} AND predicate = {p}"
                    " AND object_entity_id IS NOT NULL".format(p='?'),
                    (common.iso(since), namespace, predicate)).fetchall()}
            else:
                touched = {r["object_entity_id"] for r in self._conn.execute(
                    "SELECT DISTINCT object_entity_id FROM observations"
                    " WHERE namespace = {p} AND predicate = {p} AND object_entity_id IS NOT NULL".format(p='?'),
                    (namespace, predicate)).fetchall()}
            ids = sorted(touched)
            holders: dict[str, set[str]] = {}
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                marks = ",".join(['?'] * len(chunk))
                for r in self._conn.execute(
                        "SELECT o.object_entity_id AS ident, o.subject_id FROM observations o"
                        " WHERE o.object_entity_id IN (" + marks + ") AND o.namespace = {p}"
                        " AND o.predicate = {p} AND ".format(p='?') + live,
                        (*chunk, namespace, predicate)).fetchall():
                    holders.setdefault(r["ident"], set()).add(r["subject_id"])
            multi = sorted(i for i, subs in holders.items() if len(subs) > 1)
            rows: dict[str, Entity] = {}
            wanted = {f"{k}:" for k in kinds} if kinds else None
            out = []
            for start in range(0, len(multi), 500):
                chunk = multi[start:start + 500]
                marks = ",".join(['?'] * len(chunk))
                idents = {r["id"]: common.row_to_entity(r) for r in self._conn.execute(
                    "SELECT * FROM entities WHERE id IN (" + marks + ")", tuple(chunk)).fetchall()}
                keep = [i for i in chunk if i in idents and (
                    wanted is None or any(idents[i].key.startswith(w) for w in wanted))]
                subjects = sorted({s for i in keep for s in holders[i]} - set(rows))
                for s_start in range(0, len(subjects), 500):
                    s_chunk = subjects[s_start:s_start + 500]
                    s_marks = ",".join(['?'] * len(s_chunk))
                    for r in self._conn.execute("SELECT * FROM entities WHERE id IN (" + s_marks + ")", tuple(s_chunk)).fetchall():
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
        doc = "o.source LIKE 'doc:%' OR o.attrs_json LIKE '%\"extracted\": true%'"
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
                rows = self._conn.execute(sql.format(p="?"), tuple(args)).fetchall()
            for r in rows:
                total = int(r["s_all"]) + int(r["o_all"])
                structured = total - int(r["s_doc"]) - int(r["o_doc"])
                out[(r["type"], r["key"])] = (structured, total, common.parse(r["created_at"]))
        return out

    def fuzzy_merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        with self._tx(read=True):
            # a settled group (every differing pair declined) must not
            # occupy the limit, as in merge_candidates (S-26)
            rows = self._conn.execute(
                _FUZZY_CANDIDATES_SQL.format(ns="AND e1.namespace = ?" if namespace else ""),
                ((namespace, limit) if namespace else (limit,)),
            ).fetchall()
            groups = []
            for row in rows:
                members = self._conn.execute(
                    "SELECT * FROM entities WHERE namespace = ? AND norm_key = ?"
                    " ORDER BY created_at, type, key",
                    (row["namespace"], row["norm_key"]),
                ).fetchall()
                groups.append([common.row_to_entity(m) for m in members])
        return groups

    # ------------------------------------------------ schema registry (D-024)

    def put_schema(self, registration: SchemaRegistration) -> SchemaRegistration:
        with self._tx():
            row = self._conn.execute(
                "SELECT registration_json FROM schemas WHERE namespace = ?",
                (registration.namespace,),
            ).fetchone()
            merged = common.merge_schema(
                common.row_to_schema(row) if row else None, registration)
            self._conn.execute(
                "INSERT OR REPLACE INTO schemas (namespace, registration_json,"
                " updated_at) VALUES (?, ?, ?)",
                (merged.namespace, merged.model_dump_json(),
                 common.iso(common.now())),
            )
            return merged

    def get_schema(self, namespace: str) -> SchemaRegistration | None:
        with self._tx(read=True):
            row = self._conn.execute(
                "SELECT registration_json FROM schemas WHERE namespace = ?",
                (namespace,),
            ).fetchone()
        return common.row_to_schema(row) if row else None

    def iter_schemas(self, namespace: str | None = None) -> Iterator[SchemaRegistration]:
        with self._tx(read=True):
            rows = self._conn.execute(
                "SELECT registration_json FROM schemas"
                + (" WHERE namespace = ?" if namespace else "") + " ORDER BY namespace",
                (namespace,) if namespace else ()).fetchall()
        for r in rows:
            yield common.row_to_schema(r)

    def merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        with self._tx(read=True):
            # a group every pair of which an adjudicator declined is settled:
            # left in, fifty of them filled the limit for good and starved
            # every new candidate (D-058)
            rows = self._conn.execute(
                _MERGE_CANDIDATES_SQL.format(ns="AND e1.namespace = ?" if namespace else ""),
                ((namespace, limit) if namespace else (limit,)),
            ).fetchall()
            groups = []
            for row in rows:
                members = self._conn.execute(
                    "SELECT * FROM entities WHERE namespace = ? AND key = ?"
                    " ORDER BY created_at, type",
                    (row["namespace"], row["key"]),
                ).fetchall()
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
            type_sql = f" AND type IN ({','.join('?' * len(types))})" if types else " AND 0"
            type_args = tuple(types)
        with self._tx(read=True):
            rows = self._conn.execute(
                _SEARCH_SQL + type_sql + " ORDER BY (lower(key) != ?), type, key LIMIT ?",
                (namespace, lowered, lowered + _PREFIX_END, *type_args, lowered, limit),
            ).fetchall()
            label_rows = []
            if labels and lowered:
                exact = json.dumps(lowered)                 # '"domain admins"', as stored lower-cased
                start = exact[:-1]                         # the value's prefix, opening quote kept
                label_rows = self._conn.execute(
                    _LABEL_SQL.format(preds=",".join("?" * len(labels)))
                    + type_sql.replace("type IN", "e.type IN")
                    + " GROUP BY e.id ORDER BY inexact, e.type, e.key LIMIT ?",
                    (exact, namespace, *labels, start, start + _PREFIX_END, *type_args, limit),
                ).fetchall()
        return common.merge_search(rows, label_rows, lowered, limit)

    def count_observations(
        self, namespace: str, ref: EntityRef, observed_before: datetime | None = None,
        allowed_types: tuple[str, ...] | None = None,
    ) -> int:
        with self._tx(read=True):
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return 0
            before_sql, before_args = _observed_before("?", observed_before)
            # a type-scoped caller's count: the far end of each half must be
            # in its types too (the ref's own type is the caller's to check)
            subj_types, obj_types, type_args = "", "", ()
            if allowed_types is not None:
                if not allowed_types:
                    return 0
                tm = ",".join("?" * len(allowed_types))
                subj_types = (" AND (o.object_entity_id IS NULL OR EXISTS (SELECT 1 FROM entities x"
                              f" WHERE x.id = o.object_entity_id AND x.type IN ({tm})))")
                obj_types = f" AND EXISTS (SELECT 1 FROM entities x WHERE x.id = o.subject_id AND x.type IN ({tm}))"
                type_args = tuple(allowed_types)
            # two indexed halves, like observations_for (D-035/D-038)
            row = self._conn.execute(
                "SELECT (SELECT COUNT(*) FROM observations o WHERE o.namespace = ?"
                "          AND o.subject_id = ?" + _NOT_TOMBSTONED + before_sql + subj_types + ")"
                "     + (SELECT COUNT(*) FROM observations o WHERE o.namespace = ?"
                "          AND o.object_entity_id = ? AND o.subject_id != ?" + _NOT_TOMBSTONED
                + before_sql + obj_types + ")"
                " AS n",
                (namespace, entity.id, *before_args, *type_args,
                 namespace, entity.id, entity.id, *before_args, *type_args),
            ).fetchone()
        return int(row["n"])

    def subjects_citing(
        self, namespace: str, artifact_ids: list[str],
        allowed_types: tuple[str, ...] | None = None, per_artifact: int = 5,
    ) -> dict[str, list[EntityRef]]:
        if not artifact_ids:
            return {}
        marks = ",".join("?" * len(artifact_ids))
        type_sql, type_args = "", ()
        if allowed_types is not None:
            if not allowed_types:
                return {}
            tm = ",".join("?" * len(allowed_types))
            type_sql = f" AND s.type IN ({tm}) AND (ob.id IS NULL OR ob.type IN ({tm}))"
            type_args = tuple(allowed_types) * 2
        with self._tx(read=True):
            # the per-artifact cut happens in SQL: a document cited by
            # thousands of claims returns per_artifact rows, not all of them
            rows = self._conn.execute(
                "WITH cited AS ("
                " SELECT DISTINCT json_extract(o.provenance_json, '$.artifact_id') AS aid,"
                " s.type AS stype, s.key AS skey"
                " FROM observations o JOIN entities s ON s.id = o.subject_id"
                " LEFT JOIN entities ob ON ob.id = o.object_entity_id"
                " WHERE o.namespace = ?"
                f"   AND json_extract(o.provenance_json, '$.artifact_id') IN ({marks})"
                + _NOT_TOMBSTONED + type_sql + "),"
                " ranked AS (SELECT *, row_number() OVER (PARTITION BY aid ORDER BY stype, skey) AS rn"
                "            FROM cited)"
                " SELECT aid, stype, skey FROM ranked WHERE rn <= ? ORDER BY aid, stype, skey",
                (namespace, *artifact_ids, *type_args, per_artifact),
            ).fetchall()
        out: dict[str, list[EntityRef]] = {}
        for r in rows:
            out.setdefault(r["aid"], []).append(EntityRef(type=r["stype"], key=r["skey"]))
        return out

    def artifact_cited_within(
        self, namespace: str, artifact_id: str, allowed_types: tuple[str, ...]
    ) -> bool:
        if not allowed_types:
            return False
        marks = ",".join("?" * len(allowed_types))
        with self._tx(read=True):
            row = self._conn.execute(
                "SELECT 1 FROM observations o"
                " JOIN entities s ON s.id = o.subject_id"
                " LEFT JOIN entities ob ON ob.id = o.object_entity_id"
                " WHERE o.namespace = ?"
                "   AND json_extract(o.provenance_json, '$.artifact_id') = ?"
                f"   AND s.type IN ({marks})"
                f"   AND (ob.id IS NULL OR ob.type IN ({marks}))"
                + _NOT_TOMBSTONED
                + " LIMIT 1",
                (namespace, artifact_id, *allowed_types, *allowed_types),
            ).fetchone()
        return row is not None

    def record_claim(self, claim: ClaimIn) -> Observation:
        return self.record_claims([claim])[0]

    def record_claims(self, claims: list[ClaimIn]) -> list[Observation]:
        with self._tx():
            return self._record_batch(claims)

    def observations_for(
        self, namespace: str, ref: EntityRef, limit: int = 100,
        observed_before: datetime | None = None,
    ) -> list[Observation]:
        with self._tx(read=True):
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return []
            before_sql, before_args = _observed_before("?", observed_before)
            # Two indexed halves (idx_obs_subject / idx_obs_object) merged,
            # not `subject_id = ? OR object_entity_id = ?`: SQLite planned the
            # OR as a scan of the whole namespace, ~230 ms per call on a
            # 465k-row namespace — found the day real data landed (D-035).
            # observed_at trails both indexes, so the as_of bound is a range
            # on the same index (D-046).
            rows = self._conn.execute(
                "SELECT * FROM (" + _OBS_SELECT
                + " WHERE o.namespace = ? AND o.subject_id = ?" + _NOT_TOMBSTONED + before_sql
                + " ORDER BY o.observed_at DESC LIMIT ?)"
                " UNION ALL SELECT * FROM (" + _OBS_SELECT
                + " WHERE o.namespace = ? AND o.object_entity_id = ?"
                "   AND o.subject_id != ?" + _NOT_TOMBSTONED + before_sql
                + " ORDER BY o.observed_at DESC LIMIT ?)"
                " ORDER BY observed_at DESC LIMIT ?",
                (namespace, entity.id, *before_args, limit,
                 namespace, entity.id, entity.id, *before_args, limit, limit),
            ).fetchall()
            return [common.row_to_observation(r) for r in rows]

    _MANY_CHUNK = 400

    def _resolve_many(self, namespace: str, refs: list[EntityRef]) -> dict[str, list[EntityRef]]:
        """entity id -> the ref that asked for it, following aliases (D-043)."""
        out: dict[str, list[EntityRef]] = {}
        pending = list(refs)
        for start in range(0, len(pending), self._MANY_CHUNK):
            chunk = pending[start:start + self._MANY_CHUNK]
            marks = ",".join("(?, ?)" for _ in chunk)
            rows = self._conn.execute(
                f"SELECT id, type, key FROM entities WHERE namespace = ? AND (type, key) IN (VALUES {marks})",
                (namespace, *[v for r in chunk for v in (r.type, r.key)])).fetchall()
            found = {(r["type"], r["key"]): r["id"] for r in rows}
            missing = [r for r in chunk if (r.type, r.key) not in found]
            for r in chunk:
                if (r.type, r.key) in found:
                    out.setdefault(found[(r.type, r.key)], []).append(r)
            if missing:
                amarks = ",".join("?" for _ in missing)
                arows = self._conn.execute(
                    f"SELECT a.alias, a.entity_id FROM aliases a WHERE a.namespace = ? AND a.alias IN ({amarks})",
                    (namespace, *[f"{r.type}:{r.key}" for r in missing])).fetchall()
                by_alias = {r["alias"]: r["entity_id"] for r in arows}
                for r in missing:
                    eid = by_alias.get(f"{r.type}:{r.key}")
                    if eid:
                        out.setdefault(eid, []).append(r)
        return out

    # entities per gather statement: two LIMITed subqueries each, kept
    # under SQLITE_MAX_COMPOUND_SELECT (500 terms)
    _GATHER_CHUNK = 200

    def _many_query(self, namespace: str, ids: list[str], limit: int,
                    observed_before: datetime | None,
                    predicates: list[str] | None = None,
                    side: str | None = None) -> tuple[str, tuple]:
        """The `hits` body of the batched gather and its parameters: per
        entity, the newest `limit` rows of each side as its own index range
        with its own LIMIT (idx_obs_subject / idx_obs_object, D-035), so a
        hub with 100k edges contributes 2·limit rows to the window that
        trims per entity — not every edge, per ask (R-9). One generated
        UNION ALL per chunk; the as_of bound rides each range (D-046), and
        so does a predicate filter (D-061)."""
        before_sql, before_args = _observed_before("?", observed_before)
        pred_sql, pred_args = "", ()
        if predicates is not None:
            pred_sql = f" AND o.predicate IN ({','.join('?' * len(predicates))})"
            pred_args = tuple(predicates)
        subj = ("SELECT * FROM (" + _OBS_SELECT_ENT.format(ent="o.subject_id")
                + " WHERE o.namespace = ? AND o.subject_id = ?" + _NOT_TOMBSTONED + before_sql
                + pred_sql + " ORDER BY o.observed_at DESC LIMIT ?)")
        obj = ("SELECT * FROM (" + _OBS_SELECT_ENT.format(ent="o.object_entity_id")
               + " WHERE o.namespace = ? AND o.object_entity_id = ? AND o.subject_id != ?"
               + _NOT_TOMBSTONED + before_sql + pred_sql
               + " ORDER BY o.observed_at DESC LIMIT ?)")
        params: list = []
        parts: list[str] = []
        for eid in ids:
            if side != "object":
                parts.append(subj)
                params += (namespace, eid, *before_args, *pred_args, limit)
            if side != "subject":
                parts.append(obj)
                params += (namespace, eid, eid, *before_args, *pred_args, limit)
        return " UNION ALL ".join(parts), tuple(params)

    def observations_for_many(
        self, namespace: str, refs: list[EntityRef], limit: int = 100,
        observed_before: datetime | None = None,
        predicates: list[str] | None = None,
        side: str | None = None,
    ) -> dict[tuple[str, str], list[Observation]]:
        result: dict[tuple[str, str], list[Observation]] = {}
        if not refs or (predicates is not None and not predicates):
            return result
        with self._tx(read=True):
            owners = self._resolve_many(namespace, refs)
            ids = list(owners)
            for start in range(0, len(ids), self._GATHER_CHUNK):
                chunk = ids[start:start + self._GATHER_CHUNK]
                hits, params = self._many_query(namespace, chunk, limit, observed_before, predicates, side)
                rows = self._conn.execute(
                    "WITH hits AS (" + hits + "),"
                    " ranked AS (SELECT *, row_number() OVER (PARTITION BY ent ORDER BY observed_at DESC) AS rn FROM hits)"
                    " SELECT * FROM ranked WHERE rn <= ? ORDER BY ent, observed_at DESC",
                    (*params, limit),
                ).fetchall()
                for row in rows:
                    obs = common.row_to_observation(row)
                    for ref in owners[row["ent"]]:
                        result.setdefault((ref.type, ref.key), []).append(obs)
        return result

    def subjects_with_value(
        self, namespace: str, predicate: str, value_json: str | None = None,
        limit: int = 100_000, observed_before: datetime | None = None,
    ) -> list[EntityRef]:
        """idx_obs_label serves it: (namespace, predicate, the value's
        lower-cased JSON text) — the expression written verbatim so the index
        applies (D-107)."""
        before_sql, before_args = _observed_before("?", observed_before)
        value_sql, value_args = "", ()
        if value_json is not None:
            value_sql, value_args = " AND lower(substr(o.object_json, 1, 200)) = ?", (value_json.lower()[:200],)
        sql = ("SELECT DISTINCT e.type, e.key FROM observations o JOIN entities e ON e.id = o.subject_id"
               " WHERE o.namespace = ? AND o.predicate = ? AND o.object_entity_id IS NULL"
               + value_sql + before_sql + _NOT_TOMBSTONED + " LIMIT ?")
        with self._tx(read=True):
            rows = self._conn.execute(sql, (namespace, predicate, *value_args, *before_args, limit)).fetchall()
        return [EntityRef(type=r["type"], key=r["key"]) for r in rows]

    def entity_refs_of_type(self, namespace: str, type: str, limit: int = 100_000) -> list[EntityRef]:
        with self._tx(read=True):
            rows = self._conn.execute(
                "SELECT key FROM entities WHERE namespace = ? AND type = ? ORDER BY key LIMIT ?",
                (namespace, type, limit)).fetchall()
        return [EntityRef(type=type, key=r["key"]) for r in rows]

    _LITE_FROM = (" FROM observations o JOIN entities s ON s.id = o.subject_id"
                  " LEFT JOIN entities oe ON oe.id = o.object_entity_id")

    def _label_index(self) -> str:
        """' INDEXED BY idx_obs_label' when the index exists. A predicate's
        rows ordered or partitioned by subject made the planner walk the
        namespace's whole subject index (6.5M rows at 500k, every row's
        predicate checked) to skip one sort: list mode's `contains` scans
        took 1-2 hours on the final A/B's 500k forest. The label range plus
        a sort of that predicate's rows is what is wanted. Absent (a bulk
        load deferring it into an empty store, D-105), no hint."""
        with self._tx(read=True):
            found = self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_obs_label'").fetchone()
        return " INDEXED BY idx_obs_label" if found else ""

    def lite_rows(
        self, namespace: str, refs: list[EntityRef], predicates: list[str], side: str = "subject",
        limit: int = 1_000_000, observed_before: datetime | None = None,
    ) -> list[common.LiteRow]:
        """One indexed IN-list read per chunk on the side's index
        (idx_obs_subject / idx_obs_object), every row, no window (D-107)."""
        if not refs or not predicates:
            return []
        col = "o.subject_id" if side == "subject" else "o.object_entity_id"
        before_sql, before_args = _observed_before("?", observed_before)
        out: list[common.LiteRow] = []
        with self._tx(read=True):
            ids = list(self._resolve_many(namespace, refs))
            for start in range(0, len(ids), self._MANY_CHUNK):
                chunk = ids[start:start + self._MANY_CHUNK]
                sql = ("SELECT " + common.LITE_COLS + self._LITE_FROM
                       + f" WHERE o.namespace = ? AND {col} IN ({','.join(['?'] * len(chunk))})"
                       + f" AND o.predicate IN ({','.join(['?'] * len(predicates))})"
                       + before_sql + _NOT_TOMBSTONED + " LIMIT ?")
                rows = self._conn.execute(
                    sql, (namespace, *chunk, *predicates, *before_args, limit - len(out))).fetchall()
                out.extend(common.lite_row(r) for r in rows)
                if len(out) >= limit:
                    break
        return out

    def lite_scalars(
        self, namespace: str, predicate: str, observed_before: datetime | None = None,
    ) -> Iterator[common.LiteRow]:
        """One idx_obs_label range, ordered by subject, streamed (D-107)."""
        before_sql, before_args = _observed_before("?", observed_before)
        from_ = self._LITE_FROM.replace(" o JOIN", f" o{self._label_index()} JOIN", 1)
        sql = ("SELECT " + common.LITE_COLS + from_
               + " WHERE o.namespace = ? AND o.predicate = ? AND o.object_entity_id IS NULL"
               + before_sql + _NOT_TOMBSTONED + " ORDER BY o.subject_id")
        params = (namespace, predicate, *before_args)
        with self._tx(read=True):
            cur = self._conn.execute(sql, params)
            while True:
                rows = cur.fetchmany(5000)
                if not rows:
                    return
                for r in rows:
                    yield common.lite_row(r)

    def current_scalar_subjects(
        self, namespace: str, predicate: str, value_jsons: list[str] | None = None,
        observed_before: datetime | None = None, valid_at: datetime | None = None,
    ) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
        """The newest snapshot per subject ranked in SQL over idx_obs_label's
        range (D-111): only (type, key, matched) per subject comes back."""
        before_sql, before_args = _observed_before("?", observed_before)
        valid_sql, valid_args = "", ()
        if valid_at is not None:
            v = common.iso(valid_at)
            valid_sql = (" AND (o.valid_from IS NULL OR o.valid_from <= ?)"
                         " AND (o.valid_to IS NULL OR o.valid_to > ?)")
            valid_args = (v, v)
        wanted = sorted({w.lower()[:200] for w in (value_jsons or [])})
        hit = (f"MAX(CASE WHEN cur.v IN ({','.join(['?'] * len(wanted))}) THEN 1 ELSE 0 END)"
               if wanted else "0")
        sql = ("WITH cur AS (SELECT o.subject_id, lower(substr(o.object_json, 1, 200)) AS v,"
               " RANK() OVER (PARTITION BY o.subject_id ORDER BY o.observed_at DESC) AS rk"
               " FROM observations o" + self._label_index()
               + " WHERE o.namespace = ? AND o.predicate = ? AND o.object_entity_id IS NULL"
               + before_sql + valid_sql
               + " AND o.source NOT LIKE 'doc:%%' AND coalesce(json_extract(o.attrs_json, '$.extracted'), 0) IN (0, 'false')" + _NOT_TOMBSTONED + ")"
               " SELECT e.type AS type, e.key AS key, " + hit + " AS hit"
               " FROM cur JOIN entities e ON e.id = cur.subject_id WHERE cur.rk = 1 GROUP BY e.type, e.key")
        params = (namespace, predicate, *before_args, *valid_args, *wanted)
        with self._tx(read=True):
            rows = self._conn.execute(sql, params).fetchall()
        any_ = {(r["type"], r["key"]) for r in rows}
        return any_, {(r["type"], r["key"]) for r in rows if r["hit"]}

    def first_observed(self, namespace: str) -> datetime | None:
        with self._tx(read=True):
            row = self._conn.execute("SELECT min(observed_at) FROM observations WHERE namespace = ?",
                                     (namespace,)).fetchone()
        return common.parse(row[0]) if row and row[0] else None

    def subjects_with_text(
        self, namespace: str, predicate: str, needle: str, limit: int = 100_000,
        observed_before: datetime | None = None,
    ) -> list[EntityRef]:
        """LIKE on idx_obs_label's lower-cased text: the predicate's index
        range, matched without reading the rows (D-110). A value the index
        cut at 200 characters is always returned: the needle may lie past
        the cut, and the caller's filter decides."""
        before_sql, before_args = _observed_before("?", observed_before)
        pattern = "%" + needle.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        sql = ("SELECT DISTINCT e.type, e.key FROM observations o" + self._label_index()
               + " JOIN entities e ON e.id = o.subject_id"
               " WHERE o.namespace = ? AND o.predicate = ? AND o.object_entity_id IS NULL"
               " AND (lower(substr(o.object_json, 1, 200)) LIKE ? ESCAPE '\\' OR length(lower(substr(o.object_json, 1, 200))) = 200)"
               + before_sql + _NOT_TOMBSTONED + " LIMIT ?")
        with self._tx(read=True):
            rows = self._conn.execute(sql, (namespace, predicate, pattern, *before_args, limit)).fetchall()
        return [EntityRef(type=r["type"], key=r["key"]) for r in rows]

    def edges_to_carriers(
        self, namespace: str, hubs: list[EntityRef], via: list[str], predicates: list[str],
        limit: int = 10_000, observed_before: datetime | None = None,
    ) -> list[tuple[tuple[str, str], str, str]]:
        """One join per hub side (D-061): the hub's newest `limit` edges on
        `via` from its own index range (idx_obs_object inbound, idx_obs_subject
        outbound), each far end's rows on `predicates` from idx_obs_subject.
        Only matching id pairs leave the database."""
        out: list[tuple[tuple[str, str], str, str]] = []
        if not hubs or not via or not predicates:
            return out
        with self._tx(read=True):
            owners = self._resolve_many(namespace, hubs)
            for eid, refs in owners.items():
                rows: list = []
                for inbound in (True, False):
                    sql, params = self._carriers_query(namespace, eid, inbound, via, predicates,
                                                       limit, observed_before)
                    rows += self._conn.execute(sql, params).fetchall()
                rows.sort(key=lambda r: (r["at"], r["edge_id"]), reverse=True)
                for ref in refs:
                    out.extend(((ref.type, ref.key), r["edge_id"], r["attr_id"]) for r in rows)
        return out

    @staticmethod
    def _carriers_query(namespace: str, eid: str, inbound: bool, via: list[str], predicates: list[str],
                        limit: int, observed_before: datetime | None) -> tuple[str, tuple]:
        """The join for one hub side. CROSS JOIN fixes the order — the
        hub's edges outside, the far end's rows inside: left to itself, the
        planner walked the namespace's whole observation table (7 s on the
        vulns corpus) instead of 2,785 index probes (19 ms)."""
        before_sql, before_args = _observed_before("?", observed_before)
        attr_before = before_sql.replace("o.observed_at", "a.observed_at")
        if inbound:
            where, far = "o.object_entity_id = ? AND o.subject_id != ?", "o.subject_id"
        else:
            where, far = ("o.subject_id = ? AND o.object_entity_id IS NOT NULL AND o.object_entity_id != ?",
                          "o.object_entity_id")
        sql = ("SELECT e.id AS edge_id, e.observed_at AS at, a.id AS attr_id FROM ("
               f"SELECT o.id, o.observed_at, {far} AS far FROM observations o"
               f" WHERE o.namespace = ? AND {where} AND o.predicate IN ({','.join('?' * len(via))})"
               + _NOT_TOMBSTONED + before_sql + " ORDER BY o.observed_at DESC LIMIT ?) e"
               " CROSS JOIN observations a ON a.namespace = ? AND a.subject_id = e.far"
               f" AND a.predicate IN ({','.join('?' * len(predicates))}) AND a.id != e.id"
               " AND NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.observation_id = a.id)"
               + attr_before)
        return sql, (namespace, eid, eid, *via, *before_args, limit, namespace, *predicates, *before_args)

    def store_artifact(self, doc: DocumentIn) -> Artifact:
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
        with self._tx(read=True):
            return self._artifact_by_event(namespace, event_id)

    def get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        with self._tx(read=True):
            return self._get_artifact(namespace, artifact_id)

    def ping(self) -> bool:
        try:
            with self._tx():
                self._conn.execute("SELECT 1").fetchone()
            with self._tx(read=True):
                self._conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    # ----------------------------------------------------- enrichment (D-018)

    def put_embeddings(
        self, namespace: str, model: str,
        items: list[tuple[str, list[float]]],
    ) -> None:
        with self._tx():
            self._conn.executemany(
                "INSERT OR REPLACE INTO embeddings (ref_id, namespace, model,"
                " vector) VALUES (?, ?, ?, ?)",
                [(ref_id, namespace, model, common.pack_vector(vec))
                 for ref_id, vec in items],
            )
            self._vec_upsert("vobs", model, namespace,
                             [(ref_id, None, vec) for ref_id, vec in items])

    def embeddings_for(
        self, namespace: str, ref_ids: list[str], model: str
    ) -> dict[str, list[float]]:
        result: dict[str, list[float]] = {}
        with self._tx(read=True):
            for start in range(0, len(ref_ids), 500):
                chunk = ref_ids[start:start + 500]
                rows = self._conn.execute(
                    "SELECT ref_id, vector FROM embeddings"
                    f" WHERE namespace = ? AND model = ?"
                    f" AND ref_id IN ({','.join('?' * len(chunk))})",
                    (namespace, model, *chunk),
                ).fetchall()
                for row in rows:
                    result[row["ref_id"]] = common.unpack_array(row["vector"])
        return result

    # hex value of the id's last character, 0..15: the shard key (D-031)
    _SHARD_EXPR = "(instr('0123456789abcdef', substr(o.id, -1, 1)) - 1)"

    def observations_without_embeddings(
        self, model: str, limit: int = 128, shard: tuple[int, int] | None = None
    ) -> list[Observation]:
        shard_sql, shard_args = "", ()
        if shard is not None and shard[1] > 1:
            shard_sql, shard_args = f" AND {self._SHARD_EXPR} % ? = ?", (shard[1], shard[0])
        key = f"hwm:embed:{model}:{shard[0]}/{shard[1]}" if shard_sql else f"hwm:embed:{model}:0/1"
        with self._tx():
            start = self._hwm_start(key)
            rows = self._conn.execute(
                _EMBED_BACKLOG_SQL.format(shard=shard_sql),
                (start, model, *shard_args, limit),
            ).fetchall()
            self._hwm_advance(key, "observations", rows[0]["recorded_at"] if rows else None)
            return [common.row_to_observation(r) for r in rows]

    # ---------------------------------------- tick-scan high-water marks (R-9)
    # A worker tick used to walk the whole table in recorded_at order with a
    # per-row anti-join, so an idle fleet re-examined every embedded row every
    # few seconds. The persisted mark (loomctx_meta, one per model and shard)
    # bounds the walk to rows recorded since the previous tick. The mark is
    # kept `_HWM_SLACK` rows below the oldest row a tick still needs — or the
    # newest row when nothing is pending — so writers with skewed clocks and
    # a batch that failed after it was fetched are re-examined; it never moves
    # back (max on write, so two workers on one partition cannot regress it).
    # Every `_RESCAN_EVERY`-th tick — and a process's first — walks from the
    # beginning, which is how a backfilled row (an import with an old
    # recorded_at) is found. `wipe()` forgets the marks.
    _HWM_SLACK = 1000
    _RESCAN_EVERY = 16

    def _hwm_start(self, key: str) -> str:
        """The recorded_at to scan from on this tick ('' = from the start)."""
        n = self._ticks.get(key, 0)
        self._ticks[key] = n + 1
        if n % self._RESCAN_EVERY == 0:
            return ""
        row = self._conn.execute("SELECT value FROM loomctx_meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else ""

    def _hwm_advance(self, key: str, table: str, top: str | None) -> None:
        """Persist the mark `_HWM_SLACK` rows below `top` (the oldest row
        this tick still needs; None = everything up to the newest row was
        examined). Never moves back."""
        if top is None:
            top = self._conn.execute(f"SELECT MAX(recorded_at) AS m FROM {table}").fetchone()["m"]
            if top is None:
                return
        row = self._conn.execute(
            f"SELECT recorded_at FROM {table} WHERE recorded_at <= ?"
            " ORDER BY recorded_at DESC LIMIT 1 OFFSET ?", (top, self._HWM_SLACK)).fetchone()
        if row is None:
            return
        self._conn.execute(
            "INSERT INTO loomctx_meta (key, value) VALUES (?, ?)"
            " ON CONFLICT (key) DO UPDATE SET value = max(value, excluded.value)",
            (key, row["recorded_at"]))

    def _hwm_reset(self, key: str) -> None:
        """Forget a mark: the next tick scans from the beginning (a dropped
        dossier must be rebuilt without waiting for the periodic rescan)."""
        self._conn.execute("DELETE FROM loomctx_meta WHERE key = ?", (key,))

    def pending_artifacts(
        self, limit: int = 4, now: datetime | None = None,
        lease: tuple[str, float] | None = None,
    ) -> list[Artifact]:
        moment = now or common.now()
        now_iso = common.iso(moment)
        with self._tx():
            if lease is None:
                rows = self._conn.execute(
                    "SELECT * FROM artifacts WHERE extraction_status = 'pending'"
                    " AND (next_attempt_at IS NULL OR next_attempt_at <= ?)"
                    " ORDER BY recorded_at LIMIT ?",
                    (now_iso, limit),
                ).fetchall()
            else:
                worker, seconds = lease
                until = common.iso(moment + timedelta(seconds=seconds))
                # claim atomically: one UPDATE selects and marks in one step,
                # so two workers can never both take the same artifact
                rows = self._conn.execute(
                    "UPDATE artifacts SET extract_claimed_by = ?, extract_claimed_until = ?"
                    " WHERE id IN (SELECT id FROM artifacts"
                    "   WHERE extraction_status = 'pending'"
                    "   AND (next_attempt_at IS NULL OR next_attempt_at <= ?)"
                    "   AND (extract_claimed_until IS NULL OR extract_claimed_until < ?)"
                    "   ORDER BY recorded_at LIMIT ?) RETURNING *",
                    (worker, until, now_iso, now_iso, limit),
                ).fetchall()
        return sorted((common.row_to_artifact(r) for r in rows), key=lambda a: a.recorded_at)

    # lease ownership (D-031): `worker_id=None` is unconditional (ops,
    # tests, a single worker); given, the statement applies only while that
    # worker holds the lease, so a holder whose lease expired and was
    # re-claimed cannot clobber the new holder's state
    # a worker releases only its own lease; an artifact nobody leased (direct
    # calls, `--once` on a fresh row) has no owner to protect (D-049)
    _OWNS_EXTRACT = " AND (? IS NULL OR extract_claimed_by IS NULL OR extract_claimed_by = ?)"

    def defer_extraction(
        self, namespace: str, artifact_id: str, attempts: int, next_attempt_at: datetime,
        worker_id: str | None = None,
    ) -> bool:
        with self._tx():
            return self._conn.execute(
                "UPDATE artifacts SET extraction_attempts = ?, next_attempt_at = ?,"
                " extract_claimed_until = NULL WHERE namespace = ? AND id = ?" + self._OWNS_EXTRACT,
                (attempts, common.iso(next_attempt_at), namespace, artifact_id, worker_id, worker_id),
            ).rowcount > 0

    def set_extraction_status(
        self, namespace: str, artifact_id: str, status: str, worker_id: str | None = None,
    ) -> bool:
        with self._tx():
            return self._conn.execute(
                "UPDATE artifacts SET extraction_status = ?, extract_claimed_until = NULL"
                " WHERE namespace = ? AND id = ?" + self._OWNS_EXTRACT,
                (status, namespace, artifact_id, worker_id, worker_id),
            ).rowcount > 0

    def extend_extraction_lease(
        self, namespace: str, artifact_id: str, worker_id: str, seconds: float
    ) -> bool:
        with self._tx():
            return self._conn.execute(
                "UPDATE artifacts SET extract_claimed_until = ? WHERE namespace = ? AND id = ?"
                " AND extract_claimed_by = ? AND extraction_status = 'pending'",
                (common.iso(common.now() + timedelta(seconds=seconds)), namespace, artifact_id, worker_id),
            ).rowcount > 0

    _NEEDS_CHUNKS = (
        "a.recorded_at >= ? AND a.text IS NOT NULL"   # from the high-water mark (R-9)
        # blank docs would re-queue forever (H-D4); TRIM alone strips only
        # spaces, so name the whitespace set explicitly
        " AND TRIM(a.text, ' ' || char(9) || char(10) || char(13)) <> ''"
        " AND NOT EXISTS (SELECT 1 FROM doc_chunks c"
        "   WHERE c.artifact_id = a.id AND c.model = ?)"
    )

    def artifacts_needing_chunks(
        self, model: str, limit: int = 4, lease: tuple[str, float] | None = None
    ) -> list[Artifact]:
        key = f"hwm:chunks:{model}"
        with self._tx():
            start = self._hwm_start(key)
            if lease is None:
                rows = self._conn.execute(
                    f"SELECT * FROM artifacts a WHERE {self._NEEDS_CHUNKS}"
                    " ORDER BY a.recorded_at LIMIT ?", (start, model, limit)).fetchall()
            else:
                moment = common.now()
                until = common.iso(moment + timedelta(seconds=lease[1]))
                rows = self._conn.execute(
                    "UPDATE artifacts SET chunk_claimed_until = ?, chunk_claimed_by = ? WHERE id IN"
                    f" (SELECT a.id FROM artifacts a WHERE {self._NEEDS_CHUNKS}"
                    "   AND (a.chunk_claimed_until IS NULL OR a.chunk_claimed_until < ?)"
                    "   ORDER BY a.recorded_at LIMIT ?) RETURNING *",
                    (until, lease[0], start, model, common.iso(moment), limit)).fetchall()
            self._hwm_advance(key, "artifacts", min((r["recorded_at"] for r in rows), default=None))
        return sorted((common.row_to_artifact(r) for r in rows), key=lambda a: a.recorded_at)

    def put_doc_chunks(
        self, namespace: str, artifact_id: str, model: str,
        chunks: list[tuple[int, int, int, str, list[float]]],
        worker_id: str | None = None,
    ) -> None:
        with self._tx():
            self._conn.executemany(
                "INSERT OR REPLACE INTO doc_chunks (id, namespace, artifact_id,"
                " seq, span_start, span_end, text, vector, model)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(f"{artifact_id}:{model}:{seq}", namespace, artifact_id, seq,
                  start, end, text, common.pack_vector(vec), model)
                 for seq, start, end, text, vec in chunks],
            )
            self._vec_upsert("vchk", model, namespace,
                             [(f"{artifact_id}:{model}:{seq}", artifact_id, vec)
                              for seq, _, _, _, vec in chunks])
            self._conn.execute(  # release the chunking lease (D-031) — the holder's only
                "UPDATE artifacts SET chunk_claimed_until = NULL WHERE id = ?"
                " AND (? IS NULL OR chunk_claimed_by IS NULL OR chunk_claimed_by = ?)",
                (artifact_id, worker_id, worker_id))

    def doc_chunks_for_artifacts(
        self, namespace: str, artifact_ids: list[str], model: str
    ) -> list[dict]:
        if not artifact_ids:
            return []
        out = []
        with self._tx(read=True):
            for start in range(0, len(artifact_ids), 400):
                chunk = artifact_ids[start:start + 400]
                rows = self._conn.execute(
                    "SELECT c.artifact_id, c.seq, c.span_start, c.span_end,"
                    " c.text, c.vector, a.source, a.observed_at"
                    " FROM doc_chunks c JOIN artifacts a ON a.id = c.artifact_id"
                    f" WHERE c.namespace = ? AND c.model = ?"
                    f" AND c.artifact_id IN ({','.join('?' * len(chunk))})",
                    (namespace, model, *chunk),
                ).fetchall()
                out.extend(common.row_to_chunk(r) for r in rows)
        return out

    def doc_chunks_by_seq(
        self, namespace: str, artifact_id: str, model: str, seqs: list[int]
    ) -> list[dict]:
        if not seqs:
            return []
        with self._tx(read=True):
            rows = self._conn.execute(
                "SELECT c.artifact_id, c.seq, c.span_start, c.span_end,"
                " c.text, c.vector, a.source, a.observed_at"
                " FROM doc_chunks c JOIN artifacts a ON a.id = c.artifact_id"
                " WHERE c.namespace = ? AND c.artifact_id = ? AND c.model = ?"
                f" AND c.seq IN ({','.join('?' * len(seqs))}) ORDER BY c.seq",
                (namespace, artifact_id, model, *seqs),
            ).fetchall()
        return [common.row_to_chunk(r) for r in rows]

    def get_dossier(self, namespace: str, ref: EntityRef) -> dict | None:
        with self._tx(read=True):
            entity = self._resolve_entity(namespace, ref)  # aliases too (H-B6)
            if entity is None:
                return None
            row = self._conn.execute(
                "SELECT brief, observation_count, observation_ids, updated_at"
                " FROM dossiers WHERE namespace = ? AND entity_id = ?",
                (namespace, entity.id),
            ).fetchone()
        if row is None:
            return None
        return common.row_to_dossier(row)

    def put_dossier(
        self, namespace: str, ref: EntityRef, brief: str,
        observation_count: int, observation_ids: list[str],
        worker_id: str | None = None,
    ) -> bool:
        with self._tx():
            entity = self._resolve_or_create(namespace, ref)
            if worker_id is not None:
                holder = self._conn.execute(
                    "SELECT dossier_claimed_by FROM entities WHERE id = ?", (entity.id,)).fetchone()
                if holder["dossier_claimed_by"] not in (None, worker_id):
                    return False   # re-claimed by another worker: its brief is the one to land
            self._conn.execute(
                "INSERT OR REPLACE INTO dossiers (namespace, entity_id, brief,"
                " observation_count, observation_ids, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (namespace, entity.id, brief, observation_count,
                 json.dumps(list(observation_ids)), common.iso(common.now())),
            )
            self._conn.execute(  # release the dossier lease (D-031)
                "UPDATE entities SET dossier_claimed_until = NULL WHERE id = ?", (entity.id,))
            return True

    _DOSSIER_HWM = "hwm:dossier"

    def dossier_candidates(
        self, min_new: int = 20, min_total: int = 5, limit: int = 4,
        lease: tuple[str, float] | None = None,
    ) -> list[tuple[str, EntityRef, int]]:
        moment = common.now()
        with self._tx():
            # Candidates are evaluated among the entities touched since the
            # mark (see _DOSSIER_SQL); total counts for the few winners come
            # after. The mark advances only when the tick did not fill its
            # limit — a backlog is re-evaluated in full until it drains.
            start = self._hwm_start(self._DOSSIER_HWM)
            rows = self._conn.execute(
                _DOSSIER_SQL, (start, common.iso(moment), min_total, min_new, limit),
            ).fetchall()
            if len(rows) < limit:
                self._hwm_advance(self._DOSSIER_HWM, "observations", None)
            out = []
            for r in rows:
                ref = EntityRef(type=r["type"], key=r["key"])
                if lease is not None:
                    claimed = self._conn.execute(
                        "UPDATE entities SET dossier_claimed_until = ?, dossier_claimed_by = ? WHERE id = ?"
                        " AND (dossier_claimed_until IS NULL OR dossier_claimed_until < ?)",
                        (common.iso(moment + timedelta(seconds=lease[1])), lease[0], r["eid"],
                         common.iso(moment))).rowcount
                    if not claimed:
                        continue  # another worker took it between SELECT and UPDATE
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM observations o WHERE o.subject_id = ?"
                    + _NOT_TOMBSTONED, (r["eid"],)).fetchone()["n"]
                out.append((r["namespace"], ref, int(total)))
        return out

    # ------------------------------------------------------ lifecycle (D-016)

    def redact(self, namespace: str, observation_id: str, reason: str) -> bool:
        with self._tx():
            row = self._conn.execute(
                "SELECT 1 FROM observations WHERE id = ? AND namespace = ?",
                (observation_id, namespace),
            ).fetchone()
            if row is None:
                return False
            self._put_tombstone(namespace, observation_id, reason, common.now())
            self._drop_briefs_citing(namespace, observation_id)
            self._hwm_reset(self._DOSSIER_HWM)   # a dropped brief is rebuilt next tick
            return True

    def _drop_briefs_citing(self, namespace: str, observation_id: str) -> None:
        """A brief synthesized from a redacted observation may still be
        quoting it; drop it and let the worker rebuild from what remains
        (H-D8) — on redact and on a restored tombstone alike (D-058)."""
        dropped = self._conn.execute(
            "DELETE FROM dossiers WHERE namespace = ? AND observation_ids LIKE ?",
            (namespace, f'%"{observation_id}"%'),
        ).rowcount
        if dropped:
            self._hwm_reset(self._DOSSIER_HWM)

    def purge_older_than(self, namespace: str, before: datetime) -> int:
        cutoff = common.iso(before)
        with self._tx():
            removed = self._conn.execute(
                "DELETE FROM observations WHERE namespace = ? AND observed_at < ?",
                (namespace, cutoff),
            ).rowcount
            removed += self._conn.execute(
                "DELETE FROM artifacts WHERE namespace = ? AND observed_at < ?",
                (namespace, cutoff),
            ).rowcount
            # derived rows that hung off what we just removed (H-B7)
            self._conn.execute(
                "DELETE FROM tombstones WHERE observation_id NOT IN"
                " (SELECT id FROM observations)"
            )
            self._conn.execute(
                "DELETE FROM embeddings WHERE ref_id NOT IN"
                " (SELECT id FROM observations)"
            )
            self._conn.execute(
                "DELETE FROM doc_chunks WHERE artifact_id NOT IN"
                " (SELECT id FROM artifacts)"
            )
            self._conn.execute(
                "DELETE FROM dossiers WHERE namespace = ? AND entity_id NOT IN"
                " (SELECT subject_id FROM observations WHERE namespace = ?)",
                (namespace, namespace),
            )
            self._purge_vec_rows(namespace)
        return removed

    def _purge_vec_rows(self, namespace: str) -> None:
        """ANN rows whose source row is gone: they would otherwise keep
        surfacing purged observation ids and chunk ids that no longer
        join to anything."""
        if not self._vec:
            return
        self._refresh_vec_tables()
        for name in list(self._vec_tables):
            source = "observations" if name.startswith("vobs_") else "doc_chunks"
            stale = self._conn.execute(
                f"SELECT ref_id FROM {name} WHERE namespace = ?"
                f" AND ref_id NOT IN (SELECT id FROM {source})", (namespace,)).fetchall()
            self._conn.executemany(f"DELETE FROM {name} WHERE ref_id = ?",
                                   [(r["ref_id"],) for r in stale])

    # Exports stream in keyset pages (H-E4): the lock is held per page, not
    # for the whole table, and memory is bounded by the page size.
    _PAGE = 1000

    def _pages(self, sql: str, params: tuple, order_cols: tuple[str, str]):
        last = ("", "")
        while True:
            with self._tx(read=True):
                rows = self._conn.execute(
                    sql + f" AND ({order_cols[0]}, {order_cols[1]}) > (?, ?)"
                    f" ORDER BY {order_cols[0]}, {order_cols[1]} LIMIT ?",
                    (*params, *last, self._PAGE),
                ).fetchall()
            if not rows:
                return
            yield from rows
            tail = rows[-1]
            last = (tail[order_cols[0].split(".")[-1]], tail["id"])

    def iter_observations(
        self, namespace: str | None = None
    ) -> Iterator[Observation]:
        sql = _OBS_SELECT + " WHERE 1=1" + (" AND o.namespace = ?" if namespace else "")
        for row in self._pages(sql, (namespace,) if namespace else (),
                               ("o.recorded_at", "o.id")):
            yield common.row_to_observation(row)

    def relation_summary(self, namespace: str) -> list[tuple[str, str, str | None, int]]:
        key = common.SUMMARY_KEY.format(namespace=namespace)
        with self._tx(read=True):
            marker = "|".join(str(v) for v in self._conn.execute(
                "SELECT (SELECT max(rowid) FROM observations), (SELECT count(*) FROM tombstones),"
                " (SELECT count(*) FROM merge_log)").fetchone())
            cached = self._conn.execute("SELECT value FROM loomctx_meta WHERE key = ?", (key,)).fetchone()
        hit = common.cached_summary(cached["value"] if cached else None, marker)
        if hit is not None:
            return hit
        sql = ("SELECT s.type AS stype, o.predicate AS predicate, e.type AS otype, COUNT(*) AS n"
               " FROM observations o JOIN entities s ON s.id = o.subject_id"
               " LEFT JOIN entities e ON e.id = o.object_entity_id"
               " WHERE o.namespace = ?"
               " AND NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.observation_id = o.id)"
               " GROUP BY s.type, o.predicate, e.type")
        with self._tx(read=True):
            rows = self._conn.execute(sql, (namespace,)).fetchall()
        out = sorted(((r["stype"], r["predicate"], r["otype"], int(r["n"])) for r in rows),
                     key=lambda r: (-r[3], r[0], r[1], r[2] or ""))
        try:
            with self._tx():
                self._conn.execute("INSERT INTO loomctx_meta (key, value) VALUES (?, ?)"
                                   " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                                   (key, common.summary_value(marker, out)))
        except sqlite3.Error:   # a read-only store still answers; it just can't remember
            pass
        return out

    def namespace_summary(self) -> dict[str, dict[str, int]]:
        with self._tx(read=True):
            rows = self._conn.execute(
                "SELECT namespace, type, COUNT(*) AS n FROM entities"
                " GROUP BY namespace, type ORDER BY namespace, type").fetchall()
        out: dict[str, dict[str, int]] = {}
        for r in rows:
            out.setdefault(r["namespace"], {})[r["type"]] = int(r["n"])
        return out

    def iter_entities(
        self, namespace: str | None = None, since: datetime | None = None
    ) -> Iterator[Entity]:
        sql = ("SELECT * FROM entities WHERE 1=1" + (" AND namespace = ?" if namespace else "")
               + (" AND created_at >= ?" if since else ""))
        params = (*((namespace,) if namespace else ()), *((common.iso(since),) if since else ()))
        for row in self._pages(sql, params, ("created_at", "id")):
            yield common.row_to_entity(row)

    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]:
        sql = "SELECT * FROM artifacts WHERE 1=1" + (" AND namespace = ?" if namespace else "")
        for row in self._pages(sql, (namespace,) if namespace else (),
                               ("recorded_at", "id")):
            yield common.row_to_artifact(row)

    def iter_aliases(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx(read=True):
            rows = self._conn.execute(
                "SELECT a.namespace, a.alias, e.type, e.key"
                " FROM aliases a JOIN entities e ON e.id = a.entity_id"
                + (" WHERE a.namespace = ?" if namespace else "")
                + " ORDER BY a.namespace, a.alias",
                (namespace,) if namespace else (),
            ).fetchall()
        for r in rows:
            yield {"namespace": r["namespace"], "alias": r["alias"],
                   "canonical": {"type": r["type"], "key": r["key"]}}

    def remember_decline(self, namespace: str, a: str, b: str, reason: str,
                         decided_at: datetime | None = None) -> None:
        a, b = sorted((a, b))
        with self._tx():
            self._conn.execute(
                "INSERT OR REPLACE INTO resolution_declines (namespace, a, b, reason, decided_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (namespace, a, b, reason[:500], common.iso(decided_at or common.now())))

    def forget_decline(self, namespace: str, a: str, b: str) -> bool:
        a, b = sorted((a, b))
        with self._tx():
            cur = self._conn.execute(
                "DELETE FROM resolution_declines WHERE namespace = ? AND a = ? AND b = ?",
                (namespace, a, b))
            return cur.rowcount > 0

    def iter_declines(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx(read=True):
            rows = self._conn.execute(
                "SELECT * FROM resolution_declines"
                + (" WHERE namespace = ?" if namespace else "") + " ORDER BY namespace, a, b",
                (namespace,) if namespace else ()).fetchall()
        for r in rows:
            yield {"namespace": r["namespace"], "a": r["a"], "b": r["b"],
                   "reason": r["reason"], "decided_at": r["decided_at"]}

    def declined_pairs(self, namespace: str) -> set[tuple[str, str]]:
        with self._tx(read=True):
            rows = self._conn.execute(
                "SELECT a, b FROM resolution_declines WHERE namespace = ?", (namespace,)).fetchall()
        return {(r["a"], r["b"]) for r in rows}

    def iter_tombstones(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx(read=True):
            rows = self._conn.execute(
                "SELECT * FROM tombstones"
                + (" WHERE namespace = ?" if namespace else "")
                + " ORDER BY recorded_at, observation_id",
                (namespace,) if namespace else (),
            ).fetchall()
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
            # OR IGNORE covers BOTH the id PK and the (namespace, event_id)
            # unique index, so a re-import never crashes (H-B11)
            self._conn.execute(
                _OBS_INSERT.replace("INSERT INTO", "INSERT OR IGNORE INTO"),
                self._obs_row(obs, subject.id, object_json, object_entity_id),
            )

    def restore_artifact(self, artifact: Artifact) -> None:
        with self._tx():
            self._insert_artifact(artifact, or_ignore=True)

    def restore_entity(self, entity: Entity) -> None:
        with self._tx():
            self._conn.execute(
                "INSERT OR IGNORE INTO entities (id, namespace, type, key,"
                " provisional, created_at, norm_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (uuid.uuid4().hex, entity.namespace, entity.type, entity.key,
                 int(entity.provisional), common.iso(entity.created_at),
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

    def refresh_statistics(self) -> None:
        """ANALYZE after a bulk load (D-081, now for SQLite too): without
        sqlite_stat1 the planner chooses indexes blind — at 6.5M observations
        it served a 12-hex cite lookup from the namespace index, scanning every
        row. analysis_limit samples each index, so this stays quick at size."""
        with self._tx():
            self._conn.execute("PRAGMA analysis_limit=1000")
            self._conn.execute("ANALYZE")

    def wipe(self) -> None:
        with self._tx():
            for table in ("tombstones", "embeddings", "dossiers", "doc_chunks",
                          "merge_log_observations", "merge_log", "observations",
                          "aliases", "artifacts", "entities", "schemas",
                          "resolution_declines", *self._vec_tables):
                self._conn.execute(f"DELETE FROM {table}")
            self._conn.execute("DELETE FROM loomctx_meta WHERE key LIKE 'hwm:%'")
            self._ticks.clear()

    def close(self) -> None:
        with self._lock:
            self._writer.close()
            for conn in self._readers:
                conn.close()

    # ------------------------------------------------- internals (no commit)

    def _get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        """Exact (type, key) match only — used by writes and merges."""
        row = self._conn.execute(
            "SELECT * FROM entities WHERE namespace = ? AND type = ? AND key = ?",
            (namespace, ref.type, ref.key),
        ).fetchone()
        return common.row_to_entity(row) if row else None

    def _resolve_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        """Exact match, else follow an alias record from a prior merge —
        so a query for a merged-away ref still finds the canonical entity."""
        direct = self._get_entity(namespace, ref)
        if direct is not None:
            return direct
        row = self._conn.execute(
            "SELECT e.* FROM aliases a JOIN entities e ON e.id = a.entity_id"
            " WHERE a.namespace = ? AND a.alias = ?",
            (namespace, f"{ref.type}:{ref.key}"),
        ).fetchone()
        return common.row_to_entity(row) if row else None

    def _get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        row = self._conn.execute(
            "SELECT * FROM artifacts WHERE namespace = ? AND id = ?",
            (namespace, artifact_id),
        ).fetchone()
        return common.row_to_artifact(row) if row else None

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
        row = self._conn.execute(
            "SELECT * FROM artifacts WHERE namespace = ? AND event_id = ?",
            (namespace, event_id),
        ).fetchone()
        return common.row_to_artifact(row) if row else None

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
        self._conn.execute(
            "INSERT OR IGNORE INTO entities (id, namespace, type, key, provisional,"
            " created_at, norm_key) VALUES (?, ?, ?, ?, 0, ?, ?)",
            (entity.id, namespace, ref.type, ref.key, common.iso(entity.created_at),
             common.norm_key(ref.key)),
        )
        # another process may have inserted the same key between our SELECT
        # and INSERT; the row that actually exists wins
        return self._get_entity(namespace, ref) or entity

    def _put_alias(self, namespace: str, alias: str, entity_id: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO aliases (namespace, alias, entity_id)"
            " VALUES (?, ?, ?)",
            (namespace, alias, entity_id),
        )

    def _put_tombstone(
        self, namespace: str, observation_id: str, reason: str, recorded_at: datetime
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO tombstones"
            " (observation_id, namespace, reason, recorded_at)"
            " VALUES (?, ?, ?, ?)",
            (observation_id, namespace, reason, common.iso(recorded_at)),
        )

    def _existing_by_event(self, namespace: str, event_id: str) -> Observation | None:
        """The stored observation for a replayed event_id — redacted ones
        come back as a content-free stand-in (see GraphStore.record_claim)."""
        row = self._conn.execute(
            _OBS_SELECT + " WHERE o.namespace = ? AND o.event_id = ?",
            (namespace, event_id),
        ).fetchone()
        if row is None:
            return None
        obs = common.row_to_observation(row)
        tomb = self._conn.execute(
            "SELECT 1 FROM tombstones WHERE observation_id = ?", (obs.id,)
        ).fetchone()
        return common.redacted_view(obs) if tomb else obs

    # bound parameters per batched lookup: well under SQLite's variable cap
    _WRITE_CHUNK = 400

    def _record_batch(self, claims: list[ClaimIn]) -> list[Observation]:
        """record_claims, set at a time (D-105). What lands is what a loop of
        one-claim writes in order stored: the same replays answered, the same
        entities resolved or created, the same rows. The lookups run once per
        batch (replayed event ids, exact entities, aliases) and the rows go
        in through one executemany, instead of four to six statements per
        claim. Nothing in here changes which entity or alias a ref resolves
        to, so resolving every ref up front gives the loop's answers."""
        out: list[Observation | None] = [None] * len(claims)
        known = self._existing_by_events(
            {(c.namespace, c.event_id) for c in claims if c.event_id is not None})
        todo: list[int] = []
        repeats: list[int] = []    # an event id already claimed earlier in this batch
        seen: set[tuple[str, str]] = set()
        for i, claim in enumerate(claims):
            if claim.event_id is not None:
                mark = (claim.namespace, claim.event_id)
                if mark in known:
                    metrics.INGEST_DEDUPED.inc()
                    out[i] = known[mark]
                    continue
                if mark in seen:
                    repeats.append(i)
                    continue
                seen.add(mark)
            todo.append(i)

        # A ref that was merged away resolves to its canonical entity: a
        # claim naming the old `ip_address:10.0.4.7` lands on `ip:10.0.4.7`
        # instead of resurrecting the folded node beside its alias.
        wanted: dict[str, dict[tuple[str, str], None]] = {}
        for i in todo:
            claim = claims[i]
            refs = wanted.setdefault(claim.namespace, {})
            refs[(claim.subject.type, claim.subject.key)] = None
            if isinstance(claim.object, EntityRef):
                refs[(claim.object.type, claim.object.key)] = None
        entities: dict[tuple[str, str, str], Entity] = {}
        for namespace, refs in wanted.items():
            for (etype, key), entity in self._resolve_or_create_many(namespace, list(refs)).items():
                entities[(namespace, etype, key)] = entity

        rows: list[tuple] = []
        for i, (obs, row) in zip(todo, self._observation_rows([claims[i] for i in todo], entities)):
            out[i] = obs
            rows.append(row)
        if rows:
            cur = self._conn.executemany(_OBS_INSERT + _ON_EVENT_CONFLICT, rows)
            if cur.rowcount != len(rows):
                # another writer landed some of these event ids first (H-B2):
                # a row that did not go in answers with the stored one
                landed = self._present(
                    "SELECT id FROM observations WHERE id IN ({})", [row[0] for row in rows])
                for i in todo:
                    if out[i].id not in landed:
                        metrics.INGEST_DEDUPED.inc()
                        out[i] = self._existing_by_event(claims[i].namespace, claims[i].event_id)
        for i in repeats:
            metrics.INGEST_DEDUPED.inc()
            out[i] = self._existing_by_event(claims[i].namespace, claims[i].event_id)
        return out  # type: ignore[return-value]

    def _present(self, sql: str, values: list[str]) -> set[str]:
        """The first column of `sql` (one `IN ({})` placeholder) over
        `values`, chunked under the bound-parameter cap."""
        hits: set[str] = set()
        for start in range(0, len(values), self._WRITE_CHUNK):
            chunk = values[start:start + self._WRITE_CHUNK]
            hits.update(r[0] for r in self._conn.execute(
                sql.format(",".join("?" * len(chunk))), chunk))
        return hits

    def _existing_by_events(self, marks: set[tuple[str, str]]) -> dict[tuple[str, str], Observation]:
        """`_existing_by_event` for many (namespace, event_id) pairs at once:
        the stored observation per replayed pair, a redacted one as its
        content-free stand-in."""
        found: dict[tuple[str, str], Observation] = {}
        by_ns: dict[str, list[str]] = {}
        for namespace, event_id in marks:
            by_ns.setdefault(namespace, []).append(event_id)
        for namespace, event_ids in by_ns.items():
            for start in range(0, len(event_ids), self._WRITE_CHUNK):
                chunk = event_ids[start:start + self._WRITE_CHUNK]
                for row in self._conn.execute(
                        _OBS_SELECT + " WHERE o.namespace = ? AND o.event_id IN"
                        f" ({','.join('?' * len(chunk))})", (namespace, *chunk)):
                    found[(namespace, row["event_id"])] = common.row_to_observation(row)
        if found:
            dead = self._present("SELECT observation_id FROM tombstones WHERE observation_id IN ({})",
                                 [obs.id for obs in found.values()])
            if dead:
                found = {mark: common.redacted_view(obs) if obs.id in dead else obs
                         for mark, obs in found.items()}
        return found

    def _entities_by_refs(self, namespace: str,
                          refs: list[tuple[str, str]]) -> dict[tuple[str, str], Entity]:
        """Exact (type, key) matches for many refs: `_get_entity`, batched."""
        found: dict[tuple[str, str], Entity] = {}
        step = self._WRITE_CHUNK // 2
        for start in range(0, len(refs), step):
            chunk = refs[start:start + step]
            params: list[str] = [namespace]
            for etype, key in chunk:
                params += (etype, key)
            for row in self._conn.execute(
                    "SELECT * FROM entities WHERE namespace = ? AND (type, key) IN"
                    f" (VALUES {','.join(['(?, ?)'] * len(chunk))})", params):
                found[(row["type"], row["key"])] = common.row_to_entity(row)
        return found

    def _resolve_or_create_many(self, namespace: str,
                                refs: list[tuple[str, str]]) -> dict[tuple[str, str], Entity]:
        """`_resolve_or_create` for many refs: the exact node, else the
        canonical one an alias points at, else a new node."""
        found = self._entities_by_refs(namespace, refs)
        missing = [ref for ref in refs if ref not in found]
        for start in range(0, len(missing), self._WRITE_CHUNK):
            names = {f"{etype}:{key}": (etype, key)
                     for etype, key in missing[start:start + self._WRITE_CHUNK]}
            for row in self._conn.execute(
                    "SELECT a.alias AS alias_name, e.* FROM aliases a"
                    " JOIN entities e ON e.id = a.entity_id"
                    f" WHERE a.namespace = ? AND a.alias IN ({','.join('?' * len(names))})",
                    (namespace, *names)):
                found[names[row["alias_name"]]] = common.row_to_entity(row)
        fresh = [ref for ref in missing if ref not in found]
        if fresh:
            created = [Entity(id=uuid.uuid4().hex, namespace=namespace, type=etype, key=key,
                              created_at=common.now()) for etype, key in fresh]
            cur = self._conn.executemany(
                "INSERT OR IGNORE INTO entities (id, namespace, type, key, provisional,"
                " created_at, norm_key) VALUES (?, ?, ?, ?, 0, ?, ?)",
                [(e.id, namespace, e.type, e.key, common.iso(e.created_at), common.norm_key(e.key))
                 for e in created])
            if cur.rowcount == len(created):
                found.update(((e.type, e.key), e) for e in created)
            else:
                # another process inserted some of these keys between our
                # SELECT and INSERT; the row that actually exists wins
                stored = self._entities_by_refs(namespace, fresh)
                for e in created:
                    found[(e.type, e.key)] = stored.get((e.type, e.key), e)
        return found

    def _observation_rows(self, claims: list[ClaimIn],
                          entities: dict[tuple[str, str, str], Entity]
                          ) -> Iterator[tuple[Observation, tuple]]:
        """The observation each fresh claim becomes, and its row — what
        `_obs_row` writes, with the per-batch repeats computed once: an
        entity's ref and JSON, a timestamp's stored text."""
        refs: dict[str, tuple[EntityRef, str]] = {}

        def ref(entity: Entity) -> tuple[EntityRef, str]:
            hit = refs.get(entity.id)
            if hit is None:
                hit = refs[entity.id] = (
                    EntityRef(type=entity.type, key=entity.key),
                    # == json.dumps(EntityRef.model_dump()): fields in order
                    json.dumps({"type": entity.type, "key": entity.key}))
            return hit

        stamps: dict[datetime, str] = {}

        def iso(dt: datetime | None) -> str | None:
            # equal instants store the same UTC text, so a repeat is a lookup
            if dt is None:
                return None
            text = stamps.get(dt)
            if text is None:
                text = stamps[dt] = common.iso(dt)
            return text

        for claim in claims:
            ns = claim.namespace
            subject = entities[(ns, claim.subject.type, claim.subject.key)]
            object_entity_id = None
            obj = claim.object
            if isinstance(obj, EntityRef):
                target = entities[(ns, obj.type, obj.key)]
                object_entity_id = target.id
                obj, object_json = ref(target)
            else:
                object_json = json.dumps(obj)
            provenance = self._resolve_provenance(claim)
            recorded_at = common.now()
            obs = Observation(
                id=uuid.uuid4().hex,
                namespace=ns,
                event_id=claim.event_id,
                subject=ref(subject)[0],
                predicate=claim.predicate,
                object=obj,
                observed_at=claim.observed_at,
                valid_from=claim.valid_from,
                valid_to=claim.valid_to,
                recorded_at=recorded_at,
                source=claim.source,
                confidence=claim.confidence,
                provenance=provenance,
                supersedes=claim.supersedes,
                attrs=claim.attrs,
            )
            yield obs, (
                obs.id, ns, claim.event_id, subject.id, claim.predicate,
                object_json, object_entity_id, iso(claim.observed_at),
                iso(claim.valid_from), iso(claim.valid_to),
                common.iso(recorded_at), claim.source, claim.confidence,
                json.dumps(provenance.model_dump()) if provenance else None,
                json.dumps(claim.attrs) if claim.attrs else "{}", claim.supersedes,
            )

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

    def _insert_artifact(
        self, artifact: Artifact, or_ignore: bool = False, suffix: str = ""
    ) -> bool:
        verb = "INSERT OR IGNORE" if or_ignore else "INSERT"
        cur = self._conn.execute(
            f"{verb} INTO artifacts (id, namespace, event_id, filename,"
            " content_type, text, content_b64, source, observed_at, recorded_at,"
            " extraction_status, extraction_attempts, attrs_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" + suffix,
            (
                artifact.id, artifact.namespace, artifact.event_id,
                artifact.filename, artifact.content_type, artifact.text,
                artifact.content_b64, artifact.source,
                common.iso(artifact.observed_at), common.iso(artifact.recorded_at),
                artifact.extraction_status, artifact.extraction_attempts,
                json.dumps(artifact.attrs),
            ),
        )
        return cur.rowcount > 0
