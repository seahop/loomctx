"""Default GraphStore: SQLite, single file, zero ops (D-002, D-011, D-014, D-016).

Tuned for "decent input in a singular setup": WAL journal + synchronous=NORMAL
(one fsync per transaction, safe under WAL), batched claim writes committed as
a single transaction, and a busy timeout + process-internal lock so the engine
and the scale-shape writer consumer can share the file. Edges are observations
whose object is an entity, so the graph is queryable from either end.

Every public method runs inside `_tx()`: lock, commit on success, ROLLBACK on
any exception — a failing statement can never leave half a batch behind for
the next unrelated commit to persist (hardening H-B1).

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
import sqlite3
import threading
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

# Versioned migrations (H-B12): capability checks add columns idempotently;
# anything that must run exactly once (a backfill) is keyed by version here.
# v3: packed vectors (D-039); v4: resolution_declines (D-044); v5: merge_log,
# lease owners, lower(key) index, numeric norm_key rule (recompute)
SCHEMA_VERSION = 5

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

_OBS_INSERT = (
    "INSERT INTO observations (id, namespace, event_id, subject_id, predicate,"
    " object_json, object_entity_id, observed_at, valid_from, valid_to,"
    " recorded_at, source, confidence, provenance_json, attrs_json)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

_ON_EVENT_CONFLICT = (
    " ON CONFLICT (namespace, event_id) WHERE event_id IS NOT NULL DO NOTHING"
)


class SqliteStore(GraphStore):
    def __init__(self, path: str | Path):
        # Re-entrant: a public method that calls another public method
        # (unmerge -> dossier drop, lifecycle helpers, ...) must not deadlock
        # on its own lock; `_tx` commits only at the outermost level.
        self._lock = threading.RLock()
        self._depth = 0
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        # 15 s: several enrichment workers writing 512-vector batches can
        # hold the write lock past 5 s (D-039)
        self._conn.execute("PRAGMA busy_timeout=15000")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS loom_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        current = self._meta_version()
        if current > SCHEMA_VERSION:
            # An older image opening a newer file: serve what it understands,
            # run no DDL, and never write the version down (H-B12) — the next
            # up-to-date open must still see what was actually applied.
            logging.getLogger("loom.store").warning(
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
        # don't refuse to start.
        self._conn.execute("PRAGMA foreign_keys=ON")
        dangling = self._conn.execute("PRAGMA foreign_key_check").fetchall()
        if dangling:
            logging.getLogger("loom.store").warning(
                "sqlite: %d row(s) violate foreign keys (pre-existing data);"
                " reads skip them, a lifecycle export/import cleans them",
                len(dangling))

    def _migrate(self) -> None:
        """Bring pre-existing database files up to the current shape:
        idempotent column adds first, then one-shot versioned steps."""
        wanted = {
            "observations": [("event_id", "TEXT")],
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
        for table, columns in wanted.items():
            have = {
                r["name"]
                for r in self._conn.execute(f"PRAGMA table_info({table})")
            }
            for name, ddl in columns:
                if name not in have:
                    self._conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"
                    )
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
        if current < SCHEMA_VERSION:  # an up-to-date open takes no write lock (D-039)
            self._conn.execute(
                "INSERT OR REPLACE INTO loom_meta (key, value) VALUES"
                " ('schema_version', ?)", (str(SCHEMA_VERSION),))
        self._conn.commit()

    def _meta_version(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM loom_meta WHERE key = 'schema_version'").fetchone()
        return int(row["value"]) if row else 0

    def schema_version(self) -> int:
        with self._tx():
            return self._meta_version()

    # ------------------------------------------------- vector index (D-025)

    def _load_vec(self) -> bool:
        try:
            import sqlite_vec
            self._conn.enable_load_extension(True)
            sqlite_vec.load(self._conn)
            self._conn.enable_load_extension(False)
        except Exception as exc:  # noqa: BLE001 — any failure means "no ANN"
            logging.getLogger("loom.store").info(
                "sqlite-vec unavailable (%s): vector search uses exact scans", exc)
            return False
        for row in self._conn.execute(
                "SELECT key, value FROM loom_meta WHERE key LIKE 'vec:%'"):
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
                "INSERT OR REPLACE INTO loom_meta (key, value) VALUES (?, ?)",
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
        this connection opened; loom_meta is the shared registry."""
        for row in self._conn.execute(
                "SELECT key, value FROM loom_meta WHERE key LIKE 'vec:%'"):
            self._vec_tables[row["key"][4:]] = int(row["value"])

    def _vec_query(self, kind: str, model: str, namespace: str,
                   query: list[float], k: int) -> list[tuple[str, str, float]] | None:
        """(ref_id, artifact_id, cosine) via the ANN index, best first; None
        when no index fits this (model, dimension) so callers scan exactly."""
        name = common.vec_table(kind, model, len(query))
        if name not in self._vec_tables:
            self._refresh_vec_tables()
        if name not in self._vec_tables:
            return None
        rows = self._conn.execute(
            f"SELECT ref_id, artifact_id, distance FROM {name}"
            " WHERE embedding MATCH ? AND k = ? AND namespace = ? ORDER BY distance",
            (json.dumps(query), k, namespace),
        ).fetchall()
        return [(r["ref_id"], r["artifact_id"], 1.0 - float(r["distance"])) for r in rows]

    def nearest_observations(
        self, namespace: str, model: str, query: list[float], limit: int = 20
    ) -> list[tuple[str, float]]:
        with self._tx():
            hits = self._vec_query("vobs", model, namespace, query, limit * 2) if self._vec else None
            if hits is not None:
                scored = {rid: s for rid, _, s in hits}
            else:  # exact scan over the namespace's vectors
                rows = self._conn.execute(
                    "SELECT ref_id, vector FROM embeddings WHERE namespace = ? AND model = ?",
                    (namespace, model)).fetchall()
                scored = common.cosines(
                    query, {r["ref_id"]: common.unpack_vector(r["vector"]) for r in rows})
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
        wanted = set(artifact_ids) if artifact_ids is not None else None
        with self._tx():
            scored: dict[str, float] = {}
            hits = (self._vec_query("vchk", model, namespace, query, max(limit * 8, 128))
                    if self._vec else None)
            # over-fetch, then filter by artifact in Python; if the filter
            # leaves us short (or there is no index), scan exactly below
            for cid, aid, s in hits or []:
                if wanted is None or aid in wanted:
                    scored[cid] = s
            if len(scored) < limit:
                sql = ("SELECT id, vector FROM doc_chunks WHERE namespace = ? AND model = ?")
                params: tuple = (namespace, model)
                if wanted is not None:
                    if not wanted:
                        return []
                    sql += f" AND artifact_id IN ({','.join('?' * len(wanted))})"
                    params += tuple(wanted)
                rows = self._conn.execute(sql, params).fetchall()
                scored = common.cosines(query, {r["id"]: common.unpack_vector(r["vector"]) for r in rows})
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
                vec_tables = [n for n in self._vec_tables if n.startswith(f"{kind}_")]
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
        with self._tx():
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                rows = self._conn.execute(
                    _OBS_SELECT + f" WHERE o.namespace = ? AND o.id IN ({','.join('?' * len(chunk))})"
                    + _NOT_TOMBSTONED, (namespace, *chunk)).fetchall()
                out.extend(common.row_to_observation(r) for r in rows)
        return out

    _PREFIX_CAP = 20

    def observations_by_prefix(self, namespace: str, prefix: str) -> list[Observation]:
        if not prefix:
            return []
        lo, hi = common.prefix_bounds(prefix)
        with self._tx():
            rows = self._conn.execute(
                _OBS_SELECT + " WHERE o.namespace = ? AND o.id >= ?"
                + (" AND o.id < ?" if hi is not None else "") + _NOT_TOMBSTONED
                + " ORDER BY o.id LIMIT ?",
                (namespace, lo, *((hi,) if hi is not None else ()), self._PREFIX_CAP)).fetchall()
        return [common.row_to_observation(r) for r in rows]

    @contextmanager
    def _tx(self):
        """One locked transaction: commit on success, rollback on error so a
        failure never leaks partial writes into a later commit (H-B1).
        Nested entries (a public method calling another) join the outer
        transaction: only the outermost commits or rolls back."""
        with self._lock:
            self._depth += 1
            try:
                yield
            except BaseException:
                if self._depth == 1:
                    self._conn.rollback()
                raise
            else:
                if self._depth == 1:
                    self._conn.commit()
            finally:
                self._depth -= 1

    # ------------------------------------------------------------ public API

    def upsert_entity(self, namespace: str, ref: EntityRef) -> Entity:
        with self._tx():
            return self._upsert_entity(namespace, ref)

    def get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        with self._tx():
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
            return True

    def iter_merges(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx():
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

    def fuzzy_merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT namespace, norm_key FROM entities WHERE norm_key <> ''"
                + (" AND namespace = ?" if namespace else "")
                + " GROUP BY namespace, norm_key HAVING COUNT(DISTINCT key) > 1"
                " ORDER BY namespace, norm_key LIMIT ?",
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
        with self._tx():
            row = self._conn.execute(
                "SELECT registration_json FROM schemas WHERE namespace = ?",
                (namespace,),
            ).fetchone()
        return common.row_to_schema(row) if row else None

    def iter_schemas(self, namespace: str | None = None) -> Iterator[SchemaRegistration]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT registration_json FROM schemas"
                + (" WHERE namespace = ?" if namespace else "") + " ORDER BY namespace",
                (namespace,) if namespace else ()).fetchall()
        for r in rows:
            yield common.row_to_schema(r)

    def merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT namespace, key FROM entities"
                + (" WHERE namespace = ?" if namespace else "")
                + " GROUP BY namespace, key HAVING COUNT(DISTINCT type) > 1"
                " ORDER BY namespace, key LIMIT ?",
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
    ) -> list[Entity]:
        lowered = query.lower()
        type_sql, type_args = "", ()
        if types is not None:
            type_sql = f" AND type IN ({','.join('?' * len(types))})" if types else " AND 0"
            type_args = tuple(types)
        with self._tx():
            rows = self._conn.execute(
                _SEARCH_SQL + type_sql + " ORDER BY (lower(key) != ?), type, key LIMIT ?",
                (namespace, lowered, lowered + _PREFIX_END, *type_args, lowered, limit),
            ).fetchall()
        return [common.row_to_entity(r) for r in rows]

    def count_observations(
        self, namespace: str, ref: EntityRef, observed_before: datetime | None = None
    ) -> int:
        with self._tx():
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return 0
            before_sql, before_args = _observed_before("?", observed_before)
            # two indexed halves, like observations_for (D-035/D-038)
            row = self._conn.execute(
                "SELECT (SELECT COUNT(*) FROM observations o WHERE o.namespace = ?"
                "          AND o.subject_id = ?" + _NOT_TOMBSTONED + before_sql + ")"
                "     + (SELECT COUNT(*) FROM observations o WHERE o.namespace = ?"
                "          AND o.object_entity_id = ? AND o.subject_id != ?" + _NOT_TOMBSTONED + before_sql + ")"
                " AS n",
                (namespace, entity.id, *before_args, namespace, entity.id, entity.id, *before_args),
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
        with self._tx():
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
        with self._tx():
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
            return [self._record_claim(c) for c in claims]

    def observations_for(
        self, namespace: str, ref: EntityRef, limit: int = 100,
        observed_before: datetime | None = None,
    ) -> list[Observation]:
        with self._tx():
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

    def observations_for_many(
        self, namespace: str, refs: list[EntityRef], limit: int = 100,
        observed_before: datetime | None = None,
    ) -> dict[tuple[str, str], list[Observation]]:
        result: dict[tuple[str, str], list[Observation]] = {}
        if not refs:
            return result
        before_sql, before_args = _observed_before("?", observed_before)
        with self._tx():
            owners = self._resolve_many(namespace, refs)
            ids = list(owners)
            for start in range(0, len(ids), self._MANY_CHUNK):
                chunk = ids[start:start + self._MANY_CHUNK]
                marks = ",".join("?" for _ in chunk)
                rows = self._conn.execute(
                    "WITH hits AS ("
                    + _OBS_SELECT_ENT.format(ent="o.subject_id") +
                    f" WHERE o.namespace = ? AND o.subject_id IN ({marks})" + _NOT_TOMBSTONED + before_sql +
                    " UNION ALL "
                    + _OBS_SELECT_ENT.format(ent="o.object_entity_id") +
                    f" WHERE o.namespace = ? AND o.object_entity_id IN ({marks})"
                    "   AND o.subject_id != o.object_entity_id" + _NOT_TOMBSTONED + before_sql +
                    "), ranked AS (SELECT *, row_number() OVER (PARTITION BY ent ORDER BY observed_at DESC) AS rn FROM hits)"
                    " SELECT * FROM ranked WHERE rn <= ? ORDER BY ent, observed_at DESC",
                    (namespace, *chunk, *before_args, namespace, *chunk, *before_args, limit),
                ).fetchall()
                for row in rows:
                    obs = common.row_to_observation(row)
                    for ref in owners[row["ent"]]:
                        result.setdefault((ref.type, ref.key), []).append(obs)
        return result

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
        with self._tx():
            return self._artifact_by_event(namespace, event_id)

    def get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        with self._tx():
            return self._get_artifact(namespace, artifact_id)

    def ping(self) -> bool:
        try:
            with self._tx():
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
        with self._tx():
            for start in range(0, len(ref_ids), 500):
                chunk = ref_ids[start:start + 500]
                rows = self._conn.execute(
                    "SELECT ref_id, vector FROM embeddings"
                    f" WHERE namespace = ? AND model = ?"
                    f" AND ref_id IN ({','.join('?' * len(chunk))})",
                    (namespace, model, *chunk),
                ).fetchall()
                for row in rows:
                    result[row["ref_id"]] = common.unpack_vector(row["vector"])
        return result

    # hex value of the id's last character, 0..15: the shard key (D-031)
    _SHARD_EXPR = "(instr('0123456789abcdef', substr(o.id, -1, 1)) - 1)"

    def observations_without_embeddings(
        self, model: str, limit: int = 128, shard: tuple[int, int] | None = None
    ) -> list[Observation]:
        shard_sql, shard_args = "", ()
        if shard is not None and shard[1] > 1:
            shard_sql, shard_args = f" AND {self._SHARD_EXPR} % ? = ?", (shard[1], shard[0])
        with self._tx():
            rows = self._conn.execute(
                _OBS_SELECT
                + " WHERE NOT EXISTS (SELECT 1 FROM embeddings em"
                "   WHERE em.ref_id = o.id AND em.model = ?)"
                + _NOT_TOMBSTONED + shard_sql
                + " ORDER BY o.recorded_at LIMIT ?",
                (model, *shard_args, limit),
            ).fetchall()
            return [common.row_to_observation(r) for r in rows]

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

    def defer_extraction(
        self, namespace: str, artifact_id: str, attempts: int, next_attempt_at: datetime
    ) -> None:
        with self._tx():
            self._conn.execute(
                "UPDATE artifacts SET extraction_attempts = ?, next_attempt_at = ?,"
                " extract_claimed_until = NULL WHERE namespace = ? AND id = ?",
                (attempts, common.iso(next_attempt_at), namespace, artifact_id),
            )

    def set_extraction_status(
        self, namespace: str, artifact_id: str, status: str
    ) -> None:
        with self._tx():
            self._conn.execute(
                "UPDATE artifacts SET extraction_status = ?, extract_claimed_until = NULL"
                " WHERE namespace = ? AND id = ?",
                (status, namespace, artifact_id),
            )

    _NEEDS_CHUNKS = (
        "a.text IS NOT NULL"
        # blank docs would re-queue forever (H-D4); TRIM alone strips only
        # spaces, so name the whitespace set explicitly
        " AND TRIM(a.text, ' ' || char(9) || char(10) || char(13)) <> ''"
        " AND NOT EXISTS (SELECT 1 FROM doc_chunks c"
        "   WHERE c.artifact_id = a.id AND c.model = ?)"
    )

    def artifacts_needing_chunks(
        self, model: str, limit: int = 4, lease: tuple[str, float] | None = None
    ) -> list[Artifact]:
        with self._tx():
            if lease is None:
                rows = self._conn.execute(
                    f"SELECT * FROM artifacts a WHERE {self._NEEDS_CHUNKS}"
                    " ORDER BY a.recorded_at LIMIT ?", (model, limit)).fetchall()
            else:
                moment = common.now()
                until = common.iso(moment + timedelta(seconds=lease[1]))
                rows = self._conn.execute(
                    "UPDATE artifacts SET chunk_claimed_until = ? WHERE id IN"
                    f" (SELECT a.id FROM artifacts a WHERE {self._NEEDS_CHUNKS}"
                    "   AND (a.chunk_claimed_until IS NULL OR a.chunk_claimed_until < ?)"
                    "   ORDER BY a.recorded_at LIMIT ?) RETURNING *",
                    (until, model, common.iso(moment), limit)).fetchall()
        return sorted((common.row_to_artifact(r) for r in rows), key=lambda a: a.recorded_at)

    def put_doc_chunks(
        self, namespace: str, artifact_id: str, model: str,
        chunks: list[tuple[int, int, int, str, list[float]]],
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
            self._conn.execute(  # release the chunking lease (D-031)
                "UPDATE artifacts SET chunk_claimed_until = NULL WHERE id = ?", (artifact_id,))

    def doc_chunks_for_artifacts(
        self, namespace: str, artifact_ids: list[str], model: str
    ) -> list[dict]:
        if not artifact_ids:
            return []
        out = []
        with self._tx():
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
        with self._tx():
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
        with self._tx():
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
    ) -> None:
        with self._tx():
            entity = self._resolve_entity(namespace, ref) or self._upsert_entity(
                namespace, ref
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO dossiers (namespace, entity_id, brief,"
                " observation_count, observation_ids, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (namespace, entity.id, brief, observation_count,
                 json.dumps(list(observation_ids)), common.iso(common.now())),
            )
            self._conn.execute(  # release the dossier lease (D-031)
                "UPDATE entities SET dossier_claimed_until = NULL WHERE id = ?", (entity.id,))

    def dossier_candidates(
        self, min_new: int = 20, min_total: int = 5, limit: int = 4,
        lease: tuple[str, float] | None = None,
    ) -> list[tuple[str, EntityRef, int]]:
        moment = common.now()
        with self._tx():
            # Only observations recorded AFTER the last brief count as
            # "new", so the scan is bounded by fresh rows, not the whole
            # table (H-E2). Total counts for the few winners come after.
            rows = self._conn.execute(
                # Richness over volume (D-044): the first real run briefed
                # the load generator's hosts because they had the most rows.
                # A brief is for an entity with several kinds of fact from
                # several senders; a one-predicate firehose gets none.
                "SELECT e.namespace, e.type, e.key, e.id AS eid, COUNT(o.id) AS fresh,"
                "       d.observation_count AS have,"
                "       COUNT(DISTINCT o.predicate) AS preds, COUNT(DISTINCT o.source) AS srcs"
                " FROM entities e"
                " JOIN observations o ON o.subject_id = e.id"
                "   AND NOT EXISTS (SELECT 1 FROM tombstones t"
                "                   WHERE t.observation_id = o.id)"
                " LEFT JOIN dossiers d ON d.namespace = e.namespace"
                "   AND d.entity_id = e.id"
                " WHERE (d.updated_at IS NULL OR o.recorded_at > d.updated_at)"
                "   AND (e.dossier_claimed_until IS NULL OR e.dossier_claimed_until < ?)"
                " GROUP BY e.id"
                " HAVING (have IS NULL AND fresh >= ? AND preds >= 2) OR (have IS NOT NULL AND fresh >= ?)"
                " ORDER BY preds * srcs DESC, fresh DESC, e.created_at LIMIT ?",
                (common.iso(moment), min_total, min_new, limit),
            ).fetchall()
            out = []
            for r in rows:
                ref = EntityRef(type=r["type"], key=r["key"])
                if lease is not None:
                    claimed = self._conn.execute(
                        "UPDATE entities SET dossier_claimed_until = ? WHERE id = ?"
                        " AND (dossier_claimed_until IS NULL OR dossier_claimed_until < ?)",
                        (common.iso(moment + timedelta(seconds=lease[1])), r["eid"],
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
            # a brief synthesized from this observation may still be quoting
            # it; drop it and let the worker rebuild from what remains (H-D8)
            self._conn.execute(
                "DELETE FROM dossiers WHERE namespace = ? AND observation_ids LIKE ?",
                (namespace, f'%"{observation_id}"%'),
            )
            return True

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
        return removed

    # Exports stream in keyset pages (H-E4): the lock is held per page, not
    # for the whole table, and memory is bounded by the page size.
    _PAGE = 1000

    def _pages(self, sql: str, params: tuple, order_cols: tuple[str, str]):
        last = ("", "")
        while True:
            with self._tx():
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

    def namespace_summary(self) -> dict[str, dict[str, int]]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT namespace, type, COUNT(*) AS n FROM entities"
                " GROUP BY namespace, type ORDER BY namespace, type").fetchall()
        out: dict[str, dict[str, int]] = {}
        for r in rows:
            out.setdefault(r["namespace"], {})[r["type"]] = int(r["n"])
        return out

    def iter_entities(self, namespace: str | None = None) -> Iterator[Entity]:
        sql = "SELECT * FROM entities WHERE 1=1" + (" AND namespace = ?" if namespace else "")
        for row in self._pages(sql, (namespace,) if namespace else (),
                               ("created_at", "id")):
            yield common.row_to_entity(row)

    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]:
        sql = "SELECT * FROM artifacts WHERE 1=1" + (" AND namespace = ?" if namespace else "")
        for row in self._pages(sql, (namespace,) if namespace else (),
                               ("recorded_at", "id")):
            yield common.row_to_artifact(row)

    def iter_aliases(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx():
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

    def iter_declines(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT * FROM resolution_declines"
                + (" WHERE namespace = ?" if namespace else "") + " ORDER BY namespace, a, b",
                (namespace,) if namespace else ()).fetchall()
        for r in rows:
            yield {"namespace": r["namespace"], "a": r["a"], "b": r["b"],
                   "reason": r["reason"], "decided_at": r["decided_at"]}

    def declined_pairs(self, namespace: str) -> set[tuple[str, str]]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT a, b FROM resolution_declines WHERE namespace = ?", (namespace,)).fetchall()
        return {(r["a"], r["b"]) for r in rows}

    def iter_tombstones(self, namespace: str | None = None) -> Iterator[dict]:
        with self._tx():
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

    def wipe(self) -> None:
        with self._tx():
            for table in ("tombstones", "embeddings", "dossiers", "doc_chunks",
                          "merge_log_observations", "merge_log", "observations",
                          "aliases", "artifacts", "entities", "schemas",
                          "resolution_declines", *self._vec_tables):
                self._conn.execute(f"DELETE FROM {table}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

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
            attrs=claim.attrs,
        )
        cur = self._conn.execute(
            _OBS_INSERT + _ON_EVENT_CONFLICT,
            self._obs_row(obs, subject.id, object_json, object_entity_id),
        )
        if cur.rowcount == 0:  # another writer landed this event_id first (H-B2)
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
