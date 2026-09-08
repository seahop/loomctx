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
CREATE INDEX IF NOT EXISTS idx_art_status ON artifacts (extraction_status, recorded_at);
CREATE INDEX IF NOT EXISTS idx_chunk_by_artifact ON doc_chunks (artifact_id);
CREATE INDEX IF NOT EXISTS idx_entity_key ON entities (namespace, key);
CREATE INDEX IF NOT EXISTS idx_entity_norm ON entities (namespace, norm_key);
"""

# Versioned migrations (H-B12): capability checks add columns idempotently;
# anything that must run exactly once (a backfill) is keyed by version here.
SCHEMA_VERSION = 2

_NOT_TOMBSTONED = (
    " AND NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.observation_id = o.id)"
)

_OBS_SELECT = (
    "SELECT o.*, e.type AS subj_type, e.key AS subj_key"
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
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
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
                          ("chunk_claimed_until", "TEXT")],
            "dossiers": [("observation_ids", "TEXT NOT NULL DEFAULT '[]'")],
            "doc_chunks": [("model", "TEXT NOT NULL DEFAULT ''")],
            "entities": [("norm_key", "TEXT NOT NULL DEFAULT ''"),
                         ("dossier_claimed_until", "TEXT")],
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
                [(rid, namespace, aid or "", json.dumps(vec)) for rid, aid, vec in group])
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
                    query, {r["ref_id"]: json.loads(r["vector"]) for r in rows})
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
                scored = common.cosines(query, {r["id"]: json.loads(r["vector"]) for r in rows})
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
        with self._tx():
            self._refresh_vec_tables()
            for kind, key, sql in (
                ("vobs", "observations",
                 "SELECT ref_id AS id, namespace, NULL AS artifact_id, vector"
                 " FROM embeddings WHERE model = ?"),
                ("vchk", "chunks",
                 "SELECT id, namespace, artifact_id, vector FROM doc_chunks WHERE model = ?"),
            ):
                have: set[str] = set()
                for name in self._vec_tables:
                    if name.startswith(f"{kind}_"):
                        have |= {r["ref_id"] for r in self._conn.execute(f"SELECT ref_id FROM {name}")}
                by_ns: dict[str, list] = {}
                for r in self._conn.execute(sql, (model,)):
                    if r["id"] not in have:
                        by_ns.setdefault(r["namespace"], []).append(
                            (r["id"], r["artifact_id"], json.loads(r["vector"])))
                for ns, rows in by_ns.items():
                    out[key] += self._vec_upsert(kind, model, ns, rows)
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

    @contextmanager
    def _tx(self):
        """One locked transaction: commit on success, rollback on error so a
        failure never leaks partial writes into a later commit (H-B1)."""
        with self._lock:
            try:
                yield
            except BaseException:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()

    # ------------------------------------------------------------ public API

    def upsert_entity(self, namespace: str, ref: EntityRef) -> Entity:
        with self._tx():
            return self._upsert_entity(namespace, ref)

    def get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        with self._tx():
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
            self._conn.execute(
                "UPDATE observations SET subject_id = ? WHERE subject_id = ?",
                (dst.id, src.id),
            )
            # object side: repoint the edge AND its rendered ref, so both ends
            # of a merged edge read as the canonical entity (H-B6)
            self._conn.execute(
                "UPDATE observations SET object_entity_id = ?, object_json = ?"
                " WHERE object_entity_id = ?",
                (dst.id, json.dumps({"type": dst.type, "key": dst.key}), src.id),
            )
            # existing aliases pointing at the source follow it to the target
            self._conn.execute(
                "UPDATE aliases SET entity_id = ? WHERE entity_id = ?",
                (dst.id, src.id),
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
                "SELECT * FROM entities WHERE namespace = ?"
                "   AND (LOWER(key) = ? OR LOWER(key) LIKE ? ESCAPE '\\')"
                + type_sql
                + " ORDER BY (LOWER(key) != ?), type, key LIMIT ?",
                (namespace, lowered, common.like_pattern(query), *type_args,
                 lowered, limit),
            ).fetchall()
        return [common.row_to_entity(r) for r in rows]

    def count_observations(self, namespace: str, ref: EntityRef) -> int:
        with self._tx():
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return 0
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM observations o"
                " WHERE o.namespace = ?"
                "   AND (o.subject_id = ? OR o.object_entity_id = ?)"
                + _NOT_TOMBSTONED,
                (namespace, entity.id, entity.id),
            ).fetchone()
        return int(row["n"])

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
        self, namespace: str, ref: EntityRef, limit: int = 100
    ) -> list[Observation]:
        with self._tx():
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return []
            rows = self._conn.execute(
                _OBS_SELECT
                + " WHERE o.namespace = ?"
                "   AND (o.subject_id = ? OR o.object_entity_id = ?)"
                + _NOT_TOMBSTONED
                + " ORDER BY o.observed_at DESC LIMIT ?",
                (namespace, entity.id, entity.id, limit),
            ).fetchall()
            return [common.row_to_observation(r) for r in rows]

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
                [(ref_id, namespace, model, json.dumps(vec))
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
                    result[row["ref_id"]] = json.loads(row["vector"])
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
                  start, end, text, json.dumps(vec), model)
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
                "SELECT e.namespace, e.type, e.key, e.id AS eid, COUNT(o.id) AS fresh,"
                "       d.observation_count AS have"
                " FROM entities e"
                " JOIN observations o ON o.subject_id = e.id"
                "   AND NOT EXISTS (SELECT 1 FROM tombstones t"
                "                   WHERE t.observation_id = o.id)"
                " LEFT JOIN dossiers d ON d.namespace = e.namespace"
                "   AND d.entity_id = e.id"
                " WHERE (d.updated_at IS NULL OR o.recorded_at > d.updated_at)"
                "   AND (e.dossier_claimed_until IS NULL OR e.dossier_claimed_until < ?)"
                " GROUP BY e.id"
                " HAVING (have IS NULL AND fresh >= ?) OR (have IS NOT NULL AND fresh >= ?)"
                " ORDER BY fresh DESC, e.created_at LIMIT ?",
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
            subject = self._upsert_entity(obs.namespace, obs.subject)
            object_entity_id = None
            if isinstance(obs.object, EntityRef):
                object_entity_id = self._upsert_entity(obs.namespace, obs.object).id
                object_json = json.dumps(obs.object.model_dump())
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
                          "observations", "aliases", "artifacts", "entities",
                          "schemas", *self._vec_tables):
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

    def _artifact_by_event(self, namespace: str, event_id: str) -> Artifact | None:
        row = self._conn.execute(
            "SELECT * FROM artifacts WHERE namespace = ? AND event_id = ?",
            (namespace, event_id),
        ).fetchone()
        return common.row_to_artifact(row) if row else None

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
            provenance=claim.provenance,
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
