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
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .. import metrics
from ..contracts import Artifact, ClaimIn, DocumentIn, Entity, EntityRef, Observation
from . import common
from .base import GraphStore

_TABLES = """
CREATE TABLE IF NOT EXISTS entities (
    id          TEXT PRIMARY KEY,
    namespace   TEXT NOT NULL,
    type        TEXT NOT NULL,
    key         TEXT NOT NULL,
    provisional INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
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
    vector      TEXT NOT NULL
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
"""

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

    def _migrate(self) -> None:
        """Bring pre-existing database files up to the current shape."""
        for table in ("observations", "artifacts"):
            cols = {
                r["name"]
                for r in self._conn.execute(f"PRAGMA table_info({table})")
            }
            if "event_id" not in cols:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN event_id TEXT")
        self._conn.commit()

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
                "DELETE FROM dossiers WHERE namespace = ? AND entity_id = ?",
                (namespace, src.id),
            )
            self._conn.execute("DELETE FROM entities WHERE id = ?", (src.id,))
            return True

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
        self, namespace: str, query: str, limit: int = 10
    ) -> list[Entity]:
        lowered = query.lower()
        with self._tx():
            rows = self._conn.execute(
                "SELECT * FROM entities WHERE namespace = ?"
                "   AND (LOWER(key) = ? OR LOWER(key) LIKE ? ESCAPE '\\')"
                " ORDER BY (LOWER(key) != ?), type, key LIMIT ?",
                (namespace, lowered, common.like_pattern(query), lowered, limit),
            ).fetchall()
        return [common.row_to_entity(r) for r in rows]

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

    def observations_without_embeddings(
        self, model: str, limit: int = 128
    ) -> list[Observation]:
        with self._tx():
            rows = self._conn.execute(
                _OBS_SELECT
                + " WHERE NOT EXISTS (SELECT 1 FROM embeddings em"
                "   WHERE em.ref_id = o.id AND em.model = ?)"
                + _NOT_TOMBSTONED
                + " ORDER BY o.recorded_at LIMIT ?",
                (model, limit),
            ).fetchall()
            return [common.row_to_observation(r) for r in rows]

    def pending_artifacts(self, limit: int = 4) -> list[Artifact]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT * FROM artifacts WHERE extraction_status = 'pending'"
                " ORDER BY recorded_at LIMIT ?",
                (limit,),
            ).fetchall()
        return [common.row_to_artifact(r) for r in rows]

    def set_extraction_status(
        self, namespace: str, artifact_id: str, status: str
    ) -> None:
        with self._tx():
            self._conn.execute(
                "UPDATE artifacts SET extraction_status = ?"
                " WHERE namespace = ? AND id = ?",
                (status, namespace, artifact_id),
            )

    def artifacts_needing_chunks(self, limit: int = 4) -> list[Artifact]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT * FROM artifacts a WHERE a.text IS NOT NULL"
                " AND NOT EXISTS (SELECT 1 FROM doc_chunks c"
                "   WHERE c.artifact_id = a.id)"
                " ORDER BY a.recorded_at LIMIT ?",
                (limit,),
            ).fetchall()
        return [common.row_to_artifact(r) for r in rows]

    def put_doc_chunks(
        self, namespace: str, artifact_id: str,
        chunks: list[tuple[int, int, int, str, list[float]]],
    ) -> None:
        with self._tx():
            self._conn.executemany(
                "INSERT OR REPLACE INTO doc_chunks (id, namespace, artifact_id,"
                " seq, span_start, span_end, text, vector)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [(f"{artifact_id}:{seq}", namespace, artifact_id, seq,
                  start, end, text, json.dumps(vec))
                 for seq, start, end, text, vec in chunks],
            )

    def doc_chunks_for_artifacts(
        self, namespace: str, artifact_ids: list[str]
    ) -> list[dict]:
        if not artifact_ids:
            return []
        out = []
        with self._tx():
            for start in range(0, len(artifact_ids), 400):
                chunk = artifact_ids[start:start + 400]
                rows = self._conn.execute(
                    "SELECT artifact_id, seq, span_start, span_end, text, vector"
                    f" FROM doc_chunks WHERE namespace = ?"
                    f" AND artifact_id IN ({','.join('?' * len(chunk))})",
                    (namespace, *chunk),
                ).fetchall()
                for r in rows:
                    out.append({"artifact_id": r["artifact_id"], "seq": r["seq"],
                                "span_start": r["span_start"],
                                "span_end": r["span_end"], "text": r["text"],
                                "vector": json.loads(r["vector"])})
        return out

    def get_dossier(self, namespace: str, ref: EntityRef) -> dict | None:
        with self._tx():
            entity = self._resolve_entity(namespace, ref)  # aliases too (H-B6)
            if entity is None:
                return None
            row = self._conn.execute(
                "SELECT brief, observation_count, updated_at FROM dossiers"
                " WHERE namespace = ? AND entity_id = ?",
                (namespace, entity.id),
            ).fetchone()
        if row is None:
            return None
        return {"brief": row["brief"],
                "observation_count": row["observation_count"],
                "updated_at": row["updated_at"]}

    def put_dossier(
        self, namespace: str, ref: EntityRef, brief: str,
        observation_count: int,
    ) -> None:
        with self._tx():
            entity = self._resolve_entity(namespace, ref) or self._upsert_entity(
                namespace, ref
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO dossiers (namespace, entity_id, brief,"
                " observation_count, updated_at) VALUES (?, ?, ?, ?, ?)",
                (namespace, entity.id, brief, observation_count,
                 common.iso(common.now())),
            )

    def dossier_candidates(
        self, min_new: int = 20, min_total: int = 5, limit: int = 4
    ) -> list[tuple[str, EntityRef, int]]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT e.namespace, e.type, e.key, COUNT(o.id) AS n,"
                "       d.observation_count AS have"
                " FROM entities e"
                " JOIN observations o ON o.subject_id = e.id"
                "   AND NOT EXISTS (SELECT 1 FROM tombstones t"
                "                   WHERE t.observation_id = o.id)"
                " LEFT JOIN dossiers d ON d.namespace = e.namespace"
                "   AND d.entity_id = e.id"
                " GROUP BY e.id"
                " HAVING (have IS NULL AND n >= ?) OR (n - have >= ?)"
                " ORDER BY n DESC, e.created_at LIMIT ?",
                (min_total, min_new, limit),
            ).fetchall()
        return [
            (r["namespace"], EntityRef(type=r["type"], key=r["key"]), r["n"])
            for r in rows
        ]

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

    def iter_observations(
        self, namespace: str | None = None
    ) -> Iterator[Observation]:
        with self._tx():
            rows = self._conn.execute(
                _OBS_SELECT
                + (" WHERE o.namespace = ?" if namespace else "")
                + " ORDER BY o.recorded_at",
                (namespace,) if namespace else (),
            ).fetchall()
        for row in rows:
            yield common.row_to_observation(row)

    def iter_entities(self, namespace: str | None = None) -> Iterator[Entity]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT * FROM entities"
                + (" WHERE namespace = ?" if namespace else "")
                + " ORDER BY created_at",
                (namespace,) if namespace else (),
            ).fetchall()
        for row in rows:
            yield common.row_to_entity(row)

    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]:
        with self._tx():
            rows = self._conn.execute(
                "SELECT * FROM artifacts"
                + (" WHERE namespace = ?" if namespace else "")
                + " ORDER BY recorded_at",
                (namespace,) if namespace else (),
            ).fetchall()
        for row in rows:
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
                " provisional, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (uuid.uuid4().hex, entity.namespace, entity.type, entity.key,
                 int(entity.provisional), common.iso(entity.created_at)),
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
                          "observations", "aliases", "artifacts", "entities"):
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
            " created_at) VALUES (?, ?, ?, ?, 0, ?)",
            (entity.id, namespace, ref.type, ref.key, common.iso(entity.created_at)),
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
            " extraction_status, attrs_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" + suffix,
            (
                artifact.id, artifact.namespace, artifact.event_id,
                artifact.filename, artifact.content_type, artifact.text,
                artifact.content_b64, artifact.source,
                common.iso(artifact.observed_at), common.iso(artifact.recorded_at),
                artifact.extraction_status, json.dumps(artifact.attrs),
            ),
        )
        return cur.rowcount > 0
