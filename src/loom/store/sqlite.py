"""Default GraphStore: SQLite, single file, zero ops (D-002, D-011, D-014, D-016).

Tuned for "decent input in a singular setup": WAL journal + synchronous=NORMAL
(one fsync per transaction, safe under WAL), batched claim writes committed as
a single transaction, and a busy timeout + process-internal lock so the engine
and the scale-shape writer consumer can share the file. Edges are observations
whose object is an entity, so the graph is queryable from either end.

Ingest is idempotent: an envelope carrying an event_id is deduplicated on
(namespace, event_id). Redaction is a tombstone — the row stays for audit but
never appears in reads. Startup runs capability-based migrations so existing
database files gain new columns/tables in place.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
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
"""

_NOT_TOMBSTONED = (
    " AND NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.observation_id = o.id)"
)

_OBS_SELECT = (
    "SELECT o.*, e.type AS subj_type, e.key AS subj_key"
    " FROM observations o JOIN entities e ON e.id = o.subject_id"
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

    # ------------------------------------------------------------ public API
    # Each public method takes the lock, works through the internal no-commit
    # helpers, and commits once — which is also what makes record_claims a
    # single transaction.

    def upsert_entity(self, namespace: str, ref: EntityRef) -> Entity:
        with self._lock:
            entity = self._upsert_entity(namespace, ref)
            self._conn.commit()
            return entity

    def get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        with self._lock:
            return self._get_entity(namespace, ref)

    def search_entities(
        self, namespace: str, query: str, limit: int = 10
    ) -> list[Entity]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM entities WHERE namespace = ?"
                "   AND (key = ? OR key LIKE ?)"
                " ORDER BY (key != ?), type, key LIMIT ?",
                (namespace, query, f"{query}%", query, limit),
            ).fetchall()
        return [common.row_to_entity(r) for r in rows]

    def record_claim(self, claim: ClaimIn) -> Observation:
        return self.record_claims([claim])[0]

    def record_claims(self, claims: list[ClaimIn]) -> list[Observation]:
        with self._lock:
            observations = [self._record_claim(c) for c in claims]
            self._conn.commit()
            return observations

    def observations_for(
        self, namespace: str, ref: EntityRef, limit: int = 100
    ) -> list[Observation]:
        with self._lock:
            entity = self._get_entity(namespace, ref)
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
        with self._lock:
            if doc.event_id is not None:
                row = self._conn.execute(
                    "SELECT id FROM artifacts WHERE namespace = ? AND event_id = ?",
                    (doc.namespace, doc.event_id),
                ).fetchone()
                if row is not None:
                    metrics.INGEST_DEDUPED.inc()
                    return self._get_artifact(doc.namespace, row["id"])
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
            self._insert_artifact(artifact)
            self._conn.commit()
        return artifact

    def get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        with self._lock:
            return self._get_artifact(namespace, artifact_id)

    def ping(self) -> bool:
        try:
            with self._lock:
                self._conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    # ------------------------------------------------------ lifecycle (D-016)

    def redact(self, namespace: str, observation_id: str, reason: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM observations WHERE id = ? AND namespace = ?",
                (observation_id, namespace),
            ).fetchone()
            if row is None:
                return False
            self._conn.execute(
                "INSERT OR REPLACE INTO tombstones"
                " (observation_id, namespace, reason, recorded_at)"
                " VALUES (?, ?, ?, ?)",
                (observation_id, namespace, reason, common.iso(common.now())),
            )
            self._conn.commit()
            return True

    def purge_older_than(self, namespace: str, before: datetime) -> int:
        cutoff = common.iso(before)
        with self._lock:
            removed = self._conn.execute(
                "DELETE FROM observations WHERE namespace = ? AND observed_at < ?",
                (namespace, cutoff),
            ).rowcount
            removed += self._conn.execute(
                "DELETE FROM artifacts WHERE namespace = ? AND observed_at < ?",
                (namespace, cutoff),
            ).rowcount
            self._conn.execute(
                "DELETE FROM tombstones WHERE observation_id NOT IN"
                " (SELECT id FROM observations)"
            )
            self._conn.commit()
        return removed

    def iter_observations(
        self, namespace: str | None = None
    ) -> Iterator[Observation]:
        with self._lock:
            rows = self._conn.execute(
                _OBS_SELECT
                + (" WHERE o.namespace = ?" if namespace else "")
                + " ORDER BY o.recorded_at",
                (namespace,) if namespace else (),
            ).fetchall()
        for row in rows:
            yield common.row_to_observation(row)

    def iter_entities(self, namespace: str | None = None) -> Iterator[Entity]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM entities"
                + (" WHERE namespace = ?" if namespace else "")
                + " ORDER BY created_at",
                (namespace,) if namespace else (),
            ).fetchall()
        for row in rows:
            yield common.row_to_entity(row)

    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM artifacts"
                + (" WHERE namespace = ?" if namespace else "")
                + " ORDER BY recorded_at",
                (namespace,) if namespace else (),
            ).fetchall()
        for row in rows:
            yield common.row_to_artifact(row)

    def restore_observation(self, obs: Observation) -> None:
        with self._lock:
            subject = self._upsert_entity(obs.namespace, obs.subject)
            object_entity_id = None
            if isinstance(obs.object, EntityRef):
                object_entity_id = self._upsert_entity(obs.namespace, obs.object).id
                object_json = json.dumps(obs.object.model_dump())
            else:
                object_json = json.dumps(obs.object)
            self._conn.execute(
                "INSERT OR IGNORE INTO observations (id, namespace, event_id,"
                " subject_id, predicate, object_json, object_entity_id,"
                " observed_at, valid_from, valid_to, recorded_at, source,"
                " confidence, provenance_json, attrs_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    obs.id, obs.namespace, obs.event_id, subject.id,
                    obs.predicate, object_json, object_entity_id,
                    common.iso(obs.observed_at), common.iso(obs.valid_from),
                    common.iso(obs.valid_to), common.iso(obs.recorded_at),
                    obs.source, obs.confidence,
                    json.dumps(obs.provenance.model_dump()) if obs.provenance else None,
                    json.dumps(obs.attrs),
                ),
            )
            self._conn.commit()

    def restore_artifact(self, artifact: Artifact) -> None:
        with self._lock:
            self._insert_artifact(artifact, or_ignore=True)
            self._conn.commit()

    def wipe(self) -> None:
        with self._lock:
            for table in ("tombstones", "observations", "aliases", "artifacts",
                          "entities"):
                self._conn.execute(f"DELETE FROM {table}")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------- internals (no commit)

    def _get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        row = self._conn.execute(
            "SELECT * FROM entities WHERE namespace = ? AND type = ? AND key = ?",
            (namespace, ref.type, ref.key),
        ).fetchone()
        return common.row_to_entity(row) if row else None

    def _get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        row = self._conn.execute(
            "SELECT * FROM artifacts WHERE namespace = ? AND id = ?",
            (namespace, artifact_id),
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
            "INSERT INTO entities (id, namespace, type, key, provisional,"
            " created_at) VALUES (?, ?, ?, ?, 0, ?)",
            (entity.id, namespace, ref.type, ref.key, common.iso(entity.created_at)),
        )
        return entity

    def _observation_by_id(self, observation_id: str) -> Observation | None:
        row = self._conn.execute(
            _OBS_SELECT + " WHERE o.id = ?", (observation_id,)
        ).fetchone()
        return common.row_to_observation(row) if row else None

    def _record_claim(self, claim: ClaimIn) -> Observation:
        if claim.event_id is not None:
            row = self._conn.execute(
                "SELECT id FROM observations WHERE namespace = ? AND event_id = ?",
                (claim.namespace, claim.event_id),
            ).fetchone()
            if row is not None:
                metrics.INGEST_DEDUPED.inc()
                return self._observation_by_id(row["id"])

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
            attrs=claim.attrs,
        )
        self._conn.execute(
            "INSERT INTO observations (id, namespace, event_id, subject_id,"
            " predicate, object_json, object_entity_id, observed_at, valid_from,"
            " valid_to, recorded_at, source, confidence, provenance_json,"
            " attrs_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                obs.id, obs.namespace, obs.event_id, subject.id, obs.predicate,
                object_json, object_entity_id, common.iso(obs.observed_at),
                common.iso(obs.valid_from), common.iso(obs.valid_to),
                common.iso(obs.recorded_at), obs.source, obs.confidence,
                None, json.dumps(obs.attrs),
            ),
        )
        return obs

    def _insert_artifact(self, artifact: Artifact, or_ignore: bool = False) -> None:
        verb = "INSERT OR IGNORE" if or_ignore else "INSERT"
        self._conn.execute(
            f"{verb} INTO artifacts (id, namespace, event_id, filename,"
            " content_type, text, content_b64, source, observed_at, recorded_at,"
            " extraction_status, attrs_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                artifact.id, artifact.namespace, artifact.event_id,
                artifact.filename, artifact.content_type, artifact.text,
                artifact.content_b64, artifact.source,
                common.iso(artifact.observed_at), common.iso(artifact.recorded_at),
                artifact.extraction_status, json.dumps(artifact.attrs),
            ),
        )
