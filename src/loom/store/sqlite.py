"""Default GraphStore: SQLite, single file, zero ops (decisions D-002, D-011).

Tuned for "decent input in a singular setup": WAL journal + synchronous=NORMAL
(one fsync per transaction, safe under WAL), batched claim writes committed as
a single transaction, and a busy timeout + process-internal lock so the engine
and the scale-shape writer consumer can share the file. Edges are observations
whose object is an entity, so the graph is queryable from either end.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path

from ..contracts import Artifact, ClaimIn, DocumentIn, Entity, EntityRef, Observation
from . import common
from .base import GraphStore

_SCHEMA = """
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

CREATE INDEX IF NOT EXISTS idx_obs_subject
    ON observations (namespace, subject_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_obs_object
    ON observations (namespace, object_entity_id, observed_at);
"""


class SqliteStore(GraphStore):
    def __init__(self, path: str | Path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)

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
                "SELECT o.*, e.type AS subj_type, e.key AS subj_key"
                " FROM observations o JOIN entities e ON e.id = o.subject_id"
                " WHERE o.namespace = ?"
                "   AND (o.subject_id = ? OR o.object_entity_id = ?)"
                " ORDER BY o.observed_at DESC LIMIT ?",
                (namespace, entity.id, entity.id, limit),
            ).fetchall()
            return [common.row_to_observation(r) for r in rows]

    def store_artifact(self, doc: DocumentIn) -> Artifact:
        artifact = Artifact(
            id=uuid.uuid4().hex,
            namespace=doc.namespace,
            filename=doc.filename,
            content_type=doc.content_type,
            text=doc.text,
            content_b64=doc.content_b64,
            source=doc.source,
            observed_at=doc.observed_at,
            recorded_at=common.now(),
            attrs=doc.attrs,
        )
        with self._lock:
            self._conn.execute(
                "INSERT INTO artifacts (id, namespace, filename, content_type,"
                " text, content_b64, source, observed_at, recorded_at,"
                " extraction_status, attrs_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    artifact.id,
                    artifact.namespace,
                    artifact.filename,
                    artifact.content_type,
                    artifact.text,
                    artifact.content_b64,
                    artifact.source,
                    common.iso(artifact.observed_at),
                    common.iso(artifact.recorded_at),
                    artifact.extraction_status,
                    json.dumps(artifact.attrs),
                ),
            )
            self._conn.commit()
        return artifact

    def get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM artifacts WHERE namespace = ? AND id = ?",
                (namespace, artifact_id),
            ).fetchone()
        return common.row_to_artifact(row) if row else None

    def wipe(self) -> None:
        with self._lock:
            for table in ("observations", "aliases", "artifacts", "entities"):
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

    def _record_claim(self, claim: ClaimIn) -> Observation:
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
            "INSERT INTO observations (id, namespace, subject_id, predicate,"
            " object_json, object_entity_id, observed_at, valid_from, valid_to,"
            " recorded_at, source, confidence, provenance_json, attrs_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                obs.id,
                obs.namespace,
                subject.id,
                obs.predicate,
                object_json,
                object_entity_id,
                common.iso(obs.observed_at),
                common.iso(obs.valid_from),
                common.iso(obs.valid_to),
                common.iso(obs.recorded_at),
                obs.source,
                obs.confidence,
                None,
                json.dumps(obs.attrs),
            ),
        )
        return obs
