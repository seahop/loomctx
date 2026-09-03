"""Default GraphStore: SQLite, single file, zero ops (decision D-002).

Edges are observations whose object is an entity (object_entity_id set), which
keeps the graph queryable from either end without a separate edge table.
sqlite-vec embedding storage lands in phase 4.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..contracts import ClaimIn, Entity, EntityRef, Observation, Provenance
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

CREATE INDEX IF NOT EXISTS idx_obs_subject
    ON observations (namespace, subject_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_obs_object
    ON observations (namespace, object_entity_id, observed_at);
"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def _parse(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


class SqliteStore(GraphStore):
    def __init__(self, path: str | Path):
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def upsert_entity(self, namespace: str, ref: EntityRef) -> Entity:
        existing = self.get_entity(namespace, ref)
        if existing is not None:
            return existing
        entity = Entity(
            id=uuid.uuid4().hex,
            namespace=namespace,
            type=ref.type,
            key=ref.key,
            created_at=_now(),
        )
        self._conn.execute(
            "INSERT INTO entities (id, namespace, type, key, provisional, created_at)"
            " VALUES (?, ?, ?, ?, 0, ?)",
            (entity.id, namespace, ref.type, ref.key, _iso(entity.created_at)),
        )
        self._conn.commit()
        return entity

    def get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        row = self._conn.execute(
            "SELECT * FROM entities WHERE namespace = ? AND type = ? AND key = ?",
            (namespace, ref.type, ref.key),
        ).fetchone()
        if row is None:
            return None
        return Entity(
            id=row["id"],
            namespace=row["namespace"],
            type=row["type"],
            key=row["key"],
            provisional=bool(row["provisional"]),
            created_at=_parse(row["created_at"]),
        )

    def record_claim(self, claim: ClaimIn) -> Observation:
        subject = self.upsert_entity(claim.namespace, claim.subject)
        object_entity_id = None
        if isinstance(claim.object, EntityRef):
            object_entity_id = self.upsert_entity(claim.namespace, claim.object).id
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
            recorded_at=_now(),
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
                _iso(obs.observed_at),
                _iso(obs.valid_from),
                _iso(obs.valid_to),
                _iso(obs.recorded_at),
                obs.source,
                obs.confidence,
                None,
                json.dumps(obs.attrs),
            ),
        )
        self._conn.commit()
        return obs

    def observations_for(
        self, namespace: str, ref: EntityRef, limit: int = 100
    ) -> list[Observation]:
        entity = self.get_entity(namespace, ref)
        if entity is None:
            return []
        rows = self._conn.execute(
            "SELECT o.*, e.type AS subj_type, e.key AS subj_key"
            " FROM observations o JOIN entities e ON e.id = o.subject_id"
            " WHERE o.namespace = ? AND (o.subject_id = ? OR o.object_entity_id = ?)"
            " ORDER BY o.observed_at DESC LIMIT ?",
            (namespace, entity.id, entity.id, limit),
        ).fetchall()
        return [self._row_to_observation(row) for row in rows]

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row_to_observation(row: sqlite3.Row) -> Observation:
        obj = json.loads(row["object_json"])
        if isinstance(obj, dict):
            obj = EntityRef(**obj)
        provenance = (
            Provenance(**json.loads(row["provenance_json"]))
            if row["provenance_json"]
            else None
        )
        return Observation(
            id=row["id"],
            namespace=row["namespace"],
            subject=EntityRef(type=row["subj_type"], key=row["subj_key"]),
            predicate=row["predicate"],
            object=obj,
            observed_at=_parse(row["observed_at"]),
            valid_from=_parse(row["valid_from"]),
            valid_to=_parse(row["valid_to"]),
            recorded_at=_parse(row["recorded_at"]),
            source=row["source"],
            confidence=row["confidence"],
            provenance=provenance,
            attrs=json.loads(row["attrs_json"]),
        )
