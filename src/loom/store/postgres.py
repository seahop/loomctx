"""Server-backed GraphStore: Postgres (D-008, D-011, D-014, D-016).

The scaling lane: multiple engine replicas and writer consumers share one
Postgres. Column shapes, idempotent-ingest semantics (event_id dedupe),
tombstone redaction, and lifecycle operations are identical to the SQLite
store — the shared contract tests enforce it.

Selected purely by connection string — set LOOM_DB=postgresql://... and
nothing else changes. Requires the `postgres` extra (psycopg).
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime
from typing import Iterator

from .. import metrics
from ..contracts import Artifact, ClaimIn, DocumentIn, Entity, EntityRef, Observation
from . import common
from .base import GraphStore

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    id          TEXT PRIMARY KEY,
    namespace   TEXT NOT NULL,
    type        TEXT NOT NULL,
    key         TEXT NOT NULL,
    provisional BOOLEAN NOT NULL DEFAULT FALSE,
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
    attrs_json        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tombstones (
    observation_id TEXT PRIMARY KEY,
    namespace      TEXT NOT NULL,
    reason         TEXT NOT NULL,
    recorded_at    TEXT NOT NULL
);

ALTER TABLE observations ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE artifacts    ADD COLUMN IF NOT EXISTS event_id TEXT;

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


class PostgresStore(GraphStore):
    def __init__(self, dsn: str):
        import psycopg
        from psycopg.rows import dict_row

        # One connection guarded by a lock keeps semantics identical to the
        # SQLite store. Connection pooling is a straightforward later upgrade
        # inside this class; the interface doesn't change.
        self._lock = threading.Lock()
        self._psycopg = psycopg
        self._conn = psycopg.connect(dsn, row_factory=dict_row)
        with self._conn.cursor() as cur:
            cur.execute(_SCHEMA)
        self._conn.commit()

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

    # ------------------------------------------------------------ public API

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
            rows = self._q(
                "SELECT * FROM entities WHERE namespace = %s"
                "   AND (key = %s OR key LIKE %s)"
                " ORDER BY (key != %s), type, key LIMIT %s",
                (namespace, query, f"{query}%", query, limit),
            )
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
            rows = self._q(
                _OBS_SELECT
                + " WHERE o.namespace = %s"
                "   AND (o.subject_id = %s OR o.object_entity_id = %s)"
                + _NOT_TOMBSTONED
                + " ORDER BY o.observed_at DESC LIMIT %s",
                (namespace, entity.id, entity.id, limit),
            )
            return [common.row_to_observation(r) for r in rows]

    def store_artifact(self, doc: DocumentIn) -> Artifact:
        with self._lock:
            if doc.event_id is not None:
                rows = self._q(
                    "SELECT id FROM artifacts WHERE namespace = %s AND event_id = %s",
                    (doc.namespace, doc.event_id),
                )
                if rows:
                    metrics.INGEST_DEDUPED.inc()
                    return self._get_artifact(doc.namespace, rows[0]["id"])
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
                self._q("SELECT 1")
            return True
        except self._psycopg.Error:
            return False

    # ------------------------------------------------------ lifecycle (D-016)

    def redact(self, namespace: str, observation_id: str, reason: str) -> bool:
        with self._lock:
            rows = self._q(
                "SELECT 1 FROM observations WHERE id = %s AND namespace = %s",
                (observation_id, namespace),
            )
            if not rows:
                return False
            self._x(
                "INSERT INTO tombstones (observation_id, namespace, reason,"
                " recorded_at) VALUES (%s, %s, %s, %s)"
                " ON CONFLICT (observation_id) DO UPDATE SET reason ="
                " EXCLUDED.reason",
                (observation_id, namespace, reason, common.iso(common.now())),
            )
            self._conn.commit()
            return True

    def purge_older_than(self, namespace: str, before: datetime) -> int:
        cutoff = common.iso(before)
        with self._lock:
            removed = self._x(
                "DELETE FROM observations WHERE namespace = %s AND observed_at < %s",
                (namespace, cutoff),
            )
            removed += self._x(
                "DELETE FROM artifacts WHERE namespace = %s AND observed_at < %s",
                (namespace, cutoff),
            )
            self._x(
                "DELETE FROM tombstones WHERE observation_id NOT IN"
                " (SELECT id FROM observations)"
            )
            self._conn.commit()
        return removed

    def iter_observations(
        self, namespace: str | None = None
    ) -> Iterator[Observation]:
        with self._lock:
            rows = self._q(
                _OBS_SELECT
                + (" WHERE o.namespace = %s" if namespace else "")
                + " ORDER BY o.recorded_at",
                (namespace,) if namespace else (),
            )
        for row in rows:
            yield common.row_to_observation(row)

    def iter_entities(self, namespace: str | None = None) -> Iterator[Entity]:
        with self._lock:
            rows = self._q(
                "SELECT * FROM entities"
                + (" WHERE namespace = %s" if namespace else "")
                + " ORDER BY created_at",
                (namespace,) if namespace else (),
            )
        for row in rows:
            yield common.row_to_entity(row)

    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]:
        with self._lock:
            rows = self._q(
                "SELECT * FROM artifacts"
                + (" WHERE namespace = %s" if namespace else "")
                + " ORDER BY recorded_at",
                (namespace,) if namespace else (),
            )
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
            self._x(
                "INSERT INTO observations (id, namespace, event_id, subject_id,"
                " predicate, object_json, object_entity_id, observed_at,"
                " valid_from, valid_to, recorded_at, source, confidence,"
                " provenance_json, attrs_json) VALUES"
                " (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (id) DO NOTHING",
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
            self._insert_artifact(artifact, on_conflict_ignore=True)
            self._conn.commit()

    def wipe(self) -> None:
        with self._lock:
            for table in ("tombstones", "observations", "aliases", "artifacts",
                          "entities"):
                self._x(f"DELETE FROM {table}")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------- internals (no commit)

    def _get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        rows = self._q(
            "SELECT * FROM entities"
            " WHERE namespace = %s AND type = %s AND key = %s",
            (namespace, ref.type, ref.key),
        )
        return common.row_to_entity(rows[0]) if rows else None

    def _get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        rows = self._q(
            "SELECT * FROM artifacts WHERE namespace = %s AND id = %s",
            (namespace, artifact_id),
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
            " created_at) VALUES (%s, %s, %s, %s, FALSE, %s)"
            " ON CONFLICT (namespace, type, key) DO NOTHING",
            (entity.id, namespace, ref.type, ref.key,
             common.iso(entity.created_at)),
        )
        # A concurrent writer may have won the ON CONFLICT race; re-read.
        return self._get_entity(namespace, ref) or entity

    def _observation_by_id(self, observation_id: str) -> Observation | None:
        rows = self._q(_OBS_SELECT + " WHERE o.id = %s", (observation_id,))
        return common.row_to_observation(rows[0]) if rows else None

    def _record_claim(self, claim: ClaimIn) -> Observation:
        if claim.event_id is not None:
            rows = self._q(
                "SELECT id FROM observations WHERE namespace = %s AND event_id = %s",
                (claim.namespace, claim.event_id),
            )
            if rows:
                metrics.INGEST_DEDUPED.inc()
                return self._observation_by_id(rows[0]["id"])

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
        self._x(
            "INSERT INTO observations (id, namespace, event_id, subject_id,"
            " predicate, object_json, object_entity_id, observed_at, valid_from,"
            " valid_to, recorded_at, source, confidence, provenance_json,"
            " attrs_json) VALUES"
            " (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                obs.id, obs.namespace, obs.event_id, subject.id, obs.predicate,
                object_json, object_entity_id, common.iso(obs.observed_at),
                common.iso(obs.valid_from), common.iso(obs.valid_to),
                common.iso(obs.recorded_at), obs.source, obs.confidence,
                None, json.dumps(obs.attrs),
            ),
        )
        return obs

    def _insert_artifact(
        self, artifact: Artifact, on_conflict_ignore: bool = False
    ) -> None:
        suffix = " ON CONFLICT (id) DO NOTHING" if on_conflict_ignore else ""
        self._x(
            "INSERT INTO artifacts (id, namespace, event_id, filename,"
            " content_type, text, content_b64, source, observed_at, recorded_at,"
            " extraction_status, attrs_json)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)" + suffix,
            (
                artifact.id, artifact.namespace, artifact.event_id,
                artifact.filename, artifact.content_type, artifact.text,
                artifact.content_b64, artifact.source,
                common.iso(artifact.observed_at), common.iso(artifact.recorded_at),
                artifact.extraction_status, json.dumps(artifact.attrs),
            ),
        )
