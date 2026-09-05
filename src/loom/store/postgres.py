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
            return self._resolve_entity(namespace, ref)

    def add_alias(self, namespace: str, alias: EntityRef, into: EntityRef) -> None:
        with self._lock:
            target = self._get_entity(namespace, into)
            if target is None:
                return
            self._x(
                "INSERT INTO aliases (namespace, alias, entity_id)"
                " VALUES (%s, %s, %s) ON CONFLICT (namespace, alias)"
                " DO UPDATE SET entity_id = EXCLUDED.entity_id",
                (namespace, f"{alias.type}:{alias.key}", target.id),
            )
            self._conn.commit()

    def merge_entities(
        self, namespace: str, from_ref: EntityRef, into_ref: EntityRef
    ) -> bool:
        with self._lock:
            src = self._get_entity(namespace, from_ref)
            dst = self._get_entity(namespace, into_ref)
            if src is None or dst is None or src.id == dst.id:
                return False
            self._x("UPDATE observations SET subject_id = %s WHERE subject_id = %s",
                    (dst.id, src.id))
            self._x("UPDATE observations SET object_entity_id = %s"
                    " WHERE object_entity_id = %s", (dst.id, src.id))
            self._x("UPDATE aliases SET entity_id = %s WHERE entity_id = %s",
                    (dst.id, src.id))
            self._x(
                "INSERT INTO aliases (namespace, alias, entity_id)"
                " VALUES (%s, %s, %s) ON CONFLICT (namespace, alias)"
                " DO UPDATE SET entity_id = EXCLUDED.entity_id",
                (namespace, f"{src.type}:{src.key}", dst.id),
            )
            self._x("DELETE FROM entities WHERE id = %s", (src.id,))
            self._conn.commit()
            return True

    def merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        with self._lock:
            rows = self._q(
                "SELECT namespace, key FROM entities"
                + (" WHERE namespace = %s" if namespace else "")
                + " GROUP BY namespace, key HAVING COUNT(DISTINCT type) > 1"
                " LIMIT %s",
                ((namespace, limit) if namespace else (limit,)),
            )
            groups = []
            for row in rows:
                members = self._q(
                    "SELECT * FROM entities WHERE namespace = %s AND key = %s",
                    (row["namespace"], row["key"]),
                )
                groups.append([common.row_to_entity(m) for m in members])
        return groups

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
            entity = self._resolve_entity(namespace, ref)
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

    # ----------------------------------------------------- enrichment (D-018)

    def put_embeddings(
        self, namespace: str, model: str,
        items: list[tuple[str, list[float]]],
    ) -> None:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO embeddings (ref_id, namespace, model, vector)"
                    " VALUES (%s, %s, %s, %s)"
                    " ON CONFLICT (ref_id) DO UPDATE SET model ="
                    " EXCLUDED.model, vector = EXCLUDED.vector",
                    [(ref_id, namespace, model, json.dumps(vec))
                     for ref_id, vec in items],
                )
            self._conn.commit()

    def embeddings_for(
        self, namespace: str, ref_ids: list[str], model: str
    ) -> dict[str, list[float]]:
        if not ref_ids:
            return {}
        with self._lock:
            rows = self._q(
                "SELECT ref_id, vector FROM embeddings"
                " WHERE namespace = %s AND model = %s AND ref_id = ANY(%s)",
                (namespace, model, ref_ids),
            )
        return {r["ref_id"]: json.loads(r["vector"]) for r in rows}

    def observations_without_embeddings(
        self, model: str, limit: int = 128
    ) -> list[Observation]:
        with self._lock:
            rows = self._q(
                _OBS_SELECT
                + " WHERE NOT EXISTS (SELECT 1 FROM embeddings em"
                "   WHERE em.ref_id = o.id AND em.model = %s)"
                + _NOT_TOMBSTONED
                + " ORDER BY o.recorded_at LIMIT %s",
                (model, limit),
            )
            return [common.row_to_observation(r) for r in rows]

    def pending_artifacts(self, limit: int = 4) -> list[Artifact]:
        with self._lock:
            rows = self._q(
                "SELECT * FROM artifacts WHERE extraction_status = 'pending'"
                " ORDER BY recorded_at LIMIT %s",
                (limit,),
            )
        return [common.row_to_artifact(r) for r in rows]

    def set_extraction_status(
        self, namespace: str, artifact_id: str, status: str
    ) -> None:
        with self._lock:
            self._x(
                "UPDATE artifacts SET extraction_status = %s"
                " WHERE namespace = %s AND id = %s",
                (status, namespace, artifact_id),
            )
            self._conn.commit()

    def artifacts_needing_chunks(self, limit: int = 4) -> list[Artifact]:
        with self._lock:
            rows = self._q(
                "SELECT * FROM artifacts a WHERE a.text IS NOT NULL"
                " AND NOT EXISTS (SELECT 1 FROM doc_chunks c"
                "   WHERE c.artifact_id = a.id)"
                " ORDER BY a.recorded_at LIMIT %s",
                (limit,),
            )
        return [common.row_to_artifact(r) for r in rows]

    def put_doc_chunks(
        self, namespace: str, artifact_id: str,
        chunks: list[tuple[int, int, int, str, list[float]]],
    ) -> None:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO doc_chunks (id, namespace, artifact_id, seq,"
                    " span_start, span_end, text, vector)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                    " ON CONFLICT (id) DO UPDATE SET vector = EXCLUDED.vector,"
                    " text = EXCLUDED.text",
                    [(f"{artifact_id}:{seq}", namespace, artifact_id, seq,
                      start, end, text, json.dumps(vec))
                     for seq, start, end, text, vec in chunks],
                )
            self._conn.commit()

    def doc_chunks_for_artifacts(
        self, namespace: str, artifact_ids: list[str]
    ) -> list[dict]:
        if not artifact_ids:
            return []
        with self._lock:
            rows = self._q(
                "SELECT artifact_id, seq, span_start, span_end, text, vector"
                " FROM doc_chunks WHERE namespace = %s AND artifact_id = ANY(%s)",
                (namespace, artifact_ids),
            )
        return [{"artifact_id": r["artifact_id"], "seq": r["seq"],
                 "span_start": r["span_start"], "span_end": r["span_end"],
                 "text": r["text"], "vector": json.loads(r["vector"])}
                for r in rows]

    def get_dossier(self, namespace: str, ref: EntityRef) -> dict | None:
        with self._lock:
            entity = self._get_entity(namespace, ref)
            if entity is None:
                return None
            rows = self._q(
                "SELECT brief, observation_count, updated_at FROM dossiers"
                " WHERE namespace = %s AND entity_id = %s",
                (namespace, entity.id),
            )
        if not rows:
            return None
        return {"brief": rows[0]["brief"],
                "observation_count": rows[0]["observation_count"],
                "updated_at": rows[0]["updated_at"]}

    def put_dossier(
        self, namespace: str, ref: EntityRef, brief: str,
        observation_count: int,
    ) -> None:
        with self._lock:
            entity = self._upsert_entity(namespace, ref)
            self._x(
                "INSERT INTO dossiers (namespace, entity_id, brief,"
                " observation_count, updated_at) VALUES (%s, %s, %s, %s, %s)"
                " ON CONFLICT (namespace, entity_id) DO UPDATE SET"
                " brief = EXCLUDED.brief,"
                " observation_count = EXCLUDED.observation_count,"
                " updated_at = EXCLUDED.updated_at",
                (namespace, entity.id, brief, observation_count,
                 common.iso(common.now())),
            )
            self._conn.commit()

    def dossier_candidates(
        self, min_new: int = 20, min_total: int = 5, limit: int = 4
    ) -> list[tuple[str, EntityRef, int]]:
        with self._lock:
            rows = self._q(
                "SELECT e.namespace, e.type, e.key, COUNT(o.id) AS n"
                " FROM entities e"
                " JOIN observations o ON o.subject_id = e.id"
                " LEFT JOIN dossiers d ON d.namespace = e.namespace"
                "   AND d.entity_id = e.id"
                " GROUP BY e.id, d.observation_count"
                " HAVING (d.observation_count IS NULL AND COUNT(o.id) >= %s)"
                "     OR (COUNT(o.id) - d.observation_count >= %s)"
                " ORDER BY COUNT(o.id) DESC LIMIT %s",
                (min_total, min_new, limit),
            )
        return [
            (r["namespace"], EntityRef(type=r["type"], key=r["key"]), r["n"])
            for r in rows
        ]

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
            for table in ("tombstones", "embeddings", "dossiers", "doc_chunks",
                          "observations", "aliases", "artifacts", "entities"):
                self._x(f"DELETE FROM {table}")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

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
            provenance=claim.provenance,
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
                json.dumps(obs.provenance.model_dump()) if obs.provenance else None,
                json.dumps(obs.attrs),
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
