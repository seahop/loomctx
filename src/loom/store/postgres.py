"""Server-backed GraphStore: Postgres (D-008, D-011, D-014, D-016).

The scaling lane: multiple engine replicas and writer consumers share one
Postgres. Column shapes, idempotent-ingest semantics (event_id dedupe),
tombstone redaction, and lifecycle operations are identical to the SQLite
store — the shared contract tests enforce it.

Every public method runs inside `_tx()`: lock, commit on success, ROLLBACK
on any exception. That matters more here than on SQLite: a failed statement
otherwise leaves the connection in "current transaction is aborted" and every
later call on this replica fails until restart (hardening H-B1).

Selected purely by connection string — set LOOM_DB=postgresql://... and
nothing else changes. Requires the `postgres` extra (psycopg).
"""

from __future__ import annotations

import json
import threading
import uuid
from contextlib import contextmanager
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

ALTER TABLE observations ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE artifacts    ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE dossiers     ADD COLUMN IF NOT EXISTS observation_ids TEXT NOT NULL DEFAULT '[]';
ALTER TABLE doc_chunks   ADD COLUMN IF NOT EXISTS model TEXT NOT NULL DEFAULT '';

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
    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)

_ON_EVENT_CONFLICT = (
    " ON CONFLICT (namespace, event_id) WHERE event_id IS NOT NULL DO NOTHING"
)

# Replicas start concurrently; serialize the idempotent DDL so two of them
# don't race on CREATE TABLE IF NOT EXISTS (pg_type uniqueness errors).
_SCHEMA_LOCK_ID = 0x4C4F4F4D  # "LOOM"


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
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK_ID,))
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

    @contextmanager
    def _tx(self):
        """One locked transaction: commit on success, rollback on error so
        the connection never sticks in the aborted state (H-B1)."""
        with self._lock:
            try:
                yield
            except BaseException:
                try:
                    self._conn.rollback()
                except self._psycopg.Error:
                    pass  # connection itself is gone; the caller sees the cause
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
            self._x("UPDATE observations SET subject_id = %s WHERE subject_id = %s",
                    (dst.id, src.id))
            self._x("UPDATE observations SET object_entity_id = %s, object_json = %s"
                    " WHERE object_entity_id = %s",
                    (dst.id, json.dumps({"type": dst.type, "key": dst.key}), src.id))
            self._x("UPDATE aliases SET entity_id = %s WHERE entity_id = %s",
                    (dst.id, src.id))
            self._put_alias(namespace, f"{src.type}:{src.key}", dst.id)
            self._x("DELETE FROM dossiers WHERE namespace = %s AND entity_id = %s",
                    (namespace, src.id))
            self._x("DELETE FROM entities WHERE id = %s", (src.id,))
            return True

    def merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        with self._tx():
            rows = self._q(
                "SELECT namespace, key FROM entities"
                + (" WHERE namespace = %s" if namespace else "")
                + " GROUP BY namespace, key HAVING COUNT(DISTINCT type) > 1"
                " ORDER BY namespace, key LIMIT %s",
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
    ) -> list[Entity]:
        lowered = query.lower()
        type_sql, type_args = "", ()
        if types is not None:
            type_sql, type_args = " AND type = ANY(%s)", (list(types),)
        with self._tx():
            rows = self._q(
                "SELECT * FROM entities WHERE namespace = %s"
                "   AND (LOWER(key) = %s OR LOWER(key) LIKE %s ESCAPE '\\')"
                + type_sql
                + " ORDER BY (LOWER(key) != %s), type, key LIMIT %s",
                (namespace, lowered, common.like_pattern(query), *type_args,
                 lowered, limit),
            )
        return [common.row_to_entity(r) for r in rows]

    def count_observations(self, namespace: str, ref: EntityRef) -> int:
        with self._tx():
            entity = self._resolve_entity(namespace, ref)
            if entity is None:
                return 0
            rows = self._q(
                "SELECT COUNT(*) AS n FROM observations o"
                " WHERE o.namespace = %s"
                "   AND (o.subject_id = %s OR o.object_entity_id = %s)"
                + _NOT_TOMBSTONED,
                (namespace, entity.id, entity.id),
            )
        return int(rows[0]["n"])

    def artifact_cited_within(
        self, namespace: str, artifact_id: str, allowed_types: tuple[str, ...]
    ) -> bool:
        if not allowed_types:
            return False
        with self._tx():
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
        with self._tx():
            return [self._record_claim(c) for c in claims]

    def observations_for(
        self, namespace: str, ref: EntityRef, limit: int = 100
    ) -> list[Observation]:
        with self._tx():
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
                self._q("SELECT 1")
            return True
        except self._psycopg.Error:
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
                    [(ref_id, namespace, model, json.dumps(vec))
                     for ref_id, vec in items],
                )

    def embeddings_for(
        self, namespace: str, ref_ids: list[str], model: str
    ) -> dict[str, list[float]]:
        if not ref_ids:
            return {}
        with self._tx():
            rows = self._q(
                "SELECT ref_id, vector FROM embeddings"
                " WHERE namespace = %s AND model = %s AND ref_id = ANY(%s)",
                (namespace, model, ref_ids),
            )
        return {r["ref_id"]: json.loads(r["vector"]) for r in rows}

    def observations_without_embeddings(
        self, model: str, limit: int = 128
    ) -> list[Observation]:
        with self._tx():
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
        with self._tx():
            rows = self._q(
                "SELECT * FROM artifacts WHERE extraction_status = 'pending'"
                " ORDER BY recorded_at LIMIT %s",
                (limit,),
            )
        return [common.row_to_artifact(r) for r in rows]

    def set_extraction_status(
        self, namespace: str, artifact_id: str, status: str
    ) -> None:
        with self._tx():
            self._x(
                "UPDATE artifacts SET extraction_status = %s"
                " WHERE namespace = %s AND id = %s",
                (status, namespace, artifact_id),
            )

    def artifacts_needing_chunks(self, model: str, limit: int = 4) -> list[Artifact]:
        with self._tx():
            rows = self._q(
                "SELECT * FROM artifacts a WHERE a.text IS NOT NULL"
                # blank docs would re-queue forever (H-D4); TRIM alone strips
                # only spaces, so name the whitespace set explicitly
                " AND BTRIM(a.text, E' \\t\\n\\r') <> ''"
                " AND NOT EXISTS (SELECT 1 FROM doc_chunks c"
                "   WHERE c.artifact_id = a.id AND c.model = %s)"
                " ORDER BY a.recorded_at LIMIT %s",
                (model, limit),
            )
        return [common.row_to_artifact(r) for r in rows]

    def put_doc_chunks(
        self, namespace: str, artifact_id: str, model: str,
        chunks: list[tuple[int, int, int, str, list[float]]],
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
                      start, end, text, json.dumps(vec), model)
                     for seq, start, end, text, vec in chunks],
                )

    def doc_chunks_for_artifacts(
        self, namespace: str, artifact_ids: list[str], model: str
    ) -> list[dict]:
        if not artifact_ids:
            return []
        with self._tx():
            rows = self._q(
                "SELECT c.artifact_id, c.seq, c.span_start, c.span_end,"
                " c.text, c.vector, a.source, a.observed_at"
                " FROM doc_chunks c JOIN artifacts a ON a.id = c.artifact_id"
                " WHERE c.namespace = %s AND c.model = %s"
                " AND c.artifact_id = ANY(%s)",
                (namespace, model, artifact_ids),
            )
        return [common.row_to_chunk(r) for r in rows]

    def get_dossier(self, namespace: str, ref: EntityRef) -> dict | None:
        with self._tx():
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
    ) -> None:
        with self._tx():
            entity = self._resolve_entity(namespace, ref) or self._upsert_entity(
                namespace, ref
            )
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

    def dossier_candidates(
        self, min_new: int = 20, min_total: int = 5, limit: int = 4
    ) -> list[tuple[str, EntityRef, int]]:
        with self._tx():
            rows = self._q(
                "SELECT e.namespace, e.type, e.key, COUNT(o.id) AS n"
                " FROM entities e"
                " JOIN observations o ON o.subject_id = e.id"
                "   AND NOT EXISTS (SELECT 1 FROM tombstones t"
                "                   WHERE t.observation_id = o.id)"
                " LEFT JOIN dossiers d ON d.namespace = e.namespace"
                "   AND d.entity_id = e.id"
                " GROUP BY e.id, d.observation_count"
                " HAVING (d.observation_count IS NULL AND COUNT(o.id) >= %s)"
                "     OR (COUNT(o.id) - d.observation_count >= %s)"
                " ORDER BY COUNT(o.id) DESC, e.created_at LIMIT %s",
                (min_total, min_new, limit),
            )
        return [
            (r["namespace"], EntityRef(type=r["type"], key=r["key"]), r["n"])
            for r in rows
        ]

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
            self._x(
                "DELETE FROM dossiers WHERE namespace = %s AND observation_ids LIKE %s",
                (namespace, f'%"{observation_id}"%'),
            )
            return True

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
        return removed

    def iter_observations(
        self, namespace: str | None = None
    ) -> Iterator[Observation]:
        with self._tx():
            rows = self._q(
                _OBS_SELECT
                + (" WHERE o.namespace = %s" if namespace else "")
                + " ORDER BY o.recorded_at",
                (namespace,) if namespace else (),
            )
        for row in rows:
            yield common.row_to_observation(row)

    def iter_entities(self, namespace: str | None = None) -> Iterator[Entity]:
        with self._tx():
            rows = self._q(
                "SELECT * FROM entities"
                + (" WHERE namespace = %s" if namespace else "")
                + " ORDER BY created_at",
                (namespace,) if namespace else (),
            )
        for row in rows:
            yield common.row_to_entity(row)

    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]:
        with self._tx():
            rows = self._q(
                "SELECT * FROM artifacts"
                + (" WHERE namespace = %s" if namespace else "")
                + " ORDER BY recorded_at",
                (namespace,) if namespace else (),
            )
        for row in rows:
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
            subject = self._upsert_entity(obs.namespace, obs.subject)
            object_entity_id = None
            if isinstance(obs.object, EntityRef):
                object_entity_id = self._upsert_entity(obs.namespace, obs.object).id
                object_json = json.dumps(obs.object.model_dump())
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
                " created_at) VALUES (%s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (namespace, type, key) DO NOTHING",
                (uuid.uuid4().hex, entity.namespace, entity.type, entity.key,
                 bool(entity.provisional), common.iso(entity.created_at)),
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
                self._x(f"DELETE FROM {table}")

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

    def _artifact_by_event(self, namespace: str, event_id: str) -> Artifact | None:
        rows = self._q(
            "SELECT * FROM artifacts WHERE namespace = %s AND event_id = %s",
            (namespace, event_id),
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
            json.dumps(obs.attrs),
        )

    def _insert_artifact(self, artifact: Artifact, suffix: str = "") -> bool:
        return self._x(
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
        ) > 0
