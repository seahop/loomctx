"""The GraphStore interface. All persistence lives behind this (decision D-002).

No code outside src/loom/store/ may touch a database directly. New backends
(Neo4j, Kùzu, ...) implement this ABC and become drop-in via configuration.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Iterator

from ..contracts import (
    Artifact, ClaimIn, DocumentIn, Entity, EntityRef, Observation,
    SchemaRegistration,
)


class GraphStore(ABC):
    @abstractmethod
    def upsert_entity(self, namespace: str, ref: EntityRef) -> Entity:
        """Return the canonical entity for ref, creating it if new."""

    @abstractmethod
    def get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        """Resolve by natural key, following alias records from prior merges;
        None if unknown."""

    # ------------------------------------------- entity resolution (D-019)

    @abstractmethod
    def add_alias(self, namespace: str, alias: EntityRef, into: EntityRef) -> None:
        """Record that `alias` (type:key) refers to the canonical `into`."""

    @abstractmethod
    def merge_entities(
        self, namespace: str, from_ref: EntityRef, into_ref: EntityRef
    ) -> bool:
        """Fold `from_ref` into `into_ref`: repoint its observations, record
        it as an alias, delete the now-empty node. Reversible via the alias
        record; no observation is ever lost. False if either side is unknown
        or they are the same entity."""

    @abstractmethod
    def merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        """Groups of entities that share a natural key across differing types
        (the drift LLM extraction produces, e.g. ip vs ip_address)."""

    @abstractmethod
    def fuzzy_merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        """Groups of entities whose *normalized* keys collide but whose raw
        keys differ (web-01 / web01 / WEB_01) — resolution tier 2 (D-024).
        Same-type members are safe to auto-merge; cross-type ones need
        adjudication."""

    # ------------------------------------------------ schema registry (D-024)

    @abstractmethod
    def put_schema(self, registration: SchemaRegistration) -> SchemaRegistration:
        """Merge a registration into the namespace's registry (additive by
        name); returns the effective registry."""

    @abstractmethod
    def get_schema(self, namespace: str) -> SchemaRegistration | None: ...

    @abstractmethod
    def namespace_summary(self) -> dict[str, dict[str, int]]:
        """Every namespace that holds entities -> {entity type: count}. What
        an agent needs to orient itself before it can ask anything (D-036)."""

    @abstractmethod
    def record_claim(self, claim: ClaimIn) -> Observation:
        """Append one observation (auto-creating subject/object entities).

        With an event_id, a replay returns the original observation instead
        of appending (D-014) — race-safe across writer processes. If that
        original has since been redacted, the returned observation is a
        stand-in carrying the id but no content (object "[redacted]",
        attrs {"redacted": true}): replaying an event never resurrects data.
        """

    def record_claims(self, claims: list[ClaimIn]) -> list[Observation]:
        """Batch append. Backends override to commit once per batch — the
        difference between one fsync per claim and one per batch (D-011)."""
        return [self.record_claim(c) for c in claims]

    @abstractmethod
    def observations_for(
        self, namespace: str, ref: EntityRef, limit: int = 100
    ) -> list[Observation]:
        """Observations where ref is subject OR object, newest observed first."""

    def observations_for_many(
        self, namespace: str, refs: list[EntityRef], limit: int = 100
    ) -> dict[tuple[str, str], list[Observation]]:
        """observations_for for many refs at once: (type, key) -> its newest
        `limit` observations. Backends override with one round trip per
        chunk; a 1,077-entity scope was 1,077 round trips, 5 s on Postgres
        over a network versus 0.5 s in-process (D-043). Refs that resolve
        to nothing are absent from the result."""
        return {(r.type, r.key): self.observations_for(namespace, r, limit) for r in refs}

    @abstractmethod
    def search_entities(
        self, namespace: str, query: str, limit: int = 10,
        types: tuple[str, ...] | None = None,
    ) -> list[Entity]:
        """Entities whose key matches the query exactly or by prefix
        (case-insensitive; LIKE metacharacters in the query are literal).
        `types` restricts to those entity types *inside* the query so a
        scoped caller still gets `limit` results (H-C8). Used to resolve
        entity names mentioned inside a free-form question."""

    @abstractmethod
    def count_observations(self, namespace: str, ref: EntityRef) -> int:
        """Visible observations touching ref (subject or object) — the
        connectivity signal entity resolution ranks by (H-E3)."""

    @abstractmethod
    def subjects_citing(
        self, namespace: str, artifact_ids: list[str],
        allowed_types: tuple[str, ...] | None = None, per_artifact: int = 5,
    ) -> dict[str, list[EntityRef]]:
        """artifact_id -> the subjects of visible observations that cite
        it, so a passage found by meaning maps back to the entities it is
        about (D-040). Scoped callers see only subjects (and objects) in
        their types."""

    @abstractmethod
    def artifact_cited_within(
        self, namespace: str, artifact_id: str, allowed_types: tuple[str, ...]
    ) -> bool:
        """True if some visible observation whose entities all fall inside
        `allowed_types` carries provenance from this artifact — i.e. the
        document is part of a type-scoped caller's world (H-A6)."""

    @abstractmethod
    def store_artifact(self, doc: DocumentIn) -> Artifact:
        """Persist a document verbatim; extraction happens asynchronously later."""

    @abstractmethod
    def artifact_by_event(self, namespace: str, event_id: str) -> Artifact | None:
        """The document a sender ingested under this event_id, so claims can
        cite it by that id before they know the artifact id (D-039)."""

    @abstractmethod
    def get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        """Fetch a stored document by id."""

    @abstractmethod
    def ping(self) -> bool:
        """Cheap liveness probe of the backing database (/readyz)."""

    # ------------------------------------------------- enrichment (D-018)

    @abstractmethod
    def put_embeddings(
        self, namespace: str, model: str,
        items: list[tuple[str, list[float]]],
    ) -> None:
        """Store (observation_id, vector) pairs for one embedding model."""

    @abstractmethod
    def embeddings_for(
        self, namespace: str, ref_ids: list[str], model: str
    ) -> dict[str, list[float]]: ...

    @abstractmethod
    def observations_without_embeddings(
        self, model: str, limit: int = 128, shard: tuple[int, int] | None = None
    ) -> list[Observation]:
        """Backlog for the enrichment worker (tombstoned rows excluded).
        `shard=(i, n)` returns only the rows whose id hashes to partition
        i of n, so n workers split the backlog without coordination
        (D-031); n <= 16."""

    @abstractmethod
    def observations_by_ids(self, namespace: str, ids: list[str]) -> list[Observation]:
        """Visible observations for the given ids (tombstoned excluded),
        in no particular order."""

    # ------------------------------------------------ vector index (D-025)
    # The JSON `embeddings` / `doc_chunks` tables remain the portable source
    # of truth; each backend keeps an ANN index beside them (sqlite-vec /
    # pgvector) when the extension is available and falls back to an exact
    # scan otherwise. Scores are cosine similarity in [-1, 1].

    @abstractmethod
    def vector_backend(self) -> str:
        """'sqlite-vec', 'pgvector', or 'exact' (no extension available)."""

    @abstractmethod
    def nearest_observations(
        self, namespace: str, model: str, query: list[float], limit: int = 20
    ) -> list[tuple[str, float]]:
        """Namespace-wide k-NN over observation vectors: (observation_id,
        cosine) best first. Tombstoned observations are excluded."""

    @abstractmethod
    def nearest_chunks(
        self, namespace: str, model: str, query: list[float], limit: int = 20,
        artifact_ids: list[str] | None = None,
    ) -> list[tuple[dict, float]]:
        """k-NN over document passages, optionally restricted to the given
        artifacts: (chunk dict as in doc_chunks_for_artifacts, cosine)."""

    @abstractmethod
    def ensure_vector_index(self, model: str) -> dict:
        """Backfill the ANN index for `model` from the JSON tables (rows
        written before the extension was available, or imported). Returns
        {'backend', 'observations', 'chunks'} counts indexed."""

    @abstractmethod
    def pending_artifacts(
        self, limit: int = 4, now: datetime | None = None,
        lease: tuple[str, float] | None = None,
    ) -> list[Artifact]:
        """Artifacts still awaiting claim extraction whose backoff (if any)
        has elapsed as of `now` (default: the current time). With
        `lease=(worker_id, seconds)` the rows are *claimed* atomically for
        that long (D-031): other workers skip them until the lease expires
        or the artifact's status changes, so a fleet shares the backlog
        without double LLM spend."""

    @abstractmethod
    def defer_extraction(
        self, namespace: str, artifact_id: str, attempts: int, next_attempt_at: datetime
    ) -> None:
        """Record a failed extraction attempt and when to try again (H-D4);
        survives worker restarts, unlike in-memory backoff."""

    @abstractmethod
    def doc_chunks_by_seq(
        self, namespace: str, artifact_id: str, model: str, seqs: list[int]
    ) -> list[dict]:
        """Specific passages of one artifact (excerpt expansion: the
        neighbours of a cited chunk), same dict shape as
        doc_chunks_for_artifacts, ordered by seq."""

    @abstractmethod
    def schema_version(self) -> int:
        """The store's applied migration level (loom_meta), for /readyz and
        upgrade audits (H-B12)."""

    @abstractmethod
    def artifacts_needing_chunks(
        self, model: str, limit: int = 4, lease: tuple[str, float] | None = None
    ) -> list[Artifact]:
        """Non-blank text artifacts not yet chunked+embedded under `model`
        (vectors from different models never mix — H-D3). `lease` as in
        pending_artifacts; released when chunks are stored."""

    @abstractmethod
    def put_doc_chunks(
        self, namespace: str, artifact_id: str, model: str,
        chunks: list[tuple[int, int, int, str, list[float]]],
    ) -> None:
        """Store (seq, span_start, span_end, text, vector) passages embedded
        with `model`."""

    @abstractmethod
    def doc_chunks_for_artifacts(
        self, namespace: str, artifact_ids: list[str], model: str
    ) -> list[dict]:
        """Chunks (with vectors) embedded under `model` for the given
        artifacts, for excerpt ranking. Each dict: artifact_id, seq,
        span_start, span_end, text, vector, plus the artifact's source and
        observed_at (datetime) so an excerpt can be cited."""

    @abstractmethod
    def set_extraction_status(
        self, namespace: str, artifact_id: str, status: str
    ) -> None: ...

    @abstractmethod
    def get_dossier(self, namespace: str, ref: EntityRef) -> dict | None:
        """{'brief', 'observation_count', 'observation_ids', 'updated_at'}
        or None. observation_ids are what the brief was synthesized from —
        its citations (D-023)."""

    @abstractmethod
    def put_dossier(
        self, namespace: str, ref: EntityRef, brief: str,
        observation_count: int, observation_ids: list[str],
    ) -> None: ...

    @abstractmethod
    def dossier_candidates(
        self, min_new: int = 20, min_total: int = 5, limit: int = 4,
        lease: tuple[str, float] | None = None,
    ) -> list[tuple[str, EntityRef, int]]:
        """(namespace, entity, current observation count) for entities whose
        dossier is missing (>= min_total observations) or stale (>= min_new
        observations since the last build). `lease` claims the entities for
        one worker; released by put_dossier."""

    # ------------------------------------------------- lifecycle (D-016)

    @abstractmethod
    def redact(self, namespace: str, observation_id: str, reason: str) -> bool:
        """Tombstone one observation: it stops appearing in reads but the
        append-only record (and the tombstone itself) remains auditable.
        Returns False if the observation doesn't exist."""

    @abstractmethod
    def purge_older_than(self, namespace: str, before: datetime) -> int:
        """Retention sweep: hard-delete observations and artifacts observed
        before the cutoff, plus the derived rows that hung off them
        (embeddings, doc chunks, tombstones, dossiers of entities left with
        no observations). Entities themselves are kept. Returns
        observation + artifact rows removed."""

    @abstractmethod
    def iter_observations(self, namespace: str | None = None) -> Iterator[Observation]:
        """Every observation (tombstoned included — export is a backup, and
        the matching tombstones are exported alongside via iter_tombstones)."""

    @abstractmethod
    def iter_entities(self, namespace: str | None = None) -> Iterator[Entity]: ...

    @abstractmethod
    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]: ...

    @abstractmethod
    def iter_aliases(self, namespace: str | None = None) -> Iterator[dict]:
        """{'namespace', 'alias': 'type:key', 'canonical': {'type','key'}}
        for every merge alias (D-019) — part of a faithful export."""

    @abstractmethod
    def iter_tombstones(self, namespace: str | None = None) -> Iterator[dict]:
        """{'namespace', 'observation_id', 'reason', 'recorded_at'} for every
        redaction (D-016) — exported so a restore never un-redacts."""

    @abstractmethod
    def restore_observation(self, obs: Observation) -> None:
        """Insert an exported observation verbatim (import/migration path).
        Idempotent: an existing id or (namespace, event_id) is left alone."""

    @abstractmethod
    def restore_artifact(self, artifact: Artifact) -> None: ...

    @abstractmethod
    def restore_entity(self, entity: Entity) -> None:
        """Ensure an exported entity exists (keeps `provisional`/`created_at`
        when creating; leaves an existing one alone)."""

    @abstractmethod
    def restore_alias(self, namespace: str, alias: str, canonical: EntityRef) -> None: ...

    @abstractmethod
    def restore_tombstone(
        self, namespace: str, observation_id: str, reason: str, recorded_at: datetime
    ) -> None: ...

    @abstractmethod
    def wipe(self) -> None:
        """Delete all rows (test isolation and demo resets)."""

    @abstractmethod
    def close(self) -> None:
        """Release resources."""
