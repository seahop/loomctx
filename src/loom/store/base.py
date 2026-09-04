"""The GraphStore interface. All persistence lives behind this (decision D-002).

No code outside src/loom/store/ may touch a database directly. New backends
(Neo4j, Kùzu, ...) implement this ABC and become drop-in via configuration.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Iterator

from ..contracts import Artifact, ClaimIn, DocumentIn, Entity, EntityRef, Observation


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
    def record_claim(self, claim: ClaimIn) -> Observation:
        """Append one observation (auto-creating subject/object entities)."""

    def record_claims(self, claims: list[ClaimIn]) -> list[Observation]:
        """Batch append. Backends override to commit once per batch — the
        difference between one fsync per claim and one per batch (D-011)."""
        return [self.record_claim(c) for c in claims]

    @abstractmethod
    def observations_for(
        self, namespace: str, ref: EntityRef, limit: int = 100
    ) -> list[Observation]:
        """Observations where ref is subject OR object, newest observed first."""

    @abstractmethod
    def search_entities(
        self, namespace: str, query: str, limit: int = 10
    ) -> list[Entity]:
        """Entities whose key matches the query exactly or by prefix. Used to
        resolve entity names mentioned inside a free-form question."""

    @abstractmethod
    def store_artifact(self, doc: DocumentIn) -> Artifact:
        """Persist a document verbatim; extraction happens asynchronously later."""

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
        self, model: str, limit: int = 128
    ) -> list[Observation]:
        """Backlog for the enrichment worker (tombstoned rows excluded)."""

    @abstractmethod
    def pending_artifacts(self, limit: int = 4) -> list[Artifact]:
        """Artifacts still awaiting claim extraction."""

    @abstractmethod
    def set_extraction_status(
        self, namespace: str, artifact_id: str, status: str
    ) -> None: ...

    @abstractmethod
    def get_dossier(self, namespace: str, ref: EntityRef) -> dict | None:
        """{'brief', 'observation_count', 'updated_at'} or None."""

    @abstractmethod
    def put_dossier(
        self, namespace: str, ref: EntityRef, brief: str,
        observation_count: int,
    ) -> None: ...

    @abstractmethod
    def dossier_candidates(
        self, min_new: int = 20, min_total: int = 5, limit: int = 4
    ) -> list[tuple[str, EntityRef, int]]:
        """(namespace, entity, current observation count) for entities whose
        dossier is missing (>= min_total observations) or stale (>= min_new
        observations since the last build)."""

    # ------------------------------------------------- lifecycle (D-016)

    @abstractmethod
    def redact(self, namespace: str, observation_id: str, reason: str) -> bool:
        """Tombstone one observation: it stops appearing in reads but the
        append-only record (and the tombstone itself) remains auditable.
        Returns False if the observation doesn't exist."""

    @abstractmethod
    def purge_older_than(self, namespace: str, before: datetime) -> int:
        """Retention sweep: hard-delete observations and artifacts observed
        before the cutoff. Returns rows removed."""

    @abstractmethod
    def iter_observations(self, namespace: str | None = None) -> Iterator[Observation]:
        """Every observation (tombstoned included — export is a backup)."""

    @abstractmethod
    def iter_entities(self, namespace: str | None = None) -> Iterator[Entity]: ...

    @abstractmethod
    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]: ...

    @abstractmethod
    def restore_observation(self, obs: Observation) -> None:
        """Insert an exported observation verbatim (import/migration path)."""

    @abstractmethod
    def restore_artifact(self, artifact: Artifact) -> None: ...

    @abstractmethod
    def wipe(self) -> None:
        """Delete all rows (test isolation and demo resets)."""

    @abstractmethod
    def close(self) -> None:
        """Release resources."""
