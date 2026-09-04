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
        """Deterministic resolution by natural key; None if unknown."""

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
