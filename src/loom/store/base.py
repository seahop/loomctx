"""The GraphStore interface. All persistence lives behind this (decision D-002).

No code outside src/loom/store/ may touch a database directly. New backends
(Neo4j, Kùzu, ...) implement this ABC and become drop-in via configuration.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

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

    @abstractmethod
    def observations_for(
        self, namespace: str, ref: EntityRef, limit: int = 100
    ) -> list[Observation]:
        """Observations where ref is subject OR object, newest observed first."""

    @abstractmethod
    def store_artifact(self, doc: DocumentIn) -> Artifact:
        """Persist a document verbatim; extraction happens asynchronously later."""

    @abstractmethod
    def get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        """Fetch a stored document by id."""

    @abstractmethod
    def close(self) -> None:
        """Release resources."""
