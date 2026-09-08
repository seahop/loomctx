"""Schema registry semantics (D-024): what a namespace's registration means
for ingest validation and scope expansion. Persistence is the store's job
(`put_schema`/`get_schema`); this module is the pure logic on top.

Domain knowledge lives here as *data* (hard constraint 6): the core never
knows what a "host" or "member_of" is, only that a namespace declared them.
"""

from __future__ import annotations

import time

from .contracts import ClaimIn, EntityRef, SchemaRegistration
from .store.base import GraphStore

_TTL_SECONDS = 5.0


class RegistryCache:
    """Per-process, short-TTL cache so ingest doesn't pay a registry read
    per claim; registrations are rare, ingest is not."""

    def __init__(self, store: GraphStore, ttl: float = _TTL_SECONDS):
        self._store = store
        self._ttl = ttl
        self._cache: dict[str, tuple[float, SchemaRegistration | None]] = {}

    def get(self, namespace: str) -> SchemaRegistration | None:
        now = time.monotonic()
        hit = self._cache.get(namespace)
        if hit is not None and hit[0] > now:
            return hit[1]
        schema = self._store.get_schema(namespace)
        self._cache[namespace] = (now + self._ttl, schema)
        return schema

    def invalidate(self, namespace: str) -> None:
        self._cache.pop(namespace, None)


def validate_claim(schema: SchemaRegistration | None, claim: ClaimIn) -> str | None:
    """Why this claim violates the namespace's registry, or None if it is
    acceptable. Registered predicates always enforce their object_types;
    `strict` additionally rejects anything unregistered."""
    if schema is None:
        return None
    predicates = {p.name: p for p in schema.predicates}
    types = {t.name for t in schema.entity_types}
    pred = predicates.get(claim.predicate)
    if pred is None:
        if schema.strict:
            return (f"predicate {claim.predicate!r} is not registered in "
                    f"namespace {claim.namespace!r} (strict registry)")
    elif pred.object_types:
        if not isinstance(claim.object, EntityRef):
            return (f"predicate {claim.predicate!r} expects an entity object of "
                    f"type {sorted(pred.object_types)}, got a scalar")
        if claim.object.type not in pred.object_types:
            return (f"predicate {claim.predicate!r} expects an object of type "
                    f"{sorted(pred.object_types)}, got {claim.object.type!r}")
    if schema.strict and types:
        if claim.subject.type not in types:
            return (f"entity type {claim.subject.type!r} is not registered in "
                    f"namespace {claim.namespace!r} (strict registry)")
        if isinstance(claim.object, EntityRef) and claim.object.type not in types:
            return (f"entity type {claim.object.type!r} is not registered in "
                    f"namespace {claim.namespace!r} (strict registry)")
    return None


def containment_predicates(schema: SchemaRegistration | None) -> list[str]:
    """The predicates a scope follows when the caller names none."""
    if schema is None:
        return []
    return sorted(p.name for p in schema.predicates if p.containment)
