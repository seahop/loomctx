"""Write-side gates shared by every surface that records claims (D-059).

The HTTP routes (single + batch) and the MCP `record_claim` tool apply the
same checks from here, so a rule cannot hold on one surface and lapse on
another. Each returns the problem as a string, or None.

Documents have no entity type. A type-scoped reader may read one only once
it backs a fact about entities in their world (H-A6) — which is only sound
if a writer cannot *make* a document back such a fact at will. Hence the
citation rule: a type-gated key may cite (provenance) only

1. a document it ingested itself (the engine stamps the uploading grant on
   the artifact, `attrs["loomctx.uploader"]`), or
2. a document that already backs a visible fact inside the key's entity
   types — one its holder could read anyway.

Ungated keys (no `entity_types`) and open dev mode cite anything, as before.
The NATS writer receives only the principal id; `AuthConfig.grant_by_id`
resolves it so the consumer can apply the same check.

The namespace-level views a type-scoped key gets (`scope_schema`,
`scope_counts`: GET /v1/schemas, MCP list/describe_namespace) live here too,
so every surface narrows them the same way.
"""

from __future__ import annotations

from typing import Any

from .auth import Grant
from .contracts import Artifact, ClaimIn, DocumentIn, EntityRef, SchemaRegistration
from .store.base import GraphStore

# Reserved artifact attribute: which grant ingested the document, and that
# grant's entity-type gate at the time (so the enrichment worker can keep
# extracted claims inside it without reading the keys file). Set by the
# engine only; a sender that supplies it is rejected.
UPLOADER_ATTR = "loomctx.uploader"


def uploader_of(artifact: Artifact) -> str | None:
    """The grant id that ingested this artifact, if the engine recorded one."""
    stamp = (artifact.attrs or {}).get(UPLOADER_ATTR)
    return stamp.get("grant") if isinstance(stamp, dict) else None


def stamp_uploader(doc: DocumentIn, grant: Grant | None) -> DocumentIn | str:
    """The document to store, with its uploader recorded — or the problem
    when the sender tried to supply the reserved attribute itself."""
    if UPLOADER_ATTR in doc.attrs:
        return f"attrs key {UPLOADER_ATTR!r} is reserved (the engine records the uploader)"
    if grant is None:
        return doc
    stamp: dict[str, Any] = {"grant": grant.id}
    if grant.entity_types is not None:
        stamp["entity_types"] = list(grant.entity_types)
    return doc.model_copy(update={"attrs": {**doc.attrs, UPLOADER_ATTR: stamp}})


def _in_types(grant: Grant, obs) -> bool:
    return grant.allows_entity_type(obs.subject.type) and (
        not isinstance(obs.object, EntityRef) or grant.allows_entity_type(obs.object.type))


def check_supersedes(store: GraphStore, claim: ClaimIn, grant: Grant | None = None) -> str | None:
    """A recorded supersession (D-050) must name a visible observation in
    the claim's namespace about the claim's subject — a correction stays
    on its subject, and a dangling or cross-tenant reference is a sender
    bug the read path would otherwise silently ignore. A type-gated key
    may only supersede an observation inside its entity types: retiring a
    fact is writing about it."""
    if not claim.supersedes:
        return None
    found = store.observations_by_ids(claim.namespace, [claim.supersedes])
    if not found:
        return (f"supersedes {claim.supersedes!r} does not name a visible observation in "
                f"namespace {claim.namespace!r}")
    old = found[0]
    if old.subject != claim.subject:
        return (f"supersedes {claim.supersedes!r} names an observation about "
                f"{old.subject.type}:{old.subject.key}, not {claim.subject.type}:"
                f"{claim.subject.key}; a correction stays on its subject")
    if grant is not None and not _in_types(grant, old):
        return (f"key {grant.id!r} is not scoped to the entity types of the observation "
                f"{claim.supersedes!r} names")
    return None


def check_citation(store: GraphStore, claim: ClaimIn, grant: Grant | None) -> str | None:
    """The citation rule above. Runs before the store resolves an
    artifact_event_id, so it looks the document up by whichever reference
    the claim carries."""
    prov = claim.provenance
    if prov is None or grant is None or grant.entity_types is None:
        return None
    ns = claim.namespace
    if prov.artifact_id:
        artifact = store.get_artifact(ns, prov.artifact_id)
        ref = f"provenance.artifact_id {prov.artifact_id!r}"
    else:
        artifact = store.artifact_by_event(ns, prov.artifact_event_id)
        ref = f"provenance.artifact_event_id {prov.artifact_event_id!r}"
    if artifact is None:
        return f"{ref} does not name a document in namespace {ns!r}; ingest the document first"
    if uploader_of(artifact) == grant.id:
        return None
    if store.artifact_cited_within(ns, artifact.id, grant.entity_types):
        return None
    return (f"key {grant.id!r} may cite only documents it ingested, or ones that already back "
            f"a fact about its entity types; {ref} is neither")


def scope_schema(schema: SchemaRegistration, grant: Grant | None) -> SchemaRegistration:
    """A namespace registry as a type-scoped reader may see it: only its
    entity types, and only the predicates that can reach them (a predicate
    with no object-type constraint stays; a constrained one keeps just the
    allowed object types). Unscoped callers get the registry unchanged."""
    if grant is None or grant.entity_types is None:
        return schema
    allowed = set(grant.entity_types)
    predicates = [
        p if not p.object_types else p.model_copy(
            update={"object_types": [t for t in p.object_types if t in allowed]})
        for p in schema.predicates
        if not p.object_types or allowed.intersection(p.object_types)
    ]
    return schema.model_copy(update={
        "entity_types": [e for e in schema.entity_types if e.name in allowed],
        "predicates": predicates,
    })


def scope_counts(counts: dict[str, int], grant: Grant | None) -> dict[str, int]:
    """Entity counts by type, restricted to the caller's entity types."""
    if grant is None or grant.entity_types is None:
        return dict(counts)
    return {t: n for t, n in counts.items() if t in grant.entity_types}
