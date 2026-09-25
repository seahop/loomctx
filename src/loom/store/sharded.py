"""Namespace sharding (D-032): route each namespace to its own database.

Namespaces already isolate *data*; a `ShardedStore` lets them also have
their own *capacity*. `LOOM_SHARDS` maps namespaces to connection strings
(SQLite paths or Postgres DSNs — mixing is fine); everything else goes to
`LOOM_DB`. The rest of the system sees one `GraphStore`.

Routing rules, in order:
1. A `namespace` argument (or an envelope/record carrying one) picks the
   shard.
2. `namespace=None` admin calls (`iter_*`, `merge_candidates`, ...) fan out
   and concatenate.
3. Worker backlog calls (`pending_artifacts`, `observations_without_embeddings`,
   ...) walk the shards until `limit` is filled, so a lease is never taken
   on a row that isn't returned.
4. Health/maintenance (`ping`, `wipe`, `close`, `ensure_vector_index`) hit
   every shard.

Moving a tenant is `lifecycle export` from the old shard, `import` into the
new one, then flipping the map (restart the engines). A small team never
sets `LOOM_SHARDS` and never sees this class.
"""

from __future__ import annotations

import abc
import inspect
from datetime import datetime
from typing import Iterator

from ..contracts import (
    Artifact, ClaimIn, DocumentIn, Entity, EntityRef, Observation,
    SchemaRegistration,
)
from .base import GraphStore


class ShardedStore(GraphStore):
    def __init__(self, default: GraphStore, shards: dict[str, GraphStore]):
        self._default = default
        self._map = dict(shards)
        # unique stores, default first, for fan-out
        self._all: list[GraphStore] = [default]
        for s in shards.values():
            if all(s is not x for x in self._all):
                self._all.append(s)

    def shard_for(self, namespace: str) -> GraphStore:
        return self._map.get(namespace, self._default)

    def describe(self) -> dict[str, int]:
        """namespace -> shard index (0 = default), for /readyz and audits."""
        index = {id(s): i for i, s in enumerate(self._all)}
        return {ns: index[id(s)] for ns, s in self._map.items()}

    # ---------------------------------------------------- explicit routing

    def record_claim(self, claim: ClaimIn) -> Observation:
        return self.shard_for(claim.namespace).record_claim(claim)

    def record_claims(self, claims: list[ClaimIn]) -> list[Observation]:
        # group by shard, write each batch once, restore the caller's order
        groups: dict[int, list[tuple[int, ClaimIn]]] = {}
        for i, c in enumerate(claims):
            groups.setdefault(id(self.shard_for(c.namespace)), []).append((i, c))
        out: list[Observation | None] = [None] * len(claims)
        for _, items in groups.items():
            store = self.shard_for(items[0][1].namespace)
            for (i, _), obs in zip(items, store.record_claims([c for _, c in items])):
                out[i] = obs
        return out  # type: ignore[return-value]

    def store_artifact(self, doc: DocumentIn) -> Artifact:
        return self.shard_for(doc.namespace).store_artifact(doc)

    def put_schema(self, registration: SchemaRegistration) -> SchemaRegistration:
        return self.shard_for(registration.namespace).put_schema(registration)

    def restore_observation(self, obs: Observation) -> None:
        self.shard_for(obs.namespace).restore_observation(obs)

    def restore_artifact(self, artifact: Artifact) -> None:
        self.shard_for(artifact.namespace).restore_artifact(artifact)

    def restore_entity(self, entity: Entity) -> None:
        self.shard_for(entity.namespace).restore_entity(entity)

    def restore_merge(self, record: dict) -> None:
        self.shard_for(record["namespace"]).restore_merge(record)

    # ------------------------------------------------ fan-out (admin/worker)

    def _fan(self, name: str, *args, **kwargs) -> list:
        out: list = []
        for s in self._all:
            out.extend(getattr(s, name)(*args, **kwargs))
        return out

    def _fill(self, name: str, limit: int, *args, **kwargs) -> list:
        """Walk shards until `limit` rows are collected — leased calls
        therefore never claim more than they return."""
        out: list = []
        for s in self._all:
            room = limit - len(out)
            if room <= 0:
                break
            out.extend(getattr(s, name)(*args, limit=room, **kwargs))
        return out

    def merge_candidates(self, namespace: str | None = None, limit: int = 50) -> list[list[Entity]]:
        if namespace is not None:
            return self.shard_for(namespace).merge_candidates(namespace, limit)
        return self._fill("merge_candidates", limit, None)

    def fuzzy_merge_candidates(self, namespace: str | None = None, limit: int = 50) -> list[list[Entity]]:
        if namespace is not None:
            return self.shard_for(namespace).fuzzy_merge_candidates(namespace, limit)
        return self._fill("fuzzy_merge_candidates", limit, None)

    def observations_without_embeddings(self, model: str, limit: int = 128,
                                        shard: tuple[int, int] | None = None) -> list[Observation]:
        return self._fill("observations_without_embeddings", limit, model, shard=shard)

    def pending_artifacts(self, limit: int = 4, now: datetime | None = None,
                          lease: tuple[str, float] | None = None) -> list[Artifact]:
        return self._fill("pending_artifacts", limit, now=now, lease=lease)

    def artifacts_needing_chunks(self, model: str, limit: int = 4,
                                 lease: tuple[str, float] | None = None) -> list[Artifact]:
        return self._fill("artifacts_needing_chunks", limit, model, lease=lease)

    def dossier_candidates(self, min_new: int = 20, min_total: int = 5, limit: int = 4,
                           lease: tuple[str, float] | None = None) -> list[tuple[str, EntityRef, int]]:
        return self._fill("dossier_candidates", limit, min_new, min_total, lease=lease)

    def relation_summary(self, namespace: str) -> list[tuple[str, str, str | None, int]]:
        return self.shard_for(namespace).relation_summary(namespace)

    def namespace_summary(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for s in self._all:
            for ns, types in s.namespace_summary().items():
                for etype, n in types.items():
                    out.setdefault(ns, {})[etype] = out.get(ns, {}).get(etype, 0) + n
        return out

    def observations_for_many(self, namespace: str, refs: list[EntityRef], limit: int = 100,
                              observed_before: datetime | None = None,
                              predicates: list[str] | None = None,
                              ) -> dict[tuple[str, str], list[Observation]]:
        return self.shard_for(namespace).observations_for_many(
            namespace, refs, limit, observed_before=observed_before, predicates=predicates)

    def edges_to_carriers(self, namespace: str, hubs: list[EntityRef], via: list[str], predicates: list[str],
                          limit: int = 10_000, observed_before: datetime | None = None,
                          ) -> list[tuple[tuple[str, str], str, str]]:
        return self.shard_for(namespace).edges_to_carriers(
            namespace, hubs, via, predicates, limit, observed_before=observed_before)

    def iter_observations(self, namespace: str | None = None) -> Iterator[Observation]:
        yield from self._iter("iter_observations", namespace)

    def iter_entities(self, namespace: str | None = None,
                      since: datetime | None = None) -> Iterator[Entity]:
        yield from self._iter("iter_entities", namespace, since=since)

    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]:
        yield from self._iter("iter_artifacts", namespace)

    def iter_aliases(self, namespace: str | None = None) -> Iterator[dict]:
        yield from self._iter("iter_aliases", namespace)

    def iter_tombstones(self, namespace: str | None = None) -> Iterator[dict]:
        yield from self._iter("iter_tombstones", namespace)

    def iter_schemas(self, namespace: str | None = None) -> Iterator[SchemaRegistration]:
        yield from self._iter("iter_schemas", namespace)

    def iter_declines(self, namespace: str | None = None) -> Iterator[dict]:
        yield from self._iter("iter_declines", namespace)

    def iter_merges(self, namespace: str | None = None) -> Iterator[dict]:
        yield from self._iter("iter_merges", namespace)

    def _iter(self, name: str, namespace: str | None, **kwargs):
        if namespace is not None:
            yield from getattr(self.shard_for(namespace), name)(namespace, **kwargs)
            return
        for s in self._all:
            yield from getattr(s, name)(None, **kwargs)

    def ensure_vector_index(self, model: str) -> dict:
        out = {"backend": self.vector_backend(), "observations": 0, "chunks": 0}
        for s in self._all:
            r = s.ensure_vector_index(model)
            out["observations"] += r["observations"]
            out["chunks"] += r["chunks"]
        return out

    def vector_backend(self) -> str:
        kinds = sorted({s.vector_backend() for s in self._all})
        return kinds[0] if len(kinds) == 1 else "+".join(kinds)

    def schema_version(self) -> int:
        return min(s.schema_version() for s in self._all)

    def ping(self) -> bool:
        return all(s.ping() for s in self._all)

    def wipe(self) -> None:
        for s in self._all:
            s.wipe()

    def close(self) -> None:
        for s in self._all:
            s.close()


def _route_by_namespace(name: str):
    def method(self: ShardedStore, namespace: str, *args, **kwargs):
        return getattr(self.shard_for(namespace), name)(namespace, *args, **kwargs)
    method.__name__ = name
    method.__doc__ = getattr(GraphStore, name).__doc__
    return method


# Every remaining GraphStore method takes `namespace` first: generate the
# one-line router for each so a new store method can't be forgotten here.
for _name, _fn in list(vars(GraphStore).items()):
    if not getattr(_fn, "__isabstractmethod__", False) or _name in vars(ShardedStore):
        continue
    _params = list(inspect.signature(_fn).parameters)
    assert _params[1:2] == ["namespace"], f"ShardedStore needs explicit routing for {_name}"
    setattr(ShardedStore, _name, _route_by_namespace(_name))
abc.update_abstractmethods(ShardedStore)  # methods added after class creation
