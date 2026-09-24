"""Lifecycle chaining for connector imports (hardening, 2026-09-24).

Some source records have a lifecycle: an OCSF finding opens, is re-scanned,
is resolved; a STIX relationship is revised (a `stop_time` appears) or
revoked. Each version lands as a NEW observation (event ids embed the
version's time — history, not overwrite), but the store is append-only, so
the earlier open version (`valid_to` unset) stayed current next to the
closing one: the host read as still affected, and `valid_at` queries and
scope walks kept following the stale edge.

The loader here links each version to the one before it with a recorded
supersession (D-050 `supersedes`): the new version names the previous
version's observation id, so the reader treats the old row as history.
Versions are matched by a *chain key* — namespace, subject, predicate,
object and the record's own id in `attrs` (`finding_uid`, `stix_id`) — and
the previous version is looked up in the store (once per subject per run)
or taken from earlier in the same run. A batch is flushed before a claim
that must name a row still in it (ids are assigned by the store, and the
HTTP door refuses to supersede a row of the same batch). An out-of-order
older version is recorded without superseding anything newer.

Two sinks: straight into a store (the registry gate and provenance
resolution the queue consumer applies), or the engine's batch API (the
lookups go to GET /v1/entities/{type}/{key}/observations). NDJSON `emit`
has no store to ask, so it does not chain.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from datetime import datetime, timezone
from typing import Callable, Hashable, Iterable

from ..contracts import ClaimIn, DocumentIn, EntityRef, Observation

LOOKUP_LIMIT = 1000     # rows per subject a lookup reads (the HTTP route's maximum)

ChainKey = Callable[[object], Hashable | None]


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def keyed_by(id_attr: str, predicates: set[str] | None = None,
             where: Callable[[object], bool] | None = None) -> ChainKey:
    """A chain key over claims AND stored observations (both carry
    namespace, subject, predicate, object, attrs): versions of one source
    record share it. None: the row is not part of any chain."""
    def key(row) -> Hashable | None:
        if predicates is not None and row.predicate not in predicates:
            return None
        if where is not None and not where(row):
            return None
        rid = (row.attrs or {}).get(id_attr)
        if not rid:
            return None
        obj = row.object
        obj_key = (obj.type, obj.key) if isinstance(obj, EntityRef) else ("=", json.dumps(obj))
        return (row.namespace, row.subject.type, row.subject.key, row.predicate, obj_key, str(rid))
    return key


class StoreSink:
    """Writes into a GraphStore the way the queue consumer does (registry
    gate, provenance by artifact_event_id) and reports observation ids."""

    def __init__(self, store):
        from ..registry import RegistryCache
        self.store = store
        self.registry = RegistryCache(store)
        self.totals = {"recorded": 0, "accepted": 0, "skipped": 0, "rejected": 0}

    def lookup(self, namespace: str, ref: EntityRef) -> list[Observation]:
        return self.store.observations_for(namespace, ref, limit=LOOKUP_LIMIT)

    def write(self, envelopes: list) -> list[str | None]:
        from ..consumer import resolve_provenance
        from ..registry import validate_claim
        ids: list[str | None] = [None] * len(envelopes)
        claims: list[tuple[int, ClaimIn]] = []
        for i, env in enumerate(envelopes):
            if isinstance(env, DocumentIn):
                self.store.store_artifact(env)
                self.totals["accepted"] += 1
                continue
            problem = validate_claim(self.registry.get(env.namespace), env)
            if problem is not None:
                print(f"claim {env.event_id}: rejected: {problem}", file=sys.stderr)
                self.totals["rejected"] += 1
                continue
            problem = resolve_provenance(self.store, env)
            if problem is not None:
                print(f"claim {env.event_id}: skipped: {problem}", file=sys.stderr)
                self.totals["skipped"] += 1
                continue
            claims.append((i, env))
        if claims:
            for (i, _), obs in zip(claims, self.store.record_claims([c for _, c in claims])):
                ids[i] = obs.id
            self.totals["recorded"] += len(claims)
        return ids


class HttpSink:
    """Posts batches to /v1/ingest/batch (retried on 429/5xx like the bulk
    loader) and looks prior versions up through the raw observations route."""

    def __init__(self, url: str, key: str | None):
        self.url = url.rstrip("/")
        self.key = key
        self.totals = {"total": 0, "recorded": 0, "accepted": 0, "rejected": 0}
        self._n = 0

    def lookup(self, namespace: str, ref: EntityRef) -> list[Observation]:
        from ..ingest import request_json
        headers = {"X-Loom-Key": self.key} if self.key else {}
        path = (f"/v1/entities/{urllib.parse.quote(ref.type, safe='')}/{urllib.parse.quote(ref.key, safe='')}"
                f"/observations?limit={LOOKUP_LIMIT}&namespace={urllib.parse.quote(namespace, safe='')}")
        body = request_json(self.url + path, None, headers, method="GET",
                            what=f"lookup {ref.type}:{ref.key}")
        return [Observation.model_validate(o) for o in body.get("observations", [])]

    def write(self, envelopes: list) -> list[str | None]:
        from ..ingest import post_batch
        self._n += 1
        body = post_batch(self.url, [e.model_dump_json(exclude_none=True) for e in envelopes],
                          self.key, what=f"batch {self._n}")
        for k in self.totals:
            self.totals[k] += int(body.get(k, 0))
        ids: list[str | None] = [None] * len(envelopes)
        for r in body.get("results", []):
            if r.get("status") == "rejected":
                print(f"batch {self._n} item {r['index']}: rejected: {r.get('detail')}", file=sys.stderr)
            elif r.get("observation_id") is not None and 0 <= r.get("index", -1) < len(envelopes):
                ids[r["index"]] = r["observation_id"]
        return ids


def load_chained(envs: Iterable[ClaimIn | DocumentIn], sink, chain_key: ChainKey,
                 size: int = 500, requires_prior: Callable[[ClaimIn], bool] | None = None,
                 stats: dict[str, int] | None = None) -> dict[str, int]:
    """Write `envs` through `sink` in batches of `size`, setting
    `supersedes` on every claim that continues a chain (see the module
    doc). A claim for which `requires_prior` is true is dropped when there
    is no earlier version to supersede (a STIX revocation of something
    never imported). Returns the sink's totals, plus `superseded`."""
    stats = stats if stats is not None else {}
    # chain key -> [observed_at, observation id or None while in the batch, event_id]
    latest: dict[Hashable, list] = {}
    looked_up: set[tuple[str, str, str]] = set()
    batch: list = []
    waiting: dict[str, list] = {}           # event_id -> its `latest` entry, until the batch lands
    superseded = 0

    def flush() -> None:
        if not batch:
            return
        ids = sink.write(batch)
        for env, oid in zip(batch, ids):
            entry = waiting.pop(getattr(env, "event_id", None) or "", None)
            if entry is not None:
                if oid is None:              # rejected: it cannot be superseded later in the run
                    for k, v in list(latest.items()):
                        if v is entry:
                            del latest[k]
                else:
                    entry[1] = oid
        waiting.clear()
        batch.clear()

    def prime(namespace: str, ref: EntityRef) -> None:
        mark = (namespace, ref.type, ref.key)
        if mark in looked_up:
            return
        looked_up.add(mark)
        for obs in sink.lookup(namespace, ref):
            k = chain_key(obs)
            if k is None:
                continue
            seen = latest.get(k)
            if seen is None or _aware(obs.observed_at) > seen[0]:
                latest[k] = [_aware(obs.observed_at), obs.id, obs.event_id]

    for env in envs:
        k = chain_key(env) if isinstance(env, ClaimIn) else None
        if k is not None:
            prime(env.namespace, env.subject)
            prev = latest.get(k)
            if prev is not None and prev[1] is None and prev[2] != env.event_id:
                flush()                      # the previous version is in this batch: land it first
                prev = latest.get(k)
            at = _aware(env.observed_at)
            if prev is not None and prev[2] != env.event_id and prev[0] <= at and prev[1] \
                    and not env.supersedes:
                env = env.model_copy(update={"supersedes": prev[1]})
                superseded += 1
            elif requires_prior is not None and requires_prior(env) and (prev is None or prev[2] == env.event_id):
                stats["dropped_no_prior"] = stats.get("dropped_no_prior", 0) + 1
                continue
            if prev is None or prev[0] <= at:
                entry = [at, None, env.event_id]
                latest[k] = entry
                if env.event_id:
                    waiting[env.event_id] = entry
        batch.append(env)
        if len(batch) >= size:
            flush()
    flush()
    return {**sink.totals, "superseded": superseded}
