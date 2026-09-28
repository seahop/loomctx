"""What an import collected (D-082).

A partial export and a sparse environment look the same once loaded: no
`has_ace` edge into an object reads as "nobody holds rights on it" whether
the ACLs were empty or were never dumped. A connector that can tell the two
apart records it: one ordinary, cited claim per predicate it covers,

    coverage:collection -collected-> "has_ace"
        attrs {source, scope, with, of, state, types}

meaning the import from `source` carried the data behind `has_ace` for
`with` of the `of` objects in `scope` (`state`: complete / partial /
absent). A connector records only absences its format makes meaningful —
every AD object has a security descriptor, so a missing one was not
collected; a missing `memberOf` may just mean no groups, so it is not
counted. Reads consult the newest record per (source, scope, predicate):
a scope walk or find_path over a predicate some import did not fully carry
says so in `notes`, so "no path" is not taken for "no access".

The core knows no domain here: predicates are opaque names, and which
absences count is the connector's call.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from .contracts import ClaimIn, EntityRef, EntityTypeDef, Observation, PredicateDef

COVERAGE_REF = EntityRef(type="coverage", key="collection")
# shapes (D-085) on their own entity: a busy source writes many coverage
# records, and a newest-N read of one shared entity evicted the shapes
PREDICATE = "collected"
ENTITY_TYPE = EntityTypeDef(name="coverage", description="what the imports collected (D-082)")
PREDICATE_DEF = PredicateDef(
    name=PREDICATE,
    description="an import carried the data behind the named predicate for `with` of "
                "`of` objects in `scope` (attrs); complete / partial / absent (D-082)")


def state_of(with_: int, of: int) -> str:
    if of <= 0 or with_ >= of:
        return "complete"
    return "absent" if with_ == 0 else "partial"


def claim(namespace: str, source: str, scope: str, predicate: str, with_: int, of: int,
          observed_at: datetime, types: list[str] | None = None) -> ClaimIn:
    """One coverage record. Idempotent per (source, scope, predicate, export
    time); a later export's record supersedes it by recency."""
    stamp = observed_at.strftime("%Y%m%dT%H%M%S")
    attrs = {"source": source, "scope": scope, "with": with_, "of": of,
             "state": state_of(with_, of)}
    if types:
        attrs["types"] = sorted(types)
    key = f"coverage:{source}:{scope}:{predicate}:{stamp}"
    if len(key) > 128:   # content-addressed, never truncated into a collision
        key = f"{key[:96]}:{hashlib.sha256(key.encode()).hexdigest()[:31]}"
    return ClaimIn(namespace=namespace, event_id=key,
                   subject=COVERAGE_REF, predicate=PREDICATE, object=predicate,
                   observed_at=observed_at, source=source, attrs=attrs)


@dataclass
class Gap:
    predicate: str
    source: str
    scope: str
    state: str
    with_: int
    of: int
    types: tuple[str, ...]
    observation_id: str

    def text(self) -> str:
        # the coverage record's id, cite-shaped: an agent reporting the gap
        # can cite it like any fact (D-092)
        where = f"{self.source} ({self.scope}) [{self.observation_id[:12]}]"
        if self.state == "absent":
            return f"'{self.predicate}' was not collected by {where}"
        return (f"'{self.predicate}' was collected by {where} for only "
                f"{self.with_:,} of {self.of:,} objects")


def records(store, namespace: str, as_of: datetime | None = None) -> list[Observation]:
    """The newest coverage record per (source, scope, predicate)."""
    rows = store.observations_for_many(namespace, [COVERAGE_REF], limit=5000,
                                       observed_before=as_of, predicates=[PREDICATE])
    newest: dict[tuple[str, str, str], Observation] = {}
    for obs in sorted(rows.get((COVERAGE_REF.type, COVERAGE_REF.key), []),
                      key=lambda o: o.observed_at, reverse=True):
        key = (str(obs.attrs.get("source", obs.source)), str(obs.attrs.get("scope", "")),
               str(obs.object))
        newest.setdefault(key, obs)
    return list(newest.values())


def gaps(store, namespace: str, predicates, as_of: datetime | None = None) -> list[Gap]:
    """Coverage short of complete for any of `predicates` (None: any)."""
    wanted = None if predicates is None else set(predicates)
    if wanted is not None and not wanted:
        return []
    out = []
    for obs in records(store, namespace, as_of):
        state = obs.attrs.get("state")
        if (wanted is not None and str(obs.object) not in wanted) or state not in ("absent", "partial"):
            continue
        out.append(Gap(predicate=str(obs.object), source=str(obs.attrs.get("source", obs.source)),
                       scope=str(obs.attrs.get("scope", "")), state=str(state),
                       with_=int(obs.attrs.get("with", 0) or 0), of=int(obs.attrs.get("of", 0) or 0),
                       types=tuple(obs.attrs.get("types") or ()), observation_id=obs.id))
    return sorted(out, key=lambda g: (g.predicate, g.source, g.scope))


def note(found: list[Gap], consequence: str, limit: int = 4) -> str | None:
    """One note naming the gaps (the first `limit`, then a count)."""
    if not found:
        return None
    shown = "; ".join(g.text() for g in found[:limit])
    more = f"; and {len(found) - limit} more" if len(found) > limit else ""
    return f"coverage: {shown}{more} — {consequence}"


# --------------------------------------------------------------- drift (D-085) #
# A tool upgrade that renames or drops a field does not fail an import: the
# parser just stops finding it, and the facts it carried quietly stop
# arriving. Each import therefore records the SHAPE of what it read — per
# kind of object, the fields seen and in how many objects — and the next
# import from the same source is compared with it.

SHAPE = "shape"
SHAPE_REF = EntityRef(type="coverage", key="shapes")
SHAPE_DEF = PredicateDef(
    name=SHAPE,
    description="the fields an import read per kind of object (attrs fields: name -> "
                "objects carrying it), compared import to import to catch format drift (D-085)")
_DRIFT_SHARE = 0.05     # a field in fewer than 5 % of objects is noise, not a format change
_MAX_FIELDS = 300


SCHEMA_PREDICATES = [PREDICATE_DEF, SHAPE_DEF]


def shape_claim(namespace: str, source: str, kind: str, fields: dict[str, int], objects: int,
                observed_at: datetime) -> ClaimIn:
    stamp = observed_at.strftime("%Y%m%dT%H%M%S")
    top = dict(sorted(fields.items(), key=lambda kv: (-kv[1], kv[0]))[:_MAX_FIELDS])
    key = f"shape:{source}:{kind}:{stamp}"
    if len(key) > 128:
        key = f"{key[:96]}:{hashlib.sha256(key.encode()).hexdigest()[:31]}"
    return ClaimIn(namespace=namespace, event_id=key, subject=SHAPE_REF, predicate=SHAPE,
                   object=kind, observed_at=observed_at, source=source,
                   attrs={"source": source, "kind": kind, "objects": objects, "fields": top})


class Shapes:
    """Tallies field names per kind while a connector parses."""

    def __init__(self) -> None:
        self.fields: dict[str, dict[str, int]] = {}
        self.objects: dict[str, int] = {}

    def add(self, kind: str, names) -> None:
        tally = self.fields.setdefault(kind, {})
        for name in set(names):
            tally[str(name)] = tally.get(str(name), 0) + 1
        self.objects[kind] = self.objects.get(kind, 0) + 1

    def claims(self, namespace: str, source: str, observed_at: datetime) -> list[ClaimIn]:
        return [shape_claim(namespace, source, kind, self.fields[kind], self.objects[kind],
                            observed_at) for kind in sorted(self.fields)]


@dataclass
class Drift:
    source: str
    kind: str
    added: list[str]
    removed: list[str]
    before: str          # observed_at of the earlier shape
    after: str

    def text(self) -> str:
        parts = []
        if self.removed:
            parts.append(f"no longer carries {', '.join(self.removed[:8])}"
                         + (f" (+{len(self.removed) - 8})" if len(self.removed) > 8 else ""))
        if self.added:
            parts.append(f"newly carries {', '.join(self.added[:8])}"
                         + (f" (+{len(self.added) - 8})" if len(self.added) > 8 else ""))
        return (f"{self.source} {self.kind}: " + "; ".join(parts)
                + f" (export of {self.after[:10]} vs {self.before[:10]}) — a changed tool version "
                  "or collection option; facts from the missing fields stop arriving")


def _common(attrs: dict) -> set[str]:
    n = max(int(attrs.get("objects") or 0), 1)
    return {f for f, c in (attrs.get("fields") or {}).items() if c / n >= _DRIFT_SHARE}


def compare(before: Observation, after: Observation) -> Drift | None:
    old, new = _common(before.attrs), _common(after.attrs)
    added, removed = sorted(new - old), sorted(old - new)
    if not added and not removed:
        return None
    return Drift(source=str(after.attrs.get("source", after.source)),
                 kind=str(after.object), added=added, removed=removed,
                 before=before.observed_at.isoformat(), after=after.observed_at.isoformat())


def drift(observations: list[Observation]) -> list[Drift]:
    """Newest shape against the one before it, per (source, kind)."""
    by: dict[tuple[str, str], list[Observation]] = {}
    for o in observations:
        if o.predicate == SHAPE:
            by.setdefault((str(o.attrs.get("source", o.source)), str(o.object)), []).append(o)
    out = []
    for key in sorted(by):
        rows = sorted(by[key], key=lambda o: o.observed_at, reverse=True)
        distinct = []
        for o in rows:           # a re-import of the same export is not a second export
            if not distinct or o.observed_at != distinct[-1].observed_at:
                distinct.append(o)
        if len(distinct) > 1 and (d := compare(distinct[1], distinct[0])):
            out.append(d)
    return out


def stored(store, namespace: str, as_of: datetime | None = None) -> list[Observation]:
    rows = store.observations_for_many(namespace, [COVERAGE_REF, SHAPE_REF], limit=5000,
                                       observed_before=as_of, predicates=[PREDICATE, SHAPE])
    return [o for ref in (COVERAGE_REF, SHAPE_REF) for o in rows.get((ref.type, ref.key), [])]


def remote(url: str, namespace: str, key: str | None = None,
           ref: EntityRef = COVERAGE_REF) -> list[Observation]:
    """A coverage entity's records (coverage, or `SHAPE_REF` for shapes)
    through a running engine."""
    import urllib.parse
    import urllib.request
    q = urllib.parse.urlencode({"namespace": namespace, "limit": 1000})
    req = urllib.request.Request(
        f"{url.rstrip('/')}/v1/entities/{ref.type}/{ref.key}/observations?{q}",
        headers={"X-LoomCtx-Key": key} if key else {})
    import json
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read())
    return [Observation.model_validate(o) for o in body.get("observations", [])]


class Watch:
    """Wraps a connector's envelope stream: remembers the shape records it
    carries so the import can be compared with what is already stored."""

    def __init__(self) -> None:
        self.shapes: list[ClaimIn] = []

    def wrap(self, envs):
        for env in envs:
            if isinstance(env, ClaimIn) and env.predicate == SHAPE:
                self.shapes.append(env)
            yield env

    def report(self, url: str | None, db: str | None, key: str | None) -> list[Drift]:
        """Each shape this import sent, against the newest stored one from
        the same source and kind observed before it."""
        if not self.shapes:
            return []
        namespace = self.shapes[0].namespace
        # a gateway serves ingest only: the earlier shapes are read from the
        # engine named by LOOMCTX_READ_URL when the import went through one
        import os
        read_url = os.environ.get("LOOMCTX_READ_URL") or url
        try:
            if read_url:
                prior = remote(read_url, namespace, key, SHAPE_REF)
            else:
                from .store.factory import store_from_env, store_from_url
                store = store_from_url(db) if db else store_from_env()
                try:
                    prior = stored(store, namespace)
                finally:
                    store.close()
        except Exception as exc:  # noqa: BLE001 — a drift check never fails an import
            import sys
            hint = ("; the import URL serves no reads (a gateway?) — set LOOMCTX_READ_URL to the engine"
                    if "404" in str(exc) else "")
            print(f"drift check skipped: {exc}{hint}", file=sys.stderr)
            return []
        return self.against(prior)

    def against(self, prior: list[Observation]) -> list[Drift]:
        namespace = self.shapes[0].namespace if self.shapes else ""
        out = []
        for env in self.shapes:
            earlier = [o for o in prior if o.predicate == SHAPE and str(o.object) == env.object
                       and str(o.attrs.get("source", o.source)) == env.source
                       and o.observed_at <= env.observed_at]   # a same-second export is earlier too;
            # a re-import of the SAME export compares equal, so it is not drift
            if not earlier:
                continue
            before = max(earlier, key=lambda o: o.observed_at)
            after = Observation(id="new", namespace=namespace, subject=env.subject,
                                predicate=SHAPE, object=env.object, observed_at=env.observed_at,
                                recorded_at=env.observed_at, source=env.source, confidence=1.0,
                                attrs=env.attrs)
            if (d := compare(before, after)):
                out.append(d)
        return out


def print_drift(found: list[Drift]) -> None:
    import sys
    for d in found:
        print(f"drift: {d.text()}", file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    import argparse
    import json
    parser = argparse.ArgumentParser(prog="loomctx.coverage",
                                     description="what imports collected (D-082) and how their "
                                                 "format drifted (D-085)")
    parser.add_argument("command", choices=("gaps", "drift"))
    parser.add_argument("--namespace", default="netsec")
    parser.add_argument("--db")
    parser.add_argument("--url")
    parser.add_argument("--key")
    args = parser.parse_args(argv)
    if args.url:
        rows = remote(args.url, args.namespace, args.key,
                      SHAPE_REF if args.command == "drift" else COVERAGE_REF)
    else:
        from .store.factory import store_from_env, store_from_url
        store = store_from_url(args.db) if args.db else store_from_env()
        try:
            rows = stored(store, args.namespace)
        finally:
            store.close()
    if args.command == "drift":
        print(json.dumps([d.__dict__ for d in drift(rows)], indent=2))
        return
    newest: dict[tuple[str, str, str], Observation] = {}
    for o in sorted((o for o in rows if o.predicate == PREDICATE),
                    key=lambda o: o.observed_at, reverse=True):
        newest.setdefault((str(o.attrs.get("source")), str(o.attrs.get("scope")), str(o.object)), o)
    print(json.dumps([{"source": s, "scope": sc, "predicate": p, **{k: o.attrs.get(k) for k in
                       ("state", "with", "of")}} for (s, sc, p), o in sorted(newest.items())
                      if o.attrs.get("state") != "complete"], indent=2))


if __name__ == "__main__":
    main()
