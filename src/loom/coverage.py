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
        where = f"{self.source} ({self.scope})"
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
    """Coverage short of complete for any of `predicates`."""
    wanted = set(predicates)
    if not wanted:
        return []
    out = []
    for obs in records(store, namespace, as_of):
        state = obs.attrs.get("state")
        if str(obs.object) not in wanted or state not in ("absent", "partial"):
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
