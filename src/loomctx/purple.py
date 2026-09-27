"""Purple-team correlation: what the red team did against what was detected (D-086).

    python -m loomctx.purple q3-purple --namespace netsec                 # LOOMCTX_DB store
    python -m loomctx.purple q3-purple --db postgresql://... --json
    python -m loomctx.purple q3-purple --after 2h --before 5m

For every action of an operation (`loomctx.connectors.oplog`), the detections
(`loomctx.connectors.ocsf` findings) on the same host inside a window around
it, each side cited:

  * detected   a finding on the target host within the window that maps to
               the action's ATT&CK technique (or its parent / a sub-technique)
  * host only  a finding on the target host in the window, on another or no
               technique — something fired, not necessarily for this
  * missed     nothing on the target host in the window
  * no target  the log names no host to look on

The target host is matched as resolved (D-083): its canonical entity, and
any entity of the same kind sharing an identifier with it (the short
hostname included — a join for a report, not a merge), so
`web-01` in the op log meets `web-01.corp.local` in the EDR's findings
before the resolution worker has folded them. Coverage gaps in either
source are reported with the result (D-082): a "missed" on a host whose
detections were never collected is not a miss by the defenders.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from . import coverage
from . import identity as ident
from .contracts import EntityRef, Observation

ACTIVITY_FACTS = ["performed_at", "uses_technique", "targets", "command", "procedure"]


@dataclass
class Match:
    finding: str
    title: str
    source: str
    detected_at: str
    latency_seconds: float
    level: str                       # technique | host
    techniques: list[str]
    cites: list[str]                 # observation ids: the detected_on edge, the technique edges


@dataclass
class Row:
    activity: str
    performed_at: str
    techniques: list[str]
    hosts: list[str]
    procedure: str | None
    status: str                      # detected | host_only | missed | no_target
    matches: list[Match] = field(default_factory=list)
    cites: list[str] = field(default_factory=list)


def _related(a: str, b: str) -> bool:
    """Same technique, or a technique and one of its sub-techniques."""
    return a == b or a.split(".")[0] == b.split(".")[0] and ("." not in a or "." not in b)


def _key(ref: EntityRef) -> tuple[str, str]:
    return (ref.type, ref.key)


def equivalents(store, namespace: str, refs: list[EntityRef],
                as_of: datetime | None = None) -> dict[tuple[str, str], set[tuple[str, str]]]:
    """Each ref's canonical entity plus every entity of its family sharing an
    identifier with it (D-083) — the short hostname included: this is a join
    for a report, not a merge, and Atomic logs `WEB-01` where the EDR has
    `web-01.corp.local`."""
    canon = store.resolve_refs(namespace, refs)
    base = {_key(r): canon.get(_key(r), r) for r in refs}
    out = {k: {_key(c), k} for k, c in base.items()}
    targets = list({_key(c): c for c in base.values()}.values())
    own = store.observations_for_many(namespace, targets, limit=200, observed_before=as_of,
                                      predicates=[ident.PREDICATE])
    idents: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for c in targets:
        for o in own.get(_key(c), []):
            if (o.subject == c and isinstance(o.object, EntityRef)
                    and ident.split(o.object.key)[0] in ident.KINDS):
                idents.setdefault(_key(o.object), set()).add(_key(c))
    if idents:
        shared = store.observations_for_many(
            namespace, [EntityRef(type=t, key=k) for t, k in idents], limit=200,
            observed_before=as_of, predicates=[ident.PREDICATE])
        for id_key, holders in idents.items():
            others = {_key(o.subject) for o in shared.get(id_key, [])}
            for h in holders:
                fam = ident.family(h[0])
                same = {o for o in others if fam and ident.family(o[0]) == fam}
                for k, c in base.items():
                    if _key(c) == h:
                        out[k] |= same
    return out


def correlate(store, namespace: str, operation: str,
              before: timedelta = timedelta(minutes=5), after: timedelta = timedelta(hours=24),
              as_of: datetime | None = None) -> tuple[list[Row], list[str]]:
    """Every action of `operation` with the detections around it, and notes
    (coverage gaps behind the result)."""
    op = EntityRef(type="operation", key=operation)
    members = store.observations_for_many(namespace, [op], limit=100_000, observed_before=as_of,
                                          predicates=["in_operation"]).get(_key(op), [])
    acts = list({_key(o.subject): o.subject for o in members if o.object == op}.values())
    facts: dict[tuple[str, str], list[Observation]] = {}
    for i in range(0, len(acts), 500):
        facts.update(store.observations_for_many(namespace, acts[i:i + 500], limit=100,
                                                 observed_before=as_of, predicates=ACTIVITY_FACTS))
    targets = list({_key(o.object): o.object for rows in facts.values() for o in rows
                    if o.predicate == "targets" and isinstance(o.object, EntityRef)}.values())
    same = equivalents(store, namespace, targets, as_of) if targets else {}
    host_refs = list({k: EntityRef(type=k[0], key=k[1]) for ks in same.values() for k in ks}.values())
    detections: dict[tuple[str, str], list[Observation]] = {}
    for i in range(0, len(host_refs), 500):
        got = store.observations_for_many(namespace, host_refs[i:i + 500], limit=5000,
                                          observed_before=as_of, predicates=["detected_on"])
        for k, rows in got.items():
            detections[k] = [o for o in rows if isinstance(o.object, EntityRef)
                             and _key(o.object) == k and o.subject.type == "finding"]
    findings = list({_key(o.subject): o.subject for rows in detections.values() for o in rows}.values())
    finding_facts: dict[tuple[str, str], list[Observation]] = {}
    for i in range(0, len(findings), 500):
        finding_facts.update(store.observations_for_many(
            namespace, findings[i:i + 500], limit=100, observed_before=as_of,
            predicates=["indicates", "title"]))

    rows: list[Row] = []
    for act in acts:
        mine = [o for o in facts.get(_key(act), []) if o.subject == act]
        when_obs = next((o for o in mine if o.predicate == "performed_at"), None)
        if when_obs is None:
            continue
        t = when_obs.observed_at
        techniques = sorted({o.object.key for o in mine if o.predicate == "uses_technique"
                             and isinstance(o.object, EntityRef)})
        hosts = [o.object for o in mine if o.predicate == "targets" and isinstance(o.object, EntityRef)]
        procedure = next((str(o.object) for o in mine if o.predicate == "procedure"), None)
        row = Row(activity=act.key, performed_at=t.isoformat(), techniques=techniques,
                  hosts=[f"{h.type}:{h.key}" for h in hosts], procedure=procedure, status="no_target",
                  cites=[o.id for o in mine if o.predicate in ("performed_at", "uses_technique", "targets")])
        if hosts:
            seen: set[str] = set()
            for h in hosts:
                for eq in same.get(_key(h), {_key(h)}):
                    for edge in detections.get(eq, []):
                        detected = edge.valid_from or edge.observed_at
                        if not (t - before <= detected <= t + after) or edge.id in seen:
                            continue
                        seen.add(edge.id)
                        ff = finding_facts.get(_key(edge.subject), [])
                        ftech = [o for o in ff if o.predicate == "indicates" and o.subject == edge.subject
                                 and isinstance(o.object, EntityRef)]
                        tids = sorted({o.object.key for o in ftech})
                        level = ("technique" if any(_related(a, b) for a in techniques for b in tids)
                                 else "host")
                        title = next((str(o.object) for o in ff if o.predicate == "title"), "")
                        row.matches.append(Match(
                            finding=edge.subject.key, title=title, source=edge.source,
                            detected_at=detected.isoformat(),
                            latency_seconds=round((detected - t).total_seconds(), 1), level=level,
                            techniques=tids, cites=[edge.id, *(o.id for o in ftech)]))
            row.matches.sort(key=lambda m: (m.level != "technique", m.latency_seconds))
            row.status = ("detected" if any(m.level == "technique" for m in row.matches)
                          else "host_only" if row.matches else "missed")
        rows.append(row)
    rows.sort(key=lambda r: r.performed_at)

    notes = []
    gap = coverage.note(coverage.gaps(store, namespace, ["uses_technique", "targets"], as_of),
                        "actions without it cannot be matched on it")
    if gap:
        notes.append(gap)
    return rows, notes


def summary(rows: list[Row]) -> dict:
    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r.status] = by_status.get(r.status, 0) + 1
    by_technique: dict[str, dict[str, int]] = {}
    for r in rows:
        for t in r.techniques or ["(none)"]:
            d = by_technique.setdefault(t, {})
            d[r.status] = d.get(r.status, 0) + 1
    latencies = [m.latency_seconds for r in rows if r.status == "detected"
                 for m in r.matches[:1] if m.level == "technique"]
    return {"actions": len(rows), "by_status": by_status, "by_technique": by_technique,
            "median_latency_seconds": statistics.median(latencies) if latencies else None}


def markdown(operation: str, rows: list[Row], notes: list[str]) -> str:
    s = summary(rows)
    lines = [f"# Purple report — {operation}", "",
             f"{s['actions']} actions: " + ", ".join(f"{v} {k.replace('_', ' ')}"
                                                     for k, v in sorted(s["by_status"].items())),
             ""]
    if s["median_latency_seconds"] is not None:
        lines += [f"Median time to a technique-level detection: {s['median_latency_seconds']:.0f} s", ""]
    lines += ["| When | Technique | Host | Procedure | Status | First detection | Latency |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        m = r.matches[0] if r.matches else None
        lines.append(f"| {r.performed_at[:19]} | {', '.join(r.techniques) or '-'} | "
                     f"{', '.join(h.split(':', 1)[1] for h in r.hosts) or '-'} | {r.procedure or '-'} | "
                     f"{r.status.replace('_', ' ')} | {(m.title or m.finding) if m else '-'} | "
                     f"{f'{m.latency_seconds:.0f} s' if m else '-'} |")
    for n in notes:
        lines += ["", n]
    return "\n".join(lines) + "\n"


def _duration(text: str) -> timedelta:
    m = re.fullmatch(r"(\d+)\s*([smhd])", text.strip())
    if not m:
        raise argparse.ArgumentTypeError("a duration like 30s, 5m, 2h, 1d")
    unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
    return timedelta(**{unit: int(m.group(1))})


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.purple", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("operation")
    parser.add_argument("--namespace", default="netsec")
    parser.add_argument("--db")
    parser.add_argument("--before", type=_duration, default=timedelta(minutes=5),
                        help="how early a detection may be stamped (clock skew; default 5m)")
    parser.add_argument("--after", type=_duration, default=timedelta(hours=24),
                        help="how late a detection may come (default 24h)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    from .store.factory import store_from_env, store_from_url
    store = store_from_url(args.db) if args.db else store_from_env()
    try:
        rows, notes = correlate(store, args.namespace, args.operation, args.before, args.after)
    finally:
        store.close()
    if args.json:
        print(json.dumps({"operation": args.operation, "summary": summary(rows),
                          "rows": [asdict(r) for r in rows], "notes": notes}, indent=2))
    else:
        print(markdown(args.operation, rows, notes))


if __name__ == "__main__":
    main()
