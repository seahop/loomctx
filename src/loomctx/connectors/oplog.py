"""Red-team operation logs in, cited activity claims out (D-086).

    python -m loomctx.connectors.oplog import ExecutionLog.csv --operation q3-purple
    python -m loomctx.connectors.oplog import attire.json --operation q3-purple --url http://loomctx:8000 --key ...
    python -m loomctx.connectors.oplog import actions.jsonl --operation op-bluebird
    python -m loomctx.connectors.oplog emit actions.csv --operation x > envelopes.jsonl

A record of what an authorized red team did — when, which ATT&CK
technique, against which host, as whom — so `loomctx.purple` can set it against
what the defenders' tools detected. It PARSES logs; it executes nothing.

Recognised (auto-detected):
  * Atomic Red Team's execution log (`Invoke-AtomicTest … -LoggingModule
    Default-ExecutionLogger`, CSV: Execution Time (UTC), Technique, Test Name,
    Hostname, Username, …)
  * the Attire JSON logger (`attire-version`, `execution-data`, `procedures`)
  * any CSV / JSON / JSONL whose columns name a time and a technique or a
    target: time|timestamp|datetime|executed_at, technique|technique_id|ttp|
    attack_id, host|hostname|target|target_host|computer, user|username|
    account, command|cmd, operator, outcome|status|result, tool, id

Model, in the environment's namespace (`netsec` by default):
  * `activity:<operation>:<id>` `in_operation` `operation:<name>`,
    `performed_at` (and observed at that time), `uses_technique`
    `technique:<T####[.###]>` (the ATT&CK connector's keys), `targets`
    `host:<name>` (with hostname / FQDN identifiers, D-083, so the target
    folds into the host other sources know), `as_user` an account,
    `command`, `operator`, `outcome`, `tool`
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from .. import coverage
from .. import identity as ident
from ..contracts import (ClaimIn, EntityRef, EntityTypeDef, PredicateDef,
                         SchemaRegistration)
from .endpoint import _account, _time

SOURCE_DEFAULT = "oplog"
NAMESPACE_DEFAULT = "netsec"
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)

ALIASES = {
    "time": ("execution time (utc)", "time", "timestamp", "datetime", "executed_at", "time-start",
             "start", "date"),
    "technique": ("technique", "technique_id", "techniques", "ttp", "attack_id", "mitre",
                  "mitre-technique-id"),
    "host": ("hostname", "host", "target", "target_host", "computer", "computername"),
    "user": ("username", "user", "account", "as_user"),
    "command": ("command", "cmd", "command_line", "cmdline"),
    "operator": ("operator", "operator_name"),
    "outcome": ("outcome", "status", "result", "exitcode"),
    "tool": ("tool", "executor", "module"),
    "id": ("id", "guid", "uuid", "task_id"),
    "name": ("test name", "name", "procedure-name", "description"),
}


def _eid(parts: str) -> str:
    if len(parts) <= 128:
        return parts
    return f"{parts[:96]}:{hashlib.sha256(parts.encode('utf-8', 'replace')).hexdigest()[:31]}"


def _pick(row: dict, field: str) -> Any:
    low = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
    for alias in ALIASES[field]:
        v = low.get(alias)
        if v not in (None, ""):
            return v
    return None


def detect(text: str) -> str:
    head = text.lstrip()[:2000]
    if head.startswith("{") and "attire-version" in head:
        return "attire"
    if head.startswith(("[", "{")):
        return "json"
    first = head.splitlines()[0] if head else ""
    if "Execution Time (UTC)" in first:
        return "atomic"
    if "," in first:
        return "csv"
    raise ValueError("unrecognised operation log; expected Atomic CSV, Attire JSON, CSV or JSON")


def _rows(text: str, fmt: str) -> Iterator[dict]:
    if fmt in ("atomic", "csv"):
        yield from csv.DictReader(io.StringIO(text))
        return
    if fmt == "attire":
        data = json.loads(text)
        target = (data.get("execution-data") or {}).get("target") or {}
        for proc in data.get("procedures") or []:
            for step in proc.get("steps") or [{}]:
                yield {"time": step.get("time-start") or (data.get("execution-data") or {}).get("time-generated"),
                       "technique": proc.get("mitre-technique-id"), "name": proc.get("procedure-name"),
                       "host": target.get("host"), "user": target.get("user"),
                       "command": step.get("command"), "tool": step.get("executor"),
                       "outcome": step.get("output-summary"),
                       "id": step.get("step-id") or proc.get("procedure-id")}
        return
    stripped = text.strip()
    try:
        data = json.loads(stripped)
        items = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        items = [json.loads(line) for line in stripped.splitlines() if line.strip()]
    yield from (i for i in items if isinstance(i, dict))


def to_envelopes(text: str, namespace: str, operation: str, source: str = SOURCE_DEFAULT,
                 fmt: str | None = None, stats: dict[str, int] | None = None) -> Iterator[ClaimIn]:
    stats = stats if stats is not None else {}
    fmt = fmt or detect(text)
    op_ref = EntityRef(type="operation", key=operation)
    shapes = coverage.Shapes()
    tally = {"rows": 0, "technique": 0, "host": 0, "user": 0}
    newest: datetime | None = None
    hosts_named: set[str] = set()
    for row in _rows(text, fmt):
        shapes.add(f"oplog:{fmt}", [k for k, v in row.items() if v not in (None, "")])
        when = _time(_pick(row, "time"))
        if when is None:
            stats["no_time"] = stats.get("no_time", 0) + 1
            continue
        when = min(when, datetime.now(timezone.utc))
        newest = when if newest is None or when > newest else newest
        techniques = sorted({t.upper() for t in _TECHNIQUE.findall(str(_pick(row, "technique") or ""))})
        host = str(_pick(row, "host") or "").strip().lower() or None
        rid = str(_pick(row, "id") or "") or hashlib.sha256(
            f"{when.isoformat()}|{host}|{techniques}|{_pick(row, 'command')}".encode()).hexdigest()[:16]
        ref = EntityRef(type="activity", key=f"{operation}:{rid}")
        stamp = when.strftime("%Y%m%dT%H%M%S")

        def claim(pred, obj, tag=""):
            return ClaimIn(namespace=namespace, event_id=_eid(f"oplog:{ref.key}:{stamp}:{pred}{tag}"),
                           subject=ref, predicate=pred, object=obj, observed_at=when,
                           source=source, attrs={"operation": operation})

        tally["rows"] += 1
        yield claim("in_operation", op_ref)
        yield claim("performed_at", when.isoformat())
        for t in techniques:
            yield claim("uses_technique", EntityRef(type="technique", key=t), f":{t}")
        tally["technique"] += bool(techniques)
        if host:
            tally["host"] += 1
            host_ref = EntityRef(type="host", key=host)
            yield claim("targets", host_ref)
            if host not in hosts_named:
                hosts_named.add(host)
                yield from ident.claims(namespace, host_ref,
                                        [("fqdn" if "." in host else "hostname", host)], when, source)
        account = _account(host or "unknown", _pick(row, "user")) if _pick(row, "user") else None
        if account:
            tally["user"] += 1
            yield claim("as_user", account[0])
            yield from ident.claims(namespace, account[0], account[1], when, source)
        for field in ("command", "operator", "outcome", "tool", "name"):
            value = _pick(row, field)
            if value not in (None, ""):
                yield claim("procedure" if field == "name" else field, str(value)[:2000])
        stats["activity"] = stats.get("activity", 0) + 1
    at = newest or datetime.now(timezone.utc)
    scope = f"operation:{operation}"
    for pred, key in (("uses_technique", "technique"), ("targets", "host"), ("as_user", "user")):
        yield coverage.claim(namespace, source, scope, pred, tally[key], tally["rows"], at)
    yield from shapes.claims(namespace, source, at)


def schema(namespace: str) -> SchemaRegistration:
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            EntityTypeDef(name="activity", description="one red-team action: when, which technique, "
                                                       "against what, as whom (D-086)"),
            EntityTypeDef(name="operation", description="a red-team or purple-team engagement"),
            EntityTypeDef(name="technique", description="an ATT&CK technique, keyed by its id (T1003.001)"),
            EntityTypeDef(name="host", description="a machine"),
            EntityTypeDef(name="user", description="an account"),
            coverage.ENTITY_TYPE, *ident.SCHEMA_TYPES,
        ],
        predicates=[
            *coverage.SCHEMA_PREDICATES, *ident.SCHEMA_PREDICATES,
            PredicateDef(name="in_operation", object_types=["operation"], containment=True,
                         description="the action belongs to this operation"),
            PredicateDef(name="uses_technique", object_types=["technique"],
                         description="the ATT&CK technique the action exercised"),
            PredicateDef(name="targets", object_types=["host"], description="the host acted on"),
            PredicateDef(name="as_user", object_types=["user"], description="the account used"),
            PredicateDef(name="performed_at", description="when the action ran"),
            PredicateDef(name="command", description="the command run (first 2,000 chars)"),
            PredicateDef(name="procedure", description="the test / procedure name"),
            PredicateDef(name="operator", description="who ran it"),
            PredicateDef(name="outcome", description="the logged outcome / exit code"),
            PredicateDef(name="tool", description="the executor / framework"),
        ],
    )


def _to_lines(envs: Iterable[ClaimIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.connectors.oplog", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default=NAMESPACE_DEFAULT)
    common.add_argument("--source", default=SOURCE_DEFAULT)
    common.add_argument("--operation", default=None,
                        help="the engagement these actions belong to (default: the file name)")
    common.add_argument("--format", choices=("atomic", "attire", "csv", "json"))
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common], help="parse and ingest")
    imp.add_argument("files", nargs="+")
    imp.add_argument("--url")
    imp.add_argument("--db")
    imp.add_argument("--key", default=os.environ.get("LOOMCTX_API_KEY"), type=str.strip)
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true")
    emit = sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    emit.add_argument("files", nargs="+")
    sub.add_parser("schema", parents=[common], help="print the schema")
    args = parser.parse_args(argv)
    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return
    stats: dict[str, int] = {}

    def envs() -> Iterator[ClaimIn]:
        for path in args.files:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                text = fh.read()
            op = args.operation or os.path.splitext(os.path.basename(path))[0]
            yield from to_envelopes(text, args.namespace, op, args.source, args.format, stats)

    if args.command == "emit":
        for line in _to_lines(envs()):
            sys.stdout.write(line)
        print(json.dumps({"envelopes": stats}), file=sys.stderr)
        return
    if args.url and args.db:
        parser.error("import: give --url or --db, not both")
    from ..ingest import fail_on_refusals, load_direct, post_batches
    from .vulns import register
    if not args.no_schema:
        register(schema(args.namespace), args.url, args.db, args.key)
    watch = coverage.Watch()
    lines = _to_lines(watch.wrap(envs()))
    totals = (post_batches(args.url, lines, args.batch, args.key) if args.url
              else load_direct(args.db, lines, args.batch))
    drift = watch.report(args.url, args.db, args.key)
    print(json.dumps({**totals, "envelopes": stats, "drift": [d.text() for d in drift]}))
    coverage.print_drift(drift)
    if stats.get("no_time"):
        print(f"{stats['no_time']} rows had no readable time and were skipped", file=sys.stderr)
    fail_on_refusals(totals, remote=bool(args.url))


if __name__ == "__main__":
    main()
