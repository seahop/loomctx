"""Data lifecycle CLI (D-016): export, import, retention purge, redaction.

Everything speaks the same JSONL shape, so an export is simultaneously a
backup, a migration path between store backends (SQLite <-> Postgres), and
proof that data is never trapped in Loom.

    python -m loom.lifecycle export  --out dump.jsonl [--namespace ns]
    python -m loom.lifecycle import  --path dump.jsonl [--db URL]
    python -m loom.lifecycle purge   --namespace ns --older-than-days 90
    python -m loom.lifecycle redact  --namespace ns --observation-id ID --reason "why"

--db defaults to $LOOM_DB (file path = SQLite, postgresql:// = Postgres).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from .contracts import Artifact, Observation
from .store.base import GraphStore
from .store.factory import store_from_url


def export_jsonl(store: GraphStore, out, namespace: str | None) -> dict[str, int]:
    counts = {"entities": 0, "observations": 0, "artifacts": 0}
    for entity in store.iter_entities(namespace):
        out.write(json.dumps({"type": "entity", "data": entity.model_dump(mode="json")}) + "\n")
        counts["entities"] += 1
    for obs in store.iter_observations(namespace):
        out.write(json.dumps({"type": "observation", "data": obs.model_dump(mode="json")}) + "\n")
        counts["observations"] += 1
    for artifact in store.iter_artifacts(namespace):
        out.write(json.dumps({"type": "artifact", "data": artifact.model_dump(mode="json")}) + "\n")
        counts["artifacts"] += 1
    return counts


def import_jsonl(store: GraphStore, lines) -> dict[str, int]:
    counts = {"entities": 0, "observations": 0, "artifacts": 0, "skipped": 0}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        kind, data = record.get("type"), record.get("data", {})
        if kind == "observation":
            store.restore_observation(Observation.model_validate(data))
            counts["observations"] += 1
        elif kind == "artifact":
            store.restore_artifact(Artifact.model_validate(data))
            counts["artifacts"] += 1
        elif kind == "entity":
            # entities are re-created implicitly by their observations; count
            # them so imports report faithfully, nothing to write directly
            counts["entities"] += 1
        else:
            counts["skipped"] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(prog="loom.lifecycle", description=__doc__)
    parser.add_argument("--db", default=os.environ.get("LOOM_DB", "loom.db"))
    sub = parser.add_subparsers(dest="command", required=True)

    p_export = sub.add_parser("export")
    p_export.add_argument("--out", default="-", help="file path or - for stdout")
    p_export.add_argument("--namespace", default=None)

    p_import = sub.add_parser("import")
    p_import.add_argument("--path", required=True)

    p_purge = sub.add_parser("purge")
    p_purge.add_argument("--namespace", required=True)
    p_purge.add_argument("--older-than-days", type=int, required=True)

    p_redact = sub.add_parser("redact")
    p_redact.add_argument("--namespace", required=True)
    p_redact.add_argument("--observation-id", required=True)
    p_redact.add_argument("--reason", required=True)

    args = parser.parse_args()
    store = store_from_url(args.db)
    try:
        if args.command == "export":
            out = sys.stdout if args.out == "-" else open(args.out, "w")
            try:
                counts = export_jsonl(store, out, args.namespace)
            finally:
                if out is not sys.stdout:
                    out.close()
            print(f"exported {counts}", file=sys.stderr)
        elif args.command == "import":
            with open(args.path) as fh:
                counts = import_jsonl(store, fh)
            print(f"imported {counts}")
        elif args.command == "purge":
            cutoff = datetime.now(timezone.utc) - timedelta(days=args.older_than_days)
            removed = store.purge_older_than(args.namespace, cutoff)
            print(f"purged {removed} rows from {args.namespace!r} "
                  f"(observed before {cutoff.date().isoformat()})")
        elif args.command == "redact":
            ok = store.redact(args.namespace, args.observation_id, args.reason)
            print("redacted" if ok else "no such observation")
            if not ok:
                sys.exit(1)
    finally:
        store.close()


if __name__ == "__main__":
    main()
