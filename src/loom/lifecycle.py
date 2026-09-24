"""Data lifecycle CLI (D-016): export, import, retention purge, redaction,
merge reversal.

Everything speaks the same JSONL shape, so an export is simultaneously a
backup, a migration path between store backends (SQLite <-> Postgres), and
proof that data is never trapped in Loom.

    python -m loom.lifecycle export  --out dump.jsonl [--namespace ns]
    python -m loom.lifecycle import  --path dump.jsonl
    python -m loom.lifecycle purge   --namespace ns --older-than-days 90
    python -m loom.lifecycle redact  --namespace ns --observation-id ID --reason "why"
    python -m loom.lifecycle unmerge --namespace ns --alias type:key

The store is the one the engine would build (`store_from_env`): LOOM_DB
plus LOOM_SHARDS (D-032) and LOOM_BLOB_* (D-033), so an export of a
sharded deployment covers every shard and offloaded bodies come back
whole. `--db URL` opens exactly one database instead — an escape hatch
that bypasses LOOM_SHARDS and LOOM_BLOB_* (offloaded rows export as stubs).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from .contracts import Artifact, Entity, EntityRef, Observation, SchemaRegistration
from .store.base import GraphStore
from .store.factory import store_from_env, store_from_url


def _line(kind: str, data) -> str:
    return json.dumps({"type": kind, "data": data}) + "\n"


def export_jsonl(store: GraphStore, out, namespace: str | None) -> dict[str, int]:
    """Everything a faithful restore needs, in dependency order: entities,
    the redaction tombstones (D-016), observations, artifacts, then the
    merge aliases (D-019) that qualify them, the schema registries (D-024),
    the adjudication declines (D-044) and the merge log that keeps merges
    reversible (schema v5). Tombstoned observations ARE exported (audit),
    and their tombstones ride along so a restore never un-redacts anything
    (hardening H-B4) — ahead of the observations they redact, so a restore
    streaming this file never serves a redacted row, even for the length
    of the import (D-058)."""
    counts = {"entities": 0, "observations": 0, "artifacts": 0,
              "aliases": 0, "tombstones": 0, "schemas": 0, "declines": 0, "merges": 0}
    for entity in store.iter_entities(namespace):
        out.write(_line("entity", entity.model_dump(mode="json")))
        counts["entities"] += 1
    for tomb in store.iter_tombstones(namespace):
        out.write(_line("tombstone", tomb))
        counts["tombstones"] += 1
    for obs in store.iter_observations(namespace):
        out.write(_line("observation", obs.model_dump(mode="json")))
        counts["observations"] += 1
    for artifact in store.iter_artifacts(namespace):
        out.write(_line("artifact", artifact.model_dump(mode="json")))
        counts["artifacts"] += 1
    for alias in store.iter_aliases(namespace):
        out.write(_line("alias", alias))
        counts["aliases"] += 1
    for schema in store.iter_schemas(namespace):
        out.write(_line("schema", schema.model_dump(mode="json")))
        counts["schemas"] += 1
    for decline in store.iter_declines(namespace):
        out.write(_line("decline", decline))
        counts["declines"] += 1
    for merge in store.iter_merges(namespace):
        out.write(_line("merge", merge))
        counts["merges"] += 1
    return counts


def _restore_tombstone(store: GraphStore, data: dict) -> None:
    store.restore_tombstone(
        data["namespace"], data["observation_id"], data["reason"],
        datetime.fromisoformat(data["recorded_at"]),
    )


def _records(lines):
    for line in lines:
        line = line.strip()
        if line:
            yield json.loads(line)


def import_jsonl(store: GraphStore, lines) -> dict[str, int]:
    """Restore an export. Tombstones land before any observation (D-058):
    dumps written before that order put them last, so a re-readable input
    (a list, or a seekable file) gets a first pass that applies only the
    tombstones — otherwise every redacted row was served, un-redacted,
    for the length of the import, and briefs citing it survived it."""
    counts = {"entities": 0, "observations": 0, "artifacts": 0,
              "aliases": 0, "tombstones": 0, "schemas": 0, "declines": 0, "merges": 0,
              "skipped": 0}
    early = False
    rereadable = isinstance(lines, (list, tuple))
    if not rereadable and hasattr(lines, "seekable"):
        try:
            rereadable = lines.seekable()
        except (OSError, ValueError):
            rereadable = False
    if rereadable:
        start = lines.tell() if hasattr(lines, "tell") else 0
        for record in _records(lines):
            if record.get("type") == "tombstone":
                _restore_tombstone(store, record.get("data", {}))
                counts["tombstones"] += 1
        if hasattr(lines, "seek"):
            lines.seek(start)
        early = True
    for record in _records(lines):
        kind, data = record.get("type"), record.get("data", {})
        if kind == "observation":
            store.restore_observation(Observation.model_validate(data))
            counts["observations"] += 1
        elif kind == "artifact":
            store.restore_artifact(Artifact.model_validate(data))
            counts["artifacts"] += 1
        elif kind == "entity":
            store.restore_entity(Entity.model_validate(data))
            counts["entities"] += 1
        elif kind == "alias":
            store.restore_alias(
                data["namespace"], data["alias"],
                EntityRef.model_validate(data["canonical"]),
            )
            counts["aliases"] += 1
        elif kind == "tombstone":
            if not early:
                _restore_tombstone(store, data)
                counts["tombstones"] += 1
        elif kind == "schema":
            store.put_schema(SchemaRegistration.model_validate(data))
            counts["schemas"] += 1
        elif kind == "decline":
            store.remember_decline(
                data["namespace"], data["a"], data["b"], data["reason"],
                decided_at=datetime.fromisoformat(data["decided_at"]) if data.get("decided_at") else None,
            )
            counts["declines"] += 1
        elif kind == "merge":
            store.restore_merge(data)
            counts["merges"] += 1
        else:
            counts["skipped"] += 1
    return counts


def parse_ref(handle: str) -> EntityRef:
    """`type:key` -> EntityRef (the key may itself contain colons)."""
    if ":" not in handle:
        raise ValueError(f"expected type:key, got {handle!r}")
    etype, key = handle.split(":", 1)
    return EntityRef(type=etype, key=key)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.lifecycle", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--db", default=None,
        help="open exactly this database (file path = SQLite, postgresql:// = Postgres)"
             " instead of the engine's store; BYPASSES LOOM_SHARDS and LOOM_BLOB_*."
             " Default: the store LOOM_DB / LOOM_SHARDS / LOOM_BLOB_* describe.")
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

    p_unmerge = sub.add_parser("unmerge", help="reverse the merge that folded an entity away (D-019)")
    p_unmerge.add_argument("--namespace", required=True)
    p_unmerge.add_argument("--alias", required=True, help="the merged-away ref, as type:key")

    args = parser.parse_args(argv)
    store = store_from_url(args.db) if args.db else store_from_env()
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
        elif args.command == "unmerge":
            ok = store.unmerge(args.namespace, parse_ref(args.alias))
            print("unmerged" if ok else "no merge on record for that alias")
            if not ok:
                sys.exit(1)
    finally:
        store.close()


if __name__ == "__main__":
    main()
