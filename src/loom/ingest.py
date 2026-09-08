"""Bulk loader (D-034): feed Loom from files or stdin, from any language.

Reads newline-delimited JSON envelopes (claims and documents, the same
shapes as POST /v1/ingest — see docs/contracts.md) and either posts them to
an engine or gateway in batches, or writes them straight into a store:

    python -m loom.ingest --url http://loom:8000 --key loomk_... claims.jsonl
    cat export.jsonl | python -m loom.ingest --url http://lb:8081 -
    python -m loom.ingest --db /data/loom.db claims.jsonl        # no HTTP at all

Envelopes with an event_id are idempotent, so re-running a load is safe.
Anything a tool can export as JSON lines — a scanner, a CMDB, a spreadsheet
converter — is now a Loom pipeline without an SDK.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Iterable, Iterator


def _lines(paths: list[str]) -> Iterator[str]:
    for path in paths:
        fh = sys.stdin if path == "-" else open(path, encoding="utf-8")
        with fh:
            for line in fh:
                if line.strip():
                    yield line


def _batches(lines: Iterable[str], size: int) -> Iterator[list[str]]:
    batch: list[str] = []
    for line in lines:
        batch.append(line.rstrip("\n"))
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def post_batches(url: str, lines: Iterable[str], size: int, key: str | None,
                 timeout: float = 60.0) -> dict[str, int]:
    totals = {"total": 0, "recorded": 0, "accepted": 0, "rejected": 0}
    headers = {"content-type": "application/x-ndjson"}
    if key:
        headers["X-Loom-Key"] = key
    for n, batch in enumerate(_batches(lines, size), 1):
        req = urllib.request.Request(url.rstrip("/") + "/v1/ingest/batch",
                                     data=("\n".join(batch) + "\n").encode(),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:300].decode(errors="replace")
            raise SystemExit(f"batch {n}: HTTP {exc.code}: {detail}")
        for k in totals:
            totals[k] += int(body.get(k, 0))
        for r in body.get("results", []):
            if r.get("status") == "rejected":
                print(f"batch {n} item {r['index']}: rejected: {r.get('detail')}", file=sys.stderr)
    return totals


def load_direct(db: str, lines: Iterable[str], size: int) -> dict[str, int]:
    """Write straight into a store (no engine running) — the same code path
    the queue consumer uses, so semantics are identical."""
    from .consumer import handle_batch
    from .store.factory import store_from_url

    store = store_from_url(db)
    totals = {"recorded": 0, "accepted": 0, "skipped": 0}
    try:
        for batch in _batches(lines, size):
            counts = handle_batch(store, [b.encode() for b in batch])
            for k in totals:
                totals[k] += counts.get(k, 0)
    finally:
        store.close()
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(prog="loom.ingest", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", help="NDJSON files, or - for stdin")
    parser.add_argument("--url", help="engine or gateway base URL (POST /v1/ingest/batch)")
    parser.add_argument("--db", help="write directly to this store instead of over HTTP")
    parser.add_argument("--key", default=os.environ.get("LOOM_API_KEY"), help="API key (or $LOOM_API_KEY)")
    parser.add_argument("--batch", type=int, default=500)
    args = parser.parse_args()
    if bool(args.url) == bool(args.db):
        parser.error("give exactly one of --url or --db")
    lines = _lines(args.paths)
    totals = load_direct(args.db, lines, args.batch) if args.db else post_batches(args.url, lines, args.batch, args.key)
    print(json.dumps(totals))


if __name__ == "__main__":
    main()
