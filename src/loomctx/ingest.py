"""Bulk loader (D-034): feed LoomCtx from files or stdin, from any language.

Reads newline-delimited JSON envelopes (claims and documents, the same
shapes as POST /v1/ingest — see docs/contracts.md) and either posts them to
an engine or gateway in batches, or writes them straight into a store:

    python -m loomctx.ingest --url http://loomctx:8000 --key loomctxk_... claims.jsonl
    cat export.jsonl | python -m loomctx.ingest --url http://lb:8081 -
    python -m loomctx.ingest claims.jsonl                           # no HTTP: the LOOMCTX_DB store
    python -m loomctx.ingest --db /data/loomctx.db claims.jsonl        # no HTTP: an explicit store

Envelopes with an event_id are idempotent, so re-running a load is safe.
Anything a tool can export as JSON lines — a scanner, a CMDB, a spreadsheet
converter — is now a LoomCtx pipeline without an SDK.

Over HTTP a batch the server turns away for the moment — 429 (rate limit,
D-056), 502/503/504, 500, a dropped connection — is retried with backoff,
honoring Retry-After, up to LOOMCTX_INGEST_ATTEMPTS (default 6) tries per
batch, so a nightly job rides out a busy engine instead of dying on the
first refusal. Retrying is safe for envelopes with an event_id (a batch
that half-landed dedupes); one without an event_id may be recorded twice
if a 5xx or a timeout struck after the write.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from typing import Iterable, Iterator

POST_ATTEMPTS = max(1, int(os.environ.get("LOOMCTX_INGEST_ATTEMPTS", "") or 6))
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_BACKOFF = 60.0          # seconds between tries without a Retry-After
MAX_RETRY_AFTER = 300.0     # a Retry-After longer than this is capped, not obeyed


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


def _retry_after(exc: urllib.error.HTTPError) -> float | None:
    from .llm import _retry_after_seconds
    return _retry_after_seconds(exc.headers.get("Retry-After") if exc.headers else None)


def request_json(url: str, data: bytes | None, headers: dict[str, str], *, method: str = "POST",
                 timeout: float = 60.0, attempts: int | None = None, what: str = "request",
                 sleep=None) -> dict:
    """One JSON request with bounded retries on the answers that mean "not
    now" (RETRY_STATUS, connection errors): Retry-After when the server
    sends one (capped at MAX_RETRY_AFTER), else jittered exponential
    backoff. Anything else — and the last failure — is a SystemExit naming
    `what`, as the loader always did."""
    attempts = attempts or POST_ATTEMPTS
    sleep = sleep or time.sleep
    problem, delay = "", 0.0
    for attempt in range(attempts):
        if attempt:
            print(f"{what}: {problem}; retry {attempt + 1}/{attempts} in {delay:.0f}s", file=sys.stderr)
            sleep(delay)
        delay = min(MAX_BACKOFF, 2.0 ** attempt) * random.uniform(0.75, 1.25)
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read()[:300].decode(errors="replace")
            except Exception:  # noqa: BLE001 — a synthetic HTTPError may carry no body
                detail = ""
            problem = f"HTTP {exc.code}: {detail}"
            if exc.code not in RETRY_STATUS:
                raise SystemExit(f"{what}: {problem}")
            wait = _retry_after(exc)
            if wait is not None:
                delay = min(MAX_RETRY_AFTER, max(wait, 0.0))
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            problem = f"unreachable ({exc})"
    raise SystemExit(f"{what}: {problem} (after {attempts} attempts)")


def post_batch(url: str, batch: list[str], key: str | None, timeout: float = 60.0,
               what: str = "batch") -> dict:
    """POST one NDJSON batch to /v1/ingest/batch (retried as request_json
    says); the IngestBatchResponse as a dict."""
    headers = {"content-type": "application/x-ndjson"}
    if key:
        headers["X-LoomCtx-Key"] = key
    return request_json(url.rstrip("/") + "/v1/ingest/batch", ("\n".join(batch) + "\n").encode(),
                        headers, timeout=timeout, what=what)


def post_batches(url: str, lines: Iterable[str], size: int, key: str | None,
                 timeout: float = 60.0) -> dict[str, int]:
    totals = {"total": 0, "recorded": 0, "accepted": 0, "rejected": 0}
    for n, batch in enumerate(_batches(lines, size), 1):
        body = post_batch(url, batch, key, timeout, what=f"batch {n}")
        for k in totals:
            totals[k] += int(body.get(k, 0))
        for r in body.get("results", []):
            if r.get("status") == "rejected":
                print(f"batch {n} item {r['index']}: rejected: {r.get('detail')}", file=sys.stderr)
    return totals


def load_direct(db: str | None, lines: Iterable[str], size: int,
                bulk: bool = True) -> dict[str, int]:
    """Write straight into a store (no engine running) — the same code path
    the queue consumer uses, so semantics are identical. An explicit `db`
    opens that store alone; None opens what LOOMCTX_DB / LOOMCTX_SHARDS /
    LOOMCTX_BLOB_* configure, so sharding and blob offload apply as they do
    for the engine.

    `bulk` (D-105) runs the load in the store's bulk mode: every batch is
    still handled alone and in order, with its own all-or-nothing, but it
    is committed with its neighbours every few seconds. A caller whose
    `lines` reads this same store through another connection while it is
    consumed (to see what earlier batches stored) passes False and keeps a
    commit per batch."""
    from .consumer import handle_batch
    from .registry import RegistryCache
    from .store.factory import store_from_env, store_from_url

    store = store_from_url(db) if db else store_from_env()
    totals = {"recorded": 0, "accepted": 0, "skipped": 0, "rejected": 0}
    try:
        # one registry cache for the run: it was one per batch, a schema
        # read every 500 lines
        registry = RegistryCache(store)
        with store.bulk_load() if bulk else contextlib.nullcontext():
            for batch in _batches(lines, size):
                counts = handle_batch(store, [b.encode() for b in batch], registry)
                for k in totals:
                    totals[k] += counts.get(k, 0)
        store.refresh_statistics()
    finally:
        store.close()
    return totals


def fail_on_refusals(totals: dict, noun: str = "envelopes", remote: bool = True) -> None:
    """Call after printing a load's totals: any refused envelope makes the
    loader exit non-zero. A scheduled load must fail visibly, not "succeed"
    with a hole in it — 193k of 474k refused on GKE by a mis-scoped key went
    unnoticed until the log was read (D-063, S-36)."""
    rejected = int(totals.get("rejected", 0) or 0)
    if rejected:
        by = "the engine" if remote else "the store"
        raise SystemExit(f"{rejected} {noun} were refused by {by} (see the lines above)")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.ingest", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", help="NDJSON files, or - for stdin")
    parser.add_argument("--url", help="engine or gateway base URL (POST /v1/ingest/batch); without it "
                                      "envelopes are written straight into the store LOOMCTX_DB / "
                                      "LOOMCTX_SHARDS / LOOMCTX_BLOB_* configure")
    parser.add_argument("--db", help="write directly to this explicit store URL/path; bypasses "
                                     "LOOMCTX_SHARDS and LOOMCTX_BLOB_*")
    parser.add_argument("--key", default=os.environ.get("LOOMCTX_API_KEY"), type=str.strip, help="API key (or $LOOMCTX_API_KEY)")
    parser.add_argument("--batch", type=int, default=500)
    args = parser.parse_args(argv)
    if args.url and args.db:
        parser.error("give --url or --db, not both")
    lines = _lines(args.paths)
    totals = (post_batches(args.url, lines, args.batch, args.key) if args.url
              else load_direct(args.db, lines, args.batch))
    print(json.dumps(totals))
    fail_on_refusals(totals, remote=bool(args.url))


if __name__ == "__main__":
    main()
