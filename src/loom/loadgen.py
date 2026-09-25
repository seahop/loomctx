"""Throughput measurement (D-001a: measure, don't assume).

`--mode ingest` (default) fires synthetic claim envelopes at an ingest
endpoint — the engine directly (:8000) or the scale-shape balancer (:8081).
`--mode ask` fires concurrent context-pack requests at the engine for the
entities an earlier ingest run created, which is what a connection pool and
worker count change (D-028). Both report requests/s and p50/p99 latency.
Run it from inside the compose network:

    docker compose run --rm loom python -m loom.loadgen --url http://loom:8000 --count 5000
    docker compose run --rm loom python -m loom.loadgen --url http://loom:8000 --mode ask --count 600
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time


def payloads(count: int, namespace: str) -> list[str]:
    return [
        json.dumps(
            {
                "kind": "claim",
                "namespace": namespace,
                "subject": {"type": "host", "key": f"load-{i % 50:02d}"},
                "predicate": "load_event",
                "object": i,
                "observed_at": "2026-09-03T12:00:00Z",
                "source": "loadgen",
            }
        )
        for i in range(count)
    ]


def ask_payloads(count: int, namespace: str) -> list[str]:
    return [
        json.dumps({
            "namespace": namespace,
            "subject": {"type": "host", "key": f"load-{i % 50:02d}"},
            "question": "what happened on this host?",
            "budget": 800,
        })
        for i in range(count)
    ]


async def run(url: str, count: int, concurrency: int, namespace: str,
              mode: str = "ingest", key: str | None = None) -> None:
    import httpx

    path = "/v1/ingest" if mode == "ingest" else "/v1/ask"
    bodies = payloads(count, namespace) if mode == "ingest" else ask_payloads(count, namespace)
    sem = asyncio.Semaphore(concurrency)
    outcomes = {"ok": 0, "err": 0}
    statuses: dict[str, int] = {}     # non-2xx by code: a 401 storm reads as such
    latencies: list[float] = []
    headers = {"content-type": "application/json"}
    if key:
        headers["X-Loom-Key"] = key   # a secured deployment refuses keyless requests

    async with httpx.AsyncClient(timeout=60) as client:

        async def send(body: str) -> None:
            async with sem:
                t0 = time.perf_counter()
                try:
                    resp = await client.post(
                        url + path,
                        content=body,
                        headers=headers,
                    )
                    ok = resp.status_code in (200, 202)
                    outcomes["ok" if ok else "err"] += 1
                    if not ok:
                        statuses[str(resp.status_code)] = statuses.get(str(resp.status_code), 0) + 1
                except httpx.HTTPError:
                    outcomes["err"] += 1
                latencies.append(time.perf_counter() - t0)

        started = time.perf_counter()
        await asyncio.gather(*(send(b) for b in bodies))
        elapsed = time.perf_counter() - started

    rate = count / elapsed if elapsed else 0.0
    latencies.sort()
    p50 = latencies[len(latencies) // 2] * 1000 if latencies else 0
    p99 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.99))] * 1000 if latencies else 0
    print(
        f"{mode}: {count} requests in {elapsed:.2f}s -> {rate:.0f}/s "
        f"p50={p50:.0f}ms p99={p99:.0f}ms "
        f"(ok={outcomes['ok']} err={outcomes['err']}, "
        f"concurrency={concurrency}, target={url})"
        + (f" errors by status: {statuses}" if statuses else "")
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="loom.loadgen", description=__doc__)
    parser.add_argument("--url", default="http://loom:8000")
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--namespace", default="loadtest")
    parser.add_argument("--mode", choices=["ingest", "ask"], default="ingest")
    parser.add_argument("--key", default=os.environ.get("LOOM_API_KEY"),
                        help="API key sent as X-Loom-Key (default: LOOM_API_KEY)")
    args = parser.parse_args()
    asyncio.run(run(args.url, args.count, args.concurrency, args.namespace, args.mode, args.key))


if __name__ == "__main__":
    main()
