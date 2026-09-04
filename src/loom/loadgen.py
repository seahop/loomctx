"""Ingest throughput measurement (D-001a: measure, don't assume).

Fires synthetic claim envelopes at a Loom ingest endpoint — the engine
directly (:8000) or the scale-shape balancer (:8081) — and reports envelopes
per second. Run it from inside the compose network:

    docker compose run --rm loom \
        python -m loom.loadgen --url http://loom:8000 --count 5000
"""

from __future__ import annotations

import argparse
import asyncio
import json
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


async def run(url: str, count: int, concurrency: int, namespace: str) -> None:
    import httpx

    bodies = payloads(count, namespace)
    sem = asyncio.Semaphore(concurrency)
    outcomes = {"ok": 0, "err": 0}

    async with httpx.AsyncClient(timeout=30) as client:

        async def send(body: str) -> None:
            async with sem:
                try:
                    resp = await client.post(
                        url + "/v1/ingest",
                        content=body,
                        headers={"content-type": "application/json"},
                    )
                    outcomes["ok" if resp.status_code in (200, 202) else "err"] += 1
                except httpx.HTTPError:
                    outcomes["err"] += 1

        started = time.perf_counter()
        await asyncio.gather(*(send(b) for b in bodies))
        elapsed = time.perf_counter() - started

    rate = count / elapsed if elapsed else 0.0
    print(
        f"{count} envelopes in {elapsed:.2f}s -> {rate:.0f}/s "
        f"(ok={outcomes['ok']} err={outcomes['err']}, "
        f"concurrency={concurrency}, target={url})"
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="loom.loadgen", description=__doc__)
    parser.add_argument("--url", default="http://loom:8000")
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--namespace", default="loadtest")
    args = parser.parse_args()
    asyncio.run(run(args.url, args.count, args.concurrency, args.namespace))


if __name__ == "__main__":
    main()
