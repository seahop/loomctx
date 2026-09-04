"""The scale-shape writer consumer (docs/decisions.md D-010).

Pulls validated ingestion envelopes off NATS JetStream (published there by the
Go gateways) and writes them through the GraphStore — the single serialization
point that reconciles N ingestion nodes with the store's write path.

Runs as `python -m loom.consumer` (a sidecar or sibling container of the
engine). Requires the `scale` extra (nats-py).
"""

from __future__ import annotations

import asyncio
import logging
import os

from pydantic import TypeAdapter, ValidationError

from .contracts import ClaimIn, IngestEnvelope
from .store.base import GraphStore
from .store.factory import store_from_env

log = logging.getLogger("loom.consumer")

_ENVELOPE = TypeAdapter(IngestEnvelope)

STREAM = "LOOM_INGEST"
SUBJECTS = "loom.ingest.>"
DURABLE = "loom-writer"
BATCH = 64


def handle_batch(store: GraphStore, payloads: list[bytes]) -> dict[str, int]:
    """Write one fetched batch: claims land in a single transaction.

    Gateways validated against the same contract, so a parse failure here
    means a poison message (or contract drift) — log and drop rather than
    poison-loop the stream.
    """
    counts = {"recorded": 0, "accepted": 0, "skipped": 0}
    claims: list[ClaimIn] = []
    for data in payloads:
        try:
            envelope = _ENVELOPE.validate_json(data)
        except ValidationError as exc:
            log.warning("dropping unparseable message: %s", exc.errors()[:2])
            counts["skipped"] += 1
            continue
        if isinstance(envelope, ClaimIn):
            claims.append(envelope)
        else:
            store.store_artifact(envelope)
            counts["accepted"] += 1
    if claims:
        store.record_claims(claims)
        counts["recorded"] = len(claims)
    return counts


def handle_message(store: GraphStore, data: bytes) -> str:
    """Single-envelope convenience over handle_batch."""
    counts = handle_batch(store, [data])
    return next(k for k, v in counts.items() if v)


async def run() -> None:
    import nats
    from nats.errors import TimeoutError as NatsTimeoutError

    store = store_from_env()
    nc = await nats.connect(os.environ.get("LOOM_NATS_URL", "nats://nats:4222"))
    js = nc.jetstream()
    try:
        await js.add_stream(name=STREAM, subjects=[SUBJECTS])
    except Exception:  # stream already exists (gateway may have created it)
        pass
    sub = await js.pull_subscribe(SUBJECTS, durable=DURABLE)
    log.info("consuming %s from %s", SUBJECTS, nc.connected_url.netloc)

    totals = {"recorded": 0, "accepted": 0, "skipped": 0}
    while True:
        try:
            msgs = await sub.fetch(BATCH, timeout=5)
        except (TimeoutError, NatsTimeoutError):
            continue
        batch_counts = handle_batch(store, [m.data for m in msgs])
        for msg in msgs:  # ack only after the batch is durably written
            await msg.ack()
        for key, val in batch_counts.items():
            totals[key] += val
        log.info("progress: %s", totals)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(name)s %(message)s"
    )
    asyncio.run(run())


if __name__ == "__main__":
    main()
