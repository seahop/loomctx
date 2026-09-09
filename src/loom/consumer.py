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
CONNECT_TIMEOUT_SECONDS = 120.0
# Redelivery (D-029): a batch the store rejects is nak'd and comes back
# after ACK_WAIT; after MAX_DELIVER tries a message is parked on the
# dead-letter stream with the reason, and acked, so one bad envelope can't
# hold the queue hostage. Both are env-tunable.
ACK_WAIT_SECONDS = float(os.environ.get("LOOM_ACK_WAIT", "") or 30)
MAX_DELIVER = int(os.environ.get("LOOM_MAX_DELIVER", "") or 5)
DEADLETTER_STREAM = "LOOM_DEADLETTER"
DEADLETTER_SUBJECTS = "loom.deadletter.>"
STREAM_REPLICAS = int(os.environ.get("LOOM_STREAM_REPLICAS", "") or 1)


def resolve_provenance(store: GraphStore, claim: ClaimIn) -> str | None:
    """Turn provenance.artifact_event_id into artifact_id before the claim
    is written (D-039). Returns the problem, or None when resolved or not
    applicable. Mutates the claim's provenance in place on success."""
    prov = claim.provenance
    if prov is None or prov.artifact_id:
        return None
    found = store.artifact_by_event(claim.namespace, prov.artifact_event_id)
    if found is None:
        return (f"provenance.artifact_event_id {prov.artifact_event_id!r} does not name a document "
                f"in namespace {claim.namespace!r}; ingest the document first")
    claim.provenance = prov.model_copy(update={"artifact_id": found.id})
    return None


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
            # include_input=False: the failing payload may carry document
            # text or claim values that don't belong in logs (H-A7)
            log.warning("dropping unparseable message: %s",
                        exc.errors(include_input=False)[:2])
            counts["skipped"] += 1
            continue
        if isinstance(envelope, ClaimIn):
            problem = resolve_provenance(store, envelope)
            if problem is not None:
                log.warning("dropping claim %s: %s", envelope.event_id, problem)
                counts["skipped"] += 1
                continue
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


async def settle_failed_batch(js, msgs, exc: Exception,
                              max_deliver: int | None = None) -> int:
    """The store rejected a whole batch (it rolled back, D-022). nak every
    message for prompt redelivery — event_id dedupe absorbs partial writes —
    except those on their last allowed delivery, which are parked on the
    dead-letter stream with the reason and acked, so one poison envelope
    can't hold the queue hostage (D-029). Returns how many were parked."""
    limit = max_deliver or MAX_DELIVER
    reason = f"{type(exc).__name__}: {exc}"[:500]
    parked = 0
    for m in msgs:
        delivered = getattr(getattr(m, "metadata", None), "num_delivered", 1) or 1
        if delivered >= limit:
            await js.publish(m.subject.replace("loom.ingest.", "loom.deadletter.", 1),
                             m.data, headers={**(m.headers or {}), "Loom-Error": reason})
            await m.ack()
            parked += 1
        else:
            await m.nak(delay=2)
    return parked


async def run() -> None:
    import nats
    from nats.errors import TimeoutError as NatsTimeoutError

    store = store_from_env()
    url = os.environ.get("LOOM_NATS_URL", "nats://nats:4222")
    # The queue may still be booting when we start (compose/k8s ordering
    # is best-effort): keep trying instead of dying on the first refusal
    # (H-F3). nats-py then reconnects on its own for the life of the process.
    deadline = asyncio.get_running_loop().time() + CONNECT_TIMEOUT_SECONDS
    while True:
        try:
            nc = await nats.connect(url, max_reconnect_attempts=-1)
            break
        except Exception as exc:  # noqa: BLE001 — connection-phase errors vary by cause
            if asyncio.get_running_loop().time() >= deadline:
                raise
            log.warning("NATS at %s not ready (%s); retrying", url, exc)
            await asyncio.sleep(2)
    js = nc.jetstream()
    from nats.js.api import ConsumerConfig, StreamConfig

    for name, subjects in ((STREAM, [SUBJECTS]), (DEADLETTER_STREAM, [DEADLETTER_SUBJECTS])):
        try:
            await js.add_stream(StreamConfig(name=name, subjects=subjects,
                                             num_replicas=STREAM_REPLICAS))
        except Exception:  # noqa: BLE001 — exists already (gateway creates the ingest one)
            pass
    sub = await js.pull_subscribe(
        SUBJECTS, durable=DURABLE,
        config=ConsumerConfig(durable_name=DURABLE, ack_wait=ACK_WAIT_SECONDS,
                              max_deliver=MAX_DELIVER))
    log.info("consuming %s from %s (ack_wait=%ss max_deliver=%d)",
             SUBJECTS, nc.connected_url.netloc, ACK_WAIT_SECONDS, MAX_DELIVER)

    totals = {"recorded": 0, "accepted": 0, "skipped": 0, "deadlettered": 0}
    while True:
        try:
            msgs = await sub.fetch(BATCH, timeout=5)
        except (TimeoutError, NatsTimeoutError):
            continue
        # audit trail (H-A10): which principals this batch came from — the
        # gateway stamps the grant id, never the key, on each message
        principals: dict[str, int] = {}
        for m in msgs:
            who = (m.headers or {}).get("Loom-Principal", "-")
            principals[who] = principals.get(who, 0) + 1
        try:
            batch_counts = handle_batch(store, [m.data for m in msgs])
        except Exception as exc:  # noqa: BLE001 — the store rolled back (D-022)
            parked = await settle_failed_batch(js, msgs, exc)
            totals["deadlettered"] += parked
            log.exception("batch of %d failed (%d dead-lettered); rest redelivered",
                          len(msgs), parked)
            continue
        for msg in msgs:  # ack only after the batch is durably written
            await msg.ack()
        for key, val in batch_counts.items():
            totals[key] += val
        log.info("progress: %s (principals: %s)", totals, principals)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(name)s %(message)s"
    )
    asyncio.run(run())


if __name__ == "__main__":
    main()
