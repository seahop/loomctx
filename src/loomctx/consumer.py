"""The scale-shape writer consumer (docs/decisions.md D-010).

Pulls validated ingestion envelopes off NATS JetStream (published there by the
Go gateways) and writes them through the GraphStore — the single serialization
point that reconciles N ingestion nodes with the store's write path.

Runs as `python -m loomctx.consumer` (a sidecar or sibling container of the
engine). Requires the `scale` extra (nats-py).
"""

from __future__ import annotations

import asyncio
import logging
import os

from pydantic import TypeAdapter, ValidationError

from .auth import AuthConfig
from .contracts import ClaimIn, IngestEnvelope
from .gates import check_citation, check_supersedes
from .mentions import link_quietly
from .registry import RegistryCache, validate_claim
from .store.base import GraphStore
from .store.factory import store_from_env

log = logging.getLogger("loomctx.consumer")

_ENVELOPE = TypeAdapter(IngestEnvelope)

STREAM = "LOOMCTX_INGEST"
SUBJECTS = "loomctx.ingest.>"
DURABLE = "loomctx-writer"
BATCH = 64
CONNECT_TIMEOUT_SECONDS = 120.0
# Redelivery (D-029): a batch the store rejects is nak'd and comes back
# after ACK_WAIT; after MAX_DELIVER tries a message is parked on the
# dead-letter stream with the reason, and acked, so one bad envelope can't
# hold the queue hostage. Both are env-tunable.
ACK_WAIT_SECONDS = float(os.environ.get("LOOMCTX_ACK_WAIT", "") or 30)
MAX_DELIVER = int(os.environ.get("LOOMCTX_MAX_DELIVER", "") or 5)
DEADLETTER_STREAM = "LOOMCTX_DEADLETTER"
DEADLETTER_SUBJECTS = "loomctx.deadletter.>"
# The dead-letter stream is bounded too: a poison storm must not fill the
# queue's disk. Oldest parked messages are shed first (default 256 MiB).
DEADLETTER_MAX_BYTES = int(os.environ.get("LOOMCTX_DEADLETTER_MAX_BYTES", "") or 256 * 1024 * 1024)
STREAM_REPLICAS = int(os.environ.get("LOOMCTX_STREAM_REPLICAS", "") or 1)

# Dead-letter headers carry only the exception class and a short code — the
# message text can quote row data (a constraint error names the values), and
# headers are readable by anyone who can read the stream. The text goes to
# the consumer's log, where it belongs.
ERROR_HEADER = "LoomCtx-Error"
ERROR_CODE_HEADER = "LoomCtx-Error-Code"
ERROR_CODE_STORE = "store_rejected"
ERROR_CODE_PROVENANCE = "provenance_unresolved"
# The gateway stamps the authenticated grant id (never the key) on every
# message (H-A10). With LOOMCTX_AUTH_FILE / LOOMCTX_API_KEYS mounted on the
# consumer too, that grant's write gates (D-059: citation, supersession)
# are applied here as well — the queue path gets the checks the HTTP path
# has. Without keys configured the consumer trusts the gateway, as before.
PRINCIPAL_HEADER = "LoomCtx-Principal"
# A claim citing a document the store does not have yet (the document is in
# another replica's in-flight batch, or later in the stream) is nak'd with
# this delay times its delivery count, and dead-lettered on its last allowed
# delivery — never silently dropped and acked.
PROVENANCE_RETRY_SECONDS = float(os.environ.get("LOOMCTX_PROVENANCE_RETRY", "") or 5)


def error_headers(exc: BaseException, code: str = ERROR_CODE_STORE) -> dict[str, str]:
    """What a dead-lettered message says about why: class + code, no text."""
    return {ERROR_HEADER: type(exc).__name__, ERROR_CODE_HEADER: code}


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


def _write_gate(store: GraphStore, claim: ClaimIn, principal: str | None,
                auth: AuthConfig | None) -> str | None:
    """The D-059 write gates for a queued claim, as the HTTP path applies
    them. With keys configured a message must carry a live principal: a
    revoked or unknown grant id writes nothing."""
    grant = None
    if auth is not None and auth.enabled:
        grant = auth.grant_by_id(principal)
        if grant is None:
            return f"principal {principal!r} is not a live grant"
    return check_supersedes(store, claim, grant) or check_citation(store, claim, grant)


def handle_batch(store: GraphStore, payloads: list[bytes],
                 registry: RegistryCache | None = None,
                 retry: list[int] | None = None,
                 principals: list[str | None] | None = None,
                 auth: AuthConfig | None = None) -> dict[str, int]:
    """Write one fetched batch: claims land in a single transaction.

    Gateways validated against the same contract, so a parse failure here
    means a poison message (or contract drift) — log and drop rather than
    poison-loop the stream. The namespace's schema registry (D-024) is
    applied here too: the gateway knows the contract shape but not the
    registry, so a claim that violates a registered predicate or a strict
    namespace is dropped with its reason and counted under `rejected`.

    Documents are stored before any claim's provenance is resolved, so a
    claim may cite a document later in the same batch. A claim whose
    document is still unknown is dropped (counted `skipped`) — unless the
    caller passes `retry`: then its payload index is appended there and
    nothing is counted, for the caller to redeliver (the queue consumer:
    with two replicas the document may be in the other one's batch).

    `principals` (aligned with `payloads`) and `auth` apply the sending
    grant's write gates (`_write_gate`); a claim failing them is rejected.
    """
    registry = registry or RegistryCache(store)
    counts = {"recorded": 0, "accepted": 0, "skipped": 0, "rejected": 0}
    parsed: list[tuple[int, ClaimIn]] = []
    stored: list = []   # documents, linked once the batch's claims are in (D-118)
    for index, data in enumerate(payloads):
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
            parsed.append((index, envelope))
        else:
            stored.append((store.store_artifact(envelope), envelope.text))
            counts["accepted"] += 1
    claims: list[ClaimIn] = []
    for index, envelope in parsed:
        problem = validate_claim(registry.get(envelope.namespace), envelope)
        if problem is not None:
            log.warning("rejecting claim %s: %s", envelope.event_id, problem)
            counts["rejected"] += 1
            continue
        principal = principals[index] if principals is not None else None
        problem = _write_gate(store, envelope, principal, auth)
        if problem is not None:
            if problem.endswith("ingest the document first") and retry is not None:
                retry.append(index)     # the cited document may still be in flight
                continue
            log.warning("rejecting claim %s: %s", envelope.event_id, problem)
            counts["rejected"] += 1
            continue
        problem = resolve_provenance(store, envelope)
        if problem is not None:
            if retry is not None:
                retry.append(index)
                continue
            log.warning("dropping claim %s: %s", envelope.event_id, problem)
            counts["skipped"] += 1
            continue
        claims.append(envelope)
    if claims:
        store.record_claims(claims)
        counts["recorded"] = len(claims)
    for artifact, text in stored:
        link_quietly(store, artifact, text)   # after the claims: a batch names what it brings (D-118)
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
    headers = error_headers(exc)
    parked = 0
    for m in msgs:
        if _delivered(m) >= limit:
            await js.publish(m.subject.replace("loomctx.ingest.", "loomctx.deadletter.", 1),
                             m.data, headers={**(m.headers or {}), **headers})
            await m.ack()
            parked += 1
        else:
            await m.nak(delay=2)
    if parked:
        log.error("%d message(s) dead-lettered after %d deliveries: %s: %s",
                  parked, limit, type(exc).__name__, exc)
    return parked


def _delivered(msg) -> int:
    return getattr(getattr(msg, "metadata", None), "num_delivered", 1) or 1


async def defer_unresolved(js, msgs, max_deliver: int | None = None) -> int:
    """Claims whose cited document is not in the store yet: nak with a
    growing delay so the document (in another replica's batch, or later in
    the stream) can land first; on the last allowed delivery, park on the
    dead-letter stream (code `provenance_unresolved`) and ack. Returns how
    many were parked."""
    limit = max_deliver or MAX_DELIVER
    parked = 0
    for m in msgs:
        delivered = _delivered(m)
        if delivered >= limit:
            headers = {ERROR_HEADER: "ProvenanceUnresolved", ERROR_CODE_HEADER: ERROR_CODE_PROVENANCE}
            await js.publish(m.subject.replace("loomctx.ingest.", "loomctx.deadletter.", 1),
                             m.data, headers={**(m.headers or {}), **headers})
            await m.ack()
            parked += 1
        else:
            await m.nak(delay=PROVENANCE_RETRY_SECONDS * delivered)
    if parked:
        log.error("%d claim(s) dead-lettered: cited document still unknown after %d deliveries",
                  parked, limit)
    return parked


def _principal(msg) -> str | None:
    return (getattr(msg, "headers", None) or {}).get(PRINCIPAL_HEADER)


async def write_batch(js, store: GraphStore, msgs, registry: RegistryCache | None = None,
                      max_deliver: int | None = None,
                      auth: AuthConfig | None = None) -> dict[str, int]:
    """Write one fetched batch and settle every message. The fast path is
    one transaction for the batch. When the store rejects it (it rolled
    back, D-022), each message is written alone: the good ones land and
    are acked, and only a message that fails by itself is nak'd — or
    dead-lettered on its last delivery. Batch-mates used to share the bad
    one's fate and its delivery count, so one poison envelope parked up to
    BATCH-1 good ones after MAX_DELIVER. Claims citing a document not yet
    stored are redelivered (defer_unresolved). Returns the counts plus
    `deadlettered`."""
    counts = {"recorded": 0, "accepted": 0, "skipped": 0, "rejected": 0, "deadlettered": 0}
    retry: list[int] = []
    try:
        batch_counts = handle_batch(store, [m.data for m in msgs], registry, retry,
                                    [_principal(m) for m in msgs], auth)
    except Exception as exc:  # noqa: BLE001 — the store rolled back (D-022)
        if len(msgs) == 1:
            counts["deadlettered"] += await settle_failed_batch(js, msgs, exc, max_deliver)
            log.warning("message failed (%s: %s); redelivered or dead-lettered",
                        type(exc).__name__, exc)
            return counts
        log.warning("batch of %d failed (%s: %s); writing its messages one at a time",
                    len(msgs), type(exc).__name__, exc)
        unresolved = []
        for m in msgs:
            mine: list[int] = []
            try:
                one = handle_batch(store, [m.data], registry, mine, [_principal(m)], auth)
            except Exception as one_exc:  # noqa: BLE001 — this message, on its own
                counts["deadlettered"] += await settle_failed_batch(js, [m], one_exc, max_deliver)
                continue
            if mine:
                unresolved.append(m)
                continue
            await m.ack()
            for key, val in one.items():
                counts[key] += val
        counts["deadlettered"] += await defer_unresolved(js, unresolved, max_deliver)
        return counts
    waiting = set(retry)
    for i, msg in enumerate(msgs):  # ack only after the batch is durably written
        if i not in waiting:
            await msg.ack()
    counts["deadlettered"] += await defer_unresolved(js, [msgs[i] for i in retry], max_deliver)
    for key, val in batch_counts.items():
        counts[key] += val
    return counts


async def run() -> None:
    import nats
    from nats.errors import TimeoutError as NatsTimeoutError

    store = store_from_env()
    registry = RegistryCache(store)
    auth = AuthConfig.from_env()
    if not auth.enabled:
        log.warning("no LOOMCTX_AUTH_FILE / LOOMCTX_API_KEYS on the consumer: queued claims are written "
                    "without the sending key's citation/supersession gates (D-059)")
    url = os.environ.get("LOOMCTX_NATS_URL", "nats://nats:4222")
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

    for cfg in (StreamConfig(name=STREAM, subjects=[SUBJECTS], num_replicas=STREAM_REPLICAS),
                StreamConfig(name=DEADLETTER_STREAM, subjects=[DEADLETTER_SUBJECTS],
                             num_replicas=STREAM_REPLICAS, max_bytes=DEADLETTER_MAX_BYTES)):
        try:
            await js.add_stream(cfg)
        except Exception:  # noqa: BLE001 — exists already (gateway creates the ingest one)
            pass
    sub = await js.pull_subscribe(
        SUBJECTS, durable=DURABLE,
        config=ConsumerConfig(durable_name=DURABLE, ack_wait=ACK_WAIT_SECONDS,
                              max_deliver=MAX_DELIVER))
    log.info("consuming %s from %s (ack_wait=%ss max_deliver=%d deadletter_max_bytes=%d)",
             SUBJECTS, nc.connected_url.netloc, ACK_WAIT_SECONDS, MAX_DELIVER, DEADLETTER_MAX_BYTES)

    totals = {"recorded": 0, "accepted": 0, "skipped": 0, "rejected": 0, "deadlettered": 0}
    while True:
        try:
            msgs = await sub.fetch(BATCH, timeout=5)
        except (TimeoutError, NatsTimeoutError):
            continue
        # audit trail (H-A10): which principals this batch came from — the
        # gateway stamps the grant id, never the key, on each message
        principals: dict[str, int] = {}
        for m in msgs:
            who = _principal(m) or "-"
            principals[who] = principals.get(who, 0) + 1
        batch_counts = await write_batch(js, store, msgs, registry, auth=auth)
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
