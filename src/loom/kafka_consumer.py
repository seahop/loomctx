"""Kafka / Redpanda writer consumer (D-034): read Loom envelopes from topics
your pipelines already publish to, and write them through the GraphStore —
the same batch semantics as the NATS consumer.

    LOOM_KAFKA_BROKERS=broker:9092 LOOM_KAFKA_TOPICS=loom.ingest \\
        python -m loom.kafka_consumer

Each record's value is one envelope (JSON), or several as NDJSON. Offsets
are committed only after the batch is durably written (at-least-once;
event_id dedupe makes redelivery harmless). A batch the store rejects is
retried with backoff; after LOOM_MAX_DELIVER tries it is published to
LOOM_KAFKA_DEADLETTER (default loom.deadletter) with the error class and a
short code as headers (the message text goes to the log, never the topic)
and committed, so one poison record cannot stall the partition. Records
that don't parse are dropped with a log line, as in the NATS consumer;
claims the namespace's schema registry rejects are dropped the same way.

Broker security: LOOM_KAFKA_SECURITY_PROTOCOL (PLAINTEXT | SSL |
SASL_PLAINTEXT | SASL_SSL), LOOM_KAFKA_SASL_MECHANISM (PLAIN, SCRAM-SHA-256,
SCRAM-SHA-512), LOOM_KAFKA_SASL_USERNAME / _PASSWORD, and
LOOM_KAFKA_SSL_CAFILE for a private CA. These authenticate *Loom to the
broker*; there is no per-message principal on this path. Anyone who can
produce to the topic writes into any namespace — treat topic ACLs as the
write permission.

Requires the `kafka` extra (aiokafka). Optional: nothing in the default
shape depends on it. Consuming from *your* Kafka is not the same as
requiring one (hard constraint 2 still holds).
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl

from .consumer import error_headers, handle_batch
from .registry import RegistryCache
from .store.base import GraphStore
from .store.factory import store_from_env

log = logging.getLogger("loom.kafka")

BROKERS = os.environ.get("LOOM_KAFKA_BROKERS", "localhost:9092")
TOPICS = [t.strip() for t in os.environ.get("LOOM_KAFKA_TOPICS", "loom.ingest").split(",") if t.strip()]
GROUP = os.environ.get("LOOM_KAFKA_GROUP", "loom-writer")
DEADLETTER = os.environ.get("LOOM_KAFKA_DEADLETTER", "loom.deadletter")
BATCH = int(os.environ.get("LOOM_KAFKA_BATCH", "") or 200)
MAX_DELIVER = int(os.environ.get("LOOM_MAX_DELIVER", "") or 5)
CONNECT_TIMEOUT_SECONDS = float(os.environ.get("LOOM_KAFKA_CONNECT_TIMEOUT", "") or 120)


def security_kwargs(env: dict[str, str] | None = None) -> dict:
    """aiokafka connection options from LOOM_KAFKA_SECURITY_PROTOCOL and the
    SASL / TLS variables; empty for the plaintext default so a local
    Redpanda keeps working untouched."""
    env = os.environ if env is None else env
    protocol = (env.get("LOOM_KAFKA_SECURITY_PROTOCOL") or "PLAINTEXT").upper()
    kwargs: dict = {}
    if protocol != "PLAINTEXT":
        kwargs["security_protocol"] = protocol
    if protocol.endswith("SSL"):
        cafile = env.get("LOOM_KAFKA_SSL_CAFILE") or None
        kwargs["ssl_context"] = ssl.create_default_context(cafile=cafile)
    if protocol.startswith("SASL"):
        mechanism = (env.get("LOOM_KAFKA_SASL_MECHANISM") or "PLAIN").upper()
        kwargs["sasl_mechanism"] = mechanism
        kwargs["sasl_plain_username"] = env.get("LOOM_KAFKA_SASL_USERNAME") or None
        kwargs["sasl_plain_password"] = env.get("LOOM_KAFKA_SASL_PASSWORD") or None
        if not (kwargs["sasl_plain_username"] and kwargs["sasl_plain_password"]):
            raise SystemExit(f"LOOM_KAFKA_SECURITY_PROTOCOL={protocol} needs "
                             "LOOM_KAFKA_SASL_USERNAME and LOOM_KAFKA_SASL_PASSWORD")
    return kwargs


def split_values(values: list[bytes]) -> list[bytes]:
    """A record may carry one envelope or NDJSON of several."""
    out: list[bytes] = []
    for v in values:
        for line in v.splitlines():
            if line.strip():
                out.append(line)
    return out


async def write_with_retry(store: GraphStore, producer, payloads: list[bytes],
                           sleep=asyncio.sleep, registry: RegistryCache | None = None) -> dict[str, int]:
    """Write one batch; on store failure retry with backoff up to
    MAX_DELIVER, then dead-letter the whole batch (with the error class) so
    the partition moves on. Returns the counts, adding 'deadlettered'."""
    empty = {"recorded": 0, "accepted": 0, "skipped": 0, "rejected": 0, "deadlettered": 0}
    for attempt in range(1, MAX_DELIVER + 1):
        try:
            counts = handle_batch(store, payloads, registry)
            counts["deadlettered"] = 0
            return counts
        except Exception as exc:  # noqa: BLE001 — the store rolled back (D-022)
            if attempt >= MAX_DELIVER:
                headers = [(k, v.encode()) for k, v in error_headers(exc).items()]
                for p in payloads:
                    await producer.send_and_wait(DEADLETTER, p, headers=headers)
                log.error("batch of %d dead-lettered after %d attempts: %s: %s",
                          len(payloads), attempt, type(exc).__name__, exc)
                return {**empty, "deadlettered": len(payloads)}
            delay = min(30.0, 2.0 ** attempt)
            log.warning("batch failed (attempt %d/%d), retrying in %.0fs: %s", attempt, MAX_DELIVER, delay, exc)
            await sleep(delay)
    return empty  # unreachable


async def run() -> None:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

    store = store_from_env()
    registry = RegistryCache(store)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + CONNECT_TIMEOUT_SECONDS
    security = security_kwargs()
    consumer = AIOKafkaConsumer(*TOPICS, bootstrap_servers=BROKERS, group_id=GROUP,
                                enable_auto_commit=False, auto_offset_reset="earliest",
                                max_poll_records=BATCH, **security)
    producer = AIOKafkaProducer(bootstrap_servers=BROKERS, **security)
    while True:  # brokers may still be booting (H-F3 courtesy)
        try:
            await consumer.start()
            await producer.start()
            break
        except Exception as exc:  # noqa: BLE001
            if loop.time() >= deadline:
                raise
            log.warning("kafka at %s not ready (%s); retrying", BROKERS, exc)
            await asyncio.sleep(2)
    log.info("consuming %s from %s as group %s (%s)", TOPICS, BROKERS, GROUP,
             security.get("security_protocol", "PLAINTEXT"))
    totals = {"recorded": 0, "accepted": 0, "skipped": 0, "rejected": 0, "deadlettered": 0}
    try:
        while True:
            batches = await consumer.getmany(timeout_ms=2000, max_records=BATCH)
            records = [r for msgs in batches.values() for r in msgs]
            if not records:
                continue
            payloads = split_values([r.value for r in records])
            counts = await write_with_retry(store, producer, payloads, registry=registry)
            await consumer.commit()  # only after the batch is durably written
            for k, v in counts.items():
                totals[k] += v
            log.info("progress: %s", totals)
    finally:
        await consumer.stop()
        await producer.stop()
        store.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    asyncio.run(run())


if __name__ == "__main__":
    main()
