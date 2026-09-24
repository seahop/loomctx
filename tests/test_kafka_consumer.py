"""Kafka consumer (D-034) — the parts that don't need a broker."""

import asyncio
import json

import pytest

from loom.contracts import EntityRef
from loom.kafka_consumer import split_values, write_with_retry
from loom.store.sqlite import SqliteStore

CLAIM = json.dumps({"kind": "claim", "subject": {"type": "host", "key": "web-01"},
                    "predicate": "logged_in_by", "object": {"type": "user", "key": "jdoe"},
                    "observed_at": "2026-09-01T14:03:00Z", "source": "auth-log"}).encode()


class FakeProducer:
    def __init__(self):
        self.sent = []

    async def send_and_wait(self, topic, value, headers=None):
        self.sent.append((topic, value, dict(headers or [])))


def test_split_values_handles_single_and_ndjson():
    assert split_values([CLAIM, CLAIM + b"\n" + CLAIM + b"\n\n"]) == [CLAIM, CLAIM, CLAIM]


def test_write_with_retry_then_deadletter(tmp_path, monkeypatch):
    from loom import kafka_consumer
    store = SqliteStore(tmp_path / "k.db")
    producer = FakeProducer()
    counts = asyncio.run(write_with_retry(store, producer, [CLAIM, b"{poison"]))
    assert counts["recorded"] == 1 and counts["skipped"] == 1 and counts["deadlettered"] == 0

    calls = {"n": 0}
    def boom(claims):
        calls["n"] += 1
        raise RuntimeError("database is locked")
    monkeypatch.setattr(store, "record_claims", boom)
    monkeypatch.setattr(kafka_consumer, "MAX_DELIVER", 3)
    slept = []
    async def fake_sleep(s):
        slept.append(s)
    counts = asyncio.run(write_with_retry(store, producer, [CLAIM], sleep=fake_sleep))
    assert calls["n"] == 3 and slept == [2.0, 4.0]
    assert counts["deadlettered"] == 1 and counts["recorded"] == 0
    topic, value, headers = producer.sent[0]
    assert topic == "loom.deadletter" and value == CLAIM
    assert headers == {"Loom-Error": b"RuntimeError", "Loom-Error-Code": b"store_rejected"}
    monkeypatch.undo()
    assert store.count_observations("default", EntityRef(type="host", key="web-01")) == 1


def test_only_the_poison_envelope_is_dead_lettered(tmp_path, monkeypatch):
    """The last attempt writes the batch one envelope at a time: the good
    batch-mates of a poison envelope land instead of being parked with it."""
    from loom import kafka_consumer
    store = SqliteStore(tmp_path / "k3.db")
    real = store.record_claims

    def picky(claims):
        if any(c.source == "poison" for c in claims):
            raise RuntimeError("constraint failed")
        return real(claims)

    poison = CLAIM.replace(b'"auth-log"', b'"poison"')
    monkeypatch.setattr(store, "record_claims", picky)
    monkeypatch.setattr(kafka_consumer, "MAX_DELIVER", 2)
    producer = FakeProducer()

    async def no_sleep(s):
        pass

    counts = asyncio.run(write_with_retry(store, producer, [CLAIM, poison, CLAIM], sleep=no_sleep))
    assert counts["recorded"] == 2 and counts["deadlettered"] == 1
    assert [v for _, v, _ in producer.sent] == [poison]


def test_strict_registry_rejects_on_the_kafka_path(tmp_path):
    from loom.contracts import SchemaRegistration
    store = SqliteStore(tmp_path / "k2.db")
    store.put_schema(SchemaRegistration(namespace="default", strict=True,
                                        entity_types=[{"name": "host"}], predicates=[]))
    counts = asyncio.run(write_with_retry(store, FakeProducer(), [CLAIM]))
    assert counts["rejected"] == 1 and counts["recorded"] == 0
    assert store.count_observations("default", EntityRef(type="host", key="web-01")) == 0


def test_security_kwargs():
    from loom.kafka_consumer import security_kwargs
    assert security_kwargs({}) == {}
    assert security_kwargs({"LOOM_KAFKA_SECURITY_PROTOCOL": "SSL"}).keys() == {"security_protocol", "ssl_context"}
    sasl = security_kwargs({"LOOM_KAFKA_SECURITY_PROTOCOL": "SASL_SSL", "LOOM_KAFKA_SASL_MECHANISM": "scram-sha-256",
                            "LOOM_KAFKA_SASL_USERNAME": "u", "LOOM_KAFKA_SASL_PASSWORD": "p"})
    assert sasl["security_protocol"] == "SASL_SSL" and sasl["sasl_mechanism"] == "SCRAM-SHA-256"
    assert sasl["sasl_plain_username"] == "u" and "ssl_context" in sasl
    with pytest.raises(SystemExit):
        security_kwargs({"LOOM_KAFKA_SECURITY_PROTOCOL": "SASL_PLAINTEXT"})
