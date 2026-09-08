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
    assert headers["Loom-Error"].startswith(b"RuntimeError: database is locked")
    monkeypatch.undo()
    assert store.count_observations("default", EntityRef(type="host", key="web-01")) == 1
