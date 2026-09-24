import json

from loom.consumer import handle_message
from loom.contracts import EntityRef
from loom.store.sqlite import SqliteStore

CLAIM = b"""{
  "kind": "claim",
  "subject": {"type": "host", "key": "web-01"},
  "predicate": "logged_in_by",
  "object": {"type": "user", "key": "jdoe"},
  "observed_at": "2026-09-01T14:03:00Z",
  "source": "auth-log"
}"""

DOCUMENT = (b'{"kind": "document", "text": "report", "source": "ir",'
            b' "observed_at": "2026-09-02T09:00:00Z"}')


def test_claim_message_is_recorded(tmp_path):
    store = SqliteStore(tmp_path / "c.db")
    assert handle_message(store, CLAIM) == "recorded"
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert len(obs) == 1 and obs[0].source == "auth-log"


def test_document_message_is_accepted(tmp_path):
    store = SqliteStore(tmp_path / "c.db")
    assert handle_message(store, DOCUMENT) == "accepted"


def test_poison_message_is_skipped_not_raised(tmp_path):
    store = SqliteStore(tmp_path / "c.db")
    assert handle_message(store, b"{not json") == "skipped"
    assert handle_message(store, b'{"kind": "claim"}') == "skipped"


def test_batch_mixes_kinds_and_survives_poison(tmp_path):
    from loom.consumer import handle_batch

    store = SqliteStore(tmp_path / "c.db")
    counts = handle_batch(store, [CLAIM, CLAIM, DOCUMENT, b"{poison"])
    assert counts == {"recorded": 2, "accepted": 1, "skipped": 1, "rejected": 0}
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert len(obs) == 2


def test_store_failure_propagates_so_the_batch_is_redelivered(tmp_path, monkeypatch):
    """H-I7: a store error inside a batch is NOT swallowed (the run loop
    leaves the batch un-acked for redelivery) and nothing partial lands."""
    import pytest
    from loom.consumer import handle_batch
    store = SqliteStore(tmp_path / "c.db")

    def boom(claims):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(store, "record_claims", boom)
    with pytest.raises(RuntimeError):
        handle_batch(store, [CLAIM, DOCUMENT])
    assert store.observations_for("default", EntityRef(type="host", key="web-01")) == []
    monkeypatch.undo()
    counts = handle_batch(store, [CLAIM, DOCUMENT])  # the redelivery succeeds
    assert counts["recorded"] == 1 and counts["accepted"] == 1


def test_failed_batch_naks_then_deadletters_on_last_delivery():
    """D-029: nak for redelivery until MAX_DELIVER, then park on the
    dead-letter stream with the reason and ack."""
    import asyncio
    from types import SimpleNamespace
    from loom.consumer import settle_failed_batch

    published = []

    class FakeJS:
        async def publish(self, subject, data, headers=None):
            published.append((subject, data, headers))

    class FakeMsg:
        def __init__(self, delivered):
            self.subject = "loom.ingest.claim"
            self.data = CLAIM
            self.headers = {"Loom-Principal": "shipper"}
            self.metadata = SimpleNamespace(num_delivered=delivered)
            self.acked = False
            self.naks = []

        async def ack(self):
            self.acked = True

        async def nak(self, delay=None):
            self.naks.append(delay)

    fresh, last = FakeMsg(1), FakeMsg(5)
    parked = asyncio.run(settle_failed_batch(
        FakeJS(), [fresh, last], RuntimeError("database is locked"), max_deliver=5))
    assert parked == 1
    assert fresh.naks == [2] and not fresh.acked
    assert last.acked and not last.naks
    assert published[0][0] == "loom.deadletter.claim"
    assert published[0][2]["Loom-Principal"] == "shipper"
    # class + code only: the exception text can quote row data and headers
    # are readable by anyone with the stream
    assert published[0][2]["Loom-Error"] == "RuntimeError"
    assert published[0][2]["Loom-Error-Code"] == "store_rejected"
    assert "locked" not in json.dumps(published[0][2])


def test_registry_validation_runs_on_the_queue_path(tmp_path):
    """The gateway checks the contract shape, not the registry: a strict
    namespace's rules (D-024) are applied here, per claim, and a violation
    is dropped with a reason rather than written or crashing the batch."""
    from loom.consumer import handle_batch
    from loom.contracts import PredicateDef, SchemaRegistration
    from loom.registry import RegistryCache
    store = SqliteStore(tmp_path / "r.db")
    store.put_schema(SchemaRegistration(
        namespace="strict", strict=True,
        entity_types=[{"name": "host"}, {"name": "user"}],
        predicates=[PredicateDef(name="logged_in_by", object_types=["user"])]))
    base = {"kind": "claim", "namespace": "strict", "observed_at": "2026-09-01T00:00:00Z", "source": "s"}
    ok = {**base, "event_id": "ok", "subject": {"type": "host", "key": "h"},
          "predicate": "logged_in_by", "object": {"type": "user", "key": "u"}}
    wrong_type = {**base, "event_id": "wt", "subject": {"type": "host", "key": "h"},
                  "predicate": "logged_in_by", "object": {"type": "printer", "key": "p"}}
    unregistered = {**base, "event_id": "un", "subject": {"type": "host", "key": "h"},
                    "predicate": "owned_by", "object": "x"}
    counts = handle_batch(store, [json.dumps(x).encode() for x in (ok, wrong_type, unregistered)],
                          RegistryCache(store))
    assert counts == {"recorded": 1, "accepted": 0, "skipped": 0, "rejected": 2}
    obs = store.observations_for("strict", EntityRef(type="host", key="h"))
    assert [o.predicate for o in obs] == ["logged_in_by"]
    # without an explicit cache the batch builds one itself
    assert handle_batch(store, [json.dumps(unregistered).encode()])["rejected"] == 1
    store.close()


def test_queue_path_skips_a_claim_citing_an_unknown_document(tmp_path):
    """D-039: the consumer cannot reject per item, so it drops and logs."""
    import json
    from loom.consumer import handle_batch
    store = SqliteStore(tmp_path / "q.db")
    doc = {"kind": "document", "event_id": "d1", "text": "t", "source": "s", "observed_at": "2026-09-01T00:00:00Z"}
    base = {"kind": "claim", "subject": {"type": "host", "key": "h"}, "predicate": "p", "object": 1,
            "observed_at": "2026-09-01T00:00:00Z", "source": "s"}
    good = {**base, "event_id": "g", "provenance": {"artifact_event_id": "d1"}}
    bad = {**base, "event_id": "b", "provenance": {"artifact_event_id": "zzz"}}
    counts = handle_batch(store, [json.dumps(x).encode() for x in (doc, good, bad)])
    assert counts == {"recorded": 1, "accepted": 1, "skipped": 1, "rejected": 0}
    assert store.observations_for("default", EntityRef(type="host", key="h"))[0].provenance.artifact_id
    store.close()


# ------------------------------------------- per-message settlement (2026-09-24) #

class _JS:
    def __init__(self):
        self.published = []

    async def publish(self, subject, data, headers=None):
        self.published.append((subject, data, headers))


class _Msg:
    def __init__(self, payload, delivered=1):
        from types import SimpleNamespace
        self.subject = "loom.ingest.claim"
        self.data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.headers = {}
        self.metadata = SimpleNamespace(num_delivered=delivered)
        self.acked = False
        self.naks = []

    async def ack(self):
        self.acked = True

    async def nak(self, delay=None):
        self.naks.append(delay)


def _row(event_id, **extra):
    return {"kind": "claim", "event_id": event_id, "subject": {"type": "host", "key": "h"},
            "predicate": "p", "object": event_id, "observed_at": "2026-09-01T00:00:00Z",
            "source": "s", **extra}


def test_one_bad_envelope_no_longer_sinks_its_batch_mates(tmp_path, monkeypatch):
    """A batch the store rejected was nak'd whole: batch-mates shared the
    poison message's delivery count and were dead-lettered with it after
    MAX_DELIVER. Now the batch is re-written one message at a time."""
    import asyncio
    from loom.consumer import write_batch
    store = SqliteStore(tmp_path / "iso.db")
    real = store.record_claims

    def picky(claims):
        if any(c.event_id == "poison" for c in claims):
            raise RuntimeError("constraint failed")
        return real(claims)

    monkeypatch.setattr(store, "record_claims", picky)
    js = _JS()
    msgs = [_Msg(_row("g1")), _Msg(_row("poison")), _Msg(_row("g2"))]
    counts = asyncio.run(write_batch(js, store, msgs, max_deliver=5))
    assert counts["recorded"] == 2 and counts["deadlettered"] == 0
    assert msgs[0].acked and msgs[2].acked                      # the good ones land and are acked
    assert not msgs[1].acked and msgs[1].naks == [2]            # only the bad one comes back
    assert {o.event_id for o in store.observations_for("default", EntityRef(type="host", key="h"))} == {"g1", "g2"}
    # its last delivery parks it alone
    last = [_Msg(_row("g3"), delivered=5), _Msg(_row("poison"), delivered=5)]
    counts = asyncio.run(write_batch(js, store, last, max_deliver=5))
    assert counts["recorded"] == 1 and counts["deadlettered"] == 1
    assert last[0].acked and last[1].acked
    assert [json.loads(p[1])["event_id"] for p in js.published] == ["poison"]
    store.close()


def test_claim_whose_document_is_elsewhere_is_redelivered_not_dropped(tmp_path):
    """With two consumer replicas a claim can arrive before the document it
    cites (in the other replica's batch); it was dropped and acked. It is
    now nak'd with a delay, lands once the document does, and is
    dead-lettered (not lost silently) if it never does."""
    import asyncio
    from loom.consumer import write_batch
    store = SqliteStore(tmp_path / "prov.db")
    js = _JS()
    claim = _row("c1", provenance={"artifact_event_id": "d1"})
    first = _Msg(claim)
    counts = asyncio.run(write_batch(js, store, [first, _Msg(_row("other"))], max_deliver=5))
    assert counts["recorded"] == 1 and counts["skipped"] == 0
    assert not first.acked and first.naks == [5.0]
    doc = {"kind": "document", "event_id": "d1", "text": "t", "source": "s",
           "observed_at": "2026-09-01T00:00:00Z"}
    asyncio.run(write_batch(js, store, [_Msg(doc)], max_deliver=5))    # the other replica lands it
    again = _Msg(claim, delivered=2)
    counts = asyncio.run(write_batch(js, store, [again], max_deliver=5))
    assert counts["recorded"] == 1 and again.acked
    obs = [o for o in store.observations_for("default", EntityRef(type="host", key="h")) if o.event_id == "c1"]
    assert obs[0].provenance.artifact_id
    # never resolvable: parked with a code on its last delivery
    orphan = _Msg(_row("c2", provenance={"artifact_event_id": "nope"}), delivered=5)
    counts = asyncio.run(write_batch(js, store, [orphan], max_deliver=5))
    assert counts["deadlettered"] == 1 and orphan.acked
    assert js.published[-1][2]["Loom-Error-Code"] == "provenance_unresolved"
    store.close()


def test_claim_may_cite_a_document_later_in_its_batch(tmp_path):
    from loom.consumer import handle_batch
    store = SqliteStore(tmp_path / "order.db")
    doc = {"kind": "document", "event_id": "d9", "text": "t", "source": "s",
           "observed_at": "2026-09-01T00:00:00Z"}
    counts = handle_batch(store, [json.dumps(_row("c9", provenance={"artifact_event_id": "d9"})).encode(),
                                  json.dumps(doc).encode()])
    assert counts == {"recorded": 1, "accepted": 1, "skipped": 0, "rejected": 0}
    store.close()
