"""Bulk import (D-105): the set-at-a-time claim write and the store's bulk
mode store exactly what the claim-at-a-time, commit-per-batch path stored."""

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from loomctx.consumer import handle_batch
from loomctx.contracts import ClaimIn, DocumentIn, EntityRef, Provenance
from loomctx.ingest import load_direct
from loomctx.store.sqlite import SqliteStore

T = datetime(2026, 9, 1, 14, 3, tzinfo=timezone.utc)


def _c(event_id=None, subject=("host", "web-01"), obj=("user", "jdoe"), **kw):
    o = EntityRef(type=obj[0], key=obj[1]) if isinstance(obj, tuple) else obj
    return ClaimIn(subject=EntityRef(type=subject[0], key=subject[1]), predicate=kw.pop("predicate", "p"),
                   object=o, observed_at=T, source="s", event_id=event_id, **kw)


def _prepared(path):
    """A store with a stored replay target, a redacted one and a merge."""
    s = SqliteStore(path)
    s.record_claim(_c("pre-1"))
    gone = s.record_claim(_c("red-1", obj="secret"))
    s.redact("default", gone.id, "spill")
    s.record_claim(_c(subject=("ip_address", "10.0.4.7"), obj="x"))
    s.record_claim(_c(subject=("ip", "10.0.4.7"), obj=("host", "web-01")))
    assert s.merge_entities("default", EntityRef(type="ip_address", key="10.0.4.7"),
                            EntityRef(type="ip", key="10.0.4.7"))
    return s


BATCH = [
    _c("pre-1"),                                            # replay of a stored event
    _c("e-1", subject=("host", "a"), obj=("user", "u1")),   # new entities
    _c("e-2", subject=("ip_address", "10.0.4.7"), obj=("host", "a")),   # merged-away ref
    _c("e-1", subject=("host", "never"), obj=("user", "never")),        # repeat within the batch
    _c(None, subject=("host", "a"), obj=7),                 # no event id, scalar object
    _c(None, subject=("host", "a"), obj=7),                 # ...not deduplicated
    _c("red-1", obj="secret"),                              # replay of a redacted event
    _c("e-3", subject=("user", "u1"), obj=("host", "a"), attrs={"k": [1, 2]}),
]


def _shape(o):
    return (o.event_id, o.subject, o.predicate, o.object, o.attrs)


def _content(s):
    with s._tx(read=True):
        rows = s._conn.execute(
            "SELECT o.event_id, e.type, e.key, o.predicate, o.object_json, o.source, o.observed_at,"
            # artifact ids are minted per store; the cited event id is compared
            " o.attrs_json, json_remove(o.provenance_json, '$.artifact_id')"
            " FROM observations o JOIN entities e ON e.id = o.subject_id"
            # a document's mention links (D-118) key the document by its artifact id
            " WHERE o.source NOT LIKE '%:mentions'"
        ).fetchall()
        ents = s._conn.execute("SELECT type, key FROM entities WHERE type != 'document'").fetchall()
        aliases = s._conn.execute("SELECT alias FROM aliases").fetchall()
    return sorted(map(tuple, rows), key=repr), sorted(map(tuple, ents)), sorted(map(tuple, aliases))


def test_a_batch_stores_what_one_claim_at_a_time_stores(tmp_path):
    one, many = _prepared(tmp_path / "one.db"), _prepared(tmp_path / "many.db")
    singles = [one.record_claims([c])[0] for c in BATCH]
    batch = many.record_claims(BATCH)
    assert [_shape(o) for o in batch] == [_shape(o) for o in singles]
    assert _content(many) == _content(one)
    # replays answer with the stored row; the repeat with the first of the batch
    assert batch[3].id == batch[1].id and batch[4].id != batch[5].id
    assert batch[6].object == "[redacted]" and batch[2].subject == EntityRef(type="ip", key="10.0.4.7")
    assert many.get_entity("default", EntityRef(type="host", key="never")) is None
    assert many.get_entity("default", EntityRef(type="ip_address", key="10.0.4.7")).type == "ip"
    # and every returned observation reads back as it was returned
    for o in batch[1:6]:
        assert many.observations_by_ids("default", [o.id])[0] == o


def test_a_batch_bigger_than_a_lookup_chunk(tmp_path):
    s = SqliteStore(tmp_path / "s.db")
    claims = [_c(f"b-{i}", subject=("host", f"h{i % 700}"), obj=("user", f"u{i}")) for i in range(1500)]
    assert len({o.id for o in s.record_claims(claims)}) == 1500
    again = s.record_claims(claims)                         # every one a replay
    assert s.count_observations("default", EntityRef(type="host", key="h0")) == 3
    assert len({o.id for o in again}) == 1500
    assert sum(1 for _ in s.iter_entities("default")) == 700 + 1500


def _pg():
    import os
    url = os.environ.get("LOOMCTX_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("LOOMCTX_TEST_POSTGRES_URL not set")
    from loomctx.store.postgres import PostgresStore
    s = PostgresStore(url)
    s.wipe()
    return s


def _prepare(s):
    """_prepared's history, into a given store."""
    s.record_claim(_c("pre-1"))
    gone = s.record_claim(_c("red-1", obj="secret"))
    s.redact("default", gone.id, "spill")
    s.record_claim(_c(subject=("ip_address", "10.0.4.7"), obj="x"))
    s.record_claim(_c(subject=("ip", "10.0.4.7"), obj=("host", "web-01")))
    assert s.merge_entities("default", EntityRef(type="ip_address", key="10.0.4.7"),
                            EntityRef(type="ip", key="10.0.4.7"))


def _pg_content(s):
    with s._tx(read=True):
        rows = s._q(
            "SELECT o.event_id, e.type, e.key, o.predicate, o.object_json, o.source, o.observed_at,"
            " o.attrs_json, o.provenance_json FROM observations o JOIN entities e ON e.id = o.subject_id")
        ents = s._q("SELECT type, key FROM entities")
        aliases = s._q("SELECT alias FROM aliases")

    def row(r):
        prov = r["provenance_json"]
        prov = json.loads(prov) if isinstance(prov, str) else prov
        if prov:
            prov.pop("artifact_id", None)   # minted per store; the cited event id is compared
        attrs = r["attrs_json"]
        attrs = json.loads(attrs) if isinstance(attrs, str) else attrs
        return (r["event_id"], r["type"], r["key"], r["predicate"], r["object_json"], r["source"],
                str(r["observed_at"]), json.dumps(attrs, sort_keys=True), json.dumps(prov, sort_keys=True))
    return (sorted(map(row, rows), key=repr), sorted((r["type"], r["key"]) for r in ents),
            sorted(r["alias"] for r in aliases))


def test_a_postgres_batch_stores_what_one_claim_at_a_time_stores():
    """The Postgres write path is set at a time too: one claim at a time it
    made four to six round trips per claim (~280 facts/s across a network)."""
    s = _pg()
    try:
        _prepare(s)
        singles = [s.record_claims([c])[0] for c in BATCH]
        one = _pg_content(s)
        s.wipe()
        _prepare(s)
        batch = s.record_claims(BATCH)
        assert [_shape(o) for o in batch] == [_shape(o) for o in singles]
        assert _pg_content(s) == one
        assert batch[3].id == batch[1].id and batch[4].id != batch[5].id
        assert batch[6].object == "[redacted]" and batch[2].subject == EntityRef(type="ip", key="10.0.4.7")
        assert s.get_entity("default", EntityRef(type="host", key="never")) is None
        assert s.get_entity("default", EntityRef(type="ip_address", key="10.0.4.7")).type == "ip"
        for o in batch[1:6]:
            assert s.observations_by_ids("default", [o.id])[0] == o
    finally:
        s.close()


def test_a_postgres_batch_bigger_than_an_insert_chunk():
    s = _pg()
    try:
        claims = [_c(f"b-{i}", subject=("host", f"h{i % 700}"), obj=("user", f"u{i}")) for i in range(1500)]
        assert len({o.id for o in s.record_claims(claims)}) == 1500
        again = s.record_claims(claims)                     # every one a replay
        assert s.count_observations("default", EntityRef(type="host", key="h0")) == 3
        assert len({o.id for o in again}) == 1500
        assert sum(1 for _ in s.iter_entities("default")) == 700 + 1500
    finally:
        s.close()


def test_bulk_load_reads_its_own_writes_and_restores_the_store(tmp_path):
    s = SqliteStore(tmp_path / "s.db")
    before = [s._writer.execute(f"PRAGMA {p}").fetchone()[0] for p in ("cache_size", "wal_autocheckpoint")]
    doc = DocumentIn(text="r", source="ir", observed_at=T, event_id="doc-1")
    cites = _c("c-1", provenance=Provenance(artifact_event_id="doc-1"))
    with s.bulk_load():
        assert handle_batch(s, [doc.model_dump_json().encode()])["accepted"] == 1
        # the document is in the load's open transaction: still resolvable
        assert handle_batch(s, [cites.model_dump_json().encode()])["recorded"] == 1
    assert not s._writer.in_transaction
    assert [s._writer.execute(f"PRAGMA {p}").fetchone()[0]
            for p in ("cache_size", "wal_autocheckpoint")] == before
    # the query indexes it built at the end instead of row by row are all back
    indexes = {r[0] for r in s._writer.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert set(SqliteStore._BULK_DEFERRED_INDEXES) <= indexes
    other = sqlite3.connect(tmp_path / "s.db")
    # the cited claim; the document's own title fact (D-118) rides beside it
    assert other.execute("SELECT count(*) FROM observations WHERE source NOT LIKE '%:mentions'").fetchone()[0] == 1


def test_bulk_load_keeps_each_call_atomic_and_the_calls_before_an_error(tmp_path):
    s = SqliteStore(tmp_path / "s.db")
    s._BULK_COMMIT_SECONDS = 3600            # nothing commits until the load ends
    # a citation of a document never stored fails the call after its
    # entities were written: the savepoint must take them back
    nope = Provenance(artifact_event_id="nope")
    with pytest.raises(ValueError):
        with s.bulk_load():
            s.record_claims([_c("ok-1")])
            assert sqlite3.connect(tmp_path / "s.db").execute(
                "SELECT count(*) FROM observations").fetchone()[0] == 0     # not yet committed
            with pytest.raises(ValueError):
                s.record_claims([_c("half-1", subject=("host", "half")), _c("bad-1", provenance=nope)])
            s.record_claims([_c("ok-2")])
            s.record_claims([_c("half-2", subject=("host", "half2")), _c("bad-2", provenance=nope)])
    rows = sqlite3.connect(tmp_path / "s.db").execute("SELECT event_id FROM observations").fetchall()
    assert sorted(r[0] for r in rows) == ["ok-1", "ok-2"]
    assert s.get_entity("default", EntityRef(type="host", key="half")) is None
    assert s.get_entity("default", EntityRef(type="host", key="half2")) is None
    s.record_claim(_c("after"))                # and the store works on
    assert s.count_observations("default", EntityRef(type="host", key="web-01")) == 3


def test_bulk_load_defers_query_indexes_only_into_an_empty_store(tmp_path):
    def names(s):
        return {r[0] for r in s._writer.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}

    s = SqliteStore(tmp_path / "s.db")
    full = names(s)
    with s.bulk_load():
        assert not set(SqliteStore._BULK_DEFERRED_INDEXES) & names(s)     # empty: built at the end
        s.record_claims([_c("i-1")])
    assert names(s) == full
    with s.bulk_load():                                                     # not empty: kept
        assert names(s) == full
        s.record_claims([_c("i-2")])
    # a load that dies midway leaves them to the next open
    s2 = SqliteStore(tmp_path / "t.db")
    s2._defer_indexes()
    s2.close()
    assert names(SqliteStore(tmp_path / "t.db")) == full


def test_bulk_load_commits_as_it_goes(tmp_path):
    s = SqliteStore(tmp_path / "s.db")
    s._BULK_COMMIT_SECONDS = 0
    with s.bulk_load():
        s.record_claims([_c("g-1")])
        assert sqlite3.connect(tmp_path / "s.db").execute(
            "SELECT count(*) FROM observations").fetchone()[0] == 1


def test_a_sharded_bulk_load_commits_every_shard(tmp_path):
    from loomctx.store.sharded import ShardedStore
    s = ShardedStore(SqliteStore(tmp_path / "a.db"), {"other": SqliteStore(tmp_path / "b.db")})
    with s.bulk_load():
        s.record_claims([_c("x-1"), _c("x-1").model_copy(update={"namespace": "other"})])
    for name in ("a.db", "b.db"):
        assert sqlite3.connect(tmp_path / name).execute("SELECT count(*) FROM observations").fetchone()[0] == 1
    s.close()


def test_direct_load_stores_the_same_with_and_without_bulk_mode(tmp_path):
    rows = [{"kind": "document", "namespace": "n", "text": "r", "source": "ir",
             "observed_at": "2026-09-02T09:00:00Z", "event_id": "d"}]
    rows += [{"kind": "claim", "namespace": "n", "event_id": f"e{i % 40}",
              "subject": {"type": "host", "key": f"h{i % 9}"}, "predicate": "p",
              "object": {"type": "user", "key": f"u{i % 13}"}, "observed_at": "2026-09-01T14:03:00Z",
              "source": "s", **({"provenance": {"artifact_event_id": "d"}} if i % 5 == 0 else {})}
             for i in range(120)]
    rows.append({"kind": "claim", "namespace": "n", "subject": {"type": "host", "key": "x"},
                 "predicate": "p", "object": "y", "observed_at": "2026-09-01T14:03:00Z", "source": "s",
                 "provenance": {"artifact_event_id": "missing"}})
    lines = [json.dumps(r) + "\n" for r in rows]
    bulk = load_direct(str(tmp_path / "bulk.db"), lines, size=16)
    plain = load_direct(str(tmp_path / "plain.db"), lines, size=16, bulk=False)
    assert bulk == plain == {"recorded": 120, "accepted": 1, "skipped": 1, "rejected": 0}
    assert _content(SqliteStore(tmp_path / "bulk.db")) == _content(SqliteStore(tmp_path / "plain.db"))
