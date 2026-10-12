"""GraphStore contract tests, run against every backend.

SQLite always runs. Postgres runs when LOOMCTX_TEST_POSTGRES_URL is set (CI
brings one up via the compose `pg` profile); otherwise those params skip.
"""

import json
import os
from datetime import datetime, timezone

import pytest

from loomctx.contracts import ClaimIn, EntityRef
from loomctx.store.sqlite import SqliteStore

OBSERVED = datetime(2026, 9, 1, 14, 3, tzinfo=timezone.utc)


@pytest.fixture(params=["sqlite", "postgres", "sharded"])
def store(request, tmp_path):
    if request.param == "sqlite":
        s = SqliteStore(tmp_path / "test.db")
    elif request.param == "sharded":
        # two SQLite shards: namespaces the suite uses land on both sides,
        # so every contract test also exercises the routing (D-032)
        from loomctx.store.sharded import ShardedStore
        b = SqliteStore(tmp_path / "shard-b.db")
        s = ShardedStore(SqliteStore(tmp_path / "shard-a.db"),
                         {"team-b": b, "other": b, "other-ns": b, "vuln": b})
    else:
        url = os.environ.get("LOOMCTX_TEST_POSTGRES_URL")
        if not url:
            pytest.skip("LOOMCTX_TEST_POSTGRES_URL not set")
        from loomctx.store.postgres import PostgresStore

        s = PostgresStore(url)
        s.wipe()
    yield s
    s.close()


def _raw(store):
    """Tests that poke backend internals skip the routing wrapper."""
    if not hasattr(store, "_tx"):
        pytest.skip("backend-internal test; not applicable to ShardedStore")
    return store


def _exec(store, sql, params=()):
    """Raw SQL against a backend for setup/inspection; `?` placeholders are
    translated for Postgres. Returns rows as dicts (empty for statements)."""
    with store._tx():
        if isinstance(store, SqliteStore):
            return [dict(r) for r in store._conn.execute(sql, params).fetchall()]
        return store._q(sql.replace("?", "%s"), params)


def _reopen(store, tmp_path):
    """A second store instance on the same database (migration tests)."""
    if isinstance(store, SqliteStore):
        return SqliteStore(tmp_path / "test.db")
    from loomctx.store.postgres import PostgresStore
    return PostgresStore(os.environ["LOOMCTX_TEST_POSTGRES_URL"])


def login_claim(namespace="default"):
    return ClaimIn(
        namespace=namespace,
        subject=EntityRef(type="host", key="web-01"),
        predicate="logged_in_by",
        object=EntityRef(type="user", key="jdoe"),
        observed_at=OBSERVED,
        source="auth-log",
    )


def test_record_claim_creates_entities_and_edge(store):
    obs = store.record_claim(login_claim())

    assert store.get_entity("default", EntityRef(type="host", key="web-01"))
    assert store.get_entity("default", EntityRef(type="user", key="jdoe"))

    from_subject = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert [o.id for o in from_subject] == [obs.id]

    # edge is visible from the object side too
    from_object = store.observations_for("default", EntityRef(type="user", key="jdoe"))
    assert [o.id for o in from_object] == [obs.id]
    assert from_object[0].subject == EntityRef(type="host", key="web-01")


def test_record_claims_batch(store):
    claims = [
        login_claim().model_copy(
            update={"object": EntityRef(type="user", key=f"user-{i}")}
        )
        for i in range(25)
    ]
    observations = store.record_claims(claims)
    assert len(observations) == 25
    stored = store.observations_for(
        "default", EntityRef(type="host", key="web-01"), limit=100
    )
    assert len(stored) == 25


def test_scalar_object_roundtrip(store):
    claim = login_claim().model_copy(
        update={"predicate": "runs_os", "object": "fedora-44"}
    )
    store.record_claim(claim)
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert obs[0].object == "fedora-44"


def test_namespace_isolation(store):
    store.record_claim(login_claim(namespace="team-a"))
    assert store.observations_for("team-b", EntityRef(type="host", key="web-01")) == []
    assert store.get_entity("team-b", EntityRef(type="host", key="web-01")) is None


def test_upsert_is_idempotent(store):
    first = store.upsert_entity("default", EntityRef(type="host", key="web-01"))
    second = store.upsert_entity("default", EntityRef(type="host", key="web-01"))
    assert first.id == second.id


def test_unknown_entity_returns_empty(store):
    assert store.observations_for("default", EntityRef(type="host", key="nope")) == []


def test_artifact_roundtrip(store):
    from loomctx.contracts import DocumentIn

    artifact = store.store_artifact(
        DocumentIn(
            text="incident report",
            filename="ir.txt",
            source="ir-pipeline",
            observed_at=OBSERVED,
        )
    )
    fetched = store.get_artifact("default", artifact.id)
    assert fetched is not None and fetched.text == "incident report"
    assert fetched.extraction_status == "pending"
    assert store.get_artifact("default", "missing") is None


def test_schema_merge_keeps_a_label_either_side_sets():
    from loomctx.contracts import PredicateDef, SchemaRegistration
    from loomctx.store.common import merge_schema
    a = SchemaRegistration(namespace="n", predicates=[PredicateDef(name="name", label=True)])
    b = SchemaRegistration(namespace="n", predicates=[PredicateDef(name="name", description="display name")])
    assert merge_schema(a, b).predicates[0].label and merge_schema(b, a).predicates[0].label
    c = SchemaRegistration(namespace="n", predicates=[PredicateDef(name="name", label=True, display=True)])
    assert merge_schema(c, b).predicates[0].display and merge_schema(b, c).predicates[0].display   # D-097


def test_search_entities_exact_and_prefix(store):
    store.record_claim(login_claim())  # creates host web-01 + user jdoe
    exact = store.search_entities("default", "web-01")
    assert [e.key for e in exact] == ["web-01"]
    prefix = store.search_entities("default", "web")
    assert [e.key for e in prefix] == ["web-01"]
    assert store.search_entities("default", "zzz") == []
    assert store.search_entities("other-ns", "web-01") == []


def test_search_entities_by_label(store):
    """D-091: an entity keyed by an opaque id (a SID) is found by the value
    of a label predicate — exact first, then prefix, case-insensitive —
    after key matches, within the type filter; no labels means keys only."""
    def fact(key, etype, predicate, value):
        store.record_claim(ClaimIn(namespace="ad", subject=EntityRef(type=etype, key=key), predicate=predicate,
                                   object=value, observed_at=OBSERVED, source="ldap"))
    fact("S-1-5-21-9-512", "group", "name", "Domain Admins")
    fact("S-1-5-21-9-1101", "user", "sam", "dlee")
    fact("S-1-5-21-9-1102", "user", "sam", "dleeson")
    fact("S-1-5-21-9-1103", "user", "os", "domain controller")        # not a label
    labels = ("name", "sam")
    keys = lambda q, **kw: [e.key for e in store.search_entities("ad", q, labels=labels, **kw)]  # noqa: E731
    assert keys("Domain Admins") == ["S-1-5-21-9-512"]
    assert keys("domain") == ["S-1-5-21-9-512"]
    assert keys("dlee") == ["S-1-5-21-9-1101", "S-1-5-21-9-1102"]
    assert keys("dlee", types=("group",)) == []
    assert keys("S-1-5-21-9-5") == ["S-1-5-21-9-512"]                   # keys still match
    assert store.search_entities("ad", "Domain Admins") == []


def test_merge_folds_and_aliases_resolve(store):
    # ip:10.0.4.7 (structured) and ip_address:10.0.4.7 (extracted drift)
    store.record_claim(ClaimIn(
        subject=EntityRef(type="ip", key="10.0.4.7"), predicate="assigned_to",
        object=EntityRef(type="host", key="web-01"),
        observed_at=OBSERVED, source="dhcp"))
    store.record_claim(ClaimIn(
        subject=EntityRef(type="ip_address", key="10.0.4.7"),
        predicate="mentioned_in", object="IR-4432",
        observed_at=OBSERVED, source="doc:ir"))

    assert store.merge_entities(
        "default", EntityRef(type="ip_address", key="10.0.4.7"),
        EntityRef(type="ip", key="10.0.4.7")) is True

    # both facts now hang off the canonical ip entity...
    canon = store.observations_for("default", EntityRef(type="ip", key="10.0.4.7"))
    assert {o.predicate for o in canon} == {"assigned_to", "mentioned_in"}
    # ...and a query for the merged-away ref still resolves via its alias
    via_alias = store.observations_for(
        "default", EntityRef(type="ip_address", key="10.0.4.7"))
    assert len(via_alias) == 2
    # the stray node is gone
    assert store.get_entity(
        "default", EntityRef(type="ip_address", key="10.0.4.7")).type == "ip"


def test_claim_for_a_merged_away_ref_lands_on_the_canonical(store):
    """After ip_address:10.0.4.7 is folded into ip:10.0.4.7, a claim (or a
    restored observation) naming the old ref must attach to the canonical
    entity, not resurrect the folded node beside its own alias."""
    from loomctx.contracts import Observation
    a, b = EntityRef(type="ip_address", key="10.0.4.7"), EntityRef(type="ip", key="10.0.4.7")
    store.record_claim(ClaimIn(subject=a, predicate="noted", object="x", observed_at=OBSERVED, source="s"))
    store.record_claim(ClaimIn(subject=b, predicate="assigned_to", object=EntityRef(type="host", key="web-01"),
                               observed_at=OBSERVED, source="s"))
    assert store.merge_entities("default", a, b)
    obs = store.record_claim(ClaimIn(subject=a, predicate="seen", object="y", observed_at=OBSERVED, source="s"))
    assert obs.subject == b                                  # the canonical ref, not the alias
    edge = store.record_claim(ClaimIn(subject=EntityRef(type="host", key="db-01"), predicate="uses",
                                      object=a, observed_at=OBSERVED, source="s"))
    assert edge.object == b
    store.restore_observation(Observation(
        id="restored-1", namespace="default", subject=a, predicate="imported", object=a,
        observed_at=OBSERVED, recorded_at=OBSERVED, source="s", confidence=1.0))
    got = store.observations_for("default", b)
    assert {o.predicate for o in got} == {"noted", "assigned_to", "seen", "uses", "imported"}
    assert all(o.subject != a and o.object != a for o in got)
    assert [e for e in store.iter_entities("default") if e.type == "ip_address"] == []   # not resurrected
    assert store.get_entity("default", a).type == "ip"


def test_add_alias_into_a_merged_away_ref_follows_the_alias(store):
    a, b = EntityRef(type="ip_address", key="10.0.4.7"), EntityRef(type="ip", key="10.0.4.7")
    for ref in (a, b):
        store.record_claim(ClaimIn(subject=ref, predicate="p", object="x", observed_at=OBSERVED, source="s"))
    assert store.merge_entities("default", a, b)
    stray = EntityRef(type="ipaddr", key="10.0.4.7")
    store.add_alias("default", stray, into=a)                # `into` is itself an alias by now
    assert store.get_entity("default", stray).type == "ip"
    assert len(store.observations_for("default", stray)) == 2
    store.add_alias("default", stray, into=EntityRef(type="ip", key="nope"))   # unknown: still a no-op
    assert store.get_entity("default", stray).type == "ip"


def test_merge_candidates_finds_cross_type_keys(store):
    store.record_claim(ClaimIn(
        subject=EntityRef(type="ip", key="10.0.4.7"), predicate="p",
        object="x", observed_at=OBSERVED, source="s"))
    store.record_claim(ClaimIn(
        subject=EntityRef(type="ip_address", key="10.0.4.7"), predicate="p",
        object="x", observed_at=OBSERVED, source="s"))
    store.record_claim(ClaimIn(
        subject=EntityRef(type="host", key="web-01"), predicate="p",
        object="x", observed_at=OBSERVED, source="s"))
    groups = store.merge_candidates("default")
    assert len(groups) == 1
    assert {e.type for e in groups[0]} == {"ip", "ip_address"}


def test_merge_unknown_is_false(store):
    assert store.merge_entities(
        "default", EntityRef(type="ip", key="nope"),
        EntityRef(type="ip", key="also-nope")) is False


def test_wipe_clears_everything(store):
    store.record_claim(login_claim())
    store.wipe()
    assert store.get_entity("default", EntityRef(type="host", key="web-01")) is None
    assert store.observations_for("default", EntityRef(type="host", key="web-01")) == []


# ------------------------------------------------- idempotent ingest (D-014) #

def _claim(event_id=None, namespace="default", observed=OBSERVED, **kw):
    return login_claim(namespace).model_copy(
        update={"event_id": event_id, "observed_at": observed, **kw})


def test_event_id_dedupes_redelivery(store):
    first = store.record_claim(_claim(event_id="evt-1"))
    replay = store.record_claim(_claim(event_id="evt-1"))
    assert replay.id == first.id
    assert len(store.observations_for("default", EntityRef(type="host", key="web-01"))) == 1


def test_event_id_is_namespace_scoped(store):
    a = store.record_claim(_claim(event_id="evt-1", namespace="team-a"))
    b = store.record_claim(_claim(event_id="evt-1", namespace="team-b"))
    assert a.id != b.id


def test_document_event_id_dedupes(store):
    from loomctx.contracts import DocumentIn
    doc = DocumentIn(text="report", source="ir", observed_at=OBSERVED, event_id="doc-1")
    first = store.store_artifact(doc)
    assert store.store_artifact(doc).id == first.id


def test_no_event_id_means_no_dedupe(store):
    store.record_claim(_claim())
    store.record_claim(_claim())
    assert len(store.observations_for("default", EntityRef(type="host", key="web-01"))) == 2


def test_dedupe_survives_losing_the_insert_race(store, monkeypatch):
    _raw(store)
    """H-B2: when the pre-check misses (another writer landed the event_id
    between check and insert), ON CONFLICT hands back the winner instead of
    raising — and the store keeps working afterwards."""
    from loomctx.contracts import DocumentIn
    first = store.record_claim(_claim(event_id="race-1"))
    real = store._existing_by_event
    calls = {"n": 0}

    def flaky(namespace, event_id):  # miss on the pre-check, hit on re-read
        calls["n"] += 1
        return None if calls["n"] == 1 else real(namespace, event_id)

    monkeypatch.setattr(store, "_existing_by_event", flaky)
    replay = store.record_claim(_claim(event_id="race-1"))
    assert replay.id == first.id and calls["n"] == 2
    monkeypatch.undo()
    assert len(store.observations_for("default", EntityRef(type="host", key="web-01"))) == 1

    doc = DocumentIn(text="r", source="ir", observed_at=OBSERVED, event_id="doc-race")
    art = store.store_artifact(doc)
    monkeypatch.setattr(store, "_artifact_by_event",
                        lambda ns, ev: None if ev == "never" else
                        store.__class__._artifact_by_event(store, ns, ev))
    # force the insert path by hiding the pre-check once
    seen = {"n": 0}
    real_art = store.__class__._artifact_by_event

    def flaky_art(ns, ev):
        seen["n"] += 1
        return None if seen["n"] == 1 else real_art(store, ns, ev)

    monkeypatch.setattr(store, "_artifact_by_event", flaky_art)
    assert store.store_artifact(doc).id == art.id


def test_failed_statement_does_not_poison_the_store(store):
    _raw(store)
    """H-B1: an error inside a transaction rolls back and the next call
    works (Postgres would otherwise be stuck in the aborted state)."""
    with pytest.raises(Exception):
        with store._tx():
            store._conn.execute("SELECT 1 FROM no_such_table")
    obs = store.record_claim(_claim(event_id="after-error"))
    assert store.observations_for("default", EntityRef(type="host", key="web-01"))[0].id == obs.id


def test_failed_batch_leaves_nothing_behind(store):
    """H-B1: a batch that fails midway persists none of its rows."""
    good = _claim(event_id="b-1")
    with pytest.raises(Exception):
        store.record_claims([good, "not a claim"])  # type: ignore[list-item]
    assert store.observations_for("default", EntityRef(type="host", key="web-01")) == []
    store.record_claim(good)  # and the store is still usable
    assert len(store.observations_for("default", EntityRef(type="host", key="web-01"))) == 1


# --------------------------------------------------- redaction & lifecycle #

def test_redaction_tombstones_hide_but_preserve(store):
    obs = store.record_claim(_claim())
    assert store.redact("default", obs.id, "classified spill") is True
    assert store.observations_for("default", EntityRef(type="host", key="web-01")) == []
    assert any(o.id == obs.id for o in store.iter_observations("default"))  # audit
    assert [t["observation_id"] for t in store.iter_tombstones("default")] == [obs.id]
    assert store.redact("default", "nope", "x") is False


def test_replaying_a_redacted_event_returns_no_content(store):
    """H-B3: dedupe acknowledges the event but never resurrects the data."""
    obs = store.record_claim(_claim(event_id="secret-1", attrs={"pw": "hunter2"}))
    store.redact("default", obs.id, "spill")
    replay = store.record_claim(_claim(event_id="secret-1", attrs={"pw": "hunter2"}))
    assert replay.id == obs.id
    assert replay.object == "[redacted]" and replay.attrs == {"redacted": True}
    assert store.dossier_candidates(min_new=1, min_total=1) == []  # not counted


def test_retention_purge_cleans_derived_rows(store):
    from datetime import timedelta
    from loomctx.contracts import DocumentIn
    old = OBSERVED - timedelta(days=400)
    keep = store.record_claim(_claim())
    gone = store.record_claim(_claim(observed=old))
    store.put_embeddings("default", "m", [(keep.id, [1.0]), (gone.id, [1.0])])
    art = store.store_artifact(DocumentIn(text="old doc", source="s", observed_at=old))
    store.put_doc_chunks("default", art.id, "m", [(0, 0, 7, "old doc", [1.0])])
    store.redact("default", gone.id, "x")
    removed = store.purge_older_than("default", OBSERVED - timedelta(days=90))
    assert removed == 2  # one observation + one artifact
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert [o.id for o in obs] == [keep.id]
    assert set(store.embeddings_for("default", [keep.id, gone.id], "m")) == {keep.id}
    assert store.doc_chunks_for_artifacts("default", [art.id], "m") == []
    assert list(store.iter_tombstones("default")) == []


def test_export_import_keeps_redactions_and_aliases(store, tmp_path):
    """H-B4: a restore is faithful — redacted stays hidden, merged refs resolve."""
    import io
    from loomctx.lifecycle import export_jsonl, import_jsonl
    from loomctx.store.sqlite import SqliteStore
    secret = store.record_claim(_claim(event_id="evt-9", attrs={"k": "v"}))
    store.redact("default", secret.id, "spill")
    store.record_claim(_claim(event_id="evt-10", observed=OBSERVED))
    store.record_claim(ClaimIn(
        subject=EntityRef(type="ip_address", key="10.0.4.7"), predicate="noted",
        object="x", observed_at=OBSERVED, source="doc"))
    store.record_claim(ClaimIn(
        subject=EntityRef(type="ip", key="10.0.4.7"), predicate="assigned_to",
        object=EntityRef(type="host", key="web-01"), observed_at=OBSERVED, source="dhcp"))
    assert store.merge_entities("default", EntityRef(type="ip_address", key="10.0.4.7"),
                                EntityRef(type="ip", key="10.0.4.7"))
    buf = io.StringIO()
    counts = export_jsonl(store, buf, namespace=None)
    assert counts["tombstones"] == 1 and counts["aliases"] == 1

    dst = SqliteStore(tmp_path / "restored.db")
    buf.seek(0)
    import_jsonl(dst, buf)
    visible = dst.observations_for("default", EntityRef(type="host", key="web-01"))
    assert all(o.id != secret.id for o in visible)  # still redacted
    assert any(o.event_id == "evt-10" for o in visible)
    assert len(dst.observations_for("default", EntityRef(type="ip_address", key="10.0.4.7"))) == 2
    buf.seek(0)
    import_jsonl(dst, buf)  # idempotent, including the event_id index (H-B11)
    assert len(dst.observations_for("default", EntityRef(type="host", key="web-01"))) == len(visible)
    dst.close()


def test_an_import_never_serves_a_redacted_row(store, tmp_path):
    """D-058: dumps wrote tombstones after the observations they redact, so
    an import served every redacted row for its whole length. Exports now
    put tombstones first, and an old-order dump that can be re-read gets
    its tombstones applied in a first pass."""
    import io
    from loomctx.lifecycle import export_jsonl, import_jsonl
    secret = store.record_claim(_claim(event_id="evt-s"))
    store.redact("default", secret.id, "spill")
    buf = io.StringIO()
    export_jsonl(store, buf, namespace=None)
    kinds = [json.loads(line)["type"] for line in buf.getvalue().splitlines()]
    assert kinds.index("tombstone") < kinds.index("observation")

    order: list[str] = []

    class Recording(SqliteStore):
        def restore_observation(self, obs):
            order.append("observation")
            super().restore_observation(obs)

        def restore_tombstone(self, *args):
            order.append("tombstone")
            super().restore_tombstone(*args)

    old_order = sorted(buf.getvalue().splitlines(), key=lambda line: json.loads(line)["type"] == "tombstone")
    dst = Recording(tmp_path / "old-order.db")
    try:
        assert import_jsonl(dst, old_order)["tombstones"] == 1
        assert order.index("tombstone") < order.index("observation")
        assert dst.observations_for("default", EntityRef(type="host", key="web-01")) == []
        order.clear()
        streamed = (line for line in buf.getvalue().splitlines())   # not re-readable: file order
        import_jsonl(dst, streamed)
        assert order.index("tombstone") < order.index("observation")
    finally:
        dst.close()


def test_timestamps_order_by_instant_not_text(store):
    """H-B5: 16:03+02:00 is EARLIER than 15:00Z even though it sorts later as text."""
    from datetime import timedelta, timezone as tz
    plus2 = datetime(2026, 9, 1, 16, 3, tzinfo=tz(timedelta(hours=2)))
    utc = datetime(2026, 9, 1, 15, 0, tzinfo=timezone.utc)
    naive = datetime(2026, 9, 1, 14, 30)  # naive = UTC by contract
    for i, when in enumerate((plus2, utc, naive)):
        store.record_claim(_claim(event_id=f"t{i}", observed=when))
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert [o.event_id for o in obs] == ["t1", "t2", "t0"]
    assert obs[0].observed_at == utc and obs[2].observed_at == plus2
    assert obs[1].observed_at.tzinfo is not None


def test_search_is_case_insensitive_and_escapes_wildcards(store):
    """H-B8: identical on both backends; `_`/`%` in queries are literal."""
    for key in ("web_01", "webX01", "Web-02"):
        store.upsert_entity("default", EntityRef(type="host", key=key))
    assert [e.key for e in store.search_entities("default", "web_")] == ["web_01"]
    assert [e.key for e in store.search_entities("default", "WEB-02")] == ["Web-02"]
    assert store.search_entities("default", "%") == []


def test_merge_moves_dossier_and_rewrites_object_refs(store):
    """H-B6: after a merge the edge's rendered object is the canonical ref,
    the folded node's brief is gone, and a brief is found via the alias."""
    store.record_claim(ClaimIn(
        subject=EntityRef(type="host", key="web-01"), predicate="uses_ip",
        object=EntityRef(type="ip_address", key="10.0.4.7"),
        observed_at=OBSERVED, source="doc"))
    store.record_claim(ClaimIn(
        subject=EntityRef(type="ip", key="10.0.4.7"), predicate="p", object="x",
        observed_at=OBSERVED, source="dhcp"))
    store.put_dossier("default", EntityRef(type="ip_address", key="10.0.4.7"), "stray", 1, [])
    store.put_dossier("default", EntityRef(type="ip", key="10.0.4.7"), "canonical brief", 1, [])
    assert store.merge_entities("default", EntityRef(type="ip_address", key="10.0.4.7"),
                                EntityRef(type="ip", key="10.0.4.7"))
    edge = store.observations_for("default", EntityRef(type="host", key="web-01"))[0]
    assert edge.object == EntityRef(type="ip", key="10.0.4.7")
    # both briefs are dropped by the merge (each described a partial view);
    # once rebuilt, the canonical brief is reachable through the alias
    assert store.get_dossier("default", EntityRef(type="ip", key="10.0.4.7")) is None
    store.put_dossier("default", EntityRef(type="ip", key="10.0.4.7"), "rebuilt brief", 2, [])
    via_alias = store.get_dossier("default", EntityRef(type="ip_address", key="10.0.4.7"))
    assert via_alias and via_alias["brief"] == "rebuilt brief"


def test_doc_chunks_are_keyed_by_model_and_carry_artifact_metadata(store):
    """H-D3/H-C1: chunks embedded under one model are invisible to another;
    each chunk carries what a citation needs."""
    from loomctx.contracts import DocumentIn
    art = store.store_artifact(DocumentIn(text="hello world", filename="h.txt",
                                          source="wiki", observed_at=OBSERVED))
    blank = store.store_artifact(DocumentIn(text="   \n ", source="wiki",
                                            observed_at=OBSERVED))
    assert [a.id for a in store.artifacts_needing_chunks("m1")] == [art.id]  # blank skipped
    store.put_doc_chunks("default", art.id, "m1", [(0, 0, 11, "hello world", [1.0, 0.0])])
    assert store.artifacts_needing_chunks("m1") == []
    assert [a.id for a in store.artifacts_needing_chunks("m2")] == [art.id]
    rows = store.doc_chunks_for_artifacts("default", [art.id], "m1")
    assert len(rows) == 1 and rows[0]["source"] == "wiki"
    assert rows[0]["observed_at"] == OBSERVED
    assert store.doc_chunks_for_artifacts("default", [art.id], "m2") == []
    assert blank.id != art.id


def test_dossier_round_trips_its_citations(store):
    ref = EntityRef(type="host", key="web-01")
    obs = store.record_claim(login_claim())
    store.put_dossier("default", ref, "a brief", 1, [obs.id])
    d = store.get_dossier("default", ref)
    assert d["brief"] == "a brief" and d["observation_ids"] == [obs.id]


def test_count_and_artifact_citation_scope(store):
    """H-E3 / H-A6 store primitives."""
    from loomctx.contracts import DocumentIn, Provenance
    host = EntityRef(type="host", key="web-01")
    assert store.count_observations("default", host) == 0
    a = store.record_claim(login_claim())
    b = store.record_claim(login_claim().model_copy(update={"predicate": "runs_os", "object": "x"}))
    assert store.count_observations("default", host) == 2
    assert store.count_observations("default", EntityRef(type="user", key="jdoe")) == 1
    store.redact("default", b.id, "x")
    assert store.count_observations("default", host) == 1  # tombstones excluded

    art = store.store_artifact(DocumentIn(text="t", source="s", observed_at=OBSERVED))
    assert store.artifact_cited_within("default", art.id, ("host", "user")) is False
    store.record_claim(login_claim().model_copy(update={
        "predicate": "mentioned_in", "object": "doc",
        "provenance": Provenance(artifact_id=art.id)}))
    assert store.artifact_cited_within("default", art.id, ("host", "user")) is True
    assert store.artifact_cited_within("default", art.id, ("vendor",)) is False
    assert store.artifact_cited_within("default", art.id, ()) is False
    assert a.id  # keep a referenced


def test_a_restored_tombstone_drops_briefs_citing_it(store):
    """D-058: restore_tombstone (lifecycle import) re-applies a redaction
    like `redact` does — a brief quoting the row does not survive it."""
    obs = store.record_claim(login_claim())
    host = EntityRef(type="host", key="web-01")
    store.put_dossier("default", host, "jdoe logs in", 1, [obs.id])
    store.restore_tombstone("default", obs.id, "pii", OBSERVED)
    assert store.get_dossier("default", host) is None
    assert store.observations_for("default", host) == []


def test_find_paths_drops_an_edge_superseded_off_its_walk(store):
    """D-067 on every backend: walked from its object side, a retired edge's
    correction (same subject, other object) is never gathered — find_paths
    looks the path's edge ids up with corrections_of before returning."""
    from loomctx.context import find_paths
    from loomctx.contracts import PathRequest
    b, c = EntityRef(type="host", key="b"), EntityRef(type="host", key="c")
    x = store.record_claim(ClaimIn(subject=b, predicate="link", object=c,
                                   observed_at=OBSERVED, source="g"))
    req = PathRequest(**{"from": c}, to=b, via=["link"], depth=1)
    assert len(find_paths(store, req).paths) == 1
    store.record_claim(ClaimIn(subject=b, predicate="link", object=EntityRef(type="host", key="c2"),
                               observed_at=OBSERVED.replace(day=5), source="g", supersedes=x.id))
    assert find_paths(store, req).paths == []
    # as of before the correction, the edge is current again
    early = find_paths(store, req.model_copy(update={"as_of": OBSERVED.replace(day=2)}))
    assert [e.cite.observation_id for e in early.paths[0]] == [x.id]


def test_resolve_refs_and_corrections_of(store):
    """D-058: the read path resolves its subjects to canonical entities
    (a merged-away name included) and finds the corrections of rows
    outside the window it gathered."""
    web01, alias = EntityRef(type="host", key="web-01"), EntityRef(type="host", key="WEB01")
    old = store.record_claim(login_claim())
    store.record_claim(login_claim().model_copy(update={"subject": alias, "event_id": "a1"}))
    assert store.merge_entities("default", alias, web01)
    got = store.resolve_refs("default", [alias, web01, EntityRef(type="host", key="nope")])
    assert got == {("host", "WEB01"): web01, ("host", "web-01"): web01}
    assert store.resolve_refs("default", []) == {}
    later = OBSERVED.replace(day=5)
    fix = store.record_claim(login_claim().model_copy(update={
        "object": "someone-else", "observed_at": later, "supersedes": old.id, "event_id": "fix"}))
    assert [o.id for o in store.corrections_of("default", [old.id])] == [fix.id]
    assert store.corrections_of("default", [old.id], observed_before=OBSERVED) == []
    assert store.corrections_of("default", []) == []
    store.redact("default", fix.id, "wrong")
    assert store.corrections_of("default", [old.id]) == []


def test_count_observations_for_a_type_scoped_reader(store):
    """D-058: a truncation total counts only what the reader could see."""
    host = EntityRef(type="host", key="web-01")
    store.record_claim(login_claim())                                   # host -> user
    store.record_claim(login_claim().model_copy(update={
        "predicate": "runs_os", "object": "linux", "event_id": "os"}))  # host -> scalar
    store.record_claim(ClaimIn(subject=EntityRef(type="ip", key="10.0.4.7"), predicate="assigned_to",
                               object=host, observed_at=OBSERVED, source="dhcp"))   # ip -> host
    assert store.count_observations("default", host) == 3
    assert store.count_observations("default", host, allowed_types=("host",)) == 1
    assert store.count_observations("default", host, allowed_types=("host", "ip")) == 2
    assert store.count_observations("default", host, allowed_types=("host", "ip", "user")) == 3
    assert store.count_observations("default", host, allowed_types=()) == 0


def test_redaction_invalidates_briefs_built_on_it(store):
    """H-D8: a brief that quoted a now-redacted fact is dropped."""
    host = EntityRef(type="host", key="web-01")
    obs = store.record_claim(login_claim())
    other = store.record_claim(login_claim(namespace="other"))
    store.put_dossier("default", host, "brief mentioning jdoe", 1, [obs.id])
    store.put_dossier("other", host, "other brief", 1, [other.id])
    store.redact("default", obs.id, "spill")
    assert store.get_dossier("default", host) is None
    assert store.get_dossier("other", host)["brief"] == "other brief"


# --------------------------------------------------- batch: foundations (D-024) #

def test_schema_version_is_recorded(store):
    assert store.schema_version() >= 2


def test_fuzzy_candidates_group_by_normalized_key(store):
    for t, k in [("host", "web-01"), ("host", "WEB_01"), ("host", "db-01"),
                 ("asset", "web01"), ("host", "web-02")]:
        store.upsert_entity("default", EntityRef(type=t, key=k))
    groups = store.fuzzy_merge_candidates("default")
    assert len(groups) == 1
    assert {(e.type, e.key) for e in groups[0]} == {
        ("host", "web-01"), ("host", "WEB_01"), ("asset", "web01")}
    assert store.merge_candidates("default") == []  # exact keys don't collide


def test_schema_registry_merges_by_name(store):
    from loomctx.contracts import EntityTypeDef, PredicateDef, SchemaRegistration
    assert store.get_schema("netsec") is None
    first = store.put_schema(SchemaRegistration(
        namespace="netsec",
        entity_types=[EntityTypeDef(name="host"), EntityTypeDef(name="domain")],
        predicates=[PredicateDef(name="member_of", object_types=["domain"],
                                 containment=True)]))
    assert {t.name for t in first.entity_types} == {"host", "domain"}
    second = store.put_schema(SchemaRegistration(
        namespace="netsec", strict=True,
        entity_types=[EntityTypeDef(name="host", description="a box")],
        predicates=[PredicateDef(name="runs_os")]))
    assert second.strict and {p.name for p in second.predicates} == {"member_of", "runs_os"}
    assert next(t for t in second.entity_types if t.name == "host").description == "a box"
    assert next(p for p in second.predicates if p.name == "member_of").containment
    assert store.get_schema("netsec") == second
    assert store.get_schema("other") is None


def test_extraction_backoff_is_persisted(store):
    from datetime import timedelta
    from loomctx.contracts import DocumentIn
    a = store.store_artifact(DocumentIn(text="a", source="s", observed_at=OBSERVED))
    b = store.store_artifact(DocumentIn(text="b", source="s", observed_at=OBSERVED))
    now = OBSERVED
    assert [x.id for x in store.pending_artifacts(10, now=now)] == [a.id, b.id]
    store.defer_extraction("default", a.id, 2, now + timedelta(minutes=5))
    assert [x.id for x in store.pending_artifacts(10, now=now)] == [b.id]
    assert store.get_artifact("default", a.id).extraction_attempts == 2
    later = now + timedelta(minutes=6)
    assert [x.id for x in store.pending_artifacts(10, now=later)] == [a.id, b.id]


def test_doc_chunks_by_seq(store):
    from loomctx.contracts import DocumentIn
    art = store.store_artifact(DocumentIn(text="abcdef", source="s", observed_at=OBSERVED))
    store.put_doc_chunks("default", art.id, "m", [
        (0, 0, 2, "ab", [1.0]), (1, 2, 4, "cd", [1.0]), (2, 4, 6, "ef", [1.0])])
    got = store.doc_chunks_by_seq("default", art.id, "m", [2, 0, 7])
    assert [c["seq"] for c in got] == [0, 2]
    assert store.doc_chunks_by_seq("default", art.id, "other", [0]) == []


def test_exports_stream_across_pages(store, monkeypatch):
    _raw(store)
    monkeypatch.setattr(type(store), "_PAGE", 3)
    for i in range(8):
        store.record_claim(login_claim().model_copy(
            update={"object": EntityRef(type="user", key=f"u{i}")}))
    ids = [o.id for o in store.iter_observations("default")]
    assert len(ids) == 8 and len(set(ids)) == 8
    assert len(list(store.iter_entities("default"))) == 9  # host + 8 users
    assert list(store.iter_observations("nope")) == []


def test_dossier_candidates_only_count_fresh_observations(store):
    host = EntityRef(type="host", key="web-01")
    for i in range(4):
        store.record_claim(login_claim().model_copy(
            update={"object": EntityRef(type="user", key=f"u{i}")}))
    store.record_claim(login_claim().model_copy(update={"predicate": "runs_os", "object": "fedora-44"}))  # a second kind of fact (D-044)
    cands = store.dossier_candidates(min_new=3, min_total=5)
    assert [(c[1], c[2]) for c in cands] == [(host, 5)]
    store.put_dossier("default", host, "brief", 5, [])
    assert store.dossier_candidates(min_new=3, min_total=5) == []
    for i in range(3):  # three NEW observations since the brief
        store.record_claim(login_claim().model_copy(
            update={"object": EntityRef(type="user", key=f"new{i}")}))
    cands = store.dossier_candidates(min_new=3, min_total=5)
    assert [(c[1], c[2]) for c in cands] == [(host, 8)]


def test_merge_drops_both_briefs(store):
    a, b = EntityRef(type="ip", key="1.1.1.1"), EntityRef(type="ip_address", key="1.1.1.1")
    for ref in (a, b):
        store.record_claim(ClaimIn(subject=ref, predicate="p", object="x",
                                   observed_at=OBSERVED, source="s"))
        store.put_dossier("default", ref, "old brief", 1, [])
    assert store.merge_entities("default", b, a)
    assert store.get_dossier("default", a) is None


# ----------------------------------------------------- vector index (D-025) #

def _unit(*xs):
    n = sum(x * x for x in xs) ** 0.5
    return [x / n for x in xs]


def test_nearest_observations_rank_by_cosine(store):
    ids = []
    for i, vec in enumerate([_unit(1, 0, 0), _unit(0.9, 0.1, 0), _unit(0, 1, 0), _unit(0, 0, 1)]):
        obs = store.record_claim(login_claim().model_copy(
            update={"object": EntityRef(type="user", key=f"u{i}"), "event_id": f"v{i}"}))
        ids.append(obs.id)
        store.put_embeddings("default", "m", [(obs.id, vec)])
    assert store.vector_backend() in ("sqlite-vec", "pgvector", "exact")
    hits = store.nearest_observations("default", "m", _unit(1, 0.05, 0), limit=2)
    assert [h[0] for h in hits] == [ids[0], ids[1]]
    assert hits[0][1] > hits[1][1] > 0.9
    # tombstoned rows never surface; other namespaces / models are invisible
    store.redact("default", ids[0], "x")
    assert [h[0] for h in store.nearest_observations("default", "m", _unit(1, 0.2, 0), 2)] == [ids[1], ids[2]]
    assert store.nearest_observations("other", "m", _unit(1, 0, 0), 2) == []
    assert store.nearest_observations("default", "m2", _unit(1, 0, 0), 2) == []
    assert store.nearest_observations("default", "m", _unit(1, 0), 2) == []  # wrong dim


def test_nearest_chunks_filter_by_artifact(store):
    from loomctx.contracts import DocumentIn
    a = store.store_artifact(DocumentIn(text="aaaa bbbb", source="s", observed_at=OBSERVED))
    b = store.store_artifact(DocumentIn(text="cccc dddd", source="s", observed_at=OBSERVED))
    store.put_doc_chunks("default", a.id, "m", [(0, 0, 4, "aaaa", _unit(1, 0)), (1, 5, 9, "bbbb", _unit(0, 1))])
    store.put_doc_chunks("default", b.id, "m", [(0, 0, 4, "cccc", _unit(1, 0.1))])
    hits = store.nearest_chunks("default", "m", _unit(1, 0), limit=3)
    assert [c["text"] for c, _ in hits] == ["aaaa", "cccc", "bbbb"]
    assert hits[0][0]["source"] == "s" and hits[0][0]["observed_at"] == OBSERVED
    only_b = store.nearest_chunks("default", "m", _unit(1, 0), limit=3, artifact_ids=[b.id])
    assert [c["text"] for c, _ in only_b] == ["cccc"]
    assert store.nearest_chunks("default", "m", _unit(1, 0), 3, artifact_ids=[]) == []


def test_nearest_chunks_filters_by_artifact_inside_the_index(store, monkeypatch):
    """D-058: the artifact filter ran after a namespace-wide ANN and needed
    `limit` survivors, so nearly every ask decoded every chunk vector of
    every cited artifact in Python. With an index the k nearest among the
    cited artifacts come from the index alone; chunks the index has not
    caught up with still count (the exact scan covers the lag)."""
    from loomctx.contracts import DocumentIn
    import loomctx.store.common as common
    docs = [store.store_artifact(DocumentIn(text=f"doc {i}", source="s", observed_at=OBSERVED,
                                            event_id=f"d{i}")) for i in range(6)]
    # five decoy documents sit right on the query; the cited one is off to the side
    for i, doc in enumerate(docs[:5]):
        store.put_doc_chunks("default", doc.id, "m", [(j, j, j + 1, f"decoy{i}-{j}", _unit(1, 0.01 * j, 0))
                                                      for j in range(20)])
    cited = docs[5]
    store.put_doc_chunks("default", cited.id, "m", [(j, j, j + 1, f"cited-{j}", _unit(0.2, 1, 0.1 * j))
                                                    for j in range(10)])
    backend = store.vector_backend()
    if backend != "exact":
        def no_python_scan(*a, **k):
            raise AssertionError("exact scan in Python despite an index")
        monkeypatch.setattr(common, "cosines", no_python_scan)
    hits = store.nearest_chunks("default", "m", _unit(1, 0, 0), limit=4, artifact_ids=[cited.id])
    assert [c["text"] for c, _ in hits] == ["cited-0", "cited-1", "cited-2", "cited-3"]
    monkeypatch.undo()
    # fewer chunks than `limit` is an answer, not a reason to scan
    assert len(store.nearest_chunks("default", "m", _unit(1, 0, 0), limit=64, artifact_ids=[cited.id])) == 10


def test_vector_index_backfill_and_exact_fallback_agree(store):
    _raw(store)
    """Rows that reach the JSON table without the index (imports, older
    versions) are picked up by ensure_vector_index; the exact path ranks
    identically to the ANN path."""
    ids = []
    vecs = [_unit(1, 0, 0), _unit(0, 1, 0), _unit(0.7, 0.7, 0)]
    for i, vec in enumerate(vecs):
        obs = store.record_claim(login_claim().model_copy(
            update={"object": EntityRef(type="user", key=f"u{i}"), "event_id": f"b{i}"}))
        ids.append(obs.id)
    backend = store.vector_backend()
    store._vec = False                       # write JSON only, like an old build
    for oid, vec in zip(ids, vecs):
        store.put_embeddings("default", "m", [(oid, vec)])
    exact = store.nearest_observations("default", "m", _unit(0.6, 0.8, 0), 3)
    store._vec = backend != "exact"
    counts = store.ensure_vector_index("m")
    if backend != "exact":
        assert counts["observations"] == 3
        assert store.ensure_vector_index("m")["observations"] == 0  # idempotent
    indexed = store.nearest_observations("default", "m", _unit(0.6, 0.8, 0), 3)
    assert [h[0] for h in indexed] == [h[0] for h in exact] == [ids[2], ids[1], ids[0]]
    for (_, s1), (_, s2) in zip(indexed, exact):
        assert abs(s1 - s2) < 1e-4
    assert {o.id for o in store.observations_by_ids("default", ids[:2])} == set(ids[:2])


def test_vector_index_backfill_is_per_model_and_purge_drops_stale_rows(store):
    """ensure_vector_index counted every model's index rows as `model`'s
    (a bare vobs_/vchk_ prefix), so a model whose index did not exist yet
    was skipped as already indexed; and purge left the ANN rows of purged
    observations and chunks behind, still answering searches."""
    _raw(store)
    from datetime import timedelta
    from loomctx.contracts import DocumentIn
    ids = [store.record_claim(login_claim().model_copy(update={
        "object": EntityRef(type="user", key=f"u{i}"), "event_id": f"pm{i}"})).id for i in range(3)]
    store.put_embeddings("default", "m2", [(oid, _unit(1, 0, 0)) for oid in ids])   # m2: indexed
    backend = store.vector_backend()
    store._vec = False                                                              # m: JSON only
    store.put_embeddings("default", "m", [(oid, _unit(0, 1, 0)) for oid in ids])
    store._vec = backend != "exact"
    counts = store.ensure_vector_index("m")
    if backend != "exact":
        assert counts["observations"] == 3            # m2's rows are not m's
        assert store.ensure_vector_index("m")["observations"] == 0
    assert {h[0] for h in store.nearest_observations("default", "m", _unit(0, 1, 0), 3)} == set(ids)

    old = OBSERVED - timedelta(days=400)
    gone = store.record_claim(_claim(observed=old, event_id="gone"))
    store.put_embeddings("default", "m", [(gone.id, _unit(0, 1, 0))])
    art_old = store.store_artifact(DocumentIn(text="old", source="s", observed_at=old))
    art_new = store.store_artifact(DocumentIn(text="new", source="s", observed_at=OBSERVED))
    store.put_doc_chunks("default", art_old.id, "m", [(0, 0, 3, "old", _unit(1, 0))])
    store.put_doc_chunks("default", art_new.id, "m", [(0, 0, 3, "new", _unit(0, 1))])
    assert store.purge_older_than("default", OBSERVED - timedelta(days=90)) == 2
    assert gone.id not in {h[0] for h in store.nearest_observations("default", "m", _unit(0, 1, 0), 10)}
    assert [c["text"] for c, _ in store.nearest_chunks("default", "m", _unit(1, 0), limit=1)] == ["new"]
    if backend != "exact":
        for name in store._vec_tables:
            assert _exec(store, f"SELECT COUNT(*) AS n FROM {name} WHERE ref_id IN (?, ?)",
                         (gone.id, f"{art_old.id}:m:0"))[0]["n"] == 0


def test_nearest_search_in_a_minority_namespace_is_complete(store):
    """The ANN index post-filters on namespace: with a few hundred vectors
    in one tenant, a three-vector tenant came back short or empty on
    Postgres (HNSW's default 40 candidates were all the big tenant's).
    Both stores now widen the candidate set and fall back to an exact scan
    when the index returns fewer than `limit` rows."""
    import random
    from loomctx.contracts import DocumentIn
    rng = random.Random(3)

    def vec():
        return _unit(*[rng.uniform(-1, 1) for _ in range(4)])

    big = store.record_claims([ClaimIn(namespace="big", subject=EntityRef(type="h", key=f"h{i}"), predicate="p",
                                       object=str(i), observed_at=OBSERVED, source="s") for i in range(300)])
    store.put_embeddings("big", "m", [(o.id, vec()) for o in big])
    small = store.record_claims([ClaimIn(namespace="small", subject=EntityRef(type="h", key=f"s{i}"), predicate="p",
                                         object=str(i), observed_at=OBSERVED, source="s") for i in range(3)])
    store.put_embeddings("small", "m", [(o.id, vec()) for o in small])
    assert {h[0] for h in store.nearest_observations("small", "m", _unit(1, 0, 0, 0), limit=3)} == {o.id for o in small}
    assert len(store.nearest_observations("small", "m", _unit(1, 0, 0, 0), limit=10)) == 3
    assert len(store.nearest_observations("big", "m", _unit(1, 0, 0, 0), limit=10)) == 10
    for ns, n in (("big", 300), ("small", 3)):
        art = store.store_artifact(DocumentIn(namespace=ns, text="t", source="s", observed_at=OBSERVED))
        store.put_doc_chunks(ns, art.id, "m", [(i, 0, 1, f"c{i}", vec()) for i in range(n)])
    assert len(store.nearest_chunks("small", "m", _unit(1, 0, 0, 0), limit=3)) == 3
    assert len(store.nearest_chunks("small", "m", _unit(1, 0, 0, 0), limit=10)) == 3


# ------------------------------------------------ concurrency (D-028) #

def test_concurrent_writers_and_readers(store):
    """Many threads writing and reading at once: no errors, every write
    lands once. On Postgres this exercises the connection pool; on SQLite
    the process lock serializes it."""
    import threading
    host = EntityRef(type="host", key="web-01")
    errors: list[Exception] = []

    def writer(n):
        try:
            for i in range(20):
                store.record_claim(login_claim().model_copy(update={
                    "object": EntityRef(type="user", key=f"w{n}-{i}"),
                    "event_id": f"c-{n}-{i}"}))
                store.observations_for("default", host, limit=5)
                store.search_entities("default", "web")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert store.count_observations("default", host) == 160
    # a replay from any thread still dedupes
    dup = store.record_claim(login_claim().model_copy(update={
        "object": EntityRef(type="user", key="w0-0"), "event_id": "c-0-0"}))
    assert store.count_observations("default", host) == 160 and dup.event_id == "c-0-0"


def test_postgres_read_replica_pool(tmp_path):
    """LOOMCTX_DB_READ: reads go to the replica pool (here: the same server
    under a different DSN), writes stay on the primary."""
    url = os.environ.get("LOOMCTX_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("LOOMCTX_TEST_POSTGRES_URL not set")
    from loomctx.store.postgres import PostgresStore
    read_url = url + ("&" if "?" in url else "?") + "application_name=loomctx-reader"
    s = PostgresStore(url, read_dsn=read_url, pool_size=2)
    try:
        s.wipe()
        assert s._read_pool is not None and s.ping()
        obs = s.record_claim(login_claim())
        got = s.observations_for("default", EntityRef(type="host", key="web-01"))
        assert [o.id for o in got] == [obs.id]
        assert s.get_entity("default", EntityRef(type="host", key="web-01"))
        assert s.schema_version() >= 2
        with s._tx(read=True):
            who = s._q("SELECT current_setting('application_name') AS a")[0]["a"]
        assert who == "loomctx-reader"
    finally:
        s.close()
    same = PostgresStore(url, read_dsn=url)   # identical DSN: no second pool
    assert same._read_pool is None
    same.close()


# ------------------------------------------------- worker fleet (D-031) #

def test_extraction_leases_are_exclusive_and_expire(store):
    from datetime import timedelta
    from loomctx.contracts import DocumentIn
    ids = [store.store_artifact(DocumentIn(text=f"doc {i}", source="s", observed_at=OBSERVED)).id
           for i in range(3)]
    now = OBSERVED
    a = store.pending_artifacts(2, now=now, lease=("worker-a", 300))
    b = store.pending_artifacts(5, now=now, lease=("worker-b", 300))
    assert [x.id for x in a] == ids[:2] and [x.id for x in b] == ids[2:]
    assert store.pending_artifacts(5, now=now, lease=("worker-a", 300)) == []   # all claimed
    # an unleased read (tests, ops) still sees everything pending
    assert len(store.pending_artifacts(5, now=now)) == 3
    # completion releases; the rest come back once the lease expires
    store.set_extraction_status("default", ids[0], "done")
    later = now + timedelta(seconds=301)
    again = store.pending_artifacts(5, now=later, lease=("worker-c", 300))
    assert [x.id for x in again] == ids[1:]
    # a deferral releases the lease too, but the backoff still holds it back
    store.defer_extraction("default", ids[1], 1, later + timedelta(minutes=10))
    assert [x.id for x in store.pending_artifacts(5, now=later + timedelta(seconds=301),
                                                   lease=("worker-d", 300))] == [ids[2]]


def test_chunk_and_dossier_leases(store):
    from loomctx.contracts import DocumentIn
    art = store.store_artifact(DocumentIn(text="hello world", source="s", observed_at=OBSERVED))
    assert [x.id for x in store.artifacts_needing_chunks("m", 4, lease=("a", 300))] == [art.id]
    assert store.artifacts_needing_chunks("m", 4, lease=("b", 300)) == []
    store.put_doc_chunks("default", art.id, "m", [(0, 0, 11, "hello world", [1.0])])
    assert store.artifacts_needing_chunks("m", 4, lease=("b", 300)) == []  # done, not just released

    for host in ("h1", "h2"):
        for i in range(4):
            store.record_claim(login_claim().model_copy(update={
                "subject": EntityRef(type="host", key=host),
                "object": EntityRef(type="user", key=f"u{i}")}))
        store.record_claim(login_claim().model_copy(update={
            "subject": EntityRef(type="host", key=host), "predicate": "runs_os", "object": "x"}))
    first = store.dossier_candidates(min_new=20, min_total=5, lease=("a", 300))
    assert {c[1].key for c in first} == {"h1", "h2"}
    assert store.dossier_candidates(min_new=20, min_total=5, lease=("b", 300)) == []
    store.put_dossier("default", EntityRef(type="host", key="h1"), "brief", 5, [])
    assert store.dossier_candidates(min_new=20, min_total=5) == []  # h1 built, h2 leased


def test_lease_release_honours_ownership(store):
    """A worker whose lease expired and was re-claimed must not clobber the
    new holder's state; a holder can renew per extraction window."""
    from datetime import timedelta
    from loomctx.contracts import DocumentIn
    art = store.store_artifact(DocumentIn(text="doc", source="s", observed_at=OBSERVED))
    now = OBSERVED
    assert [a.id for a in store.pending_artifacts(1, now=now, lease=("a", 300))] == [art.id]
    assert store.extend_extraction_lease("default", art.id, "a", 600) is True   # renews from the real clock
    assert store.extend_extraction_lease("default", art.id, "b", 600) is False   # not b's
    later = datetime.now(timezone.utc) + timedelta(seconds=901)                  # a's renewal ran out
    assert [a.id for a in store.pending_artifacts(1, now=later, lease=("b", 300))] == [art.id]
    assert store.set_extraction_status("default", art.id, "done", worker_id="a") is False
    assert store.get_artifact("default", art.id).extraction_status == "pending"
    assert store.defer_extraction("default", art.id, 3, later, worker_id="a") is False
    assert store.get_artifact("default", art.id).extraction_attempts == 0
    assert store.set_extraction_status("default", art.id, "done", worker_id="b") is True
    assert store.get_artifact("default", art.id).extraction_status == "done"
    assert store.extend_extraction_lease("default", art.id, "b", 600) is False   # nothing left to hold
    assert store.set_extraction_status("default", art.id, "pending") is True      # unconditional: ops/tests
    assert store.defer_extraction("default", art.id, 1, later) is True
    assert store.set_extraction_status("default", "nope", "done") is False


def test_chunk_and_dossier_release_honour_ownership(store):
    from loomctx.contracts import DocumentIn
    art = store.store_artifact(DocumentIn(text="hello world", source="s", observed_at=OBSERVED))
    assert [x.id for x in store.artifacts_needing_chunks("m", 4, lease=("a", 300))] == [art.id]
    # a stranger's chunks land (idempotent rows) but the lease stays a's
    store.put_doc_chunks("default", art.id, "m", [(0, 0, 11, "hello world", [1.0])], worker_id="c")
    assert len(store.doc_chunks_for_artifacts("default", [art.id], "m")) == 1
    assert store.artifacts_needing_chunks("m2", 4, lease=("b", 300)) == []       # still leased
    store.put_doc_chunks("default", art.id, "m", [(0, 0, 11, "hello world", [1.0])], worker_id="a")
    assert [x.id for x in store.artifacts_needing_chunks("m2", 4, lease=("b", 300))] == [art.id]

    h1 = EntityRef(type="host", key="h1")
    for i in range(4):
        store.record_claim(login_claim().model_copy(update={"subject": h1, "object": EntityRef(type="user", key=f"u{i}")}))
    store.record_claim(login_claim().model_copy(update={"subject": h1, "predicate": "runs_os", "object": "x"}))
    assert [c[1] for c in store.dossier_candidates(min_new=20, min_total=5, lease=("a", 300))] == [h1]
    assert store.put_dossier("default", h1, "b's brief", 5, [], worker_id="b") is False
    assert store.get_dossier("default", h1) is None
    assert store.put_dossier("default", h1, "a's brief", 5, [], worker_id="a") is True
    assert store.get_dossier("default", h1)["brief"] == "a's brief"
    assert store.put_dossier("default", h1, "ops brief", 5, []) is True            # unconditional


def test_embedding_backlog_shards_partition_the_work(store):
    ids = {store.record_claim(login_claim().model_copy(update={
        "object": EntityRef(type="user", key=f"u{i}")})).id for i in range(24)}
    seen: list[str] = []
    for i in range(4):
        part = [o.id for o in store.observations_without_embeddings("m", 100, shard=(i, 4))]
        assert not set(part) & set(seen)
        seen += part
    assert set(seen) == ids
    assert {o.id for o in store.observations_without_embeddings("m", 100, shard=(0, 1))} == ids


# -------------------------------------------------- namespace sharding (D-032) #

def test_sharded_store_routes_and_fans_out(tmp_path):
    from loomctx.contracts import DocumentIn
    from loomctx.store.sharded import ShardedStore
    a, b = SqliteStore(tmp_path / "a.db"), SqliteStore(tmp_path / "b.db")
    s = ShardedStore(a, {"acme": b})
    assert s.describe() == {"acme": 1}
    mixed = [login_claim("default"), login_claim("acme"), login_claim("default")]
    out = s.record_claims(mixed)
    assert [o.namespace for o in out] == ["default", "acme", "default"]   # order kept
    assert len(a.observations_for("default", EntityRef(type="host", key="web-01"))) == 2
    assert len(b.observations_for("acme", EntityRef(type="host", key="web-01"))) == 1
    assert a.observations_for("acme", EntityRef(type="host", key="web-01")) == []
    art = s.store_artifact(DocumentIn(namespace="acme", text="t", source="s", observed_at=OBSERVED))
    assert b.get_artifact("acme", art.id) and a.get_artifact("acme", art.id) is None
    # admin fan-out sees both sides; leased backlog never over-claims
    assert len(list(s.iter_observations())) == 3
    assert [x.id for x in s.pending_artifacts(10, lease=("w", 60))] == [art.id]
    assert s.pending_artifacts(10, lease=("w2", 60)) == []
    assert s.ping() and s.schema_version() >= 2 and s.vector_backend() == a.vector_backend()
    s.close()


def test_sharded_store_from_env(tmp_path, monkeypatch):
    from loomctx.store.factory import store_from_env
    from loomctx.store.sharded import ShardedStore
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "main.db"))
    monkeypatch.setenv("LOOMCTX_SHARDS", json.dumps({"acme": str(tmp_path / "acme.db"),
                                                  "globex": str(tmp_path / "acme.db")}))
    s = store_from_env()
    assert isinstance(s, ShardedStore) and s.describe() == {"acme": 1, "globex": 1}
    s.close()
    monkeypatch.delenv("LOOMCTX_SHARDS")
    assert isinstance(store_from_env(), SqliteStore)


def test_shards_never_inherit_the_default_read_replica(tmp_path, monkeypatch):
    """LOOMCTX_DB_READ names the replica of LOOMCTX_DB. A Postgres shard on another
    cluster must not be handed that replica; it gets one only from its own
    {"dsn", "read"} entry."""
    from loomctx.store import factory
    from loomctx.store.sharded import ShardedStore
    made = []

    def fake_store_from_url(url, read_url=factory._FROM_ENV):
        effective = os.environ.get("LOOMCTX_DB_READ") if read_url is factory._FROM_ENV else read_url
        made.append((url, effective))
        return SqliteStore(tmp_path / f"{len(made)}.db")

    monkeypatch.setattr(factory, "store_from_url", fake_store_from_url)
    monkeypatch.setenv("LOOMCTX_DB", "postgresql://primary/loomctx")
    monkeypatch.setenv("LOOMCTX_DB_READ", "postgresql://replica/loomctx")
    monkeypatch.setenv("LOOMCTX_SHARDS", json.dumps({
        "acme": "postgresql://acme-db/loomctx",
        "globex": {"dsn": "postgresql://globex-db/loomctx", "read": "postgresql://globex-replica/loomctx"},
        "initech": {"dsn": "postgresql://globex-db/loomctx"},
        "home": "postgresql://primary/loomctx",
    }))
    s = factory.store_from_env()
    assert isinstance(s, ShardedStore)
    assert made[0] == ("postgresql://primary/loomctx", "postgresql://replica/loomctx")   # LOOMCTX_DB keeps its replica
    assert ("postgresql://acme-db/loomctx", None) in made                              # a plain shard: no replica
    assert ("postgresql://globex-db/loomctx", "postgresql://globex-replica/loomctx") in made
    assert ("postgresql://globex-db/loomctx", None) in made                            # same dsn, no read: its own store
    assert s.describe()["home"] == 0                                                 # LOOMCTX_DB itself is shared, not reopened
    assert len(made) == 4
    s.close()
    assert factory.shard_specs('{"a": "x"}') == {"a": ("x", None)}
    with pytest.raises(ValueError):
        factory.shard_specs('{"a": {"read": "only"}}')
    with pytest.raises(ValueError):
        factory.shard_specs('["not", "a", "map"]')


def test_observations_for_merges_both_sides_newest_first_within_limit(store):
    """D-035: the lookup is two indexed halves (as subject, as object) merged,
    never a namespace scan. A self-edge appears once; the limit applies to
    the merged, newest-first result."""
    x = EntityRef(type="host", key="hub")
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    claims = []
    for i in range(3):   # hub as subject
        claims.append(ClaimIn(namespace="ns", subject=x, predicate="logged_in_by",
                              object=EntityRef(type="user", key=f"u{i}"),
                              observed_at=t.replace(hour=2 * i), source="s"))
    for i in range(3):   # hub as object
        claims.append(ClaimIn(namespace="ns", subject=EntityRef(type="ip", key=f"10.0.0.{i}"),
                              predicate="assigned_to", object=x,
                              observed_at=t.replace(hour=2 * i + 1), source="s"))
    claims.append(ClaimIn(namespace="ns", subject=x, predicate="peer_of", object=x,
                          observed_at=t.replace(hour=12), source="s"))
    store.record_claims(claims)
    got = store.observations_for("ns", x, limit=100)
    assert len(got) == 7
    hours = [o.observed_at.hour for o in got]
    assert hours == sorted(hours, reverse=True) == [12, 5, 4, 3, 2, 1, 0]
    assert sum(1 for o in got if o.predicate == "peer_of") == 1
    top = store.observations_for("ns", x, limit=4)
    assert [o.observed_at.hour for o in top] == [12, 5, 4, 3]
    assert {o.predicate for o in top} == {"peer_of", "assigned_to", "logged_in_by"}
    assert store.count_observations("ns", x) == 7            # self-edge counted once (D-038)
    assert store.count_observations("ns", EntityRef(type="host", key="nobody")) == 0


def test_namespace_summary_counts_entities_by_type(store):
    """D-036: what an agent needs before it can ask anything."""
    assert store.namespace_summary() == {}
    store.record_claims([login_claim("alpha"), login_claim("alpha"), login_claim("beta")])
    summary = store.namespace_summary()
    assert set(summary) == {"alpha", "beta"}
    assert summary["alpha"] == {"host": 1, "user": 1} and summary["beta"] == {"host": 1, "user": 1}


def test_claims_cite_documents_by_event_id(store):
    """D-039: provenance.artifact_event_id resolves to the artifact id at
    write time; a reference to a document never ingested is an error."""
    from loomctx.contracts import DocumentIn, Provenance
    art = store.store_artifact(DocumentIn(namespace="ns", event_id="rep-1", text="scan report", source="scanner",
                                          observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc)))
    claim = ClaimIn(namespace="ns", subject=EntityRef(type="host", key="h"), predicate="open_port", object=22,
                    source="scanner", observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
                    provenance=Provenance(artifact_event_id="rep-1", span_start=3, span_end=9))
    obs = store.record_claim(claim)
    assert obs.provenance.artifact_id == art.id and obs.provenance.artifact_event_id == "rep-1"
    assert store.observations_for("ns", EntityRef(type="host", key="h"))[0].provenance.artifact_id == art.id
    assert store.artifact_by_event("ns", "rep-1").id == art.id and store.artifact_by_event("ns", "nope") is None
    bad = claim.model_copy(update={"event_id": "x", "provenance": Provenance(artifact_event_id="nope")})
    with pytest.raises(ValueError, match="ingest the document first"):
        store.record_claim(bad)


def test_vectors_are_stored_packed_and_legacy_json_still_reads(store):
    """D-039: 1,536-dim vectors as JSON text were ~30 KB each and grew a
    store to 10 GB; packed float32 is ~6 KB. Old rows keep decoding."""
    import random
    from loomctx.store import common
    rng = random.Random(7)
    vec = [rng.uniform(-1, 1) for _ in range(1536)]          # realistic float text (~19 chars each)
    packed = common.pack_vector(vec)
    assert len(packed) == 4 + 1536 * 4 < len(json.dumps(vec)) / 3
    back = common.unpack_vector(packed)
    assert len(back) == 1536 and abs(back[10] - vec[10]) < 1e-6
    assert common.unpack_vector(json.dumps(vec[:3])) == vec[:3]                   # legacy TEXT
    assert common.unpack_vector(json.dumps(vec[:3]).encode()) == vec[:3]          # legacy after TEXT->BYTEA
    store.record_claims([login_claim("v")])
    ref = store.observations_for("v", EntityRef(type="host", key="web-01"))[0].id
    store.put_embeddings("v", "m", [(ref, vec)])
    got = store.embeddings_for("v", [ref], "m")[ref]
    assert len(got) == 1536 and abs(got[1535] - vec[1535]) < 1e-3
    assert store.schema_version() == 9


def test_subjects_citing_maps_documents_back_to_entities(store):
    """D-040: a passage found by meaning names the entities whose claims cite it."""
    from loomctx.contracts import DocumentIn, Provenance
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    a = store.store_artifact(DocumentIn(namespace="ns", event_id="adv-a", text="LockBit targets nginx", source="kev", observed_at=t))
    b = store.store_artifact(DocumentIn(namespace="ns", event_id="adv-b", text="unrelated", source="kev", observed_at=t))
    cve = EntityRef(type="cve", key="CVE-2026-9")
    store.record_claims([
        ClaimIn(namespace="ns", subject=cve, predicate="exploited_in_wild", object=True, source="kev", observed_at=t,
                provenance=Provenance(artifact_event_id="adv-a")),
        ClaimIn(namespace="ns", subject=EntityRef(type="host", key="h1"), predicate="mentioned_in", object=cve,
                source="kev", observed_at=t, provenance=Provenance(artifact_event_id="adv-a")),
    ])
    got = store.subjects_citing("ns", [a.id, b.id, "nope"])
    assert got == {a.id: [cve, EntityRef(type="host", key="h1")]}
    assert store.subjects_citing("ns", [a.id], allowed_types=("cve",)) == {a.id: [cve]}   # host->cve edge hidden
    assert store.subjects_citing("ns", [a.id], allowed_types=()) == {}
    assert store.subjects_citing("ns", []) == {}
    # the per-artifact cut is applied in the query, in (type, key) order
    store.record_claims([
        ClaimIn(namespace="ns", subject=EntityRef(type="host", key=f"h{i}"), predicate="mentioned_in",
                object=cve, source="kev", observed_at=t, provenance=Provenance(artifact_event_id="adv-a"))
        for i in range(2, 9)])
    assert store.subjects_citing("ns", [a.id], per_artifact=2) == {a.id: [cve, EntityRef(type="host", key="h1")]}
    assert len(store.subjects_citing("ns", [a.id], per_artifact=100)[a.id]) == 9


def test_relation_summary_is_cached_until_the_data_changes(store):
    """describe_namespace's map is a GROUP BY over every observation (86 s at
    6.5M rows), and each MCP session is a fresh process: the store keeps it
    until a write changes what it counts (D-104)."""
    def logins() -> int:
        return sum(r[3] for r in store.relation_summary("default") if r[1] == "logged_in_by")
    obs = store.record_claim(login_claim())
    first = store.relation_summary("default")
    assert store.relation_summary("default") == first and logins() == 1
    store.record_claim(login_claim().model_copy(update={"object": EntityRef(type="user", key="other")}))
    assert logins() == 2                       # a new observation invalidates it
    store.redact("default", obs.id, "x")
    assert logins() == 1                       # so does a tombstone


def test_sqlite_checks_references_on_migration_not_every_open(tmp_path, caplog):
    """foreign_key_check walks every reference (23 s at 6.5M observations)
    and every MCP session opened the store anew: it runs when a migration
    does, which is when an old file's dangling rows can still be there."""
    import logging
    import sqlite3
    from loomctx.store.sqlite import SCHEMA_VERSION, SqliteStore
    path = str(tmp_path / "fk.db")
    SqliteStore(path).close()
    c = sqlite3.connect(path)
    c.execute("PRAGMA foreign_keys=OFF")
    c.execute("INSERT INTO aliases (namespace, alias, entity_id) VALUES ('default', 'dangling', 'nowhere')")
    c.execute("UPDATE loomctx_meta SET value = ? WHERE key = 'schema_version'", (str(SCHEMA_VERSION - 1),))
    c.commit()
    c.close()
    with caplog.at_level(logging.WARNING, logger="loomctx.store"):
        SqliteStore(path).close()                     # migrates: checked, and reported
    assert any("violate foreign keys" in r.message for r in caplog.records)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="loomctx.store"):
        SqliteStore(path).close()                     # already current: not walked again
    assert not any("violate foreign keys" in r.message for r in caplog.records)


def test_sqlite_refresh_statistics_analyzes(tmp_path):
    """The SQLite planner chose indexes blind without sqlite_stat1 (a cite
    lookup scanned 6.5M rows): a bulk load now ends with ANALYZE."""
    import sqlite3
    from loomctx.store.sqlite import SqliteStore
    s = SqliteStore(str(tmp_path / "a.db"))
    s.record_claim(login_claim())
    s.refresh_statistics()
    s.close()
    c = sqlite3.connect(str(tmp_path / "a.db"))
    assert c.execute("SELECT count(*) FROM sqlite_master WHERE name = 'sqlite_stat1'").fetchone()[0] == 1


def test_observations_by_prefix_resolves_cite_tokens(store):
    """A 12-hex token from a pack finds its observation; tombstoned rows
    and other namespaces never surface; the read is capped."""
    from loomctx.contracts import Observation
    obs = [store.record_claim(login_claim().model_copy(update={"object": EntityRef(type="user", key=f"u{i}")}))
           for i in range(3)]
    assert [o.id for o in store.observations_by_prefix("default", obs[0].id[:12])] == [obs[0].id]
    assert store.observations_by_prefix("default", obs[0].id) == store.observations_by_prefix("default", obs[0].id[:12])
    assert store.observations_by_prefix("other", obs[0].id[:12]) == []
    assert store.observations_by_prefix("default", "") == []
    store.redact("default", obs[1].id, "x")
    assert store.observations_by_prefix("default", obs[1].id[:12]) == []
    for i in range(25):   # crafted ids that share a prefix: the cap holds, LIKE metacharacters are literal
        store.restore_observation(Observation(
            id=f"tok_{i:03d}", namespace="default", subject=EntityRef(type="host", key="web-01"),
            predicate="p", object="x", observed_at=OBSERVED, recorded_at=OBSERVED, source="s", confidence=1.0))
    store.restore_observation(Observation(
        id="tokX010", namespace="default", subject=EntityRef(type="host", key="web-01"),
        predicate="p", object="x", observed_at=OBSERVED, recorded_at=OBSERVED, source="s", confidence=1.0))
    got = store.observations_by_prefix("default", "tok_")
    assert len(got) == 20 and [o.id for o in got] == sorted(o.id for o in got)
    assert [o.id for o in store.observations_by_prefix("default", "tok_01")] == [f"tok_{i:03d}" for i in range(10, 20)]
    assert [o.id for o in store.observations_by_prefix("default", "tokX")] == ["tokX010"]


def test_postgres_retries_a_lost_deadlock_then_gives_up():
    """D-043: a bulk loader lost a deadlock to a pod's open-time DDL on GKE.
    The transaction was rolled back whole and writes are idempotent, so the
    store retries it, bounded."""
    pytest.importorskip("psycopg")
    from psycopg import errors
    from loomctx.store.postgres import retry_on_deadlock
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise errors.DeadlockDetected("deadlock detected")
        return "ok"

    assert retry_on_deadlock(flaky, backoff=(0.0, 0.0, 0.0)) == "ok" and calls["n"] == 3
    calls["n"] = -10
    with pytest.raises(errors.DeadlockDetected):
        retry_on_deadlock(flaky, backoff=(0.0,))


def test_observations_for_many_matches_one_by_one(store):
    """D-043: one round trip per chunk, same answer as observations_for per
    ref — per-ref limit, newest first, self-edges once, aliases followed,
    unknown refs absent."""
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    hub, other = EntityRef(type="host", key="hub"), EntityRef(type="host", key="other")
    claims = [ClaimIn(namespace="m", subject=hub, predicate="logged_in_by", object=EntityRef(type="user", key=f"u{i}"),
                      observed_at=t.replace(hour=i), source="s") for i in range(6)]
    claims += [ClaimIn(namespace="m", subject=EntityRef(type="ip", key=f"10.0.0.{i}"), predicate="assigned_to", object=hub,
                       observed_at=t.replace(hour=10 + i), source="s") for i in range(3)]
    claims += [ClaimIn(namespace="m", subject=hub, predicate="peer_of", object=hub, observed_at=t.replace(hour=20), source="s"),
               ClaimIn(namespace="m", subject=other, predicate="runs_os", object="x", observed_at=t, source="s")]
    store.record_claims(claims)
    store.merge_entities("m", EntityRef(type="host", key="other"), hub)   # 'other' becomes an alias of hub
    many = store.observations_for_many("m", [hub, EntityRef(type="host", key="other"), EntityRef(type="host", key="nope")], limit=4)
    assert set(many) == {("host", "hub"), ("host", "other")}
    assert [o.observed_at.hour for o in many[("host", "hub")]] == [20, 12, 11, 10]
    assert many[("host", "hub")] == store.observations_for("m", hub, limit=4)
    assert many[("host", "other")][0].observed_at.hour == 20            # alias resolved to the canonical entity
    full = store.observations_for_many("m", [hub], limit=100)[("host", "hub")]
    assert len(full) == 11 and sum(1 for o in full if o.predicate == "peer_of") == 1
    assert store.observations_for_many("m", [], limit=5) == {}


def test_settled_groups_do_not_starve_merge_candidates(store):
    """D-058: a group whose every cross-type pair was declined stayed a
    candidate forever; fifty of them filled merge_candidates' limit and no
    new collision was ever offered again."""
    for key in ("a-key", "b-key", "c-key"):
        for etype in ("user", "group"):
            store.upsert_entity("ns", EntityRef(type=etype, key=key))
    store.upsert_entity("ns", EntityRef(type="role", key="c-key"))
    store.remember_decline("ns", "user:a-key", "group:a-key", "different things")
    store.remember_decline("ns", "group:b-key", "user:b-key", "different things")
    store.remember_decline("ns", "group:c-key", "user:c-key", "different things")   # role:c-key still open
    assert [g[0].key for g in store.merge_candidates("ns", limit=1)] == ["c-key"]
    assert [sorted(e.type for e in g) for g in store.merge_candidates(limit=5)] == [["group", "role", "user"]]
    store.remember_decline("ns", "role:c-key", "user:c-key", "no")
    store.remember_decline("ns", "group:c-key", "role:c-key", "no")
    assert store.merge_candidates("ns") == []


def test_settled_groups_do_not_starve_fuzzy_merge_candidates(store):
    """S-26: the same starvation in tier 2 — a normalized-key group whose
    every pair of differing raw keys was declined filled
    fuzzy_merge_candidates' limit for good."""
    for t, k in [("host", "WEB_01"), ("host", "web-01"),                    # settled below
                 ("host", "app-1"), ("asset", "app-1"), ("host", "app1"),   # settled below
                 ("host", "db-01"), ("host", "DB_01"), ("asset", "db01")]:  # one pair stays open
        store.upsert_entity("ns", EntityRef(type=t, key=k))
    # upper case sorts first by code point: the backend must compare the
    # stored pair the way Python sorted it (COLLATE "C" on Postgres)
    store.remember_decline("ns", "host:web-01", "host:WEB_01", "different boxes")
    # same-key pairs are tier 1's (host:app-1 / asset:app-1): they neither
    # keep a tier-2 group open nor are needed to settle it
    store.remember_decline("ns", "host:app1", "host:app-1", "no")
    store.remember_decline("ns", "asset:app-1", "host:app1", "no")
    store.remember_decline("ns", "host:db-01", "host:DB_01", "no")
    store.remember_decline("ns", "asset:db01", "host:db-01", "no")          # asset:db01 / host:DB_01 open
    assert [{e.key for e in g} for g in store.fuzzy_merge_candidates("ns", limit=1)] == [
        {"db-01", "DB_01", "db01"}]
    assert len(store.fuzzy_merge_candidates(limit=5)) == 1
    store.remember_decline("ns", "host:DB_01", "asset:db01", "no")
    assert store.fuzzy_merge_candidates("ns") == []
    # forgetting a decline reopens its group (S-28)
    assert store.forget_decline("ns", "host:WEB_01", "host:web-01") is True
    assert [{e.key for e in g} for g in store.fuzzy_merge_candidates("ns")] == [{"WEB_01", "web-01"}]


def test_forget_decline_is_symmetric_and_scoped(store):
    """S-28: an operator can take a decline back; either order names the
    pair, other namespaces keep theirs, and a pair never declined is a
    no-op reported as False."""
    store.remember_decline("ns", "product:b", "product:a", "different vendors")
    store.remember_decline("other", "product:a", "product:b", "different vendors")
    store.remember_decline("ns", "user:x", "group:x", "no")
    assert store.forget_decline("ns", "product:b", "product:a") is True
    assert store.declined_pairs("ns") == {("group:x", "user:x")}
    assert store.declined_pairs("other") == {("product:a", "product:b")}
    assert store.forget_decline("ns", "product:a", "product:b") is False    # already gone
    assert store.forget_decline("ns", "nope:1", "nope:2") is False
    assert [d["b"] for d in store.iter_declines("ns")] == ["user:x"]


def test_declines_are_stored_symmetrically(store):
    store.remember_decline("ns", "product:b", "product:a", "different vendors")
    assert store.declined_pairs("ns") == {("product:a", "product:b")}
    store.remember_decline("ns", "product:a", "product:b", "still no")     # idempotent
    assert len(store.declined_pairs("ns")) == 1 and store.declined_pairs("other") == set()
    assert store.schema_version() == 9


# ------------------------------------------------------- schema v5 #

def test_norm_key_keeps_the_structure_of_numeric_keys():
    """web-01 / WEB_01 / web01 still collide; IPs, CIDRs and versions do not
    (10.0.4.7, 100.4.7 and 1.0.0.47 all normalized to 10047)."""
    from loomctx.store.common import norm_key
    assert norm_key("web-01") == norm_key("WEB_01") == norm_key("web01") == "web01"
    assert len({norm_key(k) for k in ("10.0.4.7", "100.4.7", "1.0.0.47")}) == 3
    assert norm_key("10.0.4.7") == norm_key(" 10.0.4.7 ") == "10.0.4.7"
    assert norm_key("10.0.0.0/8") == "10.0.0.0/8" and norm_key("1.2.3") == "1.2.3"
    assert norm_key("10.0.4.7:443") == "10.0.4.7:443" and norm_key("2026-09-01") == "2026-09-01"
    assert norm_key("v1.2.3") == "v123"          # letters: spelling, not structure
    assert norm_key("10_0_4_7") == "10047"       # underscores are spelling


def test_norm_key_keeps_the_structure_of_hex_keys():
    """v6: IPv6 and MAC addresses — hex digits with colons — keep their
    separators; case and whitespace still fold; a colon alone is not
    enough when letters outside a-f are present (that is spelling)."""
    from loomctx.store.common import norm_key
    assert norm_key("2001:DB8::1") == norm_key(" 2001:db8::1 ") == "2001:db8::1"
    assert len({norm_key(k) for k in ("2001:db8::1", "2001:db8::10", "2001:db8:0:0:0:0:0:1", "2001:db81::")}) == 4
    assert norm_key("fe80::1%eth0") == "fe801eth0"                # a zone id is not hex: spelling rule
    assert norm_key("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert norm_key("aa-bb-cc-dd-ee-ff") == "aabbccddeeff"         # no colon: the old rule (D-049 named it)
    assert norm_key("::ffff:10.0.4.7") == "::ffff:10.0.4.7" and norm_key("2001:db8::/32") == "2001:db8::/32"
    assert norm_key("cisco:ios") == "ciscoios" and norm_key("deadbeef") == "deadbeef"


def test_fuzzy_candidates_do_not_group_distinct_ips(store):
    for key in ("10.0.4.7", "100.4.7", "1.0.0.47"):
        store.upsert_entity("default", EntityRef(type="ip", key=key))
    store.upsert_entity("default", EntityRef(type="host", key="web-01"))
    store.upsert_entity("default", EntityRef(type="host", key="web01"))
    groups = store.fuzzy_merge_candidates("default")
    assert [{e.key for e in g} for g in groups] == [{"web-01", "web01"}]


def test_v5_migration_recomputes_numeric_norm_keys(store, tmp_path):
    _raw(store)
    from loomctx.store.sqlite import SCHEMA_VERSION
    store.upsert_entity("default", EntityRef(type="ip", key="10.0.4.7"))
    store.upsert_entity("default", EntityRef(type="host", key="web-01"))
    _exec(store, "UPDATE entities SET norm_key = '10047' WHERE key = '10.0.4.7'")   # as v4 wrote it
    _exec(store, "UPDATE loomctx_meta SET value = '4' WHERE key = 'schema_version'")
    again = _reopen(store, tmp_path)
    try:
        assert again.schema_version() == SCHEMA_VERSION == 9
        rows = _exec(again, "SELECT key, norm_key FROM entities ORDER BY key")
        assert [(r["key"], r["norm_key"]) for r in rows] == [("10.0.4.7", "10.0.4.7"), ("web-01", "web01")]
    finally:
        again.close()


def test_two_processes_migrating_one_old_file_both_open(tmp_path):
    """D-058: the engine and a worker opening a pre-v6 file at once both
    saw `supersedes` missing; the second ALTER died on "duplicate column
    name". Migration now runs under BEGIN IMMEDIATE and re-reads the shape
    inside the lock, and a duplicate column is tolerated regardless."""
    import sqlite3
    import threading
    path = tmp_path / "old.db"
    SqliteStore(path).close()
    raw = sqlite3.connect(path)
    raw.execute("DROP INDEX idx_obs_supersedes")
    raw.execute("ALTER TABLE observations DROP COLUMN supersedes")
    raw.execute("UPDATE loomctx_meta SET value = '5' WHERE key = 'schema_version'")
    raw.commit()
    raw.close()
    barrier, opened, errors = threading.Barrier(4), [], []

    def open_it():
        barrier.wait()
        try:
            opened.append(SqliteStore(path))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=open_it) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and len(opened) == 4
    assert all(s.schema_version() == 9 for s in opened)
    for s in opened:
        s.close()
    # the losing side of a race that slipped past the check: tolerated
    s = SqliteStore(path)
    try:
        s._missing_columns = lambda: [("observations", "supersedes", "TEXT")]
        s._migrate_locked()
    finally:
        s.close()


def test_schema_version_is_never_written_down(store, tmp_path, caplog):
    """An older image opening a newer database serves what it understands,
    runs no DDL, warns — and leaves the version alone (H-B12)."""
    _raw(store)
    from loomctx.store.sqlite import SCHEMA_VERSION
    _exec(store, "UPDATE loomctx_meta SET value = ? WHERE key = 'schema_version'", (str(SCHEMA_VERSION + 1),))
    try:
        with caplog.at_level("WARNING", logger="loomctx.store"):
            newer = _reopen(store, tmp_path)
        try:
            assert newer.schema_version() == SCHEMA_VERSION + 1
            assert "newer than this build" in caplog.text
            newer.record_claim(login_claim())
            assert len(newer.observations_for("default", EntityRef(type="host", key="web-01"))) == 1
        finally:
            newer.close()
    finally:
        _exec(store, "UPDATE loomctx_meta SET value = ? WHERE key = 'schema_version'", (str(SCHEMA_VERSION),))
    assert store.schema_version() == SCHEMA_VERSION


def test_search_entities_uses_the_lower_key_index(store):
    _raw(store)
    for key in ("web-01", "Web-02", "db-01"):
        store.upsert_entity("default", EntityRef(type="host", key=key))
    assert {e.key for e in store.search_entities("default", "WEB")} == {"web-01", "Web-02"}
    assert [e.key for e in store.search_entities("default", "web-02")] == ["Web-02"]
    assert store.search_entities("default", "") != []           # empty prefix: everything
    if isinstance(store, SqliteStore):
        from loomctx.store import sqlite as sq
        plan = _exec(store, "EXPLAIN QUERY PLAN " + sq._SEARCH_SQL, ("default", "web", "web" + sq._PREFIX_END))
        assert any("idx_entity_lower_key" in r["detail"] for r in plan), plan
    else:
        from loomctx.store import postgres as pg
        assert _exec(store, "SELECT 1 FROM pg_indexes WHERE indexname = 'idx_entity_lower_key'")
        # enough rows and fresh statistics that the planner has a real
        # choice: on a 3-row table with no stats every (namespace, ...)
        # index costs the same and any of them may be picked
        _exec(store, "INSERT INTO entities (id, namespace, type, key, created_at, norm_key)"
                     " SELECT md5(i::text), 'default', 'host', 'k' || i, '2026-01-01T00:00:00+00:00', 'k' || i"
                     " FROM generate_series(1, 500) i")
        _exec(store, "ANALYZE entities")
        with store._tx():   # one transaction: the planner hint and the EXPLAIN share a connection
            store._x("SET LOCAL enable_seqscan = off")
            plan = store._q("EXPLAIN " + pg._SEARCH_SQL, ("default", "web", "web" + pg._PREFIX_END))
        assert any("idx_entity_lower_key" in r["QUERY PLAN"] for r in plan), plan


def test_wipe_clears_declines_and_the_merge_log(store):
    store.remember_decline("ns", "a:1", "b:2", "no")
    a, b = EntityRef(type="ip", key="1.1.1.1"), EntityRef(type="ip_address", key="1.1.1.1")
    for ref in (a, b):
        store.record_claim(ClaimIn(subject=ref, predicate="p", object="x", observed_at=OBSERVED, source="s"))
    assert store.merge_entities("default", b, a) and list(store.iter_merges())
    store.wipe()
    assert store.declined_pairs("ns") == set()
    assert list(store.iter_merges()) == [] and store.unmerge("default", b) is False


# --------------------------------------------- reversible merges (D-019, v5) #

def _snapshot(store, ns, ref):
    return sorted((o.id, o.subject, o.predicate, o.object) for o in store.observations_for(ns, ref, limit=100))


def test_unmerge_restores_both_entities_exactly(store):
    """merge, claim, unmerge: the folded entity is back with exactly the
    observations it had (both as subject and as object, object refs
    rendered as before), the canonical keeps only what was its own plus
    what arrived after the merge, the alias is gone, briefs are dropped."""
    a, b = EntityRef(type="ip_address", key="10.0.4.7"), EntityRef(type="ip", key="10.0.4.7")
    host = EntityRef(type="host", key="web-01")
    store.record_claims([
        ClaimIn(subject=a, predicate="mentioned_in", object="IR-4432", observed_at=OBSERVED, source="doc"),
        ClaimIn(subject=host, predicate="uses_ip", object=a, observed_at=OBSERVED, source="doc"),
        ClaimIn(subject=a, predicate="peer_of", object=a, observed_at=OBSERVED, source="doc"),
        ClaimIn(subject=b, predicate="assigned_to", object=host, observed_at=OBSERVED, source="dhcp"),
    ])
    before_a, before_b = _snapshot(store, "default", a), _snapshot(store, "default", b)
    a_id = store.get_entity("default", a).id
    store.add_alias("default", EntityRef(type="ipaddr", key="10.0.4.7"), into=a)   # an alias that names a
    store.put_dossier("default", a, "brief a", 3, [])
    assert store.merge_entities("default", a, b)
    assert len(store.observations_for("default", b, limit=100)) == 4
    later = store.record_claim(ClaimIn(subject=b, predicate="scanned", object="clean",
                                       observed_at=OBSERVED, source="scanner"))
    store.put_dossier("default", b, "merged brief", 5, [])
    assert [m["from"] for m in store.iter_merges("default")] == [{"type": "ip_address", "key": "10.0.4.7"}]

    assert store.unmerge("default", a) is True
    assert _snapshot(store, "default", a) == before_a
    assert _snapshot(store, "default", b) == sorted(before_b + [(later.id, b, "scanned", "clean")])
    restored = store.get_entity("default", a)
    assert restored.type == "ip_address" and restored.id == a_id         # its own node, its own id
    assert store.get_entity("default", EntityRef(type="ipaddr", key="10.0.4.7")).id == a_id   # alias followed it back
    assert [al["alias"] for al in store.iter_aliases("default")] == ["ipaddr:10.0.4.7"]         # the merge's alias is gone
    assert store.get_dossier("default", a) is None and store.get_dossier("default", b) is None
    assert list(store.iter_merges("default")) == []
    assert store.unmerge("default", a) is False                          # nothing left to reverse
    # and the pair can be merged again, reversibly
    assert store.merge_entities("default", a, b) and store.unmerge("default", a)
    assert _snapshot(store, "default", a) == before_a


def test_unmerge_after_a_chained_merge(store):
    """A folded into B, then B into C: unmerging A takes back exactly A's
    observations from C; B stays an alias of C."""
    a, b, c = (EntityRef(type="ip_address", key="1.1.1.1"), EntityRef(type="ip", key="1.1.1.1"),
               EntityRef(type="ipv4", key="1.1.1.1"))
    for ref in (a, b, c):
        store.record_claim(ClaimIn(subject=ref, predicate=f"from_{ref.type}", object="x",
                                   observed_at=OBSERVED, source="s"))
    before_a = _snapshot(store, "default", a)
    assert store.merge_entities("default", a, b) and store.merge_entities("default", b, c)
    assert len(store.observations_for("default", c)) == 3
    assert store.unmerge("default", a)
    assert _snapshot(store, "default", a) == before_a
    assert {o.predicate for o in store.observations_for("default", c)} == {"from_ip", "from_ipv4"}
    assert store.get_entity("default", b).type == "ipv4"                # B is still folded into C
    assert store.unmerge("default", b)
    assert {o.predicate for o in store.observations_for("default", b)} == {"from_ip"}
    assert {o.predicate for o in store.observations_for("default", c)} == {"from_ipv4"}


def test_export_import_round_trips_schemas_declines_and_merges(store, tmp_path):
    """A restore is only faithful if the registries, the adjudication
    memory and the merge log come along — and a merge stays reversible
    on the restored store."""
    import io
    from loomctx.contracts import EntityTypeDef, PredicateDef, SchemaRegistration
    from loomctx.lifecycle import export_jsonl, import_jsonl
    store.put_schema(SchemaRegistration(namespace="netsec", strict=True,
                                        entity_types=[EntityTypeDef(name="host")],
                                        predicates=[PredicateDef(name="runs_os")]))
    store.remember_decline("netsec", "product:b", "product:a", "different vendors",
                           decided_at=datetime(2026, 9, 2, tzinfo=timezone.utc))
    a, b = EntityRef(type="ip_address", key="10.0.4.7"), EntityRef(type="ip", key="10.0.4.7")
    store.record_claims([
        ClaimIn(namespace="netsec", subject=a, predicate="noted", object="x", observed_at=OBSERVED, source="doc"),
        ClaimIn(namespace="netsec", subject=EntityRef(type="host", key="h"), predicate="uses", object=a,
                observed_at=OBSERVED, source="doc"),
        ClaimIn(namespace="netsec", subject=b, predicate="assigned", object="y", observed_at=OBSERVED, source="dhcp"),
    ])
    before_a = _snapshot(store, "netsec", a)
    assert store.merge_entities("netsec", a, b)
    buf = io.StringIO()
    counts = export_jsonl(store, buf, None)
    assert counts["schemas"] == 1 and counts["declines"] == 1 and counts["merges"] == 1
    kinds = [json.loads(l)["type"] for l in buf.getvalue().splitlines()]
    assert kinds.index("merge") > kinds.index("alias") > kinds.index("observation")

    dst = SqliteStore(tmp_path / "restored.db")
    try:
        buf.seek(0)
        got = import_jsonl(dst, buf)
        assert got["schemas"] == 1 and got["declines"] == 1 and got["merges"] == 1 and got["skipped"] == 0
        assert dst.get_schema("netsec") == store.get_schema("netsec")
        assert dst.declined_pairs("netsec") == {("product:a", "product:b")}
        assert next(dst.iter_declines("netsec"))["decided_at"] == "2026-09-02T00:00:00+00:00"
        assert [m["from"] for m in dst.iter_merges("netsec")] == [{"type": "ip_address", "key": "10.0.4.7"}]
        buf.seek(0)
        assert import_jsonl(dst, buf)["merges"] == 1 and len(list(dst.iter_merges())) == 1   # idempotent
        assert dst.unmerge("netsec", a)                                  # reversible after the restore
        assert _snapshot(dst, "netsec", a) == before_a
        assert {o.predicate for o in dst.observations_for("netsec", b)} == {"assigned"}
    finally:
        dst.close()


def test_sqlite_transactions_are_reentrant(store):
    """A public method that calls another public method must not deadlock
    on the store's own lock, and the inner call must not commit the outer
    transaction half-way: the outermost `_tx` is the only one that commits
    or rolls back."""
    if not isinstance(store, SqliteStore):
        pytest.skip("SQLite-internal")
    with store._tx():
        store.record_claim(login_claim())            # nested public call: no deadlock
        with pytest.raises(RuntimeError):
            with store._tx():
                store.record_claim(login_claim(namespace="inner"))
                raise RuntimeError("inner failure")
    # the outer block exited cleanly (the exception was caught inside it),
    # so everything it wrote — including the inner block's row — committed
    assert len(store.observations_for("default", EntityRef(type="host", key="web-01"))) == 1
    assert len(store.observations_for("inner", EntityRef(type="host", key="web-01"))) == 1
    with pytest.raises(RuntimeError):
        with store._tx():
            store.record_claim(login_claim(namespace="lost"))
            raise RuntimeError("outer failure")
    assert store.observations_for("lost", EntityRef(type="host", key="web-01")) == []


# ------------------------------------------------------- schema v6 #

def test_supersedes_is_recorded_and_round_trips(store, tmp_path):
    """D-050: a claim may name the observation it corrects. The edge is
    stored, served on every read path, carried by export/import, and
    `superseded_ids` reports exactly the rows a visible later observation
    names — a redacted superseder no longer counts, an unknown target is
    a dangling pointer, not an error."""
    import io
    from loomctx.lifecycle import export_jsonl, import_jsonl
    host = EntityRef(type="host", key="web-01")
    old = store.record_claim(login_claim().model_copy(update={"predicate": "runs_os", "object": "fedora-43"}))
    assert old.supersedes is None
    new = store.record_claim(login_claim().model_copy(update={
        "predicate": "runs_os", "object": "fedora-44", "supersedes": old.id, "event_id": "evt-sup"}))
    assert new.supersedes == old.id
    by_read = {o.id: o for o in store.observations_for("default", host)}
    assert by_read[new.id].supersedes == old.id and by_read[old.id].supersedes is None
    many = {o.id: o for o in store.observations_for_many("default", [host])[("host", "web-01")]}
    assert many[new.id].supersedes == old.id
    assert store.observations_by_ids("default", [new.id])[0].supersedes == old.id
    replay = store.record_claim(login_claim().model_copy(update={
        "predicate": "runs_os", "object": "fedora-44", "supersedes": old.id, "event_id": "evt-sup"}))
    assert replay.id == new.id and replay.supersedes == old.id            # the dedupe path carries it too
    assert store.superseded_ids("default", [old.id, new.id, "nope"]) == {old.id}
    assert store.superseded_ids("other", [old.id]) == set()               # namespace-scoped
    assert store.superseded_ids("default", []) == set()
    dangling = store.record_claim(login_claim().model_copy(update={
        "predicate": "runs_os", "object": "fedora-45", "supersedes": "0" * 32}))
    assert dangling.supersedes == "0" * 32 and store.superseded_ids("default", ["0" * 32]) == {"0" * 32}

    buf = io.StringIO()
    export_jsonl(store, buf, "default")
    assert any(json.loads(l)["data"].get("supersedes") == old.id for l in buf.getvalue().splitlines())
    dst = SqliteStore(tmp_path / "restored-sup.db")
    try:
        buf.seek(0)
        import_jsonl(dst, buf)
        restored = {o.id: o for o in dst.iter_observations("default")}
        assert restored[new.id].supersedes == old.id
        assert dst.superseded_ids("default", [old.id]) == {old.id}
    finally:
        dst.close()

    store.redact("default", new.id, "wrong correction")
    assert store.superseded_ids("default", [old.id]) == set()             # only a visible superseder counts


def test_v6_migration_adds_supersedes_to_an_existing_database(store, tmp_path):
    """A v5 file gains the column, its index and the version bump on open;
    rows written before the column carry no supersession; norm_key is
    recomputed for the keys the hex rule changes (those carrying ':')."""
    _raw(store)
    from loomctx.store.sqlite import SCHEMA_VERSION
    before = store.record_claim(login_claim())
    store.upsert_entity("default", EntityRef(type="ip", key="2001:db8::1"))
    store.upsert_entity("default", EntityRef(type="mac", key="AA:BB:CC:DD:EE:FF"))
    _exec(store, "UPDATE entities SET norm_key = '2001db81' WHERE key = '2001:db8::1'")          # as v5 wrote them
    _exec(store, "UPDATE entities SET norm_key = 'aabbccddeeff' WHERE key = 'AA:BB:CC:DD:EE:FF'")
    _exec(store, "DROP INDEX idx_obs_supersedes")
    _exec(store, "ALTER TABLE observations DROP COLUMN supersedes")
    _exec(store, "UPDATE loomctx_meta SET value = '5' WHERE key = 'schema_version'")
    again = _reopen(store, tmp_path)
    try:
        assert again.schema_version() == SCHEMA_VERSION == 9
        rows = _exec(again, "SELECT key, norm_key FROM entities WHERE key <> 'web-01' AND key <> 'jdoe' ORDER BY key")
        assert [(r["key"], r["norm_key"]) for r in rows] == [
            ("2001:db8::1", "2001:db8::1"), ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff")]
        obs = again.observations_for("default", EntityRef(type="host", key="web-01"))
        assert [o.id for o in obs] == [before.id] and obs[0].supersedes is None
        later = again.record_claim(login_claim().model_copy(update={"supersedes": before.id}))
        assert again.superseded_ids("default", [before.id]) == {before.id} and later.supersedes == before.id
        if isinstance(again, SqliteStore):
            plan = _exec(again, "EXPLAIN QUERY PLAN SELECT supersedes FROM observations o"
                                " WHERE o.namespace = ? AND o.supersedes IN (?, ?)", ("default", "a", "b"))
            assert any("idx_obs_supersedes" in r["detail"] for r in plan), plan
        else:
            assert _exec(again, "SELECT 1 FROM pg_indexes WHERE indexname = 'idx_obs_supersedes'")
    finally:
        again.close()


# ------------------------------------------- worker tick scans (R-9) #

def _meta(store, key):
    rows = _exec(store, "SELECT value FROM loomctx_meta WHERE key = ?", (key,))
    return rows[0]["value"] if rows else None


def _examined(store, table, mark):
    """Rows a tick walks: the recorded_at range from the mark (the query's
    only non-anti-join predicate, served by the recorded_at index)."""
    return _exec(store, f"SELECT COUNT(*) AS n FROM {table} WHERE recorded_at >= ?", (mark,))[0]["n"]


def test_embedding_backlog_scans_from_a_high_water_mark(store, tmp_path):
    """A tick examines the rows recorded since the previous tick plus the
    slack window — not the whole table — and a backfilled row below the
    mark (an import with an old recorded_at) is found by the periodic
    rescan within `_RESCAN_EVERY` ticks."""
    _raw(store)
    from loomctx.contracts import Observation
    store._HWM_SLACK, store._RESCAN_EVERY = 2, 3
    ids = [store.record_claim(login_claim().model_copy(
        update={"object": EntityRef(type="user", key=f"u{i}")})).id for i in range(12)]

    def tick(limit=5):
        got = store.observations_without_embeddings("m", limit)
        store.put_embeddings("default", "m", [(o.id, [1.0, 0.0]) for o in got])
        return [o.id for o in got]

    assert tick() == ids[:5]                    # the first tick of a process scans from the start
    assert tick() == ids[5:10]                  # then from the mark
    assert tick() == ids[10:]
    mark = _meta(store, "hwm:embed:m:0/1")
    assert mark is not None
    assert 0 < _examined(store, "observations", mark) <= store._HWM_SLACK + 5 < len(ids)
    if isinstance(store, SqliteStore):
        from loomctx.store import sqlite as sq
        plan = _exec(store, "EXPLAIN QUERY PLAN " + sq._EMBED_BACKLOG_SQL.format(shard=""), (mark, "m", 5))
        assert any("idx_obs_recorded" in r["detail"] for r in plan), plan
    assert tick() == []                         # tick 4: the periodic rescan, nothing pending
    old = Observation(id=uuid_hex(), namespace="default", subject=EntityRef(type="host", key="web-01"),
                      predicate="p", object="x", observed_at=OBSERVED, source="s", confidence=1.0,
                      recorded_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    store.restore_observation(old)              # a backfill lands far below the mark
    assert old.recorded_at.isoformat() < _meta(store, "hwm:embed:m:0/1")
    assert tick() == [] and tick() == []        # incremental ticks do not see it ...
    assert tick() == [old.id]                   # ... the rescan does
    store.wipe()
    assert _meta(store, "hwm:embed:m:0/1") is None


def uuid_hex():
    import uuid
    return uuid.uuid4().hex


def test_chunk_backlog_scans_from_a_high_water_mark(store, tmp_path):
    from loomctx.contracts import Artifact, DocumentIn
    _raw(store)
    store._HWM_SLACK, store._RESCAN_EVERY = 1, 3
    ids = [store.store_artifact(DocumentIn(text=f"doc {i}", source="s", observed_at=OBSERVED)).id
           for i in range(6)]

    def tick(limit=2, lease=None):
        got = store.artifacts_needing_chunks("m", limit, lease=lease)
        for a in got:
            store.put_doc_chunks("default", a.id, "m", [(0, 0, 3, "doc", [1.0, 0.0])],
                                 worker_id=lease[0] if lease else None)
        return [a.id for a in got]

    assert tick() == ids[:2]
    assert tick(lease=("w", 60)) == ids[2:4]
    assert tick() == ids[4:]
    mark = _meta(store, "hwm:chunks:m")
    assert 0 < _examined(store, "artifacts", mark) <= store._HWM_SLACK + 2 < len(ids)
    assert tick() == []
    old = Artifact(id=uuid_hex(), namespace="default", content_type="text/plain", text="late import",
                   source="s", observed_at=OBSERVED, recorded_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    store.restore_artifact(old)
    assert tick() == [] and tick() == []
    assert tick() == [old.id]


def test_dossier_candidates_are_incremental(store, tmp_path):
    """Only entities with a row since the mark — or holding a lease — are
    evaluated; a failed build (lease lapses without put_dossier) is
    re-offered, and a dropped brief (redact, merge) resets the mark so the
    rebuild does not wait for the periodic rescan."""
    _raw(store)
    store._HWM_SLACK, store._RESCAN_EVERY = 0, 100
    host, other = EntityRef(type="host", key="web-01"), EntityRef(type="host", key="db-01")
    for i in range(4):
        store.record_claim(login_claim().model_copy(update={"object": EntityRef(type="user", key=f"u{i}")}))
    store.record_claim(login_claim().model_copy(update={"predicate": "runs_os", "object": "fedora-44"}))
    cands = store.dossier_candidates(min_new=3, min_total=5, lease=("w", 60))
    assert [(c[1], c[2]) for c in cands] == [(host, 5)]
    store.put_dossier("default", host, "brief", 5, [], worker_id="w")
    assert store.dossier_candidates(min_new=3, min_total=5, lease=("w", 60)) == []
    mark = _meta(store, "hwm:dossier")
    assert mark is not None and _examined(store, "observations", mark) == 1
    if isinstance(store, SqliteStore):
        from loomctx.store import sqlite as sq
        plan = _exec(store, "EXPLAIN QUERY PLAN " + sq._DOSSIER_SQL, (mark, "2099", 5, 3, 4))
        assert any("idx_obs_subject_recorded" in r["detail"] for r in plan), plan
    for i in range(3):                                   # three NEW rows: stale again
        store.record_claim(login_claim().model_copy(update={"object": EntityRef(type="user", key=f"n{i}")}))
    cands = store.dossier_candidates(min_new=3, min_total=5, lease=("w", 0))   # a lease that lapses at once
    assert [(c[1], c[2]) for c in cands] == [(host, 8)]
    # the build fails (no put_dossier). Another entity's row, and a tick that
    # offers host again through its newest row, move the mark past every row
    # of host ...
    store.record_claim(login_claim().model_copy(update={"subject": other, "object": "x", "predicate": "runs_os"}))
    assert store.dossier_candidates(min_new=3, min_total=5, lease=("w", 0)) == [("default", host, 8)]
    mark = _meta(store, "hwm:dossier")
    assert _examined(store, "observations", mark) == 1                       # only the other entity's row is at the mark
    # ... yet it is re-offered: its lapsed lease keeps it in the touched set
    assert store.dossier_candidates(min_new=3, min_total=5, lease=("w", 60)) == [("default", host, 8)]
    store.put_dossier("default", host, "brief 2", 8, [], worker_id="w")
    assert store.dossier_candidates(min_new=3, min_total=5) == []
    assert _meta(store, "hwm:dossier") is not None
    victim = store.observations_for("default", host, limit=1)[0]
    store.redact("default", victim.id, "spill")           # drops no brief here, still resets the mark
    assert _meta(store, "hwm:dossier") is None
    store.dossier_candidates(min_new=3, min_total=5)
    assert _meta(store, "hwm:dossier") is not None
    assert store.merge_entities("default", other, host)
    assert _meta(store, "hwm:dossier") is None            # both briefs dropped: rebuild next tick
    assert [c[1] for c in store.dossier_candidates(min_new=3, min_total=5)] == [host]


# ------------------------------------ per-entity pre-limit in the gather (R-9) #

def _backend(store, namespace):
    return store.shard_for(namespace) if hasattr(store, "shard_for") else store


def test_observations_for_many_prelimits_each_entity(store):
    """The batched gather takes each entity's newest `limit` rows of each
    side from an index range with its own LIMIT, so a hub contributes at
    most 2·limit rows to the per-entity trim instead of every edge — and
    the answer is exactly what per-ref observations_for gives, with and
    without an as_of bound."""
    from datetime import timedelta
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    hub = EntityRef(type="host", key="hub")
    claims = [ClaimIn(namespace="m", subject=hub, predicate="logged_in_by", object=EntityRef(type="user", key=f"u{i}"),
                      observed_at=t + timedelta(minutes=i), source="s") for i in range(300)]
    claims += [ClaimIn(namespace="m", subject=EntityRef(type="ip", key=f"10.0.0.{i}"), predicate="assigned_to", object=hub,
                       observed_at=t + timedelta(minutes=500 + i), source="s") for i in range(50)]
    claims += [ClaimIn(namespace="m", subject=EntityRef(type="host", key=f"leaf{i}"), predicate="runs_os", object=f"os{i}",
                       observed_at=t + timedelta(minutes=i), source="s") for i in range(20)]
    claims.append(ClaimIn(namespace="m", subject=hub, predicate="peer_of", object=hub, observed_at=t + timedelta(minutes=700), source="s"))
    store.record_claims(claims)
    refs = ([hub] + [EntityRef(type="host", key=f"leaf{i}") for i in range(20)]
            + [EntityRef(type="user", key="u7"), EntityRef(type="ip", key="10.0.0.3"), EntityRef(type="host", key="nope")])
    for limit, before in ((10, None), (25, t + timedelta(minutes=250)), (400, None), (3, t + timedelta(minutes=520))):
        many = store.observations_for_many("m", refs, limit=limit, observed_before=before)
        assert ("host", "nope") not in many and set(many) <= {(r.type, r.key) for r in refs}
        for r in refs:   # a ref with nothing visible as of `before` is absent, like an unknown one
            one = store.observations_for("m", r, limit=limit, observed_before=before)
            assert [o.id for o in many.get((r.type, r.key), [])] == [o.id for o in one], (r, limit, before)
    assert set(store.observations_for_many("m", refs, limit=10)) == {(r.type, r.key) for r in refs if r.key != "nope"}
    # cost: what the gather materializes before the per-entity trim
    b = _backend(store, "m")
    with b._tx():
        ids = list(b._resolve_many("m", refs))
        hits, params = b._many_query("m", ids, 10, None)
        n = _exec(b, "WITH hits AS (" + hits + ") SELECT COUNT(*) AS n FROM hits", params)[0]["n"]
    assert len(ids) == 23 and n <= 2 * 10 * len(ids) and n < 351     # the hub alone has 351 rows
    if isinstance(b, SqliteStore):
        plan = _exec(b, "EXPLAIN QUERY PLAN WITH hits AS (" + hits + ") SELECT COUNT(*) AS n FROM hits", params)
        details = " | ".join(r["detail"] for r in plan)
        assert "idx_obs_subject" in details and "idx_obs_object" in details and "SCAN o" not in details, details


# ---------------------------------------------- iter_entities(since=) (R-9) #

def test_iter_entities_since_is_incremental(store):
    """The alias scan can ask for the entities created since its last pass
    instead of the whole namespace; the bound is inclusive and rides the
    (namespace, created_at) index."""
    from datetime import timedelta
    a = store.upsert_entity("default", EntityRef(type="host", key="a"))
    b = store.upsert_entity("default", EntityRef(type="host", key="b"))
    store.upsert_entity("team-b", EntityRef(type="host", key="elsewhere"))
    assert [e.key for e in store.iter_entities("default", since=b.created_at)] == ["b"]
    assert [e.key for e in store.iter_entities("default", since=a.created_at)] == ["a", "b"]
    assert list(store.iter_entities("default", since=b.created_at + timedelta(seconds=1))) == []
    assert {e.key for e in store.iter_entities(None, since=a.created_at)} == {"a", "b", "elsewhere"}
    assert [e.key for e in store.iter_entities("default")] == ["a", "b"]          # unchanged default
    b_ = _backend(store, "default")
    if isinstance(b_, SqliteStore):
        plan = _exec(b_, "EXPLAIN QUERY PLAN SELECT * FROM entities WHERE 1=1 AND namespace = ? AND created_at >= ?"
                         " AND (created_at, id) > (?, ?) ORDER BY created_at, id LIMIT ?", ("default", "2026", "", "", 10))
        assert any("idx_entity_created" in r["detail"] for r in plan), plan


# ------------------------------------------------ SQLite readers (R-9) #

def test_sqlite_reads_use_pooled_readers(tmp_path):
    """WAL serves readers beside the writer, so the read-only methods
    borrow pooled read connections instead of queueing on the writer's
    lock: N threads reading at once get identical answers with no
    'database is locked'; a reader sees only committed state while a read
    inside the writer's own transaction sees its uncommitted rows; a store
    with no readers answers identically."""
    import threading
    store = SqliteStore(tmp_path / "r.db", readers=3)
    assert len(store._readers) == 3
    keys = [f"h{i}" for i in range(40)]
    store.record_claims([login_claim().model_copy(update={
        "subject": EntityRef(type="host", key=k), "object": EntityRef(type="user", key=f"u{i % 5}"),
        "observed_at": OBSERVED.replace(minute=i % 60)}) for i, k in enumerate(keys * 3)])
    expected = {k: [o.id for o in store.observations_for("default", EntityRef(type="host", key=k))] for k in keys}
    assert all(len(v) == 3 for v in expected.values())
    errors: list[Exception] = []

    def reader(n):
        try:
            for i in range(150):
                k = keys[(n * 7 + i) % len(keys)]
                got = [o.id for o in store.observations_for("default", EntityRef(type="host", key=k))]
                assert got == expected[k]
                assert store.count_observations("default", EntityRef(type="host", key=k)) == 3
                assert store.search_entities("default", k)[0].key == k
                assert set(store.observations_for_many("default", [EntityRef(type="host", key=k)])) == {("host", k)}
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert store._reader_pool.qsize() == 3                     # every reader came back
    host = EntityRef(type="host", key="web-01")
    with store._tx():
        store.record_claim(login_claim(namespace="inner"))
        assert len(store.observations_for("inner", host)) == 1       # same thread: joins the write
        seen: list[int] = []
        t = threading.Thread(target=lambda: seen.append(len(store.observations_for("inner", host))))
        t.start()
        t.join()
        assert seen == [0]                                            # another thread: committed state only
    assert len(store.observations_for("inner", host)) == 1 and store.ping()
    assert [e.key for e in store.iter_entities("inner")] == ["web-01", "jdoe"]
    store.close()
    plain = SqliteStore(tmp_path / "r.db", readers=0)
    try:
        assert plain._reader_pool is None
        assert {k: [o.id for o in plain.observations_for("default", EntityRef(type="host", key=k))]
                for k in keys} == expected
    finally:
        plain.close()


# ------------------------- predicate filter and hub completion (D-061) #

def test_observations_for_many_filters_by_predicate(store):
    """`predicates` keeps only rows on those predicates, on both sides,
    applied before the per-entity limit — the newest `limit` rows *of
    them*, under the as_of bound — so a hub's edges past its gather window
    come back in one bounded read."""
    from datetime import timedelta
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    hub = EntityRef(type="product", key="kernel")
    claims = [ClaimIn(namespace="m", subject=EntityRef(type="cve", key=f"c{i}"), predicate="affects",
                      object=hub, observed_at=t + timedelta(minutes=i), source="s") for i in range(30)]
    claims += [ClaimIn(namespace="m", subject=hub, predicate="made_by", object=EntityRef(type="vendor", key="v"),
                       observed_at=t + timedelta(minutes=100), source="s")]
    claims += [ClaimIn(namespace="m", subject=EntityRef(type="cve", key=f"c{i}"), predicate="exploited_in_wild",
                       object=True, observed_at=t + timedelta(minutes=200 + i), source="k") for i in (2, 5)]
    store.record_claims(claims)
    cves = [EntityRef(type="cve", key=f"c{i}") for i in range(30)]
    edges = store.observations_for_many("m", [hub], limit=10, predicates=["affects"])[("product", "kernel")]
    assert [o.subject.key for o in edges] == [f"c{i}" for i in range(29, 19, -1)]      # the newest 10 edges
    both = store.observations_for_many("m", [hub], limit=100, predicates=["affects", "made_by"])
    assert len(both[("product", "kernel")]) == 31
    before = store.observations_for_many("m", [hub], limit=100, observed_before=t + timedelta(minutes=4),
                                         predicates=["affects"])[("product", "kernel")]
    assert [o.subject.key for o in before] == ["c4", "c3", "c2", "c1", "c0"]
    probe = store.observations_for_many("m", cves, limit=2, predicates=["exploited_in_wild"])
    assert set(probe) == {("cve", "c2"), ("cve", "c5")}                  # nothing matched: absent
    assert all(o.predicate == "exploited_in_wild" for rows in probe.values() for o in rows)
    assert store.observations_for_many("m", cves, limit=2, predicates=[]) == {}


def test_relation_summary_counts_how_types_connect(store):
    """D-064: (subject type, predicate, object type or None for a value,
    visible rows), most frequent first — describe_namespace's links and
    attributes. Tombstoned rows and other namespaces do not count; the
    default implementation agrees with the backend's query."""
    from loomctx.store.base import GraphStore
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    host, product = EntityRef(type="host", key="h1"), EntityRef(type="product", key="p1")
    rows = store.record_claims([
        ClaimIn(namespace="rel", subject=host, predicate="runs_software", object=product, observed_at=t,
                source="inv"),
        *[ClaimIn(namespace="rel", subject=EntityRef(type="cve", key=f"c{i}"), predicate="affects",
                  object=product, observed_at=t, source="nvd") for i in range(3)],
        ClaimIn(namespace="rel", subject=EntityRef(type="cve", key="c0"), predicate="exploited_in_wild",
                object=True, observed_at=t, source="kev"),
        ClaimIn(namespace="rel", subject=host, predicate="runs_os", object="linux", observed_at=t, source="inv"),
        ClaimIn(namespace="other", subject=host, predicate="runs_os", object="bsd", observed_at=t, source="inv"),
    ])
    store.redact("rel", rows[-2].id, "test")
    expected = [("cve", "affects", "product", 3), ("cve", "exploited_in_wild", None, 1),
                ("host", "runs_software", "product", 1)]
    assert store.relation_summary("rel") == expected
    assert GraphStore.relation_summary(store, "rel") == expected
    assert store.relation_summary("nowhere") == []


def test_edges_to_carriers_joins_a_hubs_edges_to_the_far_attribute(store):
    """(hub, edge, attribute) for the hub's edges on `via` — either
    direction — whose far end is the subject of a row on `predicates`,
    newest edge first, within the edge limit and the as_of bound; redacted
    rows on either side drop out; the base implementation answers the same."""
    from datetime import timedelta
    from loomctx.store.base import GraphStore
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    hub = EntityRef(type="product", key="kernel")
    claims = [ClaimIn(namespace="m", subject=EntityRef(type="cve", key=f"c{i}"), predicate="affects",
                      object=hub, observed_at=t + timedelta(minutes=i), source="s") for i in range(10)]
    claims.append(ClaimIn(namespace="m", subject=hub, predicate="bundles", object=EntityRef(type="lib", key="zlib"),
                          observed_at=t + timedelta(minutes=20), source="s"))
    claims += [ClaimIn(namespace="m", subject=EntityRef(type="cve", key=f"c{i}"), predicate="exploited_in_wild",
                       object=True, observed_at=t + timedelta(minutes=30 + i), source="k") for i in (1, 4, 8)]
    claims.append(ClaimIn(namespace="m", subject=EntityRef(type="lib", key="zlib"), predicate="exploited_in_wild",
                          object=True, observed_at=t + timedelta(minutes=40), source="k"))
    claims.append(ClaimIn(namespace="m", subject=EntityRef(type="user", key="x"), predicate="exploited_in_wild",
                          object=EntityRef(type="cve", key="c2"), observed_at=t, source="k"))   # c2 is its object
    rows = store.record_claims(claims)
    by = {(o.subject.key, o.predicate): o.id for o in rows}

    def pairs(s, **kw):
        return [(e, a) for _, e, a in s.edges_to_carriers("m", [hub], ["affects", "bundles"],
                                                         ["exploited_in_wild"], **kw)]
    expected = [(by[("kernel", "bundles")], by[("zlib", "exploited_in_wild")])] + [
        (by[(f"c{i}", "affects")], by[(f"c{i}", "exploited_in_wild")]) for i in (8, 4, 1)]
    assert pairs(store) == expected
    assert pairs(store, limit=3) == expected[:2]            # the newest 3 edges of each side only
    assert pairs(store, observed_before=t + timedelta(minutes=31)) == [
        (by[("c1", "affects")], by[("c1", "exploited_in_wild")])]
    assert GraphStore.edges_to_carriers(store, "m", [hub], ["affects", "bundles"], ["exploited_in_wild"]) \
        == store.edges_to_carriers("m", [hub], ["affects", "bundles"], ["exploited_in_wild"])
    store.redact("m", by[("c4", "exploited_in_wild")], "test")
    store.redact("m", by[("c8", "affects")], "test")
    assert pairs(store) == [expected[0], expected[3]]
    assert store.edges_to_carriers("m", [hub], ["affects"], []) == []
    b = _backend(store, "m")
    if isinstance(b, SqliteStore):   # the hub's edges outside, index probes inside — never a table scan
        with b._tx():
            eid = list(b._resolve_many("m", [hub]))[0]
            for inbound in (True, False):
                sql, params = b._carriers_query("m", eid, inbound, ["affects"], ["exploited_in_wild"],
                                                100, t)
                details = " | ".join(r["detail"] for r in _exec(b, "EXPLAIN QUERY PLAN " + sql, params))
                assert ("idx_obs_object" if inbound else "idx_obs_subject") in details, details
                assert "SEARCH a USING INDEX idx_obs_subject" in details and "SCAN o" not in details, details


def _kev_hub(store, n_edges=60, kev=(0, 1, 2), registry=True):
    """host h1 runs product kernel; `n_edges` CVEs affect it, one a minute,
    CVE-2026-0000 oldest. The CVEs in `kev` carry exploited_in_wild; every
    CVE carries a cvss_score two scorers disagree on."""
    from datetime import timedelta
    from loomctx.contracts import PredicateDef, SchemaRegistration
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    host, hub = EntityRef(type="host", key="h1"), EntityRef(type="product", key="kernel")
    if registry:
        store.put_schema(SchemaRegistration(namespace="v", predicates=[
            PredicateDef(name="exploited_in_wild"), PredicateDef(name="cvss_score")]))
    claims = [ClaimIn(namespace="v", subject=host, predicate="runs_software", object=hub,
                      observed_at=t, source="inventory")]
    for i in range(n_edges):
        cve = EntityRef(type="cve", key=f"CVE-2026-{i:04d}")
        at = t + timedelta(minutes=10 + i)
        claims.append(ClaimIn(namespace="v", subject=cve, predicate="affects", object=hub,
                              observed_at=at, source="nvd", valid_from=at))
        claims.append(ClaimIn(namespace="v", subject=cve, predicate="cvss_score", object=7.5,
                              observed_at=at, source="nvd:nist"))
        claims.append(ClaimIn(namespace="v", subject=cve, predicate="cvss_score", object=5.0,
                              observed_at=at, source="nvd:cna"))
        if i in kev:
            claims.append(ClaimIn(namespace="v", subject=cve, predicate="exploited_in_wild", object=True,
                                  observed_at=at, source="kev", valid_from=at))
    store.record_claims(claims)
    return host, hub


_KEV_Q = "Which CVEs that CISA lists as exploited in the wild affect software that host:h1 runs?"
_KEV_SCOPE = {"expand": ["runs_software", "affects"], "depth": 2}


def test_scope_walk_completes_a_truncated_hub_for_the_question(store, monkeypatch):
    """A hub the gather limit cut is completed for the attribute the
    question names (D-061): the walk reads the hub's expand edges past its
    window and admits the far ends that carry the topic predicate — the KEV
    entries, older than the window — and nothing else past it. Without a
    question, with one naming no attribute, or with no vocabulary naming
    the attribute (no registry, nothing gathered shows it), the walk is
    the recency window it always was."""
    from loomctx import context
    from loomctx.context import resolve_scope_paths
    from loomctx.contracts import ScopeSpec
    monkeypatch.setattr(context, "_GATHER_LIMIT", 20)
    host, _ = _kev_hub(store)
    scope = ScopeSpec(subjects=[host], **_KEV_SCOPE)
    kev = {f"CVE-2026-{i:04d}" for i in (0, 1, 2)}

    plain, _ = resolve_scope_paths(store, "v", scope)
    assert not kev & {r.key for r in plain} and len(plain) == 2 + 20
    truncated: dict = {}
    got, paths = resolve_scope_paths(store, "v", scope, truncated=truncated, question=_KEV_Q)
    assert kev <= {r.key for r in got} and len(got) == 2 + 20 + 3     # the window plus the carriers only
    for k in kev:
        chain = paths[("cve", k)]
        assert [o.predicate for o in chain] == ["runs_software", "affects"] and chain[-1].subject.key == k
    assert truncated[("product", "kernel")].reason == "gather_limit"   # the window is still reported
    other, _ = resolve_scope_paths(store, "v", scope, question="what software does host:h1 run?")
    assert {r.key for r in other} == {r.key for r in plain}
    # an attribute every far end carries singles nothing out: the window stands
    common, _ = resolve_scope_paths(store, "v", scope,
                                    question="Which CVEs affecting software host:h1 runs have the top CVSS score?")
    assert {r.key for r in common} == {r.key for r in plain}


def test_hub_completion_learns_the_attribute_from_the_registry(store, monkeypatch):
    """The topic vocabulary is the namespace's registry plus what the walk
    has gathered: with no registry and nothing gathered showing the
    predicate, the carriers past the window stay out (the page handle still
    offers them)."""
    from loomctx import context
    from loomctx.context import resolve_scope_paths
    from loomctx.contracts import ScopeSpec
    monkeypatch.setattr(context, "_GATHER_LIMIT", 20)
    host, _ = _kev_hub(store, registry=False)
    got, _ = resolve_scope_paths(store, "v", ScopeSpec(subjects=[host], **_KEV_SCOPE), question=_KEV_Q)
    assert len(got) == 2 + 20


def test_topic_carriers_go_first_when_the_entity_cap_binds(store, monkeypatch):
    """With the entity cap binding, the walk cuts entities that do not
    carry the question's topic, not the ones that do (D-061); the cut is
    still reported as scope_cap."""
    from loomctx import context
    from loomctx.context import resolve_scope_paths
    from loomctx.contracts import ScopeSpec
    monkeypatch.setattr(context, "_GATHER_LIMIT", 20)
    monkeypatch.setenv("LOOMCTX_MAX_SCOPE_ENTITIES", "8")
    host, _ = _kev_hub(store)
    truncated: dict = {}
    got, _ = resolve_scope_paths(store, "v", ScopeSpec(subjects=[host], **_KEV_SCOPE),
                                 truncated=truncated, question=_KEV_Q)
    keys = [r.key for r in got]
    assert len(got) == 8 and set(keys[2:5]) == {"CVE-2026-0000", "CVE-2026-0001", "CVE-2026-0002"}
    assert any(t.reason == "scope_cap" for t in truncated.values())
    # no hub at all, just a crowded frontier: the carriers are probed for
    monkeypatch.setattr(context, "_GATHER_LIMIT", 1000)
    truncated = {}
    got, _ = resolve_scope_paths(store, "v", ScopeSpec(subjects=[host], **_KEV_SCOPE),
                                 truncated=truncated, question=_KEV_Q)
    assert len(got) == 8 and set(r.key for r in got[2:5]) == {"CVE-2026-0000", "CVE-2026-0001", "CVE-2026-0002"}
    assert not any(t.reason == "gather_limit" for t in truncated.values())


def test_topic_pack_carries_the_hub_answer_with_its_edges(store, monkeypatch):
    """The pack for that question carries every KEV CVE with the edge that
    reached it, both cited, as sibling items; the CVSS disagreements on the
    reached CVEs are handed back as conflict handles instead of spending
    the budget; the pack stays inside its budget; and the scorecard's
    reader reads the grouped items back fact by fact (D-061)."""
    from loomctx import context
    from loomctx.answer import render_user_prompt
    from loomctx.context import build_pack
    from loomctx.contracts import AskRequest, ScopeSpec
    from loomctx.retrieval_eval import parse_context
    monkeypatch.setattr(context, "_GATHER_LIMIT", 20)
    host, _ = _kev_hub(store, kev=(0, 1, 2, 3, 4, 5))
    kev_rows = {}
    for i in range(6):
        for o in store.observations_for("v", EntityRef(type="cve", key=f"CVE-2026-{i:04d}")):
            kev_rows.setdefault(o.predicate, {})[o.subject.key] = o
    facts_by_cve, edges_by_cve = kev_rows["exploited_in_wild"], kev_rows["affects"]
    for budget in (800, 1600):
        pack = build_pack(store, AskRequest(namespace="v", scope=ScopeSpec(subjects=[host], **_KEV_SCOPE),
                                            question=_KEV_Q, budget=budget))
        assert pack.charged_tokens <= budget
        assert not [i for i in pack.items if i.kind == "conflict"]
        assert any(h.kind == "conflict" for h in pack.handles) or pack.omitted_handles
        grouped = [i for i in pack.items if "exploited_in_wild True" in i.text]
        assert grouped and all(len(i.citations) == 2 * i.text.count(" (2026-") for i in grouped)
        cited = {c.observation_id for i in pack.items for c in i.citations}
        assert {o.id for o in facts_by_cve.values()} | {o.id for o in edges_by_cve.values()} <= cited
        lines = parse_context(render_user_prompt(_KEV_Q, pack))
        facts = {ln.subject: ln for ln in lines if ln.predicate == "exploited_in_wild"}
        assert set(facts) == {f"cve:{k}" for k in facts_by_cve}
        for subject, ln in facts.items():
            key = subject.split(":", 1)[1]
            assert ln.object == "True" and ln.cites == [facts_by_cve[key].id[:12]]
            assert ln.valid_from == ln.observed and ln.valid_to == "present"
        edges = {ln.subject: ln for ln in lines if ln.kind == "relation" and ln.predicate == "affects"}
        for subject in facts:
            key = subject.split(":", 1)[1]
            assert edges[subject].object == "product:kernel"
            assert edges[subject].cites == [edges_by_cve[key].id[:12]]


def test_refresh_statistics_is_safe_after_a_load(store):
    """D-081: a bulk loader refreshes planner statistics when it finishes;
    a no-op on SQLite, ANALYZE on Postgres, idempotent on both."""
    store.record_claims([login_claim("stats")])
    store.refresh_statistics()
    store.refresh_statistics()
    assert store.observations_for("stats", EntityRef(type="host", key="web-01"))
    from loomctx.store.postgres import PostgresStore
    if isinstance(store, PostgresStore):
        with store._tx():
            opts = store._q("SELECT reloptions FROM pg_class WHERE relname = 'observations'")
        assert "autovacuum_analyze_threshold=5000" in (opts[0]["reloptions"] or [])


def test_shared_identifier_groups(store):
    """D-083: identifier entities two or more entities point at, narrowed by
    `since` to what new edges touched; a tombstoned edge does not count."""
    from datetime import timedelta
    ident = EntityRef(type="identifier", key="fqdn:web-01.corp.local")
    lone = EntityRef(type="identifier", key="fqdn:db-02.corp.local")
    def edge(subject_key, obj, etype="host"):
        return store.record_claim(ClaimIn(namespace="ids", subject=EntityRef(type=etype, key=subject_key),
                                          predicate="identified_by", object=obj, observed_at=datetime.now(timezone.utc),
                                          source="t"))
    edge("web-01", ident)
    edge("S-1-5-21-1", ident, etype="computer")
    third = edge("10.0.4.7", ident)
    edge("db-02", lone)
    groups = store.shared_identifier_groups("ids")
    assert [(g.key, sorted(m.key for m in ms)) for g, ms in groups] == [
        ("fqdn:web-01.corp.local", ["10.0.4.7", "S-1-5-21-1", "web-01"])]
    assert store.shared_identifier_groups("ids", since=datetime.now(timezone.utc) + timedelta(hours=1)) == []
    store.redact("ids", third.id, "test")
    [(_, members)] = store.shared_identifier_groups("ids")
    assert sorted(m.key for m in members) == ["S-1-5-21-1", "web-01"]


def test_foreign_key_child_columns_are_indexed(store):
    """S-63: deleting a merged-away entity checks nothing still points at it;
    without an index LED by each child column the check scanned the table."""
    from loomctx.store.postgres import PostgresStore
    if isinstance(store, PostgresStore):
        with store._tx():
            names = {r["indexname"] for r in store._q("SELECT indexname FROM pg_indexes")}
    elif isinstance(store, SqliteStore):
        with store._tx(read=True):
            names = {r["name"] for r in store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'")}
    else:
        pytest.skip("sharded: its shards are the stores above")
    assert {"idx_obs_object_entity", "idx_alias_entity", "idx_obs_subject_recorded"} <= names


def test_rank_facts_counts_structured_and_extracted(store):
    """S-63: the resolution tiers rank candidates in one call — both sides of
    an edge count, and a document-extracted row is not structured."""
    ns = "rank"
    a, b = EntityRef(type="host", key="a"), EntityRef(type="host", key="b")
    now = datetime.now(timezone.utc)
    store.record_claims([
        ClaimIn(namespace=ns, subject=a, predicate="os", object="linux", observed_at=now, source="cmdb"),
        ClaimIn(namespace=ns, subject=a, predicate="links", object=b, observed_at=now, source="scan"),
        ClaimIn(namespace=ns, subject=b, predicate="os", object="bsd", observed_at=now, source="doc:x",
                attrs={"extracted": True})])
    got = store.rank_facts(ns, [a, b, EntityRef(type="host", key="nope")])
    assert set(got) == {("host", "a"), ("host", "b")}
    assert got[("host", "a")][:2] == (2, 2)
    assert got[("host", "b")][:2] == (1, 2)          # the edge into it counts; the extracted row does not
