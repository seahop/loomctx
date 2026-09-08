"""GraphStore contract tests, run against every backend.

SQLite always runs. Postgres runs when LOOM_TEST_POSTGRES_URL is set (CI
brings one up via the compose `pg` profile); otherwise those params skip.
"""

import json
import os
from datetime import datetime, timezone

import pytest

from loom.contracts import ClaimIn, EntityRef
from loom.store.sqlite import SqliteStore

OBSERVED = datetime(2026, 9, 1, 14, 3, tzinfo=timezone.utc)


@pytest.fixture(params=["sqlite", "postgres", "sharded"])
def store(request, tmp_path):
    if request.param == "sqlite":
        s = SqliteStore(tmp_path / "test.db")
    elif request.param == "sharded":
        # two SQLite shards: namespaces the suite uses land on both sides,
        # so every contract test also exercises the routing (D-032)
        from loom.store.sharded import ShardedStore
        b = SqliteStore(tmp_path / "shard-b.db")
        s = ShardedStore(SqliteStore(tmp_path / "shard-a.db"),
                         {"team-b": b, "other": b, "other-ns": b, "vuln": b})
    else:
        url = os.environ.get("LOOM_TEST_POSTGRES_URL")
        if not url:
            pytest.skip("LOOM_TEST_POSTGRES_URL not set")
        from loom.store.postgres import PostgresStore

        s = PostgresStore(url)
        s.wipe()
    yield s
    s.close()


def _raw(store):
    """Tests that poke backend internals skip the routing wrapper."""
    if not hasattr(store, "_tx"):
        pytest.skip("backend-internal test; not applicable to ShardedStore")
    return store


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
    from loom.contracts import DocumentIn

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


def test_search_entities_exact_and_prefix(store):
    store.record_claim(login_claim())  # creates host web-01 + user jdoe
    exact = store.search_entities("default", "web-01")
    assert [e.key for e in exact] == ["web-01"]
    prefix = store.search_entities("default", "web")
    assert [e.key for e in prefix] == ["web-01"]
    assert store.search_entities("default", "zzz") == []
    assert store.search_entities("other-ns", "web-01") == []


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
    from loom.contracts import DocumentIn
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
    from loom.contracts import DocumentIn
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
    from loom.contracts import DocumentIn
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
    from loom.lifecycle import export_jsonl, import_jsonl
    from loom.store.sqlite import SqliteStore
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
    from loom.contracts import DocumentIn
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
    from loom.contracts import DocumentIn, Provenance
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
    from loom.contracts import EntityTypeDef, PredicateDef, SchemaRegistration
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
    from loom.contracts import DocumentIn
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
    from loom.contracts import DocumentIn
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
    for i in range(5):
        store.record_claim(login_claim().model_copy(
            update={"object": EntityRef(type="user", key=f"u{i}")}))
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
    host = EntityRef(type="host", key="web-01")
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
    from loom.contracts import DocumentIn
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


def test_vector_index_backfill_and_exact_fallback_agree(store):
    _raw(store)
    """Rows that reach the JSON table without the index (imports, older
    versions) are picked up by ensure_vector_index; the exact path ranks
    identically to the ANN path."""
    import json as _json
    host = EntityRef(type="host", key="web-01")
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
    """LOOM_DB_READ: reads go to the replica pool (here: the same server
    under a different DSN), writes stay on the primary."""
    url = os.environ.get("LOOM_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("LOOM_TEST_POSTGRES_URL not set")
    from loom.store.postgres import PostgresStore
    read_url = url + ("&" if "?" in url else "?") + "application_name=loom-reader"
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
        assert who == "loom-reader"
    finally:
        s.close()
    same = PostgresStore(url, read_dsn=url)   # identical DSN: no second pool
    assert same._read_pool is None
    same.close()


# ------------------------------------------------- worker fleet (D-031) #

def test_extraction_leases_are_exclusive_and_expire(store):
    from datetime import timedelta
    from loom.contracts import DocumentIn
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
    from loom.contracts import DocumentIn
    art = store.store_artifact(DocumentIn(text="hello world", source="s", observed_at=OBSERVED))
    assert [x.id for x in store.artifacts_needing_chunks("m", 4, lease=("a", 300))] == [art.id]
    assert store.artifacts_needing_chunks("m", 4, lease=("b", 300)) == []
    store.put_doc_chunks("default", art.id, "m", [(0, 0, 11, "hello world", [1.0])])
    assert store.artifacts_needing_chunks("m", 4, lease=("b", 300)) == []  # done, not just released

    for host in ("h1", "h2"):
        for i in range(5):
            store.record_claim(login_claim().model_copy(update={
                "subject": EntityRef(type="host", key=host),
                "object": EntityRef(type="user", key=f"u{i}")}))
    first = store.dossier_candidates(min_new=20, min_total=5, lease=("a", 300))
    assert {c[1].key for c in first} == {"h1", "h2"}
    assert store.dossier_candidates(min_new=20, min_total=5, lease=("b", 300)) == []
    store.put_dossier("default", EntityRef(type="host", key="h1"), "brief", 5, [])
    assert store.dossier_candidates(min_new=20, min_total=5) == []  # h1 built, h2 leased


def test_embedding_backlog_shards_partition_the_work(store):
    host = EntityRef(type="host", key="web-01")
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
    from loom.contracts import DocumentIn
    from loom.store.sharded import ShardedStore
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
    from loom.store.factory import store_from_env
    from loom.store.sharded import ShardedStore
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "main.db"))
    monkeypatch.setenv("LOOM_SHARDS", json.dumps({"acme": str(tmp_path / "acme.db"),
                                                  "globex": str(tmp_path / "acme.db")}))
    s = store_from_env()
    assert isinstance(s, ShardedStore) and s.describe() == {"acme": 1, "globex": 1}
    s.close()
    monkeypatch.delenv("LOOM_SHARDS")
    assert isinstance(store_from_env(), SqliteStore)


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
