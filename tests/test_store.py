"""GraphStore contract tests, run against every backend.

SQLite always runs. Postgres runs when LOOM_TEST_POSTGRES_URL is set (CI
brings one up via the compose `pg` profile); otherwise those params skip.
"""

import os
from datetime import datetime, timezone

import pytest

from loom.contracts import ClaimIn, EntityRef
from loom.store.sqlite import SqliteStore

OBSERVED = datetime(2026, 9, 1, 14, 3, tzinfo=timezone.utc)


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    if request.param == "sqlite":
        s = SqliteStore(tmp_path / "test.db")
    else:
        url = os.environ.get("LOOM_TEST_POSTGRES_URL")
        if not url:
            pytest.skip("LOOM_TEST_POSTGRES_URL not set")
        from loom.store.postgres import PostgresStore

        s = PostgresStore(url)
        s.wipe()
    yield s
    s.close()


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
    via_alias = store.get_dossier("default", EntityRef(type="ip_address", key="10.0.4.7"))
    assert via_alias and via_alias["brief"] == "canonical brief"


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
