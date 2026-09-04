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
