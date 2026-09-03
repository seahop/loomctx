from datetime import datetime, timezone

from loom.contracts import ClaimIn, EntityRef
from loom.store.sqlite import SqliteStore

OBSERVED = datetime(2026, 9, 1, 14, 3, tzinfo=timezone.utc)


def make_store(tmp_path):
    return SqliteStore(tmp_path / "test.db")


def login_claim(namespace="default"):
    return ClaimIn(
        namespace=namespace,
        subject=EntityRef(type="host", key="web-01"),
        predicate="logged_in_by",
        object=EntityRef(type="user", key="jdoe"),
        observed_at=OBSERVED,
        source="auth-log",
    )


def test_record_claim_creates_entities_and_edge(tmp_path):
    store = make_store(tmp_path)
    obs = store.record_claim(login_claim())

    assert store.get_entity("default", EntityRef(type="host", key="web-01"))
    assert store.get_entity("default", EntityRef(type="user", key="jdoe"))

    from_subject = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert [o.id for o in from_subject] == [obs.id]

    # edge is visible from the object side too
    from_object = store.observations_for("default", EntityRef(type="user", key="jdoe"))
    assert [o.id for o in from_object] == [obs.id]
    assert from_object[0].subject == EntityRef(type="host", key="web-01")


def test_scalar_object_roundtrip(tmp_path):
    store = make_store(tmp_path)
    claim = login_claim()
    claim = claim.model_copy(update={"predicate": "runs_os", "object": "fedora-44"})
    store.record_claim(claim)
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert obs[0].object == "fedora-44"


def test_namespace_isolation(tmp_path):
    store = make_store(tmp_path)
    store.record_claim(login_claim(namespace="team-a"))
    assert store.observations_for("team-b", EntityRef(type="host", key="web-01")) == []
    assert store.get_entity("team-b", EntityRef(type="host", key="web-01")) is None


def test_upsert_is_idempotent(tmp_path):
    store = make_store(tmp_path)
    first = store.upsert_entity("default", EntityRef(type="host", key="web-01"))
    second = store.upsert_entity("default", EntityRef(type="host", key="web-01"))
    assert first.id == second.id


def test_unknown_entity_returns_empty(tmp_path):
    store = make_store(tmp_path)
    assert store.observations_for("default", EntityRef(type="host", key="nope")) == []
