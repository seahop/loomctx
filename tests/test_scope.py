from datetime import datetime, timezone

from loom.context import build_pack, resolve_scope
from loom.contracts import AskRequest, ClaimIn, EntityRef, ScopeSpec
from loom.store.sqlite import SqliteStore


def _at(day, hour=12):
    return datetime(2026, 8, day, hour, tzinfo=timezone.utc)


def make_store(tmp_path):
    """corp.local contains web-01 and db-01; stray-01 is outside the domain."""
    store = SqliteStore(tmp_path / "scope.db")
    domain = EntityRef(type="domain", key="corp.local")
    for i, host in enumerate(["web-01", "db-01"]):
        store.record_claim(ClaimIn(
            subject=EntityRef(type="host", key=host), predicate="member_of",
            object=domain, observed_at=_at(1), source="inventory",
        ))
        store.record_claim(ClaimIn(
            subject=EntityRef(type="host", key=host), predicate="logged_in_by",
            object=EntityRef(type="user", key=f"user-{i}"),
            observed_at=_at(10 + i), source="auth-log",
        ))
    store.record_claim(ClaimIn(
        subject=EntityRef(type="host", key="stray-01"), predicate="logged_in_by",
        object=EntityRef(type="user", key="outsider"),
        observed_at=_at(20), source="auth-log",
    ))
    return store, domain


def test_scope_expansion_from_domain_anchor(tmp_path):
    store, domain = make_store(tmp_path)
    resolved = resolve_scope(store, "default", ScopeSpec(
        subjects=[domain], expand=["member_of"], depth=1,
    ))
    keys = {(r.type, r.key) for r in resolved}
    assert ("domain", "corp.local") in keys
    assert ("host", "web-01") in keys and ("host", "db-01") in keys
    assert ("host", "stray-01") not in keys


def test_depth_zero_is_just_the_subjects(tmp_path):
    store, domain = make_store(tmp_path)
    resolved = resolve_scope(store, "default", ScopeSpec(
        subjects=[domain], expand=["member_of"], depth=0,
    ))
    assert [(r.type, r.key) for r in resolved] == [("domain", "corp.local")]


def test_domain_scoped_pack_covers_members(tmp_path):
    store, domain = make_store(tmp_path)
    pack = build_pack(store, AskRequest(
        scope=ScopeSpec(subjects=[domain], expand=["member_of"], depth=1),
        question="who logged in?", budget=3000,
    ))
    text = " | ".join(i.text for i in pack.items)
    assert "user-0" in text and "user-1" in text
    assert "outsider" not in text
    assert pack.subject is None and len(pack.subjects) == 3
    # membership edges reachable from both ends must not duplicate items
    ids = [c.observation_id for i in pack.items for c in i.citations]
    assert len(ids) == len(set(ids))


def test_multi_subject_scope_without_expansion(tmp_path):
    store, _ = make_store(tmp_path)
    pack = build_pack(store, AskRequest(
        scope=ScopeSpec(subjects=[
            EntityRef(type="host", key="web-01"),
            EntityRef(type="host", key="stray-01"),
        ]),
        question="who logged in?", budget=3000,
    ))
    text = " | ".join(i.text for i in pack.items)
    assert "user-0" in text and "outsider" in text and "user-1" not in text


def test_ask_requires_exactly_one_of_subject_scope():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AskRequest(question="q")
    with pytest.raises(ValidationError):
        AskRequest(
            question="q",
            subject=EntityRef(type="host", key="a"),
            scope=ScopeSpec(subjects=[EntityRef(type="host", key="b")]),
        )
