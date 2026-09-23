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


def _two_hop_store(tmp_path, edge_kwargs=None, edge_time=None):
    """web-01 runs nginx; CVE-1 affects nginx and is exploited."""
    store = SqliteStore(tmp_path / "hops.db")
    host, prod, cve = (EntityRef(type="host", key="web-01"), EntityRef(type="product", key="nginx"),
                       EntityRef(type="cve", key="CVE-2026-1"))
    store.record_claims([
        ClaimIn(subject=host, predicate="runs_software", object=prod, source="inv",
                observed_at=edge_time or _at(1), **(edge_kwargs or {})),
        ClaimIn(subject=cve, predicate="affects", object=prod, source="nvd", observed_at=_at(1)),
        ClaimIn(subject=cve, predicate="exploited_in_wild", object=True, source="kev", observed_at=_at(1)),
    ])
    return store, host


def _reached(pack):
    return {(s.type, s.key) for s in pack.subjects}


def test_scope_walk_honors_as_of(tmp_path):
    """D-046: an edge observed after T did not exist as of T, so nothing
    behind it is reached — the walk used to follow it and then the pack
    hid the edge, shipping the reached facts without their chain."""
    store, host = _two_hop_store(tmp_path, edge_time=_at(15))
    scope = ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2)
    now = build_pack(store, AskRequest(scope=scope, question="exploited", budget=3000))
    assert ("cve", "CVE-2026-1") in _reached(now)
    then = build_pack(store, AskRequest(scope=scope, question="exploited", budget=3000, as_of=_at(10)))
    assert _reached(then) == {("host", "web-01")}
    assert not any("exploited" in i.text for i in then.items)


def test_scope_walk_honors_valid_at(tmp_path):
    """D-046: an edge whose validity window misses T is not walked."""
    store, host = _two_hop_store(tmp_path, edge_kwargs={"valid_from": _at(1), "valid_to": _at(5)})
    scope = ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2)
    during = build_pack(store, AskRequest(scope=scope, question="exploited", budget=3000, valid_at=_at(3)))
    assert ("cve", "CVE-2026-1") in _reached(during)
    after = build_pack(store, AskRequest(scope=scope, question="exploited", budget=3000, valid_at=_at(20)))
    assert _reached(after) == {("host", "web-01")}
    assert not any("exploited" in i.text for i in after.items)


def test_scope_walk_does_not_hop_through_an_entity_the_reader_cannot_see(tmp_path):
    """D-021/D-046: a host-only reader walking member_of from web-01 must
    not reach db-01 *through* domain:corp.local — the hop is invisible to
    them, so the reached facts would arrive without their chain."""
    store, domain = make_store(tmp_path)
    scope = ScopeSpec(subjects=[EntityRef(type="host", key="web-01")], expand=["member_of"], depth=2)
    everyone = build_pack(store, AskRequest(scope=scope, question="who logged in?", budget=3000))
    assert ("host", "db-01") in _reached(everyone)
    scoped = build_pack(store, AskRequest(scope=scope, question="who logged in?", budget=3000),
                        allowed_types=("host", "user"))
    assert _reached(scoped) == {("host", "web-01")}
    text = " | ".join(i.text for i in scoped.items)
    assert "user-0" in text and "user-1" not in text and "domain:" not in text


def test_extracted_edges_do_not_steer_expansion_by_default(tmp_path):
    """D-023/D-046: a hostile document claiming 'web-01 runs product:evil'
    could otherwise pull product:evil and its CVEs into web-01's two-hop
    pack. Extracted edges are walked only when the scope opts in."""
    store, host = _two_hop_store(tmp_path)
    evil = EntityRef(type="product", key="evil")
    store.record_claims([
        ClaimIn(subject=host, predicate="runs_software", object=evil, source="doc:phish.txt",
                observed_at=_at(2), attrs={"extracted": True}),
        ClaimIn(subject=EntityRef(type="cve", key="CVE-2026-666"), predicate="affects", object=evil,
                source="nvd", observed_at=_at(2)),
    ])
    scope = ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2)
    pack = build_pack(store, AskRequest(scope=scope, question="exploited", budget=3000))
    assert ("cve", "CVE-2026-1") in _reached(pack)
    assert ("product", "evil") not in _reached(pack) and ("cve", "CVE-2026-666") not in _reached(pack)
    assert not any("CVE-2026-666" in i.text for i in pack.items)
    # the extracted edge itself is still a (discounted) fact about web-01
    assert any("product:evil" in i.text and i.kind == "fact" for i in pack.items)
    opted = build_pack(store, AskRequest(
        scope=ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2, follow_extracted=True),
        question="exploited", budget=3000))
    assert ("cve", "CVE-2026-666") in _reached(opted)
