"""List mode (D-107): exact, paged, cited entity sets on every backend."""
import asyncio
import os
from datetime import datetime, timezone

import pytest

import loomctx.listing as listing
import loomctx.mcp_server as mcp_server
from loomctx.contracts import ClaimIn, EntityRef, ListFilter, ListRequest, PredicateDef, SchemaRegistration
from loomctx.store.sqlite import SqliteStore

T1 = datetime(2026, 9, 1, tzinfo=timezone.utc)
T2 = datetime(2026, 9, 20, tzinfo=timezone.utc)
MID = datetime(2026, 9, 10, tzinfo=timezone.utc)


def ref(handle: str) -> EntityRef:
    t, _, k = handle.partition(":")
    return EntityRef(type=t, key=k)


@pytest.fixture(params=["sqlite", "postgres", "sharded"])
def store(request, tmp_path):
    if request.param == "sqlite":
        s = SqliteStore(tmp_path / "list.db")
    elif request.param == "sharded":
        from loomctx.store.sharded import ShardedStore
        s = ShardedStore(SqliteStore(tmp_path / "a.db"), {"other": SqliteStore(tmp_path / "b.db")})
    else:
        url = os.environ.get("LOOMCTX_TEST_POSTGRES_URL")
        if not url:
            pytest.skip("LOOMCTX_TEST_POSTGRES_URL not set")
        from loomctx.store.postgres import PostgresStore
        s = PostgresStore(url)
        s.wipe()
    _forest(s)
    yield s
    s.close()


def _claim(s, subject, predicate, obj, when=T1, source="ldap", **kw):
    return s.record_claim(ClaimIn(subject=ref(subject), predicate=predicate,
                                  object=ref(obj) if isinstance(obj, str) and ":" in obj and
                                  predicate == "member_of" else obj,
                                  observed_at=when, source=source, **kw))


def _forest(s):
    """Nested admins: helpdesk -> it-admins -> domain-admins. carol was
    disabled at T2; dave's status was never collected; erin is no member."""
    s.put_schema(SchemaRegistration(namespace="default", predicates=[
        PredicateDef(name="member_of", containment=True),
        PredicateDef(name="enabled", node_status=True),
        PredicateDef(name="displayName", label=True, display=True),
        PredicateDef(name="spn"), PredicateDef(name="is_dc"),
        PredicateDef(name="trusted_for_delegation", description="unconstrained delegation")]))
    _claim(s, "group:it-admins", "member_of", "group:domain-admins")
    _claim(s, "group:helpdesk", "member_of", "group:it-admins")
    for user, group in [("alice", "domain-admins"), ("bob", "it-admins"), ("carol", "helpdesk"),
                        ("dave", "helpdesk")]:
        _claim(s, f"user:{user}", "member_of", f"group:{group}")
    for user, on in [("alice", True), ("bob", False), ("carol", True), ("erin", True)]:
        _claim(s, f"user:{user}", "enabled", on)
    _claim(s, "user:carol", "enabled", False, when=T2)
    _claim(s, "user:alice", "displayName", "Alice Admin")
    _claim(s, "user:alice", "spn", "http/a.corp.local")
    _claim(s, "user:alice", "spn", "cifs/a.corp.local")
    for host, tfd, dc in [("dc01", True, True), ("app01", True, False), ("ws01", False, False),
                          ("old01", True, None)]:
        _claim(s, f"computer:{host}", "trusted_for_delegation", tfd)
        if dc is not None:
            _claim(s, f"computer:{host}", "is_dc", dc)


def keys(page):
    return [r.entity.key for r in page.rows]


def run(store, **kw):
    stats: dict = {}
    page = listing.list_entities(store, ListRequest(**kw), stats=stats)
    return page, stats


def test_nested_members_by_depth(store):
    page, _ = run(store, of=ref("group:domain-admins"), via=["member_of"], type="user", depth=1)
    assert keys(page) == ["alice"] and page.total == 1 and page.exact
    page, _ = run(store, of=ref("group:domain-admins"), via=["member_of"], type="user", depth=3)
    assert keys(page) == ["alice", "bob", "carol", "dave"]
    # the admitting edge cites each member: the row's first citation
    carol = next(r for r in page.rows if r.entity.key == "carol")
    assert carol.cites and carol.cites[0].observation_id


def test_current_value_filter_and_ne_counts_unrecorded(store):
    # carol was enabled, then disabled: only the newest value is current
    page, _ = run(store, of=ref("group:domain-admins"), via=["member_of"], type="user", depth=3,
                  where=[ListFilter(predicate="enabled", op="ne", value=False)])
    assert keys(page) == ["alice", "dave"]
    assert any("1 candidate entity has no enabled value" in n for n in page.notes)
    page, _ = run(store, of=ref("group:domain-admins"), via=["member_of"], type="user", depth=3,
                  where=[ListFilter(predicate="enabled", op="eq", value="false")])   # text for a bool
    assert keys(page) == ["bob", "carol"]
    assert page.rows[0].values == {"enabled": False}


def test_as_of_reads_the_old_state(store):
    page, _ = run(store, type="user", where=[ListFilter(predicate="enabled", op="eq", value=True)], as_of=MID)
    assert keys(page) == ["alice", "carol", "erin"]


def test_positive_filter_starts_from_the_index(store):
    page, stats = run(store, type="computer",
                      where=[ListFilter(predicate="trusted_for_delegation", op="eq", value=True),
                             ListFilter(predicate="is_dc", op="ne", value=True)])
    assert stats["start"] == "index"
    assert keys(page) == ["app01", "old01"]        # old01 has no is_dc: not a DC as far as recorded
    assert any("no is_dc value" in n for n in page.notes)


def test_upward_and_downward_membership_agree(store, monkeypatch):
    kw = dict(of=ref("group:domain-admins"), via=["member_of"], depth=3,
              where=[ListFilter(predicate="enabled", op="exists")])
    up, s1 = run(store, **kw)
    monkeypatch.setattr(listing, "_UPWARD_MAX", 0)
    down, s2 = run(store, **kw)
    assert (s1["start"], s2["start"]) == ("upward", "downward")
    assert keys(up) == keys(down) == ["alice", "bob", "carol"]
    assert [r.cites[0].observation_id for r in up.rows] == [r.cites[0].observation_id for r in down.rows]


def test_multi_valued_snapshot_and_names(store):
    page, _ = run(store, type="user", where=[ListFilter(predicate="spn", op="contains", value="cifs/")],
                  fields=["spn"])
    assert keys(page) == ["alice"]
    row = page.rows[0]
    assert row.name == "Alice Admin"
    assert set(row.values["spn"].split(", ")) == {"cifs/a.corp.local", "http/a.corp.local"}
    assert len(row.cites) >= 2


def test_type_listing_cites_every_row_and_pages(store):
    page, stats = run(store, type="user", limit=2)
    assert stats["start"] == "type"
    assert page.total == 5 and keys(page) == ["alice", "bob"] and page.next_offset == 2
    assert all(r.cites for r in page.rows)
    last, _ = run(store, type="user", limit=2, offset=4)
    assert keys(last) == ["erin"] and last.next_offset is None


def test_budget_stops_the_page_and_says_where_to_continue(store):
    whole, _ = run(store, type="user")
    page, _ = run(store, type="user", budget=whole.charged_tokens // 2)
    assert 0 < len(page.rows) < 5 and page.next_offset == len(page.rows)
    assert any("continue from offset" in n for n in page.notes)


def test_candidate_cap_makes_the_total_a_lower_bound(store, monkeypatch):
    monkeypatch.setenv("LOOMCTX_MAX_LIST_CANDIDATES", "2")
    page, _ = run(store, type="user")
    assert not page.exact and page.total == 2
    assert any("LOOMCTX_MAX_LIST_CANDIDATES" in n for n in page.notes)


def test_scope_and_unknown_predicates(store):
    page = listing.list_entities(store, ListRequest(type="user"), allowed_types=("computer",))
    assert not page.rows and "outside this caller's scope" in page.notes[0]
    page, _ = run(store, type="user", where=[ListFilter(predicate="enabeld", op="eq", value=True)])
    assert page.total == 0 and any("did you mean enabled" in n for n in page.notes)
    page, _ = run(store, where=[ListFilter(predicate="enabled", op="ne", value=True)])
    assert "name a `type`" in page.notes[0]
    page, _ = run(store, of=ref("group:nope"), via=["member_of"])
    assert "not on record" in page.notes[0]


def test_subjects_with_value_and_side(store):
    got = store.subjects_with_value("default", "trusted_for_delegation", "true")
    assert sorted(r.key for r in got) == ["app01", "dc01", "old01"]
    assert sorted(r.key for r in store.subjects_with_value("default", "displayName", '"alice admin"')) == ["alice"]
    assert len(store.subjects_with_value("default", "enabled")) == 4
    hub = [ref("group:it-admins")]
    inbound = store.observations_for_many("default", hub, predicates=["member_of"], side="object")
    outbound = store.observations_for_many("default", hub, predicates=["member_of"], side="subject")
    assert sorted(o.subject.key for o in inbound[("group", "it-admins")]) == ["bob", "helpdesk"]
    assert [o.object.key for o in outbound[("group", "it-admins")]] == ["domain-admins"]


def test_mcp_tool_reads_text_filters(tmp_path):
    s = SqliteStore(tmp_path / "mcp.db")
    _forest(s)
    mcp_server.configure(s)
    try:
        async def call(args):
            return await mcp_server.mcp._tool_manager.call_tool("list_entities", args, context=None,
                                                                convert_result=True)
        res = asyncio.run(call({"of": "group:domain-admins", "via": "member_of", "depth": 3,
                                "type": "user", "where": "enabled=false"}))
        assert not res.is_error, res.content
        view = res.structured_content
        assert view["total"] == 2 and [r["entity"] for r in view["rows"]] == ["user:bob", "user:carol"]
        assert all(len(r["cites"][0]) >= 12 for r in view["rows"])
        res = asyncio.run(call({"type": "computer", "where": ["trusted_for_delegation=true", "is_dc!=true"]}))
        assert [r["entity"] for r in res.structured_content["rows"]] == ["computer:app01", "computer:old01"]
    finally:
        mcp_server.configure(None)
        s.close()


def test_filter_text_forms():
    f = mcp_server._filters("enabled=false, is_dc!=true; name~=svc and spn? , !mail")
    assert [(x.predicate, x.op, x.value) for x in f] == [
        ("enabled", "eq", "false"), ("is_dc", "ne", "true"), ("name", "contains", "svc"),
        ("spn", "exists", None), ("mail", "absent", None)]
    dn = mcp_server._filters("distinguishedName=CN=Bob,OU=Staff,DC=corp")
    assert [(x.predicate, x.value) for x in dn] == [("distinguishedName", "CN=Bob,OU=Staff,DC=corp")]
    assert mcp_server._filters('[{"predicate": "enabled", "op": "eq", "value": false}]')[0].value is False


def test_http_list_route(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "api.db"))
    from loomctx.api.http import app
    with TestClient(app) as client:
        _forest(app.state.store)
        r = client.post("/v1/list", json={"type": "computer", "where": [
            {"predicate": "trusted_for_delegation", "op": "eq", "value": True}]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 3 and [row["entity"]["key"] for row in body["rows"]] == ["app01", "dc01", "old01"]


def test_rows_say_how_far_and_the_walk_says_where_it_stopped(store):
    """Facts about the listing itself (D-107): each row's distance from `of`
    and the entity one step closer; a walk cut by its depth says entities at
    that depth link on; an empty listing in one direction says the other has
    edges. No advice about any question — what the call did."""
    page, _ = run(store, of=ref("group:domain-admins"), via=["member_of"], type="user", depth=3)
    by = {r.entity.key: r for r in page.rows}
    assert by["alice"].hops == 1 and by["alice"].through is None
    assert by["carol"].hops == 3 and by["carol"].through == ref("group:helpdesk")
    page, _ = run(store, of=ref("group:domain-admins"), via=["member_of"], type="user", depth=1)
    assert any("stopped at depth 1" in n and "link onward along member_of" in n for n in page.notes)
    full, _ = run(store, of=ref("group:domain-admins"), via=["member_of"], depth=3)
    assert not any("stopped at depth" in n for n in full.notes)
    page, _ = run(store, of=ref("user:carol"), via=["member_of"], direction="in")
    assert page.total == 0 and any("direction='in'" in n and "direction='out'" in n for n in page.notes)
    up, _ = run(store, of=ref("group:domain-admins"), via=["member_of"], depth=3,
                where=[ListFilter(predicate="enabled", op="exists")])
    assert {r.entity.key: r.hops for r in up.rows} == {"alice": 1, "bob": 2, "carol": 3}
    assert next(r for r in up.rows if r.entity.key == "carol").through == ref("group:helpdesk")


def test_mcp_tolerates_quoted_handles(tmp_path):
    s = SqliteStore(tmp_path / "q.db")
    _forest(s)
    mcp_server.configure(s)
    try:
        view = mcp_server.list_entities(of='"group:domain-admins"', via="member_of", type='"user"', depth=3)
        assert view["total"] == 4 and view["rows"][2]["hops"] == 3 and view["rows"][2]["through"] == "group:helpdesk"
    finally:
        mcp_server.configure(None)
        s.close()


def test_within_filters_nested_membership_and_seeds_the_listing(store):
    """`member_of within group:X` (D-110): in X directly or through nested
    groups — the closure, as a filter and, alone, as the start set."""
    page, st = run(store, type="user", where=[ListFilter(predicate="member_of", op="within",
                                                         value="group:domain-admins")])
    assert st["start"] == "closure" and keys(page) == ["alice", "bob", "carol", "dave"]
    page, _ = run(store, type="user", where=[ListFilter(predicate="member_of", op="within",
                                                        value="group:domain-admins", depth=1)])
    assert keys(page) == ["alice"]
    page, _ = run(store, type="user", where=[ListFilter(predicate="enabled", op="exists"),
                                             ListFilter(predicate="member_of", op="not_within",
                                                        value="group:domain-admins")])
    assert keys(page) == ["erin"]
    page, _ = run(store, type="user", where=[ListFilter(predicate="enabled", op="eq", value=True),
                                             ListFilter(predicate="member_of", op="within",
                                                        value="group:it-admins")])
    assert keys(page) == []                 # bob (disabled) and carol (disabled at T2), dave has no status
    page, _ = run(store, type="user", where=[ListFilter(predicate="member_of", op="within", value="group:nope")])
    assert page.total == 0 and any("not on record" in n for n in page.notes)


def test_access_style_listing_with_routes(store):
    """"Which Domain Admins have rights over this workstation?" in one call:
    walk in from the machine over ACL grants and membership, keep the
    admins (nested), and give each row its cited route."""
    store.record_claim(ClaimIn(subject=ref("group:it-admins"), predicate="has_ace", object=ref("computer:ws01"),
                               observed_at=T1, source="ldap", attrs={"right": "GenericAll"}))
    page, _ = run(store, of=ref("computer:ws01"), via=["has_ace", "member_of"], direction="in", depth=4,
                  type="user", paths=True,
                  where=[ListFilter(predicate="member_of", op="within", value="group:domain-admins")])
    assert keys(page) == ["bob", "carol", "dave"]          # alice is in domain-admins but not under it-admins
    st = {}
    listing.list_entities(store, ListRequest(of=ref("computer:ws01"), via=["has_ace", "member_of"], direction="in",
                                             depth=4, where=[ListFilter(predicate="member_of", op="within",
                                                                        value="group:domain-admins")]), stats=st)
    assert st["start"] == "upward" and st["seeded_by_closure"]   # the admins walk up, not the machine down
    carol = next(r for r in page.rows if r.entity.key == "carol")
    assert [e.predicate for e in carol.path] == ["member_of", "member_of", "has_ace"]
    assert carol.path[-1].object == ref("computer:ws01") and all(e.cite.observation_id for e in carol.path)
    view = mcp_server._list_view(page)
    assert view["rows"][1]["path"]["text"] == ("user:carol -member_of-> group:helpdesk -member_of-> "
                                               "group:it-admins -has_ace-> computer:ws01")


def test_within_text_filter():
    f = mcp_server._filters("member_of within group:domain-admins, enabled=true")
    assert [(x.predicate, x.op, x.value) for x in f] == [("member_of", "within", "group:domain-admins"),
                                                         ("enabled", "eq", "true")]
    f = mcp_server._filters("member_of not within group:protected-users depth 3")
    assert (f[0].op, f[0].value, f[0].depth) == ("not_within", "group:protected-users", 3)


def test_ranked_filters_match_the_python_path(store, monkeypatch):
    """The SQL-ranked current values (D-111) give the same pages as the
    per-candidate path: forced on a tiny store by lowering the threshold."""
    cases = [dict(type="user", where=[ListFilter(predicate="enabled", op="eq", value=True)]),
             dict(type="user", where=[ListFilter(predicate="enabled", op="ne", value=True)]),
             dict(type="user", where=[ListFilter(predicate="enabled", op="absent")]),
             dict(type="user", where=[ListFilter(predicate="enabled", op="eq", value="false")], as_of=MID),
             dict(type="computer", where=[ListFilter(predicate="is_dc", op="ne", value=True)])]
    slow = [run(store, **c)[0] for c in cases]
    monkeypatch.setattr(listing, "_FETCH_CHUNK", 0)
    for c, old in zip(cases, slow):
        new, st = run(store, **c)
        assert st.get("ranked"), c
        assert keys(new) == keys(old) and new.total == old.total, c
        assert [r.values for r in new.rows] == [r.values for r in old.rows], c
        assert [n for n in new.notes if "value on record" in n] == [n for n in old.notes if "value on record" in n]


def test_within_takes_a_name_and_an_early_as_of_is_explained(store):
    """`member_of within group:Domain Admins` with the group's name, not its
    key, resolves through the label predicates (GPT-4o wrote it so, got "not
    on record", and answered "none"); an empty listing as_of a time before
    anything was observed says so (a model set as_of two months early)."""
    _claim(store, "group:domain-admins", "displayName", "Domain Admins")
    page, _ = run(store, type="user", where=[ListFilter(predicate="member_of", op="within", value="group:Domain Admins")])
    assert keys(page) == ["alice", "bob", "carol", "dave"]
    from datetime import datetime, timezone
    page, _ = run(store, type="user", where=[ListFilter(predicate="enabled", op="eq", value=True)],
                  as_of=datetime(2026, 7, 1, tzinfo=timezone.utc))
    assert page.total == 0 and any("before anything in namespace" in n for n in page.notes)
