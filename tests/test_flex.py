"""Flexible asks (D-115, D-116): the names agents actually use, conditions
combined in one call, and notes where a request would otherwise read as an
empty, exact answer. Built on the shapes the 2026-10 harder AD audits failed
on: an admin who holds rights through a second group, a non-admin co-member,
Kerberoastable decoys, and has_ace read as local admin."""
import asyncio
import os
from datetime import datetime, timezone

import pytest

import loomctx.listing as listing
import loomctx.mcp_server as mcp_server
from loomctx.context import build_pack, find_paths
from loomctx.contracts import (
    AskRequest, ClaimIn, EntityRef, EntityTypeDef, ListFilter, ListRequest, NotCollectedDef, PathRequest,
    PredicateDef, QueryDef, QueryParam, ScopeSpec, SchemaRegistration,
)
from loomctx.store.common import merge_schema
from loomctx.store.sqlite import SqliteStore

T1 = datetime(2026, 9, 1, tzinfo=timezone.utc)
NS = "ad"


def ref(handle: str) -> EntityRef:
    t, _, k = handle.partition(":")
    return EntityRef(type=t, key=k)


@pytest.fixture(params=["sqlite", "postgres", "sharded"])
def store(request, tmp_path):
    if request.param == "sqlite":
        s = SqliteStore(tmp_path / "flex.db")
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


def _claim(s, subject, predicate, obj):
    s.record_claim(ClaimIn(namespace=NS, subject=ref(subject), predicate=predicate,
                           object=ref(obj) if isinstance(obj, str) and obj.split(":")[0] in
                           ("group", "computer", "user") else obj,
                           observed_at=T1, source="ldap"))


def _forest(s):
    s.put_schema(SchemaRegistration(
        namespace=NS,
        entity_types=[EntityTypeDef(name="user", aliases=["account"]),
                      EntityTypeDef(name="computer", aliases=["machine", "host"]),
                      EntityTypeDef(name="group")],
        predicates=[PredicateDef(name="member_of", containment=True, aliases=["memberOf"]),
                    PredicateDef(name="has_ace", description="a DACL grant over the object"),
                    PredicateDef(name="enabled", node_status=True),
                    PredicateDef(name="kerberoastable"),
                    PredicateDef(name="spn", aliases=["servicePrincipalName"]),
                    PredicateDef(name="os", aliases=["operatingSystem"])],
        not_collected=[NotCollectedDef(topic="local_groups", source="ldap",
                                       description="machines' local group membership",
                                       words=["local admin"], mistaken_for=["has_ace"])],
        queries=[QueryDef(name="enabled_members", description="enabled members, nested",
                          params=[QueryParam(name="group", kind="entity", entity_type="group")],
                          request={"of": "{group}", "via": ["member_of"], "depth": 6, "type": "user",
                                   "where": [{"predicate": "enabled", "op": "eq", "value": True}]})]))
    _claim(s, "group:tier0", "member_of", "group:da")
    for user, group in [("rlopez", "tier0"), ("pchen", "da"), ("kwu", "da"), ("rlopez", "ws-ops"),
                        ("jdoe", "ws-ops"), ("svc-sql", "da"), ("svc-bak", "da")]:
        _claim(s, f"user:{user}", "member_of", f"group:{group}")
    _claim(s, "group:ws-ops", "has_ace", "computer:ws-1")
    _claim(s, "user:pchen", "has_ace", "computer:ws-1")
    for user, on in [("rlopez", True), ("pchen", True), ("kwu", True), ("jdoe", True),
                     ("svc-sql", True), ("svc-bak", False), ("svc-web", True)]:
        _claim(s, f"user:{user}", "enabled", on)
    for user in ("svc-sql", "svc-bak", "svc-web"):
        _claim(s, f"user:{user}", "kerberoastable", True)
        _claim(s, f"user:{user}", "spn", f"MSSQL/{user}.corp.local")
    _claim(s, "computer:ws-1", "os", "Windows 11")


def _keys(page):
    return sorted(r.entity.key for r in page.rows)


def test_admins_with_rights_over_a_machine_is_one_listing(store):
    """Domain Admins (nested) who hold rights over WS-1, directly or through
    a group: pchen directly, rlopez through ws-ops; jdoe has rights but is no
    admin, kwu is an admin with none."""
    page = listing.list_entities(store, ListRequest(namespace=NS, type="user", where=[
        ListFilter(predicate="member_of", op="within", value="group:da"),
        ListFilter(predicate="has_ace,member_of", op="within", value="computer:ws-1")]))
    assert _keys(page) == ["pchen", "rlopez"] and page.exact


def test_text_conditions_split_on_any_and_and_combined_within(store):
    f = mcp_server._filters("member_of within group:da AND has_ace, member_of within computer:ws-1")
    assert [(x.predicate, x.op, x.value) for x in f] == [
        ("member_of", "within", "group:da"), ("has_ace,member_of", "within", "computer:ws-1")]
    # conditions before a within, comma-separated: only the bare names are its predicates
    f = mcp_server._filters("kerberoastable=true, enabled=true, has_ace, member_of within group:da")
    assert [(x.predicate, x.op) for x in f] == [("kerberoastable", "eq"), ("enabled", "eq"),
                                                ("has_ace,member_of", "within")]
    # a name with spaces as the within value, quoted or not, with a depth
    for text in ("member_of within group:Domain Admins", "member_of within 'group:Domain Admins' depth 3"):
        (w,) = mcp_server._filters(text)
        assert (w.op, w.value) == ("within", "group:Domain Admins"), text
    # inside a list item too, and with && — an uppercase AND was read as part of the value
    f = mcp_server._filters(["enabled=true AND kerberoastable=true", "spn? && !os"])
    assert [(x.predicate, x.op) for x in f] == [("enabled", "eq"), ("kerberoastable", "eq"),
                                                ("spn", "exists"), ("os", "absent")]


def test_type_and_predicate_aliases_are_read_as_registered_names(store):
    page = listing.list_entities(store, ListRequest(namespace=NS, type="account", where=[
        ListFilter(predicate="servicePrincipalName", op="exists"),
        ListFilter(predicate="enabled", op="eq", value=True)]))
    assert _keys(page) == ["svc-sql", "svc-web"]
    assert "type 'account' is entity type 'user' in namespace 'ad'" in page.notes
    assert "'servicePrincipalName' is predicate 'spn' in namespace 'ad'" in page.notes
    # a spelling alone, without a declared alias, maps too: is-dc / member-of
    page = listing.list_entities(store, ListRequest(namespace=NS, of=ref("group:da"), via=["Member-Of"], depth=3))
    assert "rlopez" in _keys(page) and any("'Member-Of' is predicate 'member_of'" in n for n in page.notes)


def test_an_unknown_type_names_the_types_instead_of_an_empty_answer(store):
    page = listing.list_entities(store, ListRequest(namespace=NS, type="widget"))
    assert page.total == 0
    assert any("type 'widget' is not an entity type" in n and "computer, group, user" in n for n in page.notes)


def test_a_value_no_entity_carries_says_which_values_exist(store):
    page = listing.list_entities(store, ListRequest(namespace=NS, type="computer", where=[
        ListFilter(predicate="os", op="eq", value="Windows 10")]))
    assert page.total == 0
    assert any("no entity has os = Windows 10" in n and "Windows 11" in n for n in page.notes)


def test_a_permission_walk_without_membership_names_what_it_left_out(store):
    page = listing.list_entities(store, ListRequest(namespace=NS, of=ref("computer:ws-1"), via=["has_ace"]))
    assert _keys(page) == ["pchen", "ws-ops"]
    member = [n for n in page.notes if "have members" in n]
    assert member and "'has_ace,member_of' within computer:ws-1" in member[0]
    # rights over the object are not local admin: the gap's lookalike line
    assert any(n.startswith("has_ace is not local groups") for n in page.notes)
    # walking membership too, the note has nothing to add
    both = listing.list_entities(store, ListRequest(namespace=NS, of=ref("computer:ws-1"),
                                                    via=["has_ace", "member_of"], depth=3))
    assert {"rlopez", "jdoe"} <= set(_keys(both)) and not any("have members" in n for n in both.notes)


def test_run_query_composes_with_more_conditions(store):
    mcp_server.configure(store)
    try:
        async def call(args):
            return await mcp_server.mcp._tool_manager.call_tool("run_query", args, context=None,
                                                                convert_result=True)
        res = asyncio.run(call({"name": "enabled_members", "namespace": NS, "params": {"group": "group:da"},
                                "where": "kerberoastable=true", "fields": ["spn"]}))
        assert not res.is_error, res.content
        rows = res.structured_content["rows"]
        assert [r["entity"] for r in rows] == ["user:svc-sql"] and "spn" in rows[0]["values"]
        # a failed call says how to recover
        with pytest.raises(Exception, match="describe_namespace"):
            asyncio.run(call({"name": "no_such_query", "namespace": NS}))
    finally:
        mcp_server.configure(None)


def test_packs_and_paths_take_aliases_and_flag_lookalikes(store):
    pack = build_pack(store, AskRequest(namespace=NS, question="who is local admin on ws-1?", budget=1500,
                                        scope=ScopeSpec(subjects=[ref("computer:ws-1")], expand=["has_ace"],
                                                        depth=1)))
    assert any(n.startswith("has_ace is not local groups") for n in pack.notes)
    pack = build_pack(store, AskRequest(namespace=NS, question="members?", budget=1500,
                                        scope=ScopeSpec(subjects=[ref("group:da")], expand=["memberOf"], depth=2)))
    assert "'memberOf' is predicate 'member_of' in namespace 'ad'" in pack.notes
    paths = find_paths(store, PathRequest(namespace=NS, **{"from": ref("group:da")}, to=ref("computer:ws-1"),
                                          via=["memberOf", "has_ace"], depth=5))
    assert "'memberOf' is predicate 'member_of' in namespace 'ad'" in paths.notes
    # pchen directly, and rlopez through tier0 and ws-ops (one account in two groups, D-115)
    ends = sorted({e.subject.key for p in paths.paths for e in p if e.predicate == "has_ace"} |
                  {e.subject.key for p in paths.paths for e in p if e.subject.key == "rlopez"})
    assert ends == ["pchen", "rlopez", "ws-ops"]


def test_aliases_merge_as_a_union():
    a = SchemaRegistration(namespace=NS, entity_types=[EntityTypeDef(name="user", aliases=["account"])],
                           predicates=[PredicateDef(name="spn", aliases=["servicePrincipalName"])])
    b = SchemaRegistration(namespace=NS, entity_types=[EntityTypeDef(name="user", aliases=["person"])],
                           predicates=[PredicateDef(name="spn", aliases=["spns"])])
    m = merge_schema(a, b)
    assert m.entity_types[0].aliases == ["account", "person"]
    assert m.predicates[0].aliases == ["servicePrincipalName", "spns"]
