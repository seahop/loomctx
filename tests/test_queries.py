"""Named queries (D-108): list templates a namespace registers and runs by name."""
import asyncio
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

import loomctx.mcp_server as mcp_server
from loomctx.connectors import ldap
from loomctx.contracts import ClaimIn, EntityRef, QueryDef, QueryParam, QueryRequest, SchemaRegistration
from loomctx.queries import QueryError, run_query
from loomctx.store.sqlite import SqliteStore

NS = "netsec"
T = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _c(s, subj, pred, obj):
    t, _, k = subj.partition(":")
    if isinstance(obj, str) and obj.startswith(("group:", "domain:")):
        ot, _, ok = obj.partition(":")
        obj = EntityRef(type=ot, key=ok)
    s.record_claim(ClaimIn(namespace=NS, subject=EntityRef(type=t, key=k), predicate=pred, object=obj,
                           observed_at=T, source="ad-export"))


@pytest.fixture
def store(tmp_path):
    """A small directory under the LDAP connector's registry: Domain Admins
    nests IT-Admins; web01 delegates unconstrained, dc01 is a DC."""
    s = SqliteStore(tmp_path / "q.db")
    s.put_schema(ldap.schema(NS))
    _c(s, "group:S-512", "name", "Domain Admins")
    _c(s, "group:S-1100", "name", "IT-Admins")
    _c(s, "group:S-1100", "member_of", "group:S-512")
    for sid, sam, group, enabled in [("S-2001", "alice", "S-512", True), ("S-2002", "bob", "S-1100", False),
                                     ("S-2003", "carol", "S-1100", True)]:
        _c(s, f"user:{sid}", "sam", sam)
        _c(s, f"user:{sid}", "member_of", f"group:{group}")
        _c(s, f"user:{sid}", "enabled", enabled)
    _c(s, "user:S-2003", "kerberoastable", True)
    _c(s, "user:S-2003", "spn", "MSSQLSvc/sql01.corp.local")
    for sid, name, uncon, dc in [("S-3001", "DC01", True, True), ("S-3002", "WEB01", True, False)]:
        _c(s, f"computer:{sid}", "name", name)
        _c(s, f"computer:{sid}", "unconstrained_delegation", uncon)
        if dc:
            _c(s, f"computer:{sid}", "is_dc", True)
    _c(s, "domain:partner.local", "trust_direction", "inbound")
    _c(s, "domain:partner.local", "trust_transitive", False)
    yield s
    s.close()


def run(store, name, **params):
    return run_query(store, QueryRequest(namespace=NS, name=name, params=params))


def keys(page):
    return [r.entity.key for r in page.rows]


def test_ldap_queries_answer_the_audits(store):
    assert keys(run(store, "effective_members", group="group:S-512")) == ["S-2001", "S-2002", "S-2003"]
    assert keys(run(store, "enabled_members", group="Domain Admins")) == ["S-2001", "S-2003"]   # by name
    assert keys(run(store, "account_groups", account="bob")) == ["S-1100", "S-512"]
    page = run(store, "unconstrained_delegation_hosts")
    assert keys(page) == ["S-3002"] and page.rows[0].name == "WEB01"
    assert any("no is_dc value on record (counted as not equal)" in n for n in page.notes)
    trusts = run(store, "domain_trusts")
    assert keys(trusts) == ["partner.local"] and trusts.rows[0].values["trust_transitive"] is False
    assert keys(run(store, "kerberoastable_users")) == ["S-2003"]
    groups = run(store, "effective_members", group="Domain Admins", member_type="group")
    assert keys(groups) == ["S-1100"]
    assert all(r.cites for r in groups.rows)


def test_coverage_turns_a_missing_flag_into_not_set(store):
    from loomctx import coverage
    for pred, seen in (("is_dc", 2), ("enabled", 1)):
        store.record_claim(coverage.claim(NS, "ad-export", "domain:corp.local", pred, seen, 2, T))
    page = run(store, "unconstrained_delegation_hosts")
    assert any("records is_dc as collected, so it is not set on them" in n for n in page.notes)
    page = run_query(store, QueryRequest(namespace=NS, name="effective_members", params={"group": "IT-Admins"}))
    assert keys(page) == ["S-2002", "S-2003"]


def test_parameter_errors_say_what_the_query_takes(store):
    with pytest.raises(QueryError, match="registered: account_groups"):
        run(store, "nope")
    with pytest.raises(QueryError, match="needs parameter 'group'"):
        run(store, "effective_members")
    with pytest.raises(QueryError, match="takes no parameter colour"):
        run(store, "domain_trusts", colour="red")
    with pytest.raises(QueryError, match="no group named 'Schema Admins'"):
        run(store, "effective_members", group="Schema Admins")
    _c(store, "group:S-9512", "name", "Domain Admins")      # a second domain's Domain Admins
    with pytest.raises(QueryError, match="more than one group"):
        run(store, "effective_members", group="Domain Admins")


def test_templates_are_checked_at_registration():
    with pytest.raises(ValidationError, match="the call supplies"):
        QueryDef(name="q", description="d", request={"type": "user", "limit": 5})
    with pytest.raises(ValidationError):
        QueryDef(name="q", description="d", request={"type": "user", "where": [{"predicate": "x", "op": "gt"}]})
    QueryDef(name="q", description="d", params=[QueryParam(name="g", kind="entity")],
             request={"of": "{g}", "via": ["member_of"]})


def test_registration_merges_queries_by_name(store):
    store.put_schema(SchemaRegistration(namespace=NS, queries=[
        QueryDef(name="domain_trusts", description="replaced", request={"type": "domain"}),
        QueryDef(name="all_users", description="every user", request={"type": "user"})]))
    got = {q.name: q for q in store.get_schema(NS).queries}
    assert got["domain_trusts"].description == "replaced"
    assert "all_users" in got and "effective_members" in got
    assert len(store.get_schema(NS).predicates) == len(ldap.schema(NS).predicates)


def test_describe_namespace_lists_queries_and_the_switch_hides_them(store, monkeypatch):
    mcp_server.configure(store)
    try:
        view = mcp_server.describe_namespace(namespace=NS)
        names = [q["name"] for q in view["queries"]]
        assert "effective_members" in names
        eff = next(q for q in view["queries"] if q["name"] == "effective_members")
        assert eff["params"][0].startswith("group (entity: group)")
        monkeypatch.setattr(mcp_server, "_QUERIES_ON", False)
        assert "queries" not in mcp_server.describe_namespace(namespace=NS)
    finally:
        mcp_server.configure(None)


def test_mcp_run_query_takes_params_as_text(store):
    mcp_server.configure(store)
    try:
        async def call(args):
            return await mcp_server.mcp._tool_manager.call_tool("run_query", args, context=None,
                                                                convert_result=True)
        res = asyncio.run(call({"name": "enabled_members", "namespace": NS,
                                "params": '{"group": "Domain Admins"}'}))
        assert not res.is_error, res.content
        view = res.structured_content
        assert view["total"] == 2 and view["notes"][0] == "enabled_members of group:S-512"
        with pytest.raises(Exception, match="needs parameter 'group'"):
            asyncio.run(call({"name": "effective_members", "namespace": NS, "params": {}}))
    finally:
        mcp_server.configure(None)


def test_http_query_route(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "api.db"))
    from loomctx.api.http import app
    with TestClient(app) as client:
        s = app.state.store
        s.put_schema(ldap.schema(NS))
        _c(s, "computer:S-3002", "unconstrained_delegation", True)
        r = client.post("/v1/query", json={"namespace": NS, "name": "unconstrained_delegation_hosts"})
        assert r.status_code == 200, r.text
        assert [row["entity"]["key"] for row in r.json()["rows"]] == ["S-3002"]
        r = client.post("/v1/query", json={"namespace": NS, "name": "nope"})
        assert r.status_code == 422 and "has no query 'nope'" in r.text
