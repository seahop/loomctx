import asyncio
import json
from datetime import datetime, timezone

import pytest

import loomctx.mcp_server as mcp_server
from loomctx.contracts import ClaimIn, EntityRef
from loomctx.store.sqlite import SqliteStore


@pytest.fixture
def store(tmp_path):
    s = SqliteStore(tmp_path / "mcp.db")
    domain = EntityRef(type="domain", key="corp.local")
    for host, user in [("web-01", "jdoe"), ("db-01", "asmith")]:
        s.record_claim(ClaimIn(
            subject=EntityRef(type="host", key=host), predicate="member_of",
            object=domain,
            observed_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
            source="inventory",
        ))
        s.record_claim(ClaimIn(
            subject=EntityRef(type="host", key=host), predicate="logged_in_by",
            object=EntityRef(type="user", key=user),
            observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
            source="auth-log",
        ))
    mcp_server.configure(s)
    yield s
    mcp_server.configure(None)
    s.close()


def test_all_tools_are_registered(store):
    names = {t.name for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert {"find_entity", "ask", "ask_scope", "find_path", "expand", "record_claim",
            "get_observations", "answer"} <= names


def test_find_path_input_schema_exposes_from(store):
    tool = next(t for t in asyncio.run(mcp_server.mcp.list_tools()) if t.name == "find_path")
    schema = getattr(tool, "input_schema", None) or tool.inputSchema
    props = schema["properties"]
    assert "from" in props and "to" in props and "from_" not in props


def test_find_path_connects_user_to_domain(store):
    view = mcp_server.find_path(
        from_="user:jdoe", to="domain:corp.local",
        via=["logged_in_by", "member_of"], depth=2, budget=2000)
    assert view["paths"], view
    arrow = view["paths"][0]["text"]
    assert arrow.startswith("user:jdoe") and "domain:corp.local" in arrow
    assert view["paths"][0]["cites"]
    assert view["from"]["key"] == "jdoe" and view["to"]["key"] == "corp.local"
    # list-args-as-text tolerance (D-064): a stringified list is read as a list
    view2 = mcp_server.find_path(
        from_="user:jdoe", to="domain:corp.local",
        via="['logged_in_by', 'member_of']", depth=2, budget=2000)
    assert view2["paths"]


def test_find_path_through_the_tool_manager(store):
    """The SDK dumps a tool's arguments keyed by alias, so find_path is
    invoked with from=... — a real tools/call must reach it (it raised an
    opaque TypeError on every call before the alias was mapped back)."""
    async def call(args):
        return await mcp_server.mcp._tool_manager.call_tool(
            "find_path", args, context=None, convert_result=True)

    res = asyncio.run(call({"from": "user:jdoe", "to": "domain:corp.local",
                            "via": ["logged_in_by", "member_of"], "depth": 2}))
    assert not res.is_error, res.content
    view = res.structured_content
    assert view["from"] == {"type": "user", "key": "jdoe"} and view["paths"]
    assert view["paths"][0]["text"].startswith("user:jdoe")


def test_find_entity_returns_handles(store):
    matches = mcp_server.find_entity("web-01")
    assert matches[0]["handle"] == "host:web-01"


def test_ask_scope_walks_an_over_deep_request_to_the_cap_and_says_so(store):
    """D-092: depth=5 was a validation error, and agents read it as 'this
    cannot be done'. It is walked at the cap, with a note."""
    view = mcp_server.ask_scope(["host:web-01"], "who logged in?", expand_predicates=["logged_in_by"], depth=5)
    assert view["notes"][0].startswith(f"depth 5 is above the cap of {mcp_server.SCOPE_DEPTH_CAP}")
    assert mcp_server.SCOPE_DEPTH_CAP == 3


def test_find_entity_finds_an_opaque_key_by_name_and_shows_it(store):
    from loomctx.contracts import PredicateDef, SchemaRegistration
    store.put_schema(SchemaRegistration(namespace="default", predicates=[PredicateDef(name="sam", label=True)]))
    store.record_claim(ClaimIn(subject=EntityRef(type="user", key="S-1-5-21-9-1101"), predicate="sam",
                               object="dlee", observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
                               source="ldap"))
    [match] = mcp_server.find_entity("dlee")
    assert match["handle"] == "user:S-1-5-21-9-1101" and match["name"] == "dlee"
    assert "name" not in mcp_server.find_entity("web-01")[0]     # found by its key: nothing to add
    # D-095: the account written with its realm, as agents write it
    for spelled in ("dlee@dev.local", "DEV\\dlee"):
        [match] = mcp_server.find_entity(spelled)
        assert match["handle"] == "user:S-1-5-21-9-1101" and match["name"] == "dlee", spelled
    assert mcp_server.find_entity("nobody@dev.local") == []


def test_ask_and_expand_roundtrip(store):
    pack = mcp_server.ask("host:web-01", "who logged in?", budget=2000)
    assert any("jdoe" in i["text"] for i in pack["items"])
    tight = mcp_server.ask("host:web-01", "who logged in?", budget=60)
    if tight["handles"]:
        expanded = mcp_server.expand(tight["handles"][0]["id"], budget=2000)
        assert expanded["items"]


def test_ask_scope_covers_domain_members(store):
    pack = mcp_server.ask_scope(
        ["domain:corp.local"], "who logged in?",
        expand_predicates=["member_of"], budget=3000,
    )
    text = " | ".join(i["text"] for i in pack["items"])
    assert "jdoe" in text and "asmith" in text


def test_record_claim_writeback(store):
    result = mcp_server.record_claim(
        subject="host:web-01", predicate="runs_os",
        observed_at="2026-09-03T12:00:00Z", source="agent-writeback",
        object_value="fedora-44",
    )
    assert result["status"] == "recorded"
    raw = mcp_server.get_observations("host:web-01")
    assert any(o["source"] == "agent-writeback" for o in raw["observations"])


def test_record_claim_requires_exactly_one_object(store):
    with pytest.raises(ValueError):
        mcp_server.record_claim(
            subject="host:web-01", predicate="p",
            observed_at="2026-09-03T12:00:00Z", source="s",
        )
    with pytest.raises(ValueError):
        mcp_server.record_claim(
            subject="host:web-01", predicate="p",
            observed_at="2026-09-03T12:00:00Z", source="s",
            object_ref="user:jdoe", object_value="x",
        )


def test_bad_handle_is_a_clear_error(store):
    with pytest.raises(ValueError, match="type:key"):
        mcp_server.ask("web-01", "q")


def test_answer_without_llm_is_a_tool_error(store, monkeypatch):
    """Every tool fails one way — a ToolError — never an {"error": …}
    payload an agent could read as data."""
    from mcp.server.mcpserver.exceptions import ToolError
    for var in ("LOOMCTX_LLM_MODEL", "LOOMCTX_LLM_PROVIDER",
                "LOOMCTX_LLM_BASE_URL", "LOOMCTX_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    mcp_server._llm_loaded = False
    try:
        with pytest.raises(ToolError, match="ask tool"):
            mcp_server.answer("what about web-01?")
    finally:
        mcp_server._llm_loaded = False
    mcp_server._embedder_loaded = False
    mcp_server._embedder = None
    mcp_server._embedder_loaded = True
    try:
        with pytest.raises(ToolError, match="find_entity"):
            mcp_server.find_related("what looks exploitable?")
    finally:
        mcp_server._embedder_loaded = False


def test_call_tool_through_mcp_layer(store):
    result = asyncio.run(
        mcp_server.mcp.call_tool("find_entity", {"query": "web-01"})
    )
    assert "host:web-01" in str(result)


# ------------------------------------------------------------- auth (H-A9) #

class _Ctx:
    def __init__(self, key=None):
        self.headers = {"x-loomctx-key": key} if key else {}


def _keyed_auth(monkeypatch):
    monkeypatch.setenv("LOOMCTX_API_KEYS", "reader:default:r,writer:default:rw")
    monkeypatch.delenv("LOOMCTX_AUTH_FILE", raising=False)
    from loomctx.auth import AuthConfig
    return AuthConfig.from_env()


def test_stdio_transport_is_local_trust(store, monkeypatch):
    auth = _keyed_auth(monkeypatch)
    mcp_server.configure(store, auth=auth, transport="stdio")
    assert mcp_server.find_entity("web-01")  # no headers, no gate


def test_http_transport_requires_key_per_tool_call(store, monkeypatch):
    auth = _keyed_auth(monkeypatch)
    mcp_server.configure(store, auth=auth, transport="streamable-http")
    with pytest.raises(PermissionError, match="API key"):
        mcp_server.find_entity("web-01", ctx=_Ctx())
    with pytest.raises(PermissionError):
        mcp_server.ask("host:web-01", "who?", ctx=_Ctx("nope"))
    assert mcp_server.find_entity("web-01", ctx=_Ctx("reader"))
    pack = mcp_server.ask("host:web-01", "who logged in?", budget=2000, ctx=_Ctx("reader"))
    assert any("jdoe" in i["text"] for i in pack["items"])
    with pytest.raises(PermissionError, match="'w'"):
        mcp_server.record_claim(subject="host:web-01", predicate="p",
                                observed_at="2026-09-03T12:00:00Z", source="s",
                                object_value="v", ctx=_Ctx("reader"))
    assert mcp_server.record_claim(subject="host:web-01", predicate="p",
                                   observed_at="2026-09-03T12:00:00Z", source="s",
                                   object_value="v", ctx=_Ctx("writer"))["status"] == "recorded"
    with pytest.raises(PermissionError, match="namespace"):
        mcp_server.ask("host:web-01", "who?", namespace="secret", ctx=_Ctx("reader"))


def test_ctx_parameter_is_hidden_from_tool_schemas(store):
    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    for name in ("find_entity", "ask", "ask_scope", "expand", "record_claim",
                 "get_observations", "answer"):
        assert "ctx" not in tools[name].input_schema.get("properties", {}), name


def test_key_gate_middleware_rejects_before_mcp(monkeypatch):
    auth = _keyed_auth(monkeypatch)
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    gate = mcp_server.KeyGate(inner, auth)

    async def call(headers):
        out = []

        async def send(m):
            out.append(m)

        await gate({"type": "http", "path": "/mcp", "headers": headers}, None, send)
        return out[0]["status"]

    assert asyncio.run(call([])) == 401
    assert asyncio.run(call([(b"x-loomctx-key", b"bogus")])) == 403
    assert asyncio.run(call([(b"authorization", b"Bearer reader")])) == 200
    assert seen == ["/mcp"]


def test_find_related_by_meaning(store, monkeypatch):
    from loomctx.enrich import embed_pending
    from loomctx.llm import HashingEmbedder
    monkeypatch.setenv("LOOMCTX_EMBED_PROVIDER", "hashing")
    mcp_server._embedder_loaded = False
    try:
        embed_pending(store, HashingEmbedder())
        out = mcp_server.find_related("who logged in with the jdoe account?")
        assert out.matches and out.matches[0].entity.key in ("web-01", "jdoe")
        assert out.matches[0].evidence.citations
    finally:
        mcp_server._embedder_loaded = False


def test_list_and_describe_namespaces(store):
    """D-036: an agent can discover where the data is and how it connects."""
    from loomctx.contracts import PredicateDef, SchemaRegistration
    store.put_schema(SchemaRegistration(namespace="default", predicates=[
        PredicateDef(name="member_of", object_types=["domain"], containment=True)]))
    listed = mcp_server.list_namespaces()
    assert listed == [{"namespace": "default", "entities": {"domain": 1, "host": 2, "user": 2}, "total": 5}]
    desc = mcp_server.describe_namespace("default")
    assert [t["name"] for t in desc["entity_types"]][:1] in (["host"], ["user"])   # sorted by count
    assert desc["predicates"][0]["name"] == "member_of" and desc["predicates"][0]["containment"]
    assert "expand_predicates" in desc["hint"]



def test_describe_namespace_shows_each_types_links(store):
    """D-064: a two-hop path must be visible before the agent asks — the
    registry names a predicate's object types, never its subjects. Each
    type lists the predicates leaving and arriving with the other end's
    type, and the attributes it carries; the hint's example path is one
    the namespace actually has."""
    at = datetime(2026, 9, 2, tzinfo=timezone.utc)
    web = EntityRef(type="host", key="web-01")
    nginx = EntityRef(type="product", key="nginx")
    cve = EntityRef(type="cve", key="CVE-1")
    store.record_claims([
        ClaimIn(subject=web, predicate="runs_software", object=nginx, observed_at=at, source="inv"),
        ClaimIn(subject=cve, predicate="affects", object=nginx, observed_at=at, source="nvd"),
        ClaimIn(subject=cve, predicate="exploited_in_wild", object=True, observed_at=at, source="kev"),
        ClaimIn(subject=cve, predicate="has_nothing", object=EntityRef(type="thing", key="x"),
                observed_at=at, source="nvd"),
    ])
    mcp_server.configure(store)
    types = {t["name"]: t for t in mcp_server.describe_namespace("default")["entity_types"]}
    assert "-runs_software-> product" in types["host"]["links"]
    assert "-member_of-> domain" in types["host"]["links"]
    assert types["product"]["links"] == ["<-affects- cve", "<-runs_software- host"] or \
        set(types["product"]["links"]) == {"<-affects- cve", "<-runs_software- host"}
    assert "-affects-> product" in types["cve"]["links"] and types["cve"]["attributes"] == ["exploited_in_wild"]
    assert "attributes" not in types["host"]
    hint = mcp_server.describe_namespace("default")["hint"]
    assert "-> " in hint and "depth=2" in hint
    # a type-scoped key sees only links among its own types
    import hashlib
    from loomctx.auth import AuthConfig, _parse_file
    auth = AuthConfig(_parse_file(json.dumps({"keys": [{
        "id": "k", "sha256": hashlib.sha256(b"k").hexdigest(), "namespaces": ["default"], "perms": "r",
        "entity_types": ["host", "product"]}]})))
    mcp_server.configure(store, auth=auth, transport="streamable-http")

    class Ctx:
        headers = {"x-loomctx-key": "k"}
    scoped = {t["name"]: t for t in mcp_server.describe_namespace("default", ctx=Ctx())["entity_types"]}
    assert set(scoped) == {"host", "product"}
    assert scoped["product"]["links"] == ["<-runs_software- host"]
    assert not any("cve" in link or "user" in link for t in scoped.values() for link in t.get("links", []))
    mcp_server.configure(store)


def test_describe_namespace_caps_a_types_links():
    from loomctx.mcp_server import _LINKS_SHOWN, _capped
    many = [f"-p{i}-> t" for i in range(_LINKS_SHOWN + 3)]
    assert _capped(many, _LINKS_SHOWN) == many[:_LINKS_SHOWN] + ["+3 more"]
    assert _capped(many[:2], _LINKS_SHOWN) == many[:2]


def test_scope_pack_notes_reach_the_agent(store):
    """D-064: an expand predicate the namespace does not know was ignored
    in silence; the concise view now carries a `notes` list, before the
    items, naming it and the closest known predicates."""
    pack = mcp_server.ask_scope(["domain:corp.local"], "who logged in?",
                                expand_predicates=["member_off"])
    assert pack["budget"] == mcp_server.SCOPE_BUDGET_DEFAULT
    assert list(pack)[list(pack).index("items") - 1] == "notes"
    assert "'member_off'" in pack["notes"][0] and "closest: member_of" in pack["notes"][0]
    plain = mcp_server.ask_scope(["domain:corp.local"], "who logged in?", expand_predicates=["member_of"])
    assert "notes" not in plain
    missing = mcp_server.ask("hostt:web-01", "who logged in?")
    assert missing["notes"] == ["no entity 'hostt:web-01' in namespace 'default'; "
                                "entities with that key or name: host:web-01"]


def test_unknown_namespace_is_an_error_not_an_empty_answer(store):
    """D-036: a live agent dropped the namespace argument and spent twelve
    steps querying an empty 'default'. Now it is told, and told what exists."""
    with pytest.raises(ValueError, match="holds no data.*default"):
        mcp_server.find_entity("web-01", namespace="nowhere")
    with pytest.raises(ValueError, match="pass namespace"):
        mcp_server.ask("host:web-01", "?", namespace="nowhere")
    with pytest.raises(ValueError):
        mcp_server.describe_namespace("nowhere")


def test_expand_explains_what_a_handle_is(store):
    from mcp.server.mcpserver.exceptions import ToolError
    with pytest.raises(ValueError, match="handles.*list.*h1_.*cite"):
        mcp_server.expand("host:web-01")
    # an observation id is accepted now; an unknown one says so
    with pytest.raises(ToolError, match="no observation"):
        mcp_server.expand("fb5945447eaf409e85fd0f2422b422c8")


def test_default_namespace_comes_from_the_environment(store, monkeypatch):
    import importlib
    monkeypatch.setenv("LOOMCTX_MCP_NAMESPACE", "default")
    reloaded = importlib.reload(mcp_server)
    try:
        reloaded.configure(store)
        assert reloaded._DEFAULT_NS == "default"
        assert reloaded.find_entity("web-01")[0]["handle"] == "host:web-01"
        monkeypatch.setenv("LOOMCTX_MCP_NAMESPACE", "elsewhere")
        reloaded = importlib.reload(mcp_server)
        assert reloaded.ask.__defaults__ is not None and "elsewhere" in reloaded.ask.__defaults__
    finally:
        monkeypatch.delenv("LOOMCTX_MCP_NAMESPACE", raising=False)
        importlib.reload(mcp_server).configure(store)


def test_pack_view_is_shaped_for_agents(store):
    """D-036: items first, no null citation fields, reached subjects summarized."""
    view = mcp_server.ask_scope(["domain:corp.local"], "who logged in?", expand_predicates=["member_of"],
                                depth=1, budget=2000)
    keys = list(view)
    assert keys.index("items") < keys.index("subjects") and view["subjects_total"] == 3
    assert all(i["cites"] and all(c.count(" ") >= 2 for c in i["cites"]) for i in view["items"])
    assert 0 < view["charged_tokens"] <= view["budget"]
    assert "omitted_handles" in view and "subjects_note" not in view
    mcp_server._SUBJECTS_SHOWN, saved = 1, mcp_server._SUBJECTS_SHOWN
    try:
        view = mcp_server.ask_scope(["domain:corp.local"], "who?", expand_predicates=["member_of"], depth=1)
        assert len(view["subjects"]) == 1 and "2 more" in view["subjects_note"]
    finally:
        mcp_server._SUBJECTS_SHOWN = saved


def test_agent_view_warns_about_partial_coverage(store, monkeypatch):
    import loomctx.context as ctx
    monkeypatch.setattr(ctx, "_GATHER_LIMIT", 1)
    view = mcp_server.ask("host:web-01", "who?", budget=2000)
    assert view["truncated"][0]["entity"] == {"type": "host", "key": "web-01"}
    assert "do not conclude" in view["coverage_warning"] and "host:web-01" in view["coverage_warning"]


def test_pack_view_offers_a_short_cite_token(store):
    """D-041: models mangle hand-copied 32-hex ids; a 12-hex token is what to
    cite — and once it stands for the observation, the 32-hex id is dropped
    from the view. Concise citations are one string each, token first
    ("<cite> <source> <date>"), the form the budget charges (D-058)."""
    view = mcp_server.ask("host:web-01", "who logged in?", budget=2000)
    cites = [c.split(" ") for i in view["items"] for c in i["cites"]]
    assert cites and all(len(c) == 3 and len(c[0]) == 12 for c in cites)
    assert all(c[1] and len(c[2]) == 10 for c in cites)          # source, then YYYY-MM-DD
    ids = {o.id for o in store.observations_for("default", EntityRef(type="host", key="web-01"))}
    assert all(any(i.startswith(c[0]) for i in ids) for c in cites)
    assert not any(i in json.dumps(view) for i in ids)          # no 32-hex id rides along


def test_cite_tokens_resolve_through_expand_and_get_observations(store):
    """The tools that take an observation id take its 12-hex cite token too,
    via the store's prefix lookup (`observations_by_prefix`, D-049); a store
    without one still resolves full ids and refuses the token with a reason."""
    from mcp.server.mcpserver.exceptions import ToolError
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))[0]
    full = mcp_server.expand(obs.id)
    assert full["count"] == 1 and full["observations"][0]["id"] == obs.id
    assert mcp_server.get_observations(obs.id)["observations"][0]["predicate"] == obs.predicate
    real = store.observations_by_prefix
    store.observations_by_prefix = None   # a store generation without the lookup
    with pytest.raises(ToolError, match="full"):
        mcp_server.expand(obs.id[:12])
    store.observations_by_prefix = real
    assert mcp_server.expand(obs.id[:12])["observations"][0]["id"] == obs.id
    assert mcp_server.get_observations(obs.id[:12])["observations"][0]["id"] == obs.id
    with pytest.raises(ToolError, match="no observation"):
        mcp_server.expand("0" * 12)
    with pytest.raises(ToolError, match="no observation"):
        mcp_server.expand("0" * 32)


def test_scoped_key_never_learns_other_namespaces(store, monkeypatch, tmp_path):
    """list_namespaces skipped the grant entirely, and the empty-namespace
    error named every namespace in the store."""
    store.record_claim(ClaimIn(
        namespace="secret", subject=EntityRef(type="host", key="vault-01"), predicate="runs_os",
        object="openbsd", observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc), source="inv"))
    monkeypatch.setenv("LOOMCTX_API_KEYS", "reader:default:r,admin:*:rw")
    monkeypatch.delenv("LOOMCTX_AUTH_FILE", raising=False)
    from loomctx.auth import AuthConfig
    mcp_server.configure(store, auth=AuthConfig.from_env(), transport="streamable-http")
    assert [n["namespace"] for n in mcp_server.list_namespaces(ctx=_Ctx("reader"))] == ["default"]
    assert [n["namespace"] for n in mcp_server.list_namespaces(ctx=_Ctx("admin"))] == ["default", "secret"]
    with pytest.raises(PermissionError, match="API key"):
        mcp_server.list_namespaces(ctx=_Ctx())
    with pytest.raises(ValueError) as exc:
        mcp_server.find_entity("x", namespace="nowhere", ctx=_Ctx("admin"))
    assert "secret" in str(exc.value)
    # a key granted two namespaces, one of them empty: the error for the
    # empty one names only what that key may read
    import hashlib
    import json
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": [{"id": "two", "sha256": hashlib.sha256(b"two").hexdigest(),
                                          "namespaces": ["default", "empty"], "perms": "r"}]}))
    monkeypatch.delenv("LOOMCTX_API_KEYS")
    monkeypatch.setenv("LOOMCTX_AUTH_FILE", str(keys))
    mcp_server.configure(store, auth=AuthConfig.from_env(), transport="streamable-http")
    with pytest.raises(ValueError) as exc:
        mcp_server.find_entity("x", namespace="empty", ctx=_Ctx("two"))
    assert "default" in str(exc.value) and "secret" not in str(exc.value)
    assert [n["namespace"] for n in mcp_server.list_namespaces(ctx=_Ctx("two"))] == ["default"]


def test_namespace_summary_is_cached_briefly(store, monkeypatch):
    calls = []
    real = store.namespace_summary

    def counted():
        calls.append(1)
        return real()

    monkeypatch.setattr(store, "namespace_summary", counted)
    mcp_server.configure(store)                       # resets the cache
    mcp_server.list_namespaces(); mcp_server.describe_namespace("default"); mcp_server.find_entity("web-01")
    assert len(calls) == 1
    mcp_server._summary_cache = None
    mcp_server.list_namespaces()
    assert len(calls) == 2


# ------------------------------------------------- MCP 2026-07-28 alignment (R-7) #

def test_every_tool_publishes_an_output_schema_title_and_annotations(store):
    """R-7: structured content with a schema derived from the contracts,
    a title, and honest hints — read tools read-only, nothing destructive
    (observations are append-only), nothing open-world."""
    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert set(tools) == set(mcp_server.TOOL_META)
    for name, tool in tools.items():
        assert tool.output_schema and tool.output_schema.get("type", "object") == "object", name
        assert tool.title == mcp_server.TOOL_META[name][0], name
        ann = tool.annotations
        assert ann.read_only_hint is mcp_server.TOOL_META[name][1], name
        assert ann.destructive_hint is False and ann.open_world_hint is False, name
        assert ann.idempotent_hint is mcp_server.TOOL_META[name][2], name
    # the pack schema is the agent view of ContextPack: items, cite tokens,
    # the contract's own handle/subject shapes, and the format knob
    pack = tools["ask"].output_schema
    props = pack["properties"]
    assert {"items", "handles", "subjects", "subjects_total", "format", "omitted_handles"} <= set(props)
    assert "cite" in pack["$defs"]["AgentCitation"]["properties"]
    assert "ExpansionHandle" in pack["$defs"] and "EntityRef" in pack["$defs"]
    assert props["format"]["enum"] == ["concise", "detailed"]
    assert "subjects_note" not in pack.get("required", [])
    assert tools["record_claim"].output_schema["required"] == ["status", "observation_id", "event_id"]
    assert "Observation" in tools["get_observations"].output_schema["$defs"]
    assert "anyOf" in tools["expand"].output_schema                # a pack, or one observation
    assert "matches" in tools["find_related"].output_schema["properties"]
    for name in ("ask", "ask_scope", "expand"):
        assert tools[name].input_schema["properties"]["format"]["default"] == "concise", name
    assert "supersedes" in tools["record_claim"].input_schema["properties"]
    assert "event_id" in tools["record_claim"].input_schema["properties"]


def test_ask_scope_reads_a_list_sent_as_text(store):
    """D-064 smoke run: qwen3-coder sent expand_predicates="['runs_software']"
    and the schema refused it twice. Through the MCP layer (the SDK
    validates arguments), bracketed list text — JSON, Python-style, or
    unquoted — is the list it spells; a bare string is one item."""
    from loomctx.mcp_server import _listed
    assert _listed("['runs_software', 'affects']") == ["runs_software", "affects"]
    assert _listed('["member_of"]') == ["member_of"]
    assert _listed("[member_of, logged_in_by]") == ["member_of", "logged_in_by"]
    assert _listed(None) == [] and _listed(["a"]) == ["a"] and _listed("[]") == []
    # a bare string is never comma-split: a key may hold commas (an LDAP DN)
    assert _listed("user:CN=Bob,OU=Staff,DC=corp") == ["user:CN=Bob,OU=Staff,DC=corp"]
    assert _listed("member_of") == ["member_of"] and _listed("  ") == []

    async def call(args):
        return await mcp_server.mcp._tool_manager.call_tool("ask_scope", args, context=None, convert_result=True)

    res = asyncio.run(call({"subjects": '["domain:corp.local"]', "question": "who logged in?",
                            "expand_predicates": "['member_of']"}))
    assert not res.is_error
    assert {s["key"] for s in res.structured_content["subjects"]} >= {"web-01", "db-01"}


def test_tool_calls_return_structured_content_matching_the_schema(store):
    """The SDK validates the return value against the published schema and
    ships it as structuredContent next to the text mirror."""
    async def call(name, args):
        return await mcp_server.mcp._tool_manager.call_tool(name, args, context=None, convert_result=True)

    res = asyncio.run(call("ask", {"subject": "host:web-01", "question": "who logged in?", "budget": 2000}))
    assert not res.is_error and res.structured_content["items"] and res.structured_content["format"] == "concise"
    assert res.content and res.content[0].type == "text" and '"items"' in res.content[0].text
    res = asyncio.run(call("find_entity", {"query": "web-01"}))
    assert res.structured_content["result"][0]["handle"] == "host:web-01"     # a list is wrapped
    res = asyncio.run(call("list_namespaces", {}))
    assert res.structured_content["result"][0]["namespace"] == "default"
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))[0]
    res = asyncio.run(call("expand", {"handle": obs.id[:12]}))
    assert res.structured_content["count"] == 1 and res.structured_content["observations"][0]["id"] == obs.id
    res = asyncio.run(call("record_claim", {"subject": "host:web-01", "predicate": "p", "object_value": "v",
                                             "observed_at": "2026-09-03T12:00:00Z", "source": "s"}))
    assert res.structured_content["status"] == "recorded" and res.structured_content["event_id"].startswith("mcp:")


def test_detailed_format_keeps_ids_and_lists_every_subject(store):
    concise = mcp_server.ask("host:web-01", "who logged in?", budget=2000)
    detailed = mcp_server.ask("host:web-01", "who logged in?", budget=2000, format="detailed")
    assert concise["format"] == "concise" and detailed["format"] == "detailed"
    c_cites = [c for i in concise["items"] for c in i["cites"]]
    d_cites = [c for i in detailed["items"] for c in i["citations"]]
    assert c_cites and all(isinstance(c, str) for c in c_cites)
    assert all("score" not in i and "citations" not in i for i in concise["items"])
    assert all("score" in i and "cites" not in i for i in detailed["items"])
    assert d_cites and all(len(c["observation_id"]) == 32 and c["observation_id"].startswith(c["cite"])
                           for c in d_cites)
    mcp_server._SUBJECTS_SHOWN, saved = 1, mcp_server._SUBJECTS_SHOWN
    try:
        short = mcp_server.ask_scope(["domain:corp.local"], "who?", expand_predicates=["member_of"])
        full = mcp_server.ask_scope(["domain:corp.local"], "who?", expand_predicates=["member_of"],
                                    format="detailed")
        assert len(short["subjects"]) == 1 and "subjects_note" in short
        assert len(full["subjects"]) == full["subjects_total"] == 3 and "subjects_note" not in full
    finally:
        mcp_server._SUBJECTS_SHOWN = saved
    if concise["handles"]:
        assert mcp_server.expand(concise["handles"][0]["id"], format="detailed")["format"] == "detailed"
    with pytest.raises(ValueError, match="concise"):
        mcp_server.ask("host:web-01", "?", format="verbose")


def test_record_claim_is_idempotent_by_content_and_accepts_an_event_id(store):
    kw = dict(subject="host:web-01", predicate="runs_os", observed_at="2026-09-03T12:00:00Z",
              source="agent-writeback", object_value="fedora-44")
    first = mcp_server.record_claim(**kw)
    again = mcp_server.record_claim(**kw)
    assert first == again and first["event_id"].startswith("mcp:")
    other = mcp_server.record_claim(**{**kw, "observed_at": "2026-09-04T12:00:00Z"})
    assert other["observation_id"] != first["observation_id"]
    explicit = mcp_server.record_claim(**{**kw, "event_id": "agent:42"})
    assert explicit["event_id"] == "agent:42"
    assert mcp_server.record_claim(**{**kw, "event_id": "agent:42", "object_value": "x"})["observation_id"] \
        == explicit["observation_id"]                                     # redelivery: same event, nothing new
    n = sum(1 for o in store.observations_for("default", EntityRef(type="host", key="web-01"))
            if o.source == "agent-writeback")
    assert n == 3


def test_record_claim_supersedes_resolves_a_cite_token(store):
    """A recorded correction: the new claim names the observation it
    replaces by its cite token (or full id) and ClaimIn.supersedes carries
    the resolved 32-hex id. Never inferred — an unknown token is an error."""
    from mcp.server.mcpserver.exceptions import ToolError
    old = mcp_server.record_claim(subject="host:web-01", predicate="runs_os", object_value="fedora-43",
                                  observed_at="2026-09-01T12:00:00Z", source="inventory")
    recorded = []
    real = store.record_claim

    def spy(claim):
        recorded.append(claim)
        return real(claim)

    store.record_claim = spy
    try:
        fixed = mcp_server.record_claim(subject="host:web-01", predicate="runs_os", object_value="fedora-44",
                                        observed_at="2026-09-02T12:00:00Z", source="inventory",
                                        supersedes=old["observation_id"][:12])
        assert fixed["supersedes"] == old["observation_id"] and fixed["observation_id"] != old["observation_id"]
        assert recorded[-1].supersedes == old["observation_id"]
        by_id = mcp_server.record_claim(subject="host:web-01", predicate="runs_os", object_value="fedora-45",
                                        observed_at="2026-09-03T12:00:00Z", source="inventory",
                                        supersedes=old["observation_id"])
        assert by_id["supersedes"] == old["observation_id"]
    finally:
        store.record_claim = real
    with pytest.raises(ToolError, match="no observation"):
        mcp_server.record_claim(subject="host:web-01", predicate="runs_os", object_value="x",
                                observed_at="2026-09-03T12:00:00Z", source="inventory", supersedes="0" * 12)
    with pytest.raises(ValueError, match="cite"):
        mcp_server.record_claim(subject="host:web-01", predicate="runs_os", object_value="x",
                                observed_at="2026-09-03T12:00:00Z", source="inventory", supersedes="host:web-01")


def test_instructions_and_descriptions_carry_the_agent_guidance(store):
    text = mcp_server.INSTRUCTIONS
    for word in ("cite", "format", "truncated", "supersedes", "4000", "3000", "ask_scope", "links", "notes"):
        assert word in text, word
    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert "ONE entity" in tools["ask"].description and "SEVERAL" in tools["ask_scope"].description
    for word in ("stateless", "signed", "never expire", "TTL", "rotation", "budget"):
        assert word in tools["expand"].description, word
    assert "never inferred" in tools["record_claim"].description


def test_main_closes_the_store_on_the_way_out(monkeypatch):
    """D-063: a Postgres pool left to interpreter shutdown printed a
    PythonFinalizationError after every stdio session; main() closes it,
    also when the server exits with an error."""
    import pytest
    import loomctx.mcp_server as ms
    closed = []
    fake = type("S", (), {"close": lambda self: closed.append(True)})()

    def boom():
        ms._store = fake
        raise KeyboardInterrupt
    monkeypatch.setattr(ms, "_main", boom)
    with pytest.raises(KeyboardInterrupt):
        ms.main()
    assert closed == [True] and ms._store is None


def test_start_up_warms_what_describe_namespace_reads(store, monkeypatch):
    """D-102: a stdio server starts per session; the warm-up computes the
    relation summary while the agent's first turn runs, and a concurrent
    describe_namespace reuses it instead of running its own GROUP BY."""
    calls = []
    real = store.relation_summary
    monkeypatch.setattr(store, "relation_summary", lambda ns: calls.append(ns) or real(ns))
    mcp_server._warm()
    assert calls == [mcp_server._DEFAULT_NS]
    mcp_server.describe_namespace(mcp_server._DEFAULT_NS)
    assert calls == [mcp_server._DEFAULT_NS]          # served from the warm cache
