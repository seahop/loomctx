import asyncio
from datetime import datetime, timezone

import pytest

import loom.mcp_server as mcp_server
from loom.contracts import ClaimIn, EntityRef
from loom.store.sqlite import SqliteStore


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
    assert {"find_entity", "ask", "ask_scope", "expand", "record_claim",
            "get_observations", "answer"} <= names


def test_find_entity_returns_handles(store):
    matches = mcp_server.find_entity("web-01")
    assert matches[0]["handle"] == "host:web-01"


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
    for var in ("LOOM_LLM_MODEL", "LOOM_LLM_PROVIDER",
                "LOOM_LLM_BASE_URL", "LOOM_LLM_API_KEY"):
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
        self.headers = {"x-loom-key": key} if key else {}


def _keyed_auth(monkeypatch):
    monkeypatch.setenv("LOOM_API_KEYS", "reader:default:r,writer:default:rw")
    monkeypatch.delenv("LOOM_AUTH_FILE", raising=False)
    from loom.auth import AuthConfig
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
    assert asyncio.run(call([(b"x-loom-key", b"bogus")])) == 403
    assert asyncio.run(call([(b"authorization", b"Bearer reader")])) == 200
    assert seen == ["/mcp"]


def test_find_related_by_meaning(store, monkeypatch):
    from loom.enrich import embed_pending
    from loom.llm import HashingEmbedder
    monkeypatch.setenv("LOOM_EMBED_PROVIDER", "hashing")
    mcp_server._embedder_loaded = False
    try:
        embed_pending(store, HashingEmbedder())
        out = mcp_server.find_related("who logged in with the jdoe account?")
        assert out["matches"] and out["matches"][0]["entity"]["key"] in ("web-01", "jdoe")
        assert out["matches"][0]["evidence"]["citations"]
    finally:
        mcp_server._embedder_loaded = False


def test_list_and_describe_namespaces(store):
    """D-036: an agent can discover where the data is and how it connects."""
    from loom.contracts import PredicateDef, SchemaRegistration
    store.put_schema(SchemaRegistration(namespace="default", predicates=[
        PredicateDef(name="member_of", object_types=["domain"], containment=True)]))
    listed = mcp_server.list_namespaces()
    assert listed == [{"namespace": "default", "entities": {"domain": 1, "host": 2, "user": 2}, "total": 5}]
    desc = mcp_server.describe_namespace("default")
    assert [t["name"] for t in desc["entity_types"]][:1] in (["host"], ["user"])   # sorted by count
    assert desc["predicates"][0]["name"] == "member_of" and desc["predicates"][0]["containment"]
    assert "expand_predicates" in desc["hint"]


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
    monkeypatch.setenv("LOOM_MCP_NAMESPACE", "default")
    reloaded = importlib.reload(mcp_server)
    try:
        reloaded.configure(store)
        assert reloaded._DEFAULT_NS == "default"
        assert reloaded.find_entity("web-01")[0]["handle"] == "host:web-01"
        monkeypatch.setenv("LOOM_MCP_NAMESPACE", "elsewhere")
        reloaded = importlib.reload(mcp_server)
        assert reloaded.ask.__defaults__ is not None and "elsewhere" in reloaded.ask.__defaults__
    finally:
        monkeypatch.delenv("LOOM_MCP_NAMESPACE", raising=False)
        importlib.reload(mcp_server).configure(store)


def test_pack_view_is_shaped_for_agents(store):
    """D-036: items first, no null citation fields, reached subjects summarized."""
    view = mcp_server.ask_scope(["domain:corp.local"], "who logged in?", expand_predicates=["member_of"],
                                depth=1, budget=2000)
    keys = list(view)
    assert keys.index("items") < keys.index("subjects") and view["subjects_total"] == 3
    assert all(None not in c.values() for i in view["items"] for c in i["citations"])
    assert "omitted_handles" in view and "subjects_note" not in view
    mcp_server._SUBJECTS_SHOWN, saved = 1, mcp_server._SUBJECTS_SHOWN
    try:
        view = mcp_server.ask_scope(["domain:corp.local"], "who?", expand_predicates=["member_of"], depth=1)
        assert len(view["subjects"]) == 1 and "2 more" in view["subjects_note"]
    finally:
        mcp_server._SUBJECTS_SHOWN = saved


def test_agent_view_warns_about_partial_coverage(store, monkeypatch):
    import loom.context as ctx
    monkeypatch.setattr(ctx, "_GATHER_LIMIT", 1)
    view = mcp_server.ask("host:web-01", "who?", budget=2000)
    assert view["truncated"][0]["entity"] == {"type": "host", "key": "web-01"}
    assert "do not conclude" in view["coverage_warning"] and "host:web-01" in view["coverage_warning"]


def test_pack_view_offers_a_short_cite_token(store):
    """D-041: models mangle hand-copied 32-hex ids; a 12-hex token is what to
    cite — and once it stands for the observation, the 32-hex id is dropped
    from the view (compact citations; source and observed_at stay)."""
    view = mcp_server.ask("host:web-01", "who logged in?", budget=2000)
    cites = [c for i in view["items"] for c in i["citations"]]
    assert cites and all(len(c["cite"]) == 12 and "observation_id" not in c for c in cites)
    assert all(c["source"] and c["observed_at"] for c in cites)
    ids = {o.id for o in store.observations_for("default", EntityRef(type="host", key="web-01"))}
    assert all(any(i.startswith(c["cite"]) for i in ids) for c in cites)


def test_cite_tokens_resolve_through_expand_and_get_observations(store):
    """The tools that take an observation id take its 12-hex cite token too,
    via the store's prefix lookup; without one, full ids still work and the
    token is refused with a reason."""
    from mcp.server.mcpserver.exceptions import ToolError
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))[0]
    full = mcp_server.expand(obs.id)
    assert full["count"] == 1 and full["observations"][0]["id"] == obs.id
    assert mcp_server.get_observations(obs.id)["observations"][0]["predicate"] == obs.predicate
    with pytest.raises(ToolError, match="full"):
        mcp_server.expand(obs.id[:12])
    store.observations_by_prefix = lambda ns, prefix: [o for o in store.iter_observations(ns) if o.id.startswith(prefix)]
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
    monkeypatch.setenv("LOOM_API_KEYS", "reader:default:r,admin:*:rw")
    monkeypatch.delenv("LOOM_AUTH_FILE", raising=False)
    from loom.auth import AuthConfig
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
    monkeypatch.delenv("LOOM_API_KEYS")
    monkeypatch.setenv("LOOM_AUTH_FILE", str(keys))
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
