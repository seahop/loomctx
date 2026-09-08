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


def test_answer_without_llm_returns_guidance(store, monkeypatch):
    for var in ("LOOM_LLM_MODEL", "LOOM_LLM_PROVIDER",
                "LOOM_LLM_BASE_URL", "LOOM_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    result = mcp_server.answer("what about web-01?")
    assert "error" in result and "ask tool" in result["error"]


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
