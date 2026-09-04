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
