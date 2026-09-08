"""Drive the MCP server the way an agent does: a real MCP client over stdio
(the transport `claude mcp add` uses), spawning `python -m loom.mcp_server`
as a subprocess against a seeded database. Exercises the wire protocol,
tool schemas, and the find -> ask -> expand -> record_claim loop end to end.
"""

import asyncio
import json
import os
import sys

import pytest

from loom.seed import cmd_load


@pytest.fixture(scope="module")
def seeded_db(tmp_path_factory):
    db = tmp_path_factory.mktemp("mcpclient") / "seed.db"
    cmd_load(str(db), seed=42)
    return db


async def _session(db, fn):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = {**os.environ, "LOOM_DB": str(db)}
    for var in ("LOOM_API_KEYS", "LOOM_AUTH_FILE", "LOOM_LLM_MODEL"):
        env.pop(var, None)
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "loom.mcp_server"], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await fn(session)


def _payload(result) -> dict | list:
    """Tool results arrive as content blocks; our tools return JSON."""
    structured = getattr(result, "structured_content", None)
    if structured:
        return structured.get("result", structured)
    text = "".join(c.text for c in result.content if getattr(c, "text", None))
    return json.loads(text)


def test_agent_loop_over_stdio(seeded_db):
    async def run(session):
        tools = {t.name: t for t in (await session.list_tools()).tools}
        assert {"find_entity", "find_related", "ask", "ask_scope", "expand",
                "record_claim", "get_observations", "answer"} <= set(tools)
        assert "ctx" not in tools["ask"].input_schema.get("properties", {})

        found = _payload(await session.call_tool(
            "find_entity", {"query": "web-01", "namespace": "netsec"}))
        assert found[0]["handle"] == "host:web-01"

        pack = _payload(await session.call_tool("ask", {
            "subject": "host:web-01", "question": "what operating system does it run?",
            "budget": 300, "namespace": "netsec"}))
        assert pack["items"][0]["kind"] == "conflict"          # the planted OS conflict
        assert all(i["citations"] for i in pack["items"])
        assert pack["handles"], "a small budget leaves threads to expand"

        more = _payload(await session.call_tool(
            "expand", {"handle": pack["handles"][0]["id"], "budget": 2000}))
        assert more["items"]

        lease = _payload(await session.call_tool("ask", {
            "subject": "ip:10.0.4.7", "question": "which host?", "budget": 600,
            "namespace": "netsec", "valid_at": "2026-08-20T00:00:00Z"}))
        text = " | ".join(i["text"] for i in lease["items"])
        assert "laptop-17" in text and "web-01" not in text

        wrote = _payload(await session.call_tool("record_claim", {
            "subject": "host:web-01", "predicate": "triaged_by",
            "object_ref": "user:agent-7", "observed_at": "2026-09-08T12:00:00Z",
            "source": "agent-writeback", "namespace": "netsec"}))
        assert wrote["status"] == "recorded"
        raw = _payload(await session.call_tool(
            "get_observations", {"subject": "host:web-01", "namespace": "netsec", "limit": 5}))
        assert any(o["source"] == "agent-writeback" for o in raw["observations"])
        return True

    assert asyncio.run(_session(seeded_db, run))


def test_tool_errors_are_reported_not_fatal(seeded_db):
    async def run(session):
        bad = await session.call_tool("ask", {"subject": "web-01", "question": "?"})
        assert bad.is_error
        assert "type:key" in "".join(c.text for c in bad.content if getattr(c, "text", None))
        # the session survives a tool error
        ok = _payload(await session.call_tool(
            "find_entity", {"query": "db-01", "namespace": "netsec"}))
        assert ok[0]["handle"] == "host:db-01"
        return True

    assert asyncio.run(_session(seeded_db, run))
