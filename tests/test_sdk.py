"""The Python SDK against a live engine (H-G1/H-G2/H-G3).

Boots uvicorn in a thread on a free port so the SDK's real urllib transport
is exercised end to end: URL encoding, auth header, error mapping.
"""

import socket
import threading
import time

import pytest
import uvicorn

from loomctx_sdk import LoomCtx, LoomCtxError

OBSERVED = "2026-09-01T14:03:00Z"


@pytest.fixture
def engine_url(tmp_path, monkeypatch):
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "sdk.db"))
    monkeypatch.setenv("LOOMCTX_API_KEYS", "writer:default:rw,reader:default:r")
    for var in ("LOOMCTX_LLM_MODEL", "LOOMCTX_LLM_PROVIDER", "LOOMCTX_LLM_BASE_URL",
                "LOOMCTX_AUTH_FILE", "LOOMCTX_HANDLE_SECRET"):
        monkeypatch.delenv(var, raising=False)
    from loomctx.api.http import app

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                           log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started, "engine did not start"
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def test_sdk_round_trip_with_awkward_keys(engine_url):
    loomctx = LoomCtx(engine_url, api_key="writer")
    assert loomctx.ready()

    first = loomctx.claim(("host", "web 01/a"), "logged_in_by", ("user", "j&d"),
                       observed_at=OBSERVED, source="auth-log", event_id="e1")
    replay = loomctx.claim(("host", "web 01/a"), "logged_in_by", ("user", "j&d"),
                        observed_at=OBSERVED, source="auth-log", event_id="e1")
    assert first["observation_id"] == replay["observation_id"]  # idempotent

    obs = loomctx.observations(("host", "web 01/a"))          # URL-encoded path
    assert obs["count"] == 1
    found = loomctx.search("web 01")                           # URL-encoded query
    assert [m["key"] for m in found["matches"]] == ["web 01/a"]

    pack = loomctx.ask(("host", "web 01/a"), "who logged in?", budget=400)
    assert pack["items"] and pack["items"][0]["citations"]

    loomctx.claim(("host", "web 01/a"), "member_of", ("domain", "corp.local"),
               observed_at=OBSERVED, source="inv", event_id="m1")
    paths = loomctx.path(("user", "j&d"), ("domain", "corp.local"),
                      via=["logged_in_by", "member_of"], depth=2, budget=2000)
    assert paths["from"]["key"] == "j&d" and paths["to"]["key"] == "corp.local"
    assert paths["paths"] and all(e["cite"] for p in paths["paths"] for e in p)

    doc = loomctx.document(text="report body", source="ir", observed_at=OBSERVED,
                        filename="ir.txt", event_id="d1")
    assert doc["status"] == "accepted"
    assert loomctx.document(text="report body", source="ir", observed_at=OBSERVED,
                         event_id="d1")["artifact_id"] == doc["artifact_id"]
    assert loomctx.artifact(doc["artifact_id"])["text"] == "report body"


def test_sdk_surfaces_server_errors(engine_url):
    reader = LoomCtx(engine_url, api_key="reader")
    with pytest.raises(LoomCtxError) as exc:
        reader.claim(("host", "x"), "p", "v", observed_at=OBSERVED, source="s")
    assert exc.value.status == 403 and "not authorized" in exc.value.detail
    with pytest.raises(LoomCtxError) as exc:
        reader.artifact("missing")
    assert exc.value.status == 404
    with pytest.raises(LoomCtxError) as exc:
        reader.answer("anything about web-01?")
    assert exc.value.status == 503 and "LOOMCTX_LLM_MODEL" in exc.value.detail
    with pytest.raises(LoomCtxError) as exc:
        LoomCtx(engine_url).ask(("host", "x"), "?")   # no key at all
    assert exc.value.status == 401
    with pytest.raises(LoomCtxError) as exc:
        reader.expand("garbage-handle")
    assert exc.value.status == 400
