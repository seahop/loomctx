"""loom.loadgen against a live engine: keys and error reporting (D-063)."""

import asyncio

import httpx
import pytest

from loom import loadgen


def test_loadgen_sends_the_key_and_reports_refusals(monkeypatch, capsys):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-loom-key"))
        ok = request.headers.get("x-loom-key") == "k1"
        return httpx.Response(200 if ok else 401, json={})

    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    asyncio.run(loadgen.run("http://loom", 4, 2, "loadtest", key="k1"))
    assert seen == ["k1"] * 4 and "ok=4 err=0" in capsys.readouterr().out
    asyncio.run(loadgen.run("http://loom", 3, 2, "loadtest"))
    out = capsys.readouterr().out
    assert "err=3" in out and "errors by status: {'401': 3}" in out


if __name__ == "__main__":
    pytest.main([__file__])
