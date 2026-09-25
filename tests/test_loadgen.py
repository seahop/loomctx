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


def test_cli_keys_from_a_mounted_file_are_stripped(monkeypatch):
    """`kubectl create secret --from-file` keeps the file's newline; a key
    with one is an invalid header and every request failed at once (D-063)."""
    import argparse
    import importlib
    monkeypatch.setenv("LOOM_API_KEY", "loomk_abc\n")
    for mod in ("loom.loadgen", "loom.ingest", "loom.connectors.vulns"):
        m = importlib.import_module(mod)
        seen = {}
        real = argparse.ArgumentParser.parse_args

        def grab(self, args=None, namespace=None, _real=real):
            ns = _real(self, args, namespace)
            seen.update(vars(ns))
            raise SystemExit(0)
        monkeypatch.setattr(argparse.ArgumentParser, "parse_args", grab)
        argv = {"loom.loadgen": [], "loom.ingest": ["--url", "http://x", "f.jsonl"],
                "loom.connectors.vulns": ["load", "--url", "http://x"]}[mod]
        monkeypatch.setattr("sys.argv", [mod] + argv)
        with pytest.raises(SystemExit):
            m.main()
        assert seen["key"] == "loomk_abc", mod
        monkeypatch.setattr(argparse.ArgumentParser, "parse_args", real)


if __name__ == "__main__":
    pytest.main([__file__])
