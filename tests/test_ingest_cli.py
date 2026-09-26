"""Bulk loader (D-034)."""

import json

from loom.contracts import EntityRef
from loom.ingest import load_direct, post_batches
from loom.store.sqlite import SqliteStore

ROWS = [
    {"kind": "claim", "namespace": "netsec", "event_id": f"l-{i}",
     "subject": {"type": "host", "key": "web-01"}, "predicate": "logged_in_by",
     "object": {"type": "user", "key": f"u{i}"}, "observed_at": "2026-09-01T14:03:00Z",
     "source": "auth-log"} for i in range(7)
] + [{"kind": "document", "namespace": "netsec", "text": "r", "source": "ir",
      "observed_at": "2026-09-02T09:00:00Z", "event_id": "l-doc"}]


def test_direct_load_is_batched_and_idempotent(tmp_path):
    lines = [json.dumps(r) + "\n" for r in ROWS] + ["{not json\n"]
    totals = load_direct(str(tmp_path / "d.db"), lines, size=3)
    assert totals == {"recorded": 7, "accepted": 1, "skipped": 1, "rejected": 0}
    totals = load_direct(str(tmp_path / "d.db"), (json.dumps(r) + "\n" for r in ROWS), size=3)
    assert totals["recorded"] == 7  # replayed, deduped by event_id
    store = SqliteStore(tmp_path / "d.db")
    assert store.count_observations("netsec", EntityRef(type="host", key="web-01")) == 7


def test_direct_load_without_db_uses_the_environment_store(tmp_path, monkeypatch, capsys):
    """No --db and no --url: the loader writes into the store LOOM_DB /
    LOOM_SHARDS / LOOM_BLOB_* configure (sharding and offload apply);
    --db is an explicit single-store override."""
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "env.db"))
    monkeypatch.delenv("LOOM_SHARDS", raising=False)
    assert load_direct(None, (json.dumps(r) + "\n" for r in ROWS), size=4)["recorded"] == 7
    src = tmp_path / "rows.jsonl"
    src.write_text("".join(json.dumps(r) + "\n" for r in ROWS))
    monkeypatch.setattr("sys.argv", ["loom.ingest", str(src)])
    from loom.ingest import main
    main()
    assert json.loads(capsys.readouterr().out)["recorded"] == 7          # replayed, deduped
    store = SqliteStore(tmp_path / "env.db")
    assert store.count_observations("netsec", EntityRef(type="host", key="web-01")) == 7
    monkeypatch.setattr("sys.argv", ["loom.ingest", "--url", "http://x", "--db", "y", str(src)])
    import pytest
    with pytest.raises(SystemExit):
        main()


def test_http_load_posts_ndjson_batches(monkeypatch):
    seen = []

    class Resp:
        def __init__(self, n):
            self.n = n

        def read(self):
            return json.dumps({"total": self.n, "recorded": self.n, "accepted": 0, "rejected": 0,
                               "results": []}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        body = req.data.decode()
        seen.append((req.full_url, req.headers.get("Content-type"), req.headers.get("X-loom-key"),
                     body.count("\n")))
        return Resp(body.count("\n"))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    totals = post_batches("http://loom:8000/", (json.dumps(r) + "\n" for r in ROWS), size=5, key="k")
    assert totals["recorded"] == 8 and [s[3] for s in seen] == [5, 3]
    assert seen[0][0] == "http://loom:8000/v1/ingest/batch"
    assert seen[0][1] == "application/x-ndjson" and seen[0][2] == "k"


def _http_error(code, retry_after=None):
    import io
    import urllib.error
    from email.message import Message
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("http://loom/v1/ingest/batch", code, "busy", headers,
                                  io.BytesIO(b"slow down"))


class _Resp:
    def __init__(self, n):
        self.n = n

    def read(self):
        return json.dumps({"total": self.n, "recorded": self.n, "accepted": 0, "rejected": 0,
                           "results": []}).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_http_load_retries_429_and_5xx_honoring_retry_after(monkeypatch):
    """The nightly job died on the first 429 once rate limiting landed
    (D-056): a refused batch is now retried, waiting what Retry-After says."""
    import urllib.error
    script = [_http_error(429, "7"), _http_error(503), urllib.error.URLError("refused"), None,
              _http_error(429, "1"), None]
    calls, slept = [], []

    def fake_urlopen(req, timeout=0):
        calls.append(req.data.decode().count("\n"))
        step = script.pop(0)
        if step is not None:
            raise step
        return _Resp(calls[-1])

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("time.sleep", slept.append)
    totals = post_batches("http://loom:8000", (json.dumps(r) + "\n" for r in ROWS), size=5, key=None)
    assert totals["recorded"] == 8 and calls == [5, 5, 5, 5, 3, 3]
    assert slept[0] == 7 and slept[3] == 1                      # Retry-After obeyed
    assert 0 < slept[1] <= 60 and 0 < slept[2] <= 60             # backoff otherwise


def test_http_load_gives_up_after_the_bound_and_never_retries_a_4xx(monkeypatch):
    import pytest
    from loom import ingest
    calls = []

    def always(code):
        def fake_urlopen(req, timeout=0):
            calls.append(code)
            raise _http_error(code, "0")
        return fake_urlopen

    monkeypatch.setattr("time.sleep", lambda s: None)
    monkeypatch.setattr("urllib.request.urlopen", always(503))
    with pytest.raises(SystemExit, match="after 6 attempts"):
        post_batches("http://loom", (json.dumps(r) + "\n" for r in ROWS), size=50, key=None)
    assert len(calls) == ingest.POST_ATTEMPTS == 6
    calls.clear()
    monkeypatch.setattr("urllib.request.urlopen", always(422))
    with pytest.raises(SystemExit, match="HTTP 422"):
        post_batches("http://loom", (json.dumps(r) + "\n" for r in ROWS), size=50, key=None)
    assert calls == [422]


def _strict(db, namespace="netsec"):
    """A strict registry with nothing registered: every claim is refused."""
    from loom.contracts import SchemaRegistration
    store = SqliteStore(db)
    try:
        store.put_schema(SchemaRegistration(namespace=namespace, strict=True))
    finally:
        store.close()


def test_the_loader_exits_non_zero_when_anything_is_refused(tmp_path, monkeypatch, capsys):
    """D-063/S-36 said loaders exit non-zero on any refusal; only `vulns`
    did — `python -m loom.ingest` printed its totals and exited 0 over a
    hole. Now the totals still print, then the run fails, direct or HTTP."""
    import pytest
    from loom.ingest import main
    src = tmp_path / "rows.jsonl"
    src.write_text("".join(json.dumps(r) + "\n" for r in ROWS))
    db = tmp_path / "strict.db"
    _strict(db)
    with pytest.raises(SystemExit, match="7 envelopes were refused by the store"):
        main([str(src), "--db", str(db)])
    assert json.loads(capsys.readouterr().out)["rejected"] == 7              # totals first

    class Resp(_Resp):
        def read(self):
            return json.dumps({"total": self.n, "recorded": self.n - 1, "accepted": 0, "rejected": 1,
                               "results": [{"index": 0, "status": "rejected", "detail": "no"}]}).encode()
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=0: Resp(req.data.decode().count("\n")))
    with pytest.raises(SystemExit, match="1 envelopes were refused by the engine"):
        main([str(src), "--url", "http://loom", "--batch", "50"])
    assert json.loads(capsys.readouterr().out)["rejected"] == 1

    ok = tmp_path / "ok.db"
    main([str(src), "--db", str(ok)])                                         # nothing refused: exit 0
    assert json.loads(capsys.readouterr().out)["rejected"] == 0
