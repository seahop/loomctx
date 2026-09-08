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
    assert totals == {"recorded": 7, "accepted": 1, "skipped": 1}
    totals = load_direct(str(tmp_path / "d.db"), (json.dumps(r) + "\n" for r in ROWS), size=3)
    assert totals["recorded"] == 7  # replayed, deduped by event_id
    store = SqliteStore(tmp_path / "d.db")
    assert store.count_observations("netsec", EntityRef(type="host", key="web-01")) == 7


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
