from fastapi.testclient import TestClient

CLAIM = {
    "kind": "claim",
    "subject": {"type": "host", "key": "web-01"},
    "predicate": "logged_in_by",
    "object": {"type": "user", "key": "jdoe"},
    "observed_at": "2026-09-01T14:03:00Z",
    "source": "auth-log",
}


def make_client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "api.db"))
    from loom.api.http import app

    return TestClient(app)


def test_ingest_claim_then_read(tmp_path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        assert client.get("/healthz").json() == {"status": "ok"}

        r = client.post("/v1/ingest", json=CLAIM)
        assert r.status_code == 200
        assert r.json()["status"] == "recorded"

        r = client.get("/v1/entities/host/web-01/observations")
        body = r.json()
        assert body["count"] == 1
        assert body["observations"][0]["predicate"] == "logged_in_by"
        assert body["observations"][0]["source"] == "auth-log"


def test_document_ingest_stores_artifact(tmp_path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        r = client.post(
            "/v1/ingest",
            json={
                "kind": "document",
                "text": "report about web-01",
                "filename": "note.txt",
                "source": "ir-pipeline",
                "observed_at": "2026-09-02T09:00:00Z",
            },
        )
        assert r.status_code == 202
        artifact_id = r.json()["artifact_id"]
        assert r.json()["extraction"] == "pending"

        r = client.get(f"/v1/artifacts/{artifact_id}")
        assert r.status_code == 200
        assert r.json()["text"] == "report about web-01"

        assert client.get("/v1/artifacts/nope").status_code == 404


def test_ask_and_expand_roundtrip(tmp_path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        client.post("/v1/ingest", json=CLAIM)
        r = client.post(
            "/v1/ask",
            json={
                "subject": {"type": "host", "key": "web-01"},
                "question": "who logged in?",
                "budget": 400,
            },
        )
        assert r.status_code == 200
        pack = r.json()
        assert pack["items"] and "jdoe" in pack["items"][0]["text"]
        assert pack["items"][0]["citations"][0]["source"] == "auth-log"

        assert client.post(
            "/v1/expand", json={"handle": "h1_garbage"}
        ).status_code == 400


def test_invalid_envelope_rejected(tmp_path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        r = client.post("/v1/ingest", json={"kind": "claim", "predicate": "x"})
        assert r.status_code == 422
