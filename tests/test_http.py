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


def test_entity_search(tmp_path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        client.post("/v1/ingest", json=CLAIM)
        r = client.get("/v1/entities/search", params={"q": "web-01"})
        assert r.status_code == 200
        assert [m["key"] for m in r.json()["matches"]] == ["web-01"]
        assert client.get(
            "/v1/entities/search", params={"q": "zzz"}
        ).json()["matches"] == []


def test_answer_503_when_no_llm_configured(tmp_path, monkeypatch):
    for var in ("LOOM_LLM_MODEL", "LOOM_LLM_PROVIDER",
                "LOOM_LLM_BASE_URL", "LOOM_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    with make_client(tmp_path, monkeypatch) as client:
        r = client.post("/v1/answer", json={"question": "anything?"})
        assert r.status_code == 503
        assert "LOOM_LLM_MODEL" in r.json()["detail"]


REGISTRY = {
    "namespace": "default",
    "entity_types": [{"name": "host"}, {"name": "domain"}, {"name": "user"}],
    "predicates": [
        {"name": "member_of", "object_types": ["domain"], "containment": True},
        {"name": "logged_in_by", "object_types": ["user"]},
        {"name": "runs_os"},
    ],
}


def test_schema_registry_validates_ingest(tmp_path, monkeypatch):
    """D-024: registered predicates enforce object types; strict namespaces
    reject the unregistered; scopes default to containment predicates."""
    with make_client(tmp_path, monkeypatch) as client:
        assert client.get("/v1/schemas").status_code == 404
        r = client.post("/v1/schemas", json=REGISTRY)
        assert r.status_code == 200 and not r.json()["strict"]
        assert client.get("/v1/schemas").json()["predicates"][0]["name"] == "member_of"

        ok = client.post("/v1/ingest", json=CLAIM)
        assert ok.status_code == 200
        bad = client.post("/v1/ingest", json={**CLAIM, "object": "jdoe"})  # scalar
        assert bad.status_code == 422 and "expects an entity object" in bad.json()["detail"]
        bad = client.post("/v1/ingest", json={
            **CLAIM, "object": {"type": "host", "key": "db-01"}})
        assert bad.status_code == 422 and "['user']" in bad.json()["detail"]
        # unregistered predicate/type: fine while not strict
        assert client.post("/v1/ingest", json={
            **CLAIM, "predicate": "pinged", "object": {"type": "printer", "key": "p1"}}
        ).status_code == 200

        # strict: additive re-registration flips the switch
        r = client.post("/v1/schemas", json={"namespace": "default", "strict": True})
        assert r.json()["strict"] and len(r.json()["predicates"]) == 3
        r = client.post("/v1/ingest", json={**CLAIM, "predicate": "pinged"})
        assert r.status_code == 422 and "not registered" in r.json()["detail"]
        r = client.post("/v1/ingest", json={
            **CLAIM, "predicate": "runs_os", "object": "fedora"})
        assert r.status_code == 200

        # scope with no expand follows the registry's containment predicate
        client.post("/v1/ingest", json={
            **CLAIM, "predicate": "member_of",
            "object": {"type": "domain", "key": "corp.local"}})
        r = client.post("/v1/ask", json={
            "scope": {"subjects": [{"type": "domain", "key": "corp.local"}], "depth": 1},
            "question": "who logged in?", "budget": 2000})
        assert r.status_code == 200
        assert {s["key"] for s in r.json()["subjects"]} >= {"corp.local", "web-01"}
        assert any("jdoe" in i["text"] for i in r.json()["items"])


def test_readyz_reports_schema_version(tmp_path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        assert client.get("/readyz").json()["schema_version"] >= 2
