import json

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


def test_semantic_entity_search(tmp_path, monkeypatch):
    """D-025: find entities by meaning; 503 without an embedder."""
    from loom.enrich import embed_pending
    from loom.llm import HashingEmbedder
    from loom.store.sqlite import SqliteStore
    monkeypatch.delenv("LOOM_EMBED_PROVIDER", raising=False)
    with make_client(tmp_path, monkeypatch) as client:
        assert client.get("/v1/entities/semantic", params={"q": "x"}).status_code == 503
    monkeypatch.setenv("LOOM_EMBED_PROVIDER", "hashing")
    with make_client(tmp_path, monkeypatch) as client:
        for key, pred, obj in [("web-01", "runs_os", "ubuntu linux operating system"),
                               ("db-01", "listens_on_port", "5432 postgres database"),
                               ("vpn-01", "vpn_protocol", "wireguard tunnel")]:
            client.post("/v1/ingest", json={**CLAIM, "subject": {"type": "host", "key": key},
                                            "predicate": pred, "object": obj})
        embed_pending(SqliteStore(tmp_path / "api.db"), HashingEmbedder())
        r = client.get("/v1/entities/semantic",
                       params={"q": "which host runs the postgres database?", "limit": 2})
        assert r.status_code == 200
        body = r.json()
        assert body["matches"][0]["entity"] == {"type": "host", "key": "db-01"}
        assert body["matches"][0]["evidence"]["citations"]
        assert "vector_backend" in client.get("/readyz").json()


def test_batch_ingest_array_and_ndjson(tmp_path, monkeypatch):
    """D-034: many envelopes per request; per-item outcomes; bad records
    don't block good ones; NDJSON for log shippers."""
    with make_client(tmp_path, monkeypatch) as client:
        items = [
            CLAIM,
            {**CLAIM, "subject": {"type": "host", "key": "db-01"}, "event_id": "b-2"},
            {"kind": "document", "text": "report", "source": "ir", "observed_at": "2026-09-02T09:00:00Z"},
            {"kind": "claim", "predicate": "broken"},                       # schema failure
        ]
        r = client.post("/v1/ingest/batch", json=items)
        assert r.status_code == 200
        body = r.json()
        assert (body["total"], body["recorded"], body["accepted"], body["rejected"]) == (4, 2, 1, 1)
        statuses = [x["status"] for x in body["results"]]
        assert statuses == ["recorded", "recorded", "accepted", "rejected"]
        assert body["results"][2]["artifact_id"] and "subject" in body["results"][3]["detail"]
        # NDJSON, replaying an event_id dedupes, wrapper object accepted
        nd = "\n".join(json.dumps(x) for x in items[:2]) + "\n"
        r = client.post("/v1/ingest/batch", content=nd, headers={"content-type": "application/x-ndjson"})
        assert r.status_code == 200 and r.json()["recorded"] == 2
        assert client.get("/v1/entities/host/db-01/observations").json()["count"] == 1
        r = client.post("/v1/ingest/batch", json={"items": [CLAIM]})
        assert r.json()["recorded"] == 1
        assert client.post("/v1/ingest/batch", content=b"not json", headers={"content-type": "application/json"}).status_code == 400
        monkeypatch.setenv("LOOM_MAX_BATCH", "2")
        assert client.post("/v1/ingest/batch", json=items).status_code == 413


def test_batch_ingest_applies_gates_per_item(tmp_path, monkeypatch):
    monkeypatch.setenv("LOOM_API_KEYS", "w1:default:w,r1:default:r")
    with make_client(tmp_path, monkeypatch) as client:
        assert client.post("/v1/ingest/batch", json=[CLAIM]).status_code == 401
        r = client.post("/v1/ingest/batch", json=[CLAIM, {**CLAIM, "namespace": "other"}],
                        headers={"X-Loom-Key": "w1"})
        assert r.status_code == 200
        st = {x["index"]: x for x in r.json()["results"]}
        assert st[0]["status"] == "recorded" and st[1]["status"] == "rejected"
        assert "other" in st[1]["detail"]
        r = client.post("/v1/ingest/batch", json=[CLAIM], headers={"X-Loom-Key": "r1"})
        assert r.json()["results"][0]["status"] == "rejected"


def test_openapi_document_exports(tmp_path, monkeypatch):
    from loom.schemas import openapi
    doc = openapi()
    assert doc["openapi"].startswith("3.")
    paths = set(doc["paths"])
    assert {"/v1/ingest", "/v1/ingest/batch", "/v1/ask", "/v1/expand", "/v1/answer",
            "/v1/schemas", "/v1/entities/semantic", "/readyz"} <= paths
    assert "IngestBatchResponse" in doc["components"]["schemas"]


def test_batch_claims_cite_a_document_in_the_same_batch(tmp_path, monkeypatch):
    """D-039: a document and structured claims about it arrive together; the
    claims cite it by event id and land with the resolved artifact id. An
    unknown reference rejects that item only."""
    with make_client(tmp_path, monkeypatch) as client:
        items = [
            {"kind": "document", "event_id": "adv-1", "text": "Apply the vendor patch.", "source": "kev",
             "observed_at": "2026-09-02T09:00:00Z"},
            {**CLAIM, "event_id": "c-1", "provenance": {"artifact_event_id": "adv-1"}},
            {**CLAIM, "event_id": "c-2", "provenance": {"artifact_event_id": "missing"}},
        ]
        body = client.post("/v1/ingest/batch", json=items).json()
        assert [x["status"] for x in body["results"]] == ["accepted", "recorded", "rejected"]
        assert "ingest the document first" in body["results"][2]["detail"]
        obs = client.get("/v1/entities/host/web-01/observations").json()["observations"]
        assert obs[0]["provenance"]["artifact_id"] == body["results"][0]["artifact_id"]
        # the single-envelope route rejects the same way
        r = client.post("/v1/ingest", json={**CLAIM, "event_id": "c-3", "provenance": {"artifact_event_id": "missing"}})
        assert r.status_code == 422 and "ingest the document first" in r.json()["detail"]


def test_search_endpoints_take_namespace_as_a_query_parameter(tmp_path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        client.post("/v1/ingest", json={**CLAIM, "namespace": "netsec", "event_id": "ns-1"})
        assert client.get("/v1/entities/search", params={"q": "web", "namespace": "netsec"}).json()["matches"]
        assert not client.get("/v1/entities/search", params={"q": "web"}).json()["matches"]
        assert client.get("/v1/entities/search", params={"q": "web"},
                          headers={"X-Loom-Namespace": "netsec"}).json()["matches"]
