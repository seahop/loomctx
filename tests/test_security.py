"""Browser guards, write-side citation/supersession gates, auth-before-parse
and rate-limit consistency across surfaces (D-059)."""

import asyncio
import hashlib
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import loomctx.mcp_server as mcp_server
from loomctx.auth import AuthConfig
from loomctx.contracts import ClaimIn, EntityRef, SchemaRegistration
from loomctx.store.sqlite import SqliteStore
from loomctx.webguard import BrowserGuard, HostPolicy, is_json_media_type

OBSERVED = "2026-09-01T14:03:00Z"
CLAIM = {"kind": "claim", "subject": {"type": "host", "key": "web-01"}, "predicate": "logged_in_by",
         "object": {"type": "user", "key": "jdoe"}, "observed_at": OBSERVED, "source": "auth-log"}


def _open_client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "sec.db"))
    for var in ("LOOMCTX_API_KEYS", "LOOMCTX_AUTH_FILE", "LOOMCTX_ALLOWED_HOSTS", "LOOMCTX_ALLOWED_ORIGINS"):
        monkeypatch.delenv(var, raising=False)
    from loomctx.api.http import app
    return TestClient(app)


def _keys_file(tmp_path, monkeypatch, *entries):
    """entries: (plaintext, grant dict without sha256)."""
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"keys": [
        {"sha256": hashlib.sha256(key.encode()).hexdigest(), **grant} for key, grant in entries]}))
    monkeypatch.setenv("LOOMCTX_AUTH_FILE", str(path))
    monkeypatch.delenv("LOOMCTX_API_KEYS", raising=False)
    return path


def _keyed_client(tmp_path, monkeypatch, *entries):
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "sec-keyed.db"))
    _keys_file(tmp_path, monkeypatch, *entries)
    from loomctx.api.http import app
    return TestClient(app)


# ------------------------------------------------ browser guards (engine) #

def test_simple_request_bodies_cannot_write(tmp_path, monkeypatch):
    """A cross-site page can POST text/plain, a form encoding, or a typeless
    Blob without a CORS preflight. The batch route parsed any of those as
    JSON; every body-carrying /v1 route now takes JSON-family types only."""
    with _open_client(tmp_path, monkeypatch) as client:
        raw = json.dumps([CLAIM]).encode()
        for ctype in ("text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded",
                      "multipart/form-data; boundary=x"):
            r = client.post("/v1/ingest/batch", content=raw, headers={"content-type": ctype})
            assert r.status_code == 415, ctype
        assert client.post("/v1/ingest/batch", content=raw).status_code == 415   # typeless Blob
        assert client.post("/v1/ingest", content=json.dumps(CLAIM),
                           headers={"content-type": "text/plain"}).status_code == 415
        assert client.post("/v1/ask", content=b"{}", headers={"content-type": "text/plain"}).status_code == 415
        assert client.get("/v1/entities/host/web-01/observations").json()["count"] == 0
        # what the SDKs and log shippers send still works
        assert client.post("/v1/ingest/batch", content=raw,
                           headers={"content-type": "application/json"}).json()["recorded"] == 1
        nd = (json.dumps({**CLAIM, "event_id": "n1"}) + "\n").encode()
        assert client.post("/v1/ingest/batch", content=nd,
                           headers={"content-type": "application/x-ndjson"}).json()["recorded"] == 1
    assert is_json_media_type("application/vnd.loomctx+json") and not is_json_media_type(None)


def test_host_allowlist_and_foreign_origins(tmp_path, monkeypatch):
    """DNS rebinding makes an attacker's page same-origin with a local LoomCtx;
    only its Host header gives it away. Defaults cover loopback, IPs (kubelet
    probes), service names and cluster DNS; anything else must be listed."""
    with _open_client(tmp_path, monkeypatch) as client:
        for host in ("localhost:8000", "127.0.0.1:8000", "[::1]:8000", "10.4.0.12:8000", "loomctx",
                     "loomctx:8000", "loomctx.loomctx.svc.cluster.local", "testserver", "host.docker.internal"):
            assert client.get("/healthz", headers={"host": host}).status_code == 200, host
        for host in ("evil.example.net", "evil.example.net:8000", "127.0.0.1.nip.io"):
            r = client.post("/v1/ingest", json=CLAIM, headers={"host": host})
            assert r.status_code == 400 and "LOOMCTX_ALLOWED_HOSTS" in r.json()["detail"], host
            assert client.get("/readyz", headers={"host": host}).status_code == 400
        monkeypatch.setenv("LOOMCTX_ALLOWED_HOSTS", "loomctx.example.com, *.corp.example.com")
        for host in ("loomctx.example.com", "api.corp.example.com:443"):
            assert client.get("/healthz", headers={"host": host}).status_code == 200, host
        assert client.get("/healthz", headers={"host": "evil.example.net"}).status_code == 400
        # a foreign Origin is refused even with a JSON body; loopback tools
        # and listed origins pass; non-browser clients send none
        r = client.post("/v1/ingest", json=CLAIM, headers={"origin": "https://evil.example.net"})
        assert r.status_code == 403 and "LOOMCTX_ALLOWED_ORIGINS" in r.json()["detail"]
        assert client.post("/v1/ingest", json=CLAIM, headers={"origin": "null"}).status_code == 403
        assert client.post("/v1/ingest", json=CLAIM, headers={"origin": "http://localhost:6274"}).status_code == 200
        monkeypatch.setenv("LOOMCTX_ALLOWED_ORIGINS", "https://app.example.com")
        assert client.post("/v1/ingest", json={**CLAIM, "event_id": "o2"},
                           headers={"origin": "https://app.example.com"}).status_code == 200
        monkeypatch.setenv("LOOMCTX_ALLOWED_HOSTS", "*")
        assert client.get("/healthz", headers={"host": "anything.example.net"}).status_code == 200


def test_unauthenticated_requests_are_refused_before_the_body_is_parsed(tmp_path, monkeypatch):
    """With auth on, no key -> 401 and an unknown key -> 403 before FastAPI
    reads or validates the body (a garbage body would otherwise be a 422)."""
    with _keyed_client(tmp_path, monkeypatch, ("rw-key", {"id": "rw", "namespaces": ["*"], "perms": "rw"})) as client:
        garbage = {"content-type": "application/json"}
        r = client.post("/v1/ingest", content=b"{not json", headers=garbage)
        assert r.status_code == 401 and "missing API key" in r.json()["detail"]
        r = client.post("/v1/ingest/batch", content=b"[1,2,", headers={**garbage, "x-loomctx-key": "bogus"})
        assert r.status_code == 403 and "unknown" in r.json()["detail"]
        r = client.post("/v1/ingest", content=b"{not json", headers={**garbage, "x-loomctx-key": "rw-key"})
        assert r.status_code == 422                               # a real key reaches validation
        assert client.get("/healthz").status_code == 200           # probes stay open


# ------------------------------------------- citations by type-gated keys #

def _citation_world(tmp_path, monkeypatch):
    return _keyed_client(
        tmp_path, monkeypatch,
        ("admin", {"id": "admin", "namespaces": ["default"], "perms": "rw"}),
        ("hosts", {"id": "host-agent", "namespaces": ["default"], "perms": "rw", "entity_types": ["host"]}),
    )


def test_type_gated_key_cannot_cite_its_way_into_a_document(tmp_path, monkeypatch):
    """H-A6's read gate trusted citations, and the citing key chose them: a
    host-scoped rw key could cite an HR document from a host claim and then
    read it. Now it may cite only documents it ingested or ones already
    backing a fact in its world — on the single route and per batch item."""
    admin, gated = {"X-LoomCtx-Key": "admin"}, {"X-LoomCtx-Key": "hosts"}
    with _citation_world(tmp_path, monkeypatch) as client:
        secret = client.post("/v1/ingest", headers=admin, json={
            "kind": "document", "event_id": "hr-1", "text": "salary review: jdoe", "source": "hr",
            "observed_at": OBSERVED}).json()["artifact_id"]
        claim = {**CLAIM, "object": "true", "predicate": "rebuilt", "source": "wiki"}
        for prov in ({"artifact_id": secret}, {"artifact_event_id": "hr-1"}):
            r = client.post("/v1/ingest", headers=gated, json={**claim, "provenance": prov})
            assert r.status_code == 403 and "may cite only documents it ingested" in r.json()["detail"]
        body = client.post("/v1/ingest/batch", headers=gated, json=[
            {**claim, "event_id": "b1", "provenance": {"artifact_id": secret}}]).json()
        assert body["rejected"] == 1 and "may cite only" in body["results"][0]["detail"]
        assert client.get(f"/v1/artifacts/{secret}", headers=gated).status_code == 403
        # a document id that names nothing is refused for a gated key too
        r = client.post("/v1/ingest", headers=gated, json={**claim, "provenance": {"artifact_id": "0" * 32}})
        assert r.status_code == 403 and "does not name a document" in r.json()["detail"]

        # its own upload: citable (single and batch, cited by event id in the same batch)
        own = client.post("/v1/ingest", headers=gated, json={
            "kind": "document", "text": "web-01 rebuilt", "source": "wiki", "observed_at": OBSERVED})
        own_id = own.json()["artifact_id"]
        r = client.post("/v1/ingest", headers=gated, json={**claim, "provenance": {"artifact_id": own_id}})
        assert r.status_code == 200, r.text
        assert client.get(f"/v1/artifacts/{own_id}", headers=gated).status_code == 200
        body = client.post("/v1/ingest/batch", headers=gated, json=[
            {"kind": "document", "event_id": "run-7", "text": "runbook", "source": "wiki", "observed_at": OBSERVED},
            {**claim, "event_id": "b2", "provenance": {"artifact_event_id": "run-7"}}]).json()
        assert [x["status"] for x in body["results"]] == ["accepted", "recorded"], body
        # the uploader is recorded by the engine, with the key's type gate
        stamp = client.get(f"/v1/artifacts/{own_id}", headers=admin).json()["attrs"]["loomctx.uploader"]
        assert stamp == {"grant": "host-agent", "entity_types": ["host"]}

        # a document the admin already tied to a host fact is in the gated
        # key's world: citable
        shared = client.post("/v1/ingest", headers=admin, json={
            "kind": "document", "text": "patch notes", "source": "wiki", "observed_at": OBSERVED}).json()["artifact_id"]
        assert client.post("/v1/ingest", headers=admin, json={
            **claim, "event_id": "a1", "provenance": {"artifact_id": shared}}).status_code == 200
        r = client.post("/v1/ingest", headers=gated, json={**claim, "event_id": "g9", "provenance": {"artifact_id": shared}})
        assert r.status_code == 200, r.text
        # an ungated key cites anything, as before
        assert client.post("/v1/ingest", headers=admin, json={
            **claim, "event_id": "a2", "provenance": {"artifact_id": secret}}).status_code == 200


def test_senders_cannot_forge_the_uploader_stamp(tmp_path, monkeypatch):
    with _citation_world(tmp_path, monkeypatch) as client:
        forged = {"kind": "document", "text": "x", "source": "s", "observed_at": OBSERVED,
                  "attrs": {"loomctx.uploader": {"grant": "host-agent"}}}
        r = client.post("/v1/ingest", headers={"X-LoomCtx-Key": "admin"}, json=forged)
        assert r.status_code == 422 and "reserved" in r.json()["detail"]
        body = client.post("/v1/ingest/batch", headers={"X-LoomCtx-Key": "admin"}, json=[forged]).json()
        assert body["rejected"] == 1 and "reserved" in body["results"][0]["detail"]


def test_gated_key_supersedes_only_inside_its_types(tmp_path, monkeypatch):
    """Retiring a fact is writing about it: a host-only key may not
    supersede host:web-01 -> user:jdoe (the user side is outside its world)."""
    admin, gated = {"X-LoomCtx-Key": "admin"}, {"X-LoomCtx-Key": "hosts"}
    with _citation_world(tmp_path, monkeypatch) as client:
        edge = client.post("/v1/ingest", headers=admin, json=CLAIM).json()["observation_id"]
        os_fact = client.post("/v1/ingest", headers=admin, json={
            **CLAIM, "predicate": "runs_os", "object": "fedora"}).json()["observation_id"]
        r = client.post("/v1/ingest", headers=gated, json={
            **CLAIM, "predicate": "logged_in_by", "object": "nobody", "supersedes": edge})
        assert r.status_code == 422 and "not scoped" in r.json()["detail"]
        r = client.post("/v1/ingest", headers=gated, json={
            **CLAIM, "predicate": "runs_os", "object": "debian", "supersedes": os_fact})
        assert r.status_code == 200, r.text


def test_mcp_record_claim_applies_the_supersedes_check(tmp_path):
    """MCP record_claim resolved the cite and recorded without the
    "a correction stays on its subject" check HTTP applies."""
    store = SqliteStore(tmp_path / "mcp-sup.db")
    try:
        mcp_server.configure(store)
        old = mcp_server.record_claim(subject="host:web-01", predicate="runs_os", observed_at=OBSERVED,
                                      source="inv", object_value="fedora")
        with pytest.raises(ValueError, match="a correction stays on its subject"):
            mcp_server.record_claim(subject="host:web-02", predicate="runs_os", observed_at=OBSERVED,
                                    source="inv", object_value="debian", supersedes=old["observation_id"])
        ok = mcp_server.record_claim(subject="host:web-01", predicate="runs_os", observed_at=OBSERVED,
                                     source="inv", object_value="debian", supersedes=old["observation_id"][:12])
        assert ok["supersedes"] == old["observation_id"]
    finally:
        mcp_server.configure(None)
        store.close()


# ------------------------------------------------------ type-scoped views #

def test_type_scoped_keys_see_their_own_registry_and_counts(tmp_path, monkeypatch):
    reg = {"namespace": "default", "strict": False,
           "entity_types": [{"name": "host"}, {"name": "user"}, {"name": "salary"}],
           "predicates": [{"name": "runs_os"}, {"name": "logged_in_by", "object_types": ["user", "host"]},
                          {"name": "paid", "object_types": ["salary"]}]}
    with _citation_world(tmp_path, monkeypatch) as client:
        assert client.post("/v1/schemas", headers={"X-LoomCtx-Key": "admin"}, json=reg).status_code == 200
        full = client.get("/v1/schemas", headers={"X-LoomCtx-Key": "admin"}).json()
        assert {e["name"] for e in full["entity_types"]} == {"host", "user", "salary"}
        scoped = client.get("/v1/schemas", headers={"X-LoomCtx-Key": "hosts"}).json()
        assert [e["name"] for e in scoped["entity_types"]] == ["host"]
        assert {p["name"]: p["object_types"] for p in scoped["predicates"]} == {
            "runs_os": [], "logged_in_by": ["host"]}

    store = SqliteStore(tmp_path / "mcp-counts.db")
    try:
        for key in ("jdoe", "asmith"):
            store.record_claim(ClaimIn(subject=EntityRef(type="user", key=key), predicate="paid",
                                       object=EntityRef(type="salary", key=f"s-{key}"),
                                       observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc), source="hr"))
        store.record_claim(ClaimIn(subject=EntityRef(type="host", key="web-01"), predicate="runs_os",
                                   object="fedora", observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
                                   source="inv"))
        store.put_schema(SchemaRegistration(**reg))
        mcp_server.configure(store, auth=AuthConfig.from_env(), transport="streamable-http")

        class Ctx:
            headers = {"x-loomctx-key": "hosts"}

        listed = mcp_server.list_namespaces(ctx=Ctx())
        assert listed == [{"namespace": "default", "entities": {"host": 1}, "total": 1}]
        desc = mcp_server.describe_namespace("default", ctx=Ctx())
        assert [t["name"] for t in desc["entity_types"]] == ["host"]
        assert {p["name"] for p in desc["predicates"]} == {"runs_os", "logged_in_by"}
    finally:
        mcp_server.configure(None)
        store.close()


# ------------------------------------------------------------ rate limits #

def test_engine_batch_costs_one_token_per_item(tmp_path, monkeypatch):
    """The gateway charged n for a batch of n; the engine charged 1. Now
    both charge n, and a batch larger than the bucket is a 413 (retrying
    can never help) rather than a 429."""
    from loomctx.api.http import app
    monkeypatch.setenv("LOOMCTX_RATE_PER_SEC", "0.001")      # effectively no refill during the test
    monkeypatch.setenv("LOOMCTX_RATE_BURST", "5")
    monkeypatch.setattr(app, "middleware_stack", None)   # rebuild: the limiter reads the dials fresh
    with _open_client(tmp_path, monkeypatch) as client:
        items = [{**CLAIM, "event_id": f"e{i}"} for i in range(6)]
        r = client.post("/v1/ingest/batch", json=items)
        assert r.status_code == 413 and "burst of 5" in r.json()["detail"]
        # that refusal still spent its door token: 4 left
        r = client.post("/v1/ingest/batch", json=items[:4])
        assert r.status_code == 200 and r.json()["recorded"] == 4
        r = client.post("/v1/ingest/batch", json=items[:1])
        assert r.status_code == 429 and r.headers["retry-after"]


@pytest.mark.parametrize("value", ["fast", "inf", "nan"])
def test_malformed_rate_dial_stops_engine_start_up(tmp_path, monkeypatch, value):
    """A dial that does not parse is a start-up error, not a 500 on the
    first request (and never a silent 'unlimited')."""
    monkeypatch.setenv("LOOMCTX_RATE_LLM_PER_SEC", value)
    with pytest.raises(ValueError, match="LOOMCTX_RATE_LLM_PER_SEC"):
        with _open_client(tmp_path, monkeypatch):
            pass


def test_mcp_answer_honours_rate_limits(tmp_path, monkeypatch):
    """MCP `answer` had no limit at all and ignored rate_llm_per_sec: the LLM
    spend guard of /v1/answer was one transport away from useless."""
    store = SqliteStore(tmp_path / "mcp-rate.db")
    store.record_claim(ClaimIn(subject=EntityRef(type="host", key="web-01"), predicate="runs_os",
                               object="fedora", observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
                               source="inv"))
    _keys_file(tmp_path, monkeypatch,
               ("capped", {"id": "capped", "namespaces": ["default"], "perms": "r", "rate_llm_per_sec": 0.001}),
               ("plain", {"id": "plain", "namespaces": ["default"], "perms": "r"}))
    for var in ("LOOMCTX_RATE_PER_SEC", "LOOMCTX_RATE_LLM_PER_SEC", "LOOMCTX_RATE_BURST", "LOOMCTX_RATE_LLM_BURST"):
        monkeypatch.delenv(var, raising=False)

    class Resp:
        answer, model = "fedora", "stub"
        pack = None

    monkeypatch.setattr(mcp_server, "_llm_loaded", True)
    monkeypatch.setattr(mcp_server, "_llm", object())
    monkeypatch.setattr(mcp_server, "build_answer", lambda *a, **k: Resp())
    monkeypatch.setattr(mcp_server, "_agent_view", lambda pack, fmt="concise": {})

    def ctx(key):
        return type("Ctx", (), {"headers": {"x-loomctx-key": key}})()

    try:
        mcp_server.configure(store, auth=AuthConfig.from_env(), transport="streamable-http")
        assert mcp_server.answer("what os?", subject="host:web-01", ctx=ctx("capped"))["answer"] == "fedora"
        with pytest.raises(Exception, match="rate limit exceeded"):
            mcp_server.answer("again?", subject="host:web-01", ctx=ctx("capped"))
        for _ in range(3):   # a key without an override is unlimited by default
            mcp_server.answer("what os?", subject="host:web-01", ctx=ctx("plain"))
        # the general dial applies per tool call on the HTTP transports
        monkeypatch.setenv("LOOMCTX_RATE_PER_SEC", "0.001")
        mcp_server.configure(store, auth=AuthConfig.from_env(), transport="streamable-http")
        mcp_server.find_entity("web-01", ctx=ctx("plain"))
        with pytest.raises(Exception, match="rate limit exceeded"):
            mcp_server.find_entity("web-01", ctx=ctx("plain"))
        # stdio is local trust: never limited
        mcp_server.configure(store, auth=AuthConfig.from_env(), transport="stdio")
        for _ in range(3):
            mcp_server.find_entity("web-01")
    finally:
        mcp_server.configure(None)
        store.close()


# ------------------------------------------------------- MCP HTTP transport #

def test_mcp_http_app_guards_host_and_origin(monkeypatch):
    """compose runs the MCP server with --host 0.0.0.0, which switched the
    SDK's DNS-rebinding protection off. The HTTP app now sits behind the
    engine's Host/Origin policy (then the key gate)."""
    for var in ("LOOMCTX_ALLOWED_HOSTS", "LOOMCTX_ALLOWED_ORIGINS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOOMCTX_API_KEYS", "reader:default:r")
    monkeypatch.delenv("LOOMCTX_AUTH_FILE", raising=False)
    app = mcp_server.build_http_app("streamable-http", "0.0.0.0", AuthConfig.from_env())
    assert isinstance(app, BrowserGuard)

    async def call(headers):
        out = []

        async def send(message):
            out.append(message)

        await app({"type": "http", "method": "POST", "path": "/mcp", "headers": headers}, None, send)
        return out[0]["status"]

    assert asyncio.run(call([(b"host", b"evil.example.net:8300")])) == 400
    assert asyncio.run(call([(b"host", b"localhost:8300"), (b"origin", b"https://evil.example.net")])) == 403
    # an allowed host reaches the key gate (no key -> 401), never the SDK
    assert asyncio.run(call([(b"host", b"localhost:8300")])) == 401
    assert asyncio.run(call([(b"host", b"mcp:8300")])) == 401


def test_insecure_defaults_are_flagged_or_closed(monkeypatch, caplog):
    """An open MCP http server binds loopback unless told otherwise (compose
    passes --host 0.0.0.0 inside the container); a guessable legacy key is
    called out at load; a writer that only has the principal id (NATS)
    can resolve the grant to apply its gates."""
    import logging
    assert mcp_server._arg_parser().parse_args(["--transport", "streamable-http"]).host == "127.0.0.1"
    monkeypatch.delenv("LOOMCTX_AUTH_FILE", raising=False)
    monkeypatch.setenv("LOOMCTX_API_KEYS", "agentsecret:netsec:w,k7Qm2vX9pL4sT8wZ1nB6cR3y:netsec:r")
    with caplog.at_level(logging.WARNING, logger="loomctx.auth"):
        auth = AuthConfig.from_env()
    flagged = [r.getMessage() for r in caplog.records if "guessable" in r.getMessage()]
    assert len(flagged) == 1 and "entry 0" in flagged[0] and "agentsecret" not in flagged[0]
    assert auth.grant_by_id("env-1").perms == "r" and auth.grant_by_id("nope") is None


def test_host_policy_parsing():
    p = HostPolicy.parse("LoomCtx.Example.com., .corp.example.com", "https://App.example.com/")
    assert p.allows_host("loomctx.example.com:8443") and p.allows_host("x.corp.example.com")
    assert not p.allows_host("corp.example.com.evil.net")
    assert p.allows_host(None)                          # HTTP/1.0 tooling, not a browser
    assert p.allows_origin("https://app.example.com", "loomctx.example.com")
    assert p.allows_origin("https://loomctx.example.com:8443", "loomctx.example.com:8443")   # same origin
    assert not p.allows_origin("https://evil.example.net", "loomctx.example.com")
