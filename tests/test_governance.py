"""Auth, idempotent ingest, and lifecycle (D-013, D-014, D-016)."""

import io
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from loom.auth import AuthConfig
from loom.contracts import ClaimIn, DocumentIn, EntityRef
from loom.lifecycle import export_jsonl, import_jsonl
from loom.store.sqlite import SqliteStore

OBSERVED = datetime(2026, 9, 1, 14, 3, tzinfo=timezone.utc)


def claim(event_id=None, namespace="default", observed=OBSERVED):
    return ClaimIn(
        namespace=namespace, event_id=event_id,
        subject=EntityRef(type="host", key="web-01"),
        predicate="logged_in_by", object=EntityRef(type="user", key="jdoe"),
        observed_at=observed, source="auth-log",
    )


# ------------------------------------------------------------------- D-014 #

def test_event_id_dedupes_redelivery(tmp_path):
    store = SqliteStore(tmp_path / "d.db")
    first = store.record_claim(claim(event_id="evt-1"))
    replay = store.record_claim(claim(event_id="evt-1"))
    assert replay.id == first.id
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert len(obs) == 1


def test_event_id_is_namespace_scoped(tmp_path):
    store = SqliteStore(tmp_path / "d.db")
    a = store.record_claim(claim(event_id="evt-1", namespace="team-a"))
    b = store.record_claim(claim(event_id="evt-1", namespace="team-b"))
    assert a.id != b.id


def test_document_event_id_dedupes(tmp_path):
    store = SqliteStore(tmp_path / "d.db")
    doc = DocumentIn(text="report", source="ir", observed_at=OBSERVED,
                     event_id="doc-1")
    first = store.store_artifact(doc)
    replay = store.store_artifact(doc)
    assert replay.id == first.id


def test_no_event_id_means_no_dedupe(tmp_path):
    store = SqliteStore(tmp_path / "d.db")
    store.record_claim(claim())
    store.record_claim(claim())
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert len(obs) == 2


# ------------------------------------------------------------------- D-013 #

def test_auth_config_parsing_and_checks(monkeypatch):
    monkeypatch.setenv("LOOM_API_KEYS",
                       "agent:netsec:w, dash:netsec:r ,root:*:rw")
    auth = AuthConfig.from_env()
    assert auth.enabled
    assert auth.allows("agent", "netsec", "w")
    assert not auth.allows("agent", "netsec", "r")
    assert not auth.allows("agent", "other", "w")
    assert auth.allows("dash", "netsec", "r")
    assert auth.allows("root", "anything", "w")
    assert not auth.allows(None, "netsec", "r")
    assert not auth.allows("wrong", "netsec", "r")


def test_auth_disabled_is_open(monkeypatch):
    monkeypatch.delenv("LOOM_API_KEYS", raising=False)
    auth = AuthConfig.from_env()
    assert not auth.enabled
    assert auth.allows(None, "anything", "w")


def test_auth_rejects_malformed_env(monkeypatch):
    monkeypatch.setenv("LOOM_API_KEYS", "justakey")
    with pytest.raises(ValueError):
        AuthConfig.from_env()


def make_client(tmp_path, monkeypatch, keys):
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "auth.db"))
    monkeypatch.setenv("LOOM_API_KEYS", keys)
    from loom.api.http import app
    return TestClient(app)


def test_http_enforces_write_and_read_keys(tmp_path, monkeypatch):
    keys = "agent:default:w,dash:default:r"
    body = claim().model_dump(mode="json")
    with make_client(tmp_path, monkeypatch, keys) as client:
        assert client.post("/v1/ingest", json=body).status_code == 401
        assert client.post("/v1/ingest", json=body,
                           headers={"X-Loom-Key": "dash"}).status_code == 403
        r = client.post("/v1/ingest", json=body,
                        headers={"X-Loom-Key": "agent"})
        assert r.status_code == 200

        ask = {"subject": {"type": "host", "key": "web-01"},
               "question": "who?", "budget": 300}
        assert client.post("/v1/ask", json=ask).status_code == 401
        assert client.post("/v1/ask", json=ask,
                           headers={"X-Loom-Key": "agent"}).status_code == 403
        ok = client.post("/v1/ask", json=ask,
                         headers={"Authorization": "Bearer dash"})
        assert ok.status_code == 200 and ok.json()["items"]

        # health/readiness/metrics stay unauthenticated for probes/scrapes
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 200
        assert b"loom_ingest_total" in client.get("/metrics").content


# ------------------------------------------------------------------ D-013a #

def _generate_key(tmp_path, **overrides):
    """Run the keys CLI and return (plaintext_key, keys_file_path)."""
    import subprocess, sys
    path = tmp_path / "keys.json"
    argv = [sys.executable, "-m", "loom.keys", "--file", str(path), "generate",
            "--id", overrides.pop("id", "test-key"),
            "--perms", overrides.pop("perms", "rw")]
    for ns in overrides.pop("namespaces", ["default"]):
        argv += ["--namespace", ns]
    for flag, value in overrides.items():
        argv += [f"--{flag.replace('_', '-')}", str(value)]
    out = subprocess.run(argv, capture_output=True, text=True, check=True)
    return out.stdout.strip(), path


def test_keys_cli_generates_hashed_scoped_keys(tmp_path, monkeypatch):
    plaintext, path = _generate_key(
        tmp_path, id="shipper", perms="w", namespaces=["netsec"],
        entity_types="host,ip", sources="auth-log", expires_days=30,
    )
    assert plaintext.startswith("loomk_")
    assert plaintext not in path.read_text()  # hash only at rest

    monkeypatch.setenv("LOOM_AUTH_FILE", str(path))
    monkeypatch.delenv("LOOM_API_KEYS", raising=False)
    auth = AuthConfig.from_env()
    grant = auth.grant_for(plaintext)
    assert grant is not None and grant.id == "shipper"
    assert grant.allows("netsec", "w") and not grant.allows("netsec", "r")
    assert grant.allows_entity_type("host")
    assert not grant.allows_entity_type("vendor")
    assert grant.allows_source("auth-log")
    assert not grant.allows_source("forged")
    assert auth.grant_for("loomk_wrong") is None


def test_keys_cli_update_changes_grants_not_secret(tmp_path, monkeypatch):
    import os as _os
    import subprocess, sys
    plaintext, path = _generate_key(
        tmp_path, id="analyst", perms="r", entity_types="host",
    )
    monkeypatch.setenv("LOOM_AUTH_FILE", str(path))
    monkeypatch.delenv("LOOM_API_KEYS", raising=False)
    auth = AuthConfig.from_env()
    assert not auth.grant_for(plaintext).allows_entity_type("alert")

    subprocess.run([sys.executable, "-m", "loom.keys", "--file", str(path),
                    "update", "--id", "analyst",
                    "--entity-types", "host,alert", "--perms", "rw"],
                   check=True, capture_output=True)
    stat = _os.stat(path)
    _os.utime(path, (stat.st_atime, stat.st_mtime + 5))
    grant = auth.grant_for(plaintext)  # SAME key, hot-reloaded grants
    assert grant.allows_entity_type("alert")
    assert grant.allows("default", "w")

    # 'any' removes the gate entirely
    subprocess.run([sys.executable, "-m", "loom.keys", "--file", str(path),
                    "update", "--id", "analyst", "--entity-types", "any"],
                   check=True, capture_output=True)
    _os.utime(path, (stat.st_atime, stat.st_mtime + 10))
    assert auth.grant_for(plaintext).entity_types is None


def test_keys_cli_revoke_and_hot_reload(tmp_path, monkeypatch):
    import os as _os
    plaintext, path = _generate_key(tmp_path, id="rotate-me")
    monkeypatch.setenv("LOOM_AUTH_FILE", str(path))
    monkeypatch.delenv("LOOM_API_KEYS", raising=False)
    auth = AuthConfig.from_env()
    assert auth.grant_for(plaintext) is not None

    import subprocess, sys
    subprocess.run([sys.executable, "-m", "loom.keys", "--file", str(path),
                    "revoke", "--id", "rotate-me"], check=True)
    stat = _os.stat(path)
    _os.utime(path, (stat.st_atime, stat.st_mtime + 5))  # force mtime change
    assert auth.grant_for(plaintext) is None  # picked up without restart


def make_scoped_client(tmp_path, monkeypatch):
    """Engine client + a write key pinned to host/user types and auth-log,
    plus an unrestricted reader."""
    write_key, path = _generate_key(
        tmp_path, id="shipper", perms="w",
        entity_types="host,user", sources="auth-log",
    )
    import subprocess, sys
    read = subprocess.run(
        [sys.executable, "-m", "loom.keys", "--file", str(path), "generate",
         "--id", "analyst", "--namespace", "default", "--perms", "r"],
        capture_output=True, text=True, check=True).stdout.strip()
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "scoped.db"))
    monkeypatch.setenv("LOOM_AUTH_FILE", str(path))
    monkeypatch.delenv("LOOM_API_KEYS", raising=False)
    for var in ("LOOM_LLM_MODEL", "LOOM_LLM_PROVIDER",
                "LOOM_LLM_BASE_URL", "LOOM_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)  # hermetic: no real provider
    from loom.api.http import app
    return TestClient(app), write_key, read


def test_http_scoping_gates(tmp_path, monkeypatch):
    client, write_key, read_key = make_scoped_client(tmp_path, monkeypatch)
    with client:
        headers = {"X-Loom-Key": write_key}
        ok = claim().model_dump(mode="json")
        assert client.post("/v1/ingest", json=ok, headers=headers).status_code == 200

        forged = {**ok, "source": "forged-feed"}
        r = client.post("/v1/ingest", json=forged, headers=headers)
        assert r.status_code == 403 and "source" in r.json()["detail"]

        wrong_type = {**ok, "subject": {"type": "vendor", "key": "initech"}}
        r = client.post("/v1/ingest", json=wrong_type, headers=headers)
        assert r.status_code == 403 and "entity type" in r.json()["detail"]

        # the LLM/query path itself is NEVER blocked for a valid reader: an
        # unrestricted read key hits 503 (no LLM configured), not 403
        r = client.post("/v1/answer", json={"question": "web-01?"},
                        headers={"X-Loom-Key": read_key})
        assert r.status_code == 503

def make_type_scoped_reader(tmp_path, monkeypatch, entity_types="host,user"):
    """Engine client + a reader key that may only see the given types, plus
    an unrestricted writer to seed data with."""
    import subprocess, sys
    reader, path = _generate_key(
        tmp_path, id="analyst", perms="r", entity_types=entity_types,
    )
    writer = subprocess.run(
        [sys.executable, "-m", "loom.keys", "--file", str(path), "generate",
         "--id", "root", "--namespace", "default", "--perms", "rw"],
        capture_output=True, text=True, check=True).stdout.strip()
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "scoped-read.db"))
    monkeypatch.setenv("LOOM_AUTH_FILE", str(path))
    monkeypatch.delenv("LOOM_API_KEYS", raising=False)
    monkeypatch.delenv("LOOM_HANDLE_SECRET", raising=False)
    from loom.api.http import app
    return TestClient(app), reader, writer


def _seed_scoped_world(client, writer):
    """host web-01 (in scope) with a login, a domain membership (out-of-scope
    object) and a vendor (out-of-scope subject) that also names web-01."""
    h = {"X-Loom-Key": writer}
    web01 = {"type": "host", "key": "web-01"}
    rows = [
        dict(subject=web01, predicate="logged_in_by",
             object={"type": "user", "key": "jdoe"}),
        dict(subject=web01, predicate="member_of",
             object={"type": "domain", "key": "corp.local"}),
        dict(subject={"type": "vendor", "key": "initech"}, predicate="supports",
             object=web01),
        dict(subject={"type": "vendor", "key": "initech"}, predicate="contract_owner",
             object="asmith"),
    ]
    for i, row in enumerate(rows):
        for _ in range(3):  # enough volume that tiny budgets leave handles
            body = {"kind": "claim", "namespace": "default", "source": "seed",
                    "observed_at": (OBSERVED + timedelta(hours=i)).isoformat(),
                    **row}
            assert client.post("/v1/ingest", json=body, headers=h).status_code == 200


def test_scoped_reader_sees_only_its_world(tmp_path, monkeypatch):
    """H-A2: scope expansion and object-side entities honor entity_types."""
    client, reader, writer = make_type_scoped_reader(tmp_path, monkeypatch)
    with client:
        _seed_scoped_world(client, writer)
        h = {"X-Loom-Key": reader}
        # explicit out-of-scope subject: a named wall (403)
        r = client.post("/v1/ask", json={
            "subject": {"type": "vendor", "key": "initech"},
            "question": "owner?", "budget": 500}, headers=h)
        assert r.status_code == 403
        # scope expansion over member_of would reach domain:corp.local; a
        # host-scoped reader must never see it, nor the edge pointing at it
        r = client.post("/v1/ask", json={
            "scope": {"subjects": [{"type": "host", "key": "web-01"}],
                      "expand": ["member_of", "supports"], "depth": 2},
            "question": "everything", "budget": 4000}, headers=h)
        assert r.status_code == 200
        pack = r.json()
        assert {s["type"] for s in pack["subjects"]} <= {"host", "user"}
        for item in pack["items"]:
            assert "domain:" not in item["text"] and "vendor:" not in item["text"]
        assert any("logged_in_by" in i["text"] for i in pack["items"])
        # unrestricted reader still sees the whole graph
        r = client.post("/v1/ask", json={
            "scope": {"subjects": [{"type": "host", "key": "web-01"}],
                      "expand": ["member_of", "supports"], "depth": 2},
            "question": "everything", "budget": 4000},
            headers={"X-Loom-Key": writer})
        assert any("domain:corp.local" in i["text"] for i in r.json()["items"])


def test_expand_handle_passes_entity_type_gate(tmp_path, monkeypatch):
    """H-A1: a forged handle for an out-of-scope subject is a 403, and a
    legitimate handle only yields in-scope observations."""
    from loom.context import encode_handle
    client, reader, writer = make_type_scoped_reader(tmp_path, monkeypatch)
    with client:
        _seed_scoped_world(client, writer)
        forged = encode_handle("default", EntityRef(type="vendor", key="initech"),
                               "contract_owner", None)
        r = client.post("/v1/expand", json={"handle": forged, "budget": 500},
                        headers={"X-Loom-Key": reader})
        assert r.status_code == 403
        # the unrestricted key can use the same handle
        r = client.post("/v1/expand", json={"handle": forged, "budget": 500},
                        headers={"X-Loom-Key": writer})
        assert r.status_code == 200 and r.json()["items"]
        # a handle for an in-scope subject but an out-of-scope edge yields
        # nothing rather than leaking the domain edge
        edge = encode_handle("default", EntityRef(type="host", key="web-01"),
                             "member_of", None)
        r = client.post("/v1/expand", json={"handle": edge, "budget": 500},
                        headers={"X-Loom-Key": reader})
        assert r.status_code == 200 and r.json()["items"] == []
        # garbage handles are 400s, never 500s
        import base64
        as_list = "h1_" + base64.urlsafe_b64encode(b"[1,2]").decode().rstrip("=")
        for bad in ("nope", "h1_!!!", as_list):
            r = client.post("/v1/expand", json={"handle": bad, "budget": 500},
                            headers={"X-Loom-Key": reader})
            assert r.status_code == 400, bad


def test_expand_clamps_budget_to_ceiling(tmp_path, monkeypatch):
    """H-A3: expand honors LOOM_MAX_BUDGET like ask does."""
    from loom.context import encode_handle, expand_pack
    store = SqliteStore(tmp_path / "clamp.db")
    for i in range(5):
        store.record_claim(claim(event_id=f"e{i}"))
    monkeypatch.setenv("LOOM_MAX_BUDGET", "120")
    handle = encode_handle("default", EntityRef(type="host", key="web-01"),
                           "logged_in_by", None)
    pack = expand_pack(store, handle, budget=100_000)
    assert pack.budget == 120


def test_signed_handles_reject_forgery(monkeypatch):
    """LOOM_HANDLE_SECRET: only handles this deployment issued are accepted."""
    from loom.context import decode_handle, encode_handle
    ref = EntityRef(type="host", key="web-01")
    monkeypatch.delenv("LOOM_HANDLE_SECRET", raising=False)
    unsigned = encode_handle("default", ref, "p", None)
    assert unsigned.startswith("h1_") and decode_handle(unsigned)["ns"] == "default"

    monkeypatch.setenv("LOOM_HANDLE_SECRET", "s3cret")
    signed = encode_handle("default", ref, "p", None)
    assert signed.startswith("h2_") and decode_handle(signed)["predicate"] == "p"
    with pytest.raises(ValueError):
        decode_handle(unsigned)  # unsigned no longer accepted
    with pytest.raises(ValueError):
        decode_handle(signed[:-2] + "zz")  # tampered signature
    body, _, sig = signed[3:].partition(".")
    other = encode_handle("default", EntityRef(type="vendor", key="x"), "p", None)
    with pytest.raises(ValueError):
        decode_handle("h2_" + other[3:].partition(".")[0] + "." + sig)
    monkeypatch.setenv("LOOM_HANDLE_SECRET", "different")
    with pytest.raises(ValueError):
        decode_handle(signed)  # rotated secret invalidates outstanding handles


def test_redaction_tombstones_hide_but_preserve(tmp_path):
    store = SqliteStore(tmp_path / "l.db")
    obs = store.record_claim(claim())
    assert store.redact("default", obs.id, "classified spill") is True
    assert store.observations_for(
        "default", EntityRef(type="host", key="web-01")) == []
    # still exported for audit
    assert any(o.id == obs.id for o in store.iter_observations("default"))
    assert store.redact("default", "nope", "x") is False


def test_retention_purge(tmp_path):
    store = SqliteStore(tmp_path / "l.db")
    old = OBSERVED - timedelta(days=400)
    store.record_claim(claim())
    store.record_claim(claim(observed=old))
    removed = store.purge_older_than("default", OBSERVED - timedelta(days=90))
    assert removed == 1
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert len(obs) == 1 and obs[0].observed_at == OBSERVED


def test_export_import_roundtrip_across_stores(tmp_path):
    src = SqliteStore(tmp_path / "src.db")
    src.record_claim(claim(event_id="evt-9"))
    src.store_artifact(DocumentIn(text="report", source="ir",
                                  observed_at=OBSERVED))
    buffer = io.StringIO()
    counts = export_jsonl(src, buffer, namespace=None)
    assert counts["observations"] == 1 and counts["artifacts"] == 1

    dst = SqliteStore(tmp_path / "dst.db")
    buffer.seek(0)
    import_jsonl(dst, buffer)
    obs = dst.observations_for("default", EntityRef(type="host", key="web-01"))
    assert len(obs) == 1 and obs[0].event_id == "evt-9"
    # import is idempotent
    buffer.seek(0)
    import_jsonl(dst, buffer)
    assert len(dst.observations_for(
        "default", EntityRef(type="host", key="web-01"))) == 1
