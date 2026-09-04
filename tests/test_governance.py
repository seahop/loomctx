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


# ------------------------------------------------------------------- D-016 #

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
