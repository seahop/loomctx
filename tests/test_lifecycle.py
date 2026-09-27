"""The lifecycle CLI (D-016) opens the engine's store: LOOMCTX_DB plus
LOOMCTX_SHARDS and LOOMCTX_BLOB_* — not a bare LOOMCTX_DB — so an export of a
sharded, offloading deployment is complete; `--db` is the escape hatch."""

import json
from datetime import datetime, timezone

import pytest

from loomctx.contracts import ClaimIn, DocumentIn, EntityRef
from loomctx.lifecycle import main, parse_ref
from loomctx.store.blobs import BlobOffloadStore
from loomctx.store.factory import store_from_env
from loomctx.store.sqlite import SqliteStore

OBSERVED = datetime(2026, 9, 1, tzinfo=timezone.utc)


@pytest.fixture
def offloading_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "main.db"))
    monkeypatch.setenv("LOOMCTX_SHARDS", json.dumps({"acme": str(tmp_path / "acme.db")}))
    monkeypatch.setenv("LOOMCTX_BLOB_THRESHOLD", "50")
    monkeypatch.setenv("LOOMCTX_BLOB_DIR", str(tmp_path / "blobs"))
    monkeypatch.delenv("LOOMCTX_DB_READ", raising=False)
    return tmp_path


def test_export_uses_the_env_store_and_writes_real_bodies(offloading_env, tmp_path, capsys):
    big = "x" * 400
    s = store_from_env()
    assert isinstance(s, BlobOffloadStore)
    art = s.store_artifact(DocumentIn(namespace="acme", text=big, source="s", observed_at=OBSERVED))
    s.record_claim(ClaimIn(namespace="acme", subject=EntityRef(type="h", key="k"), predicate="p",
                           object="v", observed_at=OBSERVED, source="s"))
    s.close()
    out = tmp_path / "dump.jsonl"
    main(["export", "--out", str(out)])
    records = [json.loads(l) for l in out.read_text().splitlines()]
    arts = [r["data"] for r in records if r["type"] == "artifact"]
    assert [a["id"] for a in arts] == [art.id] and arts[0]["text"] == big     # the shard AND the body
    assert "_blob" not in arts[0]["attrs"]
    assert "exported" in capsys.readouterr().err

    # --db opens one bare database: no shard routing, no reinflation
    main(["--db", str(tmp_path / "acme.db"), "export", "--out", str(tmp_path / "raw.jsonl")])
    raw = [json.loads(l)["data"] for l in (tmp_path / "raw.jsonl").read_text().splitlines()
           if json.loads(l)["type"] == "artifact"]
    assert raw[0]["text"].startswith("[offloaded:") and "_blob" in raw[0]["attrs"]
    main(["--db", str(tmp_path / "main.db"), "export", "--out", str(tmp_path / "main.jsonl")])
    assert (tmp_path / "main.jsonl").read_text() == ""                      # the default db holds nothing


def test_import_through_the_env_store_offloads_again(offloading_env, tmp_path, monkeypatch, capsys):
    big = "y" * 400
    src = SqliteStore(tmp_path / "source.db")
    art = src.store_artifact(DocumentIn(namespace="acme", text=big, source="s", observed_at=OBSERVED))
    src.close()
    dump = tmp_path / "src.jsonl"
    main(["--db", str(tmp_path / "source.db"), "export", "--out", str(dump)])
    main(["import", "--path", str(dump)])
    assert "imported" in capsys.readouterr().out
    s = store_from_env()
    try:
        assert s.get_artifact("acme", art.id).text == big
    finally:
        s.close()
    inner = SqliteStore(tmp_path / "acme.db")                              # routed to the shard, body offloaded
    try:
        row = inner.get_artifact("acme", art.id)
        assert row.attrs["_blob"]["field"] == "text" and row.text.startswith("[offloaded:")
    finally:
        inner.close()


def test_unmerge_subcommand(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "u.db"))
    monkeypatch.delenv("LOOMCTX_SHARDS", raising=False)
    monkeypatch.delenv("LOOMCTX_BLOB_THRESHOLD", raising=False)
    s = SqliteStore(tmp_path / "u.db")
    a, b = EntityRef(type="ip_address", key="10.0.4.7"), EntityRef(type="ip", key="10.0.4.7")
    for ref in (a, b):
        s.record_claim(ClaimIn(subject=ref, predicate=f"from_{ref.type}", object="x",
                               observed_at=OBSERVED, source="s"))
    assert s.merge_entities("default", a, b)
    s.close()
    main(["unmerge", "--namespace", "default", "--alias", "ip_address:10.0.4.7"])
    assert capsys.readouterr().out.strip() == "unmerged"
    s = SqliteStore(tmp_path / "u.db")
    try:
        assert {o.predicate for o in s.observations_for("default", a)} == {"from_ip_address"}
        assert {o.predicate for o in s.observations_for("default", b)} == {"from_ip"}
    finally:
        s.close()
    with pytest.raises(SystemExit):
        main(["unmerge", "--namespace", "default", "--alias", "ip_address:10.0.4.7"])
    assert "no merge on record" in capsys.readouterr().out
    assert parse_ref("url:https://x/y:8080") == EntityRef(type="url", key="https://x/y:8080")
    with pytest.raises(ValueError):
        parse_ref("nocolon")
