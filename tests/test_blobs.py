"""Artifact offload (D-033): large bodies in a blob store, rows keep a pointer."""

from datetime import datetime, timezone

from loom.contracts import DocumentIn, EntityRef, ClaimIn
from loom.store.blobs import BlobOffloadStore, FilesystemBlobs, S3Blobs
from loom.store.sqlite import SqliteStore

OBSERVED = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _store(tmp_path, threshold=100):
    tmp_path.mkdir(parents=True, exist_ok=True)
    inner = SqliteStore(tmp_path / "inner.db")
    return BlobOffloadStore(inner, FilesystemBlobs(tmp_path / "blobs"), threshold), inner


def test_large_bodies_offload_and_reinflate_everywhere(tmp_path):
    store, inner = _store(tmp_path)
    big = "x" * 500
    art = store.store_artifact(DocumentIn(text=big, filename="big.txt", source="s",
                                          observed_at=OBSERVED, event_id="d1"))
    assert art.text == big and "_blob" not in art.attrs      # caller sees the whole thing
    raw = inner.get_artifact("default", art.id)
    assert raw.text.startswith("[offloaded:") and raw.attrs["_blob"]["field"] == "text"  # slim row
    key = raw.attrs["_blob"]["key"]
    assert key.startswith("default/") and (tmp_path / "blobs" / key).read_text() == big
    # every read path reinflates: get, iter (export), worker backlogs
    assert store.get_artifact("default", art.id).text == big
    assert next(store.iter_artifacts("default")).text == big
    assert store.pending_artifacts(5)[0].text == big
    assert store.artifacts_needing_chunks("m", 5)[0].text == big
    # small bodies stay inline
    small = store.store_artifact(DocumentIn(text="tiny", source="s", observed_at=OBSERVED))
    assert inner.get_artifact("default", small.id).text == "tiny"
    # a replay (same event_id) doesn't leave a second blob behind
    again = store.store_artifact(DocumentIn(text=big, filename="big.txt", source="s",
                                            observed_at=OBSERVED, event_id="d1"))
    assert again.id == art.id
    assert [p.name for p in (tmp_path / "blobs" / "default").iterdir()] == [key.split("/")[1]]


def test_binary_bodies_export_import_and_purge(tmp_path):
    import io
    from datetime import timedelta
    from loom.lifecycle import export_jsonl, import_jsonl
    store, inner = _store(tmp_path)
    b64 = "QUJD" * 100
    art = store.store_artifact(DocumentIn(content_b64=b64, content_type="application/octet-stream",
                                          source="s", observed_at=OBSERVED))
    assert store.get_artifact("default", art.id).content_b64 == b64
    buf = io.StringIO()
    export_jsonl(store, buf, None)
    assert b64 in buf.getvalue()                       # exports carry the body
    dst, dst_inner = _store(tmp_path / "dst")
    buf.seek(0)
    import_jsonl(dst, buf)
    assert dst.get_artifact("default", art.id).content_b64 == b64
    assert dst_inner.get_artifact("default", art.id).content_b64 == ""   # offloaded on import
    # purge removes the blob with the row
    key = inner.get_artifact("default", art.id).attrs["_blob"]["key"]
    assert (tmp_path / "blobs" / key).exists()
    removed = store.purge_older_than("default", OBSERVED + timedelta(days=1))
    assert removed == 1 and not (tmp_path / "blobs" / key).exists()
    # everything else passes straight through
    obs = store.record_claim(ClaimIn(subject=EntityRef(type="h", key="k"), predicate="p",
                                     object="v", observed_at=OBSERVED, source="s"))
    assert store.observations_for("default", EntityRef(type="h", key="k"))[0].id == obs.id


def test_s3_backend_with_a_fake_client():
    class FakeS3:
        def __init__(self):
            self.objects = {}

        def put_object(self, Bucket, Key, Body):
            self.objects[(Bucket, Key)] = Body

        def get_object(self, Bucket, Key):
            if (Bucket, Key) not in self.objects:
                raise type("NoSuchKey", (Exception,), {})("missing")
            return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

        def delete_object(self, Bucket, Key):
            self.objects.pop((Bucket, Key), None)

    import io
    fake = FakeS3()
    blobs = S3Blobs("bucket", prefix="loom", client=fake)
    blobs.put("ns/a1", b"hello")
    assert ("bucket", "loom/ns/a1") in fake.objects
    assert blobs.get("ns/a1") == b"hello" and blobs.get("ns/none") is None
    blobs.delete("ns/a1")
    assert blobs.get("ns/a1") is None


def test_filesystem_backend_rejects_escaping_keys(tmp_path):
    import pytest
    blobs = FilesystemBlobs(tmp_path / "b")
    with pytest.raises(ValueError):
        blobs.put("../outside", b"x")


def test_offload_from_env(tmp_path, monkeypatch):
    from loom.store.factory import store_from_env
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "e.db"))
    monkeypatch.setenv("LOOM_BLOB_THRESHOLD", "10")
    monkeypatch.setenv("LOOM_BLOB_DIR", str(tmp_path / "blobs"))
    s = store_from_env()
    assert isinstance(s, BlobOffloadStore)
    art = s.store_artifact(DocumentIn(text="0123456789abcdef", source="s", observed_at=OBSERVED))
    assert s.get_artifact("default", art.id).text == "0123456789abcdef"
    s.close()
    monkeypatch.delenv("LOOM_BLOB_THRESHOLD")
    assert isinstance(store_from_env(), SqliteStore)
