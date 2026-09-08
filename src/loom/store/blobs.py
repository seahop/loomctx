"""Artifact offload (D-033): large document bodies live in a blob store,
the transactional database keeps the row and a pointer.

Off by default. `LOOM_BLOB_THRESHOLD` (bytes) turns it on: a document whose
text/bytes exceed it is written to `LOOM_BLOB_DIR` (a shared volume) or,
with `LOOM_BLOB_S3_BUCKET`, to any S3-compatible service (AWS S3, MinIO,
Ceph RGW, ...) under `<namespace>/<artifact_id>`. Every read path that
returns an Artifact reinflates it transparently — the worker, the API, and
`lifecycle export` all see the full body — so nothing above the store
interface knows. Import offloads again on the way in.

Persistence stays behind `GraphStore` (hard rule): `BlobOffloadStore` wraps
whatever store the factory built.
"""

from __future__ import annotations

import abc
import inspect
import os
from pathlib import Path
from typing import Any, Iterator, Protocol

from ..contracts import Artifact, DocumentIn
from .base import GraphStore

_MARK = "_blob"   # attrs key: {"backend": ..., "key": ..., "field": "text"|"content_b64"}


def _stub(field: str, key: str) -> dict:
    """What the row holds instead of the body. The text stub is deliberately
    non-blank: the chunking backlog skips blank documents, and an offloaded
    document must still be chunked (after reinflation)."""
    if field == "text":
        return {"text": f"[offloaded: {key}]", "content_b64": None}
    return {"text": None, "content_b64": ""}


class BlobStore(Protocol):
    name: str

    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes | None: ...
    def delete(self, key: str) -> None: ...


class FilesystemBlobs:
    """A directory — a shared PVC/volume in practice."""

    name = "fs"

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        p = (self.root / key).resolve()
        if self.root.resolve() not in p.parents:
            raise ValueError(f"blob key escapes the root: {key!r}")
        return p

    def put(self, key: str, data: bytes) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(p)   # atomic on POSIX

    def get(self, key: str) -> bytes | None:
        p = self._path(key)
        return p.read_bytes() if p.exists() else None

    def delete(self, key: str) -> None:
        p = self._path(key)
        if p.exists():
            p.unlink()


class S3Blobs:
    """Any S3-compatible service via boto3 (extra `s3`). `client` can be
    injected (tests); otherwise built from LOOM_BLOB_S3_* / AWS_* env."""

    name = "s3"

    def __init__(self, bucket: str, prefix: str = "", client: Any = None,
                 endpoint_url: str | None = None):
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        if client is None:
            import boto3  # optional dependency
            client = boto3.client("s3", endpoint_url=endpoint_url)
        self._c = client

    def _k(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def put(self, key: str, data: bytes) -> None:
        self._c.put_object(Bucket=self.bucket, Key=self._k(key), Body=data)

    def get(self, key: str) -> bytes | None:
        try:
            return self._c.get_object(Bucket=self.bucket, Key=self._k(key))["Body"].read()
        except Exception as exc:  # noqa: BLE001 — botocore's NoSuchKey is dynamic
            if type(exc).__name__ in ("NoSuchKey", "NotFound") or "NoSuchKey" in str(exc):
                return None
            raise

    def delete(self, key: str) -> None:
        self._c.delete_object(Bucket=self.bucket, Key=self._k(key))


def blobs_from_env() -> BlobStore | None:
    """None unless offload is configured (the default)."""
    if os.environ.get("LOOM_BLOB_S3_BUCKET", "").strip():
        return S3Blobs(os.environ["LOOM_BLOB_S3_BUCKET"].strip(),
                       prefix=os.environ.get("LOOM_BLOB_S3_PREFIX", "loom"),
                       endpoint_url=os.environ.get("LOOM_BLOB_S3_ENDPOINT", "").strip() or None)
    if os.environ.get("LOOM_BLOB_DIR", "").strip():
        return FilesystemBlobs(os.environ["LOOM_BLOB_DIR"].strip())
    return None


def threshold_from_env() -> int | None:
    raw = os.environ.get("LOOM_BLOB_THRESHOLD", "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


class BlobOffloadStore(GraphStore):
    """Wraps a GraphStore: bodies above `threshold` bytes go to `blobs`;
    every returned Artifact comes back whole."""

    def __init__(self, inner: GraphStore, blobs: BlobStore, threshold: int):
        self._inner = inner
        self._blobs = blobs
        self._threshold = threshold

    # ------------------------------------------------------------ offload

    def _offload(self, namespace: str, artifact_id: str, text: str | None,
                 b64: str | None, attrs: dict) -> tuple[str | None, str | None, dict]:
        field, body = ("text", text) if text is not None else ("content_b64", b64)
        if body is None or len(body.encode()) <= self._threshold:
            return text, b64, attrs
        key = f"{namespace}/{artifact_id}"
        self._blobs.put(key, body.encode())
        attrs = {**attrs, _MARK: {"backend": self._blobs.name, "key": key, "field": field}}
        return (None, None, attrs)

    def _inflate(self, artifact: Artifact) -> Artifact:
        mark = artifact.attrs.get(_MARK)
        if not isinstance(mark, dict):
            return artifact
        data = self._blobs.get(mark["key"])
        if data is None:
            return artifact  # pointer to a vanished blob: body stays absent, row survives
        attrs = {k: v for k, v in artifact.attrs.items() if k != _MARK}
        return artifact.model_copy(update={mark["field"]: data.decode(), "attrs": attrs})

    def _inflate_all(self, value):
        if isinstance(value, Artifact):
            return self._inflate(value)
        if isinstance(value, list) and value and isinstance(value[0], Artifact):
            return [self._inflate(a) for a in value]
        return value

    def store_artifact(self, doc: DocumentIn) -> Artifact:
        import uuid
        artifact_id = uuid.uuid4().hex
        text, b64, attrs = self._offload(doc.namespace, artifact_id, doc.text,
                                         doc.content_b64, doc.attrs)
        if text is None and b64 is None:
            # keep the DocumentIn contract (exactly one body) with a stub in
            # the same field; the real body is behind the pointer
            slim = doc.model_copy(update={**_stub(attrs[_MARK]["field"], attrs[_MARK]["key"]),
                                          "attrs": attrs})
        else:
            slim = doc
        stored = self._inner.store_artifact(slim)
        if stored.id != artifact_id and _MARK in attrs and stored.attrs.get(_MARK) != attrs[_MARK]:
            # the inner store deduped to an earlier artifact: drop our orphan blob
            self._blobs.delete(attrs[_MARK]["key"])
        return self._inflate(stored)

    def restore_artifact(self, artifact: Artifact) -> None:
        text, b64, attrs = self._offload(artifact.namespace, artifact.id,
                                         artifact.text, artifact.content_b64, artifact.attrs)
        if _MARK in attrs and _MARK not in artifact.attrs:
            artifact = artifact.model_copy(
                update={**_stub(attrs[_MARK]["field"], attrs[_MARK]["key"]), "attrs": attrs})
        self._inner.restore_artifact(artifact)

    def purge_older_than(self, namespace, before) -> int:
        # blobs of purged artifacts are removed by key; walk the candidates first
        doomed = [a for a in self._inner.iter_artifacts(namespace)
                  if a.observed_at < before and isinstance(a.attrs.get(_MARK), dict)]
        removed = self._inner.purge_older_than(namespace, before)
        for a in doomed:
            self._blobs.delete(a.attrs[_MARK]["key"])
        return removed

    def close(self) -> None:
        self._inner.close()


def _delegate(name: str):
    def method(self: BlobOffloadStore, *args, **kwargs):
        return self._inflate_all(getattr(self._inner, name)(*args, **kwargs))
    method.__name__ = name
    method.__doc__ = getattr(GraphStore, name).__doc__
    return method


def _delegate_iter(name: str):
    def method(self: BlobOffloadStore, *args, **kwargs) -> Iterator:
        for item in getattr(self._inner, name)(*args, **kwargs):
            yield self._inflate_all(item)
    method.__name__ = name
    return method


for _name, _fn in list(vars(GraphStore).items()):
    if not getattr(_fn, "__isabstractmethod__", False) or _name in vars(BlobOffloadStore):
        continue
    setattr(BlobOffloadStore, _name,
            _delegate_iter(_name) if inspect.isgeneratorfunction(_fn) or _name.startswith("iter_")
            else _delegate(_name))
abc.update_abstractmethods(BlobOffloadStore)
