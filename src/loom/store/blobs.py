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
import logging
import os
from pathlib import Path
from typing import Any, Iterator, Protocol

from ..contracts import Artifact, DocumentIn
from .base import GraphStore

log = logging.getLogger("loom.store")

_MARK = "_blob"   # attrs key: {"backend": ..., "key": ..., "field": "text"|"content_b64"}
_MISSING = "_blob_missing"   # attrs marker: the pointer's blob is gone; the body is None


def _body_size(field: str, body: str) -> int:
    """Bytes the body represents: UTF-8 length for text, the *decoded*
    length for base64 (the text is a third larger than the file it
    encodes, so comparing it to a byte threshold offloaded too early)."""
    if field == "text":
        return len(body.encode())
    stripped = body.strip()
    padding = 2 if stripped.endswith("==") else 1 if stripped.endswith("=") else 0
    return len(stripped) * 3 // 4 - padding


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

    def _plan(self, namespace: str, artifact_id: str, text: str | None,
              b64: str | None, attrs: dict) -> tuple[str, str, str, dict] | None:
        """(field, body, key, attrs-with-pointer) when the body is above the
        threshold, else None. Decides only; nothing is written here."""
        field, body = ("text", text) if text is not None else ("content_b64", b64)
        if body is None or _body_size(field, body) <= self._threshold:
            return None
        key = f"{namespace}/{artifact_id}"
        return field, body, key, {**attrs, _MARK: {"backend": self._blobs.name, "key": key, "field": field}}

    def _write_through(self, key: str, body: str, insert):
        """Put the blob, then the row; a row that never landed must not
        leave a blob behind, and a row that landed must never point at a
        blob that was not written — so the blob goes first and is removed
        if the insert raises."""
        self._blobs.put(key, body.encode())
        try:
            return insert()
        except BaseException:
            self._blobs.delete(key)
            raise

    def _inflate(self, artifact: Artifact) -> Artifact:
        mark = artifact.attrs.get(_MARK)
        if not isinstance(mark, dict):
            return artifact
        data = self._blobs.get(mark["key"])
        if data is None:
            # The row survives with its pointer (an operator can see what
            # vanished); the body is reported absent rather than served as
            # the stub text, which readers would otherwise take for content.
            log.warning("artifact %s/%s: blob %s is missing from the %s store; body unavailable",
                        artifact.namespace, artifact.id, mark["key"], mark.get("backend", "?"))
            return artifact.model_copy(update={
                "text": None, "content_b64": None, "attrs": {**artifact.attrs, _MISSING: True}})
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
        plan = self._plan(doc.namespace, uuid.uuid4().hex, doc.text, doc.content_b64, doc.attrs)
        if plan is None:
            return self._inflate(self._inner.store_artifact(doc))
        field, body, key, attrs = plan
        # keep the DocumentIn contract (exactly one body) with a stub in the
        # same field; the real body is behind the pointer
        slim = doc.model_copy(update={**_stub(field, key), "attrs": attrs})
        stored = self._write_through(key, body, lambda: self._inner.store_artifact(slim))
        if stored.attrs.get(_MARK) != attrs[_MARK]:
            # the inner store deduped to an earlier artifact: drop our orphan blob
            self._blobs.delete(key)
        return self._inflate(stored)

    def restore_artifact(self, artifact: Artifact) -> None:
        plan = self._plan(artifact.namespace, artifact.id, artifact.text,
                          artifact.content_b64, artifact.attrs)
        if plan is None or _MARK in artifact.attrs:   # small, or already a pointer (raw export)
            self._inner.restore_artifact(artifact)
            return
        field, body, key, attrs = plan
        slim = artifact.model_copy(update={**_stub(field, key), "attrs": attrs})
        self._write_through(key, body, lambda: self._inner.restore_artifact(slim))

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


# Every public GraphStore method the wrapper does not define itself is
# delegated — the concrete defaults too. Delegating only the abstract ones
# left `record_claims` on the base class's one-transaction-per-claim
# fallback and `observations_for_many` on one round trip per ref whenever
# offload was configured (the D-043 regression, reintroduced by the wrapper).
for _name, _fn in list(vars(GraphStore).items()):
    if _name.startswith("_") or not callable(_fn) or _name in vars(BlobOffloadStore):
        continue
    setattr(BlobOffloadStore, _name,
            _delegate_iter(_name) if inspect.isgeneratorfunction(_fn) or _name.startswith("iter_")
            else _delegate(_name))
abc.update_abstractmethods(BlobOffloadStore)
