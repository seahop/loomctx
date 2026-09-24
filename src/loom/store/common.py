"""Row/model conversion shared by the store backends.

Both SQLite and Postgres persist identical column shapes (timestamps as ISO
text, objects/attrs as JSON text), so the mapping back to contract models is
written once here. Rows only need dict-style access by column name.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping

import re

from ..contracts import (
    Artifact, Entity, EntityRef, Observation, Provenance, SchemaRegistration,
)

_NORM = re.compile(r"[^a-z0-9]+")
_WS = re.compile(r"\s+")
# digit-dominated keys — IPs, CIDRs, ports, versions — where the punctuation
# IS the structure: stripping it made 10.0.4.7, 100.4.7 and 1.0.0.47 collide
_NUMERIC = re.compile(r"^[\d.:/\-]+$")
# colon-structured hex keys — IPv6 addresses, MAC addresses, address:port —
# where the colons (and dots, for v4-mapped forms) are the structure too:
# 2001:db8::1 and 2001:db8:0:0:0:0:0:1 stay distinct from 2001db81 (v6)
_HEX_STRUCTURED = re.compile(r"^(?=.*:)[0-9a-f.:/]+$")


def norm_key(key: str) -> str:
    """The fuzzy-match key (D-024 entity resolution tier 2): lowercase with
    punctuation/whitespace stripped, so web-01 / WEB_01 / web01 collide.
    A key made only of digits and `. : / -` keeps those characters (only
    case and whitespace fold): 10.0.4.7 and 100.4.7 are different things.
    So does a key with a colon made only of hex digits and `. : /` (IPv6,
    MAC addresses): fe80::1 and FE80::1 collide, fe80::1 and fe80::10 do
    not (schema v6)."""
    lowered = _WS.sub("", key.lower())
    if _NUMERIC.match(lowered) or _HEX_STRUCTURED.match(lowered):
        return lowered
    return _NORM.sub("", lowered)


_SLUG = re.compile(r"[^a-z0-9]+")


def vec_slug(model: str) -> str:
    """The embedding model's table-name slug."""
    return _SLUG.sub("_", model.lower()).strip("_")


def vec_table(kind: str, model: str, dim: int) -> str:
    """Name of the ANN index table (D-025): vobs_/vchk_ + a slug of the
    embedding model + the dimension, so vectors from different models — or
    a model that changed size — never share an index."""
    return f"{kind}_{vec_slug(model)}_{int(dim)}"


def vec_tables_for(kind: str, model: str, names) -> list[str]:
    """The index tables that belong to exactly this (kind, model) — one per
    dimension it has been seen with. A prefix test matched every model
    (`vobs_m_` is a prefix of `vobs_m2_...` only by luck of naming, but
    `vobs_text_embedding_3_` is a prefix of `vobs_text_embedding_3_large_`)."""
    pattern = re.compile(rf"^{re.escape(kind)}_{re.escape(vec_slug(model))}_\d+$")
    return [n for n in names if pattern.match(n)]


try:  # optional accelerator (extra "vector"); pure Python otherwise
    import numpy as _np
except ImportError:  # pragma: no cover
    _np = None


_VEC_MAGIC = b"\x00f32"   # a JSON text never starts with NUL


def pack_vector(vec: list[float]) -> bytes:
    """float32 little-endian with a 4-byte magic prefix: ~6 KB for 1,536
    dims instead of ~30 KB of JSON text. 228k JSON vectors had grown a
    store to 10 GB (D-039)."""
    import array
    return _VEC_MAGIC + array.array("f", vec).tobytes()


def unpack_vector(raw) -> list[float]:
    """Accepts the packed form, legacy JSON text, and legacy JSON that a
    TEXT -> BYTEA migration turned into bytes."""
    import array
    if isinstance(raw, memoryview):
        raw = raw.tobytes()
    if isinstance(raw, (bytes, bytearray)):
        if raw[:4] == _VEC_MAGIC:
            arr = array.array("f")
            arr.frombytes(bytes(raw[4:]))
            return arr.tolist()
        raw = bytes(raw).decode("utf-8")
    return json.loads(raw)


def unpack_array(raw):
    """unpack_vector for the exact-scan hot path: a zero-copy float32 view
    of a packed vector when numpy is installed — no list of Python floats
    per row, which was most of the cost of scanning thousands of chunk
    vectors (D-058). Legacy JSON rows, or no numpy, fall back to the list."""
    if _np is not None:
        if isinstance(raw, memoryview):
            raw = raw.tobytes()
        if isinstance(raw, (bytes, bytearray)) and raw[:4] == _VEC_MAGIC and len(raw) % 4 == 0:
            return _np.frombuffer(raw, dtype="<f4", offset=4)
    return unpack_vector(raw)


def raw_f32(vec: list[float]) -> bytes:
    """The bare float32 buffer sqlite-vec accepts as a vector literal."""
    import array
    return array.array("f", vec).tobytes()


def cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0  # different embedding spaces never compare
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def cosines(query: list[float], vectors: dict[str, list[float]]) -> dict[str, float]:
    """Cosine of the query against many vectors at once — one matrix
    product with numpy when installed, the scalar loop otherwise. Vectors
    of another dimension (a different embedding space) are left out."""
    fitting = {k: v for k, v in vectors.items() if len(v) == len(query)}
    if _np is None or not fitting:
        return {k: cosine(query, v) for k, v in fitting.items()}
    keys = list(fitting)
    m = _np.vstack([_np.asarray(fitting[k], dtype=float) for k in keys])
    q = _np.asarray(query, dtype=float)
    norms = _np.linalg.norm(m, axis=1) * (_np.linalg.norm(q) or 1.0)
    with _np.errstate(divide="ignore", invalid="ignore"):
        sims = _np.where(norms > 0, m @ q / norms, 0.0)
    return {k: float(s) for k, s in zip(keys, sims)}


def top_k(scores: dict[str, float], limit: int) -> list[tuple[str, float]]:
    return sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:limit]


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    """Canonical stored form: UTC, `+00:00` suffix, so that the ISO text the
    stores ORDER BY and compare lexically orders by real instant. Naive
    datetimes are taken as UTC (contract rule)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def parse(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


def prefix_bounds(prefix: str) -> tuple[str, str | None]:
    """(lo, hi) such that `lo <= s < hi` holds exactly for the strings that
    start with `prefix`: hi is the prefix with its last code point
    incremented (a range the primary-key index serves on both backends,
    where LIKE would not: SQLite's default LIKE is case-insensitive and
    skips BINARY-collated indexes). hi is None when no bound exists."""
    stem = prefix.rstrip("\U0010ffff")
    if not stem:
        return prefix, None
    return prefix, stem[:-1] + chr(ord(stem[-1]) + 1)


def row_to_entity(row: Mapping[str, Any]) -> Entity:
    return Entity(
        id=row["id"],
        namespace=row["namespace"],
        type=row["type"],
        key=row["key"],
        provisional=bool(row["provisional"]),
        created_at=parse(row["created_at"]),
    )


def row_to_observation(row: Mapping[str, Any]) -> Observation:
    obj = json.loads(row["object_json"])
    if isinstance(obj, dict):
        obj = EntityRef(**obj)
    provenance = (
        Provenance(**json.loads(row["provenance_json"]))
        if row["provenance_json"]
        else None
    )
    return Observation(
        id=row["id"],
        namespace=row["namespace"],
        event_id=row["event_id"],
        subject=EntityRef(type=row["subj_type"], key=row["subj_key"]),
        predicate=row["predicate"],
        object=obj,
        observed_at=parse(row["observed_at"]),
        valid_from=parse(row["valid_from"]),
        valid_to=parse(row["valid_to"]),
        recorded_at=parse(row["recorded_at"]),
        source=row["source"],
        confidence=row["confidence"],
        provenance=provenance,
        supersedes=row["supersedes"] if "supersedes" in row.keys() else None,
        attrs=json.loads(row["attrs_json"]),
    )


def row_to_chunk(row: Mapping[str, Any]) -> dict:
    return {
        "artifact_id": row["artifact_id"], "seq": row["seq"],
        "span_start": row["span_start"], "span_end": row["span_end"],
        "text": row["text"], "vector": unpack_vector(row["vector"]),
        "source": row["source"], "observed_at": parse(row["observed_at"]),
    }


def row_to_dossier(row: Mapping[str, Any]) -> dict:
    return {
        "brief": row["brief"],
        "observation_count": row["observation_count"],
        "observation_ids": json.loads(row["observation_ids"] or "[]"),
        "updated_at": row["updated_at"],
    }


def redacted_view(obs: Observation) -> Observation:
    """Content-free stand-in for a tombstoned observation: keeps identity
    (id, namespace, event_id, subject, predicate, timestamps, source) so a
    replayed event can be acknowledged, but never returns what was redacted."""
    return obs.model_copy(update={
        "object": "[redacted]",
        "provenance": None,
        "attrs": {"redacted": True},
    })


def row_to_artifact(row: Mapping[str, Any]) -> Artifact:
    return Artifact(
        id=row["id"],
        namespace=row["namespace"],
        event_id=row["event_id"],
        filename=row["filename"],
        content_type=row["content_type"],
        text=row["text"],
        content_b64=row["content_b64"],
        source=row["source"],
        observed_at=parse(row["observed_at"]),
        recorded_at=parse(row["recorded_at"]),
        extraction_status=row["extraction_status"],
        extraction_attempts=(
            int(row["extraction_attempts"] or 0)
            if "extraction_attempts" in row.keys() else 0
        ),
        attrs=json.loads(row["attrs_json"]),
    )


def merge_record(parent: Mapping[str, Any], children) -> dict:
    """The exported shape of one merge_log row and its per-observation rows
    (GraphStore.iter_merges); both backends store identical columns."""
    return {
        "id": parent["id"],
        "namespace": parent["namespace"],
        "from": {"type": parent["from_type"], "key": parent["from_key"]},
        "into": {"type": parent["into_type"], "key": parent["into_key"]},
        "from_id": parent["from_id"],
        "from_provisional": bool(parent["from_provisional"]),
        "from_created_at": parent["from_created_at"],
        "prior_aliases": json.loads(parent["prior_aliases_json"] or "[]"),
        "recorded_at": parent["recorded_at"],
        "observations": [
            {"observation_id": c["observation_id"],
             "prior_subject_id": c["prior_subject_id"],
             "prior_object_entity_id": c["prior_object_entity_id"],
             "prior_object_json": c["prior_object_json"]}
            for c in children
        ],
    }


def merge_rows(record: dict) -> tuple[tuple, list[tuple]]:
    """The inverse of merge_record: (parent row values, child row values)
    in the tables' column order, for restore_merge."""
    parent = (
        record["id"], record["namespace"],
        record["from"]["type"], record["from"]["key"],
        record["into"]["type"], record["into"]["key"],
        record["from_id"], bool(record.get("from_provisional", False)),
        record["from_created_at"], json.dumps(list(record.get("prior_aliases", []))),
        record["recorded_at"],
    )
    children = [
        (record["id"], c["observation_id"], c.get("prior_subject_id"),
         c.get("prior_object_entity_id"), c.get("prior_object_json"))
        for c in record.get("observations", [])
    ]
    return parent, children


def row_to_schema(row: Mapping[str, Any]) -> SchemaRegistration:
    return SchemaRegistration.model_validate(json.loads(row["registration_json"]))


def merge_schema(existing: SchemaRegistration | None,
                 incoming: SchemaRegistration) -> SchemaRegistration:
    """Registration is additive: later definitions override by name, the
    rest survive; `strict` takes the incoming value."""
    if existing is None:
        return incoming
    types = {t.name: t for t in existing.entity_types}
    types.update({t.name: t for t in incoming.entity_types})
    preds = {p.name: p for p in existing.predicates}
    preds.update({p.name: p for p in incoming.predicates})
    return SchemaRegistration(
        namespace=incoming.namespace,
        entity_types=list(types.values()),
        predicates=list(preds.values()),
        strict=incoming.strict,
    )
