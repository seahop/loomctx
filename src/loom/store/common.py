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


def norm_key(key: str) -> str:
    """The fuzzy-match key: lowercase, punctuation/whitespace stripped, so
    web-01 / WEB_01 / web01 collide (D-024 entity resolution tier 2)."""
    return _NORM.sub("", key.lower())


_SLUG = re.compile(r"[^a-z0-9]+")


def vec_table(kind: str, model: str, dim: int) -> str:
    """Name of the ANN index table (D-025): vobs_/vchk_ + a slug of the
    embedding model + the dimension, so vectors from different models — or
    a model that changed size — never share an index."""
    return f"{kind}_{_SLUG.sub('_', model.lower()).strip('_')}_{int(dim)}"


try:  # optional accelerator (extra "vector"); pure Python otherwise
    import numpy as _np
except ImportError:  # pragma: no cover
    _np = None


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
    m = _np.asarray([fitting[k] for k in keys], dtype=float)
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


def like_pattern(query: str) -> str:
    """Prefix pattern for LIKE ... ESCAPE '\\' with the user's metacharacters
    neutralized, so `web_01` doesn't match `webX01` and `%` isn't a wildcard."""
    escaped = (
        query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    return escaped.lower() + "%"


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
        attrs=json.loads(row["attrs_json"]),
    )


def row_to_chunk(row: Mapping[str, Any]) -> dict:
    return {
        "artifact_id": row["artifact_id"], "seq": row["seq"],
        "span_start": row["span_start"], "span_end": row["span_end"],
        "text": row["text"], "vector": json.loads(row["vector"]),
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
