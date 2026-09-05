"""The context pack builder — the read path (docs/architecture.md).

Given (subject, question, budget, as_of?) this module gathers observations,
ranks them, surfaces conflicts, trims to the token budget, and attaches
citations + expansion handles. v1 ranking is deliberately LLM-free
(keyword similarity + recency + confidence); embedding similarity slots in
at _score() when phase 4 lands.

Expansion handles are stateless: a base64url-encoded JSON descriptor of the
query they stand for. No server-side handle table to expire or migrate.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone

from .config import max_budget

from .contracts import (
    AskRequest,
    Citation,
    ContextItem,
    ContextPack,
    EntityRef,
    Observation,
    ScopeSpec,
)
from .contracts import ExpansionHandle
from .store.base import GraphStore

_CHARS_PER_TOKEN = 4
_ITEM_OVERHEAD_TOKENS = 8  # rough JSON/citation framing cost per item
_GATHER_LIMIT = 1000

_WORD = re.compile(r"[a-z0-9][a-z0-9_.:-]*")


def est_tokens(text: str) -> int:
    return max(1, len(text) // _CHARS_PER_TOKEN) + _ITEM_OVERHEAD_TOKENS


def _tokens(text: str) -> set[str]:
    lowered = text.lower()
    words = set(_WORD.findall(lowered))
    # also split compound identifiers (logged_in_by, user:jdoe) so plain
    # question words can match them
    words |= set(_WORD.findall(re.sub(r"[_:./-]", " ", lowered)))
    return words


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _object_text(obs: Observation) -> str:
    if isinstance(obs.object, EntityRef):
        return f"{obs.object.type}:{obs.object.key}"
    return str(obs.object)


def _render_fact(obs: Observation) -> str:
    text = (
        f"{obs.subject.type}:{obs.subject.key} {obs.predicate} "
        f"{_object_text(obs)} ({obs.observed_at.date().isoformat()}, "
        f"per {obs.source})"
    )
    if obs.valid_from or obs.valid_to:
        frm = obs.valid_from.date().isoformat() if obs.valid_from else "?"
        to = obs.valid_to.date().isoformat() if obs.valid_to else "present"
        text += f" [valid {frm} to {to}]"
    return text


def _citation(obs: Observation) -> Citation:
    return Citation(
        observation_id=obs.id, source=obs.source, observed_at=obs.observed_at
    )


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _score(
    obs: Observation,
    question_tokens: set[str],
    rank: int,
    total: int,
    cos: float | None = None,
) -> float:
    recency = 1.0 - (rank / total) if total > 1 else 1.0
    if not question_tokens and cos is None:
        return 0.6 * recency + 0.4 * obs.confidence
    haystack = _tokens(
        f"{obs.predicate} {_object_text(obs)} {obs.subject.key} "
        f"{json.dumps(obs.attrs)}"
    )
    sim = (
        len(question_tokens & haystack) / len(question_tokens)
        if question_tokens else 0.0
    )
    if cos is not None:
        # semantic similarity leads once embeddings exist (phase 4, D-018);
        # keyword overlap stays as a tie-breaking signal
        return (0.5 * (cos + 1) / 2 + 0.15 * sim
                + 0.25 * recency + 0.1 * obs.confidence)
    return 0.5 * sim + 0.3 * recency + 0.2 * obs.confidence


def _find_conflicts(
    subject: EntityRef, observations: list[Observation]
) -> list[ContextItem]:
    """Scalar facts about the subject where sources disagree on the value."""
    by_predicate: dict[str, dict[str, Observation]] = {}
    for obs in observations:
        if obs.subject != subject or isinstance(obs.object, EntityRef):
            continue
        # keep the newest observation per distinct value (list is newest-first)
        by_predicate.setdefault(obs.predicate, {}).setdefault(
            str(obs.object), obs
        )
    items = []
    for predicate, by_value in sorted(by_predicate.items()):
        if len(by_value) < 2:
            continue
        # Differing values from ONE source are a time series or legitimate
        # update (invoice amounts, an OS upgrade), not a conflict. Only
        # cross-source disagreement gets flagged.
        if len({o.source for o in by_value.values()}) < 2:
            continue
        sides = sorted(
            by_value.values(), key=lambda o: o.observed_at, reverse=True
        )[:3]
        clauses = "; ".join(
            f"{o.source} says {_object_text(o)!r} "
            f"as of {o.observed_at.date().isoformat()}"
            for o in sides
        )
        items.append(
            ContextItem(
                kind="conflict",
                text=f"CONFLICT on {subject.type}:{subject.key} "
                f"{predicate}: {clauses}",
                score=1.0,
                citations=[_citation(o) for o in sides],
            )
        )
    return items


# ------------------------------------------------------------------ handles #

_HANDLE_PREFIX = "h1_"


def encode_handle(
    namespace: str, subject: EntityRef, predicate: str, as_of: datetime | None
) -> str:
    payload = {
        "ns": namespace,
        "subject": subject.model_dump(),
        "predicate": predicate,
        "as_of": as_of.isoformat() if as_of else None,
    }
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    return _HANDLE_PREFIX + raw.rstrip("=")


def decode_handle(handle: str) -> dict:
    if not handle.startswith(_HANDLE_PREFIX):
        raise ValueError("unrecognized handle format")
    raw = handle[len(_HANDLE_PREFIX):]
    raw += "=" * (-len(raw) % 4)
    payload = json.loads(base64.urlsafe_b64decode(raw))
    if not {"ns", "subject", "predicate"} <= payload.keys():
        raise ValueError("malformed handle payload")
    return payload


# ------------------------------------------------------------------ builder #

def resolve_scope(
    store: GraphStore, namespace: str, scope: ScopeSpec
) -> list[EntityRef]:
    """Expand a scope into a concrete entity list: BFS from the subjects over
    the named containment predicates, bounded by depth. Deterministic order."""
    seen = {(r.type, r.key) for r in scope.subjects}
    resolved = list(scope.subjects)
    frontier = list(scope.subjects)
    for _ in range(scope.depth):
        if not scope.expand or not frontier:
            break
        next_frontier: list[EntityRef] = []
        for ref in frontier:
            for obs in store.observations_for(namespace, ref, limit=_GATHER_LIMIT):
                if obs.predicate not in scope.expand:
                    continue
                ends = [obs.subject]
                if isinstance(obs.object, EntityRef):
                    ends.append(obs.object)
                for end in ends:
                    if (end.type, end.key) not in seen:
                        seen.add((end.type, end.key))
                        resolved.append(end)
                        next_frontier.append(end)
        frontier = next_frontier
    return resolved


def build_pack(
    store: GraphStore, req: AskRequest, embedder=None
) -> ContextPack:
    if req.scope is not None:
        subjects = resolve_scope(store, req.namespace, req.scope)
    else:
        subjects = [req.subject]
    observations: list[Observation] = []
    seen_ids: set[str] = set()  # an obs can reach us via several subjects
    for ref in subjects:
        for obs in store.observations_for(req.namespace, ref, limit=_GATHER_LIMIT):
            if obs.id not in seen_ids:
                seen_ids.add(obs.id)
                observations.append(obs)
    observations.sort(key=lambda o: _aware(o.observed_at), reverse=True)

    # Semantic ranking (D-018) + document excerpts (D-020): embed the question
    # once, reuse it to score observation vectors AND rank passages from the
    # documents that produced this entity's facts.
    cos_map: dict[str, float] = {}
    excerpts: list[tuple[float, str, str, int, int]] = []
    if embedder is not None and req.question and observations:
        query_vec = embedder.embed([req.question])[0]
        vectors = store.embeddings_for(
            req.namespace, [o.id for o in observations], embedder.model
        )
        cos_map = {oid: _cosine(query_vec, vec) for oid, vec in vectors.items()}

        artifact_ids = sorted({
            o.provenance.artifact_id for o in observations
            if o.provenance and o.provenance.artifact_id
        })
        for ch in store.doc_chunks_for_artifacts(req.namespace, artifact_ids):
            score = _cosine(query_vec, ch["vector"])
            excerpts.append((score, ch["artifact_id"], ch["text"],
                             ch["span_start"], ch["span_end"]))
        excerpts.sort(key=lambda e: e[0], reverse=True)

    # Dossier briefs: the cheap orientation layer, when the enrichment
    # worker has built one for a subject.
    briefs = []
    for ref in subjects[:3]:
        dossier = store.get_dossier(req.namespace, ref)
        if dossier:
            briefs.append((ref, dossier["brief"]))

    return _pack(
        namespace=req.namespace,
        subjects=subjects,
        question=req.question,
        as_of=req.as_of,
        budget=min(req.budget, max_budget()),
        observations=observations,
        cos_map=cos_map,
        briefs=briefs,
        excerpts=excerpts,
    )


def expand_pack(store: GraphStore, handle: str, budget: int) -> ContextPack:
    meta = decode_handle(handle)
    subject = EntityRef(**meta["subject"])
    as_of = datetime.fromisoformat(meta["as_of"]) if meta.get("as_of") else None
    observations = [
        o
        for o in store.observations_for(meta["ns"], subject, limit=_GATHER_LIMIT)
        if o.predicate == meta["predicate"]
    ]
    return _pack(
        namespace=meta["ns"],
        subjects=[subject],
        question=None,
        as_of=as_of,
        budget=budget,
        observations=observations,
        with_handles=False,
    )


def _pack(
    namespace: str,
    subjects: list[EntityRef],
    question: str | None,
    as_of: datetime | None,
    budget: int,
    observations: list[Observation],
    with_handles: bool = True,
    cos_map: dict[str, float] | None = None,
    briefs: list[tuple[EntityRef, str]] | None = None,
    excerpts: list[tuple[float, str, str, int, int]] | None = None,
) -> ContextPack:
    cos_map = cos_map or {}
    if as_of is not None:
        as_of = _aware(as_of)
        observations = [
            o
            for o in observations
            if _aware(o.observed_at) <= as_of
            and (o.valid_from is None or _aware(o.valid_from) <= as_of)
        ]

    question_tokens = _tokens(question) if question else set()
    total = len(observations)
    scored = sorted(
        (
            (_score(obs, question_tokens, rank, total, cos_map.get(obs.id)), obs)
            for rank, obs in enumerate(observations)
        ),
        key=lambda pair: pair[0],
        reverse=True,
    )

    items: list[ContextItem] = []
    remaining = budget

    # Conflicts ship first: an agent must not act on a contested fact unaware.
    for subj in subjects:
        for item in _find_conflicts(subj, observations):
            cost = est_tokens(item.text)
            if cost <= remaining:
                items.append(item)
                remaining -= cost

    # Then dossier briefs — the orientation layer (phase 4).
    for ref, brief in briefs or []:
        text = f"{ref.type}:{ref.key} — {brief}"
        cost = est_tokens(text)
        if cost <= remaining:
            items.append(ContextItem(kind="brief", text=text, score=0.99))
            remaining -= cost

    # Relevant document passages (D-020): top-ranked excerpts from the
    # documents behind this entity's facts, capped so they inform without
    # crowding out structured facts. Each cites its artifact + span in-text.
    excerpt_budget = remaining // 2
    for score, artifact_id, text, start, end in (excerpts or []):
        if score < 0.15:
            break
        rendered = f'"{text}" [doc:{artifact_id[:8]} @{start}-{end}]'
        cost = est_tokens(rendered)
        if cost <= excerpt_budget:
            items.append(ContextItem(
                kind="doc_excerpt", text=rendered,
                score=round(min(max(score, 0.0), 1.0), 4)))
            remaining -= cost
            excerpt_budget -= cost

    included: set[str] = set()
    skipped: dict[tuple[str, str, str], int] = {}  # (subj type, key, predicate)
    for score, obs in scored:
        text = _render_fact(obs)
        cost = est_tokens(text)
        if cost <= remaining:
            items.append(
                ContextItem(
                    kind="fact",
                    text=text,
                    score=round(min(score, 1.0), 4),
                    citations=[_citation(obs)],
                )
            )
            remaining -= cost
            included.add(obs.id)
        else:
            key = (obs.subject.type, obs.subject.key, obs.predicate)
            skipped[key] = skipped.get(key, 0) + 1

    handles: list[ExpansionHandle] = []
    if with_handles:
        for (stype, skey, predicate), count in sorted(
            skipped.items(), key=lambda kv: kv[1], reverse=True
        ):
            subj = EntityRef(type=stype, key=skey)
            handles.append(
                ExpansionHandle(
                    id=encode_handle(namespace, subj, predicate, as_of),
                    hint=f"{count} more '{predicate}' observations for "
                    f"{stype}:{skey}",
                    est_tokens=count * 25,
                )
            )

    return ContextPack(
        namespace=namespace,
        subject=subjects[0] if len(subjects) == 1 else None,
        subjects=subjects,
        question=question,
        as_of=as_of,
        budget=budget,
        items=items,
        handles=handles,
    )
