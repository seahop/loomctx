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

from .contracts import (
    AskRequest,
    Citation,
    ContextItem,
    ContextPack,
    EntityRef,
    Observation,
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


def _score(
    obs: Observation, question_tokens: set[str], rank: int, total: int
) -> float:
    recency = 1.0 - (rank / total) if total > 1 else 1.0
    if not question_tokens:
        return 0.6 * recency + 0.4 * obs.confidence
    haystack = _tokens(
        f"{obs.predicate} {_object_text(obs)} {obs.subject.key} "
        f"{json.dumps(obs.attrs)}"
    )
    sim = len(question_tokens & haystack) / len(question_tokens)
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

def build_pack(store: GraphStore, req: AskRequest) -> ContextPack:
    observations = store.observations_for(
        req.namespace, req.subject, limit=_GATHER_LIMIT
    )
    return _pack(
        namespace=req.namespace,
        subject=req.subject,
        question=req.question,
        as_of=req.as_of,
        budget=req.budget,
        observations=observations,
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
        subject=subject,
        question=None,
        as_of=as_of,
        budget=budget,
        observations=observations,
        with_handles=False,
    )


def _pack(
    namespace: str,
    subject: EntityRef,
    question: str | None,
    as_of: datetime | None,
    budget: int,
    observations: list[Observation],
    with_handles: bool = True,
) -> ContextPack:
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
            (_score(obs, question_tokens, rank, total), obs)
            for rank, obs in enumerate(observations)
        ),
        key=lambda pair: pair[0],
        reverse=True,
    )

    items: list[ContextItem] = []
    remaining = budget

    # Conflicts ship first: an agent must not act on a contested fact unaware.
    for item in _find_conflicts(subject, observations):
        cost = est_tokens(item.text)
        if cost <= remaining:
            items.append(item)
            remaining -= cost

    included: set[str] = set()
    skipped_by_predicate: dict[str, int] = {}
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
            skipped_by_predicate[obs.predicate] = (
                skipped_by_predicate.get(obs.predicate, 0) + 1
            )

    handles: list[ExpansionHandle] = []
    if with_handles:
        for predicate, skipped in sorted(
            skipped_by_predicate.items(), key=lambda kv: kv[1], reverse=True
        ):
            handles.append(
                ExpansionHandle(
                    id=encode_handle(namespace, subject, predicate, as_of),
                    hint=f"{skipped} more '{predicate}' observations for "
                    f"{subject.type}:{subject.key}",
                    est_tokens=skipped * 25,
                )
            )

    return ContextPack(
        namespace=namespace,
        subject=subject,
        question=question,
        as_of=as_of,
        budget=budget,
        items=items,
        handles=handles,
    )
