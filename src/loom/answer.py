"""Ask + synthesize: retrieval-grounded answers/decisions (D-012).

Flow: resolve what the question is about (explicit subject, explicit scope,
or entity names auto-detected in the question text) → build one budgeted,
cited context pack → hand pack + question to the configured LLM → return its
answer alongside the pack, so callers can audit exactly what the model saw.
"""

from __future__ import annotations

from .contracts import (
    AnswerRequest,
    AnswerResponse,
    AskRequest,
    ContextPack,
    EntityRef,
    ScopeSpec,
)
from .context import _tokens, build_pack
from .llm import LLMClient
from .store.base import GraphStore

SYSTEM_PROMPT = (
    "You answer questions using ONLY the supplied context items from Loom, a "
    "provenance-tracked knowledge store. Rules: cite the observation ids you "
    "relied on in [brackets]; when items conflict, present both sides with "
    "their sources rather than picking silently; if the context is "
    "insufficient, state exactly what is missing instead of guessing — the "
    "'more available' lines show what could be fetched. Be concise and "
    "decision-oriented."
)


class UnresolvedQuestionError(ValueError):
    """No subject/scope given and no entity names found in the question."""


def auto_subjects(
    store: GraphStore,
    namespace: str,
    question: str,
    cap: int = 5,
    allowed_types: tuple[str, ...] | None = None,
) -> list[EntityRef]:
    """Entities whose keys appear verbatim in the question ("web-01 and
    web-02", "corp.local"). Exact key matches only — auto-resolution should
    never guess. allowed_types restricts resolution to a scoped key's world
    (D-013a)."""
    subjects: list[EntityRef] = []
    seen: set[tuple[str, str]] = set()
    for token in sorted(_tokens(question)):
        if len(token) < 3:
            continue
        for entity in store.search_entities(namespace, token, limit=3,
                                            types=allowed_types):
            if entity.key.lower() != token:
                continue
            key = (entity.type, entity.key)
            if key not in seen:
                seen.add(key)
                subjects.append(EntityRef(type=entity.type, key=entity.key))
    return subjects[:cap]


_MAX_RENDERED_CITES = 8


def _cite_label(c) -> str:
    if c.observation_id:
        return c.observation_id[:12]
    return f"doc:{c.artifact_id[:8]}@{c.span_start}-{c.span_end}"


def render_user_prompt(question: str, pack: ContextPack) -> str:
    lines = [f"Question: {question}", "", "Context items:"]
    for item in pack.items:
        labels = [_cite_label(c) for c in item.citations[:_MAX_RENDERED_CITES]]
        extra = len(item.citations) - len(labels)
        cites = ",".join(labels) + (f",+{extra} more" if extra > 0 else "")
        lines.append(f"- ({item.kind}) {item.text} [{cites}]")
    if not pack.items:
        lines.append("- (none found)")
    for handle in pack.handles:
        prefix = "unresolved conflict" if handle.kind == "conflict" else "more available"
        lines.append(f"- {prefix}: {handle.hint}")
    return "\n".join(lines)


def build_answer(
    store: GraphStore,
    llm: LLMClient,
    req: AnswerRequest,
    allowed_types: tuple[str, ...] | None = None,
    embedder=None,
) -> AnswerResponse:
    if req.subject is not None or req.scope is not None:
        subject, scope = req.subject, req.scope
    else:
        found = auto_subjects(store, req.namespace, req.question,
                              allowed_types=allowed_types)
        if not found:
            raise UnresolvedQuestionError(
                "no entity named in the question was found; pass an explicit "
                "'subject' or 'scope'"
            )
        subject, scope = None, ScopeSpec(subjects=found)

    pack = build_pack(
        store,
        AskRequest(
            namespace=req.namespace,
            subject=subject,
            scope=scope,
            question=req.question,
            budget=req.budget,
            as_of=req.as_of,
        ),
        embedder=embedder,
        allowed_types=allowed_types,
    )
    text = llm.complete(
        SYSTEM_PROMPT,
        render_user_prompt(req.question, pack),
        max_tokens=req.max_tokens,
    )
    return AnswerResponse(answer=text, model=llm.model, pack=pack)
