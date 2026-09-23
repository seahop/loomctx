"""The context pack builder — the read path (docs/architecture.md).

Given (subject, question, budget, as_of?, valid_at?) this module gathers
observations, ranks them, surfaces conflicts, trims to the token budget, and
attaches citations + expansion handles. Ranking is LLM-free: cosine
similarity when vectors exist (D-018), keyword overlap otherwise, plus
time-decayed recency and source confidence (D-024).

Two time axes (architecture.md): `as_of` hides what was observed after T
("what did we know"); `valid_at` keeps only facts whose validity window
covers T ("what was true"), leaving un-windowed facts alone. `as_of` is
observation time (`observed_at <= as_of`: when the source asserted the
fact), the closest proxy to knowledge time for backfilled corpora, where
`recorded_at` is load day and useless; `recorded_at` remains the audit
column. The bound is applied in the store query (D-046), so an entity with
thousands of newer rows still yields its rows as of then, and the
`truncated` report counts as of then too.

Expansion handles are stateless: a base64url-encoded JSON descriptor of the
query they stand for. No server-side handle table to expire or migrate.
When LOOM_HANDLE_SECRET is set they are HMAC-signed and only signed handles
are accepted (defense in depth: a handle is a query, and a forged query must
still pass the same data gates as a fresh ask — see `allowed_types`).

Data scoping (D-013a): `allowed_types` restricts the world a pack is built
over. Subjects reached by scope expansion and observations whose subject OR
object entity falls outside the allowlist are silently dropped — the caller
sees "their universe", not an error.
"""

from __future__ import annotations

import base64
import logging
import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone

from .config import max_budget

from .contracts import (
    ScopeTruncation,
    AskRequest,
    Citation,
    ContextItem,
    ContextPack,
    EntityRef,
    Observation,
    ScopeSpec,
    SemanticMatch,
    SemanticSearchResponse,
)
from .contracts import ExpansionHandle
from .store.base import GraphStore

_CHARS_PER_TOKEN = 4
_ITEM_OVERHEAD_TOKENS = 8  # rough JSON/citation framing cost per item
_GATHER_LIMIT = 1000
_MAX_EXCERPT_CANDIDATES = 64   # passages considered per pack, after ranking
_MAX_HANDLES = 32              # a scope over a hub produced 8,234 handles (D-035)
_CONFLICT_BUDGET_SHARE = 0.5   # conflicts ship first, but never as the whole pack (D-035)
_QUERY_CACHE_SIZE = 256
_RECENCY_HALF_LIFE_DAYS = 30.0  # recency = 1 / (1 + age / half-life)

from .store.common import cosine as _cosine, cosines  # noqa: E402  (re-exported)

# Question words that carry no retrieval signal; stripped from the keyword
# scorer so "what is the operating system" isn't 60% noise (H-C7).
log = logging.getLogger("loom.context")

_STOPWORDS = frozenset("""
a an and are as at be been by did do does for from had has have how in is it
its of on or that the this to was were what when where which who whom why
will with about into over under any all some tell me show give list
""".split())


def embed_query(embedder, question: str) -> list[float]:
    """The question's vector, memoized per (embedder model, text): agents
    re-ask the same question with different subjects/budgets constantly,
    and each miss is a provider round-trip (H-E1)."""
    key = (embedder.model, question)
    vec = _query_cache.get(key)
    if vec is None:
        one = getattr(embedder, "embed_query", None)
        vec = one(question) if callable(one) else embedder.embed([question])[0]
        if len(_query_cache) >= _QUERY_CACHE_SIZE:
            _query_cache.pop(next(iter(_query_cache)))
        _query_cache[key] = vec
    return vec


def try_embed_query(embedder, question: str) -> list[float] | None:
    """embed_query, or None when the provider is slow or down: the ask then
    ranks by keyword instead of failing or stalling (D-039)."""
    try:
        return embed_query(embedder, question)
    except Exception as exc:  # noqa: BLE001 — any provider failure degrades, never breaks
        log.warning("query embedding unavailable (%s); ranking by keyword for this ask", exc)
        return None


_query_cache: dict[tuple[str, str], list[float]] = {}

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


def _question_tokens(question: str) -> set[str]:
    words = _tokens(question)
    content = words - _STOPWORDS
    return content or words  # a question made only of stopwords keeps them


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _now() -> datetime:
    return datetime.now(timezone.utc)


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


def _is_extracted(obs: Observation) -> bool:
    """LLM-mined from a document (D-018) rather than asserted by a sender.
    Such claims are data that came *through* an untrusted text, so they
    rank a notch below structured facts and never outrank them in a
    conflict (H-C5/H-D2)."""
    return bool(obs.attrs.get("extracted")) or obs.source.startswith("doc:")


_EXTRACTED_DISCOUNT = 0.85
_EXCERPT_RELATIVE_FLOOR = 0.6  # keep passages scoring >= 60% of the best one


def _recency(obs: Observation, newest: datetime) -> float:
    """Time-decayed, relative to the newest observation in the gathered
    set: twenty facts a second apart all score ~1, a year-old one ~0.08.
    Rank-based decay spread same-day facts across the whole range (H-C7)."""
    age_days = max(0.0, (newest - _aware(obs.observed_at)).total_seconds() / 86400)
    return 1.0 / (1.0 + age_days / _RECENCY_HALF_LIFE_DAYS)


def _score(
    obs: Observation,
    question_tokens: set[str],
    recency: float,
    cos: float | None = None,
    semantic: bool = False,
) -> float:
    """`semantic` means an embedder is serving this pack: observations that
    have no vector yet (freshly ingested) are scored on the SAME formula
    with cos=0 (neutral), so the two populations stay comparable (H-C7)."""
    if not question_tokens and not semantic:
        score = 0.6 * recency + 0.4 * obs.confidence
    else:
        haystack = _tokens(
            f"{obs.predicate} {_object_text(obs)} {obs.subject.key} "
            f"{json.dumps(obs.attrs)}"
        )
        sim = (
            len(question_tokens & haystack) / len(question_tokens)
            if question_tokens else 0.0
        )
        if semantic:
            # semantic similarity leads once embeddings exist (D-018);
            # keyword overlap stays as a tie-breaking signal
            c = cos if cos is not None else 0.0
            score = (0.5 * (c + 1) / 2 + 0.15 * sim
                     + 0.25 * recency + 0.1 * obs.confidence)
        else:
            score = 0.5 * sim + 0.3 * recency + 0.2 * obs.confidence
    return score * _EXTRACTED_DISCOUNT if _is_extracted(obs) else score


def _find_conflicts(
    subject: EntityRef, observations: list[Observation], as_of: datetime | None
) -> list[tuple[str, ContextItem]]:
    """Scalar facts about the subject where sources disagree on the value.
    Returns (predicate, item) pairs so a conflict that doesn't fit the
    budget can still be handed back as an expansion handle (H-C4)."""
    horizon = as_of or _now()
    by_predicate: dict[str, dict[str, Observation]] = {}
    for obs in observations:
        if obs.subject != subject or isinstance(obs.object, EntityRef):
            continue
        # a fact whose validity window has closed is history, not a
        # competing claim about the present (H-C3)
        if obs.valid_to is not None and _aware(obs.valid_to) <= horizon:
            continue
        # keep the newest observation per distinct value (list is newest-first)
        by_predicate.setdefault(obs.predicate, {}).setdefault(
            str(obs.object), obs
        )
    items: list[tuple[str, ContextItem]] = []
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
            f"{o.source} says {_object_text(o)!r}"
            f"{' (extracted from a document)' if _is_extracted(o) else ''} "
            f"as of {o.observed_at.date().isoformat()}"
            for o in sides
        )
        # A disagreement between structured sources outranks one that a
        # document extraction introduced: hostile text can manufacture the
        # latter, never the former (H-C5).
        structured_sides = sum(not _is_extracted(o) for o in sides)
        score = 1.0 if structured_sides >= 2 else 0.9
        items.append((predicate, ContextItem(
            kind="conflict",
            text=f"CONFLICT on {subject.type}:{subject.key} "
            f"{predicate}: {clauses}",
            score=score,
            citations=[_citation(o) for o in sides],
        )))
    items.sort(key=lambda pair: pair[1].score, reverse=True)
    return items


# ------------------------------------------------------------------ handles #

_HANDLE_PREFIX = "h1_"          # unsigned (no LOOM_HANDLE_SECRET configured)
_SIGNED_HANDLE_PREFIX = "h2_"   # payload.signature, HMAC-SHA256 truncated


def _handle_secret() -> bytes | None:
    raw = os.environ.get("LOOM_HANDLE_SECRET", "").strip()
    return raw.encode() if raw else None


def _sign(raw: str, secret: bytes) -> str:
    digest = hmac.new(secret, raw.encode(), hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def encode_handle(
    namespace: str, subject: EntityRef, predicate: str, as_of: datetime | None,
    valid_at: datetime | None = None, excerpt: dict | None = None,
) -> str:
    """`excerpt` = {"artifact_id", "seq", "model"} makes an excerpt handle:
    expanding it returns the cited passage with its neighbours."""
    # Compact keys and no nulls: agents carry every handle of every pack in
    # their context, and the long form averaged 131 chars per id (D-036).
    payload: dict = {"n": namespace, "s": [subject.type, subject.key], "p": predicate}
    if as_of is not None:
        payload["a"] = as_of.isoformat()
    if valid_at is not None:
        payload["v"] = valid_at.isoformat()
    if excerpt is not None:
        payload["x"] = excerpt
    raw = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=")
    secret = _handle_secret()
    if secret is None:
        return _HANDLE_PREFIX + raw
    return f"{_SIGNED_HANDLE_PREFIX}{raw}.{_sign(raw, secret)}"


def decode_handle(handle: str) -> dict:
    """Parse (and, when a secret is configured, verify) a handle.

    Raises ValueError for anything that is not a well-formed handle this
    deployment would have issued — including unsigned handles once
    LOOM_HANDLE_SECRET is set.
    """
    if not isinstance(handle, str):
        raise ValueError("unrecognized handle format")
    secret = _handle_secret()
    if handle.startswith(_SIGNED_HANDLE_PREFIX):
        if secret is None:
            raise ValueError("signed handle presented but no handle secret configured")
        raw, sep, sig = handle[len(_SIGNED_HANDLE_PREFIX):].partition(".")
        if not sep or not hmac.compare_digest(_sign(raw, secret), sig):
            raise ValueError("handle signature invalid")
    elif handle.startswith(_HANDLE_PREFIX):
        if secret is not None:
            raise ValueError("unsigned handles are not accepted on this deployment")
        raw = handle[len(_HANDLE_PREFIX):]
    else:
        raise ValueError("unrecognized handle format")
    raw += "=" * (-len(raw) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(raw))
    except (ValueError, UnicodeDecodeError) as exc:  # binascii.Error is a ValueError
        raise ValueError("malformed handle payload") from exc
    if not isinstance(payload, dict):
        raise ValueError("malformed handle payload")
    if {"n", "s", "p"} <= payload.keys():  # compact form
        s = payload["s"]
        if not (isinstance(s, list) and len(s) == 2 and all(isinstance(x, str) for x in s)) \
                or not isinstance(payload["n"], str):
            raise ValueError("malformed handle payload")
        out = {"ns": payload["n"], "subject": {"type": s[0], "key": s[1]}, "predicate": payload["p"]}
        for short, long in (("a", "as_of"), ("v", "valid_at"), ("x", "excerpt")):
            if short in payload:
                out[long] = payload[short]
        return out
    if not {"ns", "subject", "predicate"} <= payload.keys():  # long form (pre-D-036 handles)
        raise ValueError("malformed handle payload")
    if not isinstance(payload["subject"], dict) or not isinstance(payload["ns"], str):
        raise ValueError("malformed handle payload")
    return payload


def covers_valid_at(obs: Observation, valid_at: datetime) -> bool:
    """Fact time: was this TRUE at T? Facts that carry no validity window
    are timeless as far as we know and are kept (D-024). Shared by packs,
    scope expansion and the raw observations route (D-046)."""
    valid_at = _aware(valid_at)
    return ((obs.valid_from is None or _aware(obs.valid_from) <= valid_at)
            and (obs.valid_to is None or _aware(obs.valid_to) > valid_at))


# ------------------------------------------------------------ data scoping #

def _in_scope(obs: Observation, allowed_types: tuple[str, ...] | None) -> bool:
    """An observation is visible only if every entity it touches is in the
    caller's allowed types (mirrors the ingest gate, which checks both
    subject and object)."""
    if allowed_types is None:
        return True
    if obs.subject.type not in allowed_types:
        return False
    if isinstance(obs.object, EntityRef) and obs.object.type not in allowed_types:
        return False
    return True


# ------------------------------------------------------------------ builder #

Paths = dict[tuple[str, str], list[Observation]]
Truncations = dict[tuple[str, str], ScopeTruncation]


def _gather(store: GraphStore, namespace: str, ref: EntityRef,
            truncated: Truncations, as_of: datetime | None = None) -> list[Observation]:
    """observations_for under the gather limit, recording when the limit
    cut something off: a hub with 2,740 edges yields its newest 1,000 and
    the pack must say so (D-038). The count is only taken when the limit
    was actually hit, so ordinary entities pay nothing."""
    return _gather_many(store, namespace, [ref], truncated, as_of).get((ref.type, ref.key), [])


def _gather_many(store: GraphStore, namespace: str, refs: list[EntityRef],
                 truncated: Truncations, as_of: datetime | None = None,
                 ) -> dict[tuple[str, str], list[Observation]]:
    """One round trip per chunk for a whole frontier or subject list, with
    the same truncation accounting (D-043: a 1,077-entity scope was 1,077
    round trips — 5 s on Postgres across a network). `as_of` is pushed
    into the query as the observed_before bound (D-046): filtering after a
    newest-first LIMIT gave an entity with more than the limit of newer
    rows an empty time-travel pack, and a truncation total blind to T."""
    as_of = _aware(as_of) if as_of is not None else None
    got = store.observations_for_many(namespace, refs, limit=_GATHER_LIMIT, observed_before=as_of)
    for ref in refs:
        obs = got.get((ref.type, ref.key), [])
        if len(obs) >= _GATHER_LIMIT and (ref.type, ref.key) not in truncated:
            total = store.count_observations(namespace, ref, observed_before=as_of)
            if total > len(obs):
                truncated[(ref.type, ref.key)] = ScopeTruncation(entity=ref, gathered=len(obs), total=total)
    return got


def resolve_scope(
    store: GraphStore, namespace: str, scope: ScopeSpec
) -> list[EntityRef]:
    """Expand a scope into a concrete entity list: BFS from the subjects over
    the named containment predicates, bounded by depth. Deterministic order.
    With no `expand` named, the namespace's registry supplies its
    containment predicates (D-012 promise, D-024)."""
    return resolve_scope_paths(store, namespace, scope)[0]


def resolve_scope_paths(
    store: GraphStore, namespace: str, scope: ScopeSpec,
    truncated: Truncations | None = None,
) -> tuple[list[EntityRef], Paths]:
    """`resolve_scope` plus, for every entity the BFS reached, the chain of
    edges it was reached through (root -> ... -> entity). A fact about a
    reached entity only makes sense to a reader alongside that chain
    (D-035): "CVE-X is exploited" is noise until "web-01 runs nginx, CVE-X
    affects nginx" sits next to it."""
    expand = set(scope.expand)
    if not expand and scope.depth > 0:
        from .registry import containment_predicates
        expand = set(containment_predicates(store.get_schema(namespace)))
    seen = {(r.type, r.key) for r in scope.subjects}
    resolved = list(scope.subjects)
    frontier = list(scope.subjects)
    paths: Paths = {}
    truncated = truncated if truncated is not None else {}
    for _ in range(scope.depth):
        if not expand or not frontier:
            break
        next_frontier: list[EntityRef] = []
        gathered = _gather_many(store, namespace, frontier, truncated)
        for ref in frontier:
            via = paths.get((ref.type, ref.key), [])
            for obs in gathered.get((ref.type, ref.key), []):
                if obs.predicate not in expand:
                    continue
                ends = [obs.subject]
                if isinstance(obs.object, EntityRef):
                    ends.append(obs.object)
                for end in ends:
                    if (end.type, end.key) not in seen:
                        seen.add((end.type, end.key))
                        resolved.append(end)
                        next_frontier.append(end)
                        paths[(end.type, end.key)] = via + [obs]
        frontier = next_frontier
    return resolved, paths


def build_pack(
    store: GraphStore,
    req: AskRequest,
    embedder=None,
    allowed_types: tuple[str, ...] | None = None,
) -> ContextPack:
    paths: Paths = {}
    truncated: Truncations = {}
    if req.scope is not None:
        subjects, paths = resolve_scope_paths(store, req.namespace, req.scope, truncated)
    else:
        subjects = [req.subject]
    if allowed_types is not None:
        # scoped keys see a scoped world (D-013a): entities reached by
        # expansion outside the allowlist simply aren't there
        subjects = [s for s in subjects if s.type in allowed_types]
    observations: list[Observation] = []
    seen_ids: set[str] = set()  # an obs can reach us via several subjects
    gathered = _gather_many(store, req.namespace, subjects, truncated, req.as_of)
    for ref in subjects:
        for obs in gathered.get((ref.type, ref.key), []):
            if obs.id not in seen_ids and _in_scope(obs, allowed_types):
                seen_ids.add(obs.id)
                observations.append(obs)
    observations.sort(key=lambda o: _aware(o.observed_at), reverse=True)

    # Semantic ranking (D-018) + document excerpts (D-020): embed the question
    # once, reuse it to score observation vectors AND rank passages from the
    # documents that produced this entity's facts.
    cos_map: dict[str, float] = {}
    excerpts: list[tuple[float, Citation, str, int, str]] = []
    semantic = embedder is not None and bool(req.question) and bool(observations)
    query_vec = try_embed_query(embedder, req.question) if semantic else None
    semantic = query_vec is not None
    if semantic:
        vectors = store.embeddings_for(
            req.namespace, [o.id for o in observations], embedder.model
        )
        cos_map = cosines(query_vec, vectors)

        artifact_ids = sorted({
            o.provenance.artifact_id for o in observations
            if o.provenance and o.provenance.artifact_id
        })
        horizon = _aware(req.as_of) if req.as_of else None
        # top passages from the documents behind this entity's facts, via
        # the store's ANN index when one exists (D-025)
        # which entities a document backs: a passage in a multi-subject pack
        # must say who it is about, or a reader attributes the KEV advisory
        # for one kernel CVE to the kernel CVEs listed next to it (D-039)
        about: dict[str, list[str]] = {}
        for o in observations:
            if o.provenance and o.provenance.artifact_id:
                key = f"{o.subject.type}:{o.subject.key}"
                lst = about.setdefault(o.provenance.artifact_id, [])
                if key not in lst and len(lst) < 3:
                    lst.append(key)
        for ch, score in store.nearest_chunks(
            req.namespace, embedder.model, query_vec,
            _MAX_EXCERPT_CANDIDATES, artifact_ids,
        ):
            observed = _aware(ch["observed_at"])
            if horizon is not None and observed > horizon:
                continue  # a document we hadn't seen yet as of then (H-C2)
            cite = Citation(
                artifact_id=ch["artifact_id"], span_start=ch["span_start"],
                span_end=ch["span_end"], source=ch["source"], observed_at=observed,
            )
            subjects_of = about.get(ch["artifact_id"], [])
            text = (f"[about {', '.join(subjects_of)}] " if subjects_of else "") + ch["text"]
            excerpts.append((score, cite, text, ch["seq"], embedder.model))
        excerpts.sort(key=lambda e: e[0], reverse=True)
        excerpts = excerpts[:_MAX_EXCERPT_CANDIDATES]

    # Dossier briefs: the cheap orientation layer, when the enrichment
    # worker has built one for a subject. A brief is a present-tense
    # summary, so it is withheld from as-of (time-travel) reads (H-C2). It
    # cites the observations it was synthesized from; ones no longer
    # visible (redacted, out of scope) simply drop out of the citation list.
    briefs: list[tuple[EntityRef, str, list[Citation]]] = []
    if req.as_of is None:
        by_id = {o.id: o for o in observations}
        for ref in subjects[:3]:
            dossier = store.get_dossier(req.namespace, ref)
            if not dossier:
                continue
            cites = [_citation(by_id[i]) for i in dossier.get("observation_ids", [])
                     if i in by_id]
            if cites:
                briefs.append((ref, dossier["brief"], cites))

    return _pack(
        namespace=req.namespace,
        subjects=subjects,
        question=req.question,
        as_of=req.as_of,
        valid_at=req.valid_at,
        budget=min(req.budget, max_budget()),
        observations=observations,
        cos_map=cos_map,
        semantic=semantic,
        briefs=briefs,
        excerpts=excerpts,
        paths={key: [o.id for o in chain] for key, chain in paths.items()},
        roots=list(req.scope.subjects) if req.scope is not None else [req.subject],
        truncated=list(truncated.values()),
    )


def semantic_search(
    store: GraphStore,
    namespace: str,
    embedder,
    question: str,
    limit: int = 10,
    allowed_types: tuple[str, ...] | None = None,
) -> SemanticSearchResponse:
    """Entities related to a question by meaning, not by name (D-025):
    the namespace's nearest facts, grouped by subject, each entity backed
    by its best-matching fact as cited evidence. Scoped keys only see
    facts inside their world."""
    query_vec = embed_query(embedder, question)
    best: dict[tuple[str, str], tuple[float, EntityRef, ContextItem]] = {}

    def offer(ref: EntityRef, score: float, item: ContextItem) -> None:
        key = (ref.type, ref.key)
        if key not in best or score > best[key][0]:
            best[key] = (score, ref, item)

    # facts: the namespace's nearest rendered observations, by subject
    hits = store.nearest_observations(namespace, embedder.model, query_vec, limit * 4)
    score_by_id = dict(hits)
    for obs in store.observations_by_ids(namespace, list(score_by_id)):
        if not _in_scope(obs, allowed_types):
            continue
        s = round(min(max(score_by_id[obs.id], 0.0), 1.0), 4)
        offer(obs.subject, s, ContextItem(kind="fact", text=_render_fact(obs), score=s,
                                          citations=[_citation(obs)]))

    # passages: a document's words carry meaning a rendered fact does not
    # ("ransomware campaigns" matched the predicate name
    # ransomware_campaign_use, never the advisory that named the campaign,
    # D-040). A passage maps to the entities whose claims cite its document.
    chunks = store.nearest_chunks(namespace, embedder.model, query_vec, limit * 4, None)
    about = store.subjects_citing(namespace, sorted({ch["artifact_id"] for ch, _ in chunks}), allowed_types)
    for ch, score in chunks:
        refs = about.get(ch["artifact_id"], [])
        if not refs:
            continue  # a document nobody cites is about nothing an agent can ask for
        s = round(min(max(score, 0.0), 1.0), 4)
        cite = Citation(artifact_id=ch["artifact_id"], span_start=ch["span_start"],
                        span_end=ch["span_end"], source=ch["source"], observed_at=_aware(ch["observed_at"]))
        names = ", ".join(f"{r.type}:{r.key}" for r in refs)
        text = f'[about {names}] "{ch["text"]}" [doc:{ch["artifact_id"][:8]} @{ch["span_start"]}-{ch["span_end"]}]'
        for ref in refs:
            offer(ref, s, ContextItem(kind="doc_excerpt", text=text, score=s, citations=[cite]))

    ranked = sorted(best.values(), key=lambda t: t[0], reverse=True)[:limit]
    return SemanticSearchResponse(
        namespace=namespace, question=question,
        matches=[SemanticMatch(entity=ref, score=score, evidence=item) for score, ref, item in ranked],
    )


def expand_pack(
    store: GraphStore,
    handle: str,
    budget: int,
    allowed_types: tuple[str, ...] | None = None,
) -> ContextPack:
    meta = decode_handle(handle)
    subject = EntityRef(**meta["subject"])
    as_of = datetime.fromisoformat(meta["as_of"]) if meta.get("as_of") else None
    valid_at = (datetime.fromisoformat(meta["valid_at"])
                if meta.get("valid_at") else None)
    budget = min(budget, max_budget())
    if isinstance(meta.get("excerpt"), dict):
        return _expand_excerpt(store, meta, subject, budget, allowed_types)
    truncated: Truncations = {}
    observations = [
        o
        for o in _gather(store, meta["ns"], subject, truncated, as_of)
        if o.predicate == meta["predicate"] and _in_scope(o, allowed_types)
    ]
    return _pack(
        namespace=meta["ns"],
        subjects=[subject],
        question=None,
        as_of=as_of,
        valid_at=valid_at,
        budget=budget,
        observations=observations,
        with_handles=False,
        truncated=list(truncated.values()),
    )


_EXCERPT_NEIGHBOURS = 1  # passages on each side of the cited one


def _expand_excerpt(
    store: GraphStore, meta: dict, subject: EntityRef, budget: int,
    allowed_types: tuple[str, ...] | None,
) -> ContextPack:
    """An excerpt handle: the cited passage plus its neighbours, in document
    order, so an agent can read around a hit without fetching the whole
    artifact. A type-scoped reader gets it only if the document backs a
    fact in their world (same rule as GET /v1/artifacts, H-A6)."""
    ex = meta["excerpt"]
    ns = meta["ns"]
    artifact_id, seq, model = str(ex.get("artifact_id")), int(ex.get("seq", 0)), str(ex.get("model"))
    items: list[ContextItem] = []
    allowed = allowed_types is None or store.artifact_cited_within(ns, artifact_id, allowed_types)
    if allowed:
        seqs = list(range(max(0, seq - _EXCERPT_NEIGHBOURS), seq + _EXCERPT_NEIGHBOURS + 1))
        remaining = budget
        for ch in store.doc_chunks_by_seq(ns, artifact_id, model, seqs):
            cite = Citation(
                artifact_id=ch["artifact_id"], span_start=ch["span_start"],
                span_end=ch["span_end"], source=ch["source"],
                observed_at=_aware(ch["observed_at"]),
            )
            rendered = (f'"{ch["text"]}" [doc:{artifact_id[:8]} '
                        f'@{ch["span_start"]}-{ch["span_end"]}]')
            cost = est_tokens(rendered)
            if cost <= remaining:
                items.append(ContextItem(
                    kind="doc_excerpt", text=rendered,
                    score=1.0 if ch["seq"] == seq else 0.8, citations=[cite]))
                remaining -= cost
    return ContextPack(namespace=ns, subject=subject, subjects=[subject],
                       question=None, budget=budget, items=items, handles=[])


def _pack(
    namespace: str,
    subjects: list[EntityRef],
    question: str | None,
    as_of: datetime | None,
    budget: int,
    observations: list[Observation],
    with_handles: bool = True,
    cos_map: dict[str, float] | None = None,
    semantic: bool = False,
    briefs: list[tuple[EntityRef, str, list[Citation]]] | None = None,
    excerpts: list[tuple[float, Citation, str, int, str]] | None = None,
    valid_at: datetime | None = None,
    paths: dict[tuple[str, str], list[str]] | None = None,
    roots: list[EntityRef] | None = None,
    truncated: list[ScopeTruncation] | None = None,
) -> ContextPack:
    cos_map = cos_map or {}
    if as_of is not None:
        # observation time: nothing a source asserted after T. The gather
        # already applied this bound in the store; this keeps _pack honest
        # for any caller that hands it an unbounded list. A fact scheduled
        # for later (valid_from > T) but known at T belongs in the view —
        # hiding it is valid_at's job (D-046).
        as_of = _aware(as_of)
        observations = [o for o in observations if _aware(o.observed_at) <= as_of]
    if valid_at is not None:
        valid_at = _aware(valid_at)
        observations = [o for o in observations if covers_valid_at(o, valid_at)]

    question_tokens = _question_tokens(question) if question else set()
    # "Is web-01 exposed to anything exploited?" names the subject; without
    # this every recent login *about web-01* matched as many question words
    # as the KEV facts did and outranked them on recency (D-036). The
    # entities the caller asked about are the frame, not the topic.
    if question_tokens and roots:
        named = set()
        for r in roots:
            named |= _tokens(f"{r.type} {r.key}")
        question_tokens = question_tokens - named or question_tokens
    # The recency reference is the newest gathered fact, clamped at now: one
    # forward-dated claim (a typo'd year, a hostile sender) otherwise ages
    # every real fact by decades and flattens ranking to confidence.
    newest = max((_aware(o.observed_at) for o in observations), default=None)
    if newest is not None:
        newest = min(newest, _now())
    scored = sorted(
        (
            (_score(obs, question_tokens, _recency(obs, newest),
                    cos_map.get(obs.id), semantic), obs)
            for obs in observations
        ),
        key=lambda pair: pair[0],
        reverse=True,
    )

    items: list[ContextItem] = []
    handles: list[ExpansionHandle] = []
    remaining = budget

    # Conflicts ship first: an agent must not act on a contested fact
    # unaware. One that doesn't fit is never dropped silently — it becomes
    # a 'conflict' handle so the agent knows contested ground exists (H-C4).
    # They are bounded to a share of the budget, though: a scope over a
    # thousand CVEs where NIST and the CNA disagree produced a pack that was
    # 53 conflicts and zero facts, and the answering model correctly said it
    # could not answer (D-035). Root subjects come first in `subjects`, so
    # the caller's own contested facts are the ones that always fit.
    # Grouped once: scanning every observation per subject was quadratic on
    # a 1,000-subject scope (20 s of pydantic __eq__, D-035).
    by_subject: dict[tuple[str, str], list[Observation]] = {}
    for obs in observations:
        by_subject.setdefault((obs.subject.type, obs.subject.key), []).append(obs)
    conflict_remaining = int(budget * _CONFLICT_BUDGET_SHARE)
    for subj in subjects:
        mine = by_subject.get((subj.type, subj.key), [])
        for predicate, item in _find_conflicts(subj, mine, valid_at or as_of):
            cost = est_tokens(item.text)
            if cost <= remaining and cost <= conflict_remaining:
                items.append(item)
                remaining -= cost
                conflict_remaining -= cost
            elif with_handles:
                handles.append(ExpansionHandle(
                    id=encode_handle(namespace, subj, predicate, as_of, valid_at),
                    hint=f"CONFLICT on {subj.type}:{subj.key} {predicate} "
                    f"did not fit the budget",
                    est_tokens=cost, kind="conflict",
                ))

    # Then dossier briefs — the orientation layer (phase 4).
    for ref, brief, cites in briefs or []:
        text = f"{ref.type}:{ref.key} — {brief}"
        cost = est_tokens(text)
        if cost <= remaining:
            items.append(ContextItem(kind="brief", text=text, score=0.99,
                                     citations=cites))
            remaining -= cost

    # Relevant document passages (D-020): top-ranked excerpts from the
    # documents behind this entity's facts, capped so they inform without
    # crowding out structured facts. Only passages that are close to the
    # best match count as relevant — an absolute threshold means nothing
    # across embedders (H-C6). Each cites its artifact + span.
    excerpt_budget = remaining // 2
    best = excerpts[0][0] if excerpts else 0.0
    for score, cite, text, seq, model in (excerpts or []):
        if score <= 0 or score < best * _EXCERPT_RELATIVE_FLOOR:
            break
        about = ""
        if text.startswith("[about ") and "] " in text:   # attribution goes outside the quotes
            about, text = text.split("] ", 1)
            about += "] "
        rendered = (f'{about}"{text}" [doc:{cite.artifact_id[:8]} '
                    f'@{cite.span_start}-{cite.span_end}]')
        cost = est_tokens(rendered)
        if cost <= excerpt_budget:
            items.append(ContextItem(
                kind="doc_excerpt", text=rendered,
                score=round(min(max(score, 0.0), 1.0), 4),
                citations=[cite]))
            remaining -= cost
            excerpt_budget -= cost
            if with_handles:  # "read around this hit" (roadmap phase 4)
                handles.append(ExpansionHandle(
                    id=encode_handle(namespace, subjects[0], "", as_of, valid_at,
                                     excerpt={"artifact_id": cite.artifact_id,
                                              "seq": seq, "model": model}),
                    hint=f"surrounding passages of doc:{cite.artifact_id[:8]} "
                    f"around @{cite.span_start}",
                    est_tokens=cost * (2 * _EXCERPT_NEIGHBOURS + 1), kind="excerpt",
                ))

    included: set[str] = set()
    skipped: dict[tuple[str, str, str], int] = {}  # (owner type, key, predicate)
    inbound: set[tuple[str, str, str]] = set()
    subject_keys = {(s.type, s.key) for s in subjects}
    by_id = {o.id: o for o in observations} if paths else {}
    for score, obs in scored:
        if obs.id in included:
            continue  # already shipped as part of another fact's path
        text = _render_fact(obs)
        cost = est_tokens(text)
        # A fact about an entity the scope reached travels with the edges it
        # was reached through, as `relation` items just before it; if the
        # chain doesn't fit, neither does the fact (D-035). Without the
        # chain an answering model correctly refuses to connect the dots.
        chain = [
            by_id[pid] for pid in (paths or {}).get((obs.subject.type, obs.subject.key), [])
            if pid in by_id and pid not in included and pid != obs.id
        ]
        chain_cost = sum(est_tokens(_render_fact(p)) for p in chain)
        if cost + chain_cost <= remaining:
            for edge in chain:
                items.append(ContextItem(
                    kind="relation", text=_render_fact(edge),
                    score=round(min(score, 1.0), 4), citations=[_citation(edge)],
                ))
                included.add(edge.id)
            remaining -= chain_cost
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
            # An edge pointing INTO a pack subject from outside the pack
            # (cve X affects product P, asked about P) is one thread on P,
            # not a thread per X: a hub with 2,700 inbound edges made 965
            # one-observation handles (D-035). Expanding the aggregate
            # replays observations_for(P) filtered by predicate, which
            # includes inbound edges.
            owner = obs.subject
            if ((obs.subject.type, obs.subject.key) not in subject_keys
                    and isinstance(obs.object, EntityRef)
                    and (obs.object.type, obs.object.key) in subject_keys):
                owner = obs.object
                inbound.add((owner.type, owner.key, obs.predicate))
            key = (owner.type, owner.key, obs.predicate)
            skipped[key] = skipped.get(key, 0) + 1

    if with_handles:
        for (stype, skey, predicate), count in sorted(
            skipped.items(), key=lambda kv: kv[1], reverse=True
        ):
            subj = EntityRef(type=stype, key=skey)
            direction = "pointing at" if (stype, skey, predicate) in inbound else "for"
            handles.append(
                ExpansionHandle(
                    id=encode_handle(namespace, subj, predicate, as_of, valid_at),
                    hint=f"{count} more '{predicate}' observations {direction} "
                    f"{stype}:{skey}",
                    est_tokens=count * 25,
                )
            )

    # Handles are in priority order (conflicts, excerpts, then the most
    # skipped threads first). Past the cap they stop being a menu and become
    # a second payload; the count says how much was left out.
    omitted = max(0, len(handles) - _MAX_HANDLES)
    return ContextPack(
        namespace=namespace,
        subject=subjects[0] if len(subjects) == 1 else None,
        subjects=subjects,
        question=question,
        as_of=as_of,
        valid_at=valid_at,
        budget=budget,
        items=items,
        handles=handles[:_MAX_HANDLES],
        omitted_handles=omitted,
        truncated=truncated or [],
    )
