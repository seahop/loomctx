"""The context pack builder — the read path (docs/architecture.md).

Given (subject, question, budget, as_of?, valid_at?) this module gathers
observations, ranks them, surfaces conflicts, fills the token budget, and
attaches citations + expansion handles. Ranking is LLM-free (D-051): a
lexical leg (BM25 over the gathered candidates, predicate names split into
words) and, when vectors exist (D-018), a cosine leg, fused by reciprocal
rank; recency (time-decayed) and source confidence adjust the fused
relevance. Packing is value per charged token with a diversity term, and
the charge is the compact rendering an agent receives — item text with
citations, handle hint with id — so the budget is honest on the wire.
Conflicts cover scalar and entity-valued predicates alike; entities past
the gather cap are reachable through page handles; a recorded supersession
(D-050) retires the corrected fact from conflicts and ranks it as history.

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
import heapq
import hmac
import json
import math
import os
import re
import threading
import urllib.parse
from collections import Counter
from datetime import datetime, timedelta, timezone

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
from .contracts import MAX_PATH_DEPTH, PathEdge, PathPack, PathRequest
from .store.base import GraphStore

# Token accounting (D-051, D-058). The charged form is the compact rendering
# an agent actually receives, sized to the costlier of its two surfaces: the
# MCP concise view (compact JSON: an item's kind, text and `cites` strings;
# a handle's id, hint, estimate and kind), which `render_user_prompt` in
# answer.py undercuts. cl100k on seed packs: item text 2.76 chars/token,
# cite strings (hex token, source, ISO date) 2.0, handle ids (base64) 1.47,
# JSON framing 12 tokens an item and 17 a handle. D-051 charged text at
# len/3 + 4 and a citation at a third of its length, which held for the
# prompt but left the MCP wire at 2.8x the budget (indented JSON, citation
# objects, ISO timestamps) — 1.4x even once the view was compact.
_CHARS_PER_TOKEN = 3
_ITEM_OVERHEAD_TOKENS = 4       # framing of one rendered line (est_tokens)
_ITEM_FRAME_TOKENS = 8          # an item's JSON keys beyond that line framing
_CITE_CHARS_PER_TOKEN = 2       # hex, source and ISO date tokenize badly
_CITE_OVERHEAD_TOKENS = 1       # the list separator
_HANDLE_ID_CHARS_PER_TOKEN = 1.5  # base64
_HANDLE_FRAME_TOKENS = 13       # a handle's JSON keys, estimate and kind
_FACT_TOKENS_ESTIMATE = 50      # one rendered fact with its citation (handle estimates)
_HANDLE_BUDGET_SHARE = 0.15     # handles are a menu, not a second payload
_GATHER_LIMIT = 1000
_MAX_EXCERPT_CANDIDATES = 64   # passages considered per pack, after ranking
_MAX_HANDLES = 32              # a scope over a hub produced 8,234 handles (D-035)
_CONFLICT_BUDGET_SHARE = 0.5   # conflicts ship first, but never as the whole pack (D-035)
_BRIEF_BUDGET_SHARE = 0.25     # briefs orient; they never crowd out the facts (D-058)
_BRIEF_MAX_CITES = 8           # a brief's newest supporting observations (answer.py renders 8)
_QUERY_CACHE_SIZE = 256
_RECENCY_HALF_LIFE_DAYS = 30.0  # recency = 1 / (1 + age / half-life)
# Ranking (D-051): BM25 over the gathered candidates, fused with cosine by
# reciprocal rank; recency and confidence adjust the fused relevance.
_RRF_K = 60
_BM25_K1 = 1.2                 # term-frequency saturation; no length normalization (b = 0):
                               # documents are one-line renderings of near-equal length
_RELEVANCE_FLOOR = 0.2         # a fact no leg matched still ranks by recency, never at 0
_SUPERSEDED_DISCOUNT = 0.5     # a corrected fact is history (D-050)
# Packing (D-051): value per token with an MMR-style diversity term — once a
# predicate holds _DIVERSITY_AFTER items, further items of it compete at
# _DIVERSITY_LAMBDA times their value.
_DIVERSITY_AFTER = 3
_DIVERSITY_LAMBDA = 0.5

from .store.common import cosine as _cosine, cosines  # noqa: E402, F401  (re-exported)

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
    with _query_cache_lock:
        vec = _query_cache.get(key)
    if vec is None:
        one = getattr(embedder, "embed_query", None)
        vec = one(question) if callable(one) else embedder.embed([question])[0]
        # asks run in the threadpool: eviction (pop the oldest) raced with
        # concurrent inserts and iterated a dict that changed size (D-046)
        with _query_cache_lock:
            while len(_query_cache) >= _QUERY_CACHE_SIZE:
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
_query_cache_lock = threading.Lock()

# A word ends on a letter or digit: "Summarize web-01." must yield web-01,
# not `web-01.`, or the entity never resolves and the lexical leg misses
# every question that ends in a key (D-058).
_WORD = re.compile(r"[a-z0-9](?:[a-z0-9_.:-]*[a-z0-9])?")


def est_tokens(text: str) -> int:
    """Tokens of one rendered line of text (no citations)."""
    return max(1, len(text) // _CHARS_PER_TOKEN) + _ITEM_OVERHEAD_TOKENS


def cite_text(cite: Citation) -> str:
    """A citation in the compact form an agent receives: the 12-hex cite
    token, source and date (the MCP concise view, D-058); a document
    citation names its full artifact id and span, which get_artifact and
    excerpt handles take."""
    date = cite.observed_at.date().isoformat()
    if cite.observation_id:
        return f"{cite.observation_id[:12]} {cite.source} {date}"
    return f"{cite.artifact_id} @{cite.span_start}-{cite.span_end} {cite.source} {date}"


def cite_tokens(cite: Citation) -> int:
    """One citation in its compact form (`cite_text`)."""
    return -(-len(cite_text(cite)) // _CITE_CHARS_PER_TOKEN) + _CITE_OVERHEAD_TOKENS


def item_tokens(item: ContextItem) -> int:
    """What a pack charges for an item: its text plus every citation (D-051)."""
    return _charge(item.text, item.citations)


def handle_tokens(handle: ExpansionHandle) -> int:
    """What a pack charges for a handle: its hint plus the opaque id, which an
    agent carries in context like any other text, plus its framing."""
    return (est_tokens(handle.hint) + math.ceil(len(handle.id) / _HANDLE_ID_CHARS_PER_TOKEN)
            + _HANDLE_FRAME_TOKENS)


def _charge(text: str, citations: list[Citation]) -> int:
    return est_tokens(text) + _ITEM_FRAME_TOKENS + sum(cite_tokens(c) for c in citations)


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


def _render_fact(obs: Observation, superseded_by: Observation | None = None) -> str:
    text = (
        f"{obs.subject.type}:{obs.subject.key} {obs.predicate} "
        f"{_object_text(obs)} ({obs.observed_at.date().isoformat()}, "
        f"per {obs.source})"
    )
    text += _window_text(obs)
    if superseded_by is not None:
        text += f" [superseded by {superseded_by.id[:12]}]"
    return text


def _supersession(observations: list[Observation]) -> dict[str, Observation]:
    """Recorded supersession (D-050): X -> the visible, later observation Y
    that names X in `supersedes`. Both must be in the set — a correction the
    reader cannot see (redacted, after `as_of`, out of scope) does not act,
    so for an `as_of` before Y was observed, X is current again. Never
    inferred from values or recency."""
    ids = {o.id for o in observations}
    out: dict[str, Observation] = {}
    for obs in observations:
        old = obs.supersedes
        if old and old in ids and old != obs.id:
            prior = out.get(old)
            if prior is None or _aware(obs.observed_at) > _aware(prior.observed_at):
                out[old] = obs
    return out


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


_SEPARATORS = re.compile(r"[_:./-]")


def _stem(word: str) -> str:
    """The one suffix rule worth having: `runs` matches `run`, `ports`
    matches `port`. Applied to both sides of the lexical match only."""
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def _bag(obs: Observation) -> list[str]:
    """The BM25 document for a fact: exactly what the pack renders — the
    predicate name split on its separators (`runs_os` -> runs, os), the
    object text and the subject key — plus the compound identifiers whole
    (`web-01`). attrs never reach the reader, so they are never scored: a
    sender stuffing them with question words bought rank once (D-046)."""
    lowered = f"{obs.predicate} {_object_text(obs)} {obs.subject.key}".lower()
    words = [_stem(w) for w in _WORD.findall(_SEPARATORS.sub(" ", lowered))]
    words += [w for w in _WORD.findall(lowered) if _SEPARATORS.search(w)]
    return words


def _competition_ranks(scores: dict[str, float]) -> dict[str, int]:
    """1 = best; equal scores share a rank ("1, 1, 3"), so twenty facts
    that match the question identically fuse identically and recency,
    not id order, decides between them."""
    ranks: dict[str, int] = {}
    rank, prev = 0, None
    for i, (oid, s) in enumerate(sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))):
        if s != prev:
            rank, prev = i + 1, s
        ranks[oid] = rank
    return ranks


def _bm25(observations: list[Observation], question_tokens: set[str]) -> dict[str, float]:
    """The lexical leg (D-051): BM25 computed in Python over the gathered
    candidates (at most _GATHER_LIMIT per entity, so no index is needed and
    both store backends rank identically). IDF is what the old
    overlap-count could not express: a term that names one fact among a
    thousand outweighs one that names half of them. Only facts with a
    positive score are in the leg; the rest are absent from it."""
    if not question_tokens or not observations:
        return {}
    bags = [(o.id, _bag(o)) for o in observations]
    n = len(bags)
    df: Counter[str] = Counter()
    for _, bag in bags:
        df.update(set(bag))
    query = {_stem(t) for t in question_tokens}
    idf = {t: math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5)) for t in query if t in df}
    if not idf:
        return {}
    scores: dict[str, float] = {}
    for oid, bag in bags:
        tf = Counter(bag)
        s = 0.0
        for term, weight in idf.items():
            f = tf.get(term)
            if f:
                s += weight * f * (_BM25_K1 + 1) / (f + _BM25_K1)
        if s > 0:
            scores[oid] = s
    return scores


def _normalized(scores: dict[str, float], floor: float | None = None) -> dict[str, float]:
    """A leg's scores on [0, 1] within the gathered set. `floor` is the
    value that means "no match" (0 for BM25); with none given the set's
    minimum is the floor — real embedders compress cosine into ~0.27–0.40
    across a set, which as a raw value is nearly a constant."""
    if not scores:
        return {}
    lo = min(scores.values()) if floor is None else floor
    hi = max(scores.values())
    if hi <= lo:
        return {oid: 1.0 for oid in scores}
    return {oid: (v - lo) / (hi - lo) for oid, v in scores.items()}


def _fuse(legs: list[dict[str, float]]) -> dict[str, float]:
    """Relevance in [0, 1] from the legs that have an opinion. One leg has
    nothing to reconcile and keeps its resolution: BM25 normalized by the
    best match (so IDF's 20x gap between a rare term and a common one
    survives), cosine min-max within the set. Two legs are fused by
    reciprocal rank (k = 60) on competition ranks, normalized so a fact
    ranked first by both scores 1.0 — the scales are incomparable and RRF
    is the reconciliation every serious hybrid retriever uses; it does
    compress the top ranks (1/61 vs 1/62), so among near-ties recency and
    confidence decide, by design. A fact absent from a leg (no vector yet,
    no lexical match) simply earns nothing from it — a partially embedded
    set needs no fill-in value."""
    present = [leg for leg in legs if leg]
    if not present:
        return {}
    if len(present) == 1:
        return present[0]
    top = len(present) / (_RRF_K + 1)
    fused: dict[str, float] = {}
    for leg in present:
        for oid, r in _competition_ranks(leg).items():
            fused[oid] = fused.get(oid, 0.0) + 1.0 / (_RRF_K + r)
    return {oid: v / top for oid, v in fused.items()}


def _score(
    obs: Observation,
    relevance: float | None,
    recency: float,
    superseded: bool = False,
) -> float:
    """`relevance` is the fused rank score in [0, 1], or None when no leg had
    an opinion (no question, or nothing matched and no vectors): the pack
    is then the recency overview. Recency and confidence are post-fusion
    multiplicative adjustments — a year-old fact halves, a 0.7-confidence
    fact loses a tenth — rather than terms a strong recency could swamp.
    Extracted claims rank a notch below sender-asserted ones (D-023) and a
    superseded fact ranks as history (D-050). Always in [0, 1]."""
    if relevance is None:
        score = 0.6 * recency + 0.4 * obs.confidence
    else:
        rel = _RELEVANCE_FLOOR + (1 - _RELEVANCE_FLOOR) * relevance
        score = rel * (0.5 + 0.5 * recency) * (0.7 + 0.3 * obs.confidence)
    if _is_extracted(obs):
        score *= _EXTRACTED_DISCOUNT
    if superseded:
        score *= _SUPERSEDED_DISCOUNT
    return min(max(score, 0.0), 1.0)


def _norm_number(value: float) -> str:
    return str(int(value)) if value.is_integer() else repr(value)


def _norm_value(obj) -> str:
    """The comparison form of an object (D-051): `Ubuntu` and `ubuntu`,
    `True` and `"true"`, `9.8` and `"9.8"` are one value, not a
    disagreement. An entity is its `type:key`."""
    if isinstance(obj, EntityRef):
        return f"{obj.type}:{obj.key}".casefold()
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return _norm_number(float(obj))
    text = str(obj).strip().casefold()
    if text in ("true", "false"):
        return text
    try:
        return _norm_number(float(text))
    except ValueError:
        return text


def _windows_overlap(a: Observation, b: Observation) -> bool:
    """Two validity windows share an instant; a missing bound is open."""
    starts = [_aware(o.valid_from) for o in (a, b) if o.valid_from is not None]
    ends = [_aware(o.valid_to) for o in (a, b) if o.valid_to is not None]
    if not starts or not ends:
        return True
    return max(starts) < min(ends)


_ENTITY_CONFLICT_SCORE = 0.95   # as often a resolution gap (two spellings of one product) as a contradiction


def _find_conflicts(
    subject: EntityRef, observations: list[Observation], as_of: datetime | None,
    exclude: set[str] | frozenset[str] = frozenset(),
) -> list[tuple[str, ContextItem]]:
    """Facts about the subject where sources disagree on the value, with
    overlapping validity windows (an open bound overlaps everything).
    Returns (predicate, item) pairs so a conflict that doesn't fit the
    budget can still be handed back as an expansion handle (H-C4).

    Scalar values are compared normalized. Entity-valued predicates count
    too (D-051: dhcp says ip -> web-01, arp-scan says ip -> laptop-17, both
    current) — but an edge predicate is usually multi-valued (logins,
    flows, the products a CVE affects), so when any one source itself
    asserts several current objects the predicate is a set on this
    subject and another source's different object is an addition, not a
    contradiction. For a scalar, a source's values over time are its own
    time series: only its newest assertion is its current claim (D-058).
    cmdb ubuntu-20.04 in January, cmdb ubuntu-22.04 in March and nmap
    ubuntu-22.04 in April agree — keeping cmdb's January value as a side
    made that a conflict. Several values one source asserts at the same
    instant (ports 80 and 443) are a set, like an entity-valued edge.
    `exclude` holds superseded observations (D-050): a corrected fact is
    history, not a side."""
    horizon = as_of or _now()
    by_predicate: dict[str, list[Observation]] = {}
    for obs in observations:
        if obs.subject != subject or obs.id in exclude:
            continue
        # a fact whose validity window has closed is history, not a
        # competing claim about the present (H-C3)
        if obs.valid_to is not None and _aware(obs.valid_to) <= horizon:
            continue
        by_predicate.setdefault(obs.predicate, []).append(obs)
    items: list[tuple[str, ContextItem]] = []
    for predicate, rows in sorted(by_predicate.items()):
        rows.sort(key=lambda o: _aware(o.observed_at), reverse=True)
        entity_valued = any(isinstance(o.object, EntityRef) for o in rows)
        # newest observation per (source, normalized value); for a scalar,
        # only the values at the source's newest instant (rows are newest
        # first, so the first row per source sets that instant)
        per_source: dict[str, dict[str, Observation]] = {}
        latest: dict[str, datetime] = {}
        for o in rows:
            if not entity_valued:
                at = latest.setdefault(o.source, _aware(o.observed_at))
                if _aware(o.observed_at) < at:
                    continue  # a value this source has since moved on from
            per_source.setdefault(o.source, {}).setdefault(_norm_value(o.object), o)
        # Differing values from ONE source are a time series or legitimate
        # update (invoice amounts, an OS upgrade), not a conflict. Only
        # cross-source disagreement gets flagged.
        if len(per_source) < 2:
            continue
        if any(len(values) > 1 for values in per_source.values()):
            continue  # a set-valued predicate on this subject, not a single truth
        by_value: dict[str, Observation] = {}
        for values in per_source.values():
            for norm, o in values.items():
                prior = by_value.get(norm)
                if prior is None or _aware(o.observed_at) > _aware(prior.observed_at):
                    by_value[norm] = o
        if len(by_value) < 2:
            continue
        # only values that clash with a differing value from another source
        # over a shared instant are sides; sequential windows are a history
        contested: set[str] = set()
        candidates = list(by_value.items())
        for i, (norm_a, a) in enumerate(candidates):
            for norm_b, b in candidates[i + 1:]:
                if a.source != b.source and _windows_overlap(a, b):
                    contested.update((norm_a, norm_b))
        if len(contested) < 2:
            continue
        sides = sorted(
            (by_value[n] for n in contested), key=lambda o: o.observed_at, reverse=True
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
        if entity_valued:
            score = min(score, _ENTITY_CONFLICT_SCORE)
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
    before: datetime | None = None, question: str | None = None,
) -> str:
    """`excerpt` = {"artifact_id", "seq", "model"} makes an excerpt handle:
    expanding it returns the cited passage with its neighbours. `before`
    makes a page handle (D-051): expanding it gathers the subject's rows
    observed at or before that instant — the window past the gather cap —
    ranked for `question`, and pages on until exhausted. An empty
    predicate on a page handle means every predicate.

    The payload is plain text (D-062): `ns~type~key~predicate`, then
    tagged fields (`a` as_of, `v` valid_at, `b` before, `q` question, `x`
    excerpt), percent-escaped. Agents carry every handle of every pack in
    their context and the pack is charged for it: base64 of compact JSON
    (D-036) tokenizes at ~1.45 characters a token, so a time-scoped
    handle cost ~128 tokens — a third of a 400-token pack, spent to say
    "two more facts exist". Legacy base64 payloads still decode."""
    fields = [_handle_field(namespace), _handle_field(subject.type),
              _handle_field(subject.key), _handle_field(predicate)]
    if as_of is not None:
        fields.append("a" + _handle_time(as_of))
    if valid_at is not None:
        fields.append("v" + _handle_time(valid_at))
    if before is not None:
        fields.append("b" + _handle_time(_aware(before)))
    if question:
        fields.append("q" + _handle_field(question))
    if excerpt is not None:
        inner = _HANDLE_SAFE.replace(",", "")
        fields.append("x" + ",".join((_handle_field(str(excerpt["artifact_id"]), inner),
                                      str(excerpt["seq"]),
                                      _handle_field(str(excerpt["model"]), inner))))
    raw = "~".join(fields)
    secret = _handle_secret()
    if secret is None:
        return _HANDLE_PREFIX + raw
    return f"{_SIGNED_HANDLE_PREFIX}{raw}.{_sign(raw, secret)}"


def _handle_time(dt: datetime) -> str:
    """An instant in ISO 8601 basic form, in UTC when aware, trailing zeros
    trimmed — `20260924T041804.79Z`, `20260820T00Z`; fromisoformat reads
    both. The extended form with its offset was a third of a handle."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    clock = dt.strftime("%H%M%S")
    if dt.microsecond:
        clock += f".{dt.microsecond:06d}".rstrip("0")
    else:
        while len(clock) > 2 and clock.endswith("00"):
            clock = clock[:-2]
    return f"{dt.strftime('%Y%m%d')}T{clock}{'Z' if dt.tzinfo is not None else ''}"


# `~` separates a handle's fields and `%` escapes; whatever else a key, a
# model name or a question holds is percent-encoded (`,` too inside an
# excerpt's sub-fields).
_HANDLE_SAFE = ":/@!$'()*+,;="
_HANDLE_TAGS = {"a": "as_of", "v": "valid_at", "b": "before", "q": "question", "x": "excerpt"}


def _handle_field(value: str, safe: str = _HANDLE_SAFE) -> str:
    return urllib.parse.quote(value, safe=safe).replace("~", "%7E")


def _decode_text_handle(raw: str) -> dict:
    """The plain-text payload (D-062) in the decoded shape, instants back
    in extended ISO form, so a decoded handle reads as it always did."""
    parts = raw.split("~")
    if len(parts) < 4:
        raise ValueError("malformed handle payload")
    unq = urllib.parse.unquote
    out: dict = {"ns": unq(parts[0]), "subject": {"type": unq(parts[1]), "key": unq(parts[2])},
                 "predicate": unq(parts[3])}
    for part in parts[4:]:
        name = _HANDLE_TAGS.get(part[:1])
        if name is None or name in out:
            raise ValueError("malformed handle payload")
        value = part[1:]
        if name == "excerpt":
            bits = value.split(",")
            if len(bits) != 3 or not bits[1].isdigit():
                raise ValueError("malformed handle payload: excerpt")
            out[name] = {"artifact_id": unq(bits[0]), "seq": int(bits[1]), "model": unq(bits[2])}
        elif name == "question":
            out[name] = unq(value)
        else:
            try:
                out[name] = datetime.fromisoformat(value).isoformat()
            except ValueError as exc:
                raise ValueError(f"malformed handle payload: {name}") from exc
    return out


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
        # the signature is base64url, never a dot; a text payload may hold dots
        raw, sep, sig = handle[len(_SIGNED_HANDLE_PREFIX):].rpartition(".")
        if not sep or not hmac.compare_digest(_sign(raw, secret), sig):
            raise ValueError("handle signature invalid")
    elif handle.startswith(_HANDLE_PREFIX):
        if secret is not None:
            raise ValueError("unsigned handles are not accepted on this deployment")
        raw = handle[len(_HANDLE_PREFIX):]
    else:
        raise ValueError("unrecognized handle format")
    if "~" in raw:   # base64url never holds a tilde: the plain-text form (D-062)
        return _validated_handle(_decode_text_handle(raw))
    raw += "=" * (-len(raw) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(raw))
    except (ValueError, UnicodeDecodeError) as exc:  # binascii.Error is a ValueError
        raise ValueError("malformed handle payload") from exc
    if not isinstance(payload, dict):
        raise ValueError("malformed handle payload")
    if {"n", "s", "p"} <= payload.keys():  # compact form
        s = payload["s"]
        if not (isinstance(s, list) and len(s) == 2):
            raise ValueError("malformed handle payload")
        out = {"ns": payload["n"], "subject": {"type": s[0], "key": s[1]}, "predicate": payload["p"]}
        for short, long in (("a", "as_of"), ("v", "valid_at"), ("x", "excerpt"),
                            ("b", "before"), ("q", "question")):
            if short in payload:
                out[long] = payload[short]
    elif {"ns", "subject", "predicate"} <= payload.keys():  # long form (pre-D-036 handles)
        out = dict(payload)
    else:
        raise ValueError("malformed handle payload")
    return _validated_handle(out)


def _validated_handle(meta: dict) -> dict:
    """Every field an unsigned handle carries is caller-typed: check types
    and values here so a forged `as_of: "yesterday"` or `seq: -1` is a
    400 at the door rather than a 500 inside expand_pack (D-046)."""
    subject = meta.get("subject")
    if not (isinstance(subject, dict) and isinstance(subject.get("type"), str)
            and isinstance(subject.get("key"), str) and subject["type"] and subject["key"]):
        raise ValueError("malformed handle payload: subject")
    meta["subject"] = {"type": subject["type"], "key": subject["key"]}
    if not isinstance(meta.get("ns"), str) or not meta["ns"]:
        raise ValueError("malformed handle payload: namespace")
    if not isinstance(meta.get("predicate"), str):
        raise ValueError("malformed handle payload: predicate")
    for axis in ("as_of", "valid_at", "before"):
        value = meta.get(axis)
        if value is None:
            meta.pop(axis, None)
            continue
        try:
            if not isinstance(value, str):
                raise TypeError
            datetime.fromisoformat(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"malformed handle payload: {axis}") from exc
    question = meta.get("question")
    if question is None:
        meta.pop("question", None)
    elif not isinstance(question, str) or len(question) > 2000:
        raise ValueError("malformed handle payload: question")
    if "excerpt" in meta:
        ex = meta["excerpt"]
        seq = ex.get("seq", 0) if isinstance(ex, dict) else None
        if not (isinstance(ex, dict) and isinstance(ex.get("artifact_id"), str)
                and isinstance(ex.get("model"), str)
                and isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0):
            raise ValueError("malformed handle payload: excerpt")
    return meta


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
            truncated: Truncations, as_of: datetime | None = None,
            allowed_types: tuple[str, ...] | None = None) -> list[Observation]:
    """observations_for under the gather limit, recording when the limit
    cut something off: a hub with 2,740 edges yields its newest 1,000 and
    the pack must say so (D-038). The count is only taken when the limit
    was actually hit, so ordinary entities pay nothing."""
    return _gather_many(store, namespace, [ref], truncated, as_of,
                        allowed_types).get((ref.type, ref.key), [])


def _gather_many(store: GraphStore, namespace: str, refs: list[EntityRef],
                 truncated: Truncations, as_of: datetime | None = None,
                 allowed_types: tuple[str, ...] | None = None,
                 ) -> dict[tuple[str, str], list[Observation]]:
    """One round trip per chunk for a whole frontier or subject list, with
    the same truncation accounting (D-043: a 1,077-entity scope was 1,077
    round trips — 5 s on Postgres across a network). `as_of` is pushed
    into the query as the observed_before bound (D-046): filtering after a
    newest-first LIMIT gave an entity with more than the limit of newer
    rows an empty time-travel pack, and a truncation total blind to T.
    A type-scoped caller's truncation counts only rows it could see, on
    both sides of the ratio (D-058)."""
    as_of = _aware(as_of) if as_of is not None else None
    got = store.observations_for_many(namespace, refs, limit=_GATHER_LIMIT, observed_before=as_of)
    for ref in refs:
        obs = got.get((ref.type, ref.key), [])
        if len(obs) >= _GATHER_LIMIT and (ref.type, ref.key) not in truncated:
            total = store.count_observations(namespace, ref, observed_before=as_of,
                                             allowed_types=allowed_types)
            seen = sum(_in_scope(o, allowed_types) for o in obs)
            if total > seen:
                truncated[(ref.type, ref.key)] = ScopeTruncation(entity=ref, gathered=seen, total=total)
    return got


def resolve_scope(
    store: GraphStore, namespace: str, scope: ScopeSpec,
    as_of: datetime | None = None, valid_at: datetime | None = None,
    allowed_types: tuple[str, ...] | None = None,
) -> list[EntityRef]:
    """Expand a scope into a concrete entity list: BFS from the subjects over
    the named containment predicates, bounded by depth. Deterministic order.
    With no `expand` named, the namespace's registry supplies its
    containment predicates (D-012 promise, D-024)."""
    return resolve_scope_paths(store, namespace, scope, as_of=as_of, valid_at=valid_at,
                               allowed_types=allowed_types)[0]


def canonical_refs(store: GraphStore, namespace: str, refs: list[EntityRef]) -> list[EntityRef]:
    """Each ref as the entity it names, deduplicated in order (D-058): a
    name a merge folded away (host:WEB01 after WEB01 -> web-01) asks about
    the canonical entity — its rows, its conflicts, its scope — instead of
    gathering the canonical rows under a subject nothing matches. Unknown
    refs pass through unchanged."""
    mapping = store.resolve_refs(namespace, refs) if refs else {}
    out: list[EntityRef] = []
    seen: set[tuple[str, str]] = set()
    for ref in refs:
        canonical = mapping.get((ref.type, ref.key), ref)
        if (canonical.type, canonical.key) not in seen:
            seen.add((canonical.type, canonical.key))
            out.append(canonical)
    return out


_SCOPE_CHUNK = 400                     # entities per gather round trip (the stores' own chunk)
_SCOPE_CAP_KEY = ("", "scope_cap")     # the walk's own entry in a Truncations map
# Hub completion (D-061): how many of a hub's expand edges the store's join
# reads for the question's topic, and the rows per far entity a probe reads
# when a crowded frontier (no hub) must be ordered by it.
_HUB_EDGE_LIMIT = 10 * _GATHER_LIMIT
_TOPIC_PROBE_ROWS = 2


def _predicate_words(predicate: str) -> frozenset[str]:
    """A predicate name's content words, stemmed: `exploited_in_wild` ->
    {exploited, wild}; `logged_in_by` -> {logged}."""
    words = set(_WORD.findall(_SEPARATORS.sub(" ", predicate.lower()))) - _STOPWORDS
    return frozenset(_stem(w) for w in words)


def _asked_words(question: str, roots: list[EntityRef] | tuple = ()) -> set[str]:
    """The question's content words, stemmed, without the names of the
    entities it is asked about (they are the frame, not the topic)."""
    words = _question_tokens(question)
    named: set[str] = set()
    for r in roots:
        named |= _tokens(f"{r.type} {r.key}")
    return {_stem(w) for w in (words - named or words)}


def named_predicates(question: str | None, vocabulary, roots: list[EntityRef] | tuple = ()) -> frozenset[str]:
    """The predicates a question names (D-061): every content word of the
    predicate's name is a word of the question — "exploited in the wild"
    names `exploited_in_wild`, "the software web-01 runs" names
    `runs_software` but not `runs_os`. The same word matching the lexical
    leg uses (D-051), over names only: registry descriptions are prose and
    would name half the registry."""
    if not question:
        return frozenset()
    asked = _asked_words(question, roots)
    return frozenset(p for p in vocabulary if (w := _predicate_words(p)) and w <= asked)


def subject_attribute(question: str | None, observations: list[Observation],
                      registry: set[str], roots: list[EntityRef]) -> frozenset[str]:
    """The attribute a subject question asks for (D-062): the predicates it
    names (`named_predicates`, over the registry and the gathered rows) —
    except one whose value it names too. "Which was observed first: web-01
    communicated_with host:vpn-01, or web-01 runs_os rhel-9?" is about two
    particular facts, which the lexical leg finds by those values; taking
    every flow as the topic buried them under recency."""
    named = named_predicates(question, registry | {o.predicate for o in observations}, roots)
    if not named:
        return named
    frame: set[str] = set()
    for r in roots:
        frame |= _tokens(f"{r.type} {r.key}")
    words = _tokens(question or "") - frame
    rooted = {f"{r.type}:{r.key}".lower() for r in roots}
    valued = set()
    for obs in observations:
        if obs.predicate not in named or obs.predicate in valued:
            continue
        ends = {_object_text(obs).lower(), f"{obs.subject.type}:{obs.subject.key}".lower()} - rooted
        if ends & words:
            valued.add(obs.predicate)
    return named - valued


def _schema(store: GraphStore, namespace: str):
    getter = getattr(store, "get_schema", None)
    return getter(namespace) if callable(getter) else None


def _registry_predicates(store: GraphStore, namespace: str) -> set[str]:
    schema = _schema(store, namespace)
    return {p.name for p in schema.predicates} if schema is not None else set()


def _loose_stem(word: str) -> str:
    """`_stem` plus -ed / -ing, for matching prose (registry descriptions)
    against a question: "listed" and "listing" both read `list`."""
    for suffix, keep in (("ing", 4), ("ed", 3)):
        if word.endswith(suffix) and len(word) - len(suffix) >= keep:
            return word[:-len(suffix)]
    return _stem(word)


def _prose_words(text: str) -> set[str]:
    """Content words of prose or of an identifier, loosely stemmed: no
    stopwords, nothing under three characters, no bare numbers."""
    words = set(_WORD.findall(_SEPARATORS.sub(" ", text.lower()))) - _STOPWORDS
    return {_loose_stem(w) for w in words if len(w) >= 3 and not w.isdigit()}


_DESCRIBED_SHARE = 0.4   # of a description's words the question must say


def described_predicates(question: str | None, definitions, roots: list[EntityRef] | tuple = (),
                         exclude=frozenset()) -> frozenset[str]:
    """The attributes a question names by their registry *description*
    rather than their name (D-064): "which CVEs are listed by CISA"
    names the predicate described "CISA KEV listing (bool)". Prose names
    half a registry if any shared word counts, so a match must be
    distinctive: at least two of the question's content words (loosely
    stemmed, the asked-about entities' names aside) among the predicate's
    name and description words, and the question must say a good part of
    the description (`_DESCRIBED_SHARE` of its words) — "cite observation
    ids" and "CISA" name two of the dozen words describing `cvss_score`,
    which is no match — and only the best-scoring predicates (ties kept)
    are taken. Attributes only (no registered object types): a topic is
    what the reached entities carry, not a link. `scope_topic` asks this
    only when the question names no attribute by its name."""
    if not question:
        return frozenset()
    frame: set[str] = set()
    for r in roots:
        frame |= _prose_words(f"{r.type} {r.key}")
    asked = _prose_words(question) - frame
    scored: dict[str, int] = {}
    for d in definitions:
        if d.name in exclude or d.object_types or d.containment or not d.description:
            continue
        words = _prose_words(d.description)
        described = words & asked
        if not described or len(described) < _DESCRIBED_SHARE * len(words):
            continue
        score = len((described | _prose_words(d.name)) & asked)
        if score >= 2:
            scored[d.name] = score
    if not scored:
        return frozenset()
    top = max(scored.values())
    return frozenset(p for p, s in scored.items() if s == top)


def expand_attributes(expand, definitions, observations=()) -> frozenset[str]:
    """The predicates in a scope's expand list that are attributes, not
    links (D-064): registered with no object types (and not containment),
    or unregistered and seen only with values — and in either case never
    seen here with an entity at the other end (a STIX relationship is
    registered without object types and is still a link). An agent that
    writes expand_predicates=["runs_software", "affects",
    "exploited_in_wild"] has named the attribute its answer turns on;
    there is nothing to walk along it."""
    defs = {d.name: d for d in definitions}
    linked: set[str] = set()
    valued: set[str] = set()
    for o in observations:
        (linked if isinstance(o.object, EntityRef) else valued).add(o.predicate)
    out = set()
    for p in expand:
        if p in linked:
            continue
        d = defs.get(p)
        if (d is not None and not d.object_types and not d.containment) or (d is None and p in valued):
            out.add(p)
    return frozenset(out)


def scope_expand(store: GraphStore, namespace: str, scope: ScopeSpec) -> set[str]:
    """The predicates a scope walk follows: the named ones, or the
    registry's containment predicates when none are named (D-024)."""
    expand = set(scope.expand)
    if not expand and scope.depth > 0:
        from .registry import containment_predicates
        expand = set(containment_predicates(store.get_schema(namespace)))
    return expand


def scope_topic(store: GraphStore, namespace: str, scope: ScopeSpec | None, question: str | None,
                seen=(), expand: set[str] | None = None) -> frozenset[str]:
    """A scope question's topic (D-061): the predicates it names that are
    not the walk's own edges — the attribute the answer turns on, which
    lives on the entities the walk reaches, not on the edges it follows
    ("which CVEs CISA lists as exploited in the wild affect software
    web-01 runs": topic `exploited_in_wild`; `runs_software` and `affects`
    are the path). The vocabulary is the namespace's registry (domain
    knowledge is data) plus every predicate already gathered (`seen`: the
    gathered observations). Two more ways to name it (D-064): an attribute
    in the expand list itself (`expand_attributes`), and — when neither
    it nor the question names an attribute by its name — a registered
    attribute the question names by its description
    (`described_predicates`)."""
    if scope is None:
        return frozenset()
    expand = scope_expand(store, namespace, scope) if expand is None else expand
    schema = _schema(store, namespace)
    definitions = list(schema.predicates) if schema is not None else []
    seen = list(seen)
    attributes = expand_attributes(expand, definitions, seen)
    if not question:
        return attributes
    edges = expand - attributes
    roots = list(scope.subjects)
    vocabulary = {d.name for d in definitions} | {o.predicate for o in seen}
    topic = named_predicates(question, vocabulary - edges, roots) | attributes
    if expand_attributes(topic, definitions, seen):
        return topic   # an attribute named by its name: descriptions are only the fallback
    return topic | described_predicates(question, definitions, roots, exclude=edges | topic)


def _record_scope_cap(truncated: Truncations, at: EntityRef, kept: int, reached: int) -> None:
    prior = truncated.get(_SCOPE_CAP_KEY)
    truncated[_SCOPE_CAP_KEY] = ScopeTruncation(
        entity=prior.entity if prior else at, gathered=kept,
        total=max(reached, prior.total if prior else 0), reason="scope_cap")


def resolve_scope_paths(
    store: GraphStore, namespace: str, scope: ScopeSpec,
    truncated: Truncations | None = None,
    as_of: datetime | None = None, valid_at: datetime | None = None,
    allowed_types: tuple[str, ...] | None = None,
    gathered_out: dict[tuple[str, str], list[Observation]] | None = None,
    question: str | None = None,
) -> tuple[list[EntityRef], Paths]:
    """`resolve_scope` plus, for every entity the BFS reached, the chain of
    edges it was reached through (root -> ... -> entity). A fact about a
    reached entity only makes sense to a reader alongside that chain
    (D-035): "CVE-X is exploited" is noise until "web-01 runs nginx, CVE-X
    affects nginx" sits next to it.

    The walk follows only edges the pack itself would show (D-046): none
    observed after `as_of`, none whose validity window misses `valid_at`,
    none a visible correction has superseded (D-050, D-058),
    none touching an entity outside `allowed_types` (D-021: a scoped reader
    must not hop *through* a node they cannot see), and — unless the scope
    says `follow_extracted` — none mined from a document (D-023): a
    hostile document could otherwise rewrite the topology a scope walks
    and pull its own entities into the pack.

    Roots are resolved to canonical entities first, so a merged-away name
    is one root, not a second "reached" subject beside its canonical twin.
    The walk is bounded (D-058): at most LOOM_MAX_SCOPE_ENTITIES entities,
    and it stops expanding once LOOM_MAX_SCOPE_OBSERVATIONS rows are held —
    500 anchors at depth 3 over a 2,740-edge hub otherwise gathered up to
    1,000 rows for every entity in reach. A cut is recorded in `truncated`
    (reason scope_cap), never silent. `gathered_out` receives the frontier
    gathers so the pack need not fetch those entities a second time.

    With a `question` whose topic names an attribute (`scope_topic`, D-061),
    a hub the gather limit cut is completed for that question: the store
    joins the hub's expand edges to the rows of their far ends on the topic
    predicates, and the far ends that carry one are admitted, whatever the
    age of their edge — the KEV entries of a 2,785-edge kernel product are
    older than its newest 1,000 edges, so recency alone never reached them.
    Entities without the attribute stay beyond the window (its page handle
    still offers them). When the entity cap would cut a frontier, the
    topic's carriers are admitted before the rest.
    """
    from .config import max_scope_entities, max_scope_observations
    expand = scope_expand(store, namespace, scope)
    roots = canonical_refs(store, namespace, list(scope.subjects))
    seen = {(r.type, r.key) for r in roots}
    resolved = list(roots)
    frontier = list(roots)
    paths: Paths = {}
    truncated = truncated if truncated is not None else {}
    cap, row_cap = max_scope_entities(), max_scope_observations()
    held = 0                                # rows gathered for the walk
    beyond: set[tuple[str, str]] = set()   # reached, but past the entity cap
    cut_at: EntityRef | None = None
    topic: frozenset[str] | None = None     # computed once the first rows are in

    def walkable(obs: Observation, retired) -> bool:
        return (obs.predicate in expand and obs.id not in retired
                and _in_scope(obs, allowed_types)
                and (valid_at is None or covers_valid_at(obs, valid_at))
                and (scope.follow_extracted or not _is_extracted(obs)))

    def admit(ref: EntityRef, end: EntityRef, obs: Observation, into: list[EntityRef]) -> None:
        nonlocal cut_at
        key = (end.type, end.key)
        if key in seen:
            return
        if len(resolved) >= cap:
            beyond.add(key)   # counted, so the report can say how much was cut
            cut_at = cut_at or ref
            return
        seen.add(key)
        resolved.append(end)
        into.append(end)
        paths[key] = paths.get((ref.type, ref.key), []) + [obs]

    for _ in range(scope.depth):
        if not expand or not frontier or cut_at is not None:
            break
        next_frontier: list[EntityRef] = []
        for start in range(0, len(frontier), _SCOPE_CHUNK):
            chunk = frontier[start:start + _SCOPE_CHUNK]
            if cut_at is not None or held >= row_cap:
                cut_at = cut_at or chunk[0]
                break
            gathered = _gather_many(store, namespace, chunk, truncated, as_of, allowed_types)
            held += sum(len(rows) for rows in gathered.values())
            if gathered_out is not None:
                gathered_out.update(gathered)
            # a corrected edge is history (D-050), not topology: an open
            # finding a later closed row supersedes must not pull its
            # entities in — the same visible, as-of-bounded rule the pack
            # applies (D-058)
            retired = _supersession([o for rows in gathered.values() for o in rows
                                     if _in_scope(o, allowed_types)])
            # the far ends this chunk's windows reach, in walk order
            window: dict[tuple[str, str], tuple[EntityRef, EntityRef, Observation]] = {}
            for ref in chunk:
                for obs in gathered.get((ref.type, ref.key), []):
                    if not walkable(obs, retired):
                        continue
                    for end in (obs.subject, obs.object):
                        if isinstance(end, EntityRef) and (end.type, end.key) not in seen:
                            window.setdefault((end.type, end.key), (ref, end, obs))
            hubs = [ref for ref in chunk
                    if (t := truncated.get((ref.type, ref.key))) is not None and t.reason == "gather_limit"]
            crowded = len(resolved) + len(window) > cap
            if (hubs or crowded) and topic is None:
                topic = scope_topic(store, namespace, scope, question,
                                    [o for rows in gathered.values() for o in rows], expand)
            carriers: Reach = {}
            if topic and (hubs or crowded):
                # an attribute named in expand is the topic, not a link (D-064)
                carriers, read = _hub_carriers(store, namespace, hubs, expand - topic, topic, seen, as_of,
                                               valid_at, allowed_types, walkable, window, truncated)
                held += read
                if crowded:   # the rest of the window, by probe
                    hub_keys = {(h.type, h.key) for h in hubs}
                    rest = {k: r for k, r in window.items()
                            if k not in carriers and (r[0].type, r[0].key) not in hub_keys}
                    more, read = _topic_carriers(store, namespace, rest, topic, as_of, valid_at, allowed_types)
                    held += read
                    carriers.update(more)
                # in walk order: the window's carriers, then those past it
                carriers = {k: carriers[k] for k in [*window, *carriers] if k in carriers}
            # What the question is about goes in first: when the entity cap
            # binds, it cuts the entities that do not carry the topic, not
            # the ones that do (D-061). Past the window only carriers enter.
            for ref, end, obs in carriers.values():
                admit(ref, end, obs, next_frontier)
            for ref, end, obs in window.values():
                admit(ref, end, obs, next_frontier)
        frontier = next_frontier
    if cut_at is not None:
        _record_scope_cap(truncated, cut_at, len(resolved), len(resolved) + len(beyond))
    return resolved, paths


Reach = dict[tuple[str, str], tuple[EntityRef, EntityRef, Observation]]  # far end -> (from, end, edge)


def _hub_carriers(store: GraphStore, namespace: str, hubs: list[EntityRef], expand: set[str],
                  topic: frozenset[str], seen: set[tuple[str, str]], as_of: datetime | None,
                  valid_at: datetime | None, allowed_types: tuple[str, ...] | None,
                  walkable, window: Reach, truncated: Truncations) -> tuple[Reach, int]:
    """The far ends of hubs the gather limit cut that carry the question's
    topic, whatever their age (D-061): the walk saw each hub's newest
    `_GATHER_LIMIT` rows, and the KEV entries behind a 2,785-edge product
    are older than its newest 1,000 edges. One indexed join per hub side
    in the store (`edges_to_carriers`, over at most `_HUB_EDGE_LIMIT` of
    the hub's expand edges) returns only the matching (edge, attribute)
    pairs; the edges then pass the walk's own rules (visible, as of, valid
    at, not extracted, not superseded) and the attributes the reader's.

    Completion is for an attribute that singles out a few of a hub's far
    ends. When most of them carry it (a CVSS score on every CVE), the
    recency window already holds carriers aplenty and reaching the rest
    would only fill the scope to its cap: such a hub keeps its window.
    Returns the far ends not yet reached, newest edge first, and the rows
    read."""
    if not hubs:
        return {}, 0
    before = _aware(as_of) if as_of is not None else None
    pairs = store.edges_to_carriers(namespace, hubs, sorted(expand), sorted(topic),
                                    limit=_HUB_EDGE_LIMIT, observed_before=before)
    if not pairs:
        return {}, 0
    rows = {o.id: o for o in store.observations_by_ids(
        namespace, list({i for _, edge, attr in pairs for i in (edge, attr)}))}
    edge_ids = list({edge for _, edge, _ in pairs})
    retired = _supersession([o for o in store.corrections_of(namespace, edge_ids, observed_before=before)
                             if _in_scope(o, allowed_types)] + [rows[i] for i in edge_ids if i in rows])
    by_key = {(h.type, h.key): h for h in hubs}
    far: Reach = {}
    for hub_key, edge_id, attr_id in pairs:
        edge, attr = rows.get(edge_id), rows.get(attr_id)
        hub = by_key.get(hub_key)
        if edge is None or attr is None or hub is None or not walkable(edge, retired):
            continue
        if not _in_scope(attr, allowed_types) or (valid_at is not None and not covers_valid_at(attr, valid_at)):
            continue
        end = attr.subject
        if (end.type, end.key) not in seen:
            far.setdefault((end.type, end.key), (hub, end, edge))
    for key, hub in by_key.items():
        mine = [k for k, (h, _, _) in far.items() if h is hub]
        t = truncated.get(key)
        if t is not None and 2 * len(mine) > t.total:   # not selective: the window stands
            for k in mine:
                if k not in window:
                    del far[k]
    return far, len(rows)


def _topic_carriers(store: GraphStore, namespace: str, candidates: Reach, topic: frozenset[str],
                    as_of: datetime | None, valid_at: datetime | None,
                    allowed_types: tuple[str, ...] | None) -> tuple[Reach, int]:
    """The candidates that carry a topic predicate this reader may see at
    this time (D-061): one predicate-filtered read of at most
    `_TOPIC_PROBE_ROWS` rows per candidate — an unrelated far end costs an
    index probe, not a gather. Returns them in candidate order, and the
    rows read."""
    if not candidates:
        return {}, 0
    probe = store.observations_for_many(namespace, [end for _, end, _ in candidates.values()],
                                        limit=_TOPIC_PROBE_ROWS,
                                        observed_before=_aware(as_of) if as_of is not None else None,
                                        predicates=sorted(topic))
    # the entity's own attribute (it is the row's subject), as the hub join reads it
    carriers = {key: reach for key, reach in candidates.items()
                if any(o.subject == reach[1] and _in_scope(o, allowed_types)
                       and (valid_at is None or covers_valid_at(o, valid_at))
                       for o in probe.get(key, []))}
    return carriers, sum(len(rows) for rows in probe.values())


def _focus(scope: ScopeSpec | None, question: str | None) -> frozenset[str]:
    """The scope's own expand predicates that the question names — its
    words, stemmed, stopwords aside: `logged_in_by` for "which users
    logged in ...", not `member_of` for "who logged in?" (D-058)."""
    if scope is None or not scope.expand or not question:
        return frozenset()
    asked = {_stem(t) for t in _question_tokens(question)}
    return frozenset(
        p for p in scope.expand
        if ({_stem(w) for w in _WORD.findall(_SEPARATORS.sub(" ", p.lower()))} - _STOPWORDS) & asked)


def build_pack(
    store: GraphStore,
    req: AskRequest,
    embedder=None,
    allowed_types: tuple[str, ...] | None = None,
) -> ContextPack:
    from .config import max_scope_observations
    paths: Paths = {}
    truncated: Truncations = {}
    gathered: dict[tuple[str, str], list[Observation]] = {}
    asked = list(req.scope.subjects) if req.scope is not None else [req.subject]
    if req.scope is not None:
        subjects, paths = resolve_scope_paths(
            store, req.namespace, req.scope, truncated,
            as_of=req.as_of, valid_at=req.valid_at, allowed_types=allowed_types,
            gathered_out=gathered, question=req.question)
    else:
        # the entity the name resolves to — a merged-away alias included (D-058)
        subjects = canonical_refs(store, req.namespace, [req.subject])
    if allowed_types is not None:
        # scoped keys see a scoped world (D-013a): entities reached by
        # expansion outside the allowlist simply aren't there
        subjects = [s for s in subjects if s.type in allowed_types]
    # The walk already gathered its frontiers; fetch the rest, within the
    # ask's row bound (D-058) — subjects past it are left out and reported.
    held = sum(len(rows) for rows in gathered.values())
    row_cap = max_scope_observations()
    examined = {key for key in gathered}
    missing = [s for s in subjects if (s.type, s.key) not in examined]
    for start in range(0, len(missing), _SCOPE_CHUNK):
        if held >= row_cap:
            break
        chunk = missing[start:start + _SCOPE_CHUNK]
        got = _gather_many(store, req.namespace, chunk, truncated, req.as_of, allowed_types)
        held += sum(len(rows) for rows in got.values())
        gathered.update(got)
        examined.update((s.type, s.key) for s in chunk)
    left_out = [s for s in subjects if (s.type, s.key) not in examined]
    if left_out:
        subjects = [s for s in subjects if (s.type, s.key) in examined]
        _record_scope_cap(truncated, left_out[0], len(subjects), len(subjects) + len(left_out))
    observations: list[Observation] = []
    seen_ids: set[str] = set()  # an obs can reach us via several subjects
    for ref in subjects:
        for obs in gathered.get((ref.type, ref.key), []):
            if obs.id not in seen_ids and _in_scope(obs, allowed_types):
                seen_ids.add(obs.id)
                observations.append(obs)
    # The edges the walk reached an entity through are evidence the pack
    # must be able to show with it, even when neither end's window holds
    # them (an edge a hub's completion found past both windows, D-061).
    for key, chain in paths.items():
        if key not in examined:
            continue
        for obs in chain:
            if obs.id not in seen_ids and _in_scope(obs, allowed_types):
                seen_ids.add(obs.id)
                observations.append(obs)
    observations.sort(key=lambda o: _aware(o.observed_at), reverse=True)
    topic = (scope_topic(store, req.namespace, req.scope, req.question, observations)
             if req.scope is not None else frozenset())
    notes = request_notes(store, req.namespace, req.scope, asked, observations,
                          {key for key in examined if not gathered.get(key)}, allowed_types,
                          question=req.question, hops=max((len(c) for c in paths.values()), default=0))
    # A subject question's named attribute ("what is the has_severity of
    # CVE-X", "the largest invoiced_amount ever recorded") orders its
    # conflicts and ships before the orientation layers, exempt from the
    # diversity term (D-062) — as a scope's topic does (D-061).
    attribute = (subject_attribute(req.question, observations,
                                   _registry_predicates(store, req.namespace), asked)
                 if req.scope is None else frozenset())

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
    # summary, so it is withheld from as-of and valid-at (time-travel)
    # reads (H-C2, D-058). It cites the observations it was synthesized
    # from; ones outside the gathered window simply drop out of the list.
    # Its TEXT, though, was written from all of them: a type-scoped key
    # gets a brief only if it may see every observation the brief cites —
    # one visible citation used to ship a summary of user logins to a
    # host-only key (D-058).
    briefs: list[tuple[EntityRef, str, list[Observation]]] = []
    withheld = 0
    if req.as_of is None and req.valid_at is None:
        by_id = {o.id: o for o in observations}
        for ref in subjects[:3]:
            dossier = store.get_dossier(req.namespace, ref)
            if not dossier:
                continue
            ids = dossier.get("observation_ids", [])
            if allowed_types is not None:
                unseen = [i for i in ids if i not in by_id]
                if any(not _in_scope(o, allowed_types)
                       for o in store.observations_by_ids(req.namespace, unseen)):
                    withheld += 1
                    continue
            cited = [by_id[i] for i in ids if i in by_id]
            if cited:
                briefs.append((ref, dossier["brief"], cited))

    return _pack(
        namespace=req.namespace,
        subjects=subjects,
        question=req.question,
        as_of=req.as_of,
        valid_at=req.valid_at,
        budget=min(req.budget, max_budget()),
        observations=observations,
        cos_map=cos_map,
        # the serving embedder may have vectors for none of these rows (a
        # different model than the worker's, a backlog): rank by keyword
        # then, rather than by a neutral cosine that mutes the keywords
        semantic=semantic and bool(cos_map),
        briefs=briefs,
        withheld_briefs=withheld,
        # the attribute a scope question names is its topic; with none, the
        # walk's own edges it names are (D-058)
        focus=topic or _focus(req.scope, req.question),
        topic=topic,
        attribute=attribute,
        excerpts=excerpts,
        paths={key: [o.id for o in chain] for key, chain in paths.items()},
        # both spellings are the frame, not the topic: the name asked and
        # the entity it resolved to
        roots=asked + [s for s in subjects if (s.type, s.key) not in paths],
        truncated=list(truncated.values()),
        page_cursors=_oldest(gathered),
        notes=notes,
    )


_MAX_SUGGESTIONS = 3


def _close_predicates(name: str, definitions, vocabulary: set[str]) -> list[str]:
    """Up to three predicates an unknown name may have meant: close
    spellings first (difflib), then the ones sharing the most of its words
    in their name or registry description ("cisa_known_exploited_…" ->
    the predicate described "CISA KEV listing")."""
    import difflib
    names = sorted(vocabulary)
    out = difflib.get_close_matches(name, names, n=_MAX_SUGGESTIONS, cutoff=0.6)
    words = _prose_words(name)
    described = {d.name: d.description for d in definitions}
    shared = {n: len(words & (_prose_words(n) | _prose_words(described.get(n, "")))) for n in names}
    best = max(shared.values(), default=0)
    if best:
        out += [n for n in names if shared[n] == best and n not in out]
    return out[:_MAX_SUGGESTIONS]


def request_notes(store: GraphStore, namespace: str, scope: ScopeSpec | None, asked: list[EntityRef],
                  observations: list[Observation], empty: set[tuple[str, str]],
                  allowed_types: tuple[str, ...] | None = None,
                  question: str | None = None, hops: int = 0) -> list[str]:
    """What the pack could not do as asked, said in the pack (D-064): an
    expand predicate that is neither registered nor carried by anything
    the scope reached was ignored without a word — an agent that invented
    `cisa_known_exploited_vulnerability` got a one-hop pack and no hint —
    so it is named, with the closest predicates the namespace has; an
    attribute in the expand list is taken as the topic, and the note says
    so; when the question names an attribute nothing reached carries and
    a link the reached entities have that the scope does not follow, the
    link is pointed out (weaker agents expanded ['runs_software'] for the
    KEV CVEs affecting that software, and stopped a hop short); a subject
    that names no entity says so, with entities of that key. `empty`
    holds the examined subjects that yielded no rows (only those are
    looked up). A type-scoped reader's suggestions stay in its types."""
    notes: list[str] = []
    schema = _schema(store, namespace)
    definitions = [d for d in (schema.predicates if schema is not None else [])
                   if allowed_types is None or not d.object_types
                   or set(d.object_types) & set(allowed_types)]
    attributes = expand_attributes(scope.expand, definitions, observations) if scope else frozenset()
    if scope is not None and scope.expand:
        vocabulary = {d.name for d in definitions} | {o.predicate for o in observations}
        for p in dict.fromkeys(scope.expand):
            if p in attributes:
                notes.append(f"expand predicate '{p}' holds values, not links between entities: "
                             "taken as the question's topic, not walked")
            elif p not in vocabulary:
                close = _close_predicates(p, definitions, vocabulary)
                notes.append(f"expand predicate '{p}' is not registered in namespace '{namespace}' "
                             "and nothing this scope reached carries it, so it was not followed"
                             + (f"; closest: {', '.join(close)}" if close else "")
                             + " (describe_namespace lists each type's links)")
    if scope is not None and question:
        expand = scope_expand(store, namespace, scope)
        roots = list(scope.subjects)
        carried = {o.predicate for o in observations}
        linked = {o.predicate for o in observations if isinstance(o.object, EntityRef)}
        wanted = (named_predicates(question, {d.name for d in definitions} - expand - carried, roots)
                  | attributes) - carried
        links = named_predicates(question, linked - expand, roots)
        if wanted and links:
            # one hop more, when the walk went as deep as it was allowed to
            deeper = f" and depth={scope.depth + 1}" if hops >= scope.depth and scope.depth < 3 else ""
            notes.append(f"the question names {', '.join(repr(p) for p in sorted(wanted))}, which nothing "
                         f"this scope reached carries, and {', '.join(repr(p) for p in sorted(links))}, "
                         "a link the reached entities have that it does not follow: add that to "
                         f"expand_predicates{deeper} to reach what carries the rest")
    if empty:
        refs = list({(r.type, r.key): r for r in asked
                     if allowed_types is None or r.type in allowed_types}.values())
        mapping = store.resolve_refs(namespace, refs) if refs else {}
        for ref in refs:
            if (ref.type, ref.key) not in empty or (ref.type, ref.key) in mapping:
                continue   # it had rows, or it names an entity (canonical or merged away)
            similar = [f"{e.type}:{e.key}" for e in store.search_entities(
                namespace, ref.key, limit=_MAX_SUGGESTIONS, types=allowed_types)]
            notes.append(f"no entity '{ref.type}:{ref.key}' in namespace '{namespace}'"
                         + (f"; entities with that key: {', '.join(similar)}" if similar else ""))
    return notes


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


_PATH_ENUM_CAP = 256   # complete paths enumerated before the search stops (D-067)


def _path_edge(obs: Observation) -> PathEdge:
    """A stored observation as one edge of a path — never re-oriented."""
    return PathEdge(subject=obs.subject, predicate=obs.predicate, object=obs.object,
                    cite=_citation(obs), valid_from=obs.valid_from, valid_to=obs.valid_to,
                    source=obs.source)


def _path_cost(edges: list[Observation]) -> int:
    """What a path charges: every edge's rendered fact plus its citation,
    summed — the same accounting a pack uses (D-051, D-067)."""
    return sum(item_tokens(ContextItem(kind="relation", text=_render_fact(e), score=1.0,
                                       citations=[_citation(e)])) for e in edges)


def find_paths(
    store: GraphStore,
    req: PathRequest,
    allowed_types: tuple[str, ...] | None = None,
    stats: dict | None = None,
) -> PathPack:
    """Enumerate the edge sequence(s) that already EXIST between two entities
    along the `via` predicates (D-067). A bounded, shortest-first BFS over the
    SAME gather/walk machinery build_pack/resolve_scope use: it follows `via`
    edges in both directions (an `affects` edge is cve -> product, walked
    product -> cve, mirroring the scope walk), simple paths only (a cycle
    never loops), capped by `depth`, `max_paths`, the token `budget`, and the
    LOOM_MAX_SCOPE_* caps. Endpoints resolve to their canonical entities
    (alias-following, D-058); each edge passes the walk's own rules — visible,
    observed at or before `as_of`, covering `valid_at`, not superseded
    (D-050), not extracted from a document (D-023), and inside `allowed_types`
    (a path through a gated entity is not returned, D-021). It reports what
    exists; it never ranks, scores, or weights edges by exploitability.

    The BFS is over paths, not entities, so a hub re-reached by many routes
    multiplies them: the edge extensions it examines are bounded by
    LOOM_MAX_SCOPE_OBSERVATIONS (a cut is reported as scope_cap, with a
    note), and the last hop only checks which edges reach `to` — it
    materializes no partial path. `stats`, when given, receives the work
    counters (for tests)."""
    from .config import max_budget, max_scope_entities, max_scope_observations
    from .registry import containment_predicates

    ns = req.namespace
    notes: list[str] = []
    truncated: Truncations = {}

    # endpoints, canonical (a merged-away alias asks about the entity it
    # became, D-058); absence from the mapping means the name is unknown. A
    # canonical entity of a type the caller may not see is not there for
    # them, as build_pack drops such a subject: the requested ref is echoed,
    # nothing is searched, and it reads as unknown — a cross-type alias must
    # not reveal the gated entity it names.
    resolved = store.resolve_refs(ns, [req.from_, req.to])
    mapping = {k: v for k, v in resolved.items()
               if allowed_types is None or v.type in allowed_types}
    hidden_endpoint = len(mapping) < len(resolved)
    src = mapping.get((req.from_.type, req.from_.key), req.from_)
    dst = mapping.get((req.to.type, req.to.key), req.to)
    src_key, dst_key = (src.type, src.key), (dst.type, dst.key)

    # via: the named predicates, or the registry's containment predicates
    # when none are named (the scope-walk default, D-024)
    via = list(dict.fromkeys(req.via))
    if not via:
        via = list(containment_predicates(_schema(store, ns)))
    via_set = set(via)

    depth = min(req.depth, MAX_PATH_DEPTH)
    if req.depth > depth:
        notes.append(f"depth {req.depth} exceeds the cap; clamped to {depth}")

    endpoints_ok = not hidden_endpoint and (allowed_types is None or (
        src.type in allowed_types and dst.type in allowed_types))
    complete: list[tuple[Observation, ...]] = []
    seen_preds: set[str] = set()
    depth_open = False
    work = 0            # edge extensions examined: partials made + reach checks
    materialized = 0    # partial paths held for a next hop
    searched = bool(via_set) and endpoints_ok and src_key != dst_key

    if searched:
        cap, row_cap = max_scope_entities(), max_scope_observations()
        work_cap = row_cap
        gathered: dict[tuple[str, str], list[Observation]] = {}
        entities_seen: set[tuple[str, str]] = {src_key}
        held = 0
        cut_at: EntityRef | None = None
        work_cut = False

        def gather(refs: list[EntityRef], into: Truncations) -> bool:
            """Gather the `refs` not gathered yet, within the row cap; False
            when the cap stopped it before every one was read."""
            nonlocal held
            need = list({(r.type, r.key): r for r in refs
                         if (r.type, r.key) not in gathered}.values())
            for start in range(0, len(need), _SCOPE_CHUNK):
                if held >= row_cap:
                    return False
                chunk = need[start:start + _SCOPE_CHUNK]
                got = _gather_many(store, ns, chunk, into, req.as_of, allowed_types)
                held += sum(len(r) for r in got.values())
                gathered.update(got)
                for c in chunk:  # gathered, even when it has no rows
                    gathered.setdefault((c.type, c.key), [])
                # the vocabulary a note may name: only rows this caller sees
                seen_preds.update(o.predicate for rows in got.values() for o in rows
                                  if _in_scope(o, allowed_types))
            return True

        def adjacency():
            """Each gathered entity's walkable (edge, far end) pairs, under
            the supersession the rows gathered so far record."""
            retired = _supersession([o for rows in gathered.values() for o in rows
                                     if _in_scope(o, allowed_types)])
            cache: dict[tuple[str, str], list[tuple[Observation, EntityRef]]] = {}

            def adj(k: tuple[str, str]) -> list[tuple[Observation, EntityRef]]:
                if k not in cache:
                    cache[k] = [
                        (obs, end) for obs in gathered.get(k, [])
                        if obs.predicate in via_set and obs.id not in retired
                        and _in_scope(obs, allowed_types)
                        and (req.valid_at is None or covers_valid_at(obs, req.valid_at))
                        and not _is_extracted(obs)
                        for end in (obs.subject, obs.object)
                        if isinstance(end, EntityRef) and (end.type, end.key) != k]
                return cache[k]
            return adj

        # a partial path: (where it ends, its edges, the entities on it)
        partials: list[tuple[EntityRef, tuple[Observation, ...], frozenset]] = [
            (src, (), frozenset({src_key}))]
        # the last hop's far ends other than `to`: never materialized as
        # paths, only kept (with each path's entity set) to tell whether the
        # depth cut anything
        leaves: dict[tuple[str, str], tuple[EntityRef, list[frozenset]]] = {}
        for hop in range(depth):
            if not partials:
                break
            if not gather([node for node, _, _ in partials], truncated):
                cut_at = next(n for n, _, _ in partials if (n.type, n.key) not in gathered)
                break
            adj = adjacency()
            last = hop == depth - 1
            next_partials: list[tuple[EntityRef, tuple[Observation, ...], frozenset]] = []
            for node, edges, visited in partials:
                if work_cut or cut_at is not None or len(complete) >= _PATH_ENUM_CAP:
                    break
                for obs, end in adj((node.type, node.key)):
                    work += 1
                    if work > work_cap:
                        work_cut, cut_at = True, node
                        break
                    ekey = (end.type, end.key)
                    if ekey in visited:
                        continue   # already on this path (no cycles)
                    if ekey == dst_key:
                        if len(complete) < _PATH_ENUM_CAP:
                            complete.append(edges + (obs,))
                        continue   # reached the target; do not walk past it
                    if last:
                        leaves.setdefault(ekey, (end, []))[1].append(visited)
                        continue
                    if ekey not in entities_seen:
                        if len(entities_seen) >= cap:
                            cut_at = cut_at or end
                            continue
                        entities_seen.add(ekey)
                    next_partials.append((end, edges + (obs,), visited | {ekey}))
                    materialized += 1
            partials = next_partials
            if work_cut or len(complete) >= _PATH_ENUM_CAP:
                break

        # The depth cut something only when a depth-length path could still
        # be extended: one of its far ends has a walkable edge to an entity
        # off that path. Checked a chunk of far ends at a time, stopping at
        # the first witness; when the caps stop the check first, the cut is
        # reported (a longer path may exist — the reader must not conclude
        # absence).
        if leaves and cut_at is None and len(complete) < _PATH_ENUM_CAP:
            order = list(leaves)
            for start in range(0, len(order), _SCOPE_CHUNK):
                chunk = order[start:start + _SCOPE_CHUNK]
                # a far end's own gather limit is not the path's to report ({})
                if start >= cap or not gather([leaves[k][0] for k in chunk], {}):
                    depth_open = True
                    break
                adj = adjacency()
                for k in chunk:
                    near = {(e.type, e.key) for _, e in adj(k)}
                    if any(near - on_path for on_path in leaves[k][1]):
                        depth_open = True
                        break
                if depth_open:
                    break

        if work_cut:
            notes.append(f"the search examined {work_cap:,} edge extensions (the "
                         "LOOM_MAX_SCOPE_OBSERVATIONS bound) and stopped: a hub fans out into "
                         "more routes than that, so more paths may exist; name fewer 'via' "
                         "predicates or lower depth")
        if cut_at is not None:
            _record_scope_cap(truncated, cut_at, len(entities_seen), len(entities_seen) + 1)

    if stats is not None:
        stats.update(work=work, partials=materialized)

    # A correction can sit on a row the walk never gathered: Y shares X's
    # subject, not its object, so walked from X's object side the subject's
    # rows (and Y) are never read. Every candidate edge is looked up by id,
    # as of `as_of`, and a path holding a superseded edge is dropped (D-050,
    # as expand_pack does) — only a correction this reader may see acts.
    if complete:
        edge_rows = {e.id: e for edges in complete for e in edges}
        before = _aware(req.as_of) if req.as_of is not None else None
        fixes = [c for c in store.corrections_of(ns, list(edge_rows), observed_before=before)
                 if _in_scope(c, allowed_types)]
        retired = _supersession(fixes + list(edge_rows.values()))
        if retired:
            complete = [edges for edges in complete if not any(e.id in retired for e in edges)]

    # shortest first, then a stable order by the edges' ids
    complete.sort(key=lambda edges: (len(edges), tuple(e.id for e in edges)))
    budget = min(req.budget, max_budget())
    returned: list[tuple[Observation, ...]] = []
    charged = 0
    dropped_budget = 0
    for edges in complete:
        if len(returned) >= req.max_paths:
            break
        cost = _path_cost(list(edges))
        if charged + cost > budget:
            dropped_budget += 1
            continue   # a later, cheaper path may still fit
        returned.append(edges)
        charged += cost

    # more paths existed than were returned: the max_paths cap or the budget
    # cut them — reported, never silently dropped
    enum_capped = len(complete) >= _PATH_ENUM_CAP
    if len(returned) < len(complete) or enum_capped:
        total = len(complete) + (1 if enum_capped else 0)
        truncated[("", "max_paths")] = ScopeTruncation(
            entity=dst, gathered=len(returned), total=max(total, len(returned) + 1),
            reason="max_paths")
        if dropped_budget:
            notes.append(f"{dropped_budget} more path(s) were found but dropped to fit the "
                         "token budget; raise budget or max_paths")
    if depth_open:
        # how many longer paths exist is exactly what was not explored, so
        # `total` claims none: it is the paths found within the depth
        truncated[("", "depth")] = ScopeTruncation(
            entity=dst, gathered=len(returned), total=max(len(complete), len(returned)),
            reason="depth")
        if depth < MAX_PATH_DEPTH:
            notes.append(f"the depth {depth} frontier was not exhausted; {dst.type}:{dst.key} "
                         "may be reachable along a longer path — raise depth")
        else:
            notes.append(f"the search stopped at the depth cap {depth} with the frontier still "
                         "open; a longer path may exist but was not explored")
    if not returned and searched:
        notes.append(f"no path found from {src.type}:{src.key} to {dst.type}:{dst.key} within "
                     f"depth {depth} along {', '.join(sorted(via_set))}")
    if not via_set:
        notes.append(f"namespace '{ns}' registers no containment predicates and none were named "
                     "in 'via', so there was nothing to traverse")

    # request notes (D-064): an unknown via predicate, an unknown endpoint
    schema = _schema(store, ns)
    definitions = [d for d in (schema.predicates if schema is not None else [])
                   if allowed_types is None or not d.object_types
                   or set(d.object_types) & set(allowed_types)]
    vocabulary = {d.name for d in definitions} | seen_preds
    if req.via:
        for p in dict.fromkeys(req.via):
            if p not in vocabulary:
                close = _close_predicates(p, definitions, vocabulary)
                notes.append(f"via predicate '{p}' is not registered in namespace '{ns}' and "
                             "nothing reached carries it, so it was not traversed"
                             + (f"; closest: {', '.join(close)}" if close else ""))
    for label, named in (("from", req.from_), ("to", req.to)):
        if (named.type, named.key) not in mapping and (
                allowed_types is None or named.type in allowed_types):
            similar = [f"{e.type}:{e.key}" for e in store.search_entities(
                ns, named.key, limit=_MAX_SUGGESTIONS, types=allowed_types)]
            notes.append(f"the {label} entity '{named.type}:{named.key}' is not in namespace "
                         f"'{ns}'" + (f"; entities with that key: {', '.join(similar)}"
                                      if similar else ""))

    return PathPack(
        namespace=ns, from_=src, to=dst,
        paths=[[_path_edge(e) for e in edges] for edges in returned],
        charged_tokens=charged, truncated=list(truncated.values()), notes=notes)


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
    before = datetime.fromisoformat(meta["before"]) if meta.get("before") else None
    budget = min(budget, max_budget())
    if isinstance(meta.get("excerpt"), dict):
        return _expand_excerpt(store, meta, subject, budget, allowed_types)
    # a handle minted before a merge names the folded-away entity (D-058)
    subject = canonical_refs(store, meta["ns"], [subject])[0]
    truncated: Truncations = {}
    # A page handle (D-051) carries the window's edge: gather at or before
    # it, which is also at or before `as_of` when both are set.
    bound = as_of
    if before is not None:
        bound = before if as_of is None else min(_aware(before), _aware(as_of))
    gathered = _gather(store, meta["ns"], subject, truncated, bound, allowed_types)
    predicate = meta["predicate"]
    visible = [o for o in gathered if _in_scope(o, allowed_types)]
    observations = [o for o in visible if not predicate or o.predicate == predicate]
    # A correction outside this thread still acts on it (D-050) — but only
    # one this reader may see (a hidden one acted, and leaked its id
    # prefix, D-058), and wherever it lies: a page's window ends before the
    # corrections of its rows were made, so they are looked up by id, as
    # of the handle's `as_of` only.
    known = {o.id for o in visible}
    corrections = [c for c in store.corrections_of(
                       meta["ns"], [o.id for o in observations],
                       observed_before=_aware(as_of) if as_of is not None else None)
                   if c.id not in known and _in_scope(c, allowed_types)]
    return _pack(
        namespace=meta["ns"],
        subjects=[subject],
        question=meta.get("question") or None,
        as_of=as_of,
        valid_at=valid_at,
        budget=budget,
        observations=observations,
        # a thread handle spends the budget on the thread; a page is a pack
        # over a window and its cut threads are expandable within it
        with_handles=before is not None,
        # The caller asked for this thread — a conflict handle in particular
        # — so the whole budget is theirs to spend on it; the share cap is
        # for packs that must also carry facts (D-046).
        conflict_share=1.0 if before is None else _CONFLICT_BUDGET_SHARE,
        truncated=list(truncated.values()),
        superseded_by=_supersession(visible + corrections),
        page_cursors=_oldest(gathered, subject),
        page_before=before,
        page_predicate=predicate,
    )


def _oldest(gathered: list[Observation] | dict[tuple[str, str], list[Observation]],
            subject: EntityRef | None = None) -> dict[tuple[str, str], datetime]:
    """The edge of each gathered window: the oldest observed_at per entity,
    which is where the next page starts (D-051)."""
    if isinstance(gathered, list):
        assert subject is not None
        gathered = {(subject.type, subject.key): gathered}
    return {key: min(_aware(o.observed_at) for o in rows) for key, rows in gathered.items() if rows}


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
            cost = _charge(rendered, [cite])   # text AND citation, like every pack (D-058)
            if cost <= remaining:
                items.append(ContextItem(
                    kind="doc_excerpt", text=rendered,
                    score=1.0 if ch["seq"] == seq else 0.8, citations=[cite]))
                remaining -= cost
    return ContextPack(namespace=ns, subject=subject, subjects=[subject],
                       question=None, budget=budget, items=items, handles=[],
                       charged_tokens=sum(item_tokens(i) for i in items))


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
    briefs: list[tuple[EntityRef, str, list[Observation]]] | None = None,
    excerpts: list[tuple[float, Citation, str, int, str]] | None = None,
    valid_at: datetime | None = None,
    paths: dict[tuple[str, str], list[str]] | None = None,
    roots: list[EntityRef] | None = None,
    truncated: list[ScopeTruncation] | None = None,
    conflict_share: float = _CONFLICT_BUDGET_SHARE,
    superseded_by: dict[str, Observation] | None = None,
    page_cursors: dict[tuple[str, str], datetime] | None = None,
    page_before: datetime | None = None,
    page_predicate: str = "",
    withheld_briefs: int = 0,
    focus: frozenset[str] = frozenset(),
    topic: frozenset[str] = frozenset(),
    attribute: frozenset[str] = frozenset(),
    notes: list[str] | None = None,
) -> ContextPack:
    """Rank, then fill the budget (D-051). Order of business: conflicts
    (never silently dropped, capped at `conflict_share` of the budget),
    briefs (capped at a quarter, D-058), document excerpts (half of what
    is left), then facts by value
    per charged token with the diversity term, then handles within their
    share. Every item and handle is charged in its compact rendered form
    and `charged_tokens` reports the sum. `superseded_by` (D-050) is
    computed here from the visible set unless the caller gathered a wider
    one; `page_cursors` are the gathered windows' oldest instants, from
    which page handles are minted for entities the gather cap truncated."""
    cos_map = cos_map or {}
    if as_of is not None:
        # observation time: nothing a source asserted after T. The gather
        # already applied this bound in the store; this keeps _pack honest
        # for any caller that hands it an unbounded list. A fact scheduled
        # for later (valid_from > T) but known at T belongs in the view —
        # hiding it is valid_at's job (D-046).
        as_of = _aware(as_of)
        observations = [o for o in observations if _aware(o.observed_at) <= as_of]
    if superseded_by is None:
        # after the as_of cut: a correction observed after T has not
        # happened yet as of T, so the corrected fact is current again
        superseded_by = _supersession(observations)
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
    # Two legs, fused by reciprocal rank: BM25 over what the pack renders,
    # and cosine where vectors exist for the gathered rows. With neither
    # (no question, or nothing matched and no vectors) the pack is the
    # recency overview rather than a ranking by a neutral constant (D-046).
    legs = [_normalized(_bm25(observations, question_tokens), floor=0.0)]
    if semantic and cos_map:
        legs.append(_normalized({o.id: cos_map[o.id] for o in observations if o.id in cos_map}))
    relevance = _fuse(legs)
    # A scope's expand predicate that the question names is the question's
    # topic (D-058): "which users logged in to the host alert X triggered
    # on", walked over triggered_on + logged_in_by, spent its budget on
    # communicated_with — "host" is rare among the gathered rows, "logged"
    # is on every login, so IDF ranked the flows first and the logins
    # shipped only as handles. Facts on a focus predicate take full
    # relevance (recency and confidence still order them) and are exempt
    # from the diversity term.
    scored = sorted(
        (
            (_score(obs, (1.0 if obs.predicate in focus else relevance.get(obs.id, 0.0))
                    if relevance else None,
                    _recency(obs, newest), obs.id in superseded_by), obs)
            for obs in observations
        ),
        key=lambda pair: pair[0],
        reverse=True,
    )

    items: list[ContextItem] = []
    conflict_handles: list[ExpansionHandle] = []
    excerpt_handles: list[ExpansionHandle] = []
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
    conflict_remaining = int(budget * conflict_share)
    # A contested fact about an entity the scope walk merely reached is the
    # question's business only when the question is about that predicate
    # (D-061): a two-hop walk over a product hub reaches a thousand CVEs
    # whose CVSS scorers disagree, and shipping those first spent half of
    # every budget on scores nobody asked about. The rest are handed back
    # as conflict handles, after the pages — never dropped.
    reached = set(paths or {}) if question else set()
    aside_handles: list[ExpansionHandle] = []
    aside_unminted = 0
    # Among conflicts of equal standing (a document-introduced one still
    # ranks below two structured sources, H-C5), which ships first is the
    # question's call (D-062): the one on the attribute it names, then by
    # how relevant the contested predicate's facts ranked — name order put
    # a CVE's cvss_score conflict ahead of the has_severity one asked
    # about, and the asked one became a handle at 400 tokens.
    on_topic = attribute | focus
    predicate_relevance: dict[str, float] = {}
    for obs in observations:
        r = relevance.get(obs.id, 0.0)
        if r > predicate_relevance.get(obs.predicate, -1.0):
            predicate_relevance[obs.predicate] = r
    for subj in subjects:
        mine = by_subject.get((subj.type, subj.key), [])
        aside = (subj.type, subj.key) in reached
        found = _find_conflicts(subj, mine, valid_at or as_of, exclude=superseded_by.keys())
        found.sort(key=lambda pair: (-pair[1].score, pair[0] not in on_topic,
                                     -predicate_relevance.get(pair[0], 0.0)))
        for predicate, item in found:
            cost = item_tokens(item)
            if aside and predicate not in focus:
                if len(aside_handles) < _MAX_HANDLES:
                    aside_handles.append(ExpansionHandle(
                        id=encode_handle(namespace, subj, predicate, as_of, valid_at, before=page_before),
                        hint=f"CONFLICT on {subj.type}:{subj.key} {predicate} (not what the question asks)",
                        est_tokens=cost, kind="conflict"))
                else:
                    aside_unminted += 1
                continue
            if cost <= remaining and cost <= conflict_remaining:
                items.append(item)
                remaining -= cost
                conflict_remaining -= cost
            else:
                # est_tokens is the exact cost the expansion charges (text
                # plus citations), so a caller passing it as the expansion
                # budget is guaranteed the conflict (D-046). Minted even in
                # a thread expansion, which otherwise carries no handles: a
                # conflict that does not fit is never dropped silently (D-058).
                conflict_handles.append(ExpansionHandle(
                    id=encode_handle(namespace, subj, predicate, as_of, valid_at, before=page_before),
                    hint=f"CONFLICT on {subj.type}:{subj.key} {predicate} "
                    f"did not fit the budget",
                    est_tokens=cost, kind="conflict",
                ))

    # A scope question's topic comes next (D-061): the facts on the
    # attribute it names, with the edges that reached them, before the
    # orientation layers — at 3,200 tokens the KEV question's pack held
    # sixteen CVSS conflicts and four document excerpts and not one
    # `exploited_in_wild`. Siblings reached through one edge that share the
    # attribute's value render as one item per four (`_group_key`); the
    # handles' share is held back so the menu still fits. A subject
    # question's named attribute takes the same place (D-062): a KEV CVE's
    # advisory excerpt and its handle filled a 400-token pack asked for
    # the CVE's epss_percentile, and not one fact shipped.
    subject_keys = {(s.type, s.key) for s in subjects}
    by_id = {o.id: o for o in observations} if paths else {}
    pool = _fact_pool(scored, paths or {}, by_id, superseded_by, subject_keys)
    edge_costs: dict[str, int] = {}
    page_handles = _page_handles(namespace, truncated, page_cursors, as_of, valid_at,
                                 page_before, page_predicate, question)
    share = int(budget * _HANDLE_BUDGET_SHARE)
    included: set[str] = set()
    topic_skipped: dict[tuple[str, str, str], int] = {}
    topic_inbound: set[tuple[str, str, str]] = set()
    held_back = 0
    first = topic | attribute
    if first:
        topic_pool = [e for e in pool if e[3].predicate in first]
        if topic_pool:
            pool = [e for e in pool if e[3].predicate not in first]
            groups = {e[3].id: g for e in topic_pool
                      if (g := _group_key(e[3], e[5], by_id, superseded_by, subject_keys)) is not None}
            topic_pool = _grouped_density(topic_pool, groups)
            known = conflict_handles + page_handles + aside_handles if with_handles else []
            if with_handles and pool:
                # the rest of the facts may be cut to a thread too, and the
                # topic's items cannot be trimmed to make room for its
                # handle later: hold back the room of the biggest one
                # (D-062; a 200-token pack rode over by the handle's cost)
                _, rest_skipped, rest_inbound, _ = _select_facts(
                    pool, 0, by_id, subject_keys, on_topic, edge_costs)
                known = known + _thread_handles(namespace, rest_skipped, rest_inbound, as_of,
                                                valid_at, page_before, limit=1)[0]
            reserve = _handle_room(known, budget, share)
            for _ in range(2):
                # the handles' room is held back from the topic: what the
                # handles already known need, then — if the topic itself
                # left threads behind — what those add (the loop below
                # would otherwise have to trim facts it cannot trim)
                done = set(included)
                room = max(0, remaining - reserve)
                got, topic_skipped, topic_inbound, left = _select_facts(
                    topic_pool, room, by_id, subject_keys, on_topic, edge_costs,
                    included=done, groups=groups)
                threads = (_thread_handles(namespace, topic_skipped, topic_inbound, as_of, valid_at,
                                           page_before, limit=_MAX_HANDLES)[0] if with_handles else [])
                wanted = _handle_room(known + threads, budget, share)
                if wanted <= reserve:
                    break
                reserve = wanted
            included = done
            items.extend(got)
            remaining -= room - left
            held_back = min(reserve, remaining)
            remaining -= held_back

    # Then dossier briefs — the orientation layer (phase 4) — within their
    # share (D-058): a brief cites up to a hundred observations, and at
    # ~10 tokens a citation one brief took 1,000-1,400 tokens of an
    # 800-token pack before any fact. It carries its newest supporting
    # observations (at most _BRIEF_MAX_CITES, what the prompt renders),
    # each still a real source of the summary; a brief whose text does
    # not fit the share is withheld and counted.
    brief_remaining = int(budget * _BRIEF_BUDGET_SHARE)
    for ref, brief, cited in briefs or []:
        text = f"{ref.type}:{ref.key} — {brief}"
        room = min(brief_remaining, remaining)
        cites: list[Citation] = []
        cost = est_tokens(text)
        for obs in sorted(cited, key=lambda o: _aware(o.observed_at), reverse=True)[:_BRIEF_MAX_CITES]:
            cite = _citation(obs)
            if cites and cost + cite_tokens(cite) > room:
                break
            cites.append(cite)
            cost += cite_tokens(cite)
        if cost <= room:
            items.append(ContextItem(kind="brief", text=text, score=0.99,
                                     citations=cites))
            remaining -= cost
            brief_remaining -= cost
        else:
            withheld_briefs += 1

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
        cost = _charge(rendered, [cite])
        if cost <= excerpt_budget:
            items.append(ContextItem(
                kind="doc_excerpt", text=rendered,
                score=round(min(max(score, 0.0), 1.0), 4),
                citations=[cite]))
            remaining -= cost
            excerpt_budget -= cost
            if with_handles:  # "read around this hit" (roadmap phase 4)
                excerpt_handles.append(ExpansionHandle(
                    id=encode_handle(namespace, subjects[0], "", as_of, valid_at,
                                     excerpt={"artifact_id": cite.artifact_id,
                                              "seq": seq, "model": model}),
                    hint=f"surrounding passages of doc:{cite.artifact_id[:8]} "
                    f"around @{cite.span_start}",
                    est_tokens=cost * (2 * _EXCERPT_NEIGHBOURS + 1), kind="excerpt",
                ))

    # Facts: value per token with the diversity term, against what the
    # fixed items left. Handles are a bounded share of the budget; when the
    # threads they stand for need that share, the facts are re-selected
    # against the rest so the pack — items AND handles — fits the request.
    remaining += held_back
    fixed_remaining = remaining
    unminted = 0   # threads past the handle cap: counted, never encoded

    def select(item_budget: int) -> tuple[list[ContextItem], list[ExpansionHandle], int]:
        nonlocal unminted
        facts, skipped, inbound, left = _select_facts(
            pool, item_budget, by_id, subject_keys, on_topic, edge_costs, included=set(included))
        for key, n in topic_skipped.items():
            skipped[key] = skipped.get(key, 0) + n
        inbound |= topic_inbound
        fixed = conflict_handles + page_handles + aside_handles + excerpt_handles
        threads, unminted = _thread_handles(
            namespace, skipped, inbound, as_of, valid_at, page_before,
            limit=max(0, _MAX_HANDLES - len(fixed))) if with_handles else ([], 0)
        unminted += aside_unminted
        return facts, fixed + threads, left

    item_budget = fixed_remaining
    facts: list[ContextItem] = []
    handles: list[ExpansionHandle] = []
    allowance = fixed_remaining
    for _ in range(3):  # cutting facts can add threads; the item budget only shrinks
        facts, handles, left = select(item_budget)
        allowance = fixed_remaining - (item_budget - left)   # what the whole budget has left
        costs = [handle_tokens(h) for h in handles[:_MAX_HANDLES]]
        if not costs:
            break
        room = min(sum(costs), max(share, costs[0]))
        # Below twice a handle's cost the budget cannot hold a handle and an
        # item, so the first handle rides outside it (charged_tokens says so)
        if room <= allowance or budget < 2 * costs[0] or item_budget == max(0, fixed_remaining - room):
            break
        item_budget = max(0, fixed_remaining - room)
    shipped: list[ExpansionHandle] = []
    spent = 0
    for handle in handles[:_MAX_HANDLES]:
        cost = handle_tokens(handle)
        # the first handle always ships: a pack that cut something must be
        # able to say so. The loop above makes room for it by trimming
        # facts; only when the budget is under two handles, or the fixed
        # items (conflicts, briefs, excerpts) left no room, does it ride
        # over the budget — by its own cost at most, as the contract says
        if shipped and spent + cost > allowance:
            break
        shipped.append(handle)
        spent += cost
    omitted = len(handles) - len(shipped) + unminted
    items.extend(facts)

    # Handles are in priority order (conflicts, pages past the gather cap,
    # excerpts, then the most skipped threads first). Past the cap they
    # stop being a menu and become a second payload; the count says how
    # much was left out.
    return ContextPack(
        namespace=namespace,
        subject=subjects[0] if len(subjects) == 1 else None,
        subjects=subjects,
        question=question,
        as_of=as_of,
        valid_at=valid_at,
        budget=budget,
        items=items,
        handles=shipped,
        omitted_handles=omitted,
        truncated=truncated or [],
        charged_tokens=sum(item_tokens(i) for i in items) + sum(handle_tokens(h) for h in shipped),
        withheld_briefs=withheld_briefs,
        notes=notes or [],
    )


Pool = list[tuple[float, float, int, Observation, str, list[str]]]


def _handle_room(handles: list[ExpansionHandle], budget: int, share: int) -> int:
    """The room the handles `_pack` would ship need: those that fit, in
    order, within the share (or the first one's cost if that is larger) —
    none when the budget is under two of the first, which then rides
    outside it."""
    costs = [handle_tokens(h) for h in handles[:_MAX_HANDLES]]
    if not costs or budget < 2 * costs[0]:
        return 0
    cap, room = max(share, costs[0]), 0
    for cost in costs:
        if room + cost > cap:
            break
        room += cost
    return room


def _fact_pool(
    scored: list[tuple[float, Observation]],
    paths: dict[tuple[str, str], list[str]],
    by_id: dict[str, Observation],
    superseded_by: dict[str, Observation],
    subject_keys: set[tuple[str, str]],
) -> Pool:
    """Every candidate fact rendered and priced once per pack, densest
    first: (score per token, score, cost, obs, text, path).

    The path is the chain of the pack subject the fact was gathered on:
    its subject's, or — for an edge pointing INTO a reached entity from
    outside the pack (CVE-Y affects nginx, nginx reached through web-01) —
    its object's. Keyed on the subject alone, such a fact shipped without
    the edges that tie nginx to the root (S-27)."""
    pool: Pool = []
    for score, obs in scored:
        owner = (obs.subject.type, obs.subject.key)
        if (owner not in paths and owner not in subject_keys
                and isinstance(obs.object, EntityRef)):
            owner = (obs.object.type, obs.object.key)
        path = paths.get(owner, [])
        if any(pid not in by_id for pid in path):
            continue  # an edge of the chain is not visible in this view: neither is the fact
        text = _render_fact(obs, superseded_by.get(obs.id))
        cost = _charge(text, [_citation(obs)])
        pool.append((score / cost, score, cost, obs, text, path))
    pool.sort(key=lambda e: e[0], reverse=True)
    return pool


class _Group:
    """What siblings must share to render as one item (D-061): the fact's
    predicate, value and source, the edge that reached them (predicate,
    direction, the entity at its other end) and the chain before it, and
    the form of the facts' and the edges' validity windows (`_window_form`):
    `own` is stated once for the item, `explicit` per member."""

    __slots__ = ("key", "prefix", "edge_predicate", "anchor", "outbound", "fact_form",
                 "edge_form", "predicate", "object_text", "source")

    def __init__(self, key, prefix, edge_predicate, anchor, outbound, fact_form, edge_form,
                 predicate, object_text, source):
        self.key, self.prefix = key, prefix
        self.edge_predicate, self.anchor, self.outbound = edge_predicate, anchor, outbound
        self.fact_form, self.edge_form, self.predicate = fact_form, edge_form, predicate
        self.object_text, self.source = object_text, source


_GROUP_MAX = 4   # members per rendered item: two citations each, the eight answer.py renders


def _window_form(obs: Observation) -> str:
    """`own`: valid from its own observation instant, open-ended; `none`:
    no window (timeless); `explicit`: any other window."""
    if obs.valid_from is None and obs.valid_to is None:
        return "none"
    if obs.valid_to is None and _aware(obs.valid_from) == _aware(obs.observed_at):
        return "own"
    return "explicit"


def _window_text(obs: Observation) -> str:
    """The ` [valid X to Y]` suffix `_render_fact` writes, or nothing."""
    if not (obs.valid_from or obs.valid_to):
        return ""
    frm = obs.valid_from.date().isoformat() if obs.valid_from else "?"
    to = obs.valid_to.date().isoformat() if obs.valid_to else "present"
    return f" [valid {frm} to {to}]"


def _group_key(obs: Observation, path: list[str], by_id: dict[str, Observation],
               superseded_by: dict[str, Observation],
               subject_keys: set[tuple[str, str]]) -> tuple[_Group, Observation] | None:
    """The sibling group of a topic fact about an entity the walk reached,
    with the edge that reached it; None when the fact must render alone
    (about a root, superseded, or the edge itself)."""
    if not path or obs.id in superseded_by or obs.id in path:
        return None
    edge = by_id.get(path[-1])
    member = obs.subject
    if edge is None or (member.type, member.key) not in subject_keys:
        return None
    if edge.subject == member and isinstance(edge.object, EntityRef):
        anchor, outbound = edge.object, True
    elif edge.object == member:
        anchor, outbound = edge.subject, False
    else:
        return None
    fact_form, edge_form = _window_form(obs), _window_form(edge)
    prefix = tuple(path[:-1])
    key = (obs.predicate, _norm_value(obs.object), obs.source, edge.predicate,
           anchor.type, anchor.key, outbound, fact_form, edge_form, prefix)
    return _Group(key, prefix, edge.predicate, anchor, outbound, fact_form, edge_form,
                  obs.predicate, _object_text(obs), obs.source), edge


_OWN_WINDOWS = {("own", "own"): ", valid from each date",
                ("own", "none"): ", facts valid from each date",
                ("own", "explicit"): ", facts valid from each date",
                ("none", "own"): ", edges valid from each date",
                ("explicit", "own"): ", edges valid from each date"}


def _render_group(group: _Group, members: list[tuple[Observation, Observation]]) -> str:
    """`cve:A (2023-05-12), cve:B (2022-09-15) exploited_in_wild True (per
    cisa-kev, valid from each date); each affects product:linux:linux_kernel`
    — each member's own date (and its edge's, when that differs), the
    shared value and source once, the shared edge once. A window of the
    `own` form is stated once in the parentheses; an explicit one is
    written per member as `_render_fact` writes it: `cve:C (2026-09-18;
    edge 2026-09-21 [valid 2026-06-25 to present])`."""
    parts = []
    for obs, edge in members:
        date = obs.observed_at.date().isoformat()
        edate = edge.observed_at.date().isoformat()
        fwin = _window_text(obs) if group.fact_form == "explicit" else ""
        ewin = _window_text(edge) if group.edge_form == "explicit" else ""
        tail = f"; edge {edate}{ewin}" if (edate != date or ewin) else ""
        parts.append(f"{obs.subject.type}:{obs.subject.key} ({date}{fwin}{tail})")
    window = _OWN_WINDOWS.get((group.fact_form, group.edge_form), "")
    anchor = f"{group.anchor.type}:{group.anchor.key}"
    link = (f"each {group.edge_predicate} {anchor}" if group.outbound
            else f"{anchor} {group.edge_predicate} each")
    return (f"{', '.join(parts)} {group.predicate} {group.object_text} "
            f"(per {group.source}{window}); {link}")


def _group_charge(group: _Group, members: list[tuple[Observation, Observation]]) -> int:
    cites = [c for obs, edge in members for c in (_citation(obs), _citation(edge))]
    return _charge(_render_group(group, members), cites)


def _grouped_density(pool: Pool, groups: dict[str, tuple[_Group, Observation]]) -> Pool:
    """A groupable fact's density is its score per the tokens it adds to a
    group (its name, date and two citations), not per a standalone line
    plus its edge; re-sorted so `_select_facts` ranks by it."""
    out: Pool = []
    for density, score, cost, obs, text, path in pool:
        g = groups.get(obs.id)
        if g is not None:
            group, edge = g
            one = _group_charge(group, [(obs, edge)])
            two = _group_charge(group, [(obs, edge), (obs, edge)])
            density = score / max(1, two - one)
        out.append((density, score, cost, obs, text, path))
    out.sort(key=lambda e: e[0], reverse=True)
    return out


class _Chunk:
    """One rendered group item, filled member by member."""

    __slots__ = ("group", "members", "score")

    def __init__(self, group: _Group):
        self.group, self.members, self.score = group, [], 0.0

    def item(self) -> ContextItem:
        return ContextItem(
            kind="fact", text=_render_group(self.group, self.members),
            score=round(min(self.score, 1.0), 4),
            citations=[c for obs, edge in self.members for c in (_citation(obs), _citation(edge))])


def _select_facts(
    pool: Pool,
    budget: int,
    by_id: dict[str, Observation],
    subject_keys: set[tuple[str, str]],
    focus: frozenset[str] = frozenset(),
    edge_costs: dict[str, int] | None = None,
    included: set[str] | None = None,
    groups: dict[str, tuple[_Group, Observation]] | None = None,
) -> tuple[list[ContextItem], dict[tuple[str, str, str], int], set[tuple[str, str, str]], int]:
    """Value-per-token selection with an MMR-style diversity term (D-051).
    Candidates are ordered by score per charged token; each round takes
    the affordable candidate with the highest value, where one whose
    predicate already holds _DIVERSITY_AFTER items competes at
    _DIVERSITY_LAMBDA times its value — twenty near-identical logins no
    longer crowd out a relevant fact of another kind. Greedy trim by score
    did (and a long fact cost the same as a short one).

    A fact about an entity the scope reached travels with the edges it was
    reached through, as `relation` items just before it; if the chain
    doesn't fit, neither does the fact (D-035). Density is the fact's own
    score per token — the chain is context the reader needs, not a
    discount on the fact — while affordability counts the chain. A fact
    that cannot be afforded is skipped for good (the budget only shrinks)
    and counted toward its thread's handle.

    `groups` (D-061) maps a topic fact to its sibling group and the edge
    that reached it: such a fact joins its group's open item (four members
    each) and pays only what it adds — the item's charge with it minus the
    charge without — and its edge ships inside the item, cited, instead of
    as a relation line. `included` carries ids an earlier pass shipped and
    is updated in place.

    Returns (items, skipped thread counts, inbound thread keys, budget left).
    """
    edge_costs = edge_costs if edge_costs is not None else {}
    groups = groups or {}
    remaining = budget
    items: list[ContextItem | _Chunk] = []
    included = included if included is not None else set()
    skipped: dict[tuple[str, str, str], int] = {}  # (owner type, key, predicate)
    inbound: set[tuple[str, str, str]] = set()
    per_predicate: Counter[str] = Counter()
    open_chunks: dict[tuple, _Chunk] = {}

    def skip(obs: Observation) -> None:
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

    def edge_cost(edge: Observation) -> int:
        # a chain edge is re-priced for every candidate it precedes, in
        # every round: memoized per pack (30k renders on a 1,082-entity scope)
        cost = edge_costs.get(edge.id)
        if cost is None:
            cost = edge_costs[edge.id] = _charge(_render_fact(edge), [_citation(edge)])
        return cost

    def grouped(obs: Observation) -> tuple[_Group, Observation, _Chunk | None, int] | None:
        """(group, edge, the open chunk it would join, what it adds), when
        the fact renders as a group member here."""
        g = groups.get(obs.id)
        if g is None or g[1].id in included:
            return None   # its edge already shipped: a plain fact now
        group, edge = g
        chunk = open_chunks.get(group.key)
        if chunk is not None:
            add = (_group_charge(group, chunk.members + [(obs, edge)])
                   - _group_charge(group, chunk.members))
        else:
            add = _group_charge(group, [(obs, edge)])
        return group, edge, chunk, add

    dead: set[str] = set()  # chosen, shipped as an edge, or unaffordable for good
    # Lazy greedy: a candidate's value only falls (density is fixed; the
    # diversity factor drops once), so the heap holds an upper bound per
    # candidate and one popped still at the top is the round's best — ties
    # to the earlier (denser) pool position, as a front-to-back scan picks.
    # Rescanning the pool every round was rounds x pool (35k facts over an
    # identity hub: seconds per pack).
    heap = [(-entry[0], i) for i, entry in enumerate(pool)]
    heapq.heapify(heap)
    while heap:
        _, i = heapq.heappop(heap)
        density, score, cost, obs, text, path = pool[i]
        if obs.id in dead:
            continue
        if obs.id in included:
            dead.add(obs.id)
            continue  # already shipped as part of another fact's path
        member = grouped(obs)
        if member is not None:
            chain = [by_id[pid] for pid in member[0].prefix if pid not in included]
            cost_here = member[3]
        else:
            chain = [by_id[pid] for pid in path if pid not in included and pid != obs.id]
            cost_here = cost
        chain_cost = sum(edge_cost(p) for p in chain)
        if cost_here + chain_cost > remaining:
            dead.add(obs.id)
            skip(obs)
            continue
        value = density * (_DIVERSITY_LAMBDA
                           if per_predicate[obs.predicate] >= _DIVERSITY_AFTER
                           and obs.predicate not in focus else 1.0)
        if heap and (-value, i) > heap[0]:
            heapq.heappush(heap, (-value, i))
            continue
        cost = cost_here
        for edge in chain:
            items.append(ContextItem(
                kind="relation", text=_render_fact(edge),
                score=round(min(score, 1.0), 4), citations=[_citation(edge)],
            ))
            included.add(edge.id)
            per_predicate[edge.predicate] += 1
        remaining -= chain_cost
        if member is not None:
            group, edge, chunk, _ = member
            if chunk is None:
                chunk = open_chunks[group.key] = _Chunk(group)
                items.append(chunk)
            chunk.members.append((obs, edge))
            chunk.score = max(chunk.score, score)
            if len(chunk.members) >= _GROUP_MAX:
                del open_chunks[group.key]
            included.add(edge.id)
        else:
            items.append(ContextItem(kind="fact", text=text, score=round(min(score, 1.0), 4),
                                     citations=[_citation(obs)]))
        remaining -= cost
        included.add(obs.id)
        dead.add(obs.id)
        per_predicate[obs.predicate] += 1
    for _, _, _, obs, _, _ in pool:  # affordable but never picked (a zero score): still a thread
        if obs.id not in dead and obs.id not in included:
            skip(obs)
    return [i.item() if isinstance(i, _Chunk) else i for i in items], skipped, inbound, remaining


def _thread_handles(
    namespace: str, skipped: dict[tuple[str, str, str], int], inbound: set[tuple[str, str, str]],
    as_of: datetime | None, valid_at: datetime | None, page_before: datetime | None,
    limit: int = _MAX_HANDLES,
) -> tuple[list[ExpansionHandle], int]:
    """The `limit` biggest skipped threads as handles, and how many more
    there were: a 1,082-entity scope encoded 11k handles per pack to ship
    32 of them (D-058)."""
    handles = []
    ranked = sorted(skipped.items(), key=lambda kv: kv[1], reverse=True)
    for (stype, skey, predicate), count in ranked[:limit]:
        subj = EntityRef(type=stype, key=skey)
        direction = "pointing at" if (stype, skey, predicate) in inbound else "for"
        handles.append(ExpansionHandle(
            id=encode_handle(namespace, subj, predicate, as_of, valid_at, before=page_before),
            hint=f"{count} more '{predicate}' observations {direction} {stype}:{skey}",
            est_tokens=count * _FACT_TOKENS_ESTIMATE,
        ))
    return handles, len(ranked) - len(handles)


def _page_handles(
    namespace: str, truncated: list[ScopeTruncation] | None,
    page_cursors: dict[tuple[str, str], datetime] | None,
    as_of: datetime | None, valid_at: datetime | None, page_before: datetime | None,
    page_predicate: str, question: str | None,
) -> list[ExpansionHandle]:
    """One `more` handle per entity the gather cap truncated (D-051): its
    payload carries the window's oldest instant, so expanding it gathers
    the next window (rows observed at or before it — the boundary instant
    is re-read rather than risk losing rows that share it) and pages on
    until the count says the window was the last. A window that is one
    instant wide steps past it instead of repeating."""
    if not truncated or not page_cursors:
        return []
    handles = []
    for t in truncated:
        if t.reason != "gather_limit":
            continue  # a scope cut is reported, not paged: narrow the scope instead
        cursor = page_cursors.get((t.entity.type, t.entity.key))
        if cursor is None:
            continue
        if page_before is not None and cursor >= _aware(page_before):
            cursor = _aware(page_before) - timedelta(microseconds=1)
        left = max(0, t.total - t.gathered)
        handles.append(ExpansionHandle(
            id=encode_handle(namespace, t.entity, page_predicate, as_of, valid_at,
                             before=cursor, question=question),
            hint=f"{left:,} older observations about {t.entity.type}:{t.entity.key} "
            f"were not examined (observed at or before {cursor.date().isoformat()})",
            est_tokens=min(left, _GATHER_LIMIT) * _FACT_TOKENS_ESTIMATE,
        ))
    return handles
