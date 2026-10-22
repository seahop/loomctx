"""Find documents by their words (D-118). An incident report, an advisory or
a ticket is found by what it says — "phishing", "Kerberos ticket",
"WS-AUDIT01" — with no embedder configured: the store matches query terms
as substrings (`search_artifacts`), and the ranking here weighs each term
by how few of the matching documents hold it. Each hit carries its best
passage, cited to the span, and the entities the document names (its
`mentioned_in` links, D-118), so an agent goes from the document to the
structured facts in one more call."""

from __future__ import annotations

import math
import re

from .context import est_tokens
from .contracts import Citation, DocumentHit, DocumentPage, DocumentSearchRequest, EntityRef
from .mentions import DOCUMENT, MENTIONED_IN, TITLE
from .store.base import GraphStore

_CANDIDATES = 200
_SNIPPET = 320                 # characters around the best-matching place
_STOP = frozenset("""a an and are as at be by can could did do does for from had has have how i if in into
is it its of on or our that the their them then there these they this to was we were what when where which
who whom why will with would you your about any all after before over under than also been being more most
other some such only own same so very just document documents report reports""".split())
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@$-]*[A-Za-z0-9$]|[A-Za-z0-9]")


def terms_of(query: str) -> list[str]:
    """The query's searchable terms: quoted phrases whole, then its words of
    three or more characters that are not stop words, lower-cased."""
    phrases = [p.strip().lower() for p in re.findall(r'"([^"]{3,})"', query)]
    rest = re.sub(r'"[^"]*"', " ", query)
    words = [w.lower() for w in _WORD.findall(rest) if len(w) >= 3 and w.lower() not in _STOP]
    return list(dict.fromkeys(phrases + words))


def _best_window(text: str, terms: list[str]) -> tuple[int, int]:
    """The span of about `_SNIPPET` characters holding the most term hits."""
    low = text.lower()
    hits = sorted((m.start(), t) for t in terms for m in re.finditer(re.escape(t), low))
    if not hits:
        return 0, min(len(text), _SNIPPET)
    best, best_start = -1, hits[0][0]
    for i, (start, _) in enumerate(hits):
        inside = {t for s, t in hits[i:] if s - start <= _SNIPPET}
        if len(inside) > best:
            best, best_start = len(inside), start
    lo = max(0, best_start - _SNIPPET // 4)
    hi = min(len(text), lo + _SNIPPET)
    while lo > 0 and not text[lo - 1].isspace() and best_start - lo < _SNIPPET // 2:
        lo -= 1
    return lo, hi


def search_documents(store: GraphStore, req: DocumentSearchRequest,
                     allowed_types: tuple[str, ...] | None = None) -> DocumentPage:
    page = DocumentPage(namespace=req.namespace, query=req.query)
    if allowed_types is not None and DOCUMENT not in allowed_types:
        page.notes.append("documents are outside this caller's entity types")
        return page
    terms = terms_of(req.query)
    if not terms:
        page.notes.append("the query has no searchable words (three letters or more, not stop words)")
        return page
    found = store.search_artifacts(req.namespace, terms, _CANDIDATES + 1)
    if len(found) > _CANDIDATES:
        found = found[:_CANDIDATES]
        page.notes.append(f"more than {_CANDIDATES} documents hold a query term; ranked among the newest "
                          f"{_CANDIDATES} — add words to narrow")
    page.matched = len(found)
    if not found:
        page.notes.append("no stored document holds any of: " + ", ".join(terms)
                          + " (find_entity searches entity names; ask covers facts)")
        return page
    lows = {a.id: (a.text or "").lower() for a in found}
    df = {t: sum(1 for low in lows.values() if t in low) for t in terms}
    n = len(found)

    def score(a) -> float:
        low = lows[a.id]
        s = 0.0
        for t in terms:
            c = low.count(t)
            if c:
                s += (1 + math.log(c)) * math.log(1 + n / df[t]) * (2.0 if " " in t else 1.0)
        return s

    ranked = sorted(found, key=lambda a: (-score(a), -a.observed_at.timestamp(), a.id))[:req.limit]
    for a in ranked:
        text = a.text or ""
        lo, hi = _best_window(text, terms)
        snippet = ("…" if lo > 0 else "") + text[lo:hi].strip() + ("…" if hi < len(text) else "")
        doc = EntityRef(type=DOCUMENT, key=a.id)
        rows = store.lite_rows(req.namespace, [doc], [MENTIONED_IN, TITLE], side="object", limit=200)
        keys = dict.fromkeys(r.subject for r in rows
                             if r.predicate == MENTIONED_IN and (allowed_types is None or r.subject[0] in allowed_types))
        mentions = [EntityRef(type=t, key=k) for t, k in sorted(keys)]
        titles = store.lite_rows(req.namespace, [doc], [TITLE], side="subject", limit=1)
        hit = DocumentHit(artifact_id=a.id, title=str(titles[0].object) if titles else a.filename,
                          source=a.source, observed_at=a.observed_at, snippet=snippet,
                          citation=Citation(artifact_id=a.id, span_start=lo, span_end=hi, source=a.source,
                                            observed_at=a.observed_at),
                          mentions=mentions, score=round(score(a), 3))
        cost = est_tokens(" ".join([hit.title or "", snippet] + [f"{m.type}:{m.key}" for m in hit.mentions])) + 24
        if page.charged_tokens + cost > req.budget and page.hits:
            page.notes.append(f"{len(ranked) - len(page.hits)} more match(es) did not fit the budget ({req.budget})")
            break
        page.hits.append(hit)
        page.charged_tokens += cost
    return page
