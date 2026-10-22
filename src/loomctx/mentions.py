"""Which known entities a document names (D-118): the deterministic bridge
between unstructured and structured data. No LLM: the document's
identifier-like tokens (account names, hostnames, CVE ids, group names) are
looked up as entity keys and as label values (sAMAccountName, cn, a UPN),
and each entity found gets one cited fact,

    user:S-1-5-21-…-95320  mentioned_in  document:<artifact id>

whose provenance is the span where the document first names it. The fact is
an ordinary observation, so a pack about the account carries it, a listing
of the document's `mentioned_in` edges names everything in it, and find_path
can cross it. Claim extraction (an LLM in the enrichment worker) still mines
what the document SAYS about those entities; this only records that it
names them.

Runs at ingest, idempotent by event id; a namespace in strict mode that
does not register `mentioned_in` gets no links (the registry decides)."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime

from .contracts import (
    Artifact, ClaimIn, EntityRef, EntityTypeDef, PredicateDef, Provenance, SchemaRegistration,
)
from .registry import validate_claim
from .store.base import GraphStore
from .store.common import merge_schema

log = logging.getLogger(__name__)

MENTIONED_IN = "mentioned_in"
DOCUMENT = "document"
TITLE = "title"
SOURCE_SUFFIX = ":mentions"

_MAX_SCAN_CHARS = 200_000     # the first part of a very long document
_MAX_CANDIDATES = 400
_MAX_MATCHES = 2              # a token naming more entities than this is too vague to link
# identifier-like tokens: letters/digits with inner . _ - @ $ (WS-AUDIT01, adm-rlopez,
# svc-sqladm@corp.local, CVE-2026-0544, 10.0.4.7); trailing punctuation excluded
_TOKEN = re.compile(r"(?<![\w@$.-])[A-Za-z0-9][A-Za-z0-9._@$-]*[A-Za-z0-9$](?![\w@$-])")
# capitalised names of two or three words (Domain Admins, Enterprise Key Admins)
_PHRASE = re.compile(r"\b[A-Z][\w-]*(?:\s+[A-Z][\w-]*){1,2}\b")
_PLAIN_WORD = re.compile(r"^[A-Za-z][a-z]+$")


def _candidates(text: str) -> list[tuple[str, int]]:
    """(token, first offset), in order of first appearance: tokens that look
    like identifiers — a digit or inner punctuation, or all capitals — and
    capitalised phrases. A plain word ("server", "Monday") is never one."""
    seen: dict[str, int] = {}
    for m in _TOKEN.finditer(text):
        t = m.group(0)
        if len(t) < 3 or t in seen:
            continue
        if any(c.isdigit() for c in t) or any(c in t for c in "._-@$") or (t.isupper() and len(t) >= 3):
            seen[t] = m.start()
    for m in _PHRASE.finditer(text):
        t = m.group(0)
        if t not in seen:
            seen[t] = m.start()
    return sorted(seen.items(), key=lambda kv: kv[1])[:_MAX_CANDIDATES]


def _title(artifact: Artifact, text: str) -> str:
    attrs = artifact.attrs or {}
    for key in ("title", "subject", "name"):
        if isinstance(attrs.get(key), str) and attrs[key].strip():
            return attrs[key].strip()[:200]
    first = next((ln.strip().lstrip("#").strip() for ln in text.splitlines() if ln.strip()), "")
    return (first or artifact.filename or artifact.id)[:200]


_REGISTERED: set[tuple[int, str]] = set()


def _ensure_schema(store: GraphStore, namespace: str) -> SchemaRegistration:
    """The document type, `mentioned_in` and a `title` label, merged into the
    namespace's registry once per store and namespace (additive, D-083):
    documents are a core concept, and the label makes a document findable
    by its title."""
    schema = store.get_schema(namespace)
    if (id(store), namespace) in _REGISTERED and schema is not None:
        return schema
    have = {p.name for p in schema.predicates} if schema is not None else set()
    if MENTIONED_IN not in have or TITLE not in have:
        schema = merge_schema(schema, SchemaRegistration(
            namespace=namespace, strict=schema.strict if schema is not None else False,
            entity_types=[EntityTypeDef(name=DOCUMENT, description="a stored document (an artifact)",
                                        aliases=["doc", "report", "artifact"])],
            predicates=[PredicateDef(name=MENTIONED_IN, object_types=[DOCUMENT],
                                     description="the document names this entity (a deterministic "
                                                 "mention link, cited to the span; D-118)",
                                     aliases=["mentioned_by", "named_in", "appears_in", "mentions"]),
                        PredicateDef(name=TITLE, label=True,
                                     description="a document's title (its first line or filename)")]))
        store.put_schema(schema)
    _REGISTERED.add((id(store), namespace))
    return schema


def link_mentions(store: GraphStore, artifact: Artifact, text: str | None = None) -> int:
    """Record a cited `mentioned_in` fact for each known entity the document
    names, and its title; returns how many entities were linked."""
    from .context import label_predicates
    body = text if text is not None else artifact.text
    if not body or not body.strip():
        return 0
    body = body[:_MAX_SCAN_CHARS]
    ns = artifact.namespace
    schema = _ensure_schema(store, ns)
    types = [t.name for t in schema.entity_types if t.name != DOCUMENT]
    labels = [p for p in label_predicates(store, ns) if p != TITLE]
    found: dict[tuple[str, str], int] = {}      # entity -> offset of the first mention
    for token, offset in _candidates(body):
        hits: set[tuple[str, str]] = set()
        if types:
            got = store.resolve_refs(ns, [EntityRef(type=t, key=token) for t in types])
            hits |= {(r.type, r.key) for r in got.values() if r is not None}
        if not hits and not _PLAIN_WORD.match(token):
            for p in labels:
                for variant in dict.fromkeys([token, token.lower()]):
                    for r in store.subjects_with_value(ns, p, json.dumps(variant), _MAX_MATCHES + 1, None):
                        hits.add((r.type, r.key))
        if 0 < len(hits) <= _MAX_MATCHES:
            for h in hits:
                found.setdefault(h, offset)
    doc = EntityRef(type=DOCUMENT, key=artifact.id)
    observed: datetime = artifact.observed_at
    source = f"{artifact.source}{SOURCE_SUFFIX}"
    claims = [ClaimIn(namespace=ns, event_id=f"doctitle:{artifact.id}", subject=doc, predicate=TITLE,
                      object=_title(artifact, body), observed_at=observed, source=source)]
    for (t, k), offset in found.items():
        if (t, k) == (DOCUMENT, artifact.id):
            continue
        token = next((c for c, o in _candidates(body) if o == offset), "")
        digest = hashlib.sha1(f"{artifact.id}|{t}|{k}".encode()).hexdigest()[:32]
        claims.append(ClaimIn(
            namespace=ns, event_id=f"mention:{digest}", subject=EntityRef(type=t, key=k),
            predicate=MENTIONED_IN, object=doc, observed_at=observed, source=source,
            provenance=Provenance(artifact_id=artifact.id, span_start=offset,
                                  span_end=offset + len(token) if token else None),
            attrs={"mention": True}))
    kept = []
    for c in claims:
        problem = validate_claim(schema, c)
        if problem is None:
            kept.append(c)
        else:
            log.info("document %s: mention link not recorded: %s", artifact.id, problem)
    if kept:
        store.record_claims(kept)
    return sum(1 for c in kept if c.predicate == MENTIONED_IN)


def link_quietly(store: GraphStore, artifact: Artifact, text: str | None = None) -> int:
    """`link_mentions` for an ingest path: a failure is logged, never raised —
    the document is stored either way, and the enrichment pass retries."""
    try:
        return link_mentions(store, artifact, text)
    except Exception:   # noqa: BLE001 — linking is an enrichment, not part of the write
        log.exception("document %s: mention linking failed", artifact.id)
        return 0
