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


# common words that are never treated as names, even when an entity happens
# to be keyed by one (a host called "server", a group called "users")
_COMMON = frozenset("""about above access account accounts admin after again against alert alerts also analyst
because been before being below between both cause change changes could credential credentials daily data
during each email entered event events every failed first found from further have having here host hosts
into itself just last later like login logins made many more most never next night none other outbound over
password passwords pending report reports review rotated same scan server servers service should since some
still such than that their them then there these they this those through time today under until user users
very were what when where which while with within without would year""".split())


def _candidates(text: str) -> list[tuple[str, int, bool]]:
    """(token, first offset, plain), in order of first appearance: tokens that
    look like identifiers — a digit or inner punctuation, or all capitals —
    capitalised phrases, and plain words of four or more letters that are not
    common words (`plain`: matched to entity keys only, never to label
    values, so "Monday" cannot name an account by its display name)."""
    seen: dict[str, tuple[int, bool]] = {}
    for m in _TOKEN.finditer(text):
        t = m.group(0)
        if len(t) < 3 or t in seen:
            continue
        if any(c.isdigit() for c in t) or any(c in t for c in "._-@$") or (t.isupper() and len(t) >= 3):
            seen[t] = (m.start(), False)
        elif len(t) >= 4 and t.isalpha() and t.lower() not in _COMMON:
            seen[t] = (m.start(), True)
    for m in _PHRASE.finditer(text):
        t = m.group(0)
        if t not in seen:
            seen[t] = (m.start(), False)
    ranked = sorted(seen.items(), key=lambda kv: (kv[1][1], kv[1][0]))[:_MAX_CANDIDATES]   # identifiers first
    return sorted(((t, o, plain) for t, (o, plain) in ranked), key=lambda x: x[1])


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
    # the types to look a token up as: registered, and any the data carries
    # (a namespace may register predicates only)
    types = list(dict.fromkeys([t.name for t in schema.entity_types]
                               + [row[0] for row in store.relation_summary(ns)]
                               + [row[2] for row in store.relation_summary(ns) if row[2]]))
    types = [t for t in types if t != DOCUMENT]
    labels = [p for p in label_predicates(store, ns) if p != TITLE]
    cands = _candidates(body)
    # entity keys: every candidate as every type, in a few batched lookups
    by_token: dict[str, set[tuple[str, str]]] = {t: set() for t, _, _ in cands}
    refs = [EntityRef(type=ty, key=tok) for tok, _, _ in cands for ty in types]
    for i in range(0, len(refs), 500):
        got = store.resolve_refs(ns, refs[i:i + 500])
        for asked in refs[i:i + 500]:
            r = got.get((asked.type, asked.key))
            if r is not None:
                by_token[asked.key].add((r.type, r.key))
    # label values (a login, a cn, a UPN) for identifier-like tokens and phrases
    for tok, _, plain in cands:
        if by_token[tok] or plain:
            continue
        for p in labels:
            for variant in dict.fromkeys([tok, tok.lower()]):
                for r in store.subjects_with_value(ns, p, json.dumps(variant), _MAX_MATCHES + 1, None):
                    by_token[tok].add((r.type, r.key))
    found: dict[tuple[str, str], tuple[int, str]] = {}      # entity -> (first offset, token)
    for tok, offset, _ in cands:
        hits = by_token[tok]
        if 0 < len(hits) <= _MAX_MATCHES:
            for h in hits:
                if h not in found or offset < found[h][0]:
                    found[h] = (offset, tok)
    doc = EntityRef(type=DOCUMENT, key=artifact.id)
    observed: datetime = artifact.observed_at
    source = f"{artifact.source}{SOURCE_SUFFIX}"
    claims = [ClaimIn(namespace=ns, event_id=f"doctitle:{artifact.id}", subject=doc, predicate=TITLE,
                      object=_title(artifact, body), observed_at=observed, source=source)]
    for (t, k), (offset, token) in found.items():
        if (t, k) == (DOCUMENT, artifact.id):
            continue
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


def relink(store: GraphStore, namespace: str | None = None) -> tuple[int, int]:
    """Link every stored document again (idempotent): a document ingested
    before the entities it names gains its links once they are loaded.
    Returns (documents, links)."""
    docs = links = 0
    for artifact in store.iter_artifacts(namespace):
        if artifact.text:
            docs += 1
            links += link_mentions(store, artifact)
    return docs, links


def main(argv: list[str] | None = None) -> None:
    import argparse

    from .store.factory import store_from_env, store_from_url
    parser = argparse.ArgumentParser(prog="loomctx.mentions", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("relink", help="link every stored document to the entities it names, again")
    cmd.add_argument("--namespace", help="only this namespace (default: all)")
    cmd.add_argument("--db", help="store URL/path (default: LOOMCTX_DB)")
    args = parser.parse_args(argv)
    store = store_from_url(args.db) if args.db else store_from_env()
    try:
        docs, links = relink(store, args.namespace)
    finally:
        store.close()
    print(f"relinked {docs} document(s): {links} mention link(s)")


if __name__ == "__main__":
    main()
