"""Schema registry semantics (D-024): what a namespace's registration means
for ingest validation and scope expansion. Persistence is the store's job
(`put_schema`/`get_schema`); this module is the pure logic on top.

Domain knowledge lives here as *data* (hard constraint 6): the core never
knows what a "host" or "member_of" is, only that a namespace declared them.

    python -m loomctx.registry draft SAMPLE [--format ...] [--namespace NS] [--out FILE]

drafts a registration from a sample export for review (D-106,
`loomctx.schema_draft`); it never registers anything.
"""

from __future__ import annotations

import re
import time

from .contracts import ClaimIn, EntityRef, SchemaRegistration
from .store.base import GraphStore

_TTL_SECONDS = 5.0


class RegistryCache:
    """Per-process, short-TTL cache so ingest doesn't pay a registry read
    per claim; registrations are rare, ingest is not."""

    def __init__(self, store: GraphStore, ttl: float = _TTL_SECONDS):
        self._store = store
        self._ttl = ttl
        self._cache: dict[str, tuple[float, SchemaRegistration | None]] = {}

    def get(self, namespace: str) -> SchemaRegistration | None:
        now = time.monotonic()
        hit = self._cache.get(namespace)
        if hit is not None and hit[0] > now:
            return hit[1]
        schema = self._store.get_schema(namespace)
        self._cache[namespace] = (now + self._ttl, schema)
        return schema

    def invalidate(self, namespace: str) -> None:
        self._cache.pop(namespace, None)


_LAST_INDEX: tuple = (None, {}, set())


def _index(schema: SchemaRegistration) -> tuple[dict, set[str]]:
    """The registry's predicates by name and its entity type names, kept for
    the last schema seen: a batch validates every claim against the same
    cached registration (D-105), and rebuilding both per claim was most of
    the cost of validating it."""
    global _LAST_INDEX
    last = _LAST_INDEX
    if last[0] is schema:
        return last[1], last[2]
    predicates = {p.name: p for p in schema.predicates}
    types = {t.name for t in schema.entity_types}
    _LAST_INDEX = (schema, predicates, types)
    return predicates, types


def validate_claim(schema: SchemaRegistration | None, claim: ClaimIn) -> str | None:
    """Why this claim violates the namespace's registry, or None if it is
    acceptable. Registered predicates always enforce their object_types;
    `strict` additionally rejects anything unregistered."""
    if schema is None:
        return None
    predicates, types = _index(schema)
    pred = predicates.get(claim.predicate)
    if pred is None:
        if schema.strict:
            return (f"predicate {claim.predicate!r} is not registered in "
                    f"namespace {claim.namespace!r} (strict registry)")
    elif pred.object_types:
        if not isinstance(claim.object, EntityRef):
            return (f"predicate {claim.predicate!r} expects an entity object of "
                    f"type {sorted(pred.object_types)}, got a scalar")
        if claim.object.type not in pred.object_types:
            return (f"predicate {claim.predicate!r} expects an object of type "
                    f"{sorted(pred.object_types)}, got {claim.object.type!r}")
    if schema.strict and types:
        if claim.subject.type not in types:
            return (f"entity type {claim.subject.type!r} is not registered in "
                    f"namespace {claim.namespace!r} (strict registry)")
        if isinstance(claim.object, EntityRef) and claim.object.type not in types:
            return (f"entity type {claim.object.type!r} is not registered in "
                    f"namespace {claim.namespace!r} (strict registry)")
    return None


def containment_predicates(schema: SchemaRegistration | None) -> list[str]:
    """The predicates a scope follows when the caller names none."""
    if schema is None:
        return []
    return sorted(p.name for p in schema.predicates if p.containment)


def _spelling(name: str) -> str:
    """A name with case and separators gone: servicePrincipalName,
    service_principal_name and service-principal-name are one spelling."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _alias_table(defs) -> dict[str, str]:
    """spelling -> the one registered name it can mean: each definition's own
    name respelled and its aliases. A spelling two definitions claim maps
    to neither (a guess would be worse than the unknown-name note)."""
    table: dict[str, str] = {}
    clash: set[str] = set()
    for d in defs:
        for alias in [d.name, *d.aliases]:
            s = _spelling(alias)
            if s in table and table[s] != d.name:
                clash.add(s)
            table.setdefault(s, d.name)
    return {s: n for s, n in table.items() if s not in clash}


def canonical_predicates(schema: SchemaRegistration | None, names: list[str],
                         vocabulary: set[str] | frozenset[str] = frozenset()) -> tuple[list[str], list[str]]:
    """Each name as the namespace's own predicate, and a note per renaming
    (D-116): an agent writing `servicePrincipalName?` or `operatingSystem`
    got 0 rows and no hint. A registered name, or one the data carries
    (`vocabulary`), is kept as is."""
    if schema is None:
        return list(names), []
    known = {p.name for p in schema.predicates} | set(vocabulary)
    table = _alias_table(schema.predicates)
    out, notes = [], []
    for name in names:
        hit = None if name in known else table.get(_spelling(name))
        if hit is not None and hit != name:
            out.append(hit)
            notes.append(f"'{name}' is predicate '{hit}' in namespace '{schema.namespace}'")
        else:
            out.append(name)
    return out, notes


def canonical_type(schema: SchemaRegistration | None, name: str | None) -> tuple[str | None, str | None]:
    """A type as the namespace's own entity type, and a note when renamed
    (D-116): `type="account"` returned 0 rows in 30 AD audit runs."""
    if schema is None or name is None or name in {t.name for t in schema.entity_types}:
        return name, None
    hit = _alias_table(schema.entity_types).get(_spelling(name))
    if hit is None or hit == name:
        return name, None
    return hit, f"type '{name}' is entity type '{hit}' in namespace '{schema.namespace}'"


def lookalike_notes(schema, carried: set[str]) -> list[str]:
    """For each not-collected topic a result's predicates are commonly taken
    for, one line saying they are not it (D-116): 45 local-admin audits had
    seen "local group membership is not collected" and still presented
    has_ace holders (rights over the directory object) as local admins."""
    if schema is None:
        return []
    out = []
    for gap in schema.not_collected:
        hit = sorted(set(gap.mistaken_for) & carried)
        if hit:
            out.append(f"{', '.join(hit)} {'is' if len(hit) == 1 else 'are'} not {gap.topic.replace('_', ' ')}: "
                       f"{gap.description} — not collected"
                       + (f" by {gap.source}" if gap.source else "")
                       + "; do not present these rows as it")
    return out


def with_aliases(schema: SchemaRegistration, predicates: dict[str, list[str]] | None = None,
                 types: dict[str, list[str]] | None = None) -> SchemaRegistration:
    """A connector's registration with the other names its types and
    predicates go by (D-116), kept as data beside the definitions."""
    predicates, types = predicates or {}, types or {}
    return schema.model_copy(update={
        "predicates": [p.model_copy(update={"aliases": list(dict.fromkeys([*p.aliases, *predicates.get(p.name, [])]))})
                       for p in schema.predicates],
        "entity_types": [t.model_copy(update={"aliases": list(dict.fromkeys([*t.aliases, *types.get(t.name, [])]))})
                         for t in schema.entity_types]})

# ---------------------------------------------------------------------- CLI #

def main(argv: list[str] | None = None) -> None:
    """`python -m loomctx.registry draft SAMPLE...`: propose a registration
    from a sample export for a person to review (D-106). Prints the draft and
    its review notes; registers nothing."""
    import argparse
    import sys

    from . import schema_draft

    parser = argparse.ArgumentParser(prog="loomctx.registry", description=main.__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("draft", help="draft a SchemaRegistration from a sample export",
                       description=schema_draft.__doc__,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    d.add_argument("samples", nargs="+", metavar="SAMPLE",
                   help="sample export(s): connector envelope NDJSON, JSON records, "
                        "NDJSON records or LDIF ('-' reads stdin)")
    d.add_argument("--format", default="auto", choices=schema_draft.FORMATS,
                   help="input format (default: from the extension and content)")
    d.add_argument("--namespace", help="namespace of the draft (default: the envelopes' "
                                       "namespace, else 'default')")
    d.add_argument("--out", help="write the draft JSON here instead of stdout")
    d.add_argument("--notes", help="also write the review notes here (they always go to stderr)")
    d.add_argument("--keep-names", action="store_true",
                   help="keep source field names (snake_cased) instead of house-style names")
    args = parser.parse_args(argv)

    try:
        result = schema_draft.draft_files(args.samples, args.format, args.namespace,
                                          args.keep_names)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"loomctx.registry draft: {exc}\n")
    text = result.registration.model_dump_json(indent=2) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    notes = result.notes_text()
    sys.stderr.write(notes)
    if args.notes:
        with open(args.notes, "w", encoding="utf-8") as fh:
            fh.write(notes)


if __name__ == "__main__":
    main()
