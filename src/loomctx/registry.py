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


def validate_claim(schema: SchemaRegistration | None, claim: ClaimIn) -> str | None:
    """Why this claim violates the namespace's registry, or None if it is
    acceptable. Registered predicates always enforce their object_types;
    `strict` additionally rejects anything unregistered."""
    if schema is None:
        return None
    predicates = {p.name: p for p in schema.predicates}
    types = {t.name for t in schema.entity_types}
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
