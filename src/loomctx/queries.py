"""Named queries (D-108): the questions a namespace answers exactly, by name.

A connector registers QueryDefs with its schema — "effective_members(group)",
"unconstrained delegation hosts that are not DCs" — each a ListRequest
template. An agent runs one with `run_query` instead of composing the walk
and filters itself: fewer steps, and the same exact, cited ListPage list
mode returns (D-107). Templates are data; nothing here executes code from
a registration.
"""

from __future__ import annotations

from .context import _schema, search_by_name
from .contracts import (
    EntityRef, ListPage, ListRequest, QueryDef, QueryRequest, SchemaRegistration, fill_template,
)
from .listing import list_entities
from .store.base import GraphStore

_SHOWN_MATCHES = 5


class QueryError(ValueError):
    """A named query the caller cannot run as asked: unknown name, a missing
    or ill-typed parameter, an entity name that matches nothing or several."""


def find_query(schema: SchemaRegistration | None, namespace: str, name: str) -> QueryDef:
    queries = {q.name: q for q in (schema.queries if schema is not None else [])}
    if name not in queries:
        known = ", ".join(sorted(queries)) or "none"
        raise QueryError(f"namespace '{namespace}' has no query '{name}' (registered: {known})")
    return queries[name]


def _entity(store: GraphStore, namespace: str, value, entity_type: str | None,
            known_types: set[str], allowed_types) -> str:
    """An entity parameter as a 'type:key' handle: a handle as given, or a
    name resolved through the label predicates (one match, or an error
    naming the candidates)."""
    if isinstance(value, dict):
        return f"{value.get('type')}:{value.get('key')}"
    text = str(value).strip().strip("\"'").strip()
    prefix, sep, rest = text.partition(":")
    if sep and rest and (prefix in known_types or prefix == entity_type
                         or store.resolve_refs(namespace, [EntityRef(type=prefix, key=rest)])):
        if entity_type and prefix != entity_type:
            # a user handle where the query walks a group returns nothing and
            # reads as "no members": say what the parameter takes
            raise QueryError(f"this parameter takes a {entity_type}; {text} is a {prefix}"
                             f" (find_entity with the {entity_type}'s name finds its handle)")
        return text
    types = (entity_type,) if entity_type else None
    if allowed_types is not None:
        types = tuple(t for t in (types or allowed_types) if t in allowed_types)
    found, _ = search_by_name(store, namespace, text, limit=_SHOWN_MATCHES + 1, types=types)
    exact = [e for e in found if e.key.lower() == text.lower()]
    hits = exact if len(exact) == 1 else found
    if len(hits) == 1:
        return f"{hits[0].type}:{hits[0].key}"
    if not hits:
        raise QueryError(f"no {entity_type or 'entity'} named '{text}'; pass a 'type:key' handle "
                         "(find_entity finds one)")
    shown = ", ".join(f"{e.type}:{e.key}" for e in hits[:_SHOWN_MATCHES])
    raise QueryError(f"'{text}' names more than one {entity_type or 'entity'} ({shown}…); "
                     "pass the 'type:key' handle of the one you mean")


def resolve(store: GraphStore, req: QueryRequest, allowed_types=None) -> tuple[QueryDef, ListRequest]:
    """The ListRequest a named query and its parameters spell."""
    schema = _schema(store, req.namespace)
    query = find_query(schema, req.namespace, req.name)
    known_types = {t.name for t in schema.entity_types} if schema is not None else set()
    unknown = sorted(set(req.params) - {p.name for p in query.params})
    if unknown:
        raise QueryError(f"query '{query.name}' takes no parameter {', '.join(unknown)} "
                         f"(it takes: {', '.join(p.name for p in query.params) or 'none'})")
    values: dict = {}
    for p in query.params:
        if p.name not in req.params or req.params[p.name] in (None, ""):
            if p.default is None:
                raise QueryError(f"query '{query.name}' needs parameter '{p.name}'"
                                 + (f": {p.description}" if p.description else ""))
            values[p.name] = p.default
            continue
        v = req.params[p.name]
        try:
            if p.kind == "entity":
                v = _entity(store, req.namespace, v, p.entity_type, known_types, allowed_types)
            elif p.kind == "integer":
                v = int(v)
            elif p.kind == "boolean":
                v = v if isinstance(v, bool) else str(v).strip().lower() in ("true", "1", "yes")
            else:
                v = str(v)
        except ValueError as exc:
            if isinstance(exc, QueryError):
                raise
            raise QueryError(f"parameter '{p.name}' of query '{query.name}' must be {p.kind}") from exc
        values[p.name] = v
    body = fill_template(query.request, values)
    listed = ListRequest.model_validate({
        **body, "namespace": req.namespace, "limit": req.limit, "offset": req.offset,
        "budget": req.budget, "as_of": req.as_of, "valid_at": req.valid_at})
    return query, listed


def run_query(store: GraphStore, req: QueryRequest, allowed_types=None) -> ListPage:
    """Run a namespace's named query: one exact, cited ListPage (D-108)."""
    query, listed = resolve(store, req, allowed_types)
    page = list_entities(store, listed, allowed_types=allowed_types)
    if listed.of is not None:
        page.notes.insert(0, f"{query.name} of {_handle(listed.of)}")
    return page


def _handle(ref: EntityRef) -> str:
    return f"{ref.type}:{ref.key}"
