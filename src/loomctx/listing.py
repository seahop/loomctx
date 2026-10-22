"""List mode (D-107): an exact, paged, cited set of entities.

A pack ranks what fits a budget; a question like "which members of Domain
Admins are still enabled?" wants every match and a count, not the
best-scoring few. `list_entities` answers it from set-based, indexed reads
so the work tracks the answer, not the namespace — the same code at 10,000
objects and at 500,000:

  * a positive filter (`eq` / `in` / `exists`) seeds the candidates from
    idx_obs_label — the subjects holding that value;
  * an `of` listing walks `via` edges one index side at a time (a walk up
    from a member never reads a hub group's every inbound edge); with a
    small positive seed the membership is checked upward from the seed
    instead of enumerating the group downward;
  * each filter reads current values either per candidate (an IN-list per
    chunk) or as one scan of the predicate's index range, whichever touches
    fewer rows — the relation summary's counts decide — the most selective
    filter first, so each later one reads fewer entities;
  * the walk and the filters read store LiteRows; only the rows a returned
    page cites are read back as full observations.

The walk follows the scope walk's rules (visible, as_of, valid_at, not
superseded, not extracted, inside allowed_types). Candidates past
LOOMCTX_MAX_LIST_CANDIDATES make the total a lower bound, said in the page.
"""

from __future__ import annotations

import itertools
import json
from collections import defaultdict
from datetime import datetime

from .context import _citation, _close_predicates, _schema, cite_tokens, est_tokens, not_collected_note
from .contracts import MAX_LIST_DEPTH, EntityRef, ListFilter, ListPage, ListRequest, ListRow, PathEdge
from .store import common
from .store.base import GraphStore
from .store.common import LiteRow

_FETCH_CHUNK = 2_000     # candidates whose current values one batched read fetches
_UPWARD_MAX = 5_000      # a positive seed this small checks membership upward
_SCAN_RATIO = 20         # scan a predicate when it holds < this many rows per candidate
_ROW_FRAME = 6           # tokens a row's framing costs beyond its text and cites
_POSITIVE = ("eq", "in", "exists", "contains")
_SELECTIVITY = {"eq": 0, "in": 1, "within": 2, "contains": 3, "exists": 4, "absent": 5, "not_within": 6, "ne": 7}
_CLOSURE = ("within", "not_within")
_RANKED = ("eq", "in", "exists", "absent", "ne")   # ops the store's SQL ranking answers (D-111)

Key = tuple[str, str]


def _key(ref: EntityRef) -> Key:
    return (ref.type, ref.key)


def _ref(k: Key) -> EntityRef:
    return EntityRef(type=k[0], key=k[1])


def _text(value) -> str:
    """The comparable form of a value: case-folded, booleans and integral
    numbers spelled as JSON spells them, an entity as type:key."""
    if isinstance(value, EntityRef):
        return f"{value.type}:{value.key}".lower()
    if isinstance(value, tuple):
        return f"{value[0]}:{value[1]}".lower()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip().lower()


def _same(have, want) -> bool:
    if isinstance(have, tuple) and isinstance(want, str) and ":" not in want:
        return have[1].lower() == want.strip().lower()
    return _text(have) == _text(want)


def _value_jsons(want) -> list[str]:
    """The stored JSON spellings a wanted value may have: an agent writes
    "false" for a boolean and "1" for a number as often as not."""
    out = [json.dumps(want)]
    if isinstance(want, str):
        low = want.strip().lower()
        if low in ("true", "false"):
            out.append(low)
        else:
            for cast in (int, float):
                try:
                    out.append(json.dumps(cast(low)))
                    break
                except ValueError:
                    continue
    elif isinstance(want, (bool, int, float)):
        out.append(json.dumps(_text(want)))
    return list(dict.fromkeys(out))


def _holds(f: ListFilter, current: list) -> bool:
    if f.op == "exists":
        return bool(current)
    if f.op == "absent":
        return not current
    if f.op == "eq":
        return any(_same(v, f.value) for v in current)
    if f.op == "ne":
        return not any(_same(v, f.value) for v in current)
    if f.op == "in":
        wanted = f.value if isinstance(f.value, list) else [f.value]
        return any(_same(v, w) for v in current for w in wanted)
    if f.op == "contains":
        needle = _text(f.value)
        return any(needle in _text(v) for v in current)
    return False


class _Rules:
    """The scope walk's visibility rules over LiteRows (D-107): in the
    caller's types, sender-asserted (not extracted from a document), valid
    at `valid_at`, and not superseded by a visible later row."""

    def __init__(self, allowed_types, valid_at: datetime | None):
        self.allowed = allowed_types
        self.valid_at = common.iso(valid_at)

    def visible(self, r: LiteRow) -> bool:
        if r.extracted:
            return False
        if self.allowed is not None and (r.subject[0] not in self.allowed or (
                isinstance(r.object, tuple) and r.object[0] not in self.allowed)):
            return False
        if self.valid_at is not None and ((r.valid_from is not None and r.valid_from > self.valid_at)
                                          or (r.valid_to is not None and r.valid_to <= self.valid_at)):
            return False
        return True

    @staticmethod
    def retired(rows: list[LiteRow]) -> set[str]:
        """The ids a visible later row in the same set supersedes (D-050)."""
        ids = {r.id for r in rows}
        return {r.supersedes for r in rows if r.supersedes and r.supersedes in ids and r.supersedes != r.id}

    def current(self, rows: list[LiteRow]) -> dict[str, list[LiteRow]]:
        """predicate -> one subject's current rows of it: visible,
        unsuperseded, and observed at the newest instant any such row was
        — one snapshot, so a multi-valued attribute (an account's SPNs)
        keeps every value it last had."""
        mine = [r for r in rows if self.visible(r)]
        gone = self.retired(mine)
        by_pred: dict[str, list[LiteRow]] = defaultdict(list)
        for r in mine:
            if r.id not in gone:
                by_pred[r.predicate].append(r)
        out: dict[str, list[LiteRow]] = {}
        for pred, got in by_pred.items():
            newest = max(r.observed_at for r in got)
            out[pred] = sorted((r for r in got if r.observed_at == newest), key=lambda r: r.id)
        return out


_SIDE = {"in": "object", "out": "subject"}
_REVERSE = {"in": "out", "out": "in", "any": "any"}


def _far(r: LiteRow, node: Key, direction: str) -> Key | None:
    """The other end of edge `r` at `node`, walked in `direction` (in: the
    edge points at node; out: node points along it)."""
    if not isinstance(r.object, tuple):
        return None
    if direction in ("in", "any") and r.object == node and r.subject != node:
        return r.subject
    if direction in ("out", "any") and r.subject == node and r.object != node:
        return r.object
    return None


def _edges(store: GraphStore, req: ListRequest, nodes: list[Key], via: list[str], direction: str,
           limit: int, rules: _Rules) -> dict[Key, list[tuple[LiteRow, Key]]]:
    """node -> its walkable (edge, far end) pairs in `direction`, read from
    the one index side that direction needs (both for `any`)."""
    refs = [_ref(k) for k in nodes]
    sides = [_SIDE[direction]] if direction in _SIDE else ["subject", "object"]
    rows = [r for side in sides
            for r in store.lite_rows(req.namespace, refs, via, side=side, limit=limit, observed_before=req.as_of)]
    rows = list({r.id: r for r in rows if rules.visible(r)}.values())
    gone = rules.retired(rows)
    wanted = set(nodes)
    out: dict[Key, list[tuple[LiteRow, Key]]] = defaultdict(list)
    for r in rows:
        if r.id in gone or not isinstance(r.object, tuple):
            continue
        for node in {r.subject, r.object} & wanted:
            far = _far(r, node, direction)
            if far is not None:
                out[node].append((r, far))
    return out


def _walk_down(store, req, root: Key, via, depth, cap, rules, route: dict) -> tuple[dict[Key, LiteRow], bool]:
    """Every entity within `depth` edges of `root` along `via` in the
    request's direction -> the edge that admitted it; True when the
    candidate cap cut the walk. `route` receives entity -> (hops, the entity
    one step closer to root), and "open" -> how many entities at the last
    depth link onward to entities not listed."""
    members: dict[Key, LiteRow] = {}
    seen = {root}
    frontier = [root]
    for level in range(depth):
        if not frontier:
            break
        nxt: list[Key] = []
        for start in range(0, len(frontier), _FETCH_CHUNK):
            chunk = frontier[start:start + _FETCH_CHUNK]
            adj = _edges(store, req, chunk, via, req.direction, cap + 1, rules)
            for node in chunk:
                for r, far in adj.get(node, ()):
                    if far in seen:
                        continue
                    seen.add(far)
                    members[far] = r
                    route[far] = (level + 1, node)
                    route.setdefault("chains", {})[far] = [r] + route.get("chains", {}).get(node, [])
                    nxt.append(far)
                    if len(members) >= cap:
                        return members, True
        frontier = nxt
    if frontier:   # the depth ran out: do the last entities link on?
        probe = frontier[:_FETCH_CHUNK]
        adj = _edges(store, req, probe, via, req.direction, 50 * len(probe), rules)
        route["open"] = sum(1 for node in probe if any(far not in seen for _, far in adj.get(node, ())))
    return members, False


def _walk_up(store, req, root: Key, seed: list[Key], via, depth, cap, rules,
             route: dict) -> dict[Key, LiteRow | None]:
    """Which of `seed` reach `root` within `depth` edges — walked up from
    them (the reverse direction), so a group holding every account is never
    enumerated: the seed's few memberships are read level by level, with
    the seed entities that arrived at each node carried along."""
    rev = _REVERSE[req.direction]
    reached: dict[Key, set[Key]] = defaultdict(set)
    first: dict[Key, list[tuple[LiteRow, Key]]] = defaultdict(list)
    ups: dict[Key, list[tuple[LiteRow, Key]]] = defaultdict(list)   # node -> its edges toward root
    children: dict[Key, set[Key]] = defaultdict(set)
    cur: dict[Key, set[Key]] = {k: {k} for k in seed}
    for level in range(depth):
        nodes = [k for k in cur if k != root]
        if not nodes:
            break
        nxt: dict[Key, set[Key]] = defaultdict(set)
        for start in range(0, len(nodes), _FETCH_CHUNK):
            chunk = nodes[start:start + _FETCH_CHUNK]
            adj = _edges(store, req, chunk, via, rev, cap + 1, rules)
            for k in chunk:
                for r, far in adj.get(k, ()):
                    if level == 0:
                        first[k].append((r, far))
                    ups[k].append((r, far))
                    children[far].add(k)
                    new = cur[k] - reached[far]
                    if new:
                        reached[far] |= new
                        nxt[far] |= new
                        if far == root:
                            for origin in new:
                                route.setdefault(origin, (level + 1, None))
        cur = nxt
    if cur and any(k != root for k in cur):
        route["open"] = sum(1 for k in cur if k != root)
    # the nodes that lead to root (and how far), so each member cites an edge
    # on its route and, asked, the whole route
    dist = {root: 0}
    queue = [root]
    for node in queue:
        for child in children.get(node, ()):
            if child not in dist:
                dist[child] = dist[node] + 1
                queue.append(child)
    leads = set(dist)
    out = {}
    for k in reached.get(root, ()):
        hop = next(((r, far) for r, far in sorted(first.get(k, ()), key=lambda x: dist.get(x[1], 99))
                    if far in leads), None)
        out[k] = hop[0] if hop else None
        if k in route and hop is not None and hop[1] != root:
            route[k] = (route[k][0], hop[1])
        chain, cur = [], k     # the shortest route, edge by edge
        while cur != root and len(chain) <= depth:
            step = next(((r, far) for r, far in ups.get(cur, ()) if dist.get(far, 99) == dist.get(cur, 99) - 1),
                        None)
            if step is None:
                break
            chain.append(step[0])
            cur = step[1]
        if cur == root:
            route.setdefault("chains", {})[k] = chain
    return out


def _target(store, ns: str, value) -> Key | None:
    """A within filter's entity ('type:key' or {type, key}), canonical."""
    if isinstance(value, dict):
        ref = EntityRef(type=value.get("type", ""), key=value.get("key", ""))
    elif isinstance(value, str) and ":" in value:
        t, _, k = value.strip().strip("\"'").partition(":")
        ref = EntityRef(type=t, key=k)
    else:
        return None
    got = store.resolve_refs(ns, [ref]).get(_key(ref))
    if got is None and ref.key:
        # a name where a handle goes ("group:Domain Admins"): the one entity of
        # that type the label predicates name, as run_query resolves (D-108)
        from .context import search_by_name
        found, _ = search_by_name(store, ns, ref.key, limit=2, types=(ref.type,))
        exact = [e for e in found if e.key.lower() == ref.key.lower()]
        found = exact or found
        if len(found) == 1:
            return (found[0].type, found[0].key)
    return _key(got) if got is not None else None


def _closure(store, req, f: ListFilter, among: list[Key] | None, cap, rules) -> tuple[set[Key], bool]:
    """The entities (of `among`, or all) that reach the filter's entity along
    its predicate within its depth: up from a few candidates, or down from
    the entity — the walk list mode's `of` uses, one index side at a time."""
    target = _target(store, req.namespace, f.value)
    if target is None:
        return set(), False
    sub = req.model_copy(update={"direction": "in"})
    depth = min(f.depth, MAX_LIST_DEPTH)
    via = _walked(f)
    if among is not None and len(among) <= _UPWARD_MAX:
        return set(_walk_up(store, sub, target, among, via, depth, cap, rules, {})), False
    down, cut = _walk_down(store, sub, target, via, depth, cap, rules, {})
    got = set(down)
    return (got & set(among) if among is not None else got), cut


def _seed(store, req, cap) -> tuple[list[Key] | None, bool]:
    """The smallest COMPLETE candidate set an indexed positive filter gives,
    or None when none can seed the listing. A lookup that reached its limit
    is incomplete and never a start set (D-110): `enabled=true` at 500k
    objects hit the 200,001-row limit before the type filter, left 129,098
    users — under the cap, so nothing said "cut" — and the Domain Admins it
    should have found were not among them: an exact-looking 0. Under an
    `of` entity a seed only serves to walk upward, so a lookup stops past
    _UPWARD_MAX: 'principal exists' read 500,000 index rows for the two
    groups nested in Domain Admins."""
    if req.of is not None:
        cap = min(cap, _UPWARD_MAX)
    best: list[Key] | None = None
    for f in sorted(req.where, key=lambda f: _SELECTIVITY[f.op]):
        if f.op not in _POSITIVE or (f.op == "exists" and best is not None):
            continue
        got: dict[Key, None] = {}
        complete = True
        if f.op == "contains":
            # matched inside the stored JSON text (ASCII, quotes and
            # backslashes escaped, Python's quotes respelled), so only a
            # needle spelled the same in both can seed
            needle = _text(f.value)
            if not needle or not needle.isascii() or not needle.isprintable() or any(
                    c in needle for c in "\"'\\"):
                continue
            rows = store.subjects_with_text(req.namespace, f.predicate, needle, cap + 1, req.as_of)
            complete = len(rows) <= cap
            got = {_key(r): None for r in rows if req.type is None or r.type == req.type}
            if complete and (best is None or len(got) < len(best)):
                best = list(got)
            continue
        lookups = [None] if f.op == "exists" else [
            vj for w in (f.value if f.op == "in" and isinstance(f.value, list) else [f.value])
            for vj in _value_jsons(w)]
        for vj in lookups:
            rows = store.subjects_with_value(req.namespace, f.predicate, vj, cap + 1, req.as_of)
            complete = complete and len(rows) <= cap
            for r in rows:
                if req.type is None or r.type == req.type:
                    got.setdefault(_key(r))
        if complete and (best is None or len(got) < len(best)):
            best = list(got)
    return best, False


def _closure_smaller(store, req, seed: list[Key], cap, rules, st: dict) -> bool:
    """Whether the first within filter's closure is the smaller start set than
    a large index seed ("enabled users in Domain Admins": a handful, not the
    enabled accounts); the closure is walked to at most the seed's size."""
    f0 = next(f for f in req.where if f.op == "within")
    if _target(store, req.namespace, f0.value) is None:
        return False
    got, cut = _closure(store, req, f0, None, min(cap, len(seed)), rules)
    smaller = not cut and len(got) < len(seed)
    st["closure_probe"] = len(got)
    return smaller


def _scalar_rows(summary, predicate: str) -> int:
    return sum(n for _, p, ot, n in summary if p == predicate and ot is None)


def list_entities(store: GraphStore, req: ListRequest,
                  allowed_types: tuple[str, ...] | None = None, stats: dict | None = None) -> ListPage:
    """One page of the entities a ListRequest names, exact and cited (D-107).
    `stats`, when given, receives the work counters (for tests)."""
    from .config import max_list_candidates
    from .registry import containment_predicates, lookalike_notes

    ns = req.namespace
    notes: list[str] = []
    cap = max_list_candidates()
    rules = _Rules(allowed_types, req.valid_at)
    schema = _schema(store, ns)
    definitions = list(schema.predicates) if schema is not None else []
    summary = store.relation_summary(ns)
    vocabulary = {p for _, p, _, _ in summary} | {d.name for d in definitions}
    req, renamed = _canonical_request(req, schema, vocabulary)
    notes.extend(renamed)
    page = ListPage(namespace=ns, offset=req.offset)
    st = stats if stats is not None else {}
    st.update(start="", candidates=0, fetched=0, scanned=0)

    asked_unknown: list[str] = []
    suggested: list[str] = []   # unknown names a close match was offered for

    def unknown(name: str, what: str) -> None:
        asked_unknown.append(name)
        close = _close_predicates(name, definitions, vocabulary)
        if close:
            suggested.append(name)
        hint = f"; did you mean {', '.join(close)}?" if close else ""
        notes.append(f"{what} '{name}' is not a predicate in namespace '{ns}'{hint}")

    def done(*more: str) -> ListPage:
        page.notes = notes + list(more)
        return page

    for f in req.where:
        for part in _walked(f) if f.op in _CLOSURE else [f.predicate]:
            if part not in vocabulary:
                unknown(part, "filter")
    for name in req.fields:
        if name not in vocabulary:
            unknown(name, "field")
    if req.type is not None and allowed_types is not None and req.type not in allowed_types:
        return done(f"type '{req.type}' is outside this caller's scope")
    if (req.type is not None and schema is not None and schema.entity_types
            and req.type not in {t.name for t in schema.entity_types}
            and not store.entity_refs_of_type(ns, req.type, 1)):
        # `type="account"` read as an empty set in 30 audit runs (D-116)
        types = sorted(t.name for t in schema.entity_types
                       if allowed_types is None or t.name in allowed_types)
        return done(f"type '{req.type}' is not an entity type in namespace '{ns}' and nothing is "
                    f"recorded as one; its types are: {', '.join(types)}")
    depth = min(req.depth, MAX_LIST_DEPTH)
    if req.depth > depth:
        notes.append(f"depth {req.depth} exceeds the cap; clamped to {depth}")

    # ---------------------------------------------------------- candidates
    seed, cut = _seed(store, req, cap)
    admitted: dict[Key, LiteRow | None] = {}
    root_ref: EntityRef | None = None
    via: list[str] = []
    route: dict = {}   # entity -> (hops, the entity one step closer to `of`); "open" -> onward links
    if req.of is not None:
        root_ref = store.resolve_refs(ns, [req.of]).get(_key(req.of))
        if root_ref is None:
            # a name where the handle goes ("user:mreyes@corp.local" for a
            # SID-keyed account): Gemini 2.5 Flash took "not on record" as the
            # answer in four groups runs of five (full run, 500k)
            named = _target(store, ns, {"type": req.of.type, "key": req.of.key})
            if named is not None:
                root_ref = _ref(named)
                notes.append(f"'{req.of.type}:{req.of.key}' is {named[0]}:{named[1]} (matched by name)")
        if root_ref is None or (allowed_types is not None and root_ref.type not in allowed_types):
            return done(f"entity '{req.of.type}:{req.of.key}' is not on record, by handle or by name; "
                        "find_entity resolves a name to its handle")
        via = list(dict.fromkeys(req.via)) or containment_predicates(schema)
        if not via:
            return done("no `via` predicates named and none registered as containment; "
                        "name the edge to walk (member_of, runs_software…)")
        for p in via:
            if p not in vocabulary:
                unknown(p, "via")
        root = _key(root_ref)
        closure_seed = None
        if seed is None and any(f.op == "within" for f in req.where):
            # "admins with rights over WS-1": the admins (a group's closure,
            # usually a handful) walk up to the machine — never the machine's
            # trustees down, which at 500k objects can be Domain Users
            f0 = next(f for f in req.where if f.op == "within")
            if _target(store, ns, f0.value) is not None:
                got, closure_cut = _closure(store, req, f0, None, cap, rules)
                if len(got) <= _UPWARD_MAX and not closure_cut:
                    seed = [k for k in got if req.type is None or k[0] == req.type]
                    closure_seed = f0
        if seed is not None and len(seed) <= _UPWARD_MAX and not cut:
            admitted = _walk_up(store, req, root, seed, via, depth, cap, rules, route)
            st["start"] = "upward"
            st["seeded_by_closure"] = closure_seed is not None
        else:
            down, walk_cut = _walk_down(store, req, root, via, depth, cap, rules, route)
            cut = cut or walk_cut
            keep_only = set(seed) if seed is not None else None
            admitted = {k: r for k, r in down.items() if keep_only is None or k in keep_only}
            st["start"] = "downward"
        candidates = list(admitted)
    elif seed is not None and not (len(seed) > _UPWARD_MAX and any(f.op == "within" for f in req.where)
                                   and _closure_smaller(store, req, seed, cap, rules, st)):
        candidates = seed
        st["start"] = "index"
    elif any(f.op == "within" for f in req.where):
        # "users in Domain Admins, nested": the group's closure is the start set
        f0 = next(f for f in req.where if f.op == "within")
        if _target(store, ns, f0.value) is None:
            return done(f"within {f0.predicate}: entity {f0.value!r} is not on record")
        got, cut = _closure(store, req, f0, None, cap, rules)
        candidates = [k for k in got if req.type is None or k[0] == req.type]
        st["start"] = "closure"
    elif req.type is not None:
        candidates = [_key(r) for r in store.entity_refs_of_type(ns, req.type, cap + 1)]
        cut = len(candidates) > cap
        candidates = candidates[:cap]
        st["start"] = "type"
    else:
        return done("name a `type`, an `of` entity, or an eq / in / exists filter to list from")
    candidates = sorted(k for k in candidates if (req.type is None or k[0] == req.type)
                        and (allowed_types is None or k[0] in allowed_types))
    st["candidates"] = len(candidates)

    # ------------------------------------------------------------- filters
    # the most selective first, each over the survivors of the last; the
    # rows a filter read are kept for the row's values and cites
    current: dict[Key, dict[str, list[LiteRow]]] = defaultdict(dict)
    alive = candidates
    unrecorded: dict[str, int] = defaultdict(int)   # ne filter -> candidates with no value on record

    def keep(k: Key, f: ListFilter, cur: dict[str, list[LiteRow]], out: list[Key]) -> None:
        if _holds(f, [r.object for r in cur.get(f.predicate, ())]):
            out.append(k)
            if cur.get(f.predicate):
                current[k][f.predicate] = cur[f.predicate]
            elif f.op == "ne":
                unrecorded[f.predicate] += 1

    for f in sorted(req.where, key=lambda f: _SELECTIVITY[f.op]):
        survivors: list[Key] = []
        if f.op in _CLOSURE:
            if (st.get("start") == "closure" or st.get("seeded_by_closure")) and \
                    f is next(x for x in req.where if x.op == "within"):
                continue   # the start set is this closure already
            if _target(store, ns, f.value) is None:
                notes.append(f"{f.op} {f.predicate}: entity {f.value!r} is not on record")
                alive = alive if f.op == "not_within" else []
                continue
            inside, closure_cut = _closure(store, req, f, alive, cap, rules)
            cut = cut or closure_cut
            alive = [k for k in alive if (k in inside) == (f.op == "within")]
            continue
        if (len(alive) > _FETCH_CHUNK and f.op in _RANKED and allowed_types is None
                and _scalar_rows(summary, f.predicate) < _SCAN_RATIO * len(alive)):
            # the newest value per subject ranked in SQL, only keys back (D-111)
            vjs = None if f.op in ("exists", "absent") else [
                vj for w in (f.value if isinstance(f.value, list) else [f.value]) for vj in _value_jsons(w)]
            have, match = store.current_scalar_subjects(ns, f.predicate, vjs, req.as_of, req.valid_at)
            st["ranked"] = st.get("ranked", 0) + len(alive)
            for k in alive:
                if f.op in ("eq", "in"):
                    ok = k in match
                elif f.op == "exists":
                    ok = k in have
                elif f.op == "absent":
                    ok = k not in have
                else:   # ne
                    ok = k not in match
                    if ok and k not in have:
                        unrecorded[f.predicate] += 1
                if ok:
                    survivors.append(k)
        elif len(alive) > _FETCH_CHUNK and _scalar_rows(summary, f.predicate) < _SCAN_RATIO * len(alive):
            # one index range beats a lookup per candidate
            wanted = set(alive)
            seen: set[Key] = set()
            for subject, rows in itertools.groupby(store.lite_scalars(ns, f.predicate, req.as_of),
                                                   key=lambda r: r.subject):
                if subject in wanted:
                    seen.add(subject)
                    keep(subject, f, rules.current(list(rows)), survivors)
                else:
                    st["scanned"] += sum(1 for _ in rows)
            for k in alive:                    # candidates with no row at all
                if k not in seen:
                    keep(k, f, {}, survivors)
            survivors.sort()
        else:
            for start in range(0, len(alive), _FETCH_CHUNK):
                chunk = alive[start:start + _FETCH_CHUNK]
                by: dict[Key, list[LiteRow]] = defaultdict(list)
                for r in store.lite_rows(ns, [_ref(k) for k in chunk], [f.predicate], side="subject",
                                         observed_before=req.as_of):
                    by[r.subject].append(r)
                st["fetched"] += len(chunk)
                for k in chunk:
                    keep(k, f, rules.current(by.get(k, [])), survivors)
        alive = survivors
    if unrecorded:
        notes.extend(_unrecorded_notes(store, ns, req.as_of, unrecorded))
    page.total = len(alive)
    page.exact = not cut
    if cut:
        notes.append(f"the candidate walk stopped at LOOMCTX_MAX_LIST_CANDIDATES ({cap:,}); the total is a "
                     "lower bound — narrow with `type`, a positive filter, or a smaller `depth`")

    # --------------------------------------------------------------- page
    window = alive[req.offset:req.offset + req.limit]
    labels = ([d.name for d in definitions if d.display]
              + [d.name for d in definitions if d.label and not d.display])
    filtered = {f.predicate for f in req.where if f.op not in _CLOSURE}
    missing = [p for p in filtered if any(p not in current.get(k, {}) for k in window)]
    extra = list(dict.fromkeys([p for p in req.fields if p not in filtered] + labels + missing))
    if window and extra:
        by = defaultdict(list)
        for r in store.lite_rows(ns, [_ref(k) for k in window], extra, side="subject", observed_before=req.as_of):
            by[r.subject].append(r)
        for k in window:
            for pred, got in rules.current(by.get(k, [])).items():
                current[k].setdefault(pred, got)
    shown = list(dict.fromkeys([f.predicate for f in req.where if f.op not in _CLOSURE] + list(req.fields)))
    plan: dict[Key, tuple[str | None, list[str], list[str]]] = {}   # name, value preds, cited ids
    for k in window:
        mine = current.get(k, {})
        name_pred = next((p for p in labels if mine.get(p)), None)
        cited = [admitted[k].id] if admitted.get(k) is not None else []
        cited += [r.id for p in shown for r in mine.get(p, ())]
        if name_pred is not None:
            cited.append(mine[name_pred][0].id)
        plan[k] = (str(mine[name_pred][0].object) if name_pred else None,
                   [p for p in shown if mine.get(p)], list(dict.fromkeys(cited)))
    # an entity listed by type alone is cited by its newest row, so every
    # row carries evidence (hard constraint 3)
    bare = [k for k in window if not plan[k][2]]
    if bare:
        newest = store.observations_for_many(ns, [_ref(k) for k in bare], limit=1,
                                             observed_before=req.as_of, side="subject")
        for k in bare:
            plan[k][2].extend(o.id for o in newest.get(k, []) if rules.allowed is None
                              or o.subject.type in rules.allowed)
    chains = route.get("chains", {}) if (req.paths and req.of is not None) else {}
    chain_ids = [r.id for k in window for r in chains.get(k, [])]
    full = {o.id: o for o in store.observations_by_ids(ns, list(dict.fromkeys(
        [i for k in window for i in plan[k][2]] + chain_ids)))}
    charged = 0
    for k in window:
        name, preds, ids = plan[k]
        mine = current.get(k, {})
        values = {p: _value(mine[p]) for p in preds}
        hops, closer = route.get(k, (None, None))
        path = [_path_edge(full[r.id]) for r in chains.get(k, []) if r.id in full]
        row = ListRow(entity=_ref(k), name=name, values=values,
                      cites=[_citation(full[i]) for i in ids if i in full],
                      hops=hops, through=_ref(closer) if closer is not None and hops and hops > 1 else None,
                      path=path)
        text = " ".join([f"{k[0]}:{k[1]}"] + ([name] if name else [])
                        + [f"{p}={json.dumps(v, default=str)}" for p, v in values.items()]
                        + [f"{e.subject.key} {e.predicate} {_end_text(e.object)}" for e in path])
        cost = (est_tokens(text) + _ROW_FRAME + sum(cite_tokens(c) for c in row.cites)
                + sum(cite_tokens(e.cite) for e in path))
        if charged + cost > req.budget:
            if not page.rows:
                notes.append(f"the budget ({req.budget}) does not fit one row; raise budget")
            break
        page.rows.append(row)
        charged += cost
    gap = _gap_note(store, ns, req, root_ref if req.of is not None else None, via if req.of is not None else [])
    if gap:
        notes.insert(0, gap)
    if not alive and req.as_of is not None:
        first = store.first_observed(ns)
        if first is not None and common.iso(req.as_of) < common.iso(first):
            notes.append(f"as_of {common.iso(req.as_of)} is before anything in namespace {ns!r} was observed "
                         f"(the earliest observation is {common.iso(first)}): nothing was known then")
    if req.of is not None and route.get("open"):
        notes.append(f"the walk stopped at depth {depth}: {route['open']} entit"
                     f"{'y' if route['open'] == 1 else 'ies'} at that depth link onward along "
                     f"{', '.join(via)} to entities not listed (depth may be up to {MAX_LIST_DEPTH})")
    if req.of is not None and not admitted and req.direction in _SIDE:
        other = "out" if req.direction == "in" else "in"
        if store.lite_rows(ns, [root_ref], via, side=_SIDE[other], limit=1, observed_before=req.as_of):
            notes.append(f"direction={req.direction!r} lists entities whose {', '.join(via)} edge "
                         + ("points at " if req.direction == "in" else "starts from ")
                         + f"{req.of.type}:{req.of.key}; there are none. It has {', '.join(via)} edges "
                         f"the other way (direction={other!r})")
    page.charged_tokens = charged
    end = req.offset + len(page.rows)
    page.next_offset = end if end < len(alive) else None
    if page.rows and len(page.rows) < len(window):
        notes.append(f"{len(window) - len(page.rows)} row(s) of this page did not fit the token budget; "
                     f"continue from offset {end}")
    elif page.next_offset is not None:
        notes.append(f"{len(alive) - end} more match(es) past this page: call again with offset={end}")
    if not alive and asked_unknown:
        # an empty answer to a predicate the namespace does not have — what
        # its sources declare they do not carry may be what was asked (D-110);
        # every topic only when no close predicate was offered: the whole list
        # beside "did you mean spn" told an agent Kerberoasting was unknowable
        nc = not_collected_note(store, ns, " ".join(asked_unknown).replace("_", " "),
                                fallback_all=len(suggested) < len(asked_unknown))
        if nc:
            notes.append(nc)
    if not alive and not asked_unknown:
        notes.extend(_empty_value_notes(store, ns, req))
    carried = set(via) | {f.predicate for f in req.where if f.op not in _CLOSURE} | set(req.fields) \
        | {p for f in req.where if f.op in _CLOSURE for p in _walked(f)} \
        | {e.predicate for r in page.rows for e in r.path}
    notes.extend(lookalike_notes(schema, carried))
    if req.of is not None and admitted:
        member = _membership_note(store, ns, req, schema, via, list(admitted))
        if member:
            notes.append(member)
    return done()


def _walked(f: ListFilter) -> list[str]:
    """A within filter's edge predicates: one, or a comma-separated mix
    walked together (D-116: 'has_ace,member_of' within computer:X)."""
    return [p.strip() for p in f.predicate.split(",") if p.strip()]


def _canonical_request(req: ListRequest, schema, vocabulary) -> tuple[ListRequest, list[str]]:
    """The request in the namespace's own names (D-116): a type alias
    ('account' -> 'user'), predicate aliases in filters, fields and via
    (servicePrincipalName -> spn), each renaming noted."""
    from .registry import canonical_predicates, canonical_type
    notes: list[str] = []
    typ, note = canonical_type(schema, req.type)
    if note:
        notes.append(note)

    def names(items: list[str]) -> list[str]:
        out, said = canonical_predicates(schema, items, vocabulary)
        notes.extend(n for n in said if n not in notes)
        return out

    where = []
    for f in req.where:
        if f.op in _CLOSURE:
            where.append(f.model_copy(update={"predicate": ",".join(names(_walked(f)))}))
        else:
            where.append(f.model_copy(update={"predicate": names([f.predicate])[0]}))
    return req.model_copy(update={"type": typ, "where": where, "fields": names(list(req.fields)),
                                  "via": names(list(req.via))}), notes


def _membership_note(store, ns: str, req: ListRequest, schema, via: list[str], admitted: list[Key]) -> str | None:
    """A walk over a permission edge alone lists the groups that hold it, not
    their members (D-116): agents walked has_ace without member_of and missed
    the admin who holds rights through a group. Says how many listed
    entities are groups others belong to, and what to add."""
    from .registry import containment_predicates
    contain = [p for p in containment_predicates(schema) if p not in via]
    if not contain or set(via) & set(containment_predicates(schema)):
        return None
    probe = admitted[:_FETCH_CHUNK]
    rows = store.lite_rows(ns, [_ref(k) for k in probe], contain, side="object", limit=50 * len(probe),
                           observed_before=req.as_of)
    holders = {r.object for r in rows if isinstance(r.object, tuple) and r.object in set(probe)}
    if not holders:
        return None
    more = "+" if len(admitted) > len(probe) else ""
    return (f"{len(holders)}{more} of the entities reached have members ({', '.join(contain)} points at "
            f"them): their members reach {req.of.type}:{req.of.key} too but are not listed — add "
            f"{', '.join(contain)} to via (depth 2 or more), or filter with "
            f"'{','.join([*via, *contain])}' within {req.of.type}:{req.of.key}")


def _empty_value_notes(store, ns: str, req: ListRequest) -> list[str]:
    """For an empty listing, each eq / in filter whose value no entity
    carries, with values that are on record (D-116): `enabled=yes` and
    `os=Windows 10` returned 0 rows and nothing said the value was the
    reason."""
    out = []
    for f in req.where:
        if f.op not in ("eq", "in"):
            continue
        wanted = f.value if isinstance(f.value, list) else [f.value]
        if any(store.subjects_with_value(ns, f.predicate, vj, 1, req.as_of)
               for w in wanted for vj in _value_jsons(w)):
            continue
        sample: dict[str, str] = {}   # compared form -> as recorded
        for r in itertools.islice(store.lite_scalars(ns, f.predicate, req.as_of), 2000):
            sample.setdefault(_text(r.object), json.dumps(r.object, default=str).strip('"'))
            if len(sample) >= 6:
                break
        if sample:
            out.append(f"no entity has {f.predicate} = {', '.join(map(str, wanted))}; values on record "
                       f"include: {', '.join(sample.values())}")
    return out


def _gap_note(store, ns: str, req: ListRequest, root: EntityRef | None, via: list[str]) -> str | None:
    """The collection gaps behind what a listing could not include, as packs
    note them (D-082, D-092): an empty `account_groups` for an account whose
    domain's membership was never exported read as "no groups" to the
    agents (the final A/B's coverage audit). An `of` listing notes gaps on
    the predicates it walked from the sources that supplied `of`; a type or
    filter listing, gaps on the predicates its filters name, for the types
    the gap applies to. A `ne` filter's absences are said by
    `_unrecorded_notes`."""
    from . import coverage
    preds = set(via) | {f.predicate for f in req.where if f.op != "ne"}
    if not preds:
        return None
    # the entities the listing is about — `of`, or an entity a filter names
    # (member_of=user:X) — scope the gaps to the sources that supplied them
    about = [root] if root is not None else _filter_entities(store, ns, req)
    sources = {o.source for ref in about
               for o in store.observations_for(ns, ref, 200, observed_before=req.as_of)}
    kinds = {root.type} if root is not None else ({req.type} if req.type else set())
    found = [g for g in coverage.gaps(store, ns, preds, req.as_of)
             if (not sources or g.source in sources) and (not g.types or not kinds or kinds & set(g.types))]
    return coverage.note(found, "an entity this listing does not include may be missing data, not absent")


def _filter_entities(store, ns: str, req: ListRequest) -> list[EntityRef]:
    """The entities `where` values name as 'type:key' handles, resolved."""
    wanted = []
    for f in req.where:
        for v in (f.value if isinstance(f.value, list) else [f.value]):
            if isinstance(v, str) and ":" in v:
                t, _, k = v.partition(":")
                wanted.append(EntityRef(type=t, key=k))
    return list(store.resolve_refs(ns, wanted).values()) if wanted else []


def _unrecorded_notes(store, ns: str, as_of, unrecorded: dict[str, int]) -> list[str]:
    """What an `ne` match with no value on record means, per predicate: a
    collector that sets a flag only when it holds (LDAP's is_dc,
    unconstrained_delegation) and records the predicate as fully collected
    makes absence "not set"; a partial or absent collection makes it
    unknown — said with the coverage record to cite, bracketed as every
    coverage note writes it (D-092, D-107)."""
    from . import coverage
    recs = coverage.records(store, ns, as_of)
    out = []
    for pred, n in sorted(unrecorded.items()):
        lead = f"{n} candidate entit{'y has' if n == 1 else 'ies have'} no {pred} value on record"
        mine = [r for r in recs if str(r.object) == pred]
        gaps = [r for r in mine if r.attrs.get("state") in ("absent", "partial")]
        if gaps:
            out.append(f"{lead}: {pred} was not fully collected (coverage [{gaps[0].id[:12]}]), so for them "
                       "it is unknown, not a different value")
        elif mine:
            out.append(f"{lead}; coverage [{mine[0].id[:12]}] records {pred} as collected, so it is not set "
                       "on them")
        else:
            out.append(f"{lead} (counted as not equal)")
    return out


def _end_text(end) -> str:
    return f"{end.type}:{end.key}" if isinstance(end, EntityRef) else str(end)


def _path_edge(o) -> PathEdge:
    return PathEdge(subject=o.subject, predicate=o.predicate, object=o.object, cite=_citation(o),
                    valid_from=o.valid_from, valid_to=o.valid_to, source=o.source)


def _value(rows: list[LiteRow]):
    """A current value as a row shows it: the scalar or entity, or — for a
    multi-valued snapshot — its values joined (every one stays cited)."""
    vals = [EntityRef(type=r.object[0], key=r.object[1]) if isinstance(r.object, tuple) else r.object
            for r in rows]
    if len(vals) == 1:
        return vals[0]
    return ", ".join(f"{v.type}:{v.key}" if isinstance(v, EntityRef) else str(v) for v in vals)
