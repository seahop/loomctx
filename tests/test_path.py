"""The `path` answer type (D-067): a bounded, shortest-first BFS that
enumerates the edge sequence(s) connecting two entities along named
predicates. Domain-agnostic, cited, time-scoped, honestly capped. Every path
here is built on a synthetic SqliteStore (no embedder — find_paths does not
rank) except the seed integration at the end."""

from datetime import datetime, timezone

from loom.context import find_paths
from loom.contracts import ClaimIn, EntityRef, PathRequest, SchemaRegistration, PredicateDef
from loom.store.sqlite import SqliteStore


def _at(day, hour=12):
    return datetime(2026, 8, day, hour, tzinfo=timezone.utc)


def _edge(store, ns, subj, obj, pred="link", day=1, source="graph", **kw):
    return store.record_claim(ClaimIn(
        namespace=ns, subject=EntityRef(type=subj[0], key=subj[1]),
        predicate=pred, object=EntityRef(type=obj[0], key=obj[1]),
        observed_at=_at(day, 0), source=source, **kw))


def _req(**kw):
    kw.setdefault("namespace", "net")
    return PathRequest(**kw)


def _n(key):
    return EntityRef(type="n", key=key)


# --------------------------------------------------------------- found + cited #

def test_three_hop_path_found_and_fully_cited(tmp_path):
    store = SqliteStore(tmp_path / "p.db")
    _edge(store, "net", ("n", "a"), ("n", "b"))
    _edge(store, "net", ("n", "b"), ("n", "c"))
    _edge(store, "net", ("n", "c"), ("n", "d"))
    pack = find_paths(store, _req(**{"from": _n("a")}, to=_n("d"), via=["link"], depth=3))
    assert len(pack.paths) == 1
    path = pack.paths[0]
    assert [e.predicate for e in path] == ["link", "link", "link"]
    # the edge sequence connects a -> b -> c -> d, each edge stored as recorded
    assert [(e.subject.key, e.object.key) for e in path] == [("a", "b"), ("b", "c"), ("c", "d")]
    # every hop is cited (hard constraint 3) and time-scoped
    assert all(e.cite.observation_id for e in path)
    assert pack.charged_tokens > 0
    assert pack.from_ == _n("a") and pack.to == _n("d")
    store.close()


def test_reversible_edge_is_walked_backwards(tmp_path):
    """`affects` is cve->product but the question walks product->cve — the
    walk follows an edge in both directions, mirroring the scope walk."""
    store = SqliteStore(tmp_path / "rev.db")
    # stored cve -affects-> product, but we ask product -> cve
    store.record_claim(ClaimIn(namespace="net", subject=EntityRef(type="cve", key="CVE-1"),
                               predicate="affects", object=EntityRef(type="product", key="nginx"),
                               observed_at=_at(1), source="nvd"))
    pack = find_paths(store, _req(**{"from": EntityRef(type="product", key="nginx")},
                                  to=EntityRef(type="cve", key="CVE-1"), via=["affects"], depth=1))
    assert len(pack.paths) == 1
    edge = pack.paths[0][0]
    # rendered as stored (cve affects product), not re-oriented
    assert edge.subject.key == "CVE-1" and edge.object.key == "nginx"


# ------------------------------------------------------------------- no path #

def test_no_path_returns_empty_with_note(tmp_path):
    store = SqliteStore(tmp_path / "np.db")
    _edge(store, "net", ("n", "a"), ("n", "b"))
    _edge(store, "net", ("n", "c"), ("n", "d"))  # disconnected component
    pack = find_paths(store, _req(**{"from": _n("a")}, to=_n("d"), via=["link"], depth=3))
    assert pack.paths == []
    assert any("no path found" in note for note in pack.notes)
    store.close()


# ------------------------------------------------------------------- cycles #

def test_cycle_does_not_loop(tmp_path):
    store = SqliteStore(tmp_path / "cy.db")
    _edge(store, "net", ("n", "a"), ("n", "b"))
    _edge(store, "net", ("n", "b"), ("n", "a"))   # mutual edge -> a cycle
    _edge(store, "net", ("n", "b"), ("n", "t"))
    pack = find_paths(store, _req(**{"from": _n("a")}, to=_n("t"), via=["link"], depth=3))
    assert pack.paths, "a-b-t must be found without looping a-b-a-b..."
    # no path revisits an entity (simple paths only)
    for path in pack.paths:
        nodes = [(path[0].subject.type, path[0].subject.key)]
        for e in path:
            nodes.append((e.object.type, e.object.key) if isinstance(e.object, EntityRef)
                         else ("_scalar", str(e.object)))
        assert len(nodes) == len(set(nodes)), "a cycle must not appear inside one path"
    store.close()


# ---------------------------------------------------------- max_paths / depth #

def test_max_paths_enforced_and_noted(tmp_path):
    store = SqliteStore(tmp_path / "mp.db")
    for mid in ("x1", "x2", "x3"):   # three parallel 2-hop paths a -> xN -> d
        _edge(store, "net", ("n", "a"), ("n", mid))
        _edge(store, "net", ("n", mid), ("n", "d"))
    pack = find_paths(store, _req(**{"from": _n("a")}, to=_n("d"), via=["link"],
                                  depth=2, max_paths=2))
    assert len(pack.paths) == 2
    caps = [t for t in pack.truncated if t.reason == "max_paths"]
    assert caps and caps[0].total >= 3 and caps[0].gathered == 2


def test_depth_cap_blocks_a_longer_path(tmp_path):
    store = SqliteStore(tmp_path / "dp.db")
    for a, b in (("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")):
        _edge(store, "net", ("n", a), ("n", b))
    # e is 4 hops from a; depth 2 cannot reach it
    pack = find_paths(store, _req(**{"from": _n("a")}, to=_n("e"), via=["link"], depth=2))
    assert pack.paths == []
    assert any("no path found" in n for n in pack.notes)


def test_depth_over_cap_is_clamped_and_noted(tmp_path):
    store = SqliteStore(tmp_path / "clamp.db")
    _edge(store, "net", ("n", "a"), ("n", "b"))
    pack = find_paths(store, _req(**{"from": _n("a")}, to=_n("b"), via=["link"], depth=5))
    assert len(pack.paths) == 1
    assert any("clamped" in n for n in pack.notes)


# --------------------------------------------------------------- time axes #

def test_as_of_filters_an_edge_out(tmp_path):
    store = SqliteStore(tmp_path / "asof.db")
    store.record_claim(ClaimIn(namespace="net", subject=_n("a"), predicate="link", object=_n("b"),
                               observed_at=_at(1), source="g"))
    store.record_claim(ClaimIn(namespace="net", subject=_n("b"), predicate="link", object=_n("c"),
                               observed_at=_at(20), source="g"))   # asserted later
    got = find_paths(store, _req(**{"from": _n("a")}, to=_n("c"), via=["link"], depth=2))
    assert len(got.paths) == 1
    # as of before the b->c edge was observed, the path is not there
    early = find_paths(store, _req(**{"from": _n("a")}, to=_n("c"), via=["link"], depth=2,
                                   as_of=_at(10)))
    assert early.paths == []


def test_valid_at_filters_an_edge_out(tmp_path):
    store = SqliteStore(tmp_path / "validat.db")
    store.record_claim(ClaimIn(namespace="net", subject=_n("a"), predicate="link", object=_n("b"),
                               observed_at=_at(1), source="g"))
    store.record_claim(ClaimIn(namespace="net", subject=_n("b"), predicate="link", object=_n("c"),
                               observed_at=_at(1), source="g",
                               valid_from=_at(15), valid_to=_at(25)))
    got = find_paths(store, _req(**{"from": _n("a")}, to=_n("c"), via=["link"], depth=2))
    assert len(got.paths) == 1
    outside = find_paths(store, _req(**{"from": _n("a")}, to=_n("c"), via=["link"], depth=2,
                                     valid_at=_at(5)))
    assert outside.paths == []


def test_superseded_edge_excluded(tmp_path):
    store = SqliteStore(tmp_path / "sup.db")
    store.record_claim(ClaimIn(namespace="net", subject=_n("a"), predicate="link", object=_n("b"),
                               observed_at=_at(1), source="g"))
    bc = store.record_claim(ClaimIn(namespace="net", subject=_n("b"), predicate="link",
                                    object=_n("c"), observed_at=_at(2), source="g"))
    # a recorded correction (D-050) reroutes b to c2, retiring the b->c edge
    store.record_claim(ClaimIn(namespace="net", subject=_n("b"), predicate="link", object=_n("c2"),
                               observed_at=_at(9), source="g", supersedes=bc.id))
    to_c = find_paths(store, _req(**{"from": _n("a")}, to=_n("c"), via=["link"], depth=2))
    assert to_c.paths == [], "the corrected b->c edge is history, so c is unreachable"
    to_c2 = find_paths(store, _req(**{"from": _n("a")}, to=_n("c2"), via=["link"], depth=2))
    assert len(to_c2.paths) == 1


# --------------------------------------------------------------- scoping #

def test_type_scoped_grant_cannot_see_path_through_a_gated_type(tmp_path):
    store = SqliteStore(tmp_path / "scoped.db")
    store.record_claim(ClaimIn(namespace="net", subject=EntityRef(type="host", key="a"),
                               predicate="link", object=EntityRef(type="secret", key="m"),
                               observed_at=_at(1), source="g"))
    store.record_claim(ClaimIn(namespace="net", subject=EntityRef(type="secret", key="m"),
                               predicate="link", object=EntityRef(type="host", key="c"),
                               observed_at=_at(1), source="g"))
    full = find_paths(store, _req(**{"from": EntityRef(type="host", key="a")},
                                  to=EntityRef(type="host", key="c"), via=["link"], depth=2))
    assert len(full.paths) == 1
    scoped = find_paths(store, _req(**{"from": EntityRef(type="host", key="a")},
                                    to=EntityRef(type="host", key="c"), via=["link"], depth=2),
                        allowed_types=("host",))
    assert scoped.paths == [], "a path through the gated 'secret' hop is not returned"


# --------------------------------------------------------------- budget #

def test_over_budget_path_dropped_with_note(tmp_path):
    store = SqliteStore(tmp_path / "budget.db")
    _edge(store, "net", ("n", "a"), ("n", "b"))
    _edge(store, "net", ("n", "b"), ("n", "c"))
    pack = find_paths(store, _req(**{"from": _n("a")}, to=_n("c"), via=["link"], depth=2, budget=1))
    assert pack.paths == []
    assert pack.charged_tokens == 0
    assert any("budget" in n for n in pack.notes)
    assert any(t.reason == "max_paths" for t in pack.truncated)


# --------------------------------------------------------------- unknown via #

def test_unknown_via_predicate_noted_with_close_matches(tmp_path):
    store = SqliteStore(tmp_path / "via.db")
    store.put_schema(SchemaRegistration(namespace="net", predicates=[
        PredicateDef(name="links", description="a link between nodes")]))
    _edge(store, "net", ("n", "a"), ("n", "b"), pred="links")
    pack = find_paths(store, _req(**{"from": _n("a")}, to=_n("b"), via=["linkz"], depth=2))
    assert pack.paths == []
    note = next(n for n in pack.notes if "not registered" in n)
    assert "linkz" in note and "links" in note


def test_unknown_endpoint_noted(tmp_path):
    store = SqliteStore(tmp_path / "ep.db")
    _edge(store, "net", ("n", "a"), ("n", "b"))
    pack = find_paths(store, _req(**{"from": _n("a")}, to=_n("ghost"), via=["link"], depth=2))
    assert any("ghost" in n for n in pack.notes)


# --------------------------------------------------------- seed integration #

def test_seed_alert_to_domain_path_is_cited(tmp_path):
    """On the deterministic seed corpus: alert AL-2291 -triggered_on-> web-01
    -member_of-> corp.local, each hop cited."""
    from loom.seed import cmd_load
    db = str(tmp_path / "seed.db")
    cmd_load(db, seed=42)
    store = SqliteStore(db)
    try:
        pack = find_paths(store, PathRequest(
            namespace="netsec", **{"from": EntityRef(type="alert", key="AL-2291")},
            to=EntityRef(type="domain", key="corp.local"),
            via=["triggered_on", "member_of"], depth=2))
        assert pack.paths, "the alert reaches the domain through web-01"
        best = pack.paths[0]
        preds = [e.predicate for e in best]
        assert "triggered_on" in preds and "member_of" in preds
        assert all(e.cite.observation_id for e in best)
        # it passes through host:web-01
        keys = {(e.subject.type, e.subject.key) for e in best} | {
            (e.object.type, e.object.key) for e in best if isinstance(e.object, EntityRef)}
        assert ("host", "web-01") in keys
    finally:
        store.close()
