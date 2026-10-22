"""The `path` answer type (D-067): a bounded, shortest-first BFS that
enumerates the edge sequence(s) connecting two entities along named
predicates. Domain-agnostic, cited, time-scoped, honestly capped. Every path
here is built on a synthetic SqliteStore (no embedder — find_paths does not
rank) except the seed integration at the end."""

from datetime import datetime, timezone

from loomctx.context import find_paths
from loomctx.contracts import ClaimIn, EntityRef, PathRequest, SchemaRegistration, PredicateDef
from loomctx.store.sqlite import SqliteStore


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


def test_depth_cut_only_reported_when_the_frontier_can_extend(tmp_path):
    """A depth-length path ending at a dead end cut nothing: no depth
    truncation. One whose far end has an edge off the path did — reported,
    with `total` the paths actually found (no invented count)."""
    store = SqliteStore(tmp_path / "dead.db")
    _edge(store, "net", ("n", "a"), ("n", "b"))
    _edge(store, "net", ("n", "b"), ("n", "t"))
    _edge(store, "net", ("n", "b"), ("n", "d"))     # d: a dead end
    req = _req(**{"from": _n("a")}, to=_n("t"), via=["link"], depth=2)
    pack = find_paths(store, req)
    assert len(pack.paths) == 1
    assert not [t for t in pack.truncated if t.reason == "depth"], pack.truncated
    assert not any("frontier" in n for n in pack.notes)
    _edge(store, "net", ("n", "d"), ("n", "e"))     # now d leads on
    pack = find_paths(store, req)
    cut = [t for t in pack.truncated if t.reason == "depth"]
    assert cut and cut[0].gathered == 1 and cut[0].total == 1
    assert any("raise depth" in n for n in pack.notes)
    store.close()


def _hub(prefix, hub, shared, n=300):
    return [ClaimIn(namespace="net", subject=EntityRef(type="cve", key=f"{prefix}-{i}"),
                    predicate="affects", object=EntityRef(type="product", key=prod),
                    observed_at=_at(1), source="nvd")
            for i in range(n) for prod in [hub, *shared]]


def test_dead_end_target_is_disproved_without_the_hub(tmp_path):
    """The search grows from both ends (D-080): from a product with 300 CVEs
    to one in a two-node component, the target's side runs out after one
    hop, so no path is proved without fanning out through the hub."""
    store = SqliteStore(tmp_path / "dead.db")
    store.record_claims(_hub("CVE", "hub", [f"q{i}" for i in range(5)]) + [
        ClaimIn(namespace="net", subject=EntityRef(type="product", key="far"),
                predicate="affects", object=EntityRef(type="product", key="farther"),
                observed_at=_at(1), source="nvd")])
    stats: dict = {}
    pack = find_paths(store, _req(**{"from": EntityRef(type="product", key="hub")},
                                  to=EntityRef(type="product", key="far"), via=["affects"],
                                  depth=6), stats=stats)
    assert pack.paths == [] and not pack.truncated
    assert stats["work"] <= 2 and stats["partials"] <= 1
    assert any("no path found" in n for n in pack.notes)
    store.close()


def test_hub_fanout_is_bounded_and_reported(tmp_path, monkeypatch):
    """Two hubs, each with 300 CVEs that also affect 5 shared products of its
    own, and nothing between them: both sides must fan out, and the third
    hop of either goes back through every CVE (1,500 x 300 extensions). The
    work is capped at LOOMCTX_MAX_SCOPE_OBSERVATIONS and the cut is reported."""
    store = SqliteStore(tmp_path / "hub.db")
    store.record_claims(_hub("A", "hub", [f"q{i}" for i in range(5)])
                        + _hub("B", "hub2", [f"r{i}" for i in range(5)]))
    req = _req(**{"from": EntityRef(type="product", key="hub")},
               to=EntityRef(type="product", key="hub2"), via=["affects"], depth=6,
               siblings=True)   # product <- cve -> product is a turn at the cve

    monkeypatch.setenv("LOOMCTX_MAX_SCOPE_OBSERVATIONS", "20000")
    stats: dict = {}
    pack = find_paths(store, req, stats=stats)   # the work counters bound it; no wall clock (flaky under load)
    assert stats["work"] <= 20_000 + 1 and stats["partials"] <= 20_000
    assert pack.paths == []
    assert any(t.reason == "scope_cap" for t in pack.truncated)
    assert any("edge extensions" in n for n in pack.notes)

    monkeypatch.delenv("LOOMCTX_MAX_SCOPE_OBSERVATIONS")
    stats = {}
    pack = find_paths(store, req, stats=stats)
    assert stats["work"] <= 100_000 + 1 and stats["partials"] <= 100_000
    assert any("edge extensions" in n for n in pack.notes)
    store.close()


def test_depth_over_cap_is_clamped_and_noted(tmp_path):
    store = SqliteStore(tmp_path / "clamp.db")
    _edge(store, "net", ("n", "a"), ("n", "b"))
    pack = find_paths(store, _req(**{"from": _n("a")}, to=_n("b"), via=["link"], depth=9))
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


def test_superseded_edge_excluded_walked_from_its_object_side(tmp_path):
    """The correction Y (b -> c2) shares the retired X's subject, not its
    object: walked from c, b's rows (and Y) are never gathered before X is
    taken — the edge ids are looked up for corrections before returning."""
    store = SqliteStore(tmp_path / "suprev.db")
    _edge(store, "net", ("n", "a"), ("n", "b"))
    bc = _edge(store, "net", ("n", "b"), ("n", "c"), day=2)
    _edge(store, "net", ("n", "b"), ("n", "c2"), day=9, supersedes=bc.id)
    one = find_paths(store, _req(**{"from": _n("c")}, to=_n("b"), via=["link"], depth=1))
    assert one.paths == [], "c -> b rides the superseded b -> c edge"
    two = find_paths(store, _req(**{"from": _n("c")}, to=_n("a"), via=["link"], depth=2))
    assert two.paths == [], "the path's first hop is the superseded edge"
    # as of before the correction was observed, the edge is current again
    early = find_paths(store, _req(**{"from": _n("c")}, to=_n("b"), via=["link"], depth=1,
                                   as_of=_at(5)))
    assert len(early.paths) == 1 and early.paths[0][0].cite.observation_id == bc.id
    store.close()


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


def test_gated_predicate_names_do_not_leak_through_notes(tmp_path):
    """The 'unknown via' note's vocabulary is built from rows the caller may
    see: a predicate carried only by edges into a gated type is not named."""
    store = SqliteStore(tmp_path / "leak.db")
    store.record_claim(ClaimIn(namespace="net", subject=EntityRef(type="host", key="a"),
                               predicate="stores_secret", object=EntityRef(type="secret", key="m"),
                               observed_at=_at(1), source="g"))
    _edge(store, "net", ("host", "a"), ("host", "b"), pred="link")
    req = _req(**{"from": EntityRef(type="host", key="a")},
               to=EntityRef(type="host", key="b"), via=["stores_secrets"], depth=1)
    def named(pack):   # the notes, minus the asked-for name itself
        return " ".join(pack.notes).replace("stores_secrets", "")
    assert "closest: stores_secret" in named(find_paths(store, req))
    scoped = find_paths(store, req, allowed_types=("host",))
    assert any("stores_secrets" in n for n in scoped.notes)   # still told it is unknown
    assert "stores_secret" not in named(scoped)
    store.close()


def _keyed_path_client(tmp_path, monkeypatch, db):
    import hashlib
    import json

    from fastapi.testclient import TestClient
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": [
        {"sha256": hashlib.sha256(b"admin-key").hexdigest(), "id": "admin",
         "namespaces": ["net"], "perms": "r"},
        {"sha256": hashlib.sha256(b"host-key").hexdigest(), "id": "hosts",
         "namespaces": ["net"], "perms": "r", "entity_types": ["host"]}]}))
    monkeypatch.setenv("LOOMCTX_DB", str(db))
    monkeypatch.setenv("LOOMCTX_AUTH_FILE", str(keys))
    for var in ("LOOMCTX_API_KEYS", "LOOMCTX_ALLOWED_HOSTS", "LOOMCTX_ALLOWED_ORIGINS"):
        monkeypatch.delenv(var, raising=False)
    from loomctx.api.http import app
    return TestClient(app)


def test_type_scoped_key_does_not_learn_a_gated_canonical_through_an_alias(tmp_path, monkeypatch):
    """/v1/path gates the requested types; a cross-type alias (host:shadow ->
    secret:m) must not echo the gated canonical back, nor search from it."""
    db = tmp_path / "alias.db"
    store = SqliteStore(db)
    store.record_claim(ClaimIn(namespace="net", subject=EntityRef(type="secret", key="m"),
                               predicate="link", object=EntityRef(type="host", key="b"),
                               observed_at=_at(1), source="g"))
    store.add_alias("net", EntityRef(type="host", key="shadow"), EntityRef(type="secret", key="m"))
    store.close()
    body = {"namespace": "net", "from": {"type": "host", "key": "shadow"},
            "to": {"type": "host", "key": "b"}, "via": ["link"], "depth": 1}
    with _keyed_path_client(tmp_path, monkeypatch, db) as client:
        admin = client.post("/v1/path", json=body, headers={"x-loomctx-key": "admin-key"})
        assert admin.status_code == 200
        assert admin.json()["from"] == {"type": "secret", "key": "m"} and admin.json()["paths"]
        # the scoped key asked about a host it may see; the name resolves to
        # a gated secret, which is not there for it
        scoped = client.post("/v1/path", json=body, headers={"x-loomctx-key": "host-key"})
        assert scoped.status_code == 200
        out = scoped.json()
        assert out["from"] == {"type": "host", "key": "shadow"} and out["paths"] == []
        assert "secret" not in json_text(out)
        # asking for the gated type directly is refused outright
        direct = client.post("/v1/path", json={**body, "from": {"type": "secret", "key": "m"}},
                             headers={"x-loomctx-key": "host-key"})
        assert direct.status_code == 403


def json_text(value) -> str:
    import json
    return json.dumps(value)


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
    from loomctx.seed import cmd_load
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


# ---------------------------------------------- longer paths, hubs, status (D-080) #

def test_four_and_six_hop_paths_found(tmp_path):
    store = SqliteStore(tmp_path / "long.db")
    chain = "abcdefg"
    for x, y in zip(chain, chain[1:]):
        _edge(store, "net", ("n", x), ("n", y))
    four = find_paths(store, _req(**{"from": _n("a")}, to=_n("e"), via=["link"]))  # default depth
    assert [(e.subject.key, e.object.key) for e in four.paths[0]] == [
        ("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")]
    six = find_paths(store, _req(**{"from": _n("a")}, to=_n("g"), via=["link"], depth=6))
    assert len(six.paths) == 1 and len(six.paths[0]) == 6
    assert all(e.cite.observation_id for e in six.paths[0])
    store.close()


def test_path_is_met_from_the_target_side_past_a_hub(tmp_path):
    """A user in a group holding 1,000 users and in a small group that holds
    a role: the search extends the cheaper side, so it reaches the role
    without walking the big group's members."""
    store = SqliteStore(tmp_path / "meet.db")
    claims = [ClaimIn(namespace="iam", subject=EntityRef(type="user", key=f"u{i}"),
                      predicate="member_of", object=EntityRef(type="group", key="everyone"),
                      observed_at=_at(1), source="idp") for i in range(1000)]
    claims += [
        ClaimIn(namespace="iam", subject=EntityRef(type="user", key="u7"), predicate="member_of",
                object=EntityRef(type="group", key="ops"), observed_at=_at(1), source="idp"),
        ClaimIn(namespace="iam", subject=EntityRef(type="group", key="ops"), predicate="member_of",
                object=EntityRef(type="group", key="tier0"), observed_at=_at(1), source="idp"),
        ClaimIn(namespace="iam", subject=EntityRef(type="group", key="tier0"), predicate="has_role",
                object=EntityRef(type="role", key="global-admin"), observed_at=_at(1), source="idp")]
    store.record_claims(claims)
    stats: dict = {}
    pack = find_paths(store, PathRequest(
        namespace="iam", **{"from": EntityRef(type="user", key="u7")},
        to=EntityRef(type="role", key="global-admin"), via=["member_of", "has_role"], depth=4),
        stats=stats)
    assert [e.predicate for e in pack.paths[0]] == ["member_of", "member_of", "has_role"]
    assert stats["work"] < 50, stats     # the 1,000 members were never walked
    store.close()


def test_path_through_a_disabled_account_is_returned_and_flagged(tmp_path):
    """A disabled account on a path is still a path (it may matter), so it is
    returned — with its `enabled = false` beside it, cited and charged, for
    every predicate the registry marks node_status."""
    store = SqliteStore(tmp_path / "status.db")
    store.put_schema(SchemaRegistration(namespace="iam", predicates=[
        PredicateDef(name="member_of", containment=True),
        PredicateDef(name="enabled", node_status=True)]))
    user, group = EntityRef(type="user", key="old-admin"), EntityRef(type="group", key="admins")
    store.record_claim(ClaimIn(namespace="iam", subject=user, predicate="member_of", object=group,
                               observed_at=_at(1), source="idp"))
    store.record_claim(ClaimIn(namespace="iam", subject=user, predicate="enabled", object=True,
                               observed_at=_at(1), source="idp"))
    off = store.record_claim(ClaimIn(namespace="iam", subject=user, predicate="enabled",
                                     object=False, observed_at=_at(5), source="idp"))
    req = PathRequest(namespace="iam", **{"from": user}, to=group, via=["member_of"], depth=1)
    pack = find_paths(store, req)
    assert len(pack.paths) == 1
    assert [(s.entity, s.predicate, s.value, s.cite.observation_id) for s in pack.node_status] == [
        (user, "enabled", False, off.id)]           # the newest value, not the older True
    bare = find_paths(store, req.model_copy(update={"budget": 60}))
    assert bare.charged_tokens < pack.charged_tokens or not bare.paths
    # as of before it was disabled, the path reads the account as enabled
    early = find_paths(store, req.model_copy(update={"as_of": _at(3)}))
    assert [s.value for s in early.node_status] == [True]
    store.close()


def test_a_shared_group_is_not_a_route_unless_siblings_asked(tmp_path):
    """user -member_of-> staff <-member_of- admin -has_role-> GA is a shared
    group, not a way to the role; returned only with siblings=True."""
    store = SqliteStore(tmp_path / "sib.db")
    _edge(store, "iam", ("user", "eve"), ("group", "staff"), pred="member_of")
    _edge(store, "iam", ("user", "root"), ("group", "staff"), pred="member_of")
    _edge(store, "iam", ("user", "root"), ("role", "ga"), pred="has_role")
    req = PathRequest(namespace="iam", **{"from": EntityRef(type="user", key="eve")},
                      to=EntityRef(type="role", key="ga"), via=["member_of", "has_role"], depth=3)
    assert find_paths(store, req).paths == []
    both = find_paths(store, req.model_copy(update={"siblings": True}))
    assert [e.predicate for e in both.paths[0]] == ["member_of", "member_of", "has_role"]
    store.close()


def test_one_account_in_two_groups_is_a_route(tmp_path):
    """Domain Admins <-member_of- Tier0 <-member_of- rlopez -member_of->
    WS-Operators -has_ace-> WS-1: rlopez is an admin through Tier0 and holds
    rights through WS-Operators. The account is the subject of both
    member_of edges, so this is a route, not a shared group (D-115); the
    access audit missed rlopez in 22 runs while this turn was refused. A
    sideways step through a shared group is still refused, and says so."""
    store = SqliteStore(tmp_path / "two.db")
    _edge(store, "ad", ("group", "tier0"), ("group", "da"), pred="member_of")
    _edge(store, "ad", ("user", "rlopez"), ("group", "tier0"), pred="member_of")
    _edge(store, "ad", ("user", "rlopez"), ("group", "ws-ops"), pred="member_of")
    _edge(store, "ad", ("group", "ws-ops"), ("computer", "ws-1"), pred="has_ace")
    _edge(store, "ad", ("user", "jdoe"), ("group", "ws-ops"), pred="member_of")   # a co-member, not an admin
    req = PathRequest(namespace="ad", **{"from": EntityRef(type="group", key="da")},
                      to=EntityRef(type="computer", key="ws-1"), via=["member_of", "has_ace"], depth=5)
    got = find_paths(store, req)
    routes = [[(e.subject.key, e.predicate, e.object.key) for e in p] for p in got.paths]
    assert routes == [[("tier0", "member_of", "da"), ("rlopez", "member_of", "tier0"),
                       ("rlopez", "member_of", "ws-ops"), ("ws-ops", "has_ace", "ws-1")]]
    # jdoe shares ws-ops with rlopez: reaching jdoe that way is co-membership
    to_jdoe = find_paths(store, req.model_copy(update={"to": EntityRef(type="user", key="jdoe")}))
    assert to_jdoe.paths == []
    assert any("sideways through a group" in n for n in to_jdoe.notes)
    store.close()
