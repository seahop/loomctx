"""The MITRE ATT&CK taxonomy connector (loomctx.connectors.attack): parse the
published `mitre-attack` STIX 2.1 knowledge base into cited, timestamped
catalog claims — technique / tactic / group / software / mitigation entities
keyed by their ATT&CK id, and the catalog edges MITRE publishes (in_tactic,
uses, mitigates) — then walk them: a group reaches the techniques it uses, and
a technique reaches the mitigations that address it, cited.

`tests/fixtures/attack_stix_slice.json` is a SMALL slice of the GENUINE MITRE
ATT&CK enterprise STIX bundle, extracted VERBATIM from the public
attack-stix-data repository
(https://github.com/mitre-attack/attack-stix-data — enterprise-attack.json).
The eleven objects are a coherent, connected sub-graph, unaltered:
  * group        G0001  Axiom (intrusion-set)
  * technique    T1005  Data from Local System   (in tactic Collection)
  * technique    T1560  Archive Collected Data    (in tactic Collection)
  * software     S0412  ZxShell (malware)
  * mitigation   M1057  Data Loss Prevention (course-of-action)
  * tactic       TA0009 Collection (x-mitre-tactic)
  * relationships: Axiom uses T1005, Axiom uses T1560, Axiom uses ZxShell,
    ZxShell uses T1005, M1057 mitigates T1005.
Parser edge cases (unknown object type, revoked object, missing id) are
exercised with small inline STIX objects; no STIX is hand-fabricated as data."""

from pathlib import Path

import pytest

from loomctx.connectors import attack, vulns
from loomctx.context import build_pack, find_paths
from loomctx.contracts import AskRequest, EntityRef, PathRequest, ScopeSpec
from loomctx.store.sqlite import SqliteStore

FIX = Path(__file__).parent / "fixtures"
SLICE = FIX / "attack_stix_slice.json"

GROUP = EntityRef(type="group", key="G0001")
T1005 = EntityRef(type="technique", key="T1005")
T1560 = EntityRef(type="technique", key="T1560")
SOFTWARE = EntityRef(type="software", key="S0412")
MITIGATION = EntityRef(type="mitigation", key="M1057")
TACTIC = EntityRef(type="tactic", key="TA0009")


def _envs():
    stats: dict = {}
    return list(attack.bundle_to_envelopes(_load(SLICE), "attack", stats=stats)), stats


def _by_subject(envs):
    out: dict = {}
    for e in envs:
        out.setdefault((e.subject.type, e.subject.key), []).append(e)
    return out


def _edges(envs, predicate):
    return [(e.subject, e.object) for e in envs
            if e.predicate == predicate and isinstance(e.object, EntityRef)]


# ------------------------------------------------------------ parse: entities #

def test_entities_are_keyed_by_their_attack_id_with_name_desc_url():
    envs, stats = _envs()
    by = _by_subject(envs)
    # every catalogued object is present, keyed by its ATT&CK external id
    assert set(by) == {("group", "G0001"), ("technique", "T1005"), ("technique", "T1560"),
                       ("software", "S0412"), ("mitigation", "M1057"), ("tactic", "TA0009")}

    tech = {e.predicate: e for e in by[("technique", "T1005")] if not isinstance(e.object, EntityRef)}
    assert tech["name"].object == "Data from Local System"
    assert tech["summary"].object.startswith("Adversaries may search local system")
    assert tech["url"].object == "https://attack.mitre.org/techniques/T1005"
    # the ATT&CK id and object version ride in attrs; source is mitre-attack
    assert tech["name"].attrs["attack_id"] == "T1005"
    assert tech["name"].attrs["attack_version"] == "1.8"
    assert all(e.source == "mitre-attack" for e in envs)

    # the group, software, mitigation and tactic each got their name too
    assert {e.object for e in by[("group", "G0001")] if e.predicate == "name"} == {"Axiom"}
    assert {e.object for e in by[("software", "S0412")] if e.predicate == "name"} == {"ZxShell"}
    assert {e.object for e in by[("mitigation", "M1057")] if e.predicate == "name"} == {"Data Loss Prevention"}
    assert {e.object for e in by[("tactic", "TA0009")] if e.predicate == "name"} == {"Collection"}


def test_time_is_the_modified_stamp_valid_from_created():
    envs, _ = _envs()
    name = next(e for e in envs if e.subject == T1005 and e.predicate == "name")
    # observed_at = the object's `modified`, valid_from = its `created`
    assert name.observed_at.isoformat().startswith("2026-05-12")
    assert name.valid_from.isoformat().startswith("2017-05-31")


# ------------------------------------------------------------- parse: edges #

def test_technique_in_tactic_from_kill_chain_phases():
    envs, _ = _envs()
    edges = _edges(envs, "in_tactic")
    # both techniques are in the Collection tactic (TA0009), resolved from the
    # kill_chain phase shortname via the bundle's x-mitre-tactic object
    assert (T1005, TACTIC) in edges and (T1560, TACTIC) in edges


def test_uses_edges_group_and_software():
    envs, _ = _envs()
    uses = _edges(envs, "uses")
    assert (GROUP, T1005) in uses          # group uses technique
    assert (GROUP, T1560) in uses          # group uses technique
    assert (GROUP, SOFTWARE) in uses       # group uses software
    assert (SOFTWARE, T1005) in uses       # software uses technique


def test_mitigates_edge():
    envs, _ = _envs()
    assert (MITIGATION, T1005) in _edges(envs, "mitigates")


def test_relationship_procedure_descriptions_are_not_imported():
    """D-073: catalog edges only — the per-edge 'how a group used this' prose
    is defensive-scope out and must not ride along in attrs or as a claim."""
    envs, _ = _envs()
    edge_claims = [e for e in envs if e.predicate in ("uses", "mitigates")]
    assert edge_claims
    for e in edge_claims:
        assert "description" not in e.attrs
        assert set(e.attrs) <= {"stix_id", "stix_type", "attack_version", "created"}


# --------------------------------------------------------------- edge cases #

UNKNOWN = {"type": "x-mitre-data-source", "id": "x-mitre-data-source--0000",
           "modified": "2024-01-01T00:00:00.000Z", "name": "Command",
           "external_references": [{"source_name": "mitre-attack", "external_id": "DS0017"}]}
REVOKED = {"type": "attack-pattern", "id": "attack-pattern--dead0000", "revoked": True,
           "modified": "2024-01-01T00:00:00.000Z", "name": "Old Technique",
           "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]}
NO_ID = {"type": "intrusion-set", "id": "intrusion-set--noid0000",
         "modified": "2024-01-01T00:00:00.000Z", "name": "No external id"}


def test_unknown_and_dropped_objects_are_skipped():
    stats: dict = {}
    bundle = {"type": "bundle", "objects": [UNKNOWN, REVOKED, NO_ID]}
    envs = list(attack.bundle_to_envelopes(bundle, "attack", stats=stats))
    assert envs == []                                    # nothing catalogued
    assert stats.get("skipped", 0) >= 2                  # unknown type + no-id object
    assert stats.get("dropped", 0) == 1                  # the revoked technique
    # an edge whose endpoint was dropped/out-of-scope is not emitted either
    edge = {"type": "relationship", "id": "relationship--x", "relationship_type": "uses",
            "modified": "2024-01-01T00:00:00.000Z",
            "source_ref": "intrusion-set--noid0000", "target_ref": "attack-pattern--dead0000"}
    stats = {}
    assert list(attack.bundle_to_envelopes({"type": "bundle", "objects": [REVOKED, NO_ID, edge]},
                                           "attack", stats=stats)) == []
    assert stats.get("skipped_edge", 0) == 1


def test_schema_registers_the_taxonomy_non_strict():
    reg = attack.schema("attack")
    assert {t.name for t in reg.entity_types} == {
        "technique", "tactic", "group", "software", "mitigation", "cve"}
    by = {p.name: p for p in reg.predicates}
    assert by["in_tactic"].containment is True and by["in_tactic"].object_types == ["tactic"]
    assert set(by["uses"].object_types) == {"technique", "software"}
    assert by["mitigates"].object_types == ["technique"]
    assert reg.strict is False


# --------------------------------------------------------------- idempotency #

def test_reimport_is_idempotent(tmp_path):
    db = str(tmp_path / "attack.db")
    attack.main(["import", str(SLICE), "--namespace", "attack", "--db", db])
    before = sum(1 for _ in SqliteStore(db).iter_observations("attack"))
    attack.main(["import", str(SLICE), "--namespace", "attack", "--db", db])
    after = sum(1 for _ in SqliteStore(db).iter_observations("attack"))
    assert before == after and before > 0


def test_import_exits_nonzero_when_the_engine_refuses(monkeypatch):
    """D-063 / S-36: a loader that saw any refusal must not exit 0."""
    from loomctx import ingest
    monkeypatch.setattr(vulns, "register", lambda *a, **k: None)

    def refusing(url, lines, size, key, timeout=60.0):
        n = sum(1 for _ in lines)
        return {"total": n, "recorded": n - 3, "accepted": 0, "rejected": 3}

    monkeypatch.setattr(ingest, "post_batches", refusing)
    with pytest.raises(SystemExit) as exc:
        attack.main(["import", str(SLICE), "--namespace", "attack", "--url", "http://loomctx.invalid"])
    assert exc.value.code not in (0, None) and "3" in str(exc.value.code) and "refused" in str(exc.value.code)


# ------------------------------------------------------- WALK: the taxonomy #

def test_walk_group_reaches_its_techniques_and_their_mitigations_cited(tmp_path):
    """The point of the connector: hold ATT&CK as a queryable, cited graph. From
    a group over `uses` reach its techniques; from a technique over `mitigates`
    (reverse) reach the mitigations that address it — every hop cited (D-073)."""
    db = str(tmp_path / "walk.db")
    attack.main(["import", str(SLICE), "--namespace", "attack", "--db", db])

    store = SqliteStore(db)
    try:
        # group --uses--> technique
        pack = find_paths(store, PathRequest(
            namespace="attack", **{"from": GROUP}, to=T1005, via=["uses"], depth=1))
        assert pack.paths, "Axiom must reach T1005 over `uses`"
        best = pack.paths[0]
        assert [e.predicate for e in best] == ["uses"]
        assert best[0].subject == GROUP and best[0].object == T1005
        assert all(e.cite.observation_id for e in best)      # every hop cited

        # technique --mitigates (reverse)--> mitigation
        pack = find_paths(store, PathRequest(
            namespace="attack", **{"from": T1005}, to=MITIGATION, via=["mitigates"], depth=1))
        assert pack.paths, "T1005 must reach M1057 over `mitigates` (reverse)"
        edge = pack.paths[0][0]
        assert edge.subject == MITIGATION and edge.object == T1005    # stored orientation preserved
        assert edge.cite.observation_id

        # a scope walk from the group reaches the techniques AND their tactic
        pack = build_pack(store, AskRequest(
            namespace="attack", question="which techniques does this group use, and their tactic?",
            scope=ScopeSpec(subjects=[GROUP], expand=["uses", "in_tactic"], depth=2), budget=3000))
        reached = {(s.type, s.key) for s in pack.subjects}
        assert ("technique", "T1005") in reached and ("technique", "T1560") in reached
        assert ("software", "S0412") in reached and ("tactic", "TA0009") in reached
        assert any(i.citations for i in pack.items)
    finally:
        store.close()


def _load(path: Path) -> dict:
    import json
    return json.loads(path.read_text())
