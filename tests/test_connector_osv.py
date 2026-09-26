"""The OSV / GHSA advisory connector (loom.connectors.osv): parse genuine OSV
JSON into cited, timestamped claims, key it to the SAME `cve:` node NVD/KEV
write to when the record carries a CVE alias, and prove the fusion — an OSV
CVSS score shows as a cross-source CONFLICT on the existing CVE (D-035), cited.

The two `tests/fixtures/osv_ghsa_*.json` records are REAL OSV records pulled
verbatim from the public osv.dev API (https://api.osv.dev/v1/vulns/<id>):
  * `osv_ghsa_log4shell.json`  = GHSA-jfh8-c2jp-5v3q (Log4Shell), which aliases
    CVE-2021-44228 and affects Maven packages — the CVE-alias / fusion case;
  * `osv_ghsa_eslint_scope_malware.json` = GHSA-hxxf-q3w9-4xgw (the 2018
    eslint-scope npm supply-chain compromise), a malware advisory with NO CVE
    alias — the OSV-id-keyed case.
The parser edge cases (no affected, no severity, a v4-only vector, multiple
non-CVE aliases) are exercised with small inline records."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from loom.connectors import osv, vulns
from loom.context import build_pack
from loom.contracts import AskRequest, ClaimIn, DocumentIn, EntityRef
from loom.store.sqlite import SqliteStore

FIX = Path(__file__).parent / "fixtures"
LOG4SHELL = FIX / "osv_ghsa_log4shell.json"
ESLINT = FIX / "osv_ghsa_eslint_scope_malware.json"


def _by_pred(envs):
    out: dict = {}
    for e in envs:
        if isinstance(e, ClaimIn):
            out.setdefault(e.predicate, []).append(e)
    return out


# ---------------------------------------------------------------- CVSS scoring #

def test_cvss_base_scores_are_computed_from_the_vector():
    # v3.1 (Log4Shell, base+temporal — the temporal E:H is ignored) => 10.0
    assert osv.best_severity({"severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H"}]})[:2] == (10.0, "3.1")
    # v3.1 with A:N (eslint-scope) => 9.1
    assert osv.best_severity({"severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}]})[:2] == (9.1, "3.1")
    # a genuine v2 vector is scored too
    assert osv.score_severity({"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"})[:2] == (7.5, "2.0")
    # a v4.0 vector yields no numeric base score (lookup tables not implemented)
    v4 = osv.score_severity({"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"})
    assert v4[0] is None and v4[1] == "4.0" and v4[2].startswith("CVSS:4.0")
    assert osv.severity_band(10.0) == "critical" and osv.severity_band(9.1) == "critical"
    assert osv.severity_band(7.5) == "high" and osv.severity_band(0.0) == "none"


# ------------------------------------------------------- parse: CVE-alias fusion #

def test_cve_aliased_record_fuses_to_the_cve_node():
    envs = list(osv.record_to_envelopes(_load(LOG4SHELL), "netsec"))
    # the advisory document comes first and every claim cites it (D-039)
    assert isinstance(envs[0], DocumentIn)
    doc = envs[0]
    assert doc.event_id.startswith("osv:GHSA-jfh8-c2jp-5v3q:") and doc.event_id.endswith(":doc")
    assert "Log4j" in doc.text
    claims = [e for e in envs if isinstance(e, ClaimIn)]
    assert all(c.provenance and c.provenance.artifact_event_id == doc.event_id for c in claims)
    # keyed to the SHARED cve node (the alias), not a GHSA node
    assert all(c.subject == EntityRef(type="cve", key="CVE-2021-44228") for c in claims)
    # the OSV/GHSA id is retained in attrs
    assert all(c.attrs["osv_id"] == "GHSA-jfh8-c2jp-5v3q" for c in claims)
    assert all("CVE-2021-44228" in c.attrs["aliases"] for c in claims)

    by = _by_pred(claims)
    # CVSS computed from the record's own vector, source ghsa, beside NVD's
    score = by["cvss_score"][0]
    assert score.object == 10.0 and score.source == "ghsa" and score.attrs["version"] == "3.1"
    assert by["has_severity"][0].object == "critical"
    assert by["summary"][0].object.startswith("Remote code injection")
    # observed at the record's `modified`, valid from `published`
    assert score.observed_at.year == 2025 and score.valid_from.isoformat().startswith("2021-12-10")


def test_affected_packages_are_keyed_by_ecosystem_not_cpe():
    envs = list(osv.record_to_envelopes(_load(LOG4SHELL), "netsec"))
    affects = {c.object.key: c for c in envs if isinstance(c, ClaimIn) and c.predicate == "affects"}
    # keyed ecosystem:name (Maven group:artifact), NOT a CPE vendor:product
    assert "Maven:org.apache.logging.log4j:log4j-core" in affects
    edge = affects["Maven:org.apache.logging.log4j:log4j-core"]
    assert edge.object.type == "package" and edge.attrs["ecosystem"] == "Maven"
    # the affected version ranges ride in attrs (multiple ranges merged onto one edge)
    assert edge.attrs["ranges"] and any("events" in r for r in edge.attrs["ranges"])
    assert edge.attrs["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core"


# ------------------------------------------------------- parse: no CVE alias #

def test_record_without_a_cve_alias_is_keyed_by_its_osv_id():
    envs = list(osv.record_to_envelopes(_load(ESLINT), "netsec"))
    claims = [e for e in envs if isinstance(e, ClaimIn)]
    # no CVE alias => keyed on advisory:<OSV id>, not a cve node
    assert all(c.subject == EntityRef(type="advisory", key="GHSA-hxxf-q3w9-4xgw") for c in claims)
    by = _by_pred(claims)
    assert by["cvss_score"][0].object == 9.1 and by["cvss_score"][0].source == "ghsa"
    assert by["summary"][0].object.startswith("Malicious Package")
    affects = {c.object.key for c in by["affects"]}
    assert {"npm:eslint-scope", "npm:eslint-config-eslint"} <= affects
    assert all(c.object.type == "package" for c in by["affects"])


# --------------------------------------------------------------- edge records #

NO_AFFECTED_NO_SEVERITY = {"id": "GHSA-empt-y000-0000", "modified": "2026-02-01T00:00:00Z"}
V4_ONLY = {"id": "GHSA-v4on-ly00-0000", "modified": "2026-02-01T00:00:00Z",
           "summary": "A v4-only advisory",
           "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}],
           "database_specific": {"severity": "HIGH"},
           "affected": [{"package": {"ecosystem": "PyPI", "name": "demo"}}]}
MULTI_ALIAS = {"id": "PYSEC-2099-1", "modified": "2099-01-01T00:00:00Z", "published": "2098-01-01T00:00:00Z",
               "aliases": ["GHSA-aaaa-bbbb-cccc", "CVE-2099-11111", "OSV-2099-9"],
               "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}],
               "affected": [{"package": {"ecosystem": "PyPI", "name": "demo"}}]}


def test_no_affected_no_severity_yields_just_the_document():
    stats: dict = {}
    envs = list(osv.records_to_envelopes([NO_AFFECTED_NO_SEVERITY], "netsec", stats=stats))
    assert len(envs) == 1 and isinstance(envs[0], DocumentIn)
    assert envs[0].text == "GHSA-empt-y000-0000"       # no summary/details: the id is the body
    assert stats == {"record": 1, "document": 1}


def test_v4_only_vector_keeps_the_band_from_database_specific():
    by = _by_pred(osv.record_to_envelopes(V4_ONLY, "netsec"))
    assert "cvss_score" not in by                        # v4 not numerically scored
    sev = by["has_severity"][0]
    assert sev.object == "high" and sev.attrs["cvss"][0].startswith("CVSS:4.0")


def test_multiple_aliases_pick_the_cve_and_keep_the_rest():
    by = _by_pred(osv.record_to_envelopes(MULTI_ALIAS, "netsec"))
    score = by["cvss_score"][0]
    assert score.subject == EntityRef(type="cve", key="CVE-2099-11111")   # the CVE among the aliases
    assert score.object == 7.5 and score.attrs["version"] == "2.0"        # the v2 vector, scored
    assert set(score.attrs["aliases"]) == {"GHSA-aaaa-bbbb-cccc", "CVE-2099-11111", "OSV-2099-9"}
    # PYSEC- id => source osv (only a GHSA- id is labelled ghsa)
    assert score.source == "osv" and score.attrs["osv_id"] == "PYSEC-2099-1"


def test_malformed_records_are_counted_and_skipped():
    stats: dict = {}
    envs = list(osv.records_to_envelopes([{"no": "id"}, "not a dict", MULTI_ALIAS], "netsec", stats=stats))
    assert stats["invalid"] == 2 and stats["record"] == 1 and any(isinstance(e, ClaimIn) for e in envs)


# --------------------------------------------------------------- idempotency #

def test_reimport_is_idempotent(tmp_path):
    db = str(tmp_path / "idem.db")
    osv.main(["import", str(LOG4SHELL), "--namespace", "netsec", "--db", db])
    before = sum(1 for _ in SqliteStore(db).iter_observations("netsec"))
    osv.main(["import", str(LOG4SHELL), "--namespace", "netsec", "--db", db])
    after = sum(1 for _ in SqliteStore(db).iter_observations("netsec"))
    assert before == after and before > 0


def test_schema_registers_package_and_the_shared_cve_vocabulary():
    reg = osv.schema("netsec")
    assert {t.name for t in reg.entity_types} == {"cve", "advisory", "package"}
    by = {p.name: p for p in reg.predicates}
    # affects allows BOTH the OSV package and the NVD product node (merge is
    # by-name override, so the object types must be a superset)
    assert set(by["affects"].object_types) == {"product", "package"}
    assert {"cvss_score", "has_severity", "summary"} <= set(by)
    assert reg.strict is False


def test_import_exits_nonzero_when_the_engine_refuses(monkeypatch):
    """D-063 / S-36: a loader that saw any refusal must not exit 0."""
    from loom import ingest
    monkeypatch.setattr(vulns, "register", lambda *a, **k: None)

    def refusing(url, lines, size, key, timeout=60.0):
        n = sum(1 for _ in lines)
        return {"total": n, "recorded": n - 2, "accepted": 0, "rejected": 2}

    monkeypatch.setattr(ingest, "post_batches", refusing)
    with pytest.raises(SystemExit) as exc:
        osv.main(["import", str(LOG4SHELL), "--namespace", "netsec", "--url", "http://loom.invalid"])
    assert exc.value.code not in (0, None) and "2" in str(exc.value.code) and "refused" in str(exc.value.code)


# ------------------------------------------------ FUSION: OSV conflicts with NVD #

def test_osv_severity_shows_as_a_conflict_on_the_existing_cve_cited(tmp_path):
    """The point of the connector: seed a CVE with an NVD CVSS score, import an
    OSV/GHSA record aliased to that CVE carrying a DIFFERENT score, and assert
    the pack on that CVE shows BOTH sources as one cross-source conflict (D-035),
    cited — i.e. OSV corroborates/adds to the same CVE entity, not a duplicate."""
    db = str(tmp_path / "fusion.db")
    store = SqliteStore(db)
    cve = EntityRef(type="cve", key="CVE-2021-44228")
    # NVD's score for this CVE (seeded as NVD/KEV would land it)
    store.record_claim(ClaimIn(namespace="netsec", subject=cve, predicate="cvss_score", object=9.0,
                               observed_at=datetime(2021, 12, 11, tzinfo=timezone.utc),
                               source="nvd:nvd@nist.gov", attrs={"version": "3.1"}))
    store.close()

    # the OSV record lands on the SAME cve node with its own (10.0) score
    osv.main(["import", str(LOG4SHELL), "--namespace", "netsec", "--db", db])

    store = SqliteStore(db)
    try:
        rows = [o for o in store.observations_for("netsec", cve) if o.predicate == "cvss_score"]
        sources = {o.source: o.object for o in rows}
        assert sources == {"nvd:nvd@nist.gov": 9.0, "ghsa": 10.0}     # one node, two sources
        pack = build_pack(store, AskRequest(namespace="netsec", subject=cve,
                                            question="how severe is this, and do the sources agree?",
                                            budget=1500))
        conflict = next(i for i in pack.items if i.kind == "conflict" and "cvss_score" in i.text)
        assert "ghsa" in conflict.text and "nvd:nvd@nist.gov" in conflict.text
        assert "10" in conflict.text and "9" in conflict.text
        assert conflict.citations and all(c.observation_id for c in conflict.citations)
    finally:
        store.close()


def _load(path: Path) -> dict:
    import json
    return json.loads(path.read_text())
