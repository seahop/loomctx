"""OCSF interop (R-8): vulnerability_finding events -> claims -> findings.

Fixture events are trimmed real-shape records (a scanner's finding with
CVSS/EPSS/packages, a resolved one, and a non-finding class that must be
ignored)."""

import json
from datetime import datetime, timezone

import pytest

from loom.connectors import ocsf
from loom.contracts import ClaimIn, EntityRef, Observation
from loom.ingest import load_direct
from loom.store.sqlite import SqliteStore

T0 = 1756728000000            # 2025-09-01T12:00:00Z
FINDING = {
    "class_uid": 2002, "category_uid": 2, "class_name": "Vulnerability Finding", "activity_id": 1,
    "type_uid": 200201, "time": T0, "severity_id": 5, "severity": "Critical", "status_id": 1, "status": "New",
    "metadata": {"version": "1.3.0", "product": {"name": "Acme Scanner", "vendor_name": "Acme"}},
    "device": {"hostname": "web-01", "ip": "10.0.4.7", "type_id": 1},
    "resources": [{"name": "web-01", "uid": "i-0abc", "type": "host"}],
    "finding_info": {"uid": "fnd-1001", "title": "OpenSSL heartbeat read overrun",
                     "first_seen_time": T0 - 86_400_000 * 3, "last_seen_time": T0},
    "vulnerabilities": [{
        "cve": {"uid": "cve-2014-0160", "desc": "  The (1) TLS and (2) DTLS implementations in OpenSSL ... allow  remote attackers to obtain sensitive information.",
                "cvss": [{"version": "3.1", "base_score": 7.5, "vector_string": "CVSS:3.1/AV:N/AC:L", "severity": "High"},
                         {"version": "2.0", "base_score": 5.0, "vector_string": "AV:N/AC:L", "severity": "Medium"}],
                "epss": {"score": 0.97, "percentile": 0.999, "version": "v2025.03.14"}},
        "title": "Heartbleed", "is_exploit_available": True, "is_fix_available": True,
        "affected_packages": [{"name": "openssl", "vendor_name": "OpenSSL", "version": "1.0.1e",
                               "fixed_in_version": "1.0.1g"}],
    }],
}
RESOLVED = {
    "class_uid": 2002, "activity_id": 2, "time": T0 + 3_600_000, "severity_id": 4, "status_id": 4,
    "metadata": {"product": {"name": "Acme Scanner"}},
    "resources": [{"hostname": "db-01", "type": "host"}],
    "finding_info": {"uid": "fnd-2002", "title": "CVE-2026-1337", "first_seen_time": T0},
    "vulnerabilities": [{"cve": {"uid": "CVE-2026-1337"}, "last_seen_time": T0 + 1_800_000},
                        {"cve": {"uid": "not-a-cve"}}],
}
OTHER_CLASS = {"class_uid": 2004, "time": T0, "finding_info": {"uid": "x"},
               "vulnerabilities": [{"cve": {"uid": "CVE-2026-9999"}}]}


def _by_pred(claims):
    out: dict[str, list[ClaimIn]] = {}
    for c in claims:
        out.setdefault(c.predicate, []).append(c)
    return out


def test_finding_maps_to_host_and_cve_claims():
    stats: dict[str, int] = {}
    claims = list(ocsf.events_to_envelopes([FINDING, RESOLVED, OTHER_CLASS, "junk"], "netsec", stats=stats))
    assert stats == {"finding": 2, "other_class": 1, "skipped": 1}
    by = _by_pred(claims)
    cve = EntityRef(type="cve", key="CVE-2014-0160")                          # uid upper-cased

    edge = [c for c in by["affected_by"] if c.subject.key == "web-01"][0]
    assert edge.object == cve and edge.source == "acme_scanner"                 # metadata.product.name
    assert edge.observed_at == datetime(2025, 9, 1, 12, tzinfo=timezone.utc)   # time (epoch ms)
    assert edge.valid_from == datetime(2025, 8, 29, 12, tzinfo=timezone.utc) and edge.valid_to is None
    assert edge.attrs["finding_uid"] == "fnd-1001" and edge.attrs["status"] == "New"
    assert edge.attrs["severity_id"] == 5 and edge.attrs["is_exploit_available"] is True
    assert edge.event_id == "ocsf:fnd-1001:20250901T120000:affected_by:CVE-2014-0160"

    scores = {c.source: (c.object, c.attrs["version"], c.attrs["vector"]) for c in by["cvss_score"]}
    assert scores == {"acme_scanner:cvss3.1": (7.5, "3.1", "CVSS:3.1/AV:N/AC:L"),
                      "acme_scanner:cvss2.0": (5.0, "2.0", "AV:N/AC:L")}
    assert {c.object for c in by["has_severity"]} == {"high", "medium"}
    assert by["epss_score"][0].object == 0.97 and by["epss_percentile"][0].object == 0.999
    assert by["epss_score"][0].attrs["model"] == "v2025.03.14"
    summary = by["summary"][0]
    assert summary.subject == cve and "  " not in summary.object and summary.attrs["truncated"] is False
    assert by["exploit_available"][0].object is True and by["fix_available"][0].object is True
    affects = by["affects"][0]
    assert affects.object == EntityRef(type="product", key="openssl:openssl")
    assert affects.attrs == {"finding_uid": "fnd-1001", "ocsf_class_uid": 2002, "version": "1.0.1e", "fixed_in": "1.0.1g"}
    for c in claims:
        if c.attrs.get("finding_uid") == "fnd-1001":
            assert c.observed_at == edge.observed_at

    # resolved: the edge closes at the vulnerability's last_seen; a non-CVE uid is dropped
    closed = [c for c in by["affected_by"] if c.subject.key == "db-01"]
    assert len(closed) == 1 and closed[0].object.key == "CVE-2026-1337"
    assert closed[0].valid_from == datetime(2025, 9, 1, 12, tzinfo=timezone.utc)
    assert closed[0].valid_to == datetime(2025, 9, 1, 12, 30, tzinfo=timezone.utc)
    assert closed[0].attrs["status"] == "resolved" and closed[0].attrs["severity"] == "high"
    assert "CVE-2026-9999" not in {c.object.key for c in by["affected_by"]}

    # deterministic: replays dedupe by event_id, a re-scan (new time) records anew
    again = list(ocsf.events_to_envelopes([FINDING], "netsec"))
    assert [c.event_id for c in again] == [c.event_id for c in claims if c.attrs.get("finding_uid") == "fnd-1001"]
    assert len({c.event_id for c in claims}) == len(claims)
    rescan = list(ocsf.events_to_envelopes([{**FINDING, "time": T0 + 86_400_000}], "netsec"))
    assert rescan[0].event_id != again[0].event_id


def test_finding_without_uid_or_time_still_maps():
    event = {"class_uid": 2002, "metadata": {"logged_time": T0},
             "finding_info": {"created_time": T0 - 1000},
             "vulnerabilities": [{"cve": {"uid": "CVE-2020-0001", "cvss": [{"base_score": "9.8"}]}}]}
    claims = list(ocsf.event_to_envelopes(event, "netsec"))
    assert [c.predicate for c in claims] == ["cvss_score"]                      # no host -> no edge
    assert claims[0].object == 9.8 and claims[0].source == "ocsf:cvss"
    assert claims[0].observed_at == datetime(2025, 9, 1, 11, 59, 59, tzinfo=timezone.utc)   # created_time
    assert claims[0].attrs["finding_uid"].startswith("sha256:")
    assert list(ocsf.event_to_envelopes({"class_uid": 2002}, "netsec")) == []


# ------------------------------------------------------------------- export #

REQUIRED = {"activity_id", "category_uid", "class_uid", "finding_info", "metadata", "severity_id",
            "time", "type_uid", "vulnerabilities"}


def _assert_valid_finding(record: dict) -> None:
    assert REQUIRED <= set(record)
    assert record["class_uid"] == 2002 and record["category_uid"] == 2
    assert record["type_uid"] == 2002 * 100 + record["activity_id"]
    assert record["severity_id"] in ocsf.SEVERITY and record["status_id"] in ocsf.STATUS
    assert isinstance(record["time"], int) and record["time"] > 1e12
    assert record["metadata"]["product"]["name"] and record["metadata"]["version"]
    assert record["finding_info"]["uid"] and record["finding_info"]["title"]
    for vuln in record["vulnerabilities"]:
        assert vuln["cve"]["uid"].startswith("CVE-")
        for metric in vuln["cve"].get("cvss", []):
            assert isinstance(metric["base_score"], float)
    assert record["unmapped"]["loom_observation_ids"]


def test_round_trip_through_a_store(tmp_path):
    db = tmp_path / "ocsf.db"
    claims = list(ocsf.events_to_envelopes([FINDING, RESOLVED], "netsec"))
    # a KEV-style fact from another connector joins the same CVE record
    claims.append(ClaimIn(namespace="netsec", event_id="kev:CVE-2014-0160", subject=EntityRef(type="cve", key="CVE-2014-0160"),
                          predicate="exploited_in_wild", object=True, source="cisa-kev",
                          observed_at=datetime(2025, 9, 2, tzinfo=timezone.utc)))
    load_direct(str(db), (c.model_dump_json(exclude_none=True) + "\n" for c in claims), 100)
    store = SqliteStore(db)
    try:
        observations = list(store.iter_observations("netsec"))
        findings = ocsf.observations_to_findings(observations, "netsec")
    finally:
        store.close()
    for record in findings:
        _assert_valid_finding(record)
    by_key = {(r.get("device", {}).get("hostname"), r["vulnerabilities"][0]["cve"]["uid"]): r for r in findings}
    assert set(by_key) == {("web-01", "CVE-2014-0160"), ("db-01", "CVE-2026-1337")}

    web = by_key[("web-01", "CVE-2014-0160")]
    assert web["severity_id"] == 4 and web["status_id"] == 1               # newest has_severity (high), open
    assert web["resources"] == [{"name": "web-01", "type": "host"}]
    assert web["finding_info"]["first_seen_time"] == T0 - 86_400_000 * 3
    vuln = web["vulnerabilities"][0]
    assert {(m["version"], m["base_score"]) for m in vuln["cve"]["cvss"]} == {("3.1", 7.5), ("2.0", 5.0)}
    assert vuln["cve"]["epss"] == {"score": 0.97, "percentile": 0.999}
    assert vuln["cve"]["desc"].startswith("The (1) TLS")
    assert vuln["is_exploit_available"] is True and vuln["is_fix_available"] is True
    assert vuln["affected_packages"] == [{"name": "openssl", "vendor_name": "openssl"}]
    assert "cisa-kev" in web["unmapped"]["loom_sources"] and "acme_scanner" in web["unmapped"]["loom_sources"]
    ids = {o.id for o in observations}
    assert set(web["unmapped"]["loom_observation_ids"]) <= ids
    assert web["unmapped"]["loom_observation_ids"][0] in {o.id for o in observations if o.predicate == "affected_by"}

    db01 = by_key[("db-01", "CVE-2026-1337")]
    assert db01["status_id"] == 4 and db01["status"] == "Resolved"
    assert db01["finding_info"]["last_seen_time"] == T0 + 1_800_000
    assert db01["severity_id"] == 4                                          # from the edge's severity_id

    # importing the export lands on the same entities
    back = _by_pred(ocsf.events_to_envelopes(findings, "netsec"))
    assert {(c.subject.key, c.object.key) for c in back["affected_by"]} == {("web-01", "CVE-2014-0160"), ("db-01", "CVE-2026-1337")}
    assert {c.object for c in back["cvss_score"]} == {7.5, 5.0}
    assert back["affected_by"][0].source == "loom"


def test_cve_facts_without_a_host_export_as_findings():
    now = datetime(2026, 9, 1, tzinfo=timezone.utc)

    def obs(i, pred, value, source="nvd:nvd@nist.gov", **attrs):
        return Observation(id=f"o{i}", namespace="netsec", subject=EntityRef(type="cve", key="CVE-2026-1337"),
                           predicate=pred, object=value, observed_at=now, recorded_at=now, source=source,
                           confidence=1.0, attrs=attrs)

    findings = ocsf.observations_to_findings([
        obs(1, "cvss_score", 9.8, version="3.1", vector="CVSS:3.1/AV:N"),
        obs(2, "cvss_score", 7.5, source="nvd:security@nginx.org", version="3.1"),
        obs(3, "has_severity", "critical"),
        obs(4, "exploited_in_wild", True, source="cisa-kev"),
        obs(5, "affects", EntityRef(type="product", key="nginx:nginx")),
        obs(6, "summary", "Heap overflow in nginx"),
    ], "netsec", now=now)
    assert len(findings) == 1
    record = findings[0]
    _assert_valid_finding(record)
    assert "resources" not in record and record["finding_info"]["title"] == "CVE-2026-1337"
    assert record["severity_id"] == 5 and record["severity"] == "Critical"
    vuln = record["vulnerabilities"][0]
    assert len(vuln["cve"]["cvss"]) == 2 and all(m["severity"] == "Critical" for m in vuln["cve"]["cvss"])
    assert vuln["is_exploit_available"] is True and vuln["affected_packages"] == [{"name": "nginx", "vendor_name": "nginx"}]
    assert sorted(record["unmapped"]["loom_observation_ids"]) == ["o1", "o2", "o3", "o4", "o5", "o6"]
    assert ocsf.observations_to_findings([], "netsec") == []


# ---------------------------------------------------------------------- CLI #

def test_cli_import_export_emit_schema(tmp_path, capsys):
    events = tmp_path / "events.ndjson"
    events.write_text("\n".join(json.dumps(e) for e in (FINDING, RESOLVED, OTHER_CLASS)) + "\n")
    db = tmp_path / "cli.db"
    ocsf.main(["import", str(events), "--namespace", "netsec", "--db", str(db)])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["recorded"] > 0 and out["events"] == {"finding": 2, "other_class": 1}
    store = SqliteStore(db)
    try:
        reg = store.get_schema("netsec")
        assert reg is not None and "affected_by" in {p.name for p in reg.predicates}
        assert {o.predicate for o in store.observations_for("netsec", EntityRef(type="host", key="web-01"))} == {"affected_by"}
    finally:
        store.close()
    def count():
        store = SqliteStore(db)
        try:
            return sum(1 for _ in store.iter_observations("netsec"))
        finally:
            store.close()

    before = count()
    ocsf.main(["import", str(events), "--namespace", "netsec", "--db", str(db)])      # idempotent
    capsys.readouterr()
    assert count() == before

    out_path = tmp_path / "findings.ndjson"
    ocsf.main(["export", "--namespace", "netsec", "--db", str(db), "--out", str(out_path)])
    records = [json.loads(l) for l in out_path.read_text().splitlines()]
    assert len(records) == 2
    for record in records:
        _assert_valid_finding(record)

    array = tmp_path / "events.json"
    array.write_text(json.dumps([FINDING]))
    ocsf.main(["emit", str(array), "--namespace", "netsec", "--source", "pinned"])
    captured = capsys.readouterr()
    lines = [json.loads(l) for l in captured.out.strip().splitlines()]
    assert lines and all(l["source"].startswith("pinned") for l in lines)
    assert json.loads(captured.err.strip().splitlines()[-1]) == {"events": {"finding": 1}}

    ocsf.main(["schema", "--namespace", "netsec"])
    assert json.loads(capsys.readouterr().out)["strict"] is False
    with pytest.raises(SystemExit):
        ocsf.main(["import", str(events), "--db", str(db), "--url", "http://x"])
