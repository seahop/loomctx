"""STIX 2.1 interop (R-8): bundle -> envelopes -> store -> bundle.

The fixture is an APT-style bundle: an intrusion set uses a malware that
targets an identity, an indicator for the malware's C2 domain, a sighting
of the malware at that identity, the vulnerability it exploits
(CVE-2014-0160, so the STIX object lands on the same entity the KEV/NVD
connector writes), a report about it all, and a revoked relationship."""

import json
import re
import uuid
from datetime import datetime, timezone

import pytest

from loom.connectors import stix
from loom.contracts import ClaimIn, DocumentIn, EntityRef, Provenance
from loom.ingest import load_direct
from loom.store.sqlite import SqliteStore

APT = "intrusion-set--4e78f27c-31b3-4a17-8e93-7b64f0b7c3e1"
MALWARE = "malware--31b940d4-6f7f-459a-80ea-9c1f17b58abc"
TARGET = "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
CTI_TEAM = "identity--311b2d2d-f010-4473-83ec-1edf84858f4c"
DOMAIN = "domain-name--ecb120bf-2694-4902-a737-62b74539a41b"
INDICATOR = "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
VULN = "vulnerability--c7cab3fb-0822-43a5-b1ba-c9bab130a7f7"
REL_USES = "relationship--44298a74-ba52-4a5e-a35b-51fbd0d70c60"
REL_TARGETS = "relationship--9ee8fad6-2e50-4a3b-a1f3-1c0f6e1a4c11"
REL_INDICATES = "relationship--a3f05d3a-3f4f-4f9d-9c2c-4d5e6f7a8b9c"
REL_EXPLOITS = "relationship--3f1b9a44-6b7c-4d8e-9f0a-1b2c3d4e5f60"
REL_REVOKED = "relationship--0aa27c3d-7f1e-4c2b-8d3e-9f0a1b2c3d4e"
SIGHTING = "sighting--ee20065d-2555-424f-ad9e-0f8428623c75"
REPORT = "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3"

BUNDLE = {"type": "bundle", "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d", "objects": [
    {"type": "identity", "spec_version": "2.1", "id": CTI_TEAM, "created": "2026-01-10T09:00:00.000Z",
     "modified": "2026-01-10T09:00:00.000Z", "name": "ACME CTI", "identity_class": "organization"},
    {"type": "identity", "spec_version": "2.1", "id": TARGET, "created": "2026-01-10T09:00:00.000Z",
     "modified": "2026-01-10T09:00:00.000Z", "name": "Initech", "identity_class": "organization",
     "sectors": ["technology"]},
    {"type": "intrusion-set", "spec_version": "2.1", "id": APT, "created_by_ref": CTI_TEAM,
     "created": "2026-02-01T08:00:00.000Z", "modified": "2026-03-05T12:30:00.000Z", "name": "Bobcat Breakdown",
     "description": "A hobbyist group that graduated to ransomware.", "aliases": ["BOBCAT", "TA-4471"],
     "first_seen": "2025-11-01T00:00:00.000Z", "resource_level": "club", "confidence": 60},
    {"type": "malware", "spec_version": "2.1", "id": MALWARE, "created_by_ref": CTI_TEAM,
     "created": "2026-02-01T08:00:00.000Z", "modified": "2026-02-01T08:00:00.000Z", "name": "Poison Ivy",
     "malware_types": ["remote-access-trojan"], "is_family": True,
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]},
    {"type": "vulnerability", "spec_version": "2.1", "id": VULN, "created": "2026-02-01T08:00:00.000Z",
     "modified": "2026-02-01T08:00:00.000Z", "name": "Heartbleed",
     "description": "OpenSSL TLS heartbeat read overrun.",
     "external_references": [{"source_name": "cve", "external_id": "CVE-2014-0160"},
                             {"source_name": "nvd", "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"}]},
    {"type": "domain-name", "spec_version": "2.1", "id": DOMAIN, "value": "c2.bobcat.example",
     "resolves_to_refs": ["ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd"]},
    {"type": "indicator", "spec_version": "2.1", "id": INDICATOR, "created_by_ref": CTI_TEAM,
     "created": "2026-02-02T08:00:00.000Z", "modified": "2026-02-02T08:00:00.000Z", "name": "Bobcat C2 domain",
     "indicator_types": ["malicious-activity"], "pattern": "[domain-name:value = 'c2.bobcat.example']",
     "pattern_type": "stix", "valid_from": "2026-02-02T00:00:00.000Z", "valid_until": "2026-08-01T00:00:00.000Z",
     "confidence": 85},
    {"type": "relationship", "spec_version": "2.1", "id": REL_USES, "created_by_ref": CTI_TEAM,
     "created": "2026-02-01T08:00:00.000Z", "modified": "2026-02-01T08:00:00.000Z",
     "relationship_type": "uses", "source_ref": APT, "target_ref": MALWARE, "confidence": 70,
     "start_time": "2025-12-01T00:00:00.000Z"},
    {"type": "relationship", "spec_version": "2.1", "id": REL_TARGETS, "created_by_ref": CTI_TEAM,
     "created": "2026-02-01T08:00:00.000Z", "modified": "2026-02-01T08:00:00.000Z",
     "relationship_type": "targets", "source_ref": MALWARE, "target_ref": TARGET,
     "start_time": "2026-01-15T00:00:00.000Z", "stop_time": "2026-02-20T00:00:00.000Z",
     "description": "Spear-phishing wave against Initech finance."},
    {"type": "relationship", "spec_version": "2.1", "id": REL_INDICATES,
     "created": "2026-02-02T08:00:00.000Z", "modified": "2026-02-02T08:00:00.000Z",
     "relationship_type": "indicates", "source_ref": INDICATOR, "target_ref": MALWARE},
    {"type": "relationship", "spec_version": "2.1", "id": REL_EXPLOITS, "created_by_ref": CTI_TEAM,
     "created": "2026-02-01T08:00:00.000Z", "modified": "2026-02-01T08:00:00.000Z",
     "relationship_type": "exploits", "source_ref": MALWARE, "target_ref": VULN},
    {"type": "relationship", "spec_version": "2.1", "id": REL_REVOKED, "revoked": True,
     "created": "2026-02-01T08:00:00.000Z", "modified": "2026-02-09T08:00:00.000Z",
     "relationship_type": "attributed-to", "source_ref": APT, "target_ref": TARGET},
    {"type": "sighting", "spec_version": "2.1", "id": SIGHTING, "created_by_ref": CTI_TEAM,
     "created": "2026-02-10T08:00:00.000Z", "modified": "2026-02-10T08:00:00.000Z", "count": 3,
     "sighting_of_ref": MALWARE, "where_sighted_refs": [TARGET],
     "first_seen": "2026-02-05T00:00:00.000Z", "last_seen": "2026-02-09T00:00:00.000Z"},
    {"type": "report", "spec_version": "2.1", "id": REPORT, "created_by_ref": CTI_TEAM,
     "created": "2026-03-01T08:00:00.000Z", "modified": "2026-03-01T08:00:00.000Z",
     "name": "Bobcat Breakdown targets Initech", "report_types": ["threat-report"],
     "published": "2026-03-01T08:00:00.000Z",
     "description": "Bobcat Breakdown deployed Poison Ivy against Initech via Heartbleed-vulnerable hosts.",
     "object_refs": [APT, MALWARE, TARGET, REL_USES]},
    {"type": "marking-definition", "spec_version": "2.1", "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
     "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp", "definition": {"tlp": "amber"}},
]}


def _index(envs):
    claims = [e for e in envs if isinstance(e, ClaimIn)]
    docs = [e for e in envs if isinstance(e, DocumentIn)]
    by_pred: dict[str, list[ClaimIn]] = {}
    for c in claims:
        by_pred.setdefault(c.predicate, []).append(c)
    return claims, docs, by_pred


def test_bundle_to_envelopes_default_mapping():
    stats: dict[str, int] = {}
    envs = stix.bundle_to_envelopes(BUNDLE, "netsec", stats=stats)
    claims, docs, by_pred = _index(envs)
    assert isinstance(envs[0], DocumentIn)                                  # documents first (D-039)
    assert stats["revoked"] == 1 and stats["skipped"] == 1 and stats["document"] == 1
    assert stats["relationship"] == 4 and stats["sighting"] == 1

    uses = by_pred["uses"][0]
    assert uses.subject == EntityRef(type="intrusion_set", key="Bobcat Breakdown")
    assert uses.object == EntityRef(type="malware", key="Poison Ivy")
    assert uses.confidence == 0.7 and uses.source == "ACME CTI"             # created_by_ref -> identity name
    assert uses.valid_from == datetime(2025, 12, 1, tzinfo=timezone.utc) and uses.valid_to is None
    assert uses.observed_at == datetime(2026, 2, 1, 8, tzinfo=timezone.utc)
    assert uses.attrs["stix_id"] == REL_USES and uses.attrs["stix_type"] == "relationship"
    assert uses.event_id == f"stix:{REL_USES}:20260201T080000:uses"
    assert uses.provenance == Provenance(artifact_event_id=f"stix:{REPORT}:20260301T080000:doc")  # listed by the report

    targets = by_pred["targets"][0]
    assert targets.object == EntityRef(type="identity", key="Initech")
    assert targets.valid_to == datetime(2026, 2, 20, tzinfo=timezone.utc)
    assert targets.attrs["description"].startswith("Spear-phishing")
    assert targets.confidence == 1.0                                        # no confidence -> the contract default
    indicates = by_pred["indicates"][0]
    assert indicates.subject == EntityRef(type="indicator", key="Bobcat C2 domain")
    assert indicates.source == "stix" and indicates.provenance is None      # no created_by_ref, not in the report
    assert "attributed_to" not in by_pred                                   # revoked -> skipped

    # the STIX vulnerability lands on the KEV/NVD connector's entity
    exploits = by_pred["exploits"][0]
    assert exploits.object == EntityRef(type="cve", key="CVE-2014-0160")
    assert [c.subject for c in by_pred["summary"] if c.subject.type == "cve"] == [EntityRef(type="cve", key="CVE-2014-0160")]
    assert any(c.subject.type == "cve" and c.predicate == "name" and c.object == "Heartbleed" for c in claims)

    # sighting: malware sighted_by identity, window + count
    seen = by_pred["sighted_by"][0]
    assert seen.subject == EntityRef(type="malware", key="Poison Ivy")
    assert seen.object == EntityRef(type="identity", key="Initech")
    assert seen.valid_from == datetime(2026, 2, 5, tzinfo=timezone.utc)
    assert seen.valid_to == datetime(2026, 2, 9, tzinfo=timezone.utc)
    assert seen.attrs["count"] == 3

    # object properties -> scalar claims; lists fan out, indicator validity rides on the pattern
    apt = EntityRef(type="intrusion_set", key="Bobcat Breakdown")
    assert {c.object for c in by_pred["alias"] if c.subject == apt} == {"BOBCAT", "TA-4471"}
    assert [c.event_id for c in by_pred["alias"] if c.subject == apt] == [
        f"stix:{APT}:20260305T123000:alias:0", f"stix:{APT}:20260305T123000:alias:1"]
    summary = [c for c in by_pred["summary"] if c.subject == apt][0]
    assert summary.confidence == 0.6 and summary.observed_at == datetime(2026, 3, 5, 12, 30, tzinfo=timezone.utc)
    assert summary.attrs["created"] == "2026-02-01T08:00:00.000Z"        # `modified` is the assertion time
    pattern = by_pred["pattern"][0]
    assert pattern.object.startswith("[domain-name:value") and pattern.confidence == 0.85
    assert pattern.valid_from == datetime(2026, 2, 2, tzinfo=timezone.utc)
    assert pattern.valid_to == datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert by_pred["is_family"][0].object is True
    assert by_pred["kill_chain_phase"][0].object == "mitre-attack:command-and-control"
    assert by_pred["malware_type"][0].object == "remote-access-trojan"
    assert by_pred["sector"][0].subject == EntityRef(type="identity", key="Initech")
    # an SCO keyed by its value; a dangling ref keeps the edge keyed by the STIX id
    resolves = by_pred["resolves_to"][0]
    assert resolves.subject == EntityRef(type="domain", key="c2.bobcat.example")
    assert resolves.object == EntityRef(type="ip", key="ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd")

    # the report is a document carrying the objects it is about
    doc = docs[0]
    assert doc.filename == f"{REPORT}.txt" and doc.source == "ACME CTI"
    assert doc.text.startswith("Bobcat Breakdown targets Initech\n\n")
    assert doc.attrs["object_refs"] == [APT, MALWARE, TARGET, REL_USES]
    assert doc.attrs["report_types"] == ["threat-report"]

    # deterministic: a re-import is idempotent
    again = stix.bundle_to_envelopes(BUNDLE, "netsec")
    assert [e.event_id for e in again] == [e.event_id for e in envs]
    assert len({e.event_id for e in envs}) == len(envs)


def test_mapping_overrides_types_and_predicates():
    mapping = {"entity_types": {"identity": "org"}, "predicates": {"targets": "attacks"},
               "properties": {"description": "description"}, "sighting": "seen_at"}
    _, _, by_pred = _index(stix.bundle_to_envelopes(BUNDLE, "netsec", mapping))
    assert "targets" not in by_pred and by_pred["attacks"][0].object == EntityRef(type="org", key="Initech")
    assert "summary" not in by_pred and by_pred["description"]
    assert by_pred["seen_at"][0].object.type == "org"
    reg = stix.schema("netsec", mapping)
    names = {p.name for p in reg.predicates}
    assert {"attacks", "seen_at", "description", "uses", "attributed_to"} <= names and "targets" not in names
    assert {"org", "cve", "malware", "intrusion_set", "ip", "domain"} <= {t.name for t in reg.entity_types}
    assert not reg.strict


def test_revoked_and_malformed_objects_are_skipped_not_fatal():
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "relationship", "id": "relationship--x", "relationship_type": "uses", "source_ref": APT},  # no target
        {"type": "sighting", "id": "sighting--y", "created": "2026-01-01T00:00:00Z", "count": 2,
         "sighting_of_ref": MALWARE},                                                            # no where
        {"type": "note", "id": "note--z", "created": "2026-01-01T00:00:00Z", "content": "  "},   # empty
        "not-an-object",
        {"type": "malware", "id": "malware--w", "name": "Nameless", "revoked": True},
    ]}
    stats: dict[str, int] = {}
    envs = stix.bundle_to_envelopes(bundle, "netsec", stats=stats)
    assert stats == {"skipped": 2, "sighting": 1, "revoked": 1}
    assert len(envs) == 1 and envs[0].predicate == "sighted_count" and envs[0].object == 2
    assert envs[0].subject == EntityRef(type="malware", key=MALWARE)      # dangling: keyed by the id


# ------------------------------------------------------------------- export #

STIX_ID = re.compile(r"^[a-z][a-z0-9-]*[a-z0-9]--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
STIX_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def _assert_valid_bundle(bundle: dict) -> dict[str, dict]:
    assert bundle["type"] == "bundle" and STIX_ID.match(bundle["id"])
    by_id = {}
    for obj in bundle["objects"]:
        assert STIX_ID.match(obj["id"]) and obj["id"].startswith(obj["type"] + "--")
        assert obj["id"] not in by_id
        by_id[obj["id"]] = obj
        assert obj["spec_version"] == "2.1"
        for key in obj:
            assert key.islower() and re.match(r"^[a-z0-9_]+$", key)
        if obj["type"] in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "mac-addr"):
            assert obj["value"]
        elif obj["type"] in ("user-account", "file"):
            continue
        else:
            assert STIX_TS.match(obj["created"]) and STIX_TS.match(obj["modified"])
            assert obj["created"] <= obj["modified"]
        if obj["type"] == "relationship":
            assert obj["relationship_type"] and obj["source_ref"] and obj["target_ref"]
            assert 0 <= obj["confidence"] <= 100
        elif obj["type"] == "sighting":
            assert obj["sighting_of_ref"] and obj.get("count", 1) >= 1
        elif obj["type"] not in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "mac-addr",
                                 "user-account", "file"):
            assert obj["name"]
        if obj["type"] == "vulnerability":
            assert any(r["source_name"] == "cve" for r in obj.get("external_references", []))
    for obj in bundle["objects"]:
        for key in ("source_ref", "target_ref", "sighting_of_ref", "created_by_ref"):
            if key in obj:
                assert obj[key] in by_id, f"{key} of {obj['id']} dangles"
        for key in ("where_sighted_refs", "object_refs"):
            for target in obj.get(key, []):
                assert target in by_id
    return by_id


def test_round_trip_through_a_store(tmp_path):
    db = tmp_path / "stix.db"
    stats: dict[str, int] = {}
    envs = stix.bundle_to_envelopes(BUNDLE, "netsec", stats=stats)
    lines = (e.model_dump_json(exclude_none=True) + "\n" for e in envs)
    totals = load_direct(str(db), lines, 100)
    assert totals["recorded"] == sum(1 for e in envs if isinstance(e, ClaimIn))
    store = SqliteStore(db)
    try:
        observations = list(store.iter_observations("netsec"))
        bundle = stix.observations_to_bundle(observations, "netsec")
    finally:
        store.close()
    by_id = _assert_valid_bundle(bundle)
    by_type: dict[str, list[dict]] = {}
    for obj in by_id.values():
        by_type.setdefault(obj["type"], []).append(obj)

    # every source became an identity; relationships cite their observation
    sources = {o["name"] for o in by_type["identity"] if "x_loom_source" in o}
    assert sources == {"ACME CTI", "stix"}
    def label(sid):
        return by_id[sid].get("name") or by_id[sid].get("value")

    rels = {(label(r["source_ref"]), r["relationship_type"], label(r["target_ref"])): r
            for r in by_type["relationship"]}
    assert ("c2.bobcat.example", "resolves-to", "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd") in rels
    uses = rels[("Bobcat Breakdown", "uses", "Poison Ivy")]
    assert uses["confidence"] == 70 and uses["start_time"] == "2025-12-01T00:00:00.000Z"
    assert "stop_time" not in uses
    assert uses["x_loom_observation_id"] in {o.id for o in observations}
    assert by_id[uses["created_by_ref"]]["name"] == "ACME CTI"
    targets = rels[("Poison Ivy", "targets", "Initech")]
    assert targets["stop_time"] == "2026-02-20T00:00:00.000Z" and targets["description"].startswith("Spear")
    # the CVE entity is a vulnerability with the cve external reference
    exploits = rels[("Poison Ivy", "exploits", "CVE-2014-0160")]
    vuln = by_id[exploits["target_ref"]]
    assert vuln["external_references"] == [{"source_name": "cve", "external_id": "CVE-2014-0160"}]
    assert vuln["description"] == "OpenSSL TLS heartbeat read overrun."
    assert vuln["x_loom_entity_type"] == "cve"
    # the sighting round-trips as a sighting
    sighting = by_type["sighting"][0]
    assert by_id[sighting["sighting_of_ref"]]["name"] == "Poison Ivy"
    assert [by_id[w]["name"] for w in sighting["where_sighted_refs"]] == ["Initech"]
    assert sighting["count"] == 3 and sighting["first_seen"] == "2026-02-05T00:00:00.000Z"
    # scalars sit on their entity: mapped properties + every observation, cited
    apt = [o for o in by_type["intrusion-set"]][0]
    assert apt["name"] == "Bobcat Breakdown" and sorted(apt["aliases"]) == ["BOBCAT", "TA-4471"]
    assert apt["description"].startswith("A hobbyist") and apt["resource_level"] == "club"
    assert {r["predicate"] for r in apt["x_loom_observations"]} >= {"summary", "alias", "resource_level", "name"}
    assert all(STIX_TS.match(r["observed_at"]) and r["id"] for r in apt["x_loom_observations"])
    malware = by_type["malware"][0]
    assert malware["is_family"] is True and malware["malware_types"] == ["remote-access-trojan"]
    assert malware["kill_chain_phases"] == [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]
    indicator = by_type["indicator"][0]
    assert indicator["pattern"].startswith("[domain-name") and indicator["pattern_type"] == "stix"
    assert indicator["valid_from"] == "2026-02-02T00:00:00.000Z" and indicator["valid_until"] == "2026-08-01T00:00:00.000Z"
    # SCOs: deterministic spec ids (uuid5 over the value), and the ip keyed by a STIX id is an ipv4-addr
    domain = by_type["domain-name"][0]
    assert domain["value"] == "c2.bobcat.example"
    assert domain["id"] == "domain-name--" + str(uuid.uuid5(stix.SCO_UUID_NS, '{"value":"c2.bobcat.example"}'))
    # ids are deterministic across exports
    again = stix.observations_to_bundle(observations, "netsec")
    assert {o["id"] for o in again["objects"]} == set(by_id)

    # ... and importing the export lands on the same entities/predicates
    _, _, by_pred = _index(stix.bundle_to_envelopes(bundle, "netsec"))
    assert by_pred["uses"][0].subject == EntityRef(type="intrusion_set", key="Bobcat Breakdown")
    assert by_pred["exploits"][0].object == EntityRef(type="cve", key="CVE-2014-0160")
    assert by_pred["sighted_by"][0].attrs["count"] == 3
    assert by_pred["uses"][0].source == "ACME CTI"


def test_export_of_loom_native_types_uses_custom_objects_and_scalars():
    from loom.contracts import Observation
    now = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)

    def obs(i, subject, pred, obj, **kw):
        return Observation(id=f"obs-{i}", namespace="netsec", subject=subject, predicate=pred, object=obj,
                           observed_at=now, recorded_at=now, source="inventory", confidence=0.9, **kw)

    host = EntityRef(type="host", key="web-01")
    observations = [
        obs(1, host, "has_ip", EntityRef(type="ip", key="10.0.4.7"), valid_from=now),
        obs(2, host, "has_ip", EntityRef(type="ip", key="2001:db8::7")),
        obs(3, host, "runs_os", "ubuntu-24.04"),
        obs(4, host, "owned_by", EntityRef(type="user", key="jdoe")),
        obs(5, EntityRef(type="ip", key="10.0.4.7"), "leased_to", host, valid_to=now),
        obs(6, host, "sighted_by", EntityRef(type="identity", key="SOC"), attrs={"count": 2}),
    ]
    bundle = stix.observations_to_bundle(observations, "netsec")
    by_id = _assert_valid_bundle(bundle)
    types = {o["type"] for o in by_id.values()}
    assert {"x-loom-host", "ipv4-addr", "ipv6-addr", "user-account", "identity", "relationship", "sighting"} <= types
    hostobj = [o for o in by_id.values() if o["type"] == "x-loom-host"][0]
    assert hostobj["name"] == "web-01" and hostobj["x_loom_entity_type"] == "host"
    assert hostobj["x_loom_observations"][0]["predicate"] == "runs_os"
    assert "runs_os" not in hostobj                                        # unmapped scalars are not invented properties
    rels = [o for o in by_id.values() if o["type"] == "relationship"]
    assert {r["relationship_type"] for r in rels} == {"has-ip", "owned-by", "leased-to"}
    ipv6 = [o for o in by_id.values() if o["type"] == "ipv6-addr"][0]
    assert ipv6["value"] == "2001:db8::7"
    user = [o for o in by_id.values() if o["type"] == "user-account"][0]
    assert user["user_id"] == "jdoe"
    assert [r for r in rels if r["relationship_type"] == "leased-to"][0]["stop_time"] == "2026-09-01T12:00:00.000Z"


# ---------------------------------------------------------------------- CLI #

def test_cli_import_export_emit_schema(tmp_path, capsys):
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(BUNDLE))
    db = tmp_path / "cli.db"
    stix.main(["import", str(bundle_path), "--namespace", "netsec", "--db", str(db)])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["recorded"] > 0 and out["accepted"] == 1 and out["envelopes"]["relationship"] == 4
    store = SqliteStore(db)
    try:
        reg = store.get_schema("netsec")
        assert reg is not None and {"uses", "sighted_by"} <= {p.name for p in reg.predicates}
        facts = store.observations_for("netsec", EntityRef(type="cve", key="CVE-2014-0160"))
        assert {o.predicate for o in facts} >= {"exploits", "summary", "name"}
    finally:
        store.close()
    # a second import is a no-op (event ids dedupe; the loader reports the
    # replayed rows as recorded, the store does not grow)
    def count():
        store = SqliteStore(db)
        try:
            return sum(1 for _ in store.iter_observations("netsec")), sum(1 for _ in store.iter_artifacts("netsec"))
        finally:
            store.close()

    before = count()
    stix.main(["import", str(bundle_path), "--namespace", "netsec", "--db", str(db)])
    capsys.readouterr()
    assert count() == before and before[1] == 1

    out_path = tmp_path / "export.json"
    stix.main(["export", "--namespace", "netsec", "--db", str(db), "--out", str(out_path)])
    exported = json.loads(out_path.read_text())
    _assert_valid_bundle(exported)
    assert any(o["type"] == "relationship" and o["relationship_type"] == "uses" for o in exported["objects"])

    stix.main(["emit", str(bundle_path), "--namespace", "netsec"])
    captured = capsys.readouterr()
    lines = [json.loads(l) for l in captured.out.strip().splitlines()]
    assert lines[0]["kind"] == "document" and all("event_id" in l for l in lines)
    assert json.loads(captured.err.strip().splitlines()[-1])["envelopes"]["document"] == 1

    stix.main(["schema", "--namespace", "netsec"])
    reg = json.loads(capsys.readouterr().out)
    assert reg["namespace"] == "netsec" and reg["strict"] is False

    with pytest.raises(SystemExit):
        stix.main(["import", str(bundle_path), "--db", str(db), "--url", "http://x"])


def test_cli_import_exits_non_zero_when_anything_is_refused(tmp_path, capsys):
    """D-063/S-36: a refused envelope fails the load (after the totals print)."""
    from loom.contracts import SchemaRegistration
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(BUNDLE))
    db = tmp_path / "strict.db"
    store = SqliteStore(db)
    try:
        store.put_schema(SchemaRegistration(namespace="netsec", strict=True))   # nothing registered
    finally:
        store.close()
    with pytest.raises(SystemExit, match="envelopes were refused by the store"):
        stix.main(["import", str(bundle_path), "--namespace", "netsec", "--db", str(db), "--no-schema"])
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["rejected"] > 0
