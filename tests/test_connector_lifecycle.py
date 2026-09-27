"""Source-record lifecycles through the connectors (hardening, 2026-09-24):
an OCSF finding that is resolved closes the host's exposure (its versions
are chained by recorded supersession, D-050), a suppressed one does not,
and a revised or revoked STIX relationship supersedes the version before
it — straight into a store and through the engine's batch API."""

import copy
import io
import json
import urllib.error
import urllib.parse
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from loomctx.connectors import ocsf, stix
from loomctx.context import build_pack
from loomctx.contracts import AskRequest, EntityRef
from loomctx.store.sqlite import SqliteStore

T0 = 1756728000000            # 2025-09-01T12:00:00Z
DAY = 86_400_000
OPEN = {
    "class_uid": 2002, "activity_id": 1, "time": T0, "severity_id": 5, "status_id": 1,
    "metadata": {"product": {"name": "Acme Scanner"}},
    "device": {"hostname": "web-01"},
    "finding_info": {"uid": "fnd-1001", "title": "Heartbleed", "first_seen_time": T0 - 3 * DAY,
                     "last_seen_time": T0},
    "vulnerabilities": [{"cve": {"uid": "CVE-2014-0160"}}],
}


def _version(base, when, **changes):
    event = copy.deepcopy(base)
    event["time"] = when
    event["finding_info"]["last_seen_time"] = when
    event.update(changes)
    return event


RESCAN = _version(OPEN, T0 + DAY, status_id=2)
RESOLVED = _version(OPEN, T0 + 2 * DAY, status_id="4", activity_id=2)     # "4": real producers send strings
SUPPRESSED = _version({**OPEN, "device": {"hostname": "app-01"},
                       "finding_info": {**OPEN["finding_info"], "uid": "fnd-3003"}},
                      T0 + DAY, status_id=3, activity_id=3)
HOST = EntityRef(type="host", key="web-01")
NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _exposure(store, host="web-01"):
    rows = [o for o in store.observations_for("netsec", EntityRef(type="host", key=host), limit=100)
            if o.predicate == "affected_by"]
    return sorted(rows, key=lambda o: o.observed_at)


def _route_urllib_to(client, monkeypatch):
    """urllib (what the connectors speak) -> the in-process engine."""
    class Resp:
        def __init__(self, body):
            self.body = body

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        url = urllib.parse.urlsplit(req.full_url)
        r = client.request(req.get_method(), url.path + ("?" + url.query if url.query else ""),
                           content=req.data, headers=dict(req.header_items()))
        if r.status_code >= 400:
            raise urllib.error.HTTPError(req.full_url, r.status_code, "error", r.headers, io.BytesIO(r.content))
        return Resp(r.content)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)


def _check_closed_chain(rows):
    assert len(rows) == 3
    first, rescan, resolved = rows
    assert first.valid_to is None and first.supersedes is None
    assert rescan.valid_to is None and rescan.supersedes == first.id       # a re-scan does not pile up open rows
    assert resolved.valid_to is not None and resolved.supersedes == rescan.id


def test_resolved_finding_closes_the_exposure(tmp_path, capsys):
    events = tmp_path / "scan.ndjson"
    events.write_text("".join(json.dumps(e) + "\n" for e in (OPEN, RESCAN, RESOLVED, SUPPRESSED)))
    db = tmp_path / "o.db"
    ocsf.main(["import", str(events), "--namespace", "netsec", "--db", str(db)])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["superseded"] == 2
    store = SqliteStore(db)
    try:
        _check_closed_chain(_exposure(store))
        # the reader: every open version is history now, and the one that
        # is current says the exposure ended
        pack = build_pack(store, AskRequest(namespace="netsec", subject=HOST, budget=1500,
                                           question="is web-01 affected by heartbleed?", valid_at=NOW))
        open_items = [i for i in pack.items if "affected_by" in i.text]
        assert open_items and all("[superseded by" in i.text for i in open_items)
        # suppressed is muted, not fixed: still open, status kept
        muted = _exposure(store, "app-01")
        assert len(muted) == 1 and muted[0].valid_to is None and muted[0].attrs["status"] == "suppressed"
        # export round-trips both states
        findings = ocsf.observations_to_findings(store.iter_observations("netsec"), "netsec")
        by_host = {f["device"]["hostname"]: f for f in findings if "device" in f}
        assert by_host["web-01"]["status_id"] == 4 and by_host["app-01"]["status_id"] == 3
    finally:
        store.close()
    # re-importing the same scan changes nothing
    before = sum(1 for _ in SqliteStore(db).iter_observations("netsec"))
    ocsf.main(["import", str(events), "--namespace", "netsec", "--db", str(db)])
    capsys.readouterr()
    assert sum(1 for _ in SqliteStore(db).iter_observations("netsec")) == before


def test_findings_chain_across_runs_and_out_of_order(tmp_path, capsys):
    """Each nightly file carries the finding's state that night: the chain
    continues from the store. An older event arriving late supersedes
    nothing newer."""
    db = tmp_path / "runs.db"
    for i, event in enumerate((OPEN, RESCAN, RESOLVED)):
        path = tmp_path / f"night-{i}.json"
        path.write_text(json.dumps(event, indent=2))          # pretty-printed single object
        ocsf.main(["import", str(path), "--namespace", "netsec", "--db", str(db), "--no-schema"])
    capsys.readouterr()
    store = SqliteStore(db)
    try:
        rows = _exposure(store)
        _check_closed_chain(rows)
    finally:
        store.close()
    late = tmp_path / "late.json"
    late.write_text(json.dumps(_version(OPEN, T0 + DAY // 2, status_id=2)))
    ocsf.main(["import", str(late), "--namespace", "netsec", "--db", str(db), "--no-schema"])
    capsys.readouterr()
    store = SqliteStore(db)
    try:
        rows = _exposure(store)
        assert len(rows) == 4
        assert rows[-1].valid_to is not None                     # still the newest, still closed
        assert not any(r.supersedes == rows[-1].id for r in rows)
    finally:
        store.close()


def test_finding_chain_through_the_batch_api(tmp_path, monkeypatch, capsys):
    """Over HTTP: prior versions are looked up via the observations route
    and a version in the same batch is flushed first (the batch door
    refuses to supersede a row of the same batch)."""
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "api.db"))
    from loomctx.api.http import app
    events = tmp_path / "scan.ndjson"
    events.write_text("".join(json.dumps(e) + "\n" for e in (OPEN, RESCAN)))
    with TestClient(app) as client:
        _route_urllib_to(client, monkeypatch)
        ocsf.main(["import", str(events), "--namespace", "netsec", "--url", "http://loomctx"])
        more = tmp_path / "later.ndjson"
        more.write_text(json.dumps(RESOLVED) + "\n")
        ocsf.main(["import", str(more), "--namespace", "netsec", "--url", "http://loomctx"])
        out = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
        assert [o["rejected"] for o in out] == [0, 0] and [o["superseded"] for o in out] == [1, 1]
        rows = client.get("/v1/entities/host/web-01/observations?namespace=netsec").json()["observations"]
    store = SqliteStore(tmp_path / "api.db")
    try:
        _check_closed_chain(_exposure(store))
    finally:
        store.close()
    assert len([r for r in rows if r["predicate"] == "affected_by"]) == 3


def test_a_write_only_key_imports_without_cross_run_chaining(monkeypatch, capsys):
    """The usual shipper grant cannot read: the lookup's 403 degrades to
    in-run chaining with a warning instead of failing the import."""
    from loomctx.connectors.chain import HttpSink, keyed_by, load_chained
    posted = []

    class Resp:
        def __init__(self, body):
            self.body = body

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        if req.get_method() == "GET":
            raise urllib.error.HTTPError(req.full_url, 403, "no", {}, io.BytesIO(b"key may not read"))
        items = [json.loads(line) for line in req.data.decode().splitlines()]
        posted.append(items)
        base = sum(len(p) for p in posted[:-1])
        return Resp(json.dumps({"total": len(items), "recorded": len(items), "accepted": 0, "rejected": 0,
                                "results": [{"index": i, "status": "recorded", "observation_id": f"o{base + i}"}
                                            for i in range(len(items))]}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    envs = [e for e in ocsf.events_to_envelopes([OPEN, RESCAN], "netsec")
            if e.predicate == "affected_by"]          # identity / shape claims: tested apart
    totals = load_chained(envs, HttpSink("http://loomctx", "k"), keyed_by("finding_uid", {"affected_by"}))
    assert totals["recorded"] == 2 and totals["superseded"] == 1        # in-run chaining still works
    assert posted[1][0]["supersedes"] == "o0"
    assert "WITHOUT version chaining" in capsys.readouterr().err


@pytest.mark.parametrize("text", [
    json.dumps(OPEN, indent=2),
    json.dumps([OPEN, RESCAN], indent=2),
    json.dumps(OPEN) + "\n" + json.dumps(RESCAN) + "\n",
    json.dumps(OPEN),
])
def test_iter_events_reads_every_shape(tmp_path, text):
    path = tmp_path / "e.json"
    path.write_text(text)
    events = list(ocsf.iter_events(str(path)))
    assert events and all(e["class_uid"] == 2002 for e in events)


def test_status_mapping_follows_the_spec():
    assert ocsf.closes_exposure({"status_id": 4})
    assert ocsf.closes_exposure({"status_id": "4"})
    assert ocsf.closes_exposure({"status_id": 1, "activity_id": 3})          # a Close activity
    assert not ocsf.closes_exposure({"status_id": 3})                         # suppressed: muted, not fixed
    assert not ocsf.closes_exposure({"status_id": 3, "activity_id": 3})
    assert not ocsf.closes_exposure({"status_id": 5}) and not ocsf.closes_exposure({"status_id": "New"})
    claims = list(ocsf.event_to_envelopes({**OPEN, "status_id": "weird", "severity_id": None}, "netsec"))
    assert next(c for c in claims if c.predicate == "affected_by").attrs["status_id"] == 0


# ----------------------------------------------------------------------- STIX #

REL_ID = "relationship--6f1ab1b2-1111-4b8e-9c3b-000000000001"
MAL = {"type": "malware", "spec_version": "2.1", "id": "malware--6f1ab1b2-1111-4b8e-9c3b-000000000002",
       "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
       "name": "QuietRat", "is_family": True}
ACTOR = {"type": "threat-actor", "spec_version": "2.1", "id": "threat-actor--6f1ab1b2-1111-4b8e-9c3b-000000000003",
         "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z", "name": "APT Example"}
REL_V1 = {"type": "relationship", "spec_version": "2.1", "id": REL_ID, "relationship_type": "uses",
          "source_ref": ACTOR["id"], "target_ref": MAL["id"], "start_time": "2026-01-01T00:00:00Z",
          "created": "2026-01-02T00:00:00.000Z", "modified": "2026-01-02T00:00:00.000Z"}
REL_V2 = {**REL_V1, "modified": "2026-03-01T00:00:00.000Z", "stop_time": "2026-02-15T00:00:00Z"}
REL_REVOKED = {**REL_V1, "modified": "2026-04-01T00:00:00.000Z", "revoked": True}


def _bundle(path, *objects):
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--6f1ab1b2-1111-4b8e-9c3b-00000000000f",
                                "objects": list(objects)}))
    return str(path)


def _uses(store):
    actor = EntityRef(type="threat_actor", key="APT Example")
    return sorted((o for o in store.observations_for("netsec", actor, limit=100) if o.predicate == "uses"),
                  key=lambda o: o.observed_at)


def test_revised_and_revoked_relationships_supersede_their_prior_version(tmp_path, capsys):
    db = str(tmp_path / "s.db")
    stix.main(["import", _bundle(tmp_path / "v1.json", ACTOR, MAL, REL_V1), "--namespace", "netsec", "--db", db])
    stix.main(["import", _bundle(tmp_path / "v2.json", ACTOR, MAL, REL_V2), "--namespace", "netsec", "--db", db])
    store = SqliteStore(db)
    try:
        v1, v2 = _uses(store)
        assert v2.supersedes == v1.id and v2.valid_to is not None
    finally:
        store.close()
    stix.main(["import", _bundle(tmp_path / "v3.json", ACTOR, MAL, REL_REVOKED), "--namespace", "netsec", "--db", db])
    capsys.readouterr()
    store = SqliteStore(db)
    try:
        v1, v2, revoked = _uses(store)
        assert revoked.supersedes == v2.id and revoked.attrs["revoked"] is True
        assert revoked.valid_to is not None
        # a scope walk at a time the edge was valid under v1 no longer
        # has a current edge to follow once it is revoked: the revoked
        # row closes at its revocation, the earlier ones are history
        pack = build_pack(store, AskRequest(namespace="netsec", budget=1500, question="what does it use?",
                                            subject=EntityRef(type="threat_actor", key="APT Example")))
        uses = [i for i in pack.items if " uses " in f" {i.text} "]
        assert uses and sum("[superseded by" not in i.text for i in uses) <= 1
    finally:
        store.close()


def test_revocation_of_something_never_imported_is_skipped(tmp_path, capsys):
    db = str(tmp_path / "r.db")
    stix.main(["import", _bundle(tmp_path / "r.json", ACTOR, MAL, REL_REVOKED), "--namespace", "netsec", "--db", db])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["dropped_no_prior"] == 1
    store = SqliteStore(db)
    try:
        assert _uses(store) == []
    finally:
        store.close()
    # emit (no store to ask) keeps skipping revoked objects, as documented
    stix.main(["emit", _bundle(tmp_path / "e.json", ACTOR, MAL, REL_REVOKED), "--namespace", "netsec"])
    lines = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
    assert not any(line.get("predicate") == "uses" for line in lines)


# ------------------------------------------ one bad record is not the whole feed #

def test_one_malformed_record_does_not_abort_an_import(tmp_path):
    """A future timestamp or a field of the wrong shape in one record used
    to raise out of the generator and end the whole import."""
    import gzip
    from loomctx.connectors import vulns
    future = _version(OPEN, 4102444800000)                   # 2100-01-01: the contract refuses it
    stats = {}
    claims = list(ocsf.events_to_envelopes([future, RESCAN, {"class_uid": 2002, "vulnerabilities": 7}],
                                           "netsec", stats=stats))
    assert stats["invalid"] == 2 and stats["finding"] == 1 and claims

    bad = {**MAL, "id": "malware--6f1ab1b2-1111-4b8e-9c3b-00000000000a", "modified": "yesterday-ish"}
    stats = {}
    envs = stix.bundle_to_envelopes({"objects": [ACTOR, bad, MAL, REL_V1]}, "netsec", stats=stats)
    assert stats["invalid"] == 1 and stats["relationship"] == 1
    assert not any(e.attrs.get("stix_id") == bad["id"] for e in envs)

    item = {"cve": {"id": "CVE-2026-0001", "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2126-01-01T00:00:00.000", "vulnStatus": "Analyzed"}}
    good = {"cve": {"id": "CVE-2026-0002", "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000", "vulnStatus": "Analyzed"}}
    with gzip.open(tmp_path / "nvdcve-2.0-2026.json.gz", "wt") as fh:
        json.dump({"vulnerabilities": [item, good, {"nope": 1}]}, fh)
    stats = {}
    envs = list(vulns.envelopes(tmp_path, "netsec", [2026], {"nvd"}, stats=stats))
    assert stats["nvd_invalid"] == 2 and stats["nvd"] == 1 and envs[0].subject.key == "CVE-2026-0002"


# ------------------------------------------ export expresses versions (S-30) #

STIX_KEYS = ("type", "id", "created", "modified", "relationship_type", "start_time", "stop_time",
             "confidence", "revoked")


def _count(db, predicate=None):
    store = SqliteStore(db)
    try:
        return sum(1 for o in store.iter_observations("netsec") if predicate in (None, o.predicate))
    finally:
        store.close()


def _export_stix(tmp_path, db, name, *extra):
    out = tmp_path / name
    stix.main(["export", "--namespace", "netsec", "--db", db, "--out", str(out), *extra])
    return json.loads(out.read_text())


def _edges(bundle, kind="relationship"):
    return [{k: o[k] for k in STIX_KEYS if k in o} for o in bundle["objects"] if o["type"] == kind]


def test_stix_export_writes_versions_under_one_id(tmp_path, capsys):
    """STIX 2.1 §3.6: versions of one object share its id and `created`
    and differ in `modified`. The default export is the newest version
    only; --history writes each. Import -> export -> import is stable."""
    db = str(tmp_path / "a.db")
    for i, rel in enumerate((REL_V1, REL_V2)):
        stix.main(["import", _bundle(tmp_path / f"v{i}.json", ACTOR, MAL, rel), "--namespace", "netsec", "--db", db])
    newest = _export_stix(tmp_path, db, "newest.json")
    ids = [o["id"] for o in newest["objects"]]
    assert len(ids) == len(set(ids))                                   # one object per id
    assert _edges(newest) == [{"type": "relationship", "id": REL_ID, "created": "2026-01-02T00:00:00.000Z",
                               "modified": "2026-03-01T00:00:00.000Z", "relationship_type": "uses",
                               "start_time": "2026-01-01T00:00:00.000Z", "stop_time": "2026-02-15T00:00:00.000Z",
                               "confidence": 100}]
    history = _export_stix(tmp_path, db, "history.json", "--history")
    assert [(e["id"], e["created"], e["modified"], "stop_time" in e) for e in _edges(history)] == [
        (REL_ID, "2026-01-02T00:00:00.000Z", "2026-01-02T00:00:00.000Z", False),
        (REL_ID, "2026-01-02T00:00:00.000Z", "2026-03-01T00:00:00.000Z", True)]

    # back into the store it came from: nothing new, either form
    before = _count(db)
    for name in ("newest.json", "history.json"):
        stix.main(["import", str(tmp_path / name), "--namespace", "netsec", "--db", db])
    assert _count(db) == before

    # into a fresh store: the same current version (history: the same chain),
    # and exporting that store gives the same objects again
    for name, versions in (("newest.json", 1), ("history.json", 2)):
        fresh = str(tmp_path / f"fresh-{name}.db")
        stix.main(["import", str(tmp_path / name), "--namespace", "netsec", "--db", fresh])
        store = SqliteStore(fresh)
        try:
            rows = _uses(store)                        # the actor keeps its LoomCtx type (x_loomctx_entity_type)
            assert len(rows) == versions and all(r.supersedes == p.id for p, r in zip(rows, rows[1:]))
        finally:
            store.close()
        assert _edges(_export_stix(tmp_path, fresh, "again.json")) == _edges(newest)
    assert _edges(_export_stix(tmp_path, str(tmp_path / "fresh-history.json.db"), "again.json", "--history")) \
        == _edges(history)

    def facts(path):
        store = SqliteStore(path)
        try:
            return sorted((o.subject.type, o.subject.key, o.predicate, json.dumps(o.object, default=str),
                           o.observed_at.isoformat(), o.source, o.event_id) for o in store.iter_observations("netsec"))
        finally:
            store.close()

    # the whole store came across as recorded: sources, times, event ids
    assert facts(str(tmp_path / "fresh-history.json.db")) == facts(db)

    # a revocation is the object's last version, `revoked: true`
    stix.main(["import", _bundle(tmp_path / "rev.json", ACTOR, MAL, REL_REVOKED), "--namespace", "netsec", "--db", db])
    revoked = _export_stix(tmp_path, db, "revoked.json")
    (edge,) = _edges(revoked)
    assert edge["id"] == REL_ID and edge["revoked"] is True and edge["modified"] == "2026-04-01T00:00:00.000Z"
    before = _count(db)
    stix.main(["import", str(tmp_path / "revoked.json"), "--namespace", "netsec", "--db", db])
    capsys.readouterr()
    assert _count(db) == before


def test_stix_export_of_a_loomctx_native_chain():
    """A recorded supersession (D-050) with no STIX origin: the versions
    share an id derived from the first one; an edge corrected into
    something that is not a version of it ends revoked."""
    import uuid
    from loomctx.contracts import Observation
    t = [datetime(2026, 9, d, tzinfo=timezone.utc) for d in (1, 2, 3, 4)]
    host, ip = EntityRef(type="host", key="web-01"), EntityRef(type="ip", key="10.0.4.7")

    def obs(i, pred, obj, at, **kw):
        return Observation(id=f"o{i}", namespace="netsec", subject=host, predicate=pred, object=obj,
                           observed_at=at, recorded_at=at, source="inventory", confidence=1.0, **kw)

    rows = [obs(1, "has_ip", ip, t[0]), obs(2, "has_ip", ip, t[1], supersedes="o1", valid_to=t[1]),
            obs(3, "owned_by", EntityRef(type="user", key="jdoe"), t[0]),
            obs(4, "owner_note", "jdoe left; no owner", t[2], supersedes="o3")]
    bundle = stix.observations_to_bundle(rows, "netsec")
    rels = {r["relationship_type"]: r for r in bundle["objects"] if r["type"] == "relationship"}
    has_ip = rels["has-ip"]
    assert has_ip["id"] == f"relationship--{uuid.uuid5(stix.LOOMCTX_UUID_NS, 'o1')}"
    assert has_ip["x_loomctx_observation_id"] == "o2" and has_ip["created"] < has_ip["modified"]
    assert has_ip["stop_time"] == stix.stix_timestamp(t[1])
    owned = rels["owned-by"]
    assert owned["revoked"] is True and owned["x_loomctx_superseded_by"] == "o4"
    assert owned["modified"] == stix.stix_timestamp(t[2])
    history = stix.observations_to_bundle(rows, "netsec", history=True)
    versions = [(r["relationship_type"], r["modified"], r.get("revoked", False))
                for r in history["objects"] if r["type"] == "relationship"]
    assert versions == [("has-ip", stix.stix_timestamp(t[0]), False), ("has-ip", stix.stix_timestamp(t[1]), False),
                        ("owned-by", stix.stix_timestamp(t[0]), False), ("owned-by", stix.stix_timestamp(t[2]), True)]


def _finding_state(findings):
    return [(f["finding_info"]["uid"], f.get("device", {}).get("hostname"), f["activity_id"], f["status_id"],
             f["time"], f["finding_info"].get("first_seen_time"), f["finding_info"].get("last_seen_time"))
            for f in findings if "device" in f]


def _export_ocsf(tmp_path, db, *extra):
    out = tmp_path / "findings.ndjson"
    ocsf.main(["export", "--namespace", "netsec", "--db", db, "--out", str(out), *extra])
    return [json.loads(line) for line in out.read_text().splitlines()]


def test_ocsf_export_writes_one_finding_per_chain(tmp_path, capsys):
    """A finding's versions share finding_info.uid; the default export is
    its newest state (resolved), not one open finding per version."""
    events = tmp_path / "scan.ndjson"
    events.write_text("".join(json.dumps(e) + "\n" for e in (OPEN, RESCAN, RESOLVED)))
    db = str(tmp_path / "o.db")
    ocsf.main(["import", str(events), "--namespace", "netsec", "--db", db])
    from loomctx.contracts import ClaimIn
    from loomctx.ingest import load_direct
    nvd = ClaimIn(namespace="netsec", event_id="nvd:CVE-2014-0160:cvss", subject=EntityRef(type="cve", key="CVE-2014-0160"),
                  predicate="cvss_score", object=7.5, source="nvd:nvd@nist.gov", attrs={"version": "3.1"},
                  observed_at=datetime(2025, 9, 2, tzinfo=timezone.utc))
    load_direct(db, [nvd.model_dump_json() + "\n"], 10)
    newest = _export_ocsf(tmp_path, db)
    assert _finding_state(newest) == [("fnd-1001", "web-01", 3, 4, T0 + 2 * DAY, T0 - 3 * DAY, T0 + 2 * DAY)]
    assert newest[0]["type_uid"] == 200203
    history = _export_ocsf(tmp_path, db, "--history")
    assert [(uid, act, status) for uid, _, act, status, *_ in _finding_state(history)] == [
        ("fnd-1001", 1, 1), ("fnd-1001", 2, 2), ("fnd-1001", 3, 4)]

    # back into the same store: no new finding versions, still closed
    (tmp_path / "history.ndjson").write_text("".join(json.dumps(f) + "\n" for f in history))
    before = _count(db)
    ocsf.main(["import", str(tmp_path / "history.ndjson"), "--namespace", "netsec", "--db", db])
    store = SqliteStore(db)
    try:
        assert _count(db) == before           # the CVE facts it restates are replays too, not "loomctx" copies
        _check_closed_chain(_exposure(store))
    finally:
        store.close()
    # into a fresh store: the same chain, and the same findings out again
    fresh = str(tmp_path / "fresh.db")
    ocsf.main(["import", str(tmp_path / "history.ndjson"), "--namespace", "netsec", "--db", fresh])
    capsys.readouterr()
    store = SqliteStore(fresh)
    try:
        _check_closed_chain(_exposure(store))
        (score,) = [o for o in store.observations_for("netsec", EntityRef(type="cve", key="CVE-2014-0160"))
                    if o.predicate == "cvss_score"]
        assert (score.source, score.event_id, score.object, score.attrs) == (nvd.source, nvd.event_id, 7.5, nvd.attrs)
        assert {o.source for o in _exposure(store)} == {"acme_scanner"}
    finally:
        store.close()
    assert _finding_state(_export_ocsf(tmp_path, fresh, "--history")) == _finding_state(history)
    assert _finding_state(_export_ocsf(tmp_path, fresh)) == _finding_state(newest)


def test_ocsf_export_of_a_loomctx_native_chain():
    """Recorded supersessions with no OCSF origin: a correction that moves
    the finding to another host is its next version; one that names
    another CVE closes the old finding as Superseded."""
    from loomctx.contracts import Observation
    t = [datetime(2026, 9, d, tzinfo=timezone.utc) for d in (1, 2, 3)]
    heartbleed, other = EntityRef(type="cve", key="CVE-2014-0160"), EntityRef(type="cve", key="CVE-2026-1337")

    def obs(i, host, at, cve=heartbleed, **kw):
        return Observation(id=f"o{i}", namespace="netsec", subject=EntityRef(type="host", key=host),
                           predicate="affected_by", object=cve, observed_at=at, recorded_at=at,
                           source="inventory", confidence=1.0, **kw)

    rows = [obs(1, "web-01", t[0]), obs(2, "web-01", t[1], supersedes="o1", valid_to=t[1]),     # resolved
            obs(3, "web-02", t[0]), obs(4, "web-03", t[2], supersedes="o3"),                    # wrong host
            obs(5, "web-04", t[0]), obs(6, "web-04", t[2], cve=other, supersedes="o5")]         # wrong CVE
    findings = ocsf.observations_to_findings(rows, "netsec", now=t[2])
    state = {(f["finding_info"]["uid"], f["device"]["hostname"]): f for f in findings}
    assert set(state) == {("o1", "web-01"), ("o3", "web-03"), ("o5", "web-04"), ("o6", "web-04")}
    assert state[("o1", "web-01")]["status_id"] == 4 and state[("o1", "web-01")]["activity_id"] == 3
    assert state[("o1", "web-01")]["unmapped"]["loomctx_observation_ids"][0] == "o2"
    assert state[("o3", "web-03")]["status_id"] == 1 and state[("o3", "web-03")]["activity_id"] == 2
    gone = state[("o5", "web-04")]
    assert (gone["status_id"], gone["status"], gone["activity_id"]) == (99, "Superseded", 3)
    assert gone["unmapped"]["loomctx_superseded_by"] == "o6"
    assert state[("o6", "web-04")]["vulnerabilities"][0]["cve"]["uid"] == "CVE-2026-1337"
    history = ocsf.observations_to_findings(rows, "netsec", now=t[2], history=True)
    assert [(f["finding_info"]["uid"], f["device"]["hostname"], f["status_id"]) for f in history
            if f["finding_info"]["uid"] == "o3"] == [("o3", "web-02", 1), ("o3", "web-03", 1)]


def test_a_source_pinned_refresh_key_skips_a_registration_it_cannot_make(tmp_path, monkeypatch):
    """D-063: the nightly refresh (vulns-refresh.yaml) runs with a key pinned
    to the feed sources; the engine refuses it the registry (D-059), and the
    connector re-registered on every run — a 403 in the first two seconds.
    It now reads the registry first and registers only what is missing."""
    import hashlib
    import pytest
    from fastapi.testclient import TestClient
    from loomctx.connectors import vulns
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": [
        {"sha256": hashlib.sha256(b"admin").hexdigest(), "id": "admin", "namespaces": ["*"], "perms": "rw"},
        {"sha256": hashlib.sha256(b"refresh").hexdigest(), "id": "vulns-refresh", "namespaces": ["netsec"],
         "perms": "rw", "sources": ["nvd", "cisa-kev", "first-epss"]}]}))
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "reg.db"))
    monkeypatch.setenv("LOOMCTX_AUTH_FILE", str(keys))
    monkeypatch.delenv("LOOMCTX_API_KEYS", raising=False)
    from loomctx.api.http import app
    with TestClient(app) as client:
        _route_urllib_to(client, monkeypatch)
        reg = vulns.schema("netsec")
        with pytest.raises(SystemExit, match="403"):
            vulns.register(reg, "http://loomctx", None, "refresh")      # nothing registered yet: refused
        vulns.register(reg, "http://loomctx", None, "admin")            # the first load, by an operator
        vulns.register(reg, "http://loomctx", None, "refresh")          # nightly: nothing to add, no call
        more = reg.model_copy(update={"predicates": [*reg.predicates,
                                                     reg.predicates[0].model_copy(update={"name": "new_pred"})]})
        with pytest.raises(SystemExit, match="403"):
            vulns.register(more, "http://loomctx", None, "refresh")     # a real change still needs the operator


def test_a_gateway_import_reads_prior_versions_from_the_engine(monkeypatch, capsys):
    """A gateway serves ingest only: lookups go to LOOMCTX_READ_URL when set,
    and a 404 without it degrades to in-run chaining instead of failing."""
    from loomctx.connectors.chain import HttpSink, keyed_by, load_chained
    gets = []

    class Resp:
        def __init__(self, body):
            self.body = body

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        if req.get_method() == "GET":
            gets.append(req.full_url)
            if req.full_url.startswith("http://gateway"):
                raise urllib.error.HTTPError(req.full_url, 404, "no", {}, io.BytesIO(b"404 page not found"))
            return Resp(json.dumps({"observations": []}).encode())
        items = [json.loads(line) for line in req.data.decode().splitlines()]
        return Resp(json.dumps({"total": len(items), "recorded": len(items), "accepted": 0, "rejected": 0,
                                "results": []}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    envs = [e for e in ocsf.events_to_envelopes([OPEN], "netsec") if e.predicate == "affected_by"]
    totals = load_chained(envs, HttpSink("http://gateway", "k"), keyed_by("finding_uid", {"affected_by"}))
    assert totals["recorded"] == 1 and "LOOMCTX_READ_URL" in capsys.readouterr().err
    gets.clear()
    monkeypatch.setenv("LOOMCTX_READ_URL", "http://engine:8000")
    load_chained(envs, HttpSink("http://gateway", "k"), keyed_by("finding_uid", {"affected_by"}))
    assert gets and all(u.startswith("http://engine:8000/") for u in gets)
