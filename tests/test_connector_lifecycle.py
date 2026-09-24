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

from loom.connectors import ocsf, stix
from loom.context import build_pack
from loom.contracts import AskRequest, EntityRef, ScopeSpec
from loom.store.sqlite import SqliteStore

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
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "api.db"))
    from loom.api.http import app
    events = tmp_path / "scan.ndjson"
    events.write_text("".join(json.dumps(e) + "\n" for e in (OPEN, RESCAN)))
    with TestClient(app) as client:
        _route_urllib_to(client, monkeypatch)
        ocsf.main(["import", str(events), "--namespace", "netsec", "--url", "http://loom"])
        more = tmp_path / "later.ndjson"
        more.write_text(json.dumps(RESOLVED) + "\n")
        ocsf.main(["import", str(more), "--namespace", "netsec", "--url", "http://loom"])
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
    from loom.connectors.chain import HttpSink, keyed_by, load_chained
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
    envs = ocsf.events_to_envelopes([OPEN, RESCAN], "netsec")
    totals = load_chained(envs, HttpSink("http://loom", "k"), keyed_by("finding_uid", {"affected_by"}))
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
    assert claims and claims[0].attrs["status_id"] == 0


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
    from loom.connectors import vulns
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
