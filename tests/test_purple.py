"""Purple-team correlation (D-086): a red operation log (Atomic CSV, Attire,
generic) set against OCSF detections on the same host — matched across
tool naming — with detected / host-only / missed and each side cited."""

import json
from datetime import datetime, timezone

from loom import purple
from loom.connectors import ocsf, oplog
from loom.store.sqlite import SqliteStore

ATOMIC = '''"Execution Time (UTC)","Execution Time (Local)","Technique","Test Number","Test Name","Hostname","IP Address","Username","GUID","ProcessId","ExitCode"
"2026-09-20T10:00:00Z","2026-09-20T12:00:00","T1003.001","1","Dump LSASS with procdump","WEB-01","10.0.4.7","CORP\\redop","g1","4120","0"
"2026-09-20T10:10:00Z","2026-09-20T12:10:00","T1059.001","2","PowerShell download cradle","WEB-01","10.0.4.7","CORP\\redop","g2","4200","0"
"2026-09-20T10:20:00Z","2026-09-20T12:20:00","T1053.005","1","Scheduled task persistence","DB-02","10.0.4.9","CORP\\redop","g3","4300","0"
'''


def _detection(uid, host_fqdn, t, technique=None, title="alert"):
    event = {"class_uid": 2004, "time": int(t.timestamp() * 1000), "status_id": 1, "severity_id": 4,
             "metadata": {"product": {"name": "EDR", "vendor_name": "Acme"}},
             "finding_info": {"uid": uid, "title": title,
                              "created_time": int(t.timestamp() * 1000)},
             "device": {"hostname": host_fqdn}}
    if technique:
        event["finding_info"]["attacks"] = [{"technique": {"uid": technique.split(".")[0]},
                                             "sub_technique": {"uid": technique}}]
    return event


def _load(tmp_path, events):
    store = SqliteStore(tmp_path / "p.db")
    for mod in (oplog, ocsf):
        store.put_schema(mod.schema("netsec"))
    store.record_claims(list(oplog.to_envelopes(ATOMIC, "netsec", "q3")))
    store.record_claims([e for e in ocsf.events_to_envelopes(events, "netsec") if hasattr(e, "predicate")])
    return store


def test_detected_host_only_and_missed(tmp_path):
    at = lambda m: datetime(2026, 9, 20, 10, m, tzinfo=timezone.utc)  # noqa: E731
    store = _load(tmp_path, [
        _detection("F-1", "web-01.corp.local", at(3), "T1003.001", "LSASS access"),   # 3 min later
        _detection("F-2", "web-01.corp.local", at(12), "T1105", "Suspicious download"),
    ])
    rows, notes = purple.correlate(store, "netsec", "q3")
    by = {r.techniques[0]: r for r in rows}
    lsass = by["T1003.001"]
    assert lsass.status == "detected" and lsass.matches[0].latency_seconds == 180
    assert lsass.matches[0].finding == "F-1" and lsass.matches[0].cites and lsass.cites
    assert by["T1059.001"].status == "host_only"         # something fired, not that technique
    assert by["T1053.005"].status == "missed"            # nothing on DB-02
    summary = purple.summary(rows)
    assert summary["by_status"] == {"detected": 1, "host_only": 1, "missed": 1}
    assert summary["median_latency_seconds"] == 180
    assert "| T1053.005 | db-02 |" in purple.markdown("q3", rows, notes)
    store.close()


def test_a_parent_technique_detection_counts(tmp_path):
    at = datetime(2026, 9, 20, 10, 1, tzinfo=timezone.utc)
    event = _detection("F-9", "WEB-01", at, None, "credential dumping")
    event["finding_info"]["attacks"] = [{"technique": {"uid": "T1003"}}]
    store = _load(tmp_path, [event])
    rows, _ = purple.correlate(store, "netsec", "q3")
    assert next(r for r in rows if r.techniques == ["T1003.001"]).status == "detected"
    store.close()


def test_outside_the_window_is_missed(tmp_path):
    late = datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)
    store = _load(tmp_path, [_detection("F-1", "web-01.corp.local", late, "T1003.001")])
    rows, _ = purple.correlate(store, "netsec", "q3")
    assert next(r for r in rows if r.techniques == ["T1003.001"]).status == "missed"
    store.close()


def test_attire_and_generic_logs():
    attire = json.dumps({"attire-version": "1.1", "execution-data": {
        "target": {"host": "WEB-01", "user": "CORP\\redop"}},
        "procedures": [{"mitre-technique-id": "T1082", "procedure-name": "System info",
                        "steps": [{"command": "systeminfo", "time-start": "2026-09-20T11:00:00Z",
                                   "executor": "cmd"}]}]})
    envs = list(oplog.to_envelopes(attire, "netsec", "op"))
    assert any(e.predicate == "uses_technique" and e.object.key == "T1082" for e in envs)
    generic = "timestamp,ttp,target,command\n2026-09-20T11:05:00Z,T1016,web-01,ipconfig /all\n"
    envs = list(oplog.to_envelopes(generic, "netsec", "op"))
    assert any(e.predicate == "targets" and e.object.key == "web-01" for e in envs)
    assert any(e.predicate == "command" and e.object == "ipconfig /all" for e in envs)
