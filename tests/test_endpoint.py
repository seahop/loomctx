"""Host artifacts (D-084): process lists and file listings in every format the
endpoint connector recognises, keyed so a reused pid is a new process, a
binary on many hosts is one hash, and an account in a process list folds
into the directory's user; what a format does not carry is coverage."""

import json
from datetime import datetime, timezone

import pytest

from loom import coverage, enrich
from loom.connectors import endpoint
from loom.contracts import EntityRef
from loom.store.sqlite import SqliteStore

T0 = datetime(2026, 9, 20, 9, 0, tzinfo=timezone.utc)

TASKLIST = '''"Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"
"svchost.exe","884","Services","0","22,112 K","Unknown","NT AUTHORITY\\SYSTEM","0:00:03","N/A"
"powershell.exe","4120","Console","1","98,404 K","Running","CORP\\jdoe","0:00:09","Windows PowerShell"
'''

PS = """  PID  PPID USER     STARTED                  COMMAND
    1     0 root     Sat Sep 20 08:00:00 2026 /sbin/init
  812     1 www-data Sat Sep 20 08:01:10 2026 /usr/sbin/nginx -g daemon off;
  990   812 www-data Sat Sep 20 08:30:00 2026 /bin/sh -c id
"""

WIN32 = json.dumps([
    {"ProcessId": 4120, "ParentProcessId": 3000, "Name": "powershell.exe", "CSName": "WEB-01",
     "ExecutablePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "CommandLine": "powershell -enc AAAA", "CreationDate": "/Date(1790000000000)/"},
    {"ProcessId": 3000, "ParentProcessId": 700, "Name": "explorer.exe", "CSName": "WEB-01",
     "ExecutablePath": "C:\\Windows\\explorer.exe", "CreationDate": "/Date(1789990000000)/"}])

OSQUERY_LOG = "\n".join(json.dumps(x) for x in [
    {"name": "processes", "hostIdentifier": "db-02.corp.local", "unixTime": 1790000000, "action": "snapshot",
     "snapshot": [{"pid": "42", "parent": "1", "name": "sshd", "path": "/usr/sbin/sshd",
                   "cmdline": "sshd: admin", "start_time": "1789999000", "username": "root"}]},
    {"name": "hashes", "hostIdentifier": "db-02.corp.local", "unixTime": 1790000000, "action": "added",
     "columns": {"path": "/usr/sbin/sshd", "sha256": "a" * 64, "size": "900000"}}])

LS = """/opt/app:
total 24
-rwxr-xr-x 1 root root 1048576 2026-09-01 10:00:00.000000000 +0000 run.sh
-rw-r--r-- 1 root root     120 2026-09-01 10:00:00.000000000 +0000 notes.txt
-rw------- 1 app  app      400 2026-09-02 11:00:00.000000000 +0000 id_rsa.pem
drwxr-xr-x 2 root root    4096 2026-09-01 10:00:00.000000000 +0000 lib
"""

SHA = f"{'b' * 64}  C:\\Tools\\tool.exe\n{'b' * 64}  /usr/local/bin/tool\n"


def _envs(text, **kw):
    kw.setdefault("as_of", T0)
    return list(endpoint.to_envelopes(text, "net", **kw))


def _facts(envs, pred):
    return [(e.subject.key, e.object.key if isinstance(e.object, EntityRef) else e.object)
            for e in envs if e.predicate == pred]


@pytest.mark.parametrize("text,fmt", [(TASKLIST, "tasklist"), (PS, "ps"), (WIN32, "win32_process"),
                                      (OSQUERY_LOG, "osquery"), (LS, "ls"), (SHA, "sha256sum")])
def test_formats_are_recognised(text, fmt):
    assert endpoint.detect(text) == fmt


def test_tasklist_accounts_and_what_it_lacks():
    envs = _envs(TASKLIST, host="WEB-01")
    runs_as = dict(_facts(envs, "run_as"))
    assert set(runs_as.values()) == {"web-01\\system", "corp\\jdoe"}   # built-in stays local
    ids = {e.object.key for e in envs if e.predicate == "identified_by" and e.subject.key == "corp\\jdoe"}
    assert ids == {"account:corp\\jdoe"}                                 # folds into AD's user
    gaps = {(e.object, e.attrs["state"]) for e in envs if e.predicate == "collected"}
    assert ("spawned_by", "absent") in gaps and ("cmdline", "absent") in gaps


def test_ps_links_parents_within_the_snapshot():
    envs = _envs(PS, host="app-01")
    parents = dict(_facts(envs, "spawned_by"))
    child = next(k for k in parents if k.startswith("app-01:990:"))
    assert parents[child].startswith("app-01:812:20260920T080110")   # the parent's own start
    assert ("app-01:1:20260920T080000", "app-01\\root") in _facts(envs, "run_as")


def test_a_reused_pid_is_a_different_process():
    a = _envs(PS, host="app-01")
    b = _envs(PS.replace("08:30:00", "09:45:00"), host="app-01")
    ka = {k for k, _ in _facts(a, "runs_on") if ":990:" in k}
    kb = {k for k, _ in _facts(b, "runs_on") if ":990:" in k}
    assert ka and kb and ka != kb


def test_win32_process_reads_the_host_and_images():
    envs = _envs(WIN32)
    assert {v for _, v in _facts(envs, "runs_on")} == {"web-01"}
    images = dict(_facts(envs, "executes"))
    assert any(v == "web-01:c:\\windows\\explorer.exe" for v in images.values())


def test_osquery_log_carries_host_time_and_hash():
    envs = _envs(OSQUERY_LOG)
    assert {v for _, v in _facts(envs, "runs_on")} == {"db-02.corp.local"}
    assert ("db-02.corp.local:/usr/sbin/sshd", f"sha256:{'a' * 64}") in _facts(envs, "has_hash")
    assert all(e.observed_at == datetime.fromtimestamp(1790000000, tz=timezone.utc)
               for e in envs if e.predicate == "runs_on")


def test_listing_keeps_what_matters_unless_asked():
    stats: dict = {}
    kept = {k for k, _ in _facts(_envs(LS, host="app-01", stats=stats), "located_on")}
    assert kept == {"app-01:/opt/app/run.sh", "app-01:/opt/app/id_rsa.pem"}
    assert stats["file_skipped"] == 1
    everything = {k for k, _ in _facts(_envs(LS, host="app-01", all_files=True), "located_on")}
    assert "app-01:/opt/app/notes.txt" in everything


def test_one_binary_on_two_hosts_is_one_hash(tmp_path):
    store = SqliteStore(tmp_path / "h.db")
    store.put_schema(endpoint.schema("net"))
    store.record_claims(_envs(SHA, host="web-01") + _envs(SHA, host="db-02"))
    rows = store.observations_for("net", EntityRef(type="hash", key=f"sha256:{'b' * 64}"), limit=50)
    assert {o.subject.key for o in rows} == {"web-01:c:\\tools\\tool.exe", "web-01:/usr/local/bin/tool",
                                             "db-02:c:\\tools\\tool.exe", "db-02:/usr/local/bin/tool"}
    store.close()


def test_a_process_account_folds_into_the_directory_user(tmp_path):
    from loom import identity
    store = SqliteStore(tmp_path / "u.db")
    store.put_schema(endpoint.schema("net"))
    ad_user = EntityRef(type="user", key="S-1-5-21-1-2-3-1105")
    store.record_claims(identity.claims("net", ad_user, [("account", "corp.local\\jdoe")], T0, "ad"))
    store.record_claims(_envs(TASKLIST, host="WEB-01"))
    enrich._identity_seen_until.clear()
    enrich.resolve_identities(store)
    canon = store.resolve_refs("net", [EntityRef(type="user", key="corp\\jdoe")])
    assert canon[("user", "corp\\jdoe")] == store.resolve_refs("net", [ad_user])[("user", ad_user.key)]
    store.close()


def test_shapes_are_recorded_per_format():
    shapes = [e for e in _envs(WIN32) if e.predicate == coverage.SHAPE]
    assert [s.object for s in shapes] == ["endpoint:win32_process:process"]
    assert {"cmdline", "path", "ppid"} <= set(shapes[0].attrs["fields"])


def test_ls_times_with_nanoseconds_parse():
    envs = _envs(LS, host="app-01")
    assert ("app-01:/opt/app/run.sh", "2026-09-01T10:00:00+00:00") in _facts(envs, "modified_at")
