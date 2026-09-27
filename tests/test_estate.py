"""The four D-082…D-086 features together on a small synthetic estate
(`loom.connectors.estate_gen` + `loom.estate_eval`): machines and accounts
fold across tools, the twin and address traps do not, coverage gaps and
format drift are reported, and purple classification matches the truth."""

from pathlib import Path

from loom import estate_eval
from loom.connectors import estate_gen
from loom.store.sqlite import SqliteStore


def test_small_estate_end_to_end(tmp_path):
    d = tmp_path / "estate"
    truth = estate_gen.generate(7, "small", str(d))
    store = SqliteStore(tmp_path / "estate.db")
    try:
        load = estate_eval.load_all(store, Path(d), "estate")
        assert all(v["rejected"] == 0 and v["skipped"] == 0 for v in load.values()), load
        r = estate_eval.evaluate(store, Path(d), "estate", truth)
    finally:
        store.close()
    assert r["hosts"]["folded"] == r["hosts"]["corp_hosts"] > 0
    assert r["hosts"]["false_merges"] == 0 and r["hosts"]["twins"] > 0
    assert r["users"]["referenced"] > 0 and r["users"]["folded"] == r["users"]["referenced"]
    assert r["coverage"]["tasklist_parents"] == "absent" and r["coverage"]["tasklist_rows"] > 0
    assert r["coverage"]["ask_notes_gap"]
    assert r["drift"]["uac_removed"] and "ldap:computer" in r["drift"]["kinds"]
    p = r["purple"]
    assert p["status_right"] == p["actions"] and p["latency_right"] == p["detected"] > 0
