"""loom.keys writes its file atomically, private, under secrets/ by default."""

import json
import os
import stat
import sys

import pytest

from loom import keys


def _run(argv, capsys):
    sys.argv = ["loom.keys", *argv]
    keys.main()
    return capsys.readouterr()


def test_generate_writes_0600_and_no_temp_files(tmp_path, capsys):
    path = tmp_path / "secrets" / "keys.json"   # parent does not exist yet
    out = _run(["--file", str(path), "generate", "--id", "a", "--namespace", "netsec", "--perms", "r"], capsys)
    assert out.out.strip().startswith("loomk_")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert sorted(os.listdir(path.parent)) == ["keys.json"]     # no .tmp left behind
    data = json.loads(path.read_text())
    assert [k["id"] for k in data["keys"]] == ["a"]
    assert "loomk_" not in path.read_text()                      # hash only


def test_replace_is_atomic_on_failure(tmp_path, monkeypatch):
    path = tmp_path / "keys.json"
    keys._save(str(path), {"keys": [{"id": "keep"}]})
    before = path.read_text()

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(keys.os, "replace", boom)
    with pytest.raises(OSError):
        keys._save(str(path), {"keys": []})
    assert path.read_text() == before                            # old file intact
    assert sorted(os.listdir(tmp_path)) == ["keys.json"]         # tmp cleaned up


def test_rate_limit_fields_generate_update_list(tmp_path, capsys):
    """R-10: per-key rate overrides live beside the grant; the engine and
    the Go gateway read the same field names."""
    from loom.auth import _parse_file

    path = tmp_path / "keys.json"
    _run(["--file", str(path), "generate", "--id", "agent", "--namespace", "netsec", "--perms", "r",
          "--rate-per-sec", "5", "--rate-burst", "20", "--rate-llm-per-sec", "0.5"], capsys)
    _run(["--file", str(path), "generate", "--id", "plain", "--namespace", "netsec", "--perms", "r"], capsys)
    entry = {k["id"]: k for k in json.loads(path.read_text())["keys"]}
    assert (entry["agent"]["rate_per_sec"], entry["agent"]["rate_burst"],
            entry["agent"]["rate_llm_per_sec"]) == (5.0, 20, 0.5)
    assert (entry["plain"]["rate_per_sec"], entry["plain"]["rate_burst"],
            entry["plain"]["rate_llm_per_sec"]) == (None, None, None)
    grants = {g.id: g for _, g in _parse_file(path.read_text())}          # what the engine loads
    assert (grants["agent"].rate_per_sec, grants["agent"].rate_burst, grants["agent"].rate_llm_per_sec) == (5.0, 20, 0.5)
    assert grants["plain"].rate_per_sec is None

    out = _run(["--file", str(path), "list"], capsys).out
    assert "rate=5/s burst=20" in out and "llm_rate=0.5/s" in out

    # update: set, and 0 drops the override (the LOOM_RATE_* defaults apply)
    _run(["--file", str(path), "update", "--id", "plain", "--rate-per-sec", "2"], capsys)
    _run(["--file", str(path), "update", "--id", "agent", "--rate-llm-per-sec", "0", "--rate-burst", "0"], capsys)
    entry = {k["id"]: k for k in json.loads(path.read_text())["keys"]}
    assert entry["plain"]["rate_per_sec"] == 2.0
    assert entry["agent"]["rate_per_sec"] == 5.0                            # untouched
    assert entry["agent"]["rate_burst"] is None and entry["agent"]["rate_llm_per_sec"] is None
    with pytest.raises(SystemExit):                                         # negative is refused
        _run(["--file", str(path), "update", "--id", "plain", "--rate-per-sec", "-1"], capsys)


def test_default_file_is_under_secrets(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _run(["generate", "--id", "a", "--namespace", "*", "--perms", "rw"], capsys)
    assert (tmp_path / "secrets" / "keys.json").exists()
    assert keys.DEFAULT_FILE == "secrets/keys.json"
