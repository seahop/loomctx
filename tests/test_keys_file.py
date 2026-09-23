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


def test_default_file_is_under_secrets(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _run(["generate", "--id", "a", "--namespace", "*", "--perms", "rw"], capsys)
    assert (tmp_path / "secrets" / "keys.json").exists()
    assert keys.DEFAULT_FILE == "secrets/keys.json"
