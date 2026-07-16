"""Tests for diff_captures and the `canzap diff` subcommand."""
from __future__ import annotations

import json

from canzap.core import diff_captures, parse_candump_text
from canzap.cli import main


def _f(text):
    return parse_candump_text(text)


def test_diff_identical_captures():
    text = "(1.0) can0 100#00\n(1.1) can0 100#00"
    res = diff_captures(_f(text), _f(text))
    assert res["identical"] is True
    assert res["added"] == res["removed"] == res["changed"] == []


def test_diff_added_removed_changed():
    baseline = _f("(1.0) can0 100#00\n(1.1) can0 200#00\n(1.2) can0 200#00")
    candidate = _f("(1.0) can0 200#00\n(1.1) can0 300#00")
    res = diff_captures(baseline, candidate)
    assert res["identical"] is False
    assert [r["id_hex"] for r in res["added"]] == ["0x300"]
    assert [r["id_hex"] for r in res["removed"]] == ["0x100"]
    changed = res["changed"][0]
    assert changed["id_hex"] == "0x200"
    assert changed["baseline"] == 2 and changed["candidate"] == 1


def test_diff_cli_exit_nonzero_on_drift(tmp_path, capsys):
    base = tmp_path / "base.log"
    cand = tmp_path / "cand.log"
    base.write_text("(1.0) can0 100#00\n")
    cand.write_text("(1.0) can0 100#00\n(1.1) can0 999#00\n")
    rc = main(["diff", "--baseline", str(base), "--candidate", str(cand)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "+ 0x999" in out


def test_diff_cli_exit_zero_when_identical(tmp_path, capsys):
    base = tmp_path / "base.log"
    cand = tmp_path / "cand.log"
    base.write_text("(1.0) can0 100#00\n")
    cand.write_text("(2.0) can0 100#00\n")  # same IDs/counts, different time
    rc = main(["diff", "--baseline", str(base), "--candidate", str(cand)])
    assert rc == 0
    assert "identical" in capsys.readouterr().out


def test_diff_cli_json(tmp_path, capsys):
    base = tmp_path / "base.log"
    cand = tmp_path / "cand.log"
    base.write_text("(1.0) can0 100#00\n")
    cand.write_text("(1.0) can0 200#00\n")
    rc = main(["diff", "--baseline", str(base), "--candidate", str(cand), "--format", "json"])
    assert rc == 1
    data = json.loads(capsys.readouterr().out)
    assert data["added"][0]["id_hex"] == "0x200"
    assert data["removed"][0]["id_hex"] == "0x100"
