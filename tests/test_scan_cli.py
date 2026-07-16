"""Tests for the `canzap scan` subcommand (table, JSON, SARIF, --fail-on)."""
from __future__ import annotations

import json
import os

from canzap.cli import main
from canzap.core import scan

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "demos", "fixtures")
FUZZ = os.path.join(FIXTURES, "fuzz_replay.log")
DRIVE = os.path.join(FIXTURES, "drive_cycle.log")


def test_scan_core_on_fuzz_capture():
    report = scan(FUZZ)
    assert report["frame_count"] == 16
    assert report["finding_count"] > 0
    # the fuzz/replay fixture contains a flood and diagnostic traffic
    rules = {f["rule"] for f in report["findings"]}
    assert "bus-flood" in rules


def test_scan_accepts_raw_text():
    report = scan("(1.0) can0 7DF#0201050000000000")
    assert report["frame_count"] == 1
    assert any(f["rule"] == "diagnostic-traffic" for f in report["findings"])


def test_scan_accepts_directory():
    report = scan(FIXTURES)
    # all three fixtures concatenated
    assert report["frame_count"] == 17 + 16 + 15
    assert report["finding_count"] > 0


def test_scan_cli_json(capsys):
    rc = main(["scan", FUZZ, "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tool"] == "canzap"
    assert data["frame_count"] == 16


def test_scan_cli_sarif(capsys):
    rc = main(["scan", FUZZ, "--format", "sarif"])
    assert rc == 0
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "canzap"


def test_scan_cli_table(capsys):
    rc = main(["scan", FUZZ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "risk score" in out
    assert "bus-flood" in out


def test_scan_fail_on_high_exits_nonzero(capsys):
    rc = main(["scan", FUZZ, "--fail-on", "high"])
    assert rc == 1


def test_scan_fail_on_critical_passes_when_no_critical(capsys):
    # fuzz fixture has high but not critical -> gate at critical passes
    rc = main(["scan", FUZZ, "--fail-on", "critical"])
    assert rc == 0


def test_scan_clean_capture_no_fail_on_high(capsys):
    rc = main(["scan", DRIVE, "--fail-on", "high"])
    assert rc == 0
