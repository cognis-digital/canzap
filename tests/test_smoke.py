"""Smoke tests for CANZAP - import core, run on the demo, assert real behavior."""

import os

import pytest

from canzap import (
    parse_candump,
    parse_candump_text,
    load_scenario,
    load_scenario_text,
    run_scenario,
    TOOL_NAME,
    TOOL_VERSION,
)
from canzap.cli import main

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic")
LOG = os.path.join(DEMO, "capture.log")
SCENARIO = os.path.join(DEMO, "startup.canzap")


def test_metadata():
    assert TOOL_NAME == "canzap"
    assert TOOL_VERSION


def test_parse_single_frame():
    f = parse_candump("(1623241200.000000) can0 1A0#0BB80000")
    assert f is not None
    assert f.can_id == 0x1A0
    assert f.interface == "can0"
    assert f.timestamp == 1623241200.0
    assert f.data == bytes([0x0B, 0xB8, 0x00, 0x00])
    assert f.dlc == 4
    assert f.extended is False


def test_parse_extended_id():
    f = parse_candump("can1 18FF1234#01")
    assert f.extended is True
    assert f.can_id == 0x18FF1234


def test_parse_skips_blank_and_comment():
    assert parse_candump("") is None
    assert parse_candump("   ") is None
    assert parse_candump("# a comment") is None


def test_parse_rejects_bad_hex():
    with pytest.raises(ValueError):
        parse_candump("can0 1A0#0BZ8")
    with pytest.raises(ValueError):
        parse_candump("can0 1A0#0BB")  # odd length


def test_parse_demo_log():
    with open(LOG, encoding="utf-8") as fh:
        frames = parse_candump_text(fh.read())
    assert len(frames) == 12
    heartbeats = [f for f in frames if f.can_id == 0x700]
    assert len(heartbeats) == 6


def test_scenario_parsing():
    sc = load_scenario(SCENARIO)
    assert sc.name == "Engine startup checks"
    assert len(sc.assertions) == 4
    rpm = sc.assertions[0]
    assert rpm.can_id == 0x1A0
    assert rpm.present is True
    assert rpm.min_count == 3


def test_demo_scenario_passes():
    with open(LOG, encoding="utf-8") as fh:
        frames = parse_candump_text(fh.read())
    sc = load_scenario(SCENARIO)
    res = run_scenario(frames, sc)
    assert res.passed, [r.detail for r in res.failures]
    assert res.frame_count == 12
    assert len(res.results) == 4


def test_present_false_detects_unexpected_frame():
    frames = parse_candump_text(
        "(1.0) can0 500#01\n(1.1) can0 1A0#00"
    )
    sc = load_scenario_text(
        "name: t\nassertions:\n  - name: no fault\n    id: 0x500\n    present: false\n"
    )
    res = run_scenario(frames, sc)
    assert res.passed is False
    assert res.failures[0].assertion.can_id == 0x500


def test_byte_equals_failure():
    frames = parse_candump_text("(1.0) can0 2B1#FF00")
    sc = load_scenario_text(
        "name: t\nassertions:\n  - name: brake\n    id: 0x2B1\n    byte: 0\n    equals: 0x00\n"
    )
    res = run_scenario(frames, sc)
    assert res.passed is False
    assert "0xFF" in res.failures[0].detail


def test_cadence_failure_on_large_gap():
    # two heartbeats 500ms apart, allowed max 120ms
    frames = parse_candump_text("(1.000) can0 700#01\n(1.500) can0 700#01")
    sc = load_scenario_text(
        "name: t\nassertions:\n  - name: hb\n    id: 0x700\n    present: true\n"
        "    min_count: 2\n    max_period_ms: 120\n"
    )
    res = run_scenario(frames, sc)
    assert res.passed is False


def test_cli_check_passes_exit_zero(capsys):
    rc = main(["check", "--log", LOG, "--scenario", SCENARIO])
    assert rc == 0
    out = capsys.readouterr().out
    assert "4/4 passed" in out


def test_cli_check_json(capsys):
    rc = main(["check", "--log", LOG, "--scenario", SCENARIO, "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    import json
    data = json.loads(out)
    assert data["passed"] is True
    assert data["total"] == 4
    assert data["failed"] == 0


def test_cli_dump_json(capsys):
    rc = main(["dump", "--log", LOG, "--format", "json"])
    assert rc == 0
    import json
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 12
    assert data[0]["id_hex"] == "0x1A0"


def test_cli_failure_exits_nonzero(tmp_path, capsys):
    log = tmp_path / "bad.log"
    log.write_text("(1.0) can0 500#01\n")
    scn = tmp_path / "s.canzap"
    scn.write_text(
        "name: t\nassertions:\n  - name: no fault\n    id: 0x500\n    present: false\n"
    )
    rc = main(["check", "--log", str(log), "--scenario", str(scn)])
    assert rc == 1
