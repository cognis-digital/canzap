"""Deeper edge-case coverage for canzap.core parsing, DSL, and evaluation."""
from __future__ import annotations

import json

import pytest

from canzap.core import (
    TOOL_VERSION,
    Assertion,
    Scenario,
    bus_stats,
    load_scenario_text,
    parse_candump,
    parse_candump_text,
    run_scenario,
    to_json,
)


# --------------------------------------------------------------------------
# Parsing edge cases
# --------------------------------------------------------------------------


def test_parse_rtr_frame_sets_flag_and_empty_data():
    f = parse_candump("(1.0) can0 300#R")
    assert f is not None
    assert f.rtr is True
    assert f.data == b""
    assert f.dlc == 0
    assert f.to_dict()["rtr"] is True


def test_parse_rejects_data_over_64_bytes():
    payload = "AA" * 65
    with pytest.raises(ValueError):
        parse_candump(f"can0 1A0#{payload}")


def test_parse_accepts_can_fd_64_bytes():
    payload = "AA" * 64
    f = parse_candump(f"can0 1A0#{payload}")
    assert f is not None
    assert f.dlc == 64


def test_parse_text_reports_line_number_on_error():
    with pytest.raises(ValueError) as exc:
        parse_candump_text("(1.0) can0 1A0#0BB8\nnot-a-frame!!\n")
    assert "line 2" in str(exc.value)


def test_to_dict_roundtrips_via_json():
    f = parse_candump("(1.0) can0 1A0#0BB80000")
    assert f is not None
    d = json.loads(json.dumps(f.to_dict()))
    assert d["id_hex"] == "0x1A0"
    assert d["dlc"] == 4


# --------------------------------------------------------------------------
# DSL edge cases
# --------------------------------------------------------------------------


def test_dsl_strips_inline_comments():
    sc = load_scenario_text(
        "name: t  # trailing comment\n"
        "assertions:\n"
        "  - name: rpm  # per-item comment\n"
        "    id: 0x1A0\n"
        "    present: true\n"
    )
    assert sc.name == "t"
    assert sc.assertions[0].can_id == 0x1A0


def test_dsl_missing_id_raises():
    with pytest.raises(ValueError):
        load_scenario_text("name: t\nassertions:\n  - name: nope\n    present: true\n")


def test_dsl_key_outside_list_item_raises():
    with pytest.raises(ValueError):
        load_scenario_text("name: t\nassertions:\n    id: 0x1A0\n")


def test_dsl_unknown_top_level_key_ignored():
    sc = load_scenario_text(
        "name: t\nversion: 9\nassertions:\n  - name: x\n    id: 0x1\n    present: true\n"
    )
    assert sc.name == "t"
    assert len(sc.assertions) == 1


def test_dsl_data_equals_and_interface_parsed():
    sc = load_scenario_text(
        "name: t\nassertions:\n"
        "  - name: payload\n    id: 0x2B1\n    data_equals: FF00\n    interface: can1\n"
    )
    a = sc.assertions[0]
    assert a.data_equals == bytes([0xFF, 0x00])
    assert a.interface == "can1"


# --------------------------------------------------------------------------
# Evaluation edge cases
# --------------------------------------------------------------------------


def _run(frames_text, assertion):
    return run_scenario(parse_candump_text(frames_text), Scenario("t", [assertion]))


def test_interface_filter_scopes_matches():
    frames = "(1.0) can0 1A0#01\n(1.1) can1 1A0#02"
    res = _run(frames, Assertion("iface", 0x1A0, present=True, min_count=2, interface="can0"))
    # only one frame on can0 -> min_count 2 fails
    assert res.passed is False


def test_max_count_violation():
    frames = "(1.0) can0 1A0#01\n(1.1) can0 1A0#02\n(1.2) can0 1A0#03"
    res = _run(frames, Assertion("cap", 0x1A0, max_count=2))
    assert res.passed is False
    assert "max_count" in res.failures[0].detail


def test_data_equals_pass_and_fail():
    ok = _run("(1.0) can0 2B1#FF00", Assertion("d", 0x2B1, data_equals=bytes([0xFF, 0x00])))
    assert ok.passed is True
    bad = _run("(1.0) can0 2B1#FF01", Assertion("d", 0x2B1, data_equals=bytes([0xFF, 0x00])))
    assert bad.passed is False


def test_byte_index_out_of_range():
    res = _run("(1.0) can0 2B1#FF", Assertion("b", 0x2B1, byte=5, equals=0x00))
    assert res.passed is False
    assert "out of range" in res.failures[0].detail


def test_constraint_without_frames_fails():
    res = _run("(1.0) can0 999#00", Assertion("missing", 0x1A0, byte=0, equals=0x00))
    assert res.passed is False
    assert "no frames" in res.failures[0].detail


def test_cadence_needs_two_frames():
    res = _run("(1.0) can0 700#01", Assertion("hb", 0x700, max_period_ms=120))
    assert res.passed is False


# --------------------------------------------------------------------------
# Version + serialization helpers
# --------------------------------------------------------------------------


def test_tool_version_reflects_version_file():
    # core reads the repo VERSION file; it must be a non-empty dotted string
    assert TOOL_VERSION
    assert TOOL_VERSION[0].isdigit()


def test_to_json_serializes_bus_stats():
    stats = bus_stats(parse_candump_text("(1.0) can0 1A0#0BB8"))
    parsed = json.loads(to_json(stats))
    assert parsed["frame_count"] == 1
