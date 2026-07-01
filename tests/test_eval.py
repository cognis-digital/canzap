"""Assertion evaluation semantics: present/count/byte/data/timing.

Exercises run_scenario over hand-built frames for every assertion type, both the
pass and fail direction, plus the JSON/result serialisation contract and the new
min_period_ms timing floor.
"""
import json

import pytest

from canzap.core import (
    Assertion,
    Scenario,
    load_scenario_text,
    parse_candump_text,
    result_to_json,
    run_scenario,
)


def _run(log: str, dsl: str):
    return run_scenario(parse_candump_text(log), load_scenario_text(dsl))


# --------------------------------------------------------------------------
# present / absent
# --------------------------------------------------------------------------


def test_present_true_passes_when_frame_seen():
    res = _run("(1.0) can0 1A0#00", "assertions:\n  - id: 0x1A0\n    present: true\n")
    assert res.passed


def test_present_true_fails_when_absent():
    res = _run("(1.0) can0 200#00", "assertions:\n  - id: 0x1A0\n    present: true\n")
    assert not res.passed
    assert "none found" in res.failures[0].detail


def test_present_false_passes_when_absent():
    res = _run("(1.0) can0 200#00", "assertions:\n  - id: 0x1A0\n    present: false\n")
    assert res.passed
    assert res.results[0].detail == "ID correctly absent"


def test_present_false_fails_when_seen():
    res = _run("(1.0) can0 1A0#00\n(1.1) can0 1A0#00",
               "assertions:\n  - id: 0x1A0\n    present: false\n")
    assert not res.passed
    assert "found 2 frame" in res.failures[0].detail


# --------------------------------------------------------------------------
# counts
# --------------------------------------------------------------------------


def test_min_count_pass_and_fail():
    log = "\n".join(f"(1.{i}) can0 700#00" for i in range(3))
    assert _run(log, "assertions:\n  - id: 0x700\n    min_count: 3\n").passed
    assert not _run(log, "assertions:\n  - id: 0x700\n    min_count: 4\n").passed


def test_max_count_pass_and_fail():
    log = "\n".join(f"(1.{i}) can0 333#FF" for i in range(5))
    assert _run(log, "assertions:\n  - id: 0x333\n    max_count: 5\n").passed
    res = _run(log, "assertions:\n  - id: 0x333\n    max_count: 2\n")
    assert not res.passed
    assert "> max_count" in res.failures[0].detail


def test_count_observed_reported():
    res = _run("(1.0) can0 1A0#00\n(1.1) can0 1A0#00",
               "assertions:\n  - id: 0x1A0\n    present: true\n")
    assert res.results[0].observed["count"] == 2


def test_no_frames_for_count_constraint_fails_clearly():
    res = _run("(1.0) can0 200#00", "assertions:\n  - id: 0x1A0\n    min_count: 1\n")
    assert not res.passed
    assert "no frames for this ID" in res.failures[0].detail


# --------------------------------------------------------------------------
# byte / equals
# --------------------------------------------------------------------------


def test_byte_equals_pass():
    res = _run("(1.0) can0 2B1#00FF",
               "assertions:\n  - id: 0x2B1\n    byte: 0\n    equals: 0x00\n")
    assert res.passed


def test_byte_equals_fail_reports_actual():
    res = _run("(1.0) can0 2B1#FF00",
               "assertions:\n  - id: 0x2B1\n    byte: 0\n    equals: 0x00\n")
    assert not res.passed
    assert "0xFF" in res.failures[0].detail
    assert res.failures[0].observed["byte_value"] == "0xFF"


def test_byte_equals_uses_last_matching_frame():
    log = "(1.0) can0 2B1#01\n(1.1) can0 2B1#00"
    res = _run(log, "assertions:\n  - id: 0x2B1\n    byte: 0\n    equals: 0x00\n")
    assert res.passed  # last frame's byte0 is 0x00


def test_byte_index_out_of_range_fails():
    res = _run("(1.0) can0 2B1#00",
               "assertions:\n  - id: 0x2B1\n    byte: 4\n    equals: 0x00\n")
    assert not res.passed
    assert "out of range" in res.failures[0].detail


# --------------------------------------------------------------------------
# data_equals
# --------------------------------------------------------------------------


def test_data_equals_pass():
    res = _run("(1.0) can0 700#DEADBEEF",
               "assertions:\n  - id: 0x700\n    data_equals: DEADBEEF\n")
    assert res.passed


def test_data_equals_fail_reports_observed():
    res = _run("(1.0) can0 700#DEADBEE0",
               "assertions:\n  - id: 0x700\n    data_equals: DEADBEEF\n")
    assert not res.passed
    assert "DEADBEE0" in res.failures[0].detail
    assert res.failures[0].observed["data"] == "DEADBEE0"


def test_data_equals_checks_last_frame():
    log = "(1.0) can0 700#0000\n(1.1) can0 700#DEAD"
    res = _run(log, "assertions:\n  - id: 0x700\n    data_equals: DEAD\n")
    assert res.passed


# --------------------------------------------------------------------------
# timing: max_period_ms / min_period_ms
# --------------------------------------------------------------------------


def test_max_period_pass():
    log = "(1.000) can0 700#00\n(1.100) can0 700#00\n(1.200) can0 700#00"
    res = _run(log, "assertions:\n  - id: 0x700\n    max_period_ms: 120\n")
    assert res.passed
    assert res.results[0].observed["max_period_ms"] == pytest.approx(100.0, abs=0.5)


def test_max_period_fail_on_gap():
    log = "(1.000) can0 700#00\n(1.500) can0 700#00"
    res = _run(log, "assertions:\n  - id: 0x700\n    max_period_ms: 120\n")
    assert not res.passed
    assert "max gap" in res.failures[0].detail


def test_min_period_detects_flood():
    log = "\n".join(f"(1.{i:03d}) can0 333#FF" for i in range(0, 8))  # 1ms apart
    res = _run(log, "assertions:\n  - id: 0x333\n    min_period_ms: 5\n")
    assert not res.passed
    assert "too fast" in res.failures[0].detail


def test_min_period_pass_when_spaced_out():
    log = "(1.000) can0 333#FF\n(1.100) can0 333#FF"
    res = _run(log, "assertions:\n  - id: 0x333\n    min_period_ms: 5\n")
    assert res.passed


def test_two_sided_window_pass():
    log = "(1.000) can0 3E0#00\n(1.100) can0 3E0#00\n(1.200) can0 3E0#00"
    res = _run(log, "assertions:\n  - id: 0x3E0\n    min_period_ms: 90\n    max_period_ms: 110\n")
    assert res.passed


def test_two_sided_window_fail_too_fast():
    log = "(1.000) can0 3E0#00\n(1.001) can0 3E0#00"
    res = _run(log, "assertions:\n  - id: 0x3E0\n    min_period_ms: 90\n    max_period_ms: 110\n")
    assert not res.passed
    assert "too fast" in res.failures[0].detail


def test_period_needs_two_frames():
    res = _run("(1.0) can0 700#00", "assertions:\n  - id: 0x700\n    max_period_ms: 120\n")
    assert not res.passed
    assert ">=2 frames" in res.failures[0].detail


# --------------------------------------------------------------------------
# interface scoping
# --------------------------------------------------------------------------


def test_interface_scopes_matching_frames():
    log = "(1.0) can0 700#00\n(1.1) can1 700#00\n(1.2) can1 700#00"
    res = _run(log, "assertions:\n  - id: 0x700\n    interface: can1\n    min_count: 2\n")
    assert res.passed


def test_interface_isolation_fails_when_on_wrong_bus():
    log = "(1.0) can0 3E0#00"
    res = _run(log, "assertions:\n  - id: 0x3E0\n    interface: can1\n    present: true\n")
    assert not res.passed


def test_interface_present_false_scoped():
    log = "(1.0) can0 3E0#00"  # only on can0
    res = _run(log, "assertions:\n  - id: 0x3E0\n    interface: can1\n    present: false\n")
    assert res.passed  # correctly absent on can1


# --------------------------------------------------------------------------
# scenario roll-up + serialisation
# --------------------------------------------------------------------------


def test_scenario_passed_requires_all_pass():
    log = "(1.0) can0 1A0#00"
    res = _run(log, "assertions:\n  - id: 0x1A0\n    present: true\n  - id: 0x200\n    present: true\n")
    assert not res.passed
    assert len(res.results) == 2
    assert len(res.failures) == 1


def test_frame_count_recorded():
    res = _run("(1.0) can0 1A0#00\n(1.1) can0 2B1#00",
               "assertions:\n  - id: 0x1A0\n    present: true\n")
    assert res.frame_count == 2


def test_result_to_json_roundtrip():
    res = _run("(1.0) can0 1A0#00", "assertions:\n  - id: 0x1A0\n    present: true\n")
    data = json.loads(result_to_json(res))
    assert data["passed"] is True
    assert data["total"] == 1
    assert data["failed"] == 0
    assert data["assertions"][0]["id_hex"] == "0x1A0"


def test_json_reports_failures():
    res = _run("(1.0) can0 200#00", "assertions:\n  - id: 0x1A0\n    present: true\n")
    data = json.loads(result_to_json(res))
    assert data["passed"] is False and data["failed"] == 1
    assert data["assertions"][0]["passed"] is False


def test_empty_scenario_trivially_passes():
    res = run_scenario(parse_candump_text("(1.0) can0 1A0#00"), Scenario(name="empty"))
    assert res.passed
    assert res.results == []


def test_direct_assertion_construction():
    a = Assertion(name="rpm", can_id=0x1A0, present=True, min_count=1)
    res = run_scenario(parse_candump_text("(1.0) can0 1A0#00"), Scenario("s", [a]))
    assert res.passed
