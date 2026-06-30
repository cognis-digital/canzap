"""Tests for the bundled demo scenarios and capture fixtures.

These ensure the demos stay runnable (exit 0, real API, offline) and that the
fixtures keep parsing - so the demos double as executable documentation.
"""
import importlib
import os
import sys

import pytest

DEMO_DIR = os.path.join(os.path.dirname(__file__), "..", "demos")
FIXTURES = os.path.join(DEMO_DIR, "fixtures")
sys.path.insert(0, os.path.abspath(DEMO_DIR))

from canzap.core import parse_candump_text  # noqa: E402

DEMOS = [
    "01_security_researcher",
    "02_ecu_engineer",
    "03_red_team",
    "04_ir_forensics",
    "05_bus_report",
]

FIXTURE_FRAMES = {
    "drive_cycle.log": 17,
    "fuzz_replay.log": 16,
    "incident_capture.log": 15,
}


@pytest.mark.parametrize("name,expected", FIXTURE_FRAMES.items())
def test_fixtures_parse(name, expected):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        frames = parse_candump_text(fh.read())
    assert len(frames) == expected


@pytest.mark.parametrize("modname", DEMOS)
def test_demo_runs_and_exits_clean(modname, capsys):
    mod = importlib.import_module(modname)
    mod.main()  # raises (e.g. AssertionError) if the demo's own checks fail
    out = capsys.readouterr().out
    assert out.strip(), f"{modname} produced no output"


def test_run_all_imports_every_scenario():
    run_all = importlib.import_module("run_all")
    assert run_all.SCENARIOS == DEMOS


def test_common_helpers_dedent_inline_dsl():
    from _common import assert_against
    # leading indentation in the DSL must still parse (dedent in the helper)
    res = assert_against(
        parse_candump_text("(1.0) can0 1A0#0BB8\n(1.1) can0 1A0#0BB8"),
        """
        name: indented
        assertions:
          - name: rpm present
            id: 0x1A0
            present: true
            min_count: 2
        """,
    )
    assert res.passed
    assert res.scenario.name == "indented"
