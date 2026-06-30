"""Shared helpers for the CANZAP demo scenarios.

Every scenario is fully offline: it works from bundled candump capture
fixtures (`demos/fixtures/*.log`) and the real `canzap.core` API. No live CAN
hardware, no SocketCAN interface, and no network access are required.
"""
from __future__ import annotations

import os
import sys
import textwrap
from typing import List

# allow `python demos/NN_name.py` from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canzap.core import (  # noqa: E402
    CanFrame,
    Scenario,
    ScenarioResult,
    parse_candump_text,
    load_scenario_text,
    run_scenario,
)

DEMO_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(DEMO_DIR, "fixtures")


def rule(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def load_capture(name: str) -> List[CanFrame]:
    """Parse a bundled candump capture fixture into frames (offline)."""
    path = os.path.join(FIXTURES, name)
    with open(path, "r", encoding="utf-8") as fh:
        return parse_candump_text(fh.read())


def scenario(text: str) -> Scenario:
    """Build a Scenario from inline mini-YAML DSL text (auto-dedented)."""
    return load_scenario_text(textwrap.dedent(text).strip("\n"))


def assert_against(frames: List[CanFrame], dsl: str) -> ScenarioResult:
    """Convenience: parse a scenario from DSL text and run it over frames.

    The DSL is `textwrap.dedent`-ed so demos can keep readable indentation in
    triple-quoted strings; the real parser still sees top-level keys at column 0.
    """
    return run_scenario(frames, load_scenario_text(textwrap.dedent(dsl).strip("\n")))


def print_result(res: ScenarioResult) -> None:
    """Render a ScenarioResult the way the CLI's table format does."""
    print(f"\nScenario: {res.scenario.name}   ({res.frame_count} frames)")
    print("-" * 66)
    for r in res.results:
        mark = "PASS" if r.passed else "FAIL"
        print(f"  [{mark}] {r.assertion.name}  ({r.to_dict()['id_hex']})")
        if not r.passed:
            print(f"         -> {r.detail}")
    n_pass = len(res.results) - len(res.failures)
    print("-" * 66)
    print(f"  {n_pass}/{len(res.results)} passed   (exit code would be "
          f"{0 if res.passed else 1})")
