"""Scenario 2 - embedded / ECU engineers.

A periodic frame (here the 0x700 heartbeat) is a contract: it must keep ticking
inside a deadline, or downstream ECUs fault. CANZAP's `max_period_ms` assertion
turns that timing contract into a pass/fail check you can put in firmware CI.
This demo runs the contract against a healthy capture (PASS), then against the
same capture with one heartbeat dropped (FAIL) - showing the regression catch.
"""
from _common import load_capture, assert_against, print_result, rule
from canzap.core import run_scenario, load_scenario_text

HEARTBEAT_CONTRACT = """
name: 0x700 heartbeat timing contract
assertions:
  - name: heartbeat present and frequent
    id: 0x700
    present: true
    min_count: 5
    max_period_ms: 120
"""


def main() -> None:
    rule("EMBEDDED / ECU ENGINEER  -  a periodic-frame timing contract in CI")

    frames = load_capture("drive_cycle.log")
    hb = [f for f in frames if f.can_id == 0x700]
    gaps = [(hb[i].timestamp - hb[i - 1].timestamp) * 1000 for i in range(1, len(hb))]
    print(f"\n0x700 heartbeat: {len(hb)} frames, "
          f"gaps {min(gaps):.0f}-{max(gaps):.0f} ms, deadline 120 ms.")

    print("\n1) Healthy firmware build - heartbeat meets its deadline:")
    res_ok = assert_against(frames, HEARTBEAT_CONTRACT)
    print_result(res_ok)
    assert res_ok.passed

    # Simulate a regression: a scheduling bug drops one heartbeat, doubling a gap.
    dropped = [f for f in frames if not (f.can_id == 0x700 and abs(f.timestamp - 1623241200.450000) < 1e-6)]
    print("\n2) Regressed build - one 0x700 heartbeat is dropped (scheduler bug):")
    res_bad = run_scenario(dropped, load_scenario_text(HEARTBEAT_CONTRACT))
    print_result(res_bad)
    assert not res_bad.passed

    worst = res_bad.failures[0].observed.get("max_period_ms")
    print(f"\nThe dropped frame widened the worst gap to {worst} ms, blowing the "
          "120 ms\ndeadline. In CI this returns a non-zero exit and fails the "
          "firmware build\nbefore it ever reaches a vehicle.")


if __name__ == "__main__":
    main()
