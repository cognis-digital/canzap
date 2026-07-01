"""Scenario 12 - diff a new capture against a golden baseline.

The core CANZAP workflow: record a known-good capture, freeze its invariants as
a scenario, then run every later capture through the same scenario. This demo
runs the golden baseline (PASS) and a regressed capture with the brake byte
stuck (FAIL) through the *identical* scenario - the diff is the exit code.
"""
from _common import load_capture, scenario, print_result, rule
from canzap.core import run_scenario


BASELINE = scenario("""
    name: Golden drive-cycle baseline
    assertions:
      - name: RPM broadcasting
        id: 0x1A0
        present: true
        min_count: 3
      - name: heartbeat within deadline
        id: 0x700
        present: true
        max_period_ms: 120
      - name: brake released at end
        id: 0x2B1
        byte: 0
        equals: 0x00
""")


def main() -> None:
    rule("REGRESSION  -  one scenario, two captures, the diff is the exit code")

    good = load_capture("drive_cycle.log")
    print("\n1) Golden baseline capture:")
    res_good = run_scenario(good, BASELINE)
    print_result(res_good)
    assert res_good.passed

    # Regressed capture: flip the final 0x2B1 brake frame to 'engaged' (byte0=1).
    regressed = list(good)
    for i in range(len(regressed) - 1, -1, -1):
        f = regressed[i]
        if f.can_id == 0x2B1:
            from canzap.core import CanFrame
            regressed[i] = CanFrame(f.timestamp, f.interface, f.can_id,
                                    bytes([0x01]) + f.data[1:], f.extended, f.rtr)
            break
    print("\n2) New capture where the brake byte is stuck engaged (regression):")
    res_bad = run_scenario(regressed, BASELINE)
    print_result(res_bad)
    assert not res_bad.passed
    assert res_bad.failures[0].assertion.can_id == 0x2B1

    print("\nThe same frozen scenario turns a stuck brake byte from green to "
          "red -\nno new code, just replay the capture through the baseline "
          "gate.")


if __name__ == "__main__":
    main()
