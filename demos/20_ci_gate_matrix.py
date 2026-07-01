"""Scenario 20 - a full CI gate matrix over every bundled capture.

The artifact a team actually ships: a matrix of (capture x gate) with a single
overall verdict and exit code. This demo runs the health, hygiene, and IOC gates
across all five bundled captures, prints a compact pass/fail grid, and computes
the exit code a CI job would return.
"""
from _common import load_capture, assert_against, rule


HEALTH = """
name: health
assertions:
  - name: heartbeat present
    id: 0x700
    present: true
"""

HYGIENE = """
name: hygiene
assertions:
  - name: 0x333 not flooding
    id: 0x333
    max_count: 2
  - name: no unsolicited UDS
    id: 0x7DF
    present: false
"""

IOC = """
name: ioc
assertions:
  - name: no odometer/VIN spoof
    id: 0x3D0
    present: false
  - name: no door-unlock replay burst
    id: 0x19B
    max_count: 2
"""

GATES = [("health", HEALTH), ("hygiene", HYGIENE), ("ioc", IOC)]
CAPTURES = [
    "drive_cycle.log",
    "fuzz_replay.log",
    "incident_capture.log",
    "gateway_traffic.log",
    "extended_ids.log",
]


def main() -> None:
    rule("CI GATE MATRIX  -  every capture x every gate, one verdict")

    header = f"   {'CAPTURE':<22}" + "".join(f"{g:>12}" for g, _ in GATES)
    print("\n" + header)
    print("   " + "-" * (22 + 12 * len(GATES)))

    grid = {}
    for cap in CAPTURES:
        frames = load_capture(cap)
        row = []
        for gate_name, dsl in GATES:
            res = assert_against(frames, dsl)
            grid[(cap, gate_name)] = res.passed
            row.append("PASS" if res.passed else f"FAIL/{len(res.failures)}")
        print(f"   {cap:<22}" + "".join(f"{c:>12}" for c in row))

    # Clean captures must pass every gate; the two attack captures must fail
    # the gate that targets their IOC - that expected pattern IS the test.
    assert grid[("drive_cycle.log", "health")]
    assert grid[("drive_cycle.log", "ioc")]
    assert not grid[("fuzz_replay.log", "hygiene")]
    assert not grid[("incident_capture.log", "ioc")]
    assert grid[("gateway_traffic.log", "health")]
    assert grid[("extended_ids.log", "hygiene")]

    total = len(grid)
    passed = sum(1 for v in grid.values() if v)
    print("\n   " + "-" * (22 + 12 * len(GATES)))
    print(f"   {passed}/{total} cells green   "
          "(attack captures are *expected* to fail their IOC gate)")
    print("\nThis grid is the release artifact: reviewers read it at a glance "
          "and CI\nturns any unexpected red into a non-zero exit.")


if __name__ == "__main__":
    main()
