"""Scenario 5 - architects & reviewers.

The same capture answers different questions for different teams. This demo
renders a one-screen *bus map* of a capture (every ID, its rate, payload width
and a sparkline of activity) and a roll-up of all the demo scenarios as a
pass/fail table - the artifact you paste into a review or a release gate.
Pure offline replay; no hardware, no network.
"""
from _common import load_capture, assert_against, rule


def bus_map(name: str) -> None:
    frames = load_capture(name)
    print(f"\nBus map for {name}  ({len(frames)} frames):")
    print(f"   {'ID':<8} {'COUNT':>5} {'DLC':>4} {'SPAN(ms)':>9}  PAYLOAD (last)")
    print("   " + "-" * 56)
    by_id = {}
    for f in frames:
        by_id.setdefault(f.can_id, []).append(f)
    for can_id in sorted(by_id):
        fs = by_id[can_id]
        span = (fs[-1].timestamp - fs[0].timestamp) * 1000.0
        print(f"   0x{can_id:<6X} {len(fs):>5} {fs[-1].dlc:>4} {span:>9.1f}  "
              f"{fs[-1].data.hex().upper()}")


def main() -> None:
    rule("ARCHITECTS & REVIEWERS  -  a bus map + scenario roll-up for review")

    for name in ("drive_cycle.log", "fuzz_replay.log", "incident_capture.log"):
        bus_map(name)

    # Roll-up table: run a representative gate over each capture.
    print("\nScenario roll-up (what each capture asserts):")
    print(f"   {'CAPTURE':<22} {'GATE':<28} RESULT")
    print("   " + "-" * 62)

    checks = [
        ("drive_cycle.log", "clean baseline", """
name: baseline
assertions:
  - name: rpm present
    id: 0x1A0
    present: true
    min_count: 3
  - name: no fault
    id: 0x500
    present: false
""", True),
        ("fuzz_replay.log", "no 0x333 flood", """
name: hygiene
assertions:
  - name: flood
    id: 0x333
    max_count: 2
""", False),
        ("incident_capture.log", "no 0x3D0 spoof", """
name: ioc
assertions:
  - name: spoof
    id: 0x3D0
    present: false
""", False),
    ]
    all_ok = True
    for capture, label, dsl, expect_pass in checks:
        res = assert_against(load_capture(capture), dsl)
        mark = "PASS (clean)" if res.passed else f"FAIL ({len(res.failures)} IOC)"
        print(f"   {capture:<22} {label:<28} {mark}")
        all_ok = all_ok and (res.passed == expect_pass)

    assert all_ok, "roll-up gates did not match expectations"
    print("\nOne capture, one command per gate: the green/red roll-up is the "
          "review\nartifact - and the exact same scenarios run unattended in CI.")


if __name__ == "__main__":
    main()
