"""Scenario 1 - automotive security researchers.

You recorded a drive cycle off the OBD-II port with `candump -l`. Before you go
hunting for bugs you want a *baseline*: what IDs are on this bus, how fast does
the powertrain heartbeat tick, and does the brake-status frame behave. CANZAP
turns those questions into a replayable, asserted baseline you can diff against
later captures - all offline, from the recorded log.
"""
from _common import load_capture, assert_against, print_result, rule


def main() -> None:
    rule("AUTOMOTIVE SECURITY RESEARCHER  -  baseline a recorded drive cycle")

    frames = load_capture("drive_cycle.log")
    print(f"\nReplayed {len(frames)} frames from demos/fixtures/drive_cycle.log "
          "(candump -l format, offline).")

    # Enumerate the bus - the first thing you do on an unknown CAN segment.
    ids = {}
    for f in frames:
        ids.setdefault(f.can_id, 0)
        ids[f.can_id] += 1
    print("\nArbitration IDs seen on the bus:")
    for can_id in sorted(ids):
        print(f"   0x{can_id:<4X}  x{ids[can_id]}   (last DLC "
              f"{[f for f in frames if f.can_id == can_id][-1].dlc})")

    # Capture the baseline as assertions. Re-run them against any later capture
    # to catch a drifted or tampered bus.
    print("\nAsserting the baseline invariants for this drive cycle:")
    res = assert_against(frames, """
        name: Drive-cycle baseline
        assertions:
          - name: RPM frame is broadcasting
            id: 0x1A0
            present: true
            min_count: 3
          - name: heartbeat cadence within spec
            id: 0x700
            present: true
            min_count: 5
            max_period_ms: 120
          - name: brake released by end of capture
            id: 0x2B1
            byte: 0
            equals: 0x00
          - name: no diagnostic fault broadcast
            id: 0x500
            present: false
    """)
    print_result(res)

    assert res.passed, "baseline drive cycle should be clean"
    print("\nThis passing baseline becomes a regression test: capture another "
          "drive,\nreplay it through the same scenario, and any new ID, dropped "
          "heartbeat,\nor stuck brake byte turns the green into a red.")


if __name__ == "__main__":
    main()
