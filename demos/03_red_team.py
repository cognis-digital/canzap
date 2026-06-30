"""Scenario 3 - red teams.

A replay/fuzz run leaves fingerprints on the bus: a flood of a single ID, an
injected UDS diagnostic request (0x7DF), a positive ECU response (0x7E8). CANZAP
lets the red team *assert their attack landed* - and gives the blue team the
exact detection rules to flip. This demo replays a fuzz capture and proves both
the flood and the injected diagnostic session are present, then shows the same
rules as a defender's "this must NOT happen" gate.
"""
from _common import load_capture, assert_against, print_result, rule


def main() -> None:
    rule("RED TEAM  -  prove the replay/fuzz landed, then hand blue team the rule")

    frames = load_capture("fuzz_replay.log")
    print(f"\nReplayed {len(frames)} frames from a fuzz/injection run (offline).")

    flood = [f for f in frames if f.can_id == 0x333]
    print(f"Injected ID 0x333 appears {len(flood)} times back-to-back - "
          "a classic flood/fuzz signature.")

    # Attacker's view: assert the attack is observable in the capture.
    print("\n1) Red team - 'did my injection actually hit the bus?'")
    res = assert_against(frames, """
        name: Attack landed (attacker assertions)
        assertions:
          - name: flood ID 0x333 was injected heavily
            id: 0x333
            present: true
            min_count: 5
          - name: UDS diagnostic request injected
            id: 0x7DF
            present: true
          - name: ECU answered the diagnostic session
            id: 0x7E8
            present: true
    """)
    print_result(res)
    assert res.passed, "attack signatures should be present in the fuzz capture"

    # Defender's view: the same facts, inverted into a detection gate.
    print("\n2) Blue team - the same capture against a 'must stay quiet' rule:")
    res_def = assert_against(frames, """
        name: Bus hygiene gate (defender assertions)
        assertions:
          - name: no flood of ID 0x333
            id: 0x333
            max_count: 2
          - name: no unsolicited UDS broadcast request
            id: 0x7DF
            present: false
    """)
    print_result(res_def)
    assert not res_def.passed

    print("\nSame capture, two lenses: the red team proves the injection landed,\n"
          "the blue team ships those inverted assertions as an IDS gate in CI.")


if __name__ == "__main__":
    main()
