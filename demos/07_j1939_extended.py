"""Scenario 7 - heavy-duty / J1939 buses use 29-bit extended IDs.

Trucks, tractors, and marine engines speak J1939 over 29-bit arbitration IDs
(e.g. 0x18FEF100). CANZAP classifies extended vs. standard IDs correctly - and
crucially does NOT misread a zero-padded standard ID like `0700` as extended.
This demo enumerates an extended-ID capture and asserts on the PGN frames.
"""
from _common import load_capture, assert_against, print_result, rule


def main() -> None:
    rule("HEAVY-DUTY / J1939  -  29-bit extended IDs, correctly classified")

    frames = load_capture("extended_ids.log")
    print(f"\nReplayed {len(frames)} frames from a J1939-style capture.\n")
    print("   ID           EXT   DATA (last)")
    print("   " + "-" * 44)
    seen = {}
    for f in frames:
        seen[f.can_id] = f
    for can_id in sorted(seen):
        f = seen[can_id]
        print(f"   0x{f.can_id:<10X} {str(f.extended):<5} {f.data.hex().upper()}")

    # The zero-padded 0x700 must NOT be flagged extended (it is 11-bit).
    std = [f for f in frames if f.can_id == 0x700]
    assert std and all(not f.extended for f in std), \
        "0x700 written as '0700' must stay a standard 11-bit ID"
    print("\n'0700' stayed standard (0x700 <= 0x7FF); the two PGNs above 0x7FF "
          "are extended.")

    res = assert_against(frames, """
        name: J1939 PGN health
        assertions:
          - name: engine-temp PGN present
            id: 0x18FEF100
            present: true
            min_count: 3
          - name: electronic-engine-controller PGN present
            id: 0x0CF00400
            present: true
            min_count: 3
    """)
    print_result(res)
    assert res.passed, "both J1939 PGNs should be present"
    print("\nExtended-ID classification by value (not written width) keeps "
          "J1939\nbaselines honest.")


if __name__ == "__main__":
    main()
