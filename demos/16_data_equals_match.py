"""Scenario 16 - exact full-payload matching with data_equals.

Some checks need the *entire* payload, not a single byte: a fixed keep-alive, a
known-good calibration frame, or a signature message. `data_equals` asserts the
last matching frame's payload byte-for-byte. This demo confirms the 0x700
heartbeat payload is exactly DEADBEEF and catches a corrupted variant.
"""
from _common import load_capture, assert_against, print_result, rule
from canzap.core import parse_candump_text


def main() -> None:
    rule("EXACT MATCH  -  full-payload assertions with data_equals")

    frames = load_capture("drive_cycle.log")
    hb = [f for f in frames if f.can_id == 0x700]
    print(f"\nThe 0x700 heartbeat carries a fixed payload; last of {len(hb)}: "
          f"{hb[-1].data.hex().upper()}")

    res = assert_against(frames, """
        name: Heartbeat payload integrity
        assertions:
          - name: 0x700 payload is exactly DEADBEEF
            id: 0x700
            data_equals: DEADBEEF
    """)
    print_result(res)
    assert res.passed, "the heartbeat payload should match exactly"

    # A corrupted heartbeat is caught byte-for-byte.
    corrupt = parse_candump_text("(1.0) can0 700#DEADBEE0")
    res_bad = assert_against(corrupt, """
        name: Corrupted heartbeat
        assertions:
          - name: 0x700 payload is exactly DEADBEEF
            id: 0x700
            data_equals: DE AD BE EF
    """)
    print_result(res_bad)
    assert not res_bad.passed
    assert "DEADBEE0" in res_bad.failures[0].detail
    print("\ndata_equals ignores whitespace in the DSL (DE AD BE EF) and reports "
          "the\nexact observed payload on mismatch - ideal for signature or "
          "calibration frames.")


if __name__ == "__main__":
    main()
