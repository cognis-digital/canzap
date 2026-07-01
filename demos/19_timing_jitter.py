"""Scenario 19 - bound a periodic frame from both sides (jitter window).

A well-behaved periodic frame lives inside a window: not slower than its deadline
(`max_period_ms`) and not faster than its floor (`min_period_ms`). Combined, they
express an allowed jitter band. This demo measures the 0x3E0 body frame's period
and asserts it stays inside a 90-110 ms window, then shows a jittery capture
breaking out of it.
"""
from _common import load_capture, assert_against, print_result, rule
from canzap.core import parse_candump_text


def periods_ms(frames, can_id):
    fs = [f for f in frames if f.can_id == can_id]
    return [(fs[i].timestamp - fs[i - 1].timestamp) * 1000 for i in range(1, len(fs))]


def main() -> None:
    rule("TIMING  -  bound a periodic frame inside a jitter window")

    frames = load_capture("gateway_traffic.log")
    p = periods_ms(frames, 0x3E0)
    print(f"\n0x3E0 periods (ms): {[round(x, 1) for x in p]}  "
          f"-> {min(p):.0f}-{max(p):.0f} ms")

    res = assert_against(frames, """
        name: 0x3E0 jitter window
        assertions:
          - name: 0x3E0 within a 90-110 ms window
            id: 0x3E0
            interface: can1
            min_period_ms: 90
            max_period_ms: 110
    """)
    print_result(res)
    assert res.passed, "0x3E0 should sit inside its jitter window"

    # A capture where the frame arrives late (jitter spike) breaks the ceiling.
    jittery = parse_candump_text(
        "(0.000) can1 3E0#01\n(0.100) can1 3E0#01\n(0.320) can1 3E0#01"
    )
    res_bad = assert_against(jittery, """
        name: jitter spike
        assertions:
          - name: 0x3E0 within window
            id: 0x3E0
            min_period_ms: 90
            max_period_ms: 110
    """)
    print_result(res_bad)
    assert not res_bad.passed
    assert "max gap" in res_bad.failures[0].detail
    print("\nA two-sided window catches both a dropped frame (too slow) and a "
          "burst\n(too fast) with a single assertion.")


if __name__ == "__main__":
    main()
