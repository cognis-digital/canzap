"""Scenario 6 - detecting a bus flood by *timing*, not just count.

`max_count` catches a flood by how many frames appear; `min_period_ms` catches
it by how *fast* they arrive. A slow trickle of 0x333 might pass a count gate but
a back-to-back burst always violates a spacing floor. This demo asserts a
minimum inter-frame gap and shows the flood tripping it.
"""
from _common import load_capture, assert_against, print_result, rule


def main() -> None:
    rule("BLUE TEAM  -  catch a flood by inter-frame timing (min_period_ms)")

    frames = load_capture("fuzz_replay.log")
    burst = [f for f in frames if f.can_id == 0x333]
    gaps = [(burst[i].timestamp - burst[i - 1].timestamp) * 1000
            for i in range(1, len(burst))]
    print(f"\n0x333 arrived {len(burst)} times; tightest gap {min(gaps):.1f} ms "
          "- far below any legitimate cadence.")

    res = assert_against(frames, """
        name: Bus timing hygiene
        assertions:
          - name: 0x333 not flooding the bus
            id: 0x333
            min_period_ms: 5
          - name: 0x700 heartbeat still healthy
            id: 0x700
            present: true
            max_period_ms: 600
    """)
    print_result(res)
    assert not res.passed, "the 1 ms 0x333 burst must trip the timing floor"

    print("\nA spacing floor detects fast injection even when the total count "
          "looks\nplausible - the timing contract is the tell, not the tally.")


if __name__ == "__main__":
    main()
