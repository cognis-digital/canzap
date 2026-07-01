"""Scenario 13 - decode a signal out of the raw payload.

CANZAP frames expose raw bytes; a signal (here engine RPM in the first two bytes
of 0x1A0, big-endian, 1 rpm/bit) is a decode on top. This demo replays the drive
cycle, decodes the RPM trace, and asserts every sample sits inside a plausible
band using per-frame byte checks - the bridge from raw bus to physical meaning.
"""
from _common import load_capture, assert_against, print_result, rule


def rpm_of(frame) -> int:
    return int.from_bytes(frame.data[0:2], "big")


def main() -> None:
    rule("SIGNAL DECODE  -  turn 0x1A0 payload bytes into an RPM trace")

    frames = load_capture("drive_cycle.log")
    rpm_frames = [f for f in frames if f.can_id == 0x1A0]
    print(f"\nDecoded RPM from {len(rpm_frames)} x 0x1A0 frames "
          "(bytes[0:2], big-endian):\n")
    for f in rpm_frames:
        print(f"   t={f.timestamp:.3f}   raw={f.data.hex().upper()}   "
              f"rpm={rpm_of(f)}")

    lo = min(rpm_of(f) for f in rpm_frames)
    hi = max(rpm_of(f) for f in rpm_frames)
    print(f"\nRPM ranged {lo}-{hi} over the cycle.")
    assert 0 < lo and hi < 8000, "decoded RPM should be within a sane engine band"

    # Assert the *first byte* of the RPM word stays within the high-byte range
    # the decode implies (a coarse but real payload check the DSL can express).
    res = assert_against(frames, """
        name: RPM payload sanity
        assertions:
          - name: last RPM sample decodes to idle-ish high byte
            id: 0x1A0
            byte: 0
            equals: 0x09
          - name: RPM frame present enough to trend
            id: 0x1A0
            present: true
            min_count: 4
    """)
    print_result(res)
    assert res.passed
    print("\nRaw bytes -> engineering units: the same capture that gates on "
          "presence\nand timing also carries decodable signals for deeper "
          "analysis.")


if __name__ == "__main__":
    main()
