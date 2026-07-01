"""Scenario 9 - remote-transmission-request (RTR) frames.

RTR frames (`123#R`) request data without carrying a payload. CANZAP parses
them, flags them as RTR, and keeps them out of data assertions. This demo builds
a small capture with an RTR request followed by its data response and shows the
RTR flag surviving the parse.
"""
from _common import rule
from canzap.core import parse_candump_text


def main() -> None:
    rule("PROTOCOL  -  remote-transmission-request (RTR) frames")

    capture = "\n".join([
        "(1.000) can0 123#R",            # RTR request, no data
        "(1.010) can0 123#00112233",     # the answering data frame
        "(1.020) can0 456#R",            # another RTR request
    ])
    frames = parse_candump_text(capture)
    print(f"\nParsed {len(frames)} frames:\n")
    print("   ID       RTR    DLC   DATA")
    print("   " + "-" * 36)
    for f in frames:
        print(f"   0x{f.can_id:<6X} {str(f.rtr):<5}  {f.dlc:>3}   {f.data.hex().upper() or '(none)'}")

    rtrs = [f for f in frames if f.rtr]
    assert len(rtrs) == 2, "two RTR requests expected"
    assert all(f.dlc == 0 for f in rtrs), "RTR frames carry no data"
    data = [f for f in frames if not f.rtr]
    assert data and data[0].data == bytes.fromhex("00112233")
    print("\nRTR requests are parsed and flagged (rtr=True, dlc=0); the data "
          "response\nis a normal frame. An RTR frame with a payload is rejected "
          "as malformed.")


if __name__ == "__main__":
    main()
