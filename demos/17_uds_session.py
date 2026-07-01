"""Scenario 17 - detect an unsolicited UDS diagnostic session.

UDS (ISO 14229) diagnostics ride on CAN: a functional request on 0x7DF, an ECU
response on 0x7E8. On a running vehicle bus an *unsolicited* diagnostic session
is a red flag (tooling attached, or an attacker probing). This demo confirms the
request/response pair in the fuzz capture and asserts the defender's "no
diagnostics in production traffic" gate.
"""
from _common import load_capture, assert_against, print_result, rule


def main() -> None:
    rule("UDS  -  spot an unsolicited diagnostic request/response pair")

    frames = load_capture("fuzz_replay.log")
    req = [f for f in frames if f.can_id == 0x7DF]
    resp = [f for f in frames if f.can_id == 0x7E8]
    print(f"\nUDS request 0x7DF x{len(req)}, response 0x7E8 x{len(resp)}.")
    for f in req + resp:
        sid = f.data[1] if len(f.data) > 1 else None
        print(f"   0x{f.can_id:X}#{f.data.hex().upper()}   "
              f"(service byte 0x{sid:02X})" if sid is not None else "")

    print("\n1) Confirm the diagnostic session is on the bus (attacker view):")
    res = assert_against(frames, """
        name: UDS session present
        assertions:
          - name: functional diagnostic request seen
            id: 0x7DF
            present: true
          - name: ECU positive response seen
            id: 0x7E8
            present: true
    """)
    print_result(res)
    assert res.passed

    print("\n2) Production gate - no diagnostics should appear (defender view):")
    res_def = assert_against(frames, """
        name: No diagnostics in production
        assertions:
          - name: no functional diagnostic requests
            id: 0x7DF
            present: false
          - name: no diagnostic responses
            id: 0x7E8
            present: false
    """)
    print_result(res_def)
    assert not res_def.passed
    assert len(res_def.failures) == 2
    print("\nThe request/response pair proves the session landed; inverting the "
          "rule\nmakes any diagnostic traffic in a production capture fail the "
          "gate.")


if __name__ == "__main__":
    main()
