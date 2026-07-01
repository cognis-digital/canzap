"""Scenario 8 - gateways bridge two CAN segments; assert per-interface.

A gateway ECU sits between can0 (powertrain) and can1 (body). The same
arbitration ID can legitimately appear on both segments, so assertions can be
scoped to an `interface`. This demo shows the same 0x700 heartbeat on both
buses and asserts a body-only frame stays off the powertrain segment.
"""
from _common import load_capture, assert_against, print_result, rule


def main() -> None:
    rule("GATEWAY  -  scope assertions to a specific CAN interface")

    frames = load_capture("gateway_traffic.log")
    ifaces = sorted({f.interface for f in frames})
    print(f"\nReplayed {len(frames)} frames across interfaces: {', '.join(ifaces)}")
    for iface in ifaces:
        ids = sorted({f.can_id for f in frames if f.interface == iface})
        print(f"   {iface}: " + ", ".join(f"0x{i:X}" for i in ids))

    res = assert_against(frames, """
        name: Gateway segmentation
        assertions:
          - name: heartbeat present on powertrain bus
            id: 0x700
            interface: can0
            present: true
            min_count: 3
          - name: heartbeat present on body bus
            id: 0x700
            interface: can1
            present: true
            min_count: 3
          - name: body-only 0x3E0 never leaks onto powertrain
            id: 0x3E0
            interface: can0
            present: false
    """)
    print_result(res)
    assert res.passed, "gateway segmentation invariants should hold"
    print("\nInterface-scoped assertions verify a gateway keeps segments "
          "separated -\na body frame appearing on the powertrain bus would "
          "flip this red.")


if __name__ == "__main__":
    main()
