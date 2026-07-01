"""Scenario 18 - build a scenario from a DBC-style ID watchlist.

Teams keep a list of the arbitration IDs they care about (a slice of a DBC). This
demo turns such a watchlist into a CANZAP scenario *programmatically* - each ID
becomes a `present` assertion with an expected count - then runs it. Scenarios
are just data, so they can be generated from any ID inventory.
"""
from _common import load_capture, print_result, rule
from canzap.core import Assertion, Scenario, run_scenario


# A tiny "DBC slice": id -> (human name, minimum expected frames)
WATCHLIST = {
    0x1A0: ("EngineRPM", 3),
    0x2B1: ("BrakeStatus", 2),
    0x700: ("PowertrainHeartbeat", 5),
}


def build_scenario(watchlist) -> Scenario:
    assertions = [
        Assertion(name=f"{name} present", can_id=can_id, present=True, min_count=lo)
        for can_id, (name, lo) in watchlist.items()
    ]
    return Scenario(name="DBC watchlist coverage", assertions=assertions)


def main() -> None:
    rule("DBC WATCHLIST  -  generate a scenario from an ID inventory")

    print("\nWatchlist (a DBC slice):")
    for can_id, (name, lo) in WATCHLIST.items():
        print(f"   0x{can_id:<4X} {name:<22} expect >= {lo}")

    sc = build_scenario(WATCHLIST)
    assert len(sc.assertions) == len(WATCHLIST)

    frames = load_capture("drive_cycle.log")
    res = run_scenario(frames, sc)
    print_result(res)
    assert res.passed, "every watchlisted ID should be present in the drive cycle"

    # The same generated scenario flags a capture that is missing a signal.
    partial = [f for f in frames if f.can_id != 0x2B1]
    res_missing = run_scenario(partial, sc)
    print("\nSame generated scenario against a capture missing 0x2B1:")
    print_result(res_missing)
    assert not res_missing.passed
    assert res_missing.failures[0].assertion.can_id == 0x2B1
    print("\nScenarios are plain objects, so a whole regression suite can be "
          "generated\nfrom a DBC, a spreadsheet, or a discovery scan.")


if __name__ == "__main__":
    main()
