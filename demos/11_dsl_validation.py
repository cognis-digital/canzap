"""Scenario 11 - the scenario DSL validates itself.

A typo'd key or a half-written assertion in a `.canzap` file should fail at load
time with a clear message, not silently skip the check (a silently-skipped
security assertion is worse than none). This demo feeds the loader several
broken scenarios and shows each precise error.
"""
from _common import rule
from canzap.core import load_scenario_text


BAD_SCENARIOS = [
    ("missing id",
     "name: t\nassertions:\n  - name: x\n    present: true\n"),
    ("unknown key (typo)",
     "name: t\nassertions:\n  - name: x\n    id: 0x1A0\n    prezent: true\n"),
    ("byte without equals",
     "name: t\nassertions:\n  - name: x\n    id: 0x1A0\n    byte: 0\n"),
    ("non-integer id",
     "name: t\nassertions:\n  - name: x\n    id: notanumber\n"),
    ("min_count > max_count",
     "name: t\nassertions:\n  - name: x\n    id: 0x1A0\n    min_count: 5\n    max_count: 2\n"),
    ("no assertions block",
     "name: t\n"),
]


def main() -> None:
    rule("DSL SAFETY  -  a broken scenario fails at load, never silently skips")

    print("\nEvery malformed scenario is rejected with a specific reason:\n")
    for label, text in BAD_SCENARIOS:
        try:
            load_scenario_text(text)
        except ValueError as exc:
            print(f"   [{label}]")
            print(f"     -> {exc}\n")
        else:  # pragma: no cover - defensive
            raise AssertionError(f"expected {label!r} scenario to be rejected")

    # A well-formed scenario still loads cleanly, including 0b / 0x integers.
    sc = load_scenario_text(
        "name: valid\nassertions:\n  - name: ok\n    id: 0x1A0\n    "
        "byte: 0b0001\n    equals: 0xFF\n"
    )
    assert sc.assertions[0].byte == 1 and sc.assertions[0].equals == 0xFF
    print("   (a valid scenario loads fine; 0x / 0b / decimal integers accepted)")
    print("\nFail-closed DSL parsing means a mistyped rule breaks the build "
          "loudly\ninstead of quietly passing an unchecked bus.")


if __name__ == "__main__":
    main()
