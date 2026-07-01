"""Scenario 10 - clear errors on malformed captures.

Real captures get truncated, concatenated, or corrupted. CANZAP fails loudly
with a line number and the offending text rather than silently dropping frames
or emitting garbage. This demo walks a batch of malformed lines and shows the
exact error each produces - the behaviour a pipeline relies on.
"""
from _common import rule
from canzap.core import parse_candump, parse_candump_text


BAD_LINES = [
    ("can0 1A0#0BZ8", "non-hex data"),
    ("can0 1A0#0BB", "odd-length data"),
    ("can0 1A0#R00FF", "RTR frame carrying data"),
    ("(1.0) can0 3FFFFFFF#00", "ID above the 29-bit maximum"),
    ("garbage without a hash", "no ID#DATA separator"),
]


def main() -> None:
    rule("ROBUSTNESS  -  malformed captures fail loudly, with a line number")

    print("\nEach malformed line raises a ValueError explaining exactly what "
          "is wrong:\n")
    for line, why in BAD_LINES:
        try:
            parse_candump(line)
        except ValueError as exc:
            print(f"   [{why}]")
            print(f"     input : {line!r}")
            print(f"     error : {exc}\n")
        else:  # pragma: no cover - defensive
            raise AssertionError(f"expected {line!r} to raise")

    # Blank lines and comments are skipped, not errors.
    assert parse_candump("") is None
    assert parse_candump("# a comment") is None
    print("   (blank lines and '# comments' are skipped, not errors)\n")

    # In a full log, the error names the offending line number.
    log = "(1.0) can0 1A0#0BB8\n(1.1) can0 2B1#0BZ8\n"
    try:
        parse_candump_text(log)
    except ValueError as exc:
        print(f"   whole-log error carries the line number: {exc}")
        assert "line 2" in str(exc)
    print("\nA pipeline can trust that bad input stops the run with a precise "
          "diagnostic\ninstead of producing a quietly wrong verdict.")


if __name__ == "__main__":
    main()
