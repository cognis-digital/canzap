"""Scenario 15 - synthesise a fuzz campaign and assert its shape.

A red-team fuzzer sweeps an ID space with varying payloads. This demo *generates*
a deterministic fuzz capture in memory (no hardware), replays it through CANZAP,
and asserts the campaign's shape: every target ID got hit, the sweep stayed
inside its ID band, and the injection rate tripped a spacing floor.
"""
from _common import rule
from canzap.core import parse_candump_text, load_scenario_text, run_scenario


def synth_fuzz(base_id: int, n: int, start_ts: float = 0.0, step_ms: float = 2.0) -> str:
    """Deterministically emit `n` frames sweeping payloads on one ID."""
    lines = []
    for i in range(n):
        ts = start_ts + (i * step_ms) / 1000.0
        payload = ((i * 0x11) & 0xFF)
        lines.append(f"({ts:.6f}) can0 {base_id:X}#{payload:02X}{payload:02X}")
    return "\n".join(lines)


def main() -> None:
    rule("RED TEAM  -  generate a fuzz campaign in memory, then assert its shape")

    capture = "\n".join([
        synth_fuzz(0x400, 12, start_ts=0.0, step_ms=2.0),
        synth_fuzz(0x401, 8, start_ts=0.1, step_ms=2.0),
    ])
    frames = parse_candump_text(capture)
    ids = sorted({f.can_id for f in frames})
    print(f"\nSynthesised {len(frames)} fuzz frames across IDs "
          f"{', '.join(f'0x{i:X}' for i in ids)} (2 ms spacing).")

    res = run_scenario(frames, load_scenario_text("""
name: Fuzz campaign shape
assertions:
  - name: primary target swept hard
    id: 0x400
    present: true
    min_count: 10
    min_period_ms: 5
  - name: secondary target also hit
    id: 0x401
    present: true
    min_count: 5
"""))
    # The primary target's spacing floor (5 ms) is violated by the 2 ms sweep;
    # every other clause holds. So the campaign "landed" AND is detectable.
    flood = next(r for r in res.results if r.assertion.can_id == 0x400)
    swept = next(r for r in res.results if r.assertion.can_id == 0x401)
    print(f"\n   0x400 spacing floor tripped : {not flood.passed}  ({flood.detail})")
    print(f"   0x401 present & counted      : {swept.passed}")
    assert not flood.passed, "the 2 ms sweep must violate the 5 ms floor"
    assert swept.passed, "the secondary target should be present"
    print("\nGenerating captures in code makes fuzz coverage a reproducible, "
          "asserted\nartifact - and the same rules become the defender's "
          "detection gate.")


if __name__ == "__main__":
    main()
