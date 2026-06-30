"""Run every CANZAP demo scenario end to end.

    python demos/run_all.py

Each scenario is independent and replays a bundled candump capture fixture
through the real `canzap.core` API - fully offline, no CAN hardware. Every
scenario prints narrated output and exits 0, so this doubles as a smoke test.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "01_security_researcher",
    "02_ecu_engineer",
    "03_red_team",
    "04_ir_forensics",
    "05_bus_report",
]


def main() -> None:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 70)
    print("  All CANZAP demo scenarios completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
