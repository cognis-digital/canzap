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
    "06_flood_detection",
    "07_j1939_extended",
    "08_multi_interface",
    "09_rtr_frames",
    "10_malformed_recovery",
    "11_dsl_validation",
    "12_regression_diff",
    "13_payload_decode",
    "14_cli_pipeline",
    "15_fuzz_campaign",
    "16_data_equals_match",
    "17_uds_session",
    "18_dbc_style_watchlist",
    "19_timing_jitter",
    "20_ci_gate_matrix",
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
