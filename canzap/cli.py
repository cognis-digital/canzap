"""CANZAP command-line interface.

Examples:
    # Assert a candump log against a scenario (table output)
    canzap check --log capture.log --scenario startup.canzap

    # Machine-readable for CI; exits non-zero on any failed assertion
    canzap check --log capture.log --scenario startup.canzap --format json

    # Just summarise / replay a candump log into frames
    canzap dump --log capture.log --format json

    canzap --version
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    parse_candump_text,
    load_scenario,
    run_scenario,
)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _cmd_check(args: argparse.Namespace) -> int:
    frames = parse_candump_text(_read(args.log))
    scenario = load_scenario(args.scenario)
    res = run_scenario(frames, scenario)

    if args.format == "json":
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(f"Scenario: {res.scenario.name}   ({res.frame_count} frames)")
        print("-" * 60)
        for r in res.results:
            mark = "PASS" if r.passed else "FAIL"
            print(f"[{mark}] {r.assertion.name} ({r.to_dict()['id_hex']})")
            if not r.passed:
                print(f"        {r.detail}")
        print("-" * 60)
        print(f"{len(res.results) - len(res.failures)}/{len(res.results)} passed")

    return 0 if res.passed else 1


def _cmd_dump(args: argparse.Namespace) -> int:
    frames = parse_candump_text(_read(args.log))
    if args.format == "json":
        print(json.dumps([f.to_dict() for f in frames], indent=2))
    else:
        print(f"{'TIMESTAMP':>17}  {'IFACE':<6} {'ID':<8} {'DLC':>3}  DATA")
        print("-" * 60)
        for f in frames:
            print(
                f"{f.timestamp:>17.6f}  {f.interface:<6} "
                f"0x{f.can_id:<6X} {f.dlc:>3}  {f.data.hex().upper()}"
            )
        print("-" * 60)
        print(f"{len(frames)} frames")
    # dump never fails as a CI gate
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Replay and assert on CAN bus traffic from a candump log.",
        epilog=(
            "examples:\n"
            "  canzap check --log capture.log --scenario startup.canzap\n"
            "  canzap check --log capture.log --scenario s.canzap --format json\n"
            "  canzap dump --log capture.log --format json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )

    sub = p.add_subparsers(dest="command")

    pc = sub.add_parser("check", help="assert a candump log against a scenario")
    pc.add_argument("--log", required=True, help="candump log file ('-' for stdin)")
    pc.add_argument("--scenario", required=True, help="CANZAP scenario (.canzap) file")
    pc.set_defaults(func=_cmd_check)

    pd = sub.add_parser("dump", help="parse/replay a candump log into frames")
    pd.add_argument("--log", required=True, help="candump log file ('-' for stdin)")
    pd.set_defaults(func=_cmd_dump)

    # accept --format after the subcommand too (SUPPRESS so the subparser
    # doesn't overwrite a value already parsed at the top level)
    for spx in (pc, pd):
        spx.add_argument("--format", choices=["table", "json"],
                         default=argparse.SUPPRESS,
                         help="output format (default: table)")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, OSError, UnicodeDecodeError) as exc:
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
