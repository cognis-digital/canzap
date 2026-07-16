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
    bus_stats,
    diff_captures,
    parse_candump_text,
    load_scenario,
    run_scenario,
    scan as scan_target,
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


def _cmd_scan(args: argparse.Namespace) -> int:
    from .detect import findings_to_sarif, severity_rank

    report = scan_target(args.target)
    findings = report["findings"]

    fmt = getattr(args, "format", "table")
    if fmt == "json":
        print(json.dumps(report, indent=2))
    elif fmt == "sarif":
        print(json.dumps(findings_to_sarif(findings), indent=2))
    else:
        sev_w = {"info": "INFO", "low": "LOW", "medium": "MEDIUM",
                 "high": "HIGH", "critical": "CRITICAL"}
        for f in findings:
            print(f"  [{sev_w.get(f['severity'], f['severity']).upper():<8}] "
                  f"{f['rule']:<18} {f['id_hex']:<8} {f['description']}")
        if not findings:
            print("  no findings")
        print()
        print(f"  {report['finding_count']} finding(s) · "
              f"risk score {report['risk_score']} · {report['frame_count']} frames")

    # --fail-on gate: exit non-zero if any finding meets/exceeds the threshold.
    if args.fail_on:
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f["severity"]) >= threshold for f in findings):
            return 1
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    frames = parse_candump_text(_read(args.log))
    stats = bus_stats(frames)
    if args.format == "json":
        print(json.dumps(stats, indent=2))
    else:
        print(f"Frames: {stats['frame_count']}   Unique IDs: {stats['unique_ids']}   "
              f"Duration: {stats['duration_s']}s")
        print("-" * 72)
        print(f"{'ID':<8} {'COUNT':>6} {'DLCs':<10} {'min ms':>9} {'avg ms':>9} {'max ms':>9}")
        print("-" * 72)
        for row in stats["per_id"]:
            dlcs = ",".join(str(d) for d in row["dlcs"])
            print(f"{row['id_hex']:<8} {row['count']:>6} {dlcs:<10} "
                  f"{_fmt_ms(row['min_period_ms']):>9} "
                  f"{_fmt_ms(row['avg_period_ms']):>9} "
                  f"{_fmt_ms(row['max_period_ms']):>9}")
        print("-" * 72)
    return 0


def _fmt_ms(value: Optional[float]) -> str:
    return "-" if value is None else f"{value:.1f}"


def _cmd_diff(args: argparse.Namespace) -> int:
    baseline = parse_candump_text(_read(args.baseline))
    candidate = parse_candump_text(_read(args.candidate))
    result = diff_captures(baseline, candidate)
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Baseline: {result['baseline_frames']} frames   "
              f"Candidate: {result['candidate_frames']} frames")
        print("-" * 60)
        for row in result["added"]:
            print(f"  + {row['id_hex']:<8} (added, x{row['count']})")
        for row in result["removed"]:
            print(f"  - {row['id_hex']:<8} (removed, was x{row['count']})")
        for row in result["changed"]:
            print(f"  ~ {row['id_hex']:<8} ({row['baseline']} -> {row['candidate']})")
        print("-" * 60)
        print("identical" if result["identical"]
              else f"{len(result['added'])} added, {len(result['removed'])} removed, "
                   f"{len(result['changed'])} changed")
    return 0 if result["identical"] else 1


def _cmd_mcp(args: argparse.Namespace) -> int:
    from .mcp_server import serve
    return serve()


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

    fmt = dict(choices=("table", "json"), default=argparse.SUPPRESS,
               help="output format (default: table); also accepted after the subcommand")

    pc = sub.add_parser("check", help="assert a candump log against a scenario")
    pc.add_argument("--log", required=True, help="candump log file ('-' for stdin)")
    pc.add_argument("--scenario", required=True, help="CANZAP scenario (.canzap) file")
    pc.add_argument("--format", **fmt)
    pc.set_defaults(func=_cmd_check)

    pd = sub.add_parser("dump", help="parse/replay a candump log into frames")
    pd.add_argument("--log", required=True, help="candump log file ('-' for stdin)")
    pd.add_argument("--format", **fmt)
    pd.set_defaults(func=_cmd_dump)

    ps = sub.add_parser("scan", help="heuristically scan a capture for anomalies")
    ps.add_argument("target", nargs="?", default=".",
                    help="candump log, a directory of logs, or '.' (default: '.')")
    ps.add_argument("--format", choices=("table", "json", "sarif"),
                    default=argparse.SUPPRESS,
                    help="output format: table (default), json, or sarif")
    ps.add_argument("--fail-on", dest="fail_on",
                    choices=("info", "low", "medium", "high", "critical"),
                    default=None,
                    help="exit non-zero if any finding meets/exceeds this severity")
    ps.set_defaults(func=_cmd_scan)

    pst = sub.add_parser("stats", help="per-ID counts, DLCs, and timing for a capture")
    pst.add_argument("--log", required=True, help="candump log file ('-' for stdin)")
    pst.add_argument("--format", **fmt)
    pst.set_defaults(func=_cmd_stats)

    pdf = sub.add_parser("diff", help="compare two captures by arbitration ID")
    pdf.add_argument("--baseline", required=True, help="baseline candump log")
    pdf.add_argument("--candidate", required=True, help="candidate candump log to compare")
    pdf.add_argument("--format", **fmt)
    pdf.set_defaults(func=_cmd_diff)

    pm = sub.add_parser("mcp", help="run the MCP server (needs the 'mcp' extra)")
    pm.set_defaults(func=_cmd_mcp)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
