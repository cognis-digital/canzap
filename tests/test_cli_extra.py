"""CLI-level coverage: error paths, stdin, help, and dump table output."""
from __future__ import annotations

import io
import sys

from canzap.cli import build_parser, main


def test_no_command_prints_help_and_returns_2(capsys):
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 2
    assert "usage:" in out.lower()


def test_missing_log_file_returns_2(capsys, tmp_path):
    scn = tmp_path / "s.canzap"
    scn.write_text("name: t\nassertions:\n  - name: x\n    id: 0x1\n    present: true\n")
    rc = main(["check", "--log", str(tmp_path / "nope.log"), "--scenario", str(scn)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "error" in err.lower()


def test_bad_hex_log_returns_2(capsys, tmp_path):
    log = tmp_path / "bad.log"
    log.write_text("(1.0) can0 1A0#0BZ8\n")
    scn = tmp_path / "s.canzap"
    scn.write_text("name: t\nassertions:\n  - name: x\n    id: 0x1A0\n    present: true\n")
    rc = main(["check", "--log", str(log), "--scenario", str(scn)])
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_dump_table_output(capsys, tmp_path):
    log = tmp_path / "c.log"
    log.write_text("(1.0) can0 1A0#0BB8\n(1.1) can0 700#01\n")
    rc = main(["dump", "--log", str(log)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "2 frames" in out
    assert "0x1A0" in out


def test_check_reads_stdin(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "stdin", io.StringIO("(1.0) can0 1A0#0BB8\n"))
    scn = tmp_path / "s.canzap"
    scn.write_text("name: t\nassertions:\n  - name: rpm\n    id: 0x1A0\n    present: true\n")
    rc = main(["check", "--log", "-", "--scenario", str(scn)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "1/1 passed" in out


def test_parser_exposes_all_subcommands():
    parser = build_parser()
    # argparse stores subparser names on the 'command' action choices
    choices = set()
    for action in parser._actions:
        if getattr(action, "dest", None) == "command" and action.choices:
            choices = set(action.choices)
    assert {"check", "dump", "scan", "stats", "diff", "mcp"} <= choices
