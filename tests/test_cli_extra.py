"""CLI error paths, exit codes, stdin handling, and output formats."""
import io
import json
import sys

import pytest

from canzap.cli import build_parser, main


# --------------------------------------------------------------------------
# no-command / help / version
# --------------------------------------------------------------------------


def test_no_command_prints_help_and_returns_2(capsys):
    rc = main([])
    assert rc == 2
    assert "usage" in capsys.readouterr().out.lower()


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "canzap" in capsys.readouterr().out


def test_parser_builds():
    p = build_parser()
    args = p.parse_args(["check", "--log", "x", "--scenario", "y"])
    assert args.command == "check"


# --------------------------------------------------------------------------
# error exit codes (2 for bad input, not a traceback)
# --------------------------------------------------------------------------


def test_missing_log_file_returns_2(capsys):
    rc = main(["dump", "--log", "/no/such/file.log"])
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_missing_scenario_file_returns_2(tmp_path, capsys):
    log = tmp_path / "c.log"
    log.write_text("(1.0) can0 1A0#00\n")
    rc = main(["check", "--log", str(log), "--scenario", "/no/such.canzap"])
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_malformed_log_returns_2(tmp_path, capsys):
    log = tmp_path / "bad.log"
    log.write_text("(1.0) can0 1A0#0BZ8\n")
    scn = tmp_path / "s.canzap"
    scn.write_text("assertions:\n  - id: 0x1A0\n    present: true\n")
    rc = main(["check", "--log", str(log), "--scenario", str(scn)])
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_malformed_scenario_returns_2(tmp_path, capsys):
    log = tmp_path / "c.log"
    log.write_text("(1.0) can0 1A0#00\n")
    scn = tmp_path / "s.canzap"
    scn.write_text("assertions:\n  - id: notanumber\n")
    rc = main(["check", "--log", str(log), "--scenario", str(scn)])
    assert rc == 2


# --------------------------------------------------------------------------
# check: pass / fail exit codes
# --------------------------------------------------------------------------


def _write_pair(tmp_path, log_text, scn_text):
    log = tmp_path / "c.log"
    scn = tmp_path / "s.canzap"
    log.write_text(log_text)
    scn.write_text(scn_text)
    return str(log), str(scn)


def test_check_pass_exit_0(tmp_path):
    log, scn = _write_pair(tmp_path, "(1.0) can0 1A0#00\n",
                           "assertions:\n  - id: 0x1A0\n    present: true\n")
    assert main(["check", "--log", log, "--scenario", scn]) == 0


def test_check_fail_exit_1(tmp_path):
    log, scn = _write_pair(tmp_path, "(1.0) can0 200#00\n",
                           "assertions:\n  - id: 0x1A0\n    present: true\n")
    assert main(["check", "--log", log, "--scenario", scn]) == 1


def test_check_table_shows_fail_detail(tmp_path, capsys):
    log, scn = _write_pair(tmp_path, "(1.0) can0 200#00\n",
                           "assertions:\n  - name: rpm\n    id: 0x1A0\n    present: true\n")
    main(["check", "--log", log, "--scenario", scn])
    out = capsys.readouterr().out
    assert "[FAIL]" in out and "0/1 passed" in out


def test_check_json_fail_shape(tmp_path, capsys):
    log, scn = _write_pair(tmp_path, "(1.0) can0 200#00\n",
                           "assertions:\n  - id: 0x1A0\n    present: true\n")
    main(["check", "--log", log, "--scenario", scn, "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["passed"] is False and data["failed"] == 1


def test_format_before_subcommand_also_works(tmp_path, capsys):
    log, scn = _write_pair(tmp_path, "(1.0) can0 1A0#00\n",
                           "assertions:\n  - id: 0x1A0\n    present: true\n")
    # global --format placed before the subcommand
    main(["--format", "json", "check", "--log", log, "--scenario", scn])
    data = json.loads(capsys.readouterr().out)
    assert data["passed"] is True


# --------------------------------------------------------------------------
# dump
# --------------------------------------------------------------------------


def test_dump_table(tmp_path, capsys):
    log, _ = _write_pair(tmp_path, "(1.0) can0 1A0#DEAD\n", "assertions:\n  - id: 0x1\n")
    rc = main(["dump", "--log", log])
    assert rc == 0
    out = capsys.readouterr().out
    assert "1A0" in out and "1 frames" in out


def test_dump_json(tmp_path, capsys):
    log, _ = _write_pair(tmp_path,
                         "(1.0) can0 1A0#DEAD\n(1.1) can0 2B1#00\n",
                         "assertions:\n  - id: 0x1\n")
    rc = main(["dump", "--log", log, "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 2 and data[0]["data"] == "DEAD"


def test_dump_never_fails_on_empty(tmp_path, capsys):
    log, _ = _write_pair(tmp_path, "# only a comment\n", "assertions:\n  - id: 0x1\n")
    rc = main(["dump", "--log", log, "--format", "json"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == []


# --------------------------------------------------------------------------
# stdin ('-') handling
# --------------------------------------------------------------------------


def test_dump_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("(1.0) can0 1A0#DEAD\n"))
    rc = main(["dump", "--log", "-", "--format", "json"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)[0]["id_hex"] == "0x1A0"


def test_check_reads_log_from_stdin(monkeypatch, tmp_path, capsys):
    scn = tmp_path / "s.canzap"
    scn.write_text("assertions:\n  - id: 0x1A0\n    present: true\n")
    monkeypatch.setattr(sys, "stdin", io.StringIO("(1.0) can0 1A0#00\n"))
    rc = main(["check", "--log", "-", "--scenario", str(scn)])
    assert rc == 0
