"""Hardening tests: error paths, edge cases, and robust input handling."""

import pytest
from canzap.core import (
    _coerce_int,
    load_scenario_text,
    load_scenario,
    parse_candump_text,
    run_scenario,
)
from canzap.cli import main


def test_coerce_int_bad_decimal_gives_clear_message():
    with pytest.raises(ValueError, match="notanumber"):
        _coerce_int("notanumber", field="byte")


def test_coerce_int_bad_hex_gives_clear_message():
    with pytest.raises(ValueError, match="0xZZZZ"):
        _coerce_int("0xZZZZ", field="id")


def test_coerce_int_empty_string_raises():
    with pytest.raises(ValueError, match="must not be empty"):
        _coerce_int("", field="min_count")


def test_scenario_bad_hex_in_data_equals():
    text = 'name: t\nassertions:\n  - name: x\n    id: 0x1A0\n    data_equals: ZZ\n'
    with pytest.raises(ValueError, match="not valid hex"):
        load_scenario_text(text)


def test_scenario_bad_integer_in_byte_field():
    text = (
        'name: t\nassertions:\n  - name: x\n'
        '    id: 0x1A0\n    byte: notanumber\n    equals: 0x00\n'
    )
    with pytest.raises(ValueError, match="byte"):
        load_scenario_text(text)


def test_scenario_negative_min_count_rejected():
    text = 'name: t\nassertions:\n  - name: x\n    id: 0x1A0\n    min_count: -1\n'
    with pytest.raises(ValueError, match="min_count"):
        load_scenario_text(text)


def test_scenario_zero_max_period_ms_rejected():
    text = 'name: t\nassertions:\n  - name: x\n    id: 0x700\n    max_period_ms: 0\n'
    with pytest.raises(ValueError, match="max_period_ms.*positive"):
        load_scenario_text(text)


def test_scenario_bad_max_period_ms_string():
    text = 'name: t\nassertions:\n  - name: x\n    id: 0x700\n    max_period_ms: fast\n'
    with pytest.raises(ValueError, match="max_period_ms.*must be a number"):
        load_scenario_text(text)


def test_load_scenario_missing_file_raises_fnf():
    with pytest.raises(FileNotFoundError):
        load_scenario("/tmp/does_not_exist_canzap_hardening.canzap")


def test_cli_missing_log_exits_2(capsys):
    rc = main(
        ["check", "--log", "/tmp/no_such_hardening.log",
         "--scenario", "x.canzap"]
    )
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_cli_missing_scenario_exits_2(tmp_path, capsys):
    log = tmp_path / "ok.log"
    log.write_text('(1.0) can0 1A0#01\n')
    rc = main(
        ["check", "--log", str(log), "--scenario",
         str(tmp_path / "missing.canzap")]
    )
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_cli_malformed_scenario_exits_2(tmp_path, capsys):
    log = tmp_path / "ok.log"
    log.write_text('(1.0) can0 1A0#01\n')
    scn = tmp_path / "bad.canzap"
    scn.write_text(
        'name: t\nassertions:\n  - name: x\n'
        '    id: 0x1A0\n    data_equals: ZZ\n'
    )
    rc = main(["check", "--log", str(log), "--scenario", str(scn)])
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_cli_permission_error_exits_2(tmp_path, capsys):
    import unittest.mock as mock
    log = tmp_path / "ok.log"
    log.write_text('(1.0) can0 1A0#01\n')
    scn = tmp_path / "s.canzap"
    scn.write_text(
        'name: t\nassertions:\n  - name: rpm\n'
        '    id: 0x1A0\n    present: true\n'
    )
    original_open = open
    def patched_open(path, *args, **kwargs):
        if "ok.log" in str(path):
            raise PermissionError("Permission denied")
        return original_open(path, *args, **kwargs)
    with mock.patch("builtins.open", patched_open):
        rc = main(["check", "--log", str(log), "--scenario", str(scn)])
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_cli_no_subcommand_exits_2():
    assert main([]) == 2


def test_empty_log_returns_zero_frames():
    assert parse_candump_text("") == []


def test_log_with_only_comments_returns_zero_frames():
    assert parse_candump_text('# header\n# another comment\n\n') == []


def test_run_scenario_empty_frames_present_true_fails():
    sc = load_scenario_text(
        'name: t\nassertions:\n  - name: rpm\n'
        '    id: 0x1A0\n    present: true\n'
    )
    res = run_scenario([], sc)
    assert res.passed is False
    assert res.frame_count == 0


def test_run_scenario_no_assertions_vacuously_true():
    sc = load_scenario_text('name: empty\nassertions:\n')
    res = run_scenario([], sc)
    assert res.passed is True
    assert len(res.results) == 0


def test_mcp_server_importable_without_broken_references():
    """mcp_server.py must not raise ImportError at module-import time.

    The old code imported non-existent names (scan, to_json) from core,
    causing an ImportError on every import. This test verifies the module
    loads cleanly and serve() is callable without crashing at definition time.
    """
    import importlib
    # This must NOT raise ImportError (was broken before hardening)
    mod = importlib.import_module("canzap.mcp_server")
    assert callable(mod.serve)
