"""Tests for bus_stats and the `canzap stats` subcommand."""
from __future__ import annotations

import json

from canzap.core import bus_stats, parse_candump_text
from canzap.cli import main


def test_bus_stats_counts_and_timing():
    text = (
        "(1.000) can0 700#01\n"
        "(1.100) can0 700#01\n"
        "(1.200) can0 700#01\n"
        "(1.050) can1 1A0#0BB8\n"
    )
    stats = bus_stats(parse_candump_text(text))
    assert stats["frame_count"] == 4
    assert stats["unique_ids"] == 2
    assert stats["interfaces"] == ["can0", "can1"]

    by_id = {row["id_hex"]: row for row in stats["per_id"]}
    hb = by_id["0x700"]
    assert hb["count"] == 3
    # two 100ms gaps
    assert hb["min_period_ms"] == 100.0
    assert hb["max_period_ms"] == 100.0
    assert hb["avg_period_ms"] == 100.0

    rpm = by_id["0x1A0"]
    assert rpm["count"] == 1
    assert rpm["min_period_ms"] is None  # single frame -> no gap


def test_bus_stats_sorted_by_count_desc():
    text = "(1.0) can0 100#00\n(1.1) can0 200#00\n(1.2) can0 200#00"
    per_id = bus_stats(parse_candump_text(text))["per_id"]
    assert per_id[0]["id_hex"] == "0x200"
    assert per_id[0]["count"] == 2


def test_stats_cli_json(capsys):
    text = "(1.0) can0 700#01\n(1.1) can0 700#01"
    import tempfile
    import os
    fd, path = tempfile.mkstemp(suffix=".log")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        rc = main(["stats", "--log", path, "--format", "json"])
    finally:
        os.unlink(path)
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["frame_count"] == 2
    assert data["unique_ids"] == 1


def test_stats_cli_table(capsys):
    text = "(1.0) can0 700#01\n(1.1) can0 700#01"
    import tempfile
    import os
    fd, path = tempfile.mkstemp(suffix=".log")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        rc = main(["stats", "--log", path])
    finally:
        os.unlink(path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "Unique IDs: 1" in out
    assert "0x700" in out
