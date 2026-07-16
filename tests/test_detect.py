"""Tests for the heuristic detectors in canzap.detect.

Each test builds a controlled candump capture, runs the detectors, and asserts
on the concrete findings produced — severity, rule id, tags, and evidence.
"""
from __future__ import annotations

from canzap.core import parse_candump_text
from canzap.detect import (
    SEVERITIES,
    findings_to_sarif,
    max_severity,
    risk_score,
    scan_frames,
    scan_report,
    severity_rank,
)


def _frames(text: str):
    return parse_candump_text(text)


def _rules(findings):
    return {f["rule"] for f in findings}


def _by_rule(findings, rule):
    return [f for f in findings if f["rule"] == rule]


# --------------------------------------------------------------------------
# Severity helpers
# --------------------------------------------------------------------------


def test_severity_rank_is_ordered():
    ranks = [severity_rank(s) for s in SEVERITIES]
    assert ranks == sorted(ranks)
    assert severity_rank("critical") > severity_rank("info")
    assert severity_rank("unknown-name") == 0  # safe fallback


def test_max_severity_and_risk_score_empty():
    assert max_severity([]) is None
    assert risk_score([]) == 0


# --------------------------------------------------------------------------
# Individual detectors
# --------------------------------------------------------------------------


def test_diagnostics_detected_for_obd_ids():
    frames = _frames("(1.0) can0 7DF#0201050000000000\n(1.1) can0 7E8#0341050000000000")
    findings = scan_frames(frames)
    diag = _by_rule(findings, "diagnostic-traffic")
    assert len(diag) == 2
    assert all(f["severity"] == "medium" for f in diag)
    assert {f["can_id"] for f in diag} == {0x7DF, 0x7E8}
    assert "obd-ii" in diag[0]["tags"]


def test_non_diagnostic_id_not_flagged_as_diagnostic():
    frames = _frames("(1.0) can0 1A0#0BB8\n(1.1) can0 1A0#0BB8")
    assert not _by_rule(scan_frames(frames), "diagnostic-traffic")


def test_extended_id_detected():
    frames = _frames("(1.0) can1 18FF1234#01")
    ext = _by_rule(scan_frames(frames), "extended-id")
    assert len(ext) == 1
    assert ext[0]["severity"] == "info"
    assert ext[0]["can_id"] == 0x18FF1234


def test_rtr_frame_detected():
    frames = _frames("(1.0) can0 300#R")
    assert frames[0].rtr is True
    rtr = _by_rule(scan_frames(frames), "rtr-frame")
    assert len(rtr) == 1
    assert rtr[0]["severity"] == "low"


def test_bus_flood_detected():
    # 12 frames of 0x333 spaced 1ms apart -> dominates capture, sub-5ms cadence
    lines = [f"({1.0 + i * 0.001:.3f}) can0 333#DEADBEEF" for i in range(12)]
    lines += [f"({1.0 + i * 0.1:.3f}) can0 100#00" for i in range(3)]
    findings = scan_frames(_frames("\n".join(lines)))
    flood = _by_rule(findings, "bus-flood")
    assert len(flood) == 1
    assert flood[0]["severity"] == "high"
    assert flood[0]["can_id"] == 0x333
    assert flood[0]["share"] >= 0.4
    assert "dos" in flood[0]["tags"]


def test_no_flood_on_low_volume_capture():
    frames = _frames("(1.0) can0 333#00\n(1.001) can0 333#00\n(1.002) can0 333#00")
    assert not _by_rule(scan_frames(frames), "bus-flood")


def test_cadence_jitter_detected():
    # five frames at 100ms, then one 500ms gap -> worst >> median
    ts = [1.0, 1.1, 1.2, 1.3, 1.4, 1.9]
    frames = _frames("\n".join(f"({t:.3f}) can0 700#01" for t in ts))
    jit = _by_rule(scan_frames(frames), "cadence-jitter")
    assert len(jit) == 1
    assert jit[0]["severity"] == "medium"
    assert jit[0]["max_period_ms"] > jit[0]["median_period_ms"] * 3


def test_no_jitter_on_regular_cadence():
    ts = [1.0 + i * 0.1 for i in range(6)]
    frames = _frames("\n".join(f"({t:.3f}) can0 700#01" for t in ts))
    assert not _by_rule(scan_frames(frames), "cadence-jitter")


def test_singleton_injection_detected():
    # a busy capture (>=12 frames) with one ID appearing exactly once
    lines = [f"({1.0 + i * 0.1:.3f}) can0 700#01" for i in range(13)]
    lines.append("(3.0) can0 456#CAFE")
    findings = scan_frames(_frames("\n".join(lines)))
    lone = _by_rule(findings, "lone-frame")
    assert any(f["can_id"] == 0x456 for f in lone)


def test_dlc_variance_detected():
    frames = _frames("(1.0) can0 200#00\n(1.1) can0 200#0011\n(1.2) can0 200#001122")
    dv = _by_rule(scan_frames(frames), "dlc-variance")
    assert len(dv) == 1
    assert dv[0]["dlcs"] == [1, 2, 3]


# --------------------------------------------------------------------------
# Orchestration + serialization
# --------------------------------------------------------------------------


def test_scan_frames_sorted_by_descending_severity():
    lines = [f"({1.0 + i * 0.001:.3f}) can0 333#DEADBEEF" for i in range(12)]
    lines += [f"({1.0 + i * 0.1:.3f}) can0 7DF#02010500" for i in range(1)]
    findings = scan_frames(_frames("\n".join(lines)))
    ranks = [severity_rank(f["severity"]) for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_scan_report_shape():
    frames = _frames("(1.0) can0 7DF#0201050000000000")
    report = scan_report(frames)
    assert report["tool"] == "canzap"
    assert report["frame_count"] == 1
    assert report["finding_count"] == len(report["findings"])
    assert report["max_severity"] in SEVERITIES
    assert report["risk_score"] >= 1


def test_clean_capture_has_no_high_findings():
    ts = [1.0 + i * 0.1 for i in range(6)]
    frames = _frames("\n".join(f"({t:.3f}) can0 1A0#0BB80000" for t in ts))
    findings = scan_frames(frames)
    assert all(severity_rank(f["severity"]) < severity_rank("high") for f in findings)


def test_findings_to_sarif_structure():
    frames = _frames("(1.0) can0 7DF#0201050000000000")
    sarif = findings_to_sarif(scan_frames(frames))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "canzap"
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] in ("note", "warning", "error")
    assert run["results"][0]["ruleId"] == "diagnostic-traffic"
