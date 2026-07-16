"""CANZAP heuristic detectors.

Turns a parsed CAN capture into a prioritized list of *findings* — notable or
suspicious traffic patterns that a security researcher, ECU engineer, or
incident responder would want surfaced automatically. This is the engine behind
``canzap scan``.

Every detector is a pure function of the frame list (no I/O, no network, fully
deterministic), so a given capture always yields the same findings — which is
what makes ``scan`` usable as a CI gate. Findings are plain dicts so they
serialize straight to JSON / SARIF and map cleanly onto the ``cognis-connect``
``Finding`` schema used by :mod:`canzap.connect`.

The heuristics are intentionally conservative and explainable; each finding
records the concrete evidence (counts, timings, DLCs) that triggered it.
"""

from __future__ import annotations

from statistics import median
from typing import Any, Dict, List, Optional

from canzap.core import CanFrame

# --------------------------------------------------------------------------
# Severity model
# --------------------------------------------------------------------------

#: Ordered from least to most severe. Used for ``--fail-on`` gating and sorting.
SEVERITIES: List[str] = ["info", "low", "medium", "high", "critical"]

_SEV_RANK: Dict[str, int] = {name: i for i, name in enumerate(SEVERITIES)}


def severity_rank(severity: str) -> int:
    """Return the numeric rank of a severity name (``info`` -> 0 ... ``critical`` -> 4)."""
    return _SEV_RANK.get(severity.lower(), 0)


# Standardized OBD-II / UDS diagnostic arbitration IDs. Traffic here means
# someone is talking to the diagnostic stack of an ECU.
_OBD_FUNCTIONAL = 0x7DF          # functional (broadcast) request
_OBD_PHYS_LOW = 0x7E0            # physical request/response window
_OBD_PHYS_HIGH = 0x7EF


def _finding(
    rule: str,
    severity: str,
    can_id: int,
    description: str,
    tags: List[str],
    *,
    data_hex: str = "",
    count: int = 0,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build one finding dict in the canonical, JSON/SARIF-friendly shape."""
    rec: Dict[str, Any] = {
        "rule": rule,
        "type": "can_anomaly",
        "severity": severity,
        "can_id": can_id,
        "id_hex": f"0x{can_id:X}",
        "data_hex": data_hex,
        "count": count,
        "description": description,
        "tags": tags,
    }
    if extra:
        rec.update(extra)
    return rec


# --------------------------------------------------------------------------
# Per-ID helpers
# --------------------------------------------------------------------------


def _group_by_id(frames: List[CanFrame]) -> Dict[int, List[CanFrame]]:
    groups: Dict[int, List[CanFrame]] = {}
    for f in frames:
        groups.setdefault(f.can_id, []).append(f)
    return groups


def _periods_ms(frames: List[CanFrame]) -> List[float]:
    """Inter-frame gaps in milliseconds for a single ID's frames (time-ordered)."""
    ordered = sorted(frames, key=lambda f: f.timestamp)
    return [
        (ordered[i].timestamp - ordered[i - 1].timestamp) * 1000.0
        for i in range(1, len(ordered))
    ]


# --------------------------------------------------------------------------
# Detectors — each returns zero or more findings
# --------------------------------------------------------------------------


def detect_diagnostics(groups: Dict[int, List[CanFrame]]) -> List[Dict[str, Any]]:
    """Flag standardized OBD-II / UDS diagnostic IDs on the bus."""
    out: List[Dict[str, Any]] = []
    for can_id, fr in sorted(groups.items()):
        is_diag = can_id == _OBD_FUNCTIONAL or _OBD_PHYS_LOW <= can_id <= _OBD_PHYS_HIGH
        if not is_diag:
            continue
        kind = "functional broadcast" if can_id == _OBD_FUNCTIONAL else "physical request/response"
        out.append(
            _finding(
                "diagnostic-traffic",
                "medium",
                can_id,
                f"OBD-II/UDS diagnostic traffic ({kind}) observed on {len(fr)} frame(s); "
                "diagnostic sessions can read/clear DTCs or invoke actuator tests.",
                ["diagnostics", "obd-ii", "uds"],
                data_hex=fr[-1].data.hex().upper(),
                count=len(fr),
            )
        )
    return out


def detect_extended_ids(groups: Dict[int, List[CanFrame]]) -> List[Dict[str, Any]]:
    """Flag extended (29-bit) arbitration IDs — common on J1939 / higher layers."""
    out: List[Dict[str, Any]] = []
    for can_id, fr in sorted(groups.items()):
        if fr[0].extended:
            out.append(
                _finding(
                    "extended-id",
                    "info",
                    can_id,
                    f"Extended 29-bit arbitration ID seen on {len(fr)} frame(s).",
                    ["extended-id", "j1939"],
                    data_hex=fr[-1].data.hex().upper(),
                    count=len(fr),
                )
            )
    return out


def detect_rtr(groups: Dict[int, List[CanFrame]]) -> List[Dict[str, Any]]:
    """Flag remote-transmission-request frames (can be used to solicit data)."""
    out: List[Dict[str, Any]] = []
    for can_id, fr in sorted(groups.items()):
        rtr = [f for f in fr if getattr(f, "rtr", False)]
        if rtr:
            out.append(
                _finding(
                    "rtr-frame",
                    "low",
                    can_id,
                    f"{len(rtr)} remote-transmission-request (RTR) frame(s); RTR can be "
                    "abused to poll or fingerprint ECUs.",
                    ["rtr"],
                    count=len(rtr),
                )
            )
    return out


def detect_flood(
    groups: Dict[int, List[CanFrame]], total: int
) -> List[Dict[str, Any]]:
    """Flag an ID that dominates the capture — a hallmark of a flood / bus DoS.

    Triggers when a single ID both carries a large share of all frames and
    appears at a very high rate (sub-5ms mean period), which is well above the
    cadence of normal periodic powertrain traffic.
    """
    out: List[Dict[str, Any]] = []
    if total < 10:
        return out
    for can_id, fr in sorted(groups.items()):
        share = len(fr) / total
        periods = _periods_ms(fr)
        mean_period = sum(periods) / len(periods) if periods else float("inf")
        if share >= 0.4 and len(fr) >= 8 and mean_period < 5.0:
            out.append(
                _finding(
                    "bus-flood",
                    "high",
                    can_id,
                    f"ID accounts for {share * 100:.0f}% of the capture "
                    f"({len(fr)} frames, mean gap {mean_period:.2f}ms) — consistent with a "
                    "flood / bus denial-of-service or an aggressive injection.",
                    ["flood", "dos", "injection"],
                    data_hex=fr[-1].data.hex().upper(),
                    count=len(fr),
                    extra={"mean_period_ms": round(mean_period, 3), "share": round(share, 3)},
                )
            )
    return out


def detect_jitter(groups: Dict[int, List[CanFrame]]) -> List[Dict[str, Any]]:
    """Flag periodic IDs whose worst gap far exceeds their typical cadence.

    A dropped or delayed periodic frame (or a spoofed frame breaking cadence)
    shows up as a max gap several times the median period.
    """
    out: List[Dict[str, Any]] = []
    for can_id, fr in sorted(groups.items()):
        periods = _periods_ms(fr)
        if len(periods) < 4:
            continue
        med = median(periods)
        worst = max(periods)
        if med > 0 and worst > med * 3 and worst - med > 20.0:
            out.append(
                _finding(
                    "cadence-jitter",
                    "medium",
                    can_id,
                    f"Periodic ID has an irregular gap of {worst:.1f}ms vs a typical "
                    f"{med:.1f}ms — a dropped, delayed, or injected frame.",
                    ["timing", "jitter"],
                    count=len(fr),
                    extra={"median_period_ms": round(med, 3), "max_period_ms": round(worst, 3)},
                )
            )
    return out


def detect_singletons(
    groups: Dict[int, List[CanFrame]], total: int
) -> List[Dict[str, Any]]:
    """Flag IDs that appear exactly once in an otherwise busy capture.

    On a steady-state bus most IDs are periodic; a one-shot ID can be an
    injected/spoofed frame.
    """
    out: List[Dict[str, Any]] = []
    if total < 12:
        return out
    for can_id, fr in sorted(groups.items()):
        if len(fr) == 1:
            out.append(
                _finding(
                    "lone-frame",
                    "low",
                    can_id,
                    "ID appears exactly once on an otherwise periodic bus — possible "
                    "injected or spoofed frame.",
                    ["injection", "anomaly"],
                    data_hex=fr[0].data.hex().upper(),
                    count=1,
                )
            )
    return out


def detect_dlc_variance(groups: Dict[int, List[CanFrame]]) -> List[Dict[str, Any]]:
    """Flag an ID whose payload length changes across frames (usually fixed)."""
    out: List[Dict[str, Any]] = []
    for can_id, fr in sorted(groups.items()):
        dlcs = {f.dlc for f in fr}
        if len(fr) >= 3 and len(dlcs) > 1:
            out.append(
                _finding(
                    "dlc-variance",
                    "low",
                    can_id,
                    f"Payload length varies ({sorted(dlcs)}) across {len(fr)} frames; a "
                    "well-behaved signal usually has a fixed DLC.",
                    ["dlc", "anomaly"],
                    count=len(fr),
                    extra={"dlcs": sorted(dlcs)},
                )
            )
    return out


# --------------------------------------------------------------------------
# Orchestration + serialization
# --------------------------------------------------------------------------

#: The default detector pipeline, in evaluation order.
DETECTORS = (
    detect_diagnostics,
    detect_extended_ids,
    detect_rtr,
    detect_flood,
    detect_jitter,
    detect_singletons,
    detect_dlc_variance,
)


def scan_frames(frames: List[CanFrame]) -> List[Dict[str, Any]]:
    """Run every detector over ``frames`` and return findings, most-severe first.

    Findings are sorted by descending severity, then by arbitration ID, so the
    highest-priority items are always at the top of table/JSON output.
    """
    groups = _group_by_id(frames)
    total = len(frames)
    findings: List[Dict[str, Any]] = []
    for detector in DETECTORS:
        if detector in (detect_flood, detect_singletons):
            findings.extend(detector(groups, total))  # type: ignore[call-arg]
        else:
            findings.extend(detector(groups))  # type: ignore[call-arg]
    findings.sort(key=lambda f: (-severity_rank(f["severity"]), f["can_id"]))
    return findings


def risk_score(findings: List[Dict[str, Any]]) -> int:
    """A single integer risk score: the sum of per-finding severity weights."""
    return sum(severity_rank(f["severity"]) + 1 for f in findings)


def max_severity(findings: List[Dict[str, Any]]) -> Optional[str]:
    """Return the highest severity present, or ``None`` for an empty list."""
    if not findings:
        return None
    return max(findings, key=lambda f: severity_rank(f["severity"]))["severity"]


def scan_report(frames: List[CanFrame]) -> Dict[str, Any]:
    """Build the full ``scan`` report object (findings + summary metadata)."""
    findings = scan_frames(frames)
    return {
        "tool": "canzap",
        "frame_count": len(frames),
        "finding_count": len(findings),
        "risk_score": risk_score(findings),
        "max_severity": max_severity(findings),
        "findings": findings,
    }


def findings_to_sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Render findings as a SARIF 2.1.0 document for code-scanning ingestion."""
    sarif_level = {
        "info": "note",
        "low": "note",
        "medium": "warning",
        "high": "error",
        "critical": "error",
    }
    rule_ids = sorted({f["rule"] for f in findings})
    rules = [
        {"id": rid, "name": rid, "shortDescription": {"text": rid.replace("-", " ")}}
        for rid in rule_ids
    ]
    results = [
        {
            "ruleId": f["rule"],
            "level": sarif_level.get(f["severity"], "warning"),
            "message": {"text": f["description"]},
            "properties": {
                "id_hex": f["id_hex"],
                "severity": f["severity"],
                "count": f["count"],
                "tags": f["tags"],
            },
        }
        for f in findings
    ]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "canzap",
                        "informationUri": "https://github.com/cognis-digital/canzap",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
