"""CANZAP core engine.

Parses candump logs (the standard can-utils format) and evaluates a small
YAML-ish assertion DSL against the captured traffic. No third-party deps.

candump log line format (from `candump -l`):
    (1623241200.123456) can0 1A0#00FF12345678
    (<epoch.usec>) <iface> <CANID>#<HEXDATA>

The scenario DSL is intentionally a tiny YAML subset so we never need PyYAML:

    name: Engine startup checks
    assertions:
      - name: rpm frame present
        id: 0x1A0
        present: true
      - name: brake byte set
        id: 0x2B1
        byte: 0
        equals: 0xFF
      - name: heartbeat cadence
        id: 0x700
        min_count: 5
        max_period_ms: 120
      - name: no fault code
        id: 0x500
        present: false
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _read_version() -> str:
    """Read the package version from the repo ``VERSION`` file, if present."""
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, "VERSION"),
        os.path.join(os.path.dirname(here), "VERSION"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                v = fh.read().strip()
            if v:
                return v
        except OSError:
            continue
    return "0.1.0"


#: Public tool identity. Re-exported via :mod:`canzap` and used by the CLI.
TOOL_NAME = "canzap"
TOOL_VERSION = _read_version()

# --------------------------------------------------------------------------
# Data types
# --------------------------------------------------------------------------


@dataclass
class CanFrame:
    """A single decoded CAN frame."""

    timestamp: float  # seconds (epoch or relative); may be 0.0 if absent
    interface: str
    can_id: int
    data: bytes
    extended: bool = False
    rtr: bool = False  # remote transmission request frame

    @property
    def dlc(self) -> int:
        return len(self.data)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "interface": self.interface,
            "id": self.can_id,
            "id_hex": f"0x{self.can_id:X}",
            "dlc": self.dlc,
            "data": self.data.hex().upper(),
            "extended": self.extended,
            "rtr": self.rtr,
        }


@dataclass
class Assertion:
    """One declarative check against the captured frames."""

    name: str
    can_id: int
    present: Optional[bool] = None
    byte: Optional[int] = None
    equals: Optional[int] = None
    data_equals: Optional[bytes] = None
    min_count: Optional[int] = None
    max_count: Optional[int] = None
    max_period_ms: Optional[float] = None
    interface: Optional[str] = None


@dataclass
class Scenario:
    name: str
    assertions: List[Assertion] = field(default_factory=list)


@dataclass
class AssertResult:
    assertion: Assertion
    passed: bool
    detail: str
    observed: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.assertion.name,
            "id_hex": f"0x{self.assertion.can_id:X}",
            "passed": self.passed,
            "detail": self.detail,
            "observed": self.observed,
        }


@dataclass
class ScenarioResult:
    scenario: Scenario
    results: List[AssertResult]
    frame_count: int

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> List[AssertResult]:
        return [r for r in self.results if not r.passed]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario.name,
            "frame_count": self.frame_count,
            "passed": self.passed,
            "total": len(self.results),
            "failed": len(self.failures),
            "assertions": [r.to_dict() for r in self.results],
        }


# --------------------------------------------------------------------------
# candump parsing
# --------------------------------------------------------------------------

# (1623241200.123456) can0 1A0#00FF1234
_LOG_RE = re.compile(
    r"^\s*(?:\((?P<ts>[0-9]+(?:\.[0-9]+)?)\)\s+)?"
    r"(?P<iface>[A-Za-z0-9_-]+)\s+"
    r"(?P<id>[0-9A-Fa-f]+)"
    r"(?P<rtr>#R)?"
    r"#?"
    r"(?P<data>[0-9A-Fa-f]*)\s*$"
)


def parse_candump(line: str) -> Optional[CanFrame]:
    """Parse a single candump line. Returns None for blank/comment lines.

    Accepts both the timestamped log format and the plain `candump` console
    format. Raises ValueError on a line that looks like a frame but is malformed.
    """
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    # Normalise the canonical `IFACE  ID#DATA` form where id and data share a '#'.
    # The regex above is permissive; handle the common `1A0#00FF` shape directly.
    m = re.match(
        r"^\s*(?:\((?P<ts>[0-9]+(?:\.[0-9]+)?)\)\s+)?"
        r"(?P<iface>[A-Za-z0-9_-]+)\s+"
        r"(?P<id>[0-9A-Fa-f]+)#(?P<rtr>R)?(?P<data>[0-9A-Fa-f]*)\s*$",
        raw,
    )
    if not m:
        raise ValueError(f"unparseable candump line: {line.rstrip()!r}")

    ts = float(m.group("ts")) if m.group("ts") else 0.0
    iface = m.group("iface")
    id_str = m.group("id")
    can_id = int(id_str, 16)
    extended = len(id_str) > 3 or can_id > 0x7FF
    rtr = bool(m.group("rtr"))

    data_hex = m.group("data") or ""
    if len(data_hex) % 2 != 0:
        raise ValueError(f"odd-length data field in line: {line.rstrip()!r}")
    try:
        data = bytes.fromhex(data_hex)
    except ValueError as exc:
        raise ValueError(f"bad hex data in line {line.rstrip()!r}: {exc}")

    if len(data) > 64:
        raise ValueError(f"data exceeds 64 bytes (CAN FD max) in line: {line.rstrip()!r}")

    return CanFrame(
        timestamp=ts,
        interface=iface,
        can_id=can_id,
        data=data,
        extended=extended,
        rtr=rtr,
    )


def parse_candump_text(text: str) -> List[CanFrame]:
    """Parse an entire candump log into a list of frames."""
    frames: List[CanFrame] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        try:
            frame = parse_candump(line)
        except ValueError as exc:
            raise ValueError(f"line {lineno}: {exc}")
        if frame is not None:
            frames.append(frame)
    return frames


# --------------------------------------------------------------------------
# Scenario (mini YAML) parsing
# --------------------------------------------------------------------------


def _coerce_int(value: str) -> int:
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value, 10)


def _coerce_bool(value: str) -> bool:
    return value.strip().lower() in ("true", "yes", "on", "1")


def load_scenario_text(text: str) -> Scenario:
    """Parse the CANZAP mini-YAML scenario DSL into a Scenario.

    Supports a top-level `name:` and an `assertions:` list of `- key: value`
    blocks. Intentionally a strict subset so no PyYAML dependency is needed.
    """
    name = "scenario"
    assertions: List[Assertion] = []
    current: Optional[Dict[str, str]] = None
    in_assertions = False

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        if indent == 0 and stripped.startswith("name:") and not in_assertions:
            name = stripped.split(":", 1)[1].strip().strip('"\'') or name
            continue
        if indent == 0 and stripped.rstrip(":") == "assertions":
            in_assertions = True
            continue
        if not in_assertions:
            # Unknown top-level key; ignore gracefully.
            continue

        if stripped.startswith("- "):
            # New assertion block; flush previous.
            if current is not None:
                assertions.append(_build_assertion(current, lineno))
            current = {}
            stripped = stripped[2:].strip()
            if not stripped:
                continue
        if current is None:
            raise ValueError(f"line {lineno}: assertion key outside a '- ' list item")
        if ":" not in stripped:
            raise ValueError(f"line {lineno}: expected 'key: value', got {stripped!r}")
        key, val = stripped.split(":", 1)
        current[key.strip()] = val.strip().strip('"\'')

    if current is not None:
        assertions.append(_build_assertion(current, lineno=-1))

    return Scenario(name=name, assertions=assertions)


def _build_assertion(d: Dict[str, str], lineno: int) -> Assertion:
    if "id" not in d:
        raise ValueError(f"assertion near line {lineno} missing required 'id'")
    a = Assertion(name=d.get("name", d["id"]), can_id=_coerce_int(d["id"]))
    if "present" in d:
        a.present = _coerce_bool(d["present"])
    if "byte" in d:
        a.byte = _coerce_int(d["byte"])
    if "equals" in d:
        a.equals = _coerce_int(d["equals"])
    if "data_equals" in d:
        a.data_equals = bytes.fromhex(d["data_equals"].replace(" ", ""))
    if "min_count" in d:
        a.min_count = _coerce_int(d["min_count"])
    if "max_count" in d:
        a.max_count = _coerce_int(d["max_count"])
    if "max_period_ms" in d:
        a.max_period_ms = float(d["max_period_ms"])
    if "interface" in d:
        a.interface = d["interface"]
    return a


def load_scenario(path: str) -> Scenario:
    with open(path, "r", encoding="utf-8") as fh:
        return load_scenario_text(fh.read())


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------


def _matching(frames: List[CanFrame], a: Assertion) -> List[CanFrame]:
    out = []
    for f in frames:
        if f.can_id != a.can_id:
            continue
        if a.interface is not None and f.interface != a.interface:
            continue
        out.append(f)
    return out


def _eval_assertion(frames: List[CanFrame], a: Assertion) -> AssertResult:
    matches = _matching(frames, a)
    observed: Dict[str, Any] = {"count": len(matches)}

    # present / absent
    if a.present is False:
        if matches:
            return AssertResult(a, False, f"expected ID absent but found {len(matches)} frame(s)", observed)
        return AssertResult(a, True, "ID correctly absent", observed)

    if a.present is True and not matches:
        return AssertResult(a, False, "expected ID present but none found", observed)

    # Everything below needs at least one frame.
    if not matches and (a.byte is not None or a.equals is not None or a.data_equals is not None
                        or a.min_count is not None or a.max_period_ms is not None):
        return AssertResult(a, False, "no frames for this ID to evaluate", observed)

    # count constraints
    if a.min_count is not None and len(matches) < a.min_count:
        return AssertResult(a, False, f"count {len(matches)} < min_count {a.min_count}", observed)
    if a.max_count is not None and len(matches) > a.max_count:
        return AssertResult(a, False, f"count {len(matches)} > max_count {a.max_count}", observed)

    # byte equals (checked against the LAST matching frame)
    if a.byte is not None and a.equals is not None:
        last = matches[-1]
        if a.byte >= len(last.data):
            return AssertResult(a, False, f"byte index {a.byte} out of range (dlc={last.dlc})", observed)
        actual = last.data[a.byte]
        observed["byte_value"] = f"0x{actual:02X}"
        if actual != a.equals:
            return AssertResult(a, False, f"byte[{a.byte}]=0x{actual:02X}, expected 0x{a.equals:02X}", observed)

    # full data equals (last frame)
    if a.data_equals is not None:
        last = matches[-1]
        observed["data"] = last.data.hex().upper()
        if last.data != a.data_equals:
            return AssertResult(
                a, False,
                f"data {last.data.hex().upper()} != expected {a.data_equals.hex().upper()}",
                observed,
            )

    # cadence: max period between consecutive frames
    if a.max_period_ms is not None:
        if len(matches) < 2:
            return AssertResult(a, False, "need >=2 frames to measure period", observed)
        periods_ms = [
            (matches[i].timestamp - matches[i - 1].timestamp) * 1000.0
            for i in range(1, len(matches))
        ]
        worst = max(periods_ms)
        observed["max_period_ms"] = round(worst, 3)
        if worst > a.max_period_ms:
            return AssertResult(a, False, f"max gap {worst:.1f}ms > allowed {a.max_period_ms}ms", observed)

    return AssertResult(a, True, "ok", observed)


def run_scenario(frames: List[CanFrame], scenario: Scenario) -> ScenarioResult:
    """Evaluate every assertion in the scenario against the frames."""
    results = [_eval_assertion(frames, a) for a in scenario.assertions]
    return ScenarioResult(scenario=scenario, results=results, frame_count=len(frames))


def result_to_json(res: ScenarioResult) -> str:
    return json.dumps(res.to_dict(), indent=2)


# --------------------------------------------------------------------------
# Bus statistics
# --------------------------------------------------------------------------


def bus_stats(frames: List[CanFrame]) -> Dict[str, Any]:
    """Summarize a capture: per-ID counts, DLCs, and inter-frame timing.

    Returns a JSON-friendly dict with a top-level summary (frame count, unique
    ID count, capture duration, bus load) and a ``per_id`` list sorted by
    descending frame count. Timing fields are ``None`` when an ID has fewer than
    two frames (no gap to measure).
    """
    groups: Dict[int, List[CanFrame]] = {}
    for f in frames:
        groups.setdefault(f.can_id, []).append(f)

    timestamps = [f.timestamp for f in frames if f.timestamp]
    duration = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0

    per_id: List[Dict[str, Any]] = []
    for can_id, fr in groups.items():
        ordered = sorted(fr, key=lambda x: x.timestamp)
        periods = [
            (ordered[i].timestamp - ordered[i - 1].timestamp) * 1000.0
            for i in range(1, len(ordered))
        ]
        dlcs = sorted({x.dlc for x in fr})
        per_id.append(
            {
                "id": can_id,
                "id_hex": f"0x{can_id:X}",
                "count": len(fr),
                "extended": fr[0].extended,
                "interfaces": sorted({x.interface for x in fr}),
                "dlcs": dlcs,
                "min_period_ms": round(min(periods), 3) if periods else None,
                "max_period_ms": round(max(periods), 3) if periods else None,
                "avg_period_ms": round(sum(periods) / len(periods), 3) if periods else None,
            }
        )
    per_id.sort(key=lambda d: (-d["count"], d["id"]))

    return {
        "frame_count": len(frames),
        "unique_ids": len(groups),
        "duration_s": round(duration, 6),
        "frames_per_s": round(len(frames) / duration, 3) if duration else None,
        "interfaces": sorted({f.interface for f in frames}),
        "per_id": per_id,
    }


def diff_captures(baseline: List[CanFrame], candidate: List[CanFrame]) -> Dict[str, Any]:
    """Compare two captures by arbitration ID — the drive-log regression check.

    Reports IDs that appear only in the baseline (``removed``), only in the
    candidate (``added``), and IDs whose frame count changed (``changed``).
    ``identical`` is true when the two captures carry exactly the same set of
    IDs with the same per-ID counts.
    """
    def counts(frames: List[CanFrame]) -> Dict[int, int]:
        out: Dict[int, int] = {}
        for f in frames:
            out[f.can_id] = out.get(f.can_id, 0) + 1
        return out

    base_c = counts(baseline)
    cand_c = counts(candidate)

    added = [
        {"id_hex": f"0x{i:X}", "count": cand_c[i]}
        for i in sorted(cand_c) if i not in base_c
    ]
    removed = [
        {"id_hex": f"0x{i:X}", "count": base_c[i]}
        for i in sorted(base_c) if i not in cand_c
    ]
    changed = [
        {"id_hex": f"0x{i:X}", "baseline": base_c[i], "candidate": cand_c[i]}
        for i in sorted(set(base_c) & set(cand_c))
        if base_c[i] != cand_c[i]
    ]
    return {
        "baseline_frames": len(baseline),
        "candidate_frames": len(candidate),
        "added": added,
        "removed": removed,
        "changed": changed,
        "identical": not (added or removed or changed),
    }


# --------------------------------------------------------------------------
# Heuristic scan (delegates to canzap.detect) — powers `canzap scan` and MCP
# --------------------------------------------------------------------------


def _load_frames_from_target(target: str) -> List[CanFrame]:
    """Resolve ``target`` (file path, directory of logs, or raw text) to frames.

    - A file path is read and parsed.
    - A directory is scanned for ``*.log`` / ``*.candump`` capture files, all of
      which are parsed and concatenated.
    - Anything else is treated as raw candump text.
    """
    if os.path.isdir(target):
        frames: List[CanFrame] = []
        for root, _dirs, files in os.walk(target):
            for name in sorted(files):
                if name.endswith((".log", ".candump")):
                    with open(os.path.join(root, name), "r", encoding="utf-8") as fh:
                        frames.extend(parse_candump_text(fh.read()))
        return frames
    if os.path.isfile(target):
        with open(target, "r", encoding="utf-8") as fh:
            return parse_candump_text(fh.read())
    return parse_candump_text(target)


def scan(target: str) -> Dict[str, Any]:
    """Heuristically scan a capture and return a findings report.

    ``target`` may be a candump log file, a directory of captures, or raw
    candump text. Returns the report dict from :func:`canzap.detect.scan_report`.
    This is the function exposed over MCP by :mod:`canzap.mcp_server`.
    """
    from canzap.detect import scan_report  # local import avoids a cycle

    return scan_report(_load_frames_from_target(target))


def to_json(obj: Any) -> str:
    """Serialize any canzap result object to indented JSON."""
    return json.dumps(obj, indent=2)
