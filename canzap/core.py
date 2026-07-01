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
        max_period_ms: 120     # deadline: a frame at least this often
      - name: not flooded
        id: 0x333
        min_period_ms: 5       # floor: frames closer than this == a flood
      - name: no fault code
        id: 0x500
        present: false
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

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
    rtr: bool = False  # remote-transmission-request frame (no data payload)

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
    min_period_ms: Optional[float] = None
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

# (1623241200.123456) can0 1A0#00FF1234    — id and data share the single '#'
# (1623241200.123456) can0 123#R            — remote-transmission-request frame
_LINE_RE = re.compile(
    r"^\s*(?:\((?P<ts>[0-9]+(?:\.[0-9]+)?)\)\s+)?"
    r"(?P<iface>[A-Za-z0-9_-]+)\s+"
    r"(?P<id>[0-9A-Fa-f]+)#(?P<rtr>R)?(?P<data>[0-9A-Fa-f]*)\s*$"
)

# An 11-bit standard ID fits in <=3 hex digits; an ID written with more hex
# digits (e.g. 29-bit extended) or a value above the 11-bit range is extended.
_STD_ID_MAX = 0x7FF


def parse_candump(line: str) -> Optional[CanFrame]:
    """Parse a single candump line. Returns None for blank/comment lines.

    Accepts both the timestamped log format and the plain `candump` console
    format, including remote-transmission-request (RTR) frames (``123#R``).
    Raises ValueError on a line that looks like a frame but is malformed.
    """
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    m = _LINE_RE.match(raw)
    if not m:
        raise ValueError(f"unparseable candump line: {line.rstrip()!r}")

    ts = float(m.group("ts")) if m.group("ts") else 0.0
    iface = m.group("iface")
    id_str = m.group("id")
    can_id = int(id_str, 16)
    if can_id > 0x1FFFFFFF:
        raise ValueError(
            f"CAN ID 0x{can_id:X} exceeds the 29-bit maximum in line: {line.rstrip()!r}"
        )
    # A value above the 11-bit range is always extended. Zero-padding an ID to
    # 4+ hex digits (e.g. "0700") must NOT flip a standard ID to extended, so we
    # classify on the numeric value, not the written width.
    extended = can_id > _STD_ID_MAX

    rtr = m.group("rtr") is not None
    data_hex = m.group("data") or ""
    if rtr and data_hex:
        raise ValueError(
            f"RTR frame must not carry data in line: {line.rstrip()!r}"
        )
    if len(data_hex) % 2 != 0:
        raise ValueError(f"odd-length data field in line: {line.rstrip()!r}")
    # The regex constrains the data field to hex, and the length is now even, so
    # fromhex cannot fail here; the guard stays defensive for future changes.
    try:
        data = bytes.fromhex(data_hex)
    except ValueError as exc:  # pragma: no cover - unreachable via the grammar
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


def _coerce_int(value: str, *, key: str = "value", lineno: int = -1) -> int:
    raw = value.strip()
    try:
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        if raw.lower().startswith("0b"):
            return int(raw, 2)
        return int(raw, 10)
    except ValueError:
        where = f" (line {lineno})" if lineno >= 0 else ""
        raise ValueError(f"{key!r}{where}: expected an integer, got {value.strip()!r}")


_BOOL_TRUE = ("true", "yes", "on", "1")
_BOOL_FALSE = ("false", "no", "off", "0")


def _coerce_bool(value: str, *, key: str = "value", lineno: int = -1) -> bool:
    v = value.strip().lower()
    if v in _BOOL_TRUE:
        return True
    if v in _BOOL_FALSE:
        return False
    where = f" (line {lineno})" if lineno >= 0 else ""
    raise ValueError(
        f"{key!r}{where}: expected a boolean (one of "
        f"{', '.join(_BOOL_TRUE + _BOOL_FALSE)}), got {value.strip()!r}"
    )


def load_scenario_text(text: str) -> Scenario:
    """Parse the CANZAP mini-YAML scenario DSL into a Scenario.

    Supports a top-level `name:` and an `assertions:` list of `- key: value`
    blocks. Intentionally a strict subset so no PyYAML dependency is needed.
    """
    name = "scenario"
    assertions: List[Assertion] = []
    current: Optional[Dict[str, str]] = None
    current_line = -1  # line where the current assertion block started
    in_assertions = False
    saw_assertions_key = False

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
            saw_assertions_key = True
            continue
        if not in_assertions:
            # A non-blank, non-name top-level line before `assertions:` is a
            # structural error, not something to silently swallow.
            raise ValueError(
                f"line {lineno}: unexpected top-level line before 'assertions:': "
                f"{stripped!r}"
            )

        if stripped.startswith("- "):
            # New assertion block; flush previous.
            if current is not None:
                assertions.append(_build_assertion(current, current_line))
            current = {}
            current_line = lineno
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
        assertions.append(_build_assertion(current, lineno=current_line))

    if not saw_assertions_key:
        raise ValueError("scenario has no 'assertions:' block")

    return Scenario(name=name, assertions=assertions)


# Recognised assertion keys — anything else is a typo we should surface loudly.
_ASSERTION_KEYS = frozenset({
    "name", "id", "present", "byte", "equals", "data_equals",
    "min_count", "max_count", "max_period_ms", "min_period_ms", "interface",
})


def _build_assertion(d: Dict[str, str], lineno: int) -> Assertion:
    unknown = set(d) - _ASSERTION_KEYS
    if unknown:
        raise ValueError(
            f"assertion near line {lineno}: unknown key(s) "
            f"{', '.join(sorted(unknown))}; valid keys are "
            f"{', '.join(sorted(_ASSERTION_KEYS))}"
        )
    if "id" not in d:
        raise ValueError(f"assertion near line {lineno} missing required 'id'")
    a = Assertion(name=d.get("name", d["id"]), can_id=_coerce_int(d["id"], key="id", lineno=lineno))
    if "present" in d:
        a.present = _coerce_bool(d["present"], key="present", lineno=lineno)
    if "byte" in d:
        a.byte = _coerce_int(d["byte"], key="byte", lineno=lineno)
        if a.byte < 0:
            raise ValueError(f"assertion near line {lineno}: 'byte' index must be >= 0")
    if "equals" in d:
        a.equals = _coerce_int(d["equals"], key="equals", lineno=lineno)
        if not 0 <= a.equals <= 0xFF:
            raise ValueError(
                f"assertion near line {lineno}: 'equals' must be a byte value 0-255"
            )
    if "data_equals" in d:
        hexstr = d["data_equals"].replace(" ", "")
        try:
            a.data_equals = bytes.fromhex(hexstr)
        except ValueError:
            raise ValueError(
                f"assertion near line {lineno}: 'data_equals' is not valid hex: "
                f"{d['data_equals']!r}"
            )
    if "min_count" in d:
        a.min_count = _coerce_int(d["min_count"], key="min_count", lineno=lineno)
    if "max_count" in d:
        a.max_count = _coerce_int(d["max_count"], key="max_count", lineno=lineno)
    if "max_period_ms" in d:
        try:
            a.max_period_ms = float(d["max_period_ms"])
        except ValueError:
            raise ValueError(
                f"assertion near line {lineno}: 'max_period_ms' must be a number, "
                f"got {d['max_period_ms']!r}"
            )
    if "min_period_ms" in d:
        try:
            a.min_period_ms = float(d["min_period_ms"])
        except ValueError:
            raise ValueError(
                f"assertion near line {lineno}: 'min_period_ms' must be a number, "
                f"got {d['min_period_ms']!r}"
            )
    if "interface" in d:
        a.interface = d["interface"]

    # Cross-field validation: `byte` and `equals` are only meaningful together.
    if (a.byte is not None) ^ (a.equals is not None):
        raise ValueError(
            f"assertion near line {lineno}: 'byte' and 'equals' must be used "
            "together (byte selects the index, equals is the expected value)"
        )
    if a.min_count is not None and a.max_count is not None and a.min_count > a.max_count:
        raise ValueError(
            f"assertion near line {lineno}: min_count {a.min_count} > "
            f"max_count {a.max_count}"
        )
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
                        or a.min_count is not None or a.max_period_ms is not None
                        or a.min_period_ms is not None):
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

    # cadence: bound the gap between consecutive frames. `max_period_ms` is a
    # deadline (a frame must arrive at least this often); `min_period_ms` is a
    # floor (frames closer than this indicate a flood / replay). They compose.
    if a.max_period_ms is not None or a.min_period_ms is not None:
        if len(matches) < 2:
            return AssertResult(a, False, "need >=2 frames to measure period", observed)
        periods_ms = [
            (matches[i].timestamp - matches[i - 1].timestamp) * 1000.0
            for i in range(1, len(matches))
        ]
        worst = max(periods_ms)
        tightest = min(periods_ms)
        observed["max_period_ms"] = round(worst, 3)
        observed["min_period_ms"] = round(tightest, 3)
        if a.max_period_ms is not None and worst > a.max_period_ms:
            return AssertResult(a, False, f"max gap {worst:.1f}ms > allowed {a.max_period_ms}ms", observed)
        if a.min_period_ms is not None and tightest < a.min_period_ms:
            return AssertResult(
                a, False,
                f"min gap {tightest:.1f}ms < required {a.min_period_ms}ms "
                "(frames arriving too fast)",
                observed,
            )

    return AssertResult(a, True, "ok", observed)


def run_scenario(frames: List[CanFrame], scenario: Scenario) -> ScenarioResult:
    """Evaluate every assertion in the scenario against the frames."""
    results = [_eval_assertion(frames, a) for a in scenario.assertions]
    return ScenarioResult(scenario=scenario, results=results, frame_count=len(frames))


def result_to_json(res: ScenarioResult) -> str:
    return json.dumps(res.to_dict(), indent=2)
