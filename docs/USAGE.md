# CANZAP — Usage

`canzap` reads a **candump log** (the standard `candump -l` format) and lets you
replay it, assert on it, scan it for anomalies, summarize it, and diff it against
a baseline — all offline. Every command speaks table or JSON; `scan` also emits
SARIF. Exit codes are the contract: `check`, `diff`, and `scan --fail-on` return
non-zero on failure so they drop straight into CI.

```
canzap [--version] {check,dump,scan,stats,diff,mcp} ...
```

A candump log line looks like:

```
(1623241200.123456) can0 1A0#00FF12345678
 └ epoch.usec ─┘      │    │   └ hex payload (0–64 bytes)
                    iface  └ arbitration ID (hex; >3 nibbles ⇒ extended 29-bit)
```

Remote-transmission-request frames use `ID#R`; blank lines and `#` comments are
skipped. Pass `-` as any log path to read from stdin.

---

## `check` — assert a capture against a scenario

Evaluate a scenario (`.canzap` mini-YAML) against a capture. **Exits 1 on any
failed assertion** — this is the CI gate.

```bash
canzap check --log capture.log --scenario startup.canzap
canzap check --log capture.log --scenario startup.canzap --format json
cat capture.log | canzap check --log - --scenario startup.canzap
```

### Scenario DSL

```yaml
name: Engine startup checks
assertions:
  - name: rpm frame present
    id: 0x1A0
    present: true
    min_count: 3
  - name: brake byte released
    id: 0x2B1
    byte: 0
    equals: 0x00
  - name: heartbeat cadence
    id: 0x700
    present: true
    min_count: 5
    max_period_ms: 120
  - name: no fault code
    id: 0x500
    present: false
```

| Key | Meaning |
|---|---|
| `id` | arbitration ID (decimal or `0x` hex) — **required** |
| `name` | human label (defaults to the id) |
| `present` | ID must (`true`) / must not (`false`) appear |
| `min_count` / `max_count` | bound how many frames carry the ID |
| `byte` + `equals` | last matching frame's byte *N* equals a value |
| `data_equals` | last matching frame's full payload equals a hex string |
| `max_period_ms` | no gap between consecutive frames exceeds a deadline |
| `interface` | scope the assertion to one bus interface (e.g. `can1`) |

---

## `dump` — replay a capture into frames

Parse/normalize a log into frames. Always exits 0.

```bash
canzap dump --log capture.log
canzap dump --log capture.log --format json
```

JSON frame shape: `timestamp`, `interface`, `id`, `id_hex`, `dlc`, `data`,
`extended`, `rtr`.

---

## `scan` — heuristic anomaly scan

Run the detector pipeline over a capture and print prioritized findings
(most-severe first). `target` may be a log file, a **directory** of `*.log` /
`*.candump` captures, or `.` for the current directory.

```bash
canzap scan capture.log                 # table
canzap scan capture.log --format json   # full report object
canzap scan capture.log --format sarif  # SARIF 2.1.0 for code-scanning
canzap scan capture.log --fail-on high  # CI gate: exit 1 if any finding ≥ high
```

### Detectors

| Rule | Severity | Fires when |
|---|---|---|
| `diagnostic-traffic` | medium | OBD-II/UDS IDs (`0x7DF`, `0x7E0`–`0x7EF`) present |
| `bus-flood` | high | one ID dominates the capture at sub-5ms cadence (flood/DoS) |
| `cadence-jitter` | medium | a periodic ID's worst gap ≫ its median period |
| `lone-frame` | low | an ID appears exactly once on an otherwise busy bus |
| `dlc-variance` | low | an ID's payload length changes across frames |
| `rtr-frame` | low | remote-transmission-request frames observed |
| `extended-id` | info | extended 29-bit arbitration IDs observed |

`--fail-on` accepts `info | low | medium | high | critical`; the process exits 1
if any finding meets or exceeds that severity.

### JSON report shape

```json
{
  "tool": "canzap",
  "frame_count": 16,
  "finding_count": 6,
  "risk_score": 17,
  "max_severity": "high",
  "findings": [ { "rule": "bus-flood", "severity": "high", "id_hex": "0x333", ... } ]
}
```

---

## `stats` — per-ID counts, DLCs, and timing

```bash
canzap stats --log capture.log
canzap stats --log capture.log --format json
```

Reports total frames, unique IDs, capture duration, and a per-ID table sorted by
frame count with min/avg/max inter-frame periods (ms) and observed DLCs.

---

## `diff` — regression-diff two captures

Compare a candidate capture against a baseline by arbitration ID. **Exits 1**
when the two differ (IDs added/removed or per-ID counts changed) — record a
clean drive cycle once, then gate later captures against it.

```bash
canzap diff --baseline good.log --candidate suspect.log
canzap diff --baseline good.log --candidate suspect.log --format json
```

---

## `mcp` — Model Context Protocol server

Expose the scan engine to AI agents as a tool call. Requires the `mcp` extra.

```bash
pip install "cognis-canzap[mcp]"
canzap mcp
```

The server registers a single `canzap_scan(target)` tool that returns the JSON
scan report described above.

---

## Forwarding findings (`canzap-emit`)

With the optional `cognis-connect` extra, pipe JSON findings to STIX/TAXII, MISP,
Sigma, SIEM, or chat/webhook:

```bash
pip install "cognis-canzap[connect]"
canzap scan capture.log --format json | canzap-emit --to sigma
canzap scan capture.log --format json | canzap-emit --to slack --url "$WEBHOOK" --dry-run
```

## Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `check` | all assertions pass | an assertion failed | bad input / file error |
| `diff` | captures identical | captures differ | bad input / file error |
| `scan` | (no `--fail-on`) always 0; with gate: below threshold | finding ≥ threshold | bad input |
| `dump` / `stats` | success | — | bad input / file error |
