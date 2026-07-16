# CANZAP — Architecture

`canzap` replays a recorded CAN bus capture and asserts declarative checks
against it. It is a small, dependency-free pipeline: a candump log and a
scenario file go in, a pass/fail result (table or JSON, with a non-zero exit on
failure) comes out. Everything runs offline against a recorded capture — no
SocketCAN interface and no live hardware are required.

## The pipeline

```mermaid
flowchart LR
    log[candump log<br/>capture.log] --> parse[parse_candump_text]
    parse --> frames[("CanFrame[]<br/>id · data · ts · iface")]
    scn[scenario .canzap<br/>mini-YAML DSL] --> load[load_scenario_text]
    load --> sc[("Scenario<br/>Assertion[]")]
    frames --> run[run_scenario]
    sc --> run
    run --> res[("ScenarioResult<br/>pass / fail per assertion")]
    res --> table[table output]
    res --> json[result_to_json]
    res --> exit[exit code<br/>0 pass · 1 fail]
    json --> ci[CI / SIEM / MCP agent]
    classDef hot stroke:#6b46c1,stroke-width:3px;
    class frames,run,res hot;
```

## Components

### Frame parser (`parse_candump`, `parse_candump_text`)
Parses the standard `candump -l` log format,
`(<epoch.usec>) <iface> <CANID>#<HEXDATA>`, into `CanFrame` records. It accepts
both the timestamped log form and the plain console form, detects extended
(29-bit) IDs from the ID width, validates hex/length (rejecting odd-length data
and frames over the 64-byte CAN FD maximum), and skips blank and `#` comment
lines. A malformed frame raises `ValueError` with the line number.

### Frame model (`CanFrame`)
A dataclass: `timestamp`, `interface`, `can_id`, `data` (bytes), `extended`,
plus a derived `dlc` and a `to_dict()` for JSON. This is the single unit the
rest of the engine reasons over.

### Scenario DSL (`load_scenario`, `load_scenario_text`)
A deliberately tiny YAML subset (so there is no PyYAML dependency): a top-level
`name:` and an `assertions:` list of `- key: value` blocks. Each block becomes
one `Assertion`. Supported predicates:

| key | meaning |
|---|---|
| `present` | the ID must (`true`) / must not (`false`) appear |
| `min_count` / `max_count` | bound how many frames carry the ID |
| `byte` + `equals` | the last matching frame's byte *N* equals a value |
| `data_equals` | the last matching frame's full payload equals a hex string |
| `max_period_ms` | no gap between consecutive frames exceeds a deadline |
| `interface` | scope the assertion to one bus interface |

### Evaluator (`run_scenario`, `_eval_assertion`)
For each assertion it selects the matching frames (by `can_id`, optionally by
`interface`), then applies the predicates above and returns an `AssertResult`
with `passed`, a human-readable `detail`, and an `observed` dict (count, byte
value, worst period…). `ScenarioResult` aggregates them: `.passed` is true only
when every assertion passes, and `.failures` lists the rest.

### Heuristic scan (`canzap.detect`)
A second, complementary engine to the assertion DSL: instead of checking a
capture against a *known-good* contract, it surfaces *suspicious* patterns
automatically. Each detector is a pure function of the grouped frames —
`detect_diagnostics`, `detect_extended_ids`, `detect_rtr`, `detect_flood`,
`detect_jitter`, `detect_singletons`, `detect_dlc_variance` — and returns
JSON-friendly finding dicts carrying a rule id, severity, arbitration ID, and
the concrete evidence that fired it. `scan_frames` runs the pipeline and sorts
findings most-severe first; `scan_report` wraps them with a summary (frame
count, risk score, max severity); `findings_to_sarif` renders SARIF 2.1.0.
`canzap.core.scan(target)` resolves a file / directory / raw text to frames and
calls into this module — it is also the function exposed over MCP.

### Bus analytics (`bus_stats`, `diff_captures`)
`bus_stats` summarizes a capture into per-ID counts, DLCs, and inter-frame
timing (min/avg/max period). `diff_captures` compares two captures by
arbitration ID into `added` / `removed` / `changed` sets — the machinery behind
the "record a clean drive cycle, gate later captures against it" workflow. Both
return plain dicts and drive the `stats` and `diff` subcommands.

### CLI (`canzap.cli`)
Subcommands over the same engines. `dump` replays a log into frames (table/JSON,
always exits 0). `check` runs a scenario and **exits 1 on any failed assertion**
— the CI gate. `scan` runs the detector pipeline (table/JSON/SARIF) with an
optional `--fail-on <severity>` gate. `stats` prints the bus summary and `diff`
**exits 1** when two captures differ. `--format json` and `-` (stdin) make every
command pipeline-friendly. `result_to_json` / `to_json` are the shared JSON
serializers.

### MCP server (`canzap.mcp_server`)
`build_app()` wires `scan()` into a FastMCP `canzap_scan(target)` tool (split out
so it is unit-testable without starting the blocking stdio loop); `serve()` runs
it. Requires the optional `mcp` extra.

## Why these choices

- **No dependencies.** Pure standard library — the log parser is a regex and
  the DSL is a hand-written line parser, so `pip install` pulls in nothing.
- **Offline and deterministic.** A capture file replays to the same verdict
  every time, which is what makes a CAN assertion usable as a regression test.
- **Exit code is the contract.** `check` returns 0/1; that single fact wires the
  tool into any CI system or shell pipeline without parsing output.
