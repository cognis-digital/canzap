# Demos

Twenty runnable scenarios in [`../demos/`](../demos/), spanning audiences (security
researchers, ECU engineers, red/blue teams, IR, reviewers) and mechanics (parsing,
DSL validation, timing contracts, exact matching, multi-interface, extended IDs).
Every scenario replays a bundled candump capture fixture (`demos/fixtures/*.log`)
or an in-memory capture through the real `canzap.core`/`canzap.cli` API — fully
offline, no CAN hardware. Each prints narrated output, runs its own assertions,
and exits 0, so they double as smoke tests (`tests/test_demos.py` runs all twenty
under pytest).

```bash
PYTHONUTF8=1 python demos/run_all.py        # all twenty, end to end
PYTHONUTF8=1 python demos/03_red_team.py     # or just one
```

## Audience & mechanic map

| # | Scenario | Focus | What it shows | Capture |
|---|----------|-------|---------------|---------|
| 01 | `01_security_researcher.py` | Automotive security researchers | Enumerate every arbitration ID on a recorded drive cycle, then capture the bus invariants (RPM present, heartbeat cadence, brake released, no fault) as a replayable baseline. | `drive_cycle.log` |
| 02 | `02_ecu_engineer.py` | Embedded / ECU engineers | A periodic-frame *timing contract* (`max_period_ms`): PASS on a healthy build, then FAIL on the same capture with one heartbeat dropped. | `drive_cycle.log` |
| 03 | `03_red_team.py` | Red teams | Replay a fuzz/injection capture and *assert the attack landed*, then invert the facts into the blue team's detection gate. | `fuzz_replay.log` |
| 04 | `04_ir_forensics.py` | IR / forensics | Reconstruct an incident: timeline a door-unlock replay (0x19B) and a spoofed 0x3D0 frame, confirm the IOCs, emit JSON for the case file. | `incident_capture.log` |
| 05 | `05_bus_report.py` | Architects & reviewers | A one-screen bus map plus a green/red scenario roll-up — the review/release artifact. | all three |
| 06 | `06_flood_detection.py` | Blue team | Catch a flood by *inter-frame timing* (`min_period_ms`), not just by count. | `fuzz_replay.log` |
| 07 | `07_j1939_extended.py` | Heavy-duty / J1939 | 29-bit extended IDs, correctly classified — a zero-padded `0700` stays standard. | `extended_ids.log` |
| 08 | `08_multi_interface.py` | Gateway engineers | Scope assertions to a CAN `interface`; verify a body frame never leaks onto the powertrain bus. | `gateway_traffic.log` |
| 09 | `09_rtr_frames.py` | Protocol | Parse remote-transmission-request (`123#R`) frames; RTR flagged, zero DLC, data-carrying RTR rejected. | in-memory |
| 10 | `10_malformed_recovery.py` | Robustness | Every malformed line fails loudly with a line number and reason. | in-memory |
| 11 | `11_dsl_validation.py` | DSL safety | A typo'd key or half-written assertion is rejected at load time, never silently skipped. | in-memory |
| 12 | `12_regression_diff.py` | Regression | One frozen scenario, two captures; a stuck brake byte flips green to red. | `drive_cycle.log` |
| 13 | `13_payload_decode.py` | Signal decode | Decode an RPM trace from 0x1A0 payload bytes and sanity-check the band. | `drive_cycle.log` |
| 14 | `14_cli_pipeline.py` | CI / shell | Drive the real `canzap` CLI in-process and assert the JSON contract + exit codes (0/1/2). | `01-basic/capture.log` |
| 15 | `15_fuzz_campaign.py` | Red team | Generate a fuzz campaign in memory and assert its shape (coverage + spacing floor). | in-memory |
| 16 | `16_data_equals_match.py` | Exact match | Full-payload `data_equals` matching; catch a corrupted heartbeat byte-for-byte. | `drive_cycle.log` |
| 17 | `17_uds_session.py` | UDS / diagnostics | Spot an unsolicited 0x7DF/0x7E8 diagnostic session; invert into a production gate. | `fuzz_replay.log` |
| 18 | `18_dbc_style_watchlist.py` | Tooling | Generate a scenario programmatically from a DBC-style ID watchlist. | `drive_cycle.log` |
| 19 | `19_timing_jitter.py` | Timing | Bound a periodic frame from both sides (`min`+`max_period_ms`) as a jitter window. | `gateway_traffic.log` |
| 20 | `20_ci_gate_matrix.py` | Release gate | A full (capture × gate) matrix over every bundled capture with one overall verdict. | all five |

## Capture fixtures

All captures are in standard `candump -l` format and live in
[`../demos/fixtures/`](../demos/fixtures/):

- **`drive_cycle.log`** — 17 frames of a clean drive cycle: RPM (`0x1A0`),
  brake status (`0x2B1`), and a ~100 ms powertrain heartbeat (`0x700`).
- **`fuzz_replay.log`** — 16 frames of a replay/fuzz run: an 8-frame `0x333`
  flood plus an injected UDS diagnostic request/response pair (`0x7DF`/`0x7E8`).
- **`incident_capture.log`** — 15 frames from a vehicle access incident: a
  replayed door-unlock burst (`0x19B`) and a single spoofed `0x3D0` frame.
- **`gateway_traffic.log`** — 16 frames across two interfaces (`can0`/`can1`): a
  heartbeat on both segments and a ~100 ms body frame (`0x3E0`) on `can1` only.
- **`extended_ids.log`** — 10 frames of J1939-style 29-bit IDs (`0x18FEF100`,
  `0x0CF00400`) plus a zero-padded standard `0700` that must stay 11-bit.

## Run them as the CLI sees them

The demos use the in-process API; the same captures and DSL drive the CLI:

```bash
PYTHONUTF8=1 python -m canzap dump  --log demos/fixtures/drive_cycle.log
PYTHONUTF8=1 python -m canzap check --log demos/fixtures/fuzz_replay.log \
    --scenario demos/01-basic/startup.canzap --format json
```

`check` exits non-zero on any failed assertion — that exit code is the CI gate.
