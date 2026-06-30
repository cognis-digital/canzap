# Demos

Five runnable scenarios in [`../demos/`](../demos/), each targeting a different
audience. Every scenario replays a bundled candump capture fixture
(`demos/fixtures/*.log`) through the real `canzap.core` API — fully offline, no
CAN hardware. Each prints narrated output, runs its own assertions, and exits 0,
so they double as smoke tests (`tests/test_demos.py` runs all five under pytest).

```bash
PYTHONUTF8=1 python demos/run_all.py        # all five, end to end
PYTHONUTF8=1 python demos/03_red_team.py     # or just one
```

## Audience map

| # | Scenario | Audience | What it shows | Capture |
|---|----------|----------|---------------|---------|
| 01 | `01_security_researcher.py` | Automotive security researchers | Enumerate every arbitration ID on a recorded drive cycle, then capture the bus invariants (RPM present, heartbeat cadence, brake released, no fault) as a replayable baseline. | `drive_cycle.log` |
| 02 | `02_ecu_engineer.py` | Embedded / ECU engineers | A periodic-frame *timing contract* (`max_period_ms`): PASS on a healthy build, then FAIL on the same capture with one heartbeat dropped — a regression a firmware CI gate would catch. | `drive_cycle.log` |
| 03 | `03_red_team.py` | Red teams | Replay a fuzz/injection capture and *assert the attack landed* (0x333 flood, injected UDS 0x7DF request, 0x7E8 response); then invert the same facts into the blue team's "must stay quiet" detection gate. | `fuzz_replay.log` |
| 04 | `04_ir_forensics.py` | IR / forensics | Reconstruct an incident from a gateway capture: timeline a replayed door-unlock burst (0x19B) and a spoofed odometer/VIN frame (0x3D0), confirm the IOCs, and emit the verdict as JSON for the case file. | `incident_capture.log` |
| 05 | `05_bus_report.py` | Architects & reviewers | A one-screen bus map (per-ID count, DLC, span, last payload) across all three captures plus a green/red scenario roll-up — the artifact you paste into a review or release gate. | all three |

## Capture fixtures

All captures are in standard `candump -l` format and live in
[`../demos/fixtures/`](../demos/fixtures/):

- **`drive_cycle.log`** — 17 frames of a clean drive cycle: RPM (`0x1A0`),
  brake status (`0x2B1`), and a ~100 ms powertrain heartbeat (`0x700`).
- **`fuzz_replay.log`** — 16 frames of a replay/fuzz run: an 8-frame `0x333`
  flood plus an injected UDS diagnostic request/response pair (`0x7DF`/`0x7E8`).
- **`incident_capture.log`** — 15 frames from a vehicle access incident: a
  replayed door-unlock burst (`0x19B`) and a single spoofed `0x3D0` frame.

## Run them as the CLI sees them

The demos use the in-process API; the same captures and DSL drive the CLI:

```bash
PYTHONUTF8=1 python -m canzap dump  --log demos/fixtures/drive_cycle.log
PYTHONUTF8=1 python -m canzap check --log demos/fixtures/fuzz_replay.log \
    --scenario demos/01-basic/startup.canzap --format json
```

`check` exits non-zero on any failed assertion — that exit code is the CI gate.
