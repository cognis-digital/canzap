# Demo 01 - Basic CAN startup assertions

This demo replays a small captured CAN bus session (`capture.log`, standard
`candump -l` format) and checks it against a CANZAP scenario
(`startup.canzap`).

## Files

- `capture.log` - 12 captured frames across `can0` (engine RPM, brake status,
  a periodic heartbeat at ~100ms cadence, and traffic the scenario expects to
  be absent).
- `startup.canzap` - the assertion scenario (mini-YAML DSL).

## What the scenario asserts

1. **rpm frame present** - ID `0x1A0` must appear at least once.
2. **brake released** - the last `0x2B1` frame has `byte[0] == 0x00`.
3. **heartbeat cadence** - ID `0x700` appears >= 5 times with no gap longer
   than 120 ms between consecutive frames.
4. **no diagnostic fault** - ID `0x500` (fault code broadcast) must be absent.

## Run it

```
python -m canzap check --log demos/01-basic/capture.log \
                       --scenario demos/01-basic/startup.canzap
```

Machine-readable for CI:

```
python -m canzap check --log demos/01-basic/capture.log \
                       --scenario demos/01-basic/startup.canzap --format json
```

## Expected result

All four assertions **PASS**, so the command prints `4/4 passed` and exits `0`.

If you edit `capture.log` to add a `0x500#...` fault frame, or stretch the
heartbeat gap past 120 ms, the relevant assertion **FAILS** and the command
exits `1` - which fails a CI gate.
