# CANZAP — Roadmap

`canzap` turns a recorded CAN bus capture into something you can **assert on**,
**scan for anomalies**, and **gate a build with** — offline, dependency-free,
and scriptable. This roadmap sketches where it is headed. Priorities are shaped
in the open: open an issue or PR to move something up.

## Now — v0.x (shipped / stabilizing)

- **Assertion engine** — the mini-YAML scenario DSL (`present`, `min_count`,
  `max_count`, `byte`/`equals`, `data_equals`, `max_period_ms`, `interface`)
  evaluated against a candump capture, with a non-zero exit as the CI contract.
- **Heuristic scan** (`canzap scan`) — explainable detectors for diagnostic
  (OBD-II/UDS) traffic, extended IDs, RTR frames, bus floods / DoS, cadence
  jitter, lone/injected frames, and DLC variance, with a `--fail-on` gate.
- **Bus analytics** — `canzap stats` (per-ID counts, DLCs, timing) and
  `canzap diff` (regression-diff a new capture against a baseline drive log).
- **Output formats** — table, JSON, and SARIF 2.1.0 for code-scanning.
- **Integrations** — MCP server (`canzap mcp`) and a `cognis-connect` bridge
  (STIX/TAXII, MISP, Sigma, SIEM, chat/webhook).

## Next — mid-term

- **Richer detectors** — payload-entropy and signal-drift heuristics, UDS
  service/subfunction decoding, and per-ID counter/rolling-code checks.
- **DBC-aware decoding** — optional signal names/units when a DBC is supplied,
  so assertions and stats can be written against physical signals, not raw bytes.
- **More capture formats** — read CAN FD flags and additional log dialects while
  keeping the parser dependency-free.
- **Scenario ergonomics** — includes/imports, reusable assertion fragments, and
  a `canzap lint` for scenario files.
- **Baseline workflow** — `canzap scan --baseline` to only report *new* anomalies
  relative to a known-good capture.

## Later — long-term

- **Live capture** — an optional SocketCAN reader (guarded extra) so the same
  scenarios can run against a live bus, not just a recording.
- **Plugin API** — register custom detectors and exporters without forking.
- **Report bundles** — a single self-contained HTML/JSON report combining stats,
  scan findings, and scenario results for review sign-off.
- **Packaging** — PyPI release, container image, and a stable public API surface.

## Design invariants (won't change lightly)

- **Offline & deterministic** — a capture replays to the same verdict every run.
- **Dependency-free core** — the parser and DSL stay pure standard library;
  everything else is an optional extra.
- **Exit code is the contract** — `check`, `diff`, and `scan --fail-on` return
  0/1 so the tool drops into any CI system without parsing output.
- **Additive** — existing commands, flags, and output shapes are preserved.

See [CONTRIBUTING.md](CONTRIBUTING.md) to help shape priorities.
