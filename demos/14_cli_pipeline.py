"""Scenario 14 - drive the real CLI in-process and consume its JSON.

Everything the demos show through the API is reachable from the `canzap` CLI.
This demo calls `canzap.cli.main` exactly as a shell would (check + dump, both
--format json), captures stdout, and asserts the JSON contract and exit codes -
the same surface a CI job or a shell pipeline depends on.
"""
import io
import json
import os
import sys
from contextlib import redirect_stdout

from _common import rule
from canzap.cli import main as cli_main

DEMO_DIR = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(DEMO_DIR, "01-basic", "capture.log")
SCENARIO = os.path.join(DEMO_DIR, "01-basic", "startup.canzap")


def run_cli(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli_main(argv)
    return rc, buf.getvalue()


def main() -> None:
    rule("CLI  -  the same engine, driven as a shell pipeline")

    print("\n$ canzap check --log capture.log --scenario startup.canzap --format json")
    rc, out = run_cli(["check", "--log", LOG, "--scenario", SCENARIO, "--format", "json"])
    data = json.loads(out)
    print(f"   exit={rc}  passed={data['passed']}  "
          f"{data['total'] - data['failed']}/{data['total']} assertions")
    assert rc == 0 and data["passed"] is True

    print("\n$ canzap dump --log capture.log --format json  | jq length")
    rc, out = run_cli(["dump", "--log", LOG, "--format", "json"])
    frames = json.loads(out)
    print(f"   exit={rc}  frames={len(frames)}  first={frames[0]['id_hex']}")
    assert rc == 0 and len(frames) == 12

    # A failing scenario returns exit 1 - the CI gate.
    print("\n$ canzap check (a scenario that must fail) ; echo $?")
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        badlog = os.path.join(d, "b.log")
        badscn = os.path.join(d, "b.canzap")
        open(badlog, "w").write("(1.0) can0 500#01\n")
        open(badscn, "w").write(
            "name: t\nassertions:\n  - name: no fault\n    id: 0x500\n    present: false\n"
        )
        rc, _ = run_cli(["check", "--log", badlog, "--scenario", badscn])
        print(f"   exit={rc}  (non-zero blocks the build)")
        assert rc == 1

    # A missing file is a clean exit 2, not a traceback.
    rc, _ = run_cli(["dump", "--log", os.path.join(DEMO_DIR, "nope.log")])
    print(f"\n$ canzap dump --log missing.log ; echo $?  ->  exit={rc}")
    assert rc == 2
    print("\nexit 0 = clean, 1 = assertion failed, 2 = bad input: a stable "
          "contract\nfor CI and shell scripting.")


if __name__ == "__main__":
    main()
