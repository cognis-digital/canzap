"""Scenario 4 - incident response / forensics.

A vehicle was accessed without the key. You have one artifact: a candump capture
pulled from the gateway logger. CANZAP lets you replay it deterministically and
assert the indicators of compromise - a replayed door-unlock burst (0x19B) and a
spoofed odometer/VIN frame (0x3D0) - then emit the verdict as JSON for the case
file. Fully offline; the capture is the only evidence touched.
"""
import json

from _common import load_capture, assert_against, print_result, rule
from canzap.core import result_to_json


def main() -> None:
    rule("IR / FORENSICS  -  reconstruct an incident from a captured bus log")

    frames = load_capture("incident_capture.log")
    print(f"\nLoaded {len(frames)} frames of evidence from "
          "demos/fixtures/incident_capture.log")

    # Reconstruct the timeline of the suspicious ID.
    unlock = [f for f in frames if f.can_id == 0x19B]
    print(f"\nTimeline for door-control ID 0x19B ({len(unlock)} frames):")
    t0 = unlock[0].timestamp
    for f in unlock:
        print(f"   +{(f.timestamp - t0) * 1000:7.1f} ms   0x19B#{f.data.hex().upper()}")
    print("   -> a tight burst of identical unlock commands == a replay attack.")

    # Indicators of compromise as assertions (defender expects these ABSENT).
    print("\nAsserting indicators of compromise against the capture:")
    res = assert_against(frames, """
        name: Incident IOC sweep
        assertions:
          - name: no replayed door-unlock burst on 0x19B
            id: 0x19B
            max_count: 2
          - name: door-control frame ends in the locked state (byte0 == 0x00)
            id: 0x19B
            byte: 0
            equals: 0x00
          - name: odometer/VIN frame 0x3D0 not spoofed onto the bus
            id: 0x3D0
            present: false
    """)
    print_result(res)
    assert not res.passed, "the incident capture should trip the IOC sweep"

    print(f"\n{len(res.failures)} indicator(s) confirmed - the bus was tampered "
          "with. Verdict for the case file (JSON):\n")
    verdict = result_to_json(res)
    print(verdict)
    # round-trip the evidence to prove it is machine-ingestible
    parsed = json.loads(verdict)
    assert parsed["passed"] is False and parsed["failed"] >= 1
    print("\nThis JSON drops straight into a SIEM/case-management pipeline as a "
          "signed,\nreproducible finding - the capture replays to the same "
          "verdict every time.")


if __name__ == "__main__":
    main()
