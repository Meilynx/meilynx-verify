#!/usr/bin/env python3
"""Check verify-pack.py against the record-signature fixtures.

    python3 fixtures/run-record-sig-cases.py

Every case under fixtures/record-sigs/ is a chain the proxy's own writer
sealed (meilynx-integrity-pack/tests/mei3591_record_sig_fixtures.rs writes
them, and fails when the committed bytes are not what the writer produces):
two records sealed before a chain signing key was configured, then a restart
with the RFC 8032 section 7.1 TEST 1 key, its `chain_signing_started`
boundary and signed LLM, MCP and admin records. Each case's expect.json lists
runs (extra arguments, the exit code, lines that must and must not be
printed); this script runs verify-pack.py offline (--records) for each.

The cases:

  signed               the intact chain                                   exit 0
  consistent-rewrite   seq 3 edited, every hash recomputed forward,
                       signatures left as they were                       exit 1
  stripped             the same rewrite with the signatures removed       exit 1
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE.parent / "verify-pack.py"
CASES = HERE / "record-sigs"
EXPECTED_CASES = {"signed", "consistent-rewrite", "stripped"}


def die(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    found = {p.name for p in CASES.iterdir() if p.is_dir()}
    if found != EXPECTED_CASES:
        die(f"record-sig cases {sorted(found)} != {sorted(EXPECTED_CASES)}")
    runs = 0
    for name in sorted(found):
        case = CASES / name
        expect = json.loads((case / "expect.json").read_text())
        for run in expect["runs"]:
            cmd = [sys.executable, "-I", str(VERIFIER), "--records", str(case / "records"),
                   "--manifest", str(case / "manifest.json"), "--allow-unsigned", *run["args"]]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            out = proc.stdout + proc.stderr
            if proc.returncode != run["exit"]:
                die(f"{name} {run['args']}: exit {proc.returncode}, expected {run['exit']}\n{out}")
            for line in run.get("contains", []):
                if line not in out:
                    die(f"{name} {run['args']}: missing {line!r}\n{out}")
            for line in run.get("absent", []):
                if line in out:
                    die(f"{name} {run['args']}: unexpected {line!r}\n{out}")
            runs += 1
    print(f"OK: {runs} record-signature runs over {len(found)} cases")


if __name__ == "__main__":
    main()
