#!/usr/bin/env python3
"""Check verify-pack.py against the local-chain fixtures.

    python3 fixtures/run-local-chain-cases.py

Every case under fixtures/local-chain/ is an unsigned manifest 1.4 pack with
evidence_class local-chain-not-write-once, written by
fixtures/gen-local-chain-fixtures.py (its docstring says where each record
comes from). Each case's expect.json lists runs: the arguments, the exit code,
and lines that must and must not be printed. This script runs verify-pack.py
offline (--records) for each, from the fixtures/ directory, so the
--tsa-root paths in expect.json are relative to it.

The cases:

  clean                    the whole chain, anchored at its head           exit 0
                           without --allow-unsigned                        exit 3
                           --require-through past its last record          exit 4
  earlier-pack             a pack built at head 2, checked with the
                           anchor at 4 made later                          exit 4
  claim-relabelled         that pack with its claim edited to interval     exit 1
  evidence-modes           a boot in write_once, then one in local_chain   exit 0
  evidence-modes-doctored  the manifest's list of modes omits the change   exit 1
  judgment-verdicts        two requests and three verdict receipts         exit 0
                           without --allow-unsigned                        exit 3
  judgment-verdicts-edited a receipt's uploaded form and another's reason
                           edited after sealing                            exit 1
  judgment-verdicts-relinked
                           a receipt sealed with a link to another record  exit 1
  judgment-verdicts-v2     a request, a tool call and four v1.22 receipts  exit 0
                           without --allow-unsigned                        exit 3
  judgment-verdicts-v2-malformed
                           four v1.22 receipts sealed breaking its rules   exit 1
  judgment-verdicts-v2-relabelled
                           a v1.22 receipt's stamp edited to v1.21         exit 1
  control-probe-runs       two v1.23 probe runs, one with a failed case    exit 0
                           without --allow-unsigned                        exit 3
  control-probe-runs-edited
                           a failed case result edited to pass             exit 1
  control-probe-runs-miscounted
                           a run sealed with counts its results disagree
                           with                                            exit 1
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE.parent / "verify-pack.py"
CASES = HERE / "local-chain"
EXPECTED_CASES = {"clean", "earlier-pack", "claim-relabelled", "evidence-modes", "evidence-modes-doctored",
                  "judgment-verdicts", "judgment-verdicts-edited", "judgment-verdicts-relinked",
                  "judgment-verdicts-v2", "judgment-verdicts-v2-malformed", "judgment-verdicts-v2-relabelled",
                  "control-probe-runs", "control-probe-runs-edited", "control-probe-runs-miscounted"}


def die(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    found = {p.name for p in CASES.iterdir() if p.is_dir()}
    if found != EXPECTED_CASES:
        die(f"local-chain cases {sorted(found)} != {sorted(EXPECTED_CASES)}")
    runs = 0
    for name in sorted(found):
        case = CASES / name
        expect = json.loads((case / "expect.json").read_text())
        for run in expect["runs"]:
            cmd = [sys.executable, "-I", str(VERIFIER), "--records", str(case / "records"),
                   "--manifest", str(case / "manifest.json"), *run["args"]]
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE)
            out = proc.stdout + proc.stderr
            if proc.returncode != run["exit"]:
                die(f"{name} {run['args']}: exit {proc.returncode}, expected {run['exit']}\n{out}")
            for line in run.get("contains", []):
                if line not in out:
                    die(f"{name} {run['args']}: missing {line!r}\n{out}")
            for line in run.get("absent", []):
                if line in out:
                    die(f"{name} {run['args']}: unexpected {line!r}\n{out}")
            shown = [a for a in run["args"] if a != "--tsa-root" and not a.startswith("test-")]
            print(f"ok   {name} {' '.join(shown) or '(no options)'}: exit {run['exit']}")
            runs += 1
    print(f"OK: {runs} local-chain runs over {len(found)} cases")


if __name__ == "__main__":
    main()
