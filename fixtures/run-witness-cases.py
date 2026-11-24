#!/usr/bin/env python3
"""Check verify-pack.py --witness and --receipt against the witness fixtures.

    python3 fixtures/run-witness-cases.py

fixtures/witness/cases.json lists each run: the local-chain pack it judges
(fixtures/local-chain/<pack>), the witness file (fixtures/witness/files/<file>.zip,
or the same tree extracted to a directory when `directory` is set), the extra
arguments, the exit code and lines that must and must not be printed. Every run
passes --allow-unsigned (the packs are unsigned local-chain packs) and the two
test witnesses' roots unless `roots` is false; paths in the arguments are
relative to fixtures/witness/. Every run also writes a receipt, which must be a
`meilynx.verification_receipt.v1` document carrying the run's exit code and the
witness file's digests; a run that names `receipt` must produce that file's
receipt, apart from verified_at and the verifier's own digest. The script also
checks the example witness manifest against the manifest in files/signed.zip.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE.parent / "verify-pack.py"
WITNESS = HERE / "witness"
ROOTS = ["--tsa-root", f"test-rsa={HERE / 'anchors/roots/rsa-root.pem'}",
         "--tsa-root", f"test-ec={HERE / 'anchors/roots/ec-root.pem'}"]
VERDICTS = {0: "pass", 1: "fail", 2: "cannot_evaluate", 3: "unsigned", 4: "coverage_not_established"}
RECEIPT_KEYS = {"format", "verified_at", "verifier", "result", "gateway", "pack", "chains", "witness_file", "options"}


def die(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    cases = json.loads((WITNESS / "cases.json").read_text())["runs"]
    example = json.loads((WITNESS / "witness-manifest.v1.example.json").read_text())
    with zipfile.ZipFile(WITNESS / "files" / "signed.zip") as z:
        if json.loads(z.read("witness-manifest.json")) != example:
            die("witness-manifest.v1.example.json is not the manifest in files/signed.zip")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for n, run in enumerate(cases):
            witness = WITNESS / "files" / f"{run['file']}.zip"
            if run.get("directory"):
                target = tmp / f"dir-{n}"
                with zipfile.ZipFile(witness) as z:
                    for name in z.namelist():
                        (target / name).parent.mkdir(parents=True, exist_ok=True)
                        (target / name).write_bytes(z.read(name))
                witness = target
            receipt_path = tmp / f"receipt-{n}.json"
            pack = HERE / "local-chain" / run["pack"]
            cmd = [sys.executable, "-I", str(VERIFIER), "--records", str(pack / "records"),
                   "--manifest", str(pack / "manifest.json"), "--allow-unsigned",
                   *(ROOTS if run.get("roots", True) else []), "--witness", str(witness),
                   "--receipt", str(receipt_path), *run["args"]]
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=WITNESS)
            out = proc.stdout + proc.stderr
            label = run["name"]
            if proc.returncode != run["exit"]:
                die(f"{label}: exit {proc.returncode}, expected {run['exit']}\n{out}")
            for line in run.get("contains", []):
                if line not in out:
                    die(f"{label}: missing {line!r}\n{out}")
            for line in run.get("absent", []):
                if line in out:
                    die(f"{label}: unexpected {line!r}\n{out}")
            raw = receipt_path.read_bytes()
            receipt = json.loads(raw)
            if set(receipt) != RECEIPT_KEYS or receipt["format"] != "meilynx.verification_receipt.v1":
                die(f"{label}: the receipt's members are {sorted(receipt)}")
            if receipt["result"] != {"exit_code": run["exit"], "verdict": VERDICTS[run["exit"]]}:
                die(f"{label}: the receipt's result is {receipt['result']}")
            if json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() != raw:
                die(f"{label}: the receipt is not written as RFC 8785 bytes")
            if receipt["verifier"]["sha256"] != hashlib.sha256(VERIFIER.read_bytes()).hexdigest():
                die(f"{label}: the receipt names another verifier digest")
            wf = receipt["witness_file"]
            if not run.get("directory") and wf["file_sha256"] != hashlib.sha256(witness.read_bytes()).hexdigest():
                die(f"{label}: the receipt's witness file digest is {wf['file_sha256']}")
            if run.get("directory") and wf["file_sha256"] is not None:
                die(f"{label}: a directory has no file digest")
            if run.get("receipt"):
                expected = json.loads((WITNESS / run["receipt"]).read_text())
                for doc in (expected, receipt):
                    doc["verified_at"] = None
                    doc["verifier"]["sha256"] = None
                    doc["options"]["tsa_root_ids"] = sorted(doc["options"]["tsa_root_ids"])
                if expected != receipt:
                    die(f"{label}: the receipt differs from {run['receipt']}\n"
                        f"{json.dumps(receipt, indent=2, sort_keys=True)}")
    print(f"witness cases: {len(cases)} runs as expected")


if __name__ == "__main__":
    main()
