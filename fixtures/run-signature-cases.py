#!/usr/bin/env python3
"""Run verify-pack.py, as a reviewer would, against every signed-pack case
from generate-signature-vectors.py and check its exit code and reason (MEI-922).

    python3 fixtures/run-signature-cases.py
    python3 fixtures/run-signature-cases.py --cosign cosign   # also ask cosign

Each case is a pack on disk (manifest.json, manifest.json.sigstore.json,
records/) plus the trust root and identity to check it against. The cases
cover the self-test's tamper matrix at the command line, the one-guard
negative cases the generator writes to cases/, and the exit codes for an
unsupported format, an unusable --trusted-root, and a signed pack stripped of
its bundle and relabelled unsigned (exit 3, or 0 with --allow-unsigned). A
case whose name ends in _allow_unsigned is run with --allow-unsigned.

With --cosign, every case that is a plain signature question is also put to
`cosign verify-blob` with the same bundle, trust root and identity, and the
two verdicts are compared. `--insecure-ignore-sct` is passed because the
test-only CA issues certificates without Certificate Transparency
timestamps, and verify-pack.py does not check SCTs. Exit 1 on any mismatch,
except the cases in STRICTER_THAN_COSIGN, where verify-pack.py rejecting a
certificate cosign accepts is expected.
"""
import argparse
import base64
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE.parent / "verify-pack.py"
spec = importlib.util.spec_from_file_location("generate_signature_vectors", HERE / "generate-signature-vectors.py")
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)
vp = gen.vp


# verify-pack.py requires what every Fulcio signing certificate carries: the
# codeSigning extended key usage, the digitalSignature key usage, and no CA
# flag. cosign (Go's x509 checks) accepts a leaf without an extKeyUsage
# extension and does not check the leaf's keyUsage or CA flag. Only this
# direction is tolerated: verify-pack.py rejecting what cosign accepts.
STRICTER_THAN_COSIGN = {"leaf_is_ca", "no_code_signing", "no_digital_signature"}


def flip_b64(value, index):
    raw = bytearray(base64.b64decode(value))
    raw[index] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cosign", metavar="PATH", help="cosign binary to cross-check each case against")
    args = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="mei922-cases-"))
    try:
        subprocess.run([sys.executable, str(HERE / "generate-signature-vectors.py"), "--out", str(work)],
                       check=True, capture_output=True)
        failures = run(work, args.cosign)
    finally:
        shutil.rmtree(work)
    sys.exit(1 if failures else 0)


def run(work, cosign):
    identity = (work / "identity").read_text().strip()
    issuer = (work / "issuer").read_text().strip()
    trusted = work / "trusted_root.json"
    foreign = work / "foreign_trusted_root.json"
    base_pack = work / "pack"
    valid = json.loads((base_pack / "manifest.json.sigstore.json").read_text())

    def entry(b):
        return b["verificationMaterial"]["tlogEntries"][0]

    def mutated(fn):
        b = json.loads(json.dumps(valid))
        fn(b)
        return b

    def corrupt_checkpoint(b):
        proof = entry(b)["inclusionProof"]["checkpoint"]
        head, _, sig = proof["envelope"].rstrip("\n").rpartition(" ")
        proof["envelope"] = f"{head} {flip_b64(sig, 12)}\n"

    unsigned = json.loads((base_pack / "manifest.json").read_text())
    unsigned.update(window="A", signing_deferred=True, signature=None)
    relabelled = (json.dumps(unsigned, indent=2) + "\n").encode()

    manifest = (base_pack / "manifest.json").read_bytes()
    flipped = manifest.replace(b'"records_checked": 2', b'"records_checked": 3')
    tampered_record = json.loads((base_pack / "records" / "00000000000000000000.bin").read_text())
    tampered_record["input_tokens"] += 1

    # (name, bundle or None to drop it, manifest bytes, trusted root, identity,
    #  issuer, record overrides, expected exit, expected text, ask cosign)
    cases = [
        ("valid", valid, manifest, trusted, identity, issuer, {}, 0, "SIGNATURE OK", True),
        ("manifest_byte_flipped", valid, flipped, trusted, identity, issuer, {}, 1, vp.REASON_MANIFEST_CHANGED, True),
        ("bundle_missing", None, manifest, trusted, identity, issuer, {}, 1, vp.REASON_SIGNATURE_MISSING, False),
        ("wrong_identity", valid, manifest, trusted, None, None, {}, 1, vp.REASON_IDENTITY_MISMATCH, True),
        ("wrong_issuer", valid, manifest, trusted, identity, None, {}, 1, vp.REASON_ISSUER_MISMATCH, True),
        ("foreign_ca", valid, manifest, foreign, identity, issuer, {}, 1, vp.REASON_UNTRUSTED_CHAIN, True),
        ("corrupt_signed_entry_timestamp", mutated(lambda b: entry(b)["inclusionPromise"].update(
            signedEntryTimestamp=flip_b64(entry(b)["inclusionPromise"]["signedEntryTimestamp"], 10))),
         manifest, trusted, identity, issuer, {}, 1, vp.REASON_TLOG_INVALID, True),
        ("corrupt_inclusion_proof", mutated(lambda b: entry(b)["inclusionProof"]["hashes"].__setitem__(
            0, flip_b64(entry(b)["inclusionProof"]["hashes"][0], 0))),
         manifest, trusted, identity, issuer, {}, 1, vp.REASON_TLOG_INVALID, True),
        ("corrupt_checkpoint", mutated(corrupt_checkpoint),
         manifest, trusted, identity, issuer, {}, 1, vp.REASON_TLOG_INVALID, True),
        ("message_digest_mismatch", mutated(lambda b: b["messageSignature"]["messageDigest"].update(
            digest=base64.b64encode(bytes(32)).decode("ascii"))),
         manifest, trusted, identity, issuer, {}, 1, vp.REASON_MANIFEST_CHANGED, True),
        ("entry_mismatch", json.loads((work / "bundles" / "entry_mismatch.sigstore.json").read_text()),
         manifest, trusted, identity, issuer, {}, 1, vp.REASON_TLOG_ENTRY_MISMATCH, True),
        ("outside_validity", json.loads((work / "bundles" / "outside_validity.sigstore.json").read_text()),
         manifest, trusted, identity, issuer, {}, 1, vp.REASON_OUTSIDE_VALIDITY, True),
        ("record_tampered_signature_ok", valid, manifest, trusted, identity, issuer,
         {0: tampered_record}, 1, "FAIL seq=0: hash recomputation disagrees with manifest", False),
        ("unsupported_media_type", mutated(lambda b: b.update(mediaType="application/vnd.dev.sigstore.bundle.v9.9+json")),
         manifest, trusted, identity, issuer, {}, 2, "unsupported Sigstore bundle media type", False),
        # Precedence: a failed record (1) outranks a signature the verifier
        # cannot evaluate (2).
        ("unsupported_bundle_and_tampered_record",
         mutated(lambda b: b.update(mediaType="application/vnd.dev.sigstore.bundle.v9.9+json")),
         manifest, trusted, identity, issuer, {0: tampered_record}, 1, "FAIL: one or more events failed", False),
        ("unusable_trusted_root", valid, manifest, work / "identity", identity, issuer, {}, 2, "cannot use --trusted-root", False),
        # The downgrade: strip the bundle and relabel the pack window A. It
        # verifies as a chain but is unsigned, so it exits 3 unless the reader
        # accepts unsigned packs.
        ("stripped_relabelled_signed_pack", None, relabelled, trusted, identity, issuer,
         {}, 3, "CHAIN OK, AUTHENTICITY NOT ESTABLISHED", False),
        ("stripped_relabelled_allow_unsigned", None, relabelled, trusted, identity, issuer,
         {}, 0, "AUTHENTICITY NOT ESTABLISHED", False),
        # --allow-unsigned never excuses a signed pack's missing signature.
        ("bundle_missing_allow_unsigned", None, manifest, trusted, identity, issuer,
         {}, 1, vp.REASON_SIGNATURE_MISSING, False),
    ]
    expectations = json.loads((work / "cases" / "expectations.json").read_text())
    for label, reason in sorted(expectations.items()):
        case_bundle = json.loads((work / "cases" / f"{label}.sigstore.json").read_text())
        cases.append((label, case_bundle, manifest, trusted, identity, issuer, {}, 1, reason, True))

    failures = 0
    print(f"{'case':34s} {'verify-pack.py':44s} {'cosign':10s} agree")
    for name, case_bundle, manifest_bytes, root, ident, iss, overrides, want_code, want_text, ask_cosign in cases:
        pack = work / "run" / name
        shutil.copytree(base_pack, pack)
        (pack / "manifest.json").write_bytes(manifest_bytes)
        bundle_path = pack / "manifest.json.sigstore.json"
        if case_bundle is None:
            bundle_path.unlink()
        else:
            bundle_path.write_text(json.dumps(case_bundle))
        for seq_no, record in overrides.items():
            (pack / "records" / vp.record_file_name(seq_no)).write_text(json.dumps(record))

        cmd = [sys.executable, str(VERIFIER), "--records", str(pack / "records"),
               "--manifest", str(pack / "manifest.json"), "--trusted-root", str(root)]
        if ident:
            cmd += ["--certificate-identity", ident]
        if iss:
            cmd += ["--certificate-oidc-issuer", iss]
        if name.endswith("_allow_unsigned"):
            cmd += ["--allow-unsigned"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout + result.stderr
        ours_ok = result.returncode == want_code and want_text in output
        ours = f"exit {result.returncode}" + ("" if ours_ok else f" (want {want_code}, '{want_text}')")

        theirs, agree = "n/a", ""
        if cosign and ask_cosign:
            cos = subprocess.run(
                [cosign, "verify-blob", "--bundle", str(bundle_path), "--trusted-root", str(root),
                 "--certificate-identity", ident or vp.PINNED_SIGNER_IDENTITY,
                 "--certificate-oidc-issuer", iss or vp.PINNED_OIDC_ISSUER,
                 "--insecure-ignore-sct", str(pack / "manifest.json")],
                capture_output=True, text=True,
            )
            theirs = "OK" if cos.returncode == 0 else "rejected"
            agree_bool = (cos.returncode == 0) == (result.returncode == 0)
            stricter = name in STRICTER_THAN_COSIGN and cos.returncode == 0 and result.returncode != 0
            agree = "yes" if agree_bool else "stricter" if stricter else "NO"
            if not agree_bool and not stricter:
                failures += 1
                print(f"  cosign said: {(cos.stdout + cos.stderr).strip().splitlines()[-1:]}")
        if not ours_ok:
            failures += 1
            print(output)
        print(f"{name:34s} {ours:44s} {theirs:10s} {agree}")
    print(f"\n{len(cases)} cases, {failures} mismatches")
    return failures


if __name__ == "__main__":
    main()
