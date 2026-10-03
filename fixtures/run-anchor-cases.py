#!/usr/bin/env python3
"""Check verify-pack.py's chain-anchor verification against the proxy's
verifier and against OpenSSL (MEI-2758, ADR-0075).

    python3 fixtures/run-anchor-cases.py

The fixtures come from examples/gen_anchor_fixtures.rs:

- anchors/cases.json — RFC 3161 tokens, each with the code the proxy's Rust
  verifier returned for it. verify-pack.py must return the same code for
  every case. Each case is also put to `openssl ts -verify` (same token,
  imprint, trust root, and genTime as the verification time) and the two
  verdicts are compared. Exit 1 on any mismatch, except the cases in
  STRICTER_THAN_OPENSSL, where verify-pack.py refusing a token OpenSSL accepts
  is expected and the reason is stated.
- anchors/packs/*/ — offline packs run through the command line as a
  reviewer would (--records, --manifest, --allow-unsigned), each with the
  exit code and the lines it must print.

OpenSSL missing: the OpenSSL comparison is skipped with a notice, unless
CI=true, where that is a failure (the proxy's CI runner ships OpenSSL).
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANCHORS = HERE / "anchors"
VERIFIER = HERE.parent / "verify-pack.py"
spec = importlib.util.spec_from_file_location("verify_pack", VERIFIER)
vp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vp)

# verify-pack.py, like the proxy's verifier, applies ADR-0075 D9 policy that
# `openssl ts -verify` does not. Only this direction is tolerated:
# verify-pack.py refusing what OpenSSL accepts, never the reverse.
STRICTER_THAN_OPENSSL = {
    "granted-with-mods": "D9 accepts only PKIStatus granted (0); OpenSSL also accepts grantedWithMods",
    "nonce-missing": "D9 requires a nonce; OpenSSL checks one only against a request (-queryfile)",
    "unexpected-signed-attribute": "D9 allows five signed attributes; OpenSSL ignores unknown ones",
    "ess-cert-id-v1-only": "D9 refuses ESSCertID v1 (SHA-1); OpenSSL accepts it",
    "ess-cert-id-v1-and-v2": "D9 refuses any ESSCertID v1 attribute; OpenSSL accepts it next to v2",
    "sha1-signed-leaf": "D9 refuses SHA-1 certificate signatures; OpenSSL accepts them at its default level",
    "root-window-not-open": "D10 trust windows are Meilynx policy; OpenSSL has no notion of them",
}

# Valid tokens `openssl ts -verify` cannot check, for a stated tool limit.
# Each names a second OpenSSL check that must pass instead, so a token
# verify-pack.py accepts is never accepted on its word alone.
OPENSSL_TS_LIMITS = {
    "rsa-pss-sha256": (
        "cms",
        "openssl ts -verify uses the PKCS7 signature path, which has no RSASSA-PSS support; "
        "`openssl cms -verify -purpose timestampsign` checks the same SignerInfo, chain and purpose at genTime",
    ),
    "cross-cert-alongside": (
        "pinned-intermediate",
        "OpenSSL takes the first issuer candidate (the cross-certificate to an unpinned root) and does not "
        "backtrack; given the intermediate the pinned root issued as -untrusted, it verifies",
    ),
}


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def pem(der):
    import base64
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def case_roots(case):
    """(roots for verify-pack.py, PEM text for OpenSSL's -CAfile)."""
    if case["pinned"]:
        pinned = vp.load_pinned_tsa_roots()[case["pinned"]]
        return pinned, "".join(pem(r.cert.der) for r in pinned)
    start = vp._rfc3339_to_epoch(case["root_window_from"])
    roots = []
    for rel in case["roots"]:
        der = (ANCHORS / rel).read_bytes()
        roots.append(vp.TsaRoot(rel, der, start, float("inf")))
    return roots, "".join(pem(r.cert.der) for r in roots)


def python_verdict(case, token, roots):
    try:
        vp.verify_tsa_token(token, bytes.fromhex(case["imprint"]), roots)
    except vp.AnchorFailure as exc:
        return exc.code
    return "ok"


def openssl_verdict(openssl, case, token_path, ca_pem, work):
    ca = work / f"{case['name']}.ca.pem"
    ca.write_text(ca_pem, encoding="ascii")
    at = int(vp._rfc3339_to_epoch(case["gen_time"]))
    proc = subprocess.run(
        [openssl, "ts", "-verify", "-in", str(token_path), "-digest", case["imprint"], "-CAfile", str(ca),
         "-attime", str(at)],
        capture_output=True, text=True,
    )
    return "ok" if proc.returncode == 0 and "Verification: OK" in proc.stdout else "fail"


def openssl_alternate(openssl, case, token_path, ca_pem, work, kind):
    """The second OpenSSL check for a case in OPENSSL_TS_LIMITS: ok or fail."""
    ca = work / f"{case['name']}.ca.pem"
    ca.write_text(ca_pem, encoding="ascii")
    at = str(int(vp._rfc3339_to_epoch(case["gen_time"])))
    if kind == "cms":
        tok = work / f"{case['name']}.tok"
        subprocess.run([openssl, "ts", "-reply", "-in", str(token_path), "-token_out", "-out", str(tok)],
                       capture_output=True, check=True)
        proc = subprocess.run(
            [openssl, "cms", "-verify", "-inform", "DER", "-in", str(tok), "-CAfile", str(ca), "-attime", at,
             "-purpose", "timestampsign", "-out", os.devnull],
            capture_output=True, text=True,
        )
        return "ok" if proc.returncode == 0 and "Verification successful" in proc.stderr else "fail"
    roots, _ = case_roots(case)
    subjects = {r.cert.subject for r in roots}
    issued = [der for der in tsa_certificates(token_path.read_bytes())
              if vp.TsaCertificate(der).issuer in subjects]
    untrusted = work / f"{case['name']}.untrusted.pem"
    untrusted.write_text("".join(pem(der) for der in issued), encoding="ascii")
    proc = subprocess.run(
        [openssl, "ts", "-verify", "-in", str(token_path), "-digest", case["imprint"], "-CAfile", str(ca),
         "-attime", at, "-untrusted", str(untrusted)],
        capture_output=True, text=True,
    )
    return "ok" if proc.returncode == 0 and "Verification: OK" in proc.stdout else "fail"


def tsa_certificates(resp):
    return vp._tsa_certificates(resp)


def run_cases(openssl, work):
    cases = json.loads((ANCHORS / "cases.json").read_text(encoding="utf-8"))["cases"]
    failures, disagreements, agree, declared, limits = 0, 0, 0, 0, 0
    for case in cases:
        token_path = ANCHORS / case["token"]
        token = token_path.read_bytes()
        roots, ca_pem = case_roots(case)
        py = python_verdict(case, token, roots)
        if py != case["rust"]:
            print(f"FAIL {case['name']}: verify-pack.py says {py}, the proxy verifier says {case['rust']}")
            disagreements += 1
            continue
        line = f"ok   {case['name']}: {py} (= proxy verifier)"
        if openssl:
            ossl = openssl_verdict(openssl, case, token_path, ca_pem, work)
            py_ok = py == "ok"
            if (ossl == "ok") == py_ok:
                agree += 1
                line += f"; openssl {ossl}"
            elif case["name"] in STRICTER_THAN_OPENSSL and ossl == "ok" and not py_ok:
                declared += 1
                line += f"; openssl ok — declared: {STRICTER_THAN_OPENSSL[case['name']]}"
            elif case["name"] in OPENSSL_TS_LIMITS and py_ok:
                kind, why = OPENSSL_TS_LIMITS[case["name"]]
                if openssl_alternate(openssl, case, token_path, ca_pem, work, kind) != "ok":
                    print(f"FAIL {case['name']}: openssl ts fails and the {kind} check fails too")
                    failures += 1
                    continue
                limits += 1
                line += f"; openssl ts fails ({why}); openssl {kind} check ok"
            else:
                print(f"FAIL {case['name']}: verify-pack.py says {py}, openssl says {ossl} (not a declared case)")
                failures += 1
                continue
        print(line)
    unused = (set(STRICTER_THAN_OPENSSL) | set(OPENSSL_TS_LIMITS)) - {c["name"] for c in cases}
    if unused:
        print(f"FAIL: declared disagreements name no case: {sorted(unused)}")
        failures += 1
    summary = (f"{len(cases)} token cases: verify-pack.py == proxy verifier on {len(cases) - disagreements}, "
               f"differs on {disagreements}")
    if openssl:
        summary += (f"; openssl agrees {agree}, declared stricter-than-openssl {declared}, "
                    f"openssl-ts limit (second openssl check ok) {limits}, unexpected {failures}")
    print(summary)
    return failures + disagreements


def run_packs(work):
    failures = 0
    packs = sorted(p for p in (ANCHORS / "packs").iterdir() if p.is_dir())
    for pack in packs:
        expect = json.loads((pack / "expect.json").read_text(encoding="utf-8"))
        for index, run in enumerate(expect["runs"]):
            args = []
            for arg in run["args"]:
                if "=roots/" in arg:
                    tsa_id, rel = arg.split("=", 1)
                    pem_path = work / f"{pack.name}-{index}-{tsa_id}.pem"
                    pem_path.write_text(pem((ANCHORS / rel).read_bytes()), encoding="ascii")
                    arg = f"{tsa_id}={pem_path}"
                args.append(arg)
            proc = subprocess.run(
                [sys.executable, str(VERIFIER), "--records", str(pack / "records"), "--manifest",
                 str(pack / "manifest.json"), "--allow-unsigned"] + args,
                capture_output=True, text=True,
            )
            output = proc.stdout + proc.stderr
            missing = [c for c in run["contains"] if c not in output]
            if proc.returncode != run["exit"] or missing:
                print(f"FAIL pack {pack.name} run {index}: exit {proc.returncode} (want {run['exit']}), "
                      f"missing {missing}")
                print("\n".join(f"    | {line}" for line in output.splitlines()))
                failures += 1
            else:
                print(f"ok   pack {pack.name} run {index}: exit {proc.returncode}")
    return failures


def main():
    openssl = shutil.which("openssl")
    if openssl is None:
        if os.environ.get("CI") == "true":
            die("openssl not found and CI=true: the OpenSSL differential must not skip in CI")
        print("NOTICE: openssl not found; skipping the OpenSSL comparison (it runs in CI)")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        failures = run_cases(openssl, work) + run_packs(work)
    if failures:
        die(f"{failures} anchor case(s) failed")
    print("all anchor cases passed")


if __name__ == "__main__":
    main()
