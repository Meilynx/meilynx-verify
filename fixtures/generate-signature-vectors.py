#!/usr/bin/env python3
"""Generate the synthetic signed-pack vectors that verify-pack.py's
--self-test checks its signature verification against (MEI-922).

    python3 fixtures/generate-signature-vectors.py            # print the block
    python3 fixtures/generate-signature-vectors.py --write    # rewrite it in verify-pack.py
    python3 fixtures/generate-signature-vectors.py --check    # exit 1 if verify-pack.py differs
    python3 fixtures/generate-signature-vectors.py --out DIR  # also write a signed pack to DIR

Everything here is a TEST-ONLY stand-in for the Sigstore public-good
instance: two throwaway CA hierarchies (A, trusted; B, foreign), a throwaway
transparency-log key, and a three-entry log. The keys are derived from fixed
labels and every signature uses RFC 6979 deterministic nonces, so the output
is byte-identical on every run. None of these keys is in verify-pack.py's
default trust root; the self-test passes them explicitly.

--out DIR writes a real pack a reviewer (or cosign) can check end to end:

    DIR/pack/manifest.json, DIR/pack/manifest.json.sigstore.json, DIR/pack/records/
    DIR/trusted_root.json            test CA A + test log key
    DIR/foreign_trusted_root.json    test CA B + the same log key
    DIR/bundles/*.sigstore.json      the valid bundle and the negative cases
    DIR/identity, DIR/issuer

The generator imports verify-pack.py for its curve arithmetic, DER reader and
record hashing, so the vectors are provably in the format the verifier checks.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE.parent / "verify-pack.py"
spec = importlib.util.spec_from_file_location("verify_pack", VERIFIER)
vp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vp)

BEGIN = "# BEGIN GENERATED SIGNATURE VECTORS"
END = "# END GENERATED SIGNATURE VECTORS"

IDENTITY = "https://selftest.invalid/meilynx-verify/test-only-signer"
ISSUER = "https://selftest.invalid/test-only-oidc-issuer"
LOG_ORIGIN = "selftest.invalid - 1"
LOG_NAME = "selftest.invalid"
INTEGRATED_TIME = 1790000000  # 2026-09-21T14:13:20Z
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"


# ── DER writer ─────────────────────────────────────────────────────────────

def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(body)]) + body
    return bytes([tag]) + length + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def der_int(value):
    body = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return tlv(0x02, body)


def der_oid(dotted):
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray()
    for i, arc in enumerate([arcs[0] * 40 + arcs[1]] + arcs[2:]):
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(chunk))
    return tlv(0x06, bytes(out))


def utc_time(epoch):
    moment = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def name(organization, common_name):
    return seq(
        tlv(0x31, seq(der_oid("2.5.4.10"), tlv(0x0C, organization.encode()))),
        tlv(0x31, seq(der_oid("2.5.4.3"), tlv(0x0C, common_name.encode()))),
    )


def extension(oid, value, critical=False):
    parts = [der_oid(oid)]
    if critical:
        parts.append(tlv(0x01, b"\xff"))
    parts.append(tlv(0x04, value))
    return seq(*parts)


# ── Keys and deterministic ECDSA ───────────────────────────────────────────

class Key:
    def __init__(self, curve, label):
        self.curve = curve
        seed = hashlib.sha512(b"meilynx-verify test-only key: " + label.encode()).digest()
        self.d = int.from_bytes(seed, "big") % (curve.n - 1) + 1
        self.point = scalar_mult(curve, self.d, curve.g)

    def spki(self):
        size = self.curve.size
        point = b"\x04" + self.point[0].to_bytes(size, "big") + self.point[1].to_bytes(size, "big")
        return seq(seq(der_oid(vp.OID_EC_PUBLIC_KEY), der_oid(self.curve.oid)), tlv(0x03, b"\x00" + point))

    def sign_digest(self, digest, hash_name, nonce=None):
        c = self.curve
        k = nonce or rfc6979_k(c, self.d, digest, hash_name)
        r = scalar_mult(c, k, c.g)[0] % c.n
        e = int.from_bytes(digest, "big")
        excess = len(digest) * 8 - c.n.bit_length()
        if excess > 0:
            e >>= excess
        s = pow(k, -1, c.n) * (e + r * self.d) % c.n
        return seq(der_int(r), der_int(s))


def scalar_mult(c, k, point):
    acc = vp._INFINITY
    base = (point[0], point[1], 1)
    for i in range(k.bit_length() - 1, -1, -1):
        acc = vp._jacobian_double(c, acc)
        if (k >> i) & 1:
            acc = vp._jacobian_add(c, acc, base)
    x, y, z = acc
    zi = pow(z, -1, c.p)
    return (x * zi * zi % c.p, y * zi * zi * zi % c.p)


def rfc6979_k(c, d, digest, hash_name):
    qlen = c.n.bit_length()
    rlen = (qlen + 7) // 8

    def bits2int(b):
        v = int.from_bytes(b, "big")
        return v >> max(0, len(b) * 8 - qlen)

    def mac(key, data):
        return hmac.new(key, data, hash_name).digest()

    hlen = hashlib.new(hash_name).digest_size
    x = d.to_bytes(rlen, "big")
    h = (bits2int(digest) % c.n).to_bytes(rlen, "big")
    v, k = b"\x01" * hlen, b"\x00" * hlen
    k = mac(k, v + b"\x00" + x + h)
    v = mac(k, v)
    k = mac(k, v + b"\x01" + x + h)
    v = mac(k, v)
    while True:
        t = b""
        while len(t) * 8 < qlen:
            v = mac(k, v)
            t += v
        candidate = bits2int(t)
        if 1 <= candidate < c.n:
            return candidate
        k = mac(k, v + b"\x00")
        v = mac(k, v)


# ── Certificates ───────────────────────────────────────────────────────────

SHA256_ALG = seq(der_oid("1.2.840.10045.4.3.2"))
SHA384_ALG = seq(der_oid("1.2.840.10045.4.3.3"))
KEY_USAGE_CA = tlv(0x03, b"\x01\x06")      # keyCertSign, cRLSign
KEY_USAGE_SIGNING = tlv(0x03, b"\x07\x80")  # digitalSignature
EKU_CODE_SIGNING = seq(der_oid(vp.OID_CODE_SIGNING))


def certificate(subject, issuer, key, issuer_key, serial, not_before, not_after, extensions,
                tbs_alg=SHA384_ALG):
    tbs = seq(
        tlv(0xA0, der_int(2)),
        der_int(serial),
        tbs_alg,
        issuer,
        seq(utc_time(not_before), utc_time(not_after)),
        subject,
        key.spki(),
        tlv(0xA3, seq(*extensions)),
    )
    signature = issuer_key.sign_digest(hashlib.sha384(tbs).digest(), "sha384")
    return seq(tbs, SHA384_ALG, tlv(0x03, b"\x00" + signature))


def ca_hierarchy(label):
    root_key = Key(vp.P384, f"{label} root")
    inter_key = Key(vp.P384, f"{label} intermediate")
    root_name = name("meilynx-verify self-test", f"TEST-ONLY {label} root")
    inter_name = name("meilynx-verify self-test", f"TEST-ONLY {label} intermediate")
    start, end = INTEGRATED_TIME - 10_000_000, INTEGRATED_TIME + 10_000_000
    root = certificate(root_name, root_name, root_key, root_key, 1, start, end, [
        extension(vp.OID_KEY_USAGE, KEY_USAGE_CA, critical=True),
        extension(vp.OID_BASIC_CONSTRAINTS, seq(tlv(0x01, b"\xff"), der_int(1)), critical=True),
    ])
    inter = certificate(inter_name, root_name, inter_key, root_key, 2, start, end, [
        extension(vp.OID_KEY_USAGE, KEY_USAGE_CA, critical=True),
        extension(vp.OID_EXT_KEY_USAGE, EKU_CODE_SIGNING),
        extension(vp.OID_BASIC_CONSTRAINTS, seq(tlv(0x01, b"\xff"), der_int(0)), critical=True),
    ])
    return {"root": root, "inter": inter, "inter_key": inter_key, "inter_name": inter_name}


def leaf_extensions(key_usage=KEY_USAGE_SIGNING, code_signing=True, extra=()):
    return [
        extension(vp.OID_KEY_USAGE, key_usage, critical=True),
        *([extension(vp.OID_EXT_KEY_USAGE, EKU_CODE_SIGNING)] if code_signing else []),
        extension(vp.OID_SUBJECT_ALT_NAME, seq(tlv(0x86, IDENTITY.encode())), critical=True),
        extension(vp.OID_FULCIO_ISSUER_V1, ISSUER.encode()),
        extension(vp.OID_FULCIO_ISSUER_V2, tlv(0x0C, ISSUER.encode())),
        *extra,
    ]


def leaf_certificate(ca, key, serial, not_before, not_after, extensions=None, tbs_alg=SHA384_ALG):
    return certificate(seq(), ca["inter_name"], key, ca["inter_key"], serial, not_before, not_after,
                       leaf_extensions() if extensions is None else extensions, tbs_alg)


# ── Transparency log ───────────────────────────────────────────────────────

def merkle_root(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return vp._merkle_node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def merkle_path(index, leaves):
    if len(leaves) == 1:
        return []
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < k:
        return merkle_path(index, leaves[:k]) + [merkle_root(leaves[k:])]
    return merkle_path(index - k, leaves[k:]) + [merkle_root(leaves[:k])]


def b64(data):
    return base64.b64encode(data).decode("ascii")


def pem(der):
    body = b64(der)
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode()


def hashedrekord(artifact_digest, signature, cert_der):
    return json.dumps({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": artifact_digest.hex()}},
            "signature": {"content": b64(signature), "publicKey": {"content": b64(pem(cert_der))}},
        },
    }, sort_keys=True, separators=(",", ":")).encode()


def build_log(log_key, bodies):
    key_id = hashlib.sha256(log_key.spki()).digest()
    leaves = [hashlib.sha256(b"\x00" + body).digest() for body in bodies]
    root = merkle_root(leaves)
    note = f"{LOG_ORIGIN}\n{len(bodies)}\n{b64(root)}\n"
    note_sig = log_key.sign_digest(hashlib.sha256(note.encode()).digest(), "sha256")
    envelope = f"{note}\n— {LOG_NAME} {b64(key_id[:4] + note_sig)}\n"
    entries = []
    for index, body in enumerate(bodies):
        body_b64 = b64(body)
        payload = vp.jcs_dumps({
            "body": body_b64, "integratedTime": INTEGRATED_TIME,
            "logID": key_id.hex(), "logIndex": index,
        }).encode()
        entries.append({
            "logIndex": str(index),
            "logId": {"keyId": b64(key_id)},
            "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
            "integratedTime": str(INTEGRATED_TIME),
            "inclusionPromise": {"signedEntryTimestamp": b64(log_key.sign_digest(hashlib.sha256(payload).digest(), "sha256"))},
            "inclusionProof": {
                "logIndex": str(index),
                "rootHash": b64(root),
                "treeSize": str(len(bodies)),
                "hashes": [b64(h) for h in merkle_path(index, leaves)],
                "checkpoint": {"envelope": envelope},
            },
            "canonicalizedBody": body_b64,
        })
    return key_id, entries


def bundle(cert_der, artifact_digest, signature, entry):
    return {
        "mediaType": BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {"certificate": {"rawBytes": b64(cert_der)}, "tlogEntries": [entry]},
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256", "digest": b64(artifact_digest)},
            "signature": b64(signature),
        },
    }


def trusted_root(ca, log_key, key_id):
    start = "2026-01-01T00:00:00Z"
    return {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [{
            "baseUrl": "https://selftest.invalid/rekor",
            "hashAlgorithm": "SHA2_256",
            "publicKey": {"rawBytes": b64(log_key.spki()), "keyDetails": "PKIX_ECDSA_P256_SHA_256", "validFor": {"start": start}},
            "logId": {"keyId": b64(key_id)},
        }],
        "certificateAuthorities": [{
            "subject": {"organization": "meilynx-verify self-test", "commonName": "TEST-ONLY"},
            "uri": "https://selftest.invalid/fulcio",
            "certChain": {"certificates": [{"rawBytes": b64(ca["inter"])}, {"rawBytes": b64(ca["root"])}]},
            "validFor": {"start": start},
        }],
        "ctlogs": [],
        "timestampAuthorities": [],
    }


# ── The signed pack ────────────────────────────────────────────────────────

def build_chain():
    genesis = vp.genesis_hash()
    records, prev = [], genesis
    for seq_no, tokens in ((0, 11), (1, 13)):
        event = {
            "schema_version": "v1",
            "sequence_number": seq_no,
            "timestamp_utc": f"2026-09-21T14:00:0{seq_no}+00:00",
            "event_id": f"evt-selftest-{seq_no}",
            "request_id": f"req-selftest-{seq_no}",
            "model_requested": "gpt-4.1-mini",
            "action": "allow",
            "input_tokens": tokens,
            "output_tokens": 7,
            "total_tokens": tokens + 7,
            "cache_creation_input_tokens": None,
            "cache_read_input_tokens": None,
            "cached_input_tokens": None,
            "reasoning_tokens": None,
            "estimated_cost_usd": 0.000123,
            "previous_hash": prev,
        }
        event["event_hash"] = vp.recompute_event_hash(event, seq_no, prev)
        prev = event["event_hash"]
        records.append(event)
    manifest = {
        "schema_version": "1.0",
        "pack_id": "00000000-0000-4000-8000-000000000922",
        "window": "B",
        "signing_deferred": False,
        "generated_at": "2026-09-21T14:13:00Z",
        "generator_version": "test-only",
        "substrate_name": "meilynx-verify self-test (TEST-ONLY)",
        "bucket": "selftest.invalid",
        "prefix": "audit/self-test/",
        "from_sequence": 0,
        "to_sequence": 1,
        "hash_algorithm": "sha256",
        "hash_version": "v1",
        "genesis_hash": genesis,
        "verified": True,
        "records_checked": 2,
        "first_sequence": 0,
        "last_sequence": 1,
        "break_at_sequence": None,
        "violation_kind": None,
        "error": None,
        "signature": {
            "method": vp.SIGNATURE_METHOD_COSIGN_KEYLESS,
            "signed_artifact": "manifest.json",
            "signature_file": "manifest.json.sigstore.json",
            "bundle_file": None,
            "transparency_log": "rekor",
        },
        "events": [
            {
                "sequence": r["sequence_number"],
                "timestamp_utc": r["timestamp_utc"],
                "action": r["action"],
                "model_requested": r["model_requested"],
                "project_id": None,
                "request_id": r["request_id"],
                "event_id": r["event_id"],
                "stored_event_hash": r["event_hash"],
                "recomputed_event_hash": r["event_hash"],
                "hash_match": True,
                "previous_hash_match": True,
            }
            for r in records
        ],
    }
    return records, (json.dumps(manifest, indent=2) + "\n").encode()


def build():
    records, manifest = build_chain()
    digest = hashlib.sha256(manifest).digest()
    other_digest = hashlib.sha256(b"a different artifact").digest()

    ca_a, ca_b = ca_hierarchy("CA-A"), ca_hierarchy("CA-B")
    log_key = Key(vp.P256, "transparency log")

    signer = Key(vp.P256, "signer")
    leaf = leaf_certificate(ca_a, signer, 1001, INTEGRATED_TIME - 60, INTEGRATED_TIME + 540)
    sig = signer.sign_digest(digest, "sha256")
    other_sig = signer.sign_digest(other_digest, "sha256")

    late_signer = Key(vp.P256, "expired signer")
    late_leaf = leaf_certificate(ca_a, late_signer, 1002, INTEGRATED_TIME - 1200, INTEGRATED_TIME - 600)
    late_sig = late_signer.sign_digest(digest, "sha256")

    # One-guard negative cases. They sit behind the tamper matrix the
    # embedded self-test covers, where an earlier check would otherwise mask
    # them, so each changes exactly one thing. Written by --out only and run
    # by fixtures/run-signature-cases.py; not embedded in verify-pack.py.
    window = (INTEGRATED_TIME - 60, INTEGRATED_TIME + 540)
    impostor = {"inter_name": ca_a["inter_name"], "inter_key": Key(vp.P384, "impostor intermediate")}
    forger = Key(vp.P256, "forged signer")
    forged_leaf = leaf_certificate(impostor, forger, 1003, *window)
    forged_sig = forger.sign_digest(digest, "sha256")
    alt_sig = signer.sign_digest(digest, "sha256", nonce=0x922)
    twin_leaf = leaf_certificate(ca_a, signer, 1004, *window)
    misnamed = {"inter_name": name("meilynx-verify self-test", "TEST-ONLY some other issuer"),
                "inter_key": ca_a["inter_key"]}
    misnamed_signer = Key(vp.P256, "misnamed signer")
    misnamed_leaf = leaf_certificate(misnamed, misnamed_signer, 1010, *window)
    misnamed_sig = misnamed_signer.sign_digest(digest, "sha256")
    variants = {}
    for label, serial, extensions, tbs_alg in (
        ("no_code_signing", 1005, leaf_extensions(code_signing=False), SHA384_ALG),
        ("no_digital_signature", 1006, leaf_extensions(key_usage=tlv(0x03, b"\x02\x04")), SHA384_ALG),
        ("unknown_critical_extension", 1007,
         leaf_extensions(extra=[extension("1.3.6.1.4.1.57264.99.1", b"\x05\x00", critical=True)]), SHA384_ALG),
        ("leaf_is_ca", 1008,
         leaf_extensions(extra=[extension(vp.OID_BASIC_CONSTRAINTS, seq(tlv(0x01, b"\xff")), critical=True)]),
         SHA384_ALG),
        ("tbs_algorithm_mismatch", 1009, leaf_extensions(), SHA256_ALG),
    ):
        key = Key(vp.P256, label)
        variants[label] = (leaf_certificate(ca_a, key, serial, *window, extensions, tbs_alg),
                           key.sign_digest(digest, "sha256"))

    logged = [
        (leaf, digest, sig), (leaf, other_digest, other_sig), (late_leaf, digest, late_sig),
        (leaf, digest, other_sig), (forged_leaf, digest, forged_sig),
        (leaf, digest, alt_sig), (twin_leaf, digest, sig),
        (leaf, other_digest, sig), (misnamed_leaf, digest, misnamed_sig),
    ] + [(cert, digest, s) for cert, s in variants.values()]
    key_id, entries = build_log(log_key, [hashedrekord(d, s, c) for c, d, s in logged])

    cases = {
        "bad_signature": (bundle(leaf, digest, other_sig, entries[3]), vp.REASON_MANIFEST_CHANGED),
        "forged_issuer": (bundle(forged_leaf, digest, forged_sig, entries[4]), vp.REASON_UNTRUSTED_CHAIN),
        "entry_signature_mismatch": (bundle(leaf, digest, sig, entries[5]), vp.REASON_TLOG_ENTRY_MISMATCH),
        "entry_certificate_mismatch": (bundle(leaf, digest, sig, entries[6]), vp.REASON_TLOG_ENTRY_MISMATCH),
        "entry_digest_mismatch": (bundle(leaf, digest, sig, entries[7]), vp.REASON_TLOG_ENTRY_MISMATCH),
        "issuer_name_mismatch": (bundle(misnamed_leaf, digest, misnamed_sig, entries[8]), vp.REASON_UNTRUSTED_CHAIN),
    }
    for offset, (label, (cert, s)) in enumerate(variants.items()):
        reason = vp.REASON_MALFORMED if label == "tbs_algorithm_mismatch" else vp.REASON_UNTRUSTED_CHAIN
        cases[label] = (bundle(cert, digest, s, entries[9 + offset]), reason)

    return {
        "identity": IDENTITY,
        "issuer": ISSUER,
        "manifest": manifest,
        "records": records,
        "trusted_root": trusted_root(ca_a, log_key, key_id),
        "foreign_trusted_root": trusted_root(ca_b, log_key, key_id),
        "bundle_valid": bundle(leaf, digest, sig, entries[0]),
        "bundle_entry_mismatch": bundle(leaf, digest, sig, entries[1]),
        "bundle_outside_validity": bundle(late_leaf, digest, late_sig, entries[2]),
        "cases": cases,
    }


def compact(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def render_block(v):
    def chunked(text, indent="        "):
        parts = [text[i:i + 72] for i in range(0, len(text), 72)]
        return "(\n" + "".join(f"{indent}{json.dumps(p)}\n" for p in parts) + "    )"

    lines = [
        BEGIN + " (fixtures/generate-signature-vectors.py; do not edit by hand)",
        "# TEST-ONLY keys, certificates and log. Never part of the default trust root.",
        "_SELFTEST_SIGNATURE_VECTORS = {",
        f"    \"identity\": {json.dumps(v['identity'])},",
        f"    \"issuer\": {json.dumps(v['issuer'])},",
        f"    \"manifest\": {chunked(b64(v['manifest']))},",
    ]
    for key in ("records", "trusted_root", "foreign_trusted_root", "bundle_valid",
                "bundle_entry_mismatch", "bundle_outside_validity"):
        lines.append(f"    \"{key}\": {chunked(compact(v[key]))},")
    lines += ["}", END]
    return "\n".join(lines) + "\n"


def embedded_block(source):
    start = source.index(BEGIN)
    end = source.index(END, start) + len(END) + 1
    return start, end


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="rewrite the block in verify-pack.py")
    ap.add_argument("--check", action="store_true", help="exit 1 if verify-pack.py's block differs")
    ap.add_argument("--out", help="also write a signed pack and trust roots to this directory")
    args = ap.parse_args()

    vectors = build()
    block = render_block(vectors)
    source = VERIFIER.read_text(encoding="utf-8")

    if args.check:
        start, end = embedded_block(source)
        if source[start:end] != block:
            print("DRIFT: verify-pack.py's generated signature vectors differ from "
                  "fixtures/generate-signature-vectors.py. Run it with --write.", file=sys.stderr)
            sys.exit(1)
        print("OK: verify-pack.py's signature vectors match the generator")
    elif args.write:
        start, end = embedded_block(source)
        VERIFIER.write_text(source[:start] + block + source[end:], encoding="utf-8")
        print(f"rewrote the signature vectors in {VERIFIER}")
    elif not args.out:
        sys.stdout.write(block)

    if args.out:
        out = Path(args.out)
        pack = out / "pack"
        (pack / "records").mkdir(parents=True, exist_ok=True)
        (out / "bundles").mkdir(parents=True, exist_ok=True)
        (pack / "manifest.json").write_bytes(vectors["manifest"])
        (pack / "manifest.json.sigstore.json").write_text(compact(vectors["bundle_valid"]))
        for r in vectors["records"]:
            (pack / "records" / vp.record_file_name(r["sequence_number"])).write_text(json.dumps(r))
        for key in ("trusted_root", "foreign_trusted_root"):
            (out / f"{key}.json").write_text(json.dumps(vectors[key], indent=2))
        for key in ("bundle_valid", "bundle_entry_mismatch", "bundle_outside_validity"):
            (out / "bundles" / f"{key[len('bundle_'):]}.sigstore.json").write_text(compact(vectors[key]))
        (out / "cases").mkdir(exist_ok=True)
        expectations = {}
        for label, (case_bundle, reason) in vectors["cases"].items():
            (out / "cases" / f"{label}.sigstore.json").write_text(compact(case_bundle))
            expectations[label] = reason
        (out / "cases" / "expectations.json").write_text(json.dumps(expectations, indent=2, sort_keys=True))
        (out / "identity").write_text(vectors["identity"] + "\n")
        (out / "issuer").write_text(vectors["issuer"] + "\n")
        print(f"wrote the signed self-test pack to {out}")


if __name__ == "__main__":
    main()
