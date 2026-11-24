#!/usr/bin/env python3
"""Generate the witness-file fixtures under fixtures/witness/.

    python3 fixtures/gen-witness-fixtures.py            # rewrites them in place
    python3 fixtures/gen-witness-fixtures.py DIR        # writes the same files under DIR

A witness file (anchor file) is what a gateway's control plane serves to the
organization's compliance members: a ZIP archive holding witness-manifest.json
(`meilynx.witness_manifest.v1`, SPEC section 6.9), the anchor statements and
timestamp tokens the gateway uploaded under anchors/<chain>/, and the heads it
signed under head-signatures/<chain>/. The cases are judged against the
local-chain packs in fixtures/local-chain/ (gateway `fixture-gateway`, chain
`chain_tnt_fixture_run_a`): `clean` holds records 0..4, `earlier-pack` 0..2.

Where the bytes come from:

- objects/bound-4.json is an anchor statement naming that chain at seq 4 with
  the record's event_hash, its run_id `fixture-gateway/boot-fixture` binding
  the gateway; objects/other-head-4.json names another head at seq 4. Their
  tokens (objects/*.test-rsa.tsr, objects/*.test-ec.tsr) were minted once with
  `openssl ts -reply` by the meilynx-proxy test-only timestamp authorities
  whose roots are fixtures/anchors/roots/ (the RSA one through its
  intermediate, the P-384 one directly); they are committed, not regenerated.
- The anchors/packs/fully-anchored statement at seq 4 and its tokens, whose
  run_id names no gateway, are reused byte for byte.
- The witness manifests, the gateway-signed head and every signature are
  written here: the manifest signature with a test-only P-256 attestation key
  and the head with a test-only Ed25519 gateway key, both derived from fixed
  labels (RFC 6979 and RFC 8032 are deterministic, so the output is the same
  on every run). attestation-key.jwk is the public attestation key the cases
  pin with --attestation-key; wrong-attestation-key.jwk is another one.

The files (cases.json lists every run and its expected exit):

  signed                 a reported head at 3 (with the gateway's signed head)
                         and a timestamp head at 4, signed                 0 / 4
  unsigned               the same heads, unsigned: only the timestamp head
                         counts                                            0 / 4
  reported-ahead         signed, a reported head at 6, after the pack, and
                         a recorded rewind                                 4
  reported-contradicts   signed, a reported head at 3 with another hash    1
  timestamp-contradicts  unsigned, a timestamp head at 4 with another hash 1
  other-gateway          unsigned, for another gateway                    2
  unbound-statement      signed, a timestamp head whose statement names no
                         gateway: counted only under the signature         0 / 4
  tampered               `signed` edited after signing                     1
  object-mismatch        unsigned, a token that is not the one listed      1
"""
import base64
import hashlib
import importlib.util
import json
import shutil
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("verify_pack", HERE.parent / "verify-pack.py")
vp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vp)

OBJECTS = HERE / "witness" / "objects"
CLEAN = HERE / "local-chain" / "clean"
ANCHORED = HERE / "anchors" / "packs" / "fully-anchored" / "records" / "anchors"
CHAIN = "chain_tnt_fixture_run_a"
PROXY = "fixture-gateway"
ORG = "0f1e2d3c-4b5a-4968-8776-655443322110"
PROJECT = "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9"
GENERATED_AT = "2026-11-24T00:00:00Z"
TOKENS_RECEIVED_AT = "2026-11-23T23:52:00Z"
TOKEN_GEN_TIME = "2026-11-23T23:50:59Z"
ANCHORED_GEN_TIME = "2026-05-01T00:10:00Z"
REPORTED_OBSERVED_AT = "2026-05-01T00:11:00Z"
REPORTED_RECEIVED_AT = "2026-05-01T00:11:02Z"
ATTESTATION_D = int.from_bytes(
    hashlib.sha256(b"meilynx-verify test-only witness attestation key").digest(), "big") % (vp.P256.n - 1) + 1
WRONG_D = int.from_bytes(hashlib.sha256(b"meilynx-verify test-only other attestation key").digest(), "big") % (
    vp.P256.n - 1) + 1
GATEWAY_SEED = hashlib.sha256(b"meilynx-verify test-only gateway evidence key").digest()
DISCLOSURE_SIGNED = (
    "The chain heads this gateway reported to its control plane, kept append-only. A pack is tamper-evident against "
    "the witnessed heads: one that contradicts a witnessed head inside it fails, one that ends before a witnessed head "
    "does not establish coverage. A witnessed head shows that the head was reported at that time, not that the records "
    "behind it were kept. Heads backed by a timestamp token count on the timestamp authority's signature; heads "
    "reported between anchors count because this file is signed with the project's evidence attestation key.")
DISCLOSURE_UNSIGNED = (
    "The chain heads this gateway reported to its control plane, kept append-only. A pack is tamper-evident against "
    "the witnessed heads: one that contradicts a witnessed head inside it fails, one that ends before a witnessed head "
    "does not establish coverage. A witnessed head shows that the head was reported at that time, not that the records "
    "behind it were kept. This file is unsigned (the control plane that built it has no evidence attestation key): "
    "only heads backed by a timestamp token count; the heads reported between anchors are listed for information.")


def record_hashes():
    manifest = json.loads((CLEAN / "manifest.json").read_text())
    return {e["sequence"]: e["stored_event_hash"] for e in manifest["events"]}


def record(seq):
    return json.loads((CLEAN / "records" / f"{seq:020d}.bin").read_text())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Builder:
    """One witness file: members by path and the manifest's head entries."""

    def __init__(self, proxy=PROXY):
        self.proxy = proxy
        self.members = {}
        self.heads = []
        self.contradictions = []

    def timestamp(self, seq, statement, tokens, event_hash=None, gen_time=TOKEN_GEN_TIME):
        """`tokens`: {tsa_id: bytes}."""
        path = vp.witness_statement_path(CHAIN, seq)
        self.members[path] = statement
        listed = {}
        for tsa_id, token in sorted(tokens.items()):
            tpath = vp.witness_token_path(CHAIN, seq, tsa_id)
            self.members[tpath] = token
            listed[tsa_id] = {"gen_time": gen_time, "path": tpath, "sha256": sha(token)}
        named = json.loads(statement)["heads"][0]["event_hash"]
        self.heads.append({"basis": "timestamp", "event_hash": event_hash or named, "received_at": TOKENS_RECEIVED_AT,
                           "seq": seq, "statement": {"path": path, "sha256": sha(statement)}, "tokens": listed})

    def reported(self, seq, event_hash, signed_head=None):
        ref = None
        if signed_head is not None:
            path = vp.witness_signed_head_path(CHAIN, seq)
            self.members[path] = signed_head
            ref = {"path": path, "sha256": sha(signed_head)}
        self.heads.append({"basis": "reported", "event_hash": event_hash, "observed_at": REPORTED_OBSERVED_AT,
                           "received_at": REPORTED_RECEIVED_AT, "seq": seq, "signed_head": ref})

    def manifest(self, signed):
        heads = sorted(self.heads, key=lambda h: (h["seq"], h["basis"] != "reported", h["event_hash"]))
        kid = vp.p256_jwk_thumbprint(vp._p256_self_test_jwk(ATTESTATION_D))
        m = {
            "chains": [{"chain": CHAIN, "heads": heads, "omitted_earlier_heads": 0}],
            "contradictions": self.contradictions,
            "disclosure": DISCLOSURE_SIGNED if signed else DISCLOSURE_UNSIGNED,
            "format": vp.WITNESS_MANIFEST_FORMAT,
            "generated_at": GENERATED_AT,
            "omitted_chains": 0,
            "org_id": ORG,
            "project_id": PROJECT,
            "proxy_id": self.proxy,
            "signing": ({"key_id": kid, "reason": "attestation_key", "state": "signed"} if signed
                        else {"key_id": None, "reason": "no_attestation_key", "state": "unsigned"}),
        }
        if signed:
            m["signature"] = sign(m, kid)
        return m


def sign(m, kid):
    raw = vp._p256_self_test_sign(ATTESTATION_D, vp.witness_manifest_message(m))
    return {"alg": "ES256", "key_id": kid, "scheme": vp.WITNESS_MANIFEST_FORMAT,
            "value": base64.b64encode(raw).decode("ascii")}


def write_zip(path, manifest, members):
    """A deterministic archive: members sorted, stored, fixed times."""
    entries = dict(members)
    entries[vp.WITNESS_MANIFEST_NAME] = vp.jcs_dumps(manifest).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as z:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            z.writestr(info, entries[name])


def signed_head(seq, event_hash):
    public, sign_fn = vp._ed25519_self_test_keypair(GATEWAY_SEED)
    statement = {
        "chain_id": CHAIN,
        "first_sequence": 0,
        "format": vp.CHAIN_HEAD_FORMAT,
        "hash_version": record(seq)["schema_version"],
        "head_event_hash": event_hash,
        "head_sequence": seq,
        "key_fingerprint": vp.chain_key_fingerprint(public),
        "key_seq": 1,
        "org_id": ORG,
        "project_id": PROJECT,
        "proxy_id": PROXY,
        "signed_at": REPORTED_OBSERVED_AT,
    }
    signature = sign_fn(vp.CHAIN_HEAD_DOMAIN + vp.jcs_dumps(statement).encode("utf-8"))
    return vp.jcs_dumps({"signature": signature.hex(), "statement": statement}).encode("utf-8")


def build(out):
    hashes = record_hashes()
    bound = (OBJECTS / "bound-4.json").read_bytes()
    bound_tokens = {t: (OBJECTS / f"bound-4.{t}.tsr").read_bytes() for t in ("test-ec", "test-rsa")}
    other = (OBJECTS / "other-head-4.json").read_bytes()
    other_tokens = {t: (OBJECTS / f"other-head-4.{t}.tsr").read_bytes() for t in ("test-ec", "test-rsa")}
    unbound = (ANCHORED / "00000000000000000004.json").read_bytes()
    unbound_tokens = {t: (ANCHORED / f"00000000000000000004.{t}.tsr").read_bytes() for t in ("test-ec", "test-rsa")}
    ahead = hashlib.sha256(b"witness fixture: a reported head at seq 6").hexdigest()
    wrong3 = hashlib.sha256(b"witness fixture: another head at seq 3").hexdigest()
    files = out / "files"
    if files.exists():
        shutil.rmtree(files)

    def standard(proxy=PROXY):
        b = Builder(proxy)
        b.reported(3, hashes[3], signed_head(3, hashes[3]))
        b.timestamp(4, bound, bound_tokens)
        return b

    b = standard()
    signed_manifest = b.manifest(signed=True)
    write_zip(files / "signed.zip", signed_manifest, b.members)
    (out / "witness-manifest.v1.example.json").write_text(
        json.dumps(signed_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    b = standard()
    write_zip(files / "unsigned.zip", b.manifest(signed=False), b.members)

    b = Builder()
    b.timestamp(4, bound, bound_tokens)
    b.reported(6, ahead)
    b.contradictions.append({"chain": CHAIN, "detected_at": "2026-05-01T00:20:00Z", "earlier_event_hash": ahead,
                             "earlier_seq": 6, "event_hash": hashes[4], "kind": "rewind", "seq": 4,
                             "source": "heartbeat"})
    write_zip(files / "reported-ahead.zip", b.manifest(signed=True), b.members)

    b = Builder()
    b.reported(3, wrong3)
    b.timestamp(4, bound, bound_tokens)
    write_zip(files / "reported-contradicts.zip", b.manifest(signed=True), b.members)

    b = Builder()
    b.timestamp(4, other, other_tokens)
    write_zip(files / "timestamp-contradicts.zip", b.manifest(signed=False), b.members)

    b = standard("other-gateway")
    write_zip(files / "other-gateway.zip", b.manifest(signed=False), b.members)

    b = Builder()
    b.timestamp(4, unbound, unbound_tokens, gen_time=ANCHORED_GEN_TIME)
    write_zip(files / "unbound-statement.zip", b.manifest(signed=True), b.members)

    b = standard()
    tampered = b.manifest(signed=True)
    tampered["chains"][0]["heads"][0]["received_at"] = "2026-05-01T00:30:00Z"
    write_zip(files / "tampered.zip", tampered, b.members)

    b = standard()
    m = b.manifest(signed=False)
    b.members[vp.witness_token_path(CHAIN, 4, "test-rsa")] = other_tokens["test-rsa"]
    write_zip(files / "object-mismatch.zip", m, b.members)

    for name, d in (("attestation-key.jwk", ATTESTATION_D), ("wrong-attestation-key.jwk", WRONG_D)):
        (out / name).write_text(json.dumps(vp._p256_self_test_jwk(d), indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "witness"
    out.mkdir(parents=True, exist_ok=True)
    build(out)
    print(f"wrote the witness fixtures to {out}")


if __name__ == "__main__":
    main()
