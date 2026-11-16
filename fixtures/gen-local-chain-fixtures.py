#!/usr/bin/env python3
"""Generate the local-chain fixtures under fixtures/local-chain/.

    python3 fixtures/gen-local-chain-fixtures.py            # rewrites them in place
    python3 fixtures/gen-local-chain-fixtures.py DIR        # writes the same cases under DIR

A local-chain pack is what a gateway with no write-once store writes from its
own audit database: manifest 1.4 with evidence_class
`local-chain-not-write-once`, no signature, and a `claim` of the whole chain
from sequence 0 up to the head the gateway read (SPEC section 6.5, 6.7, 6.8).

Where the records come from:

- The anchored cases reuse the proxy-generated anchor fixture chain in
  fixtures/anchors/packs/fully-anchored/ (written by the proxy's
  examples/gen_anchor_fixtures.rs): its record files and its anchor
  statements and RFC 3161 tokens are copied byte for byte. Only the manifest
  is written here, in the shape the proxy's local-chain pack generator writes
  (meilynx-integrity-pack src/local.rs): version 1.4, the local-chain class,
  a `local-chain:` bucket label and a `chain_to_head` claim. The aggregate
  fields, the per-record entries and the anchoring section are the proxy's,
  cut to the pack's last record where a case packs fewer records.
- The evidence-mode cases are a new chain sealed with this verifier's own
  hash functions, as fixtures/generate.py does, holding two gateway boots:
  one in write_once mode and one in local_chain mode.

The cases (each case's expect.json lists its runs):

  clean               records 0..4, anchors at 2 and 4                 exit 0 / 3
  earlier-pack        records 0..2, its anchor at 2, and the later
                      anchor at 4 supplied with it                     exit 4
  claim-relabelled    earlier-pack with its claim changed to interval  exit 1
  evidence-modes      two boots, write_once then local_chain           exit 0
  evidence-modes-doctored
                      the same records, the manifest's list of modes
                      missing the change                               exit 1

Everything is synthetic: fixed timestamps and ids, no real content.
"""
import importlib.util
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify_pack", HERE.parent / "verify-pack.py")
vp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vp)

SOURCE = HERE / "anchors" / "packs" / "fully-anchored"
# `manifest.substrate_name` and the bucket label of a local-chain pack, as
# the proxy's generator writes them (LOCAL_CHAIN_SUBSTRATE, `local-chain:{gateway}`).
SUBSTRATE = "Gateway local hash chain (audit database on the data volume); no write-once store"
BUCKET = "local-chain:fixture-gateway"

# Field order of the proxy's IntegrityPackManifest, which serializes in
# declaration order.
ORDER = (
    "schema_version", "pack_id", "window", "signing_deferred", "generated_at", "generator_version",
    "substrate_name", "evidence_class", "bucket", "prefix", "from_sequence", "to_sequence", "claim",
    "evidence_modes", "hash_algorithm", "hash_version", "genesis_hash", "verified", "records_checked",
    "first_sequence", "last_sequence", "break_at_sequence", "violation_kind", "error", "anchoring", "events",
)


def ordered(manifest):
    unknown = set(manifest) - set(ORDER)
    if unknown:
        raise SystemExit(f"manifest key(s) {sorted(unknown)} have no place in ORDER")
    return {k: manifest[k] for k in ORDER if k in manifest}


def local_manifest(base, to_seq, scope=vp.CLAIM_CHAIN_TO_HEAD, evidence_modes=None):
    """`base` relabelled as a local-chain pack holding records 0..to_seq."""
    m = dict(base)
    m.update(
        schema_version="1.4",
        evidence_class=vp.LOCAL_CHAIN_EVIDENCE_CLASS,
        substrate_name=SUBSTRATE,
        bucket=BUCKET,
        to_sequence=to_seq,
        last_sequence=to_seq,
        records_checked=to_seq + 1,
        claim={"scope": scope, "from_sequence": 0, "to_sequence": to_seq},
        events=[e for e in base["events"] if e["sequence"] <= to_seq],
    )
    if evidence_modes:
        m["evidence_modes"] = evidence_modes
    return ordered(m)


def cut_anchoring(anchoring, to_seq):
    """The anchoring section a generator that read the chain up to `to_seq`
    writes: the anchors at or below it; anchored when the last is at the head."""
    chain = dict(anchoring["chains"][0])
    chain["anchors"] = [a for a in chain["anchors"] if a["seq"] <= to_seq]
    through = max((a["seq"] for a in chain["anchors"]), default=None)
    chain["anchored_through_seq"] = through
    chain["unanchored_tail"] = None if through == to_seq else {"from_seq": (through or -1) + 1, "to_seq": to_seq}
    state = "anchored" if through == to_seq else ("partially_anchored" if through is not None else "unanchored")
    chain["reason"] = "anchored" if through is not None else "no_anchors_found"
    return {"chains": [chain], "state": state}


def copy_records(out, seqs, anchor_seqs):
    (out / "records" / "anchors").mkdir(parents=True)
    for seq in seqs:
        name = vp.record_file_name(seq)
        shutil.copyfile(SOURCE / "records" / name, out / "records" / name)
    for path in sorted((SOURCE / "records" / "anchors").iterdir()):
        if int(path.name.split(".")[0]) in anchor_seqs:
            shutil.copyfile(path, out / "records" / "anchors" / path.name)


def write_case(out, manifest, expect):
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (out / "expect.json").write_text(json.dumps(expect, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out}")


ROOTS = ["--tsa-root", "test-rsa=anchors/roots/rsa-root.pem", "--tsa-root", "test-ec=anchors/roots/ec-root.pem"]


def anchored_cases(root):
    base = json.loads((SOURCE / "manifest.json").read_text())
    chain = base["anchoring"]["chains"][0]["chain"]

    out = root / "clean"
    copy_records(out, range(5), {2, 4})
    write_case(out, local_manifest(base, 4), {"runs": [
        {"args": ["--allow-unsigned", *ROOTS], "exit": 0, "contains": [
            "EVIDENCE CLASS: local-chain-not-write-once",
            f"CLAIM: the whole chain {chain} from seq=0 up to its head at seq=4",
            "ANCHORS OK: verified through seq=4, 2/2 witnesses",
            "AUTHENTICITY NOT ESTABLISHED",
            "[evidence class: local-chain-not-write-once]"],
         "absent": ["FAIL", "COVERAGE NOT ESTABLISHED"]},
        {"args": ROOTS, "exit": 3, "contains": ["AUTHENTICITY NOT ESTABLISHED"]},
        {"args": ["--allow-unsigned", "--require-through", "4", *ROOTS], "exit": 0, "contains": [
            "COVERAGE: the pack reaches seq=4, at or after the required seq=4"]},
        {"args": ["--allow-unsigned", "--require-through", "5", *ROOTS], "exit": 4, "contains": [
            "COVERAGE NOT ESTABLISHED through seq=5: the pack's last record is seq=4",
            "INTEGRITY OK, COVERAGE NOT ESTABLISHED"],
         "absent": ["FAIL"]},
    ]})

    # The pack a gateway wrote when its head was 2. The anchor at 4 was made
    # later and is supplied with the pack by the reader, in records/anchors/,
    # as the pack's README asks; the manifest does not list it.
    earlier = local_manifest(dict(base, anchoring=cut_anchoring(base["anchoring"], 2)), 2)
    out = root / "earlier-pack"
    copy_records(out, range(3), {2, 4})
    write_case(out, earlier, {"runs": [
        {"args": ["--allow-unsigned", *ROOTS], "exit": 4, "contains": [
            f"CLAIM: the whole chain {chain} from seq=0 up to its head at seq=2",
            f"COVERAGE anchor seq=4: a verified anchor",
            "after this pack's last record seq=2",
            "COVERAGE NOT ESTABLISHED through seq=4",
            "INTEGRITY OK, COVERAGE NOT ESTABLISHED: all 3 events verified",
            "This is not a tampering verdict."],
         "absent": ["FAIL"]},
        {"args": ROOTS, "exit": 4, "contains": ["INTEGRITY OK, COVERAGE NOT ESTABLISHED"]},
    ]})

    # The same pack with its claim edited to a window, which would stop the
    # later anchor from being judged. The manifest is unsigned, so anyone can
    # make this edit; the verifier refuses the combination.
    out = root / "claim-relabelled"
    copy_records(out, range(3), {2, 4})
    write_case(out, dict(earlier, claim={"scope": vp.CLAIM_INTERVAL, "from_sequence": 0, "to_sequence": 2}),
               {"runs": [
                   {"args": ["--allow-unsigned", *ROOTS], "exit": 1, "contains": [
                       "FAIL claim: a local-chain-not-write-once pack claims 'interval'",
                       "FAIL: the manifest's claim contradicts the manifest"]},
               ]})


def mode_chain():
    genesis = vp.genesis_hash()
    records, prev = [], genesis

    def seal(event):
        nonlocal prev
        event["sequence_number"] = len(records)
        event["previous_hash"] = prev
        event["event_hash"] = vp.recompute_event_hash(event, event["sequence_number"], prev)
        prev = event["event_hash"]
        records.append(event)

    def admin(ts, action_type, description, metadata):
        seq = len(records)
        return {
            "schema_version": "v1.3", "event_kind": "admin_action",
            "timestamp_utc": ts, "event_id": f"00000000-0000-4000-8000-0000000e00{seq:02d}",
            "request_id": f"00000000-0000-4000-8000-0000000e00{seq:02d}",
            "model_requested": "", "action": "allow", "input_tokens": 0, "output_tokens": 0,
            "estimated_cost_usd": None, "findings": [], "messages": [], "response_text": None,
            "admin_action": {"action_type": action_type, "actor": "system:pid:1", "description": description,
                             "metadata_json": json.dumps(metadata, separators=(",", ":"), sort_keys=True)},
        }

    def request(ts):
        seq = len(records)
        return {
            "schema_version": "v1.1", "timestamp_utc": ts,
            "event_id": f"00000000-0000-4000-8000-0000000e00{seq:02d}",
            "request_id": f"00000000-0000-4000-8000-0000000e10{seq:02d}",
            "model_requested": "gpt-4.1-mini", "model_executed": "gpt-4.1-mini-2025-04-14",
            "provider": "openai", "action": "allow", "input_tokens": 12, "output_tokens": 30,
            "total_tokens": 42, "estimated_cost_usd": 5.4e-05, "policy_version": "0" * 64,
            "findings": [], "messages": [{"role": "user", "content": "Synthetic request."}],
            "response_text": "Synthetic response.",
        }

    # The proxy's own descriptions of each mode (evidence_mode.rs).
    write_once = "Evidence mode write_once: records are confirmed by the write-once store before export"
    local_chain = ("Evidence mode local_chain: no write-once store; the local chain is the only record and "
                   "exports say their records are not write-once confirmed")
    seal(admin("2026-11-01T09:00:00.000000000Z", "proxy_startup", "Proxy server started",
               {"proxy_version": "fixture"}))
    seal(admin("2026-11-01T09:00:00.100000000Z", "evidence_mode_resolved", write_once,
               {"mode": "write_once", "source": "derived", "write_once_confirmed": True}))
    seal(request("2026-11-01T09:05:00.000000000Z"))
    seal(admin("2026-11-02T09:00:00.000000000Z", "proxy_startup", "Proxy server started",
               {"proxy_version": "fixture"}))
    seal(admin("2026-11-02T09:00:00.100000000Z", "evidence_mode_resolved", local_chain,
               {"mode": "local_chain", "source": "configured", "write_once_confirmed": False}))
    seal(request("2026-11-02T09:05:00.000000000Z"))
    return genesis, records


def mode_cases(root):
    genesis, records = mode_chain()
    head = records[-1]["sequence_number"]
    modes = [{"sequence": 1, "mode": "write_once", "source": "derived"},
             {"sequence": 4, "mode": "local_chain", "source": "configured"}]
    base = {
        "schema_version": "1.4", "pack_id": "00000000-0000-4000-8000-0000000e0f00", "window": "A",
        "signing_deferred": True, "generated_at": "2026-11-02T10:00:00Z", "generator_version": "fixture",
        "prefix": "audit/proxy/", "from_sequence": 0, "hash_algorithm": "SHA-256", "hash_version": "v1",
        "genesis_hash": genesis, "verified": True, "first_sequence": 0, "break_at_sequence": None,
        "violation_kind": None, "error": None,
        "anchoring": {"chains": [{"anchored_through_seq": None, "anchors": [], "chain": "proxy",
                                  "reason": "no_anchors_found", "seals": [],
                                  "unanchored_tail": {"from_seq": 0, "to_seq": head}}],
                      "state": "unanchored"},
        "events": [{
            "sequence": r["sequence_number"], "timestamp_utc": r["timestamp_utc"], "action": r["action"],
            "model_requested": r["model_requested"], "project_id": None, "request_id": r["request_id"],
            "event_id": r["event_id"], "stored_event_hash": r["event_hash"],
            "recomputed_event_hash": r["event_hash"], "hash_match": True, "previous_hash_match": True,
        } for r in records],
    }

    def write_records(out):
        (out / "records").mkdir(parents=True)
        for r in records:
            (out / "records" / vp.record_file_name(r["sequence_number"])).write_bytes(
                json.dumps(r, indent=1).encode("utf-8"))

    out = root / "evidence-modes"
    write_records(out)
    write_case(out, local_manifest(base, head, evidence_modes=modes), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 0, "contains": [
            "EVIDENCE MODE seq=1: write_once (derived)",
            "EVIDENCE MODE CHANGED at seq=4: write_once -> local_chain (configured)",
            "CLAIM: the whole chain proxy from seq=0 up to its head at seq=5"],
         "absent": ["FAIL"]},
    ]})

    out = root / "evidence-modes-doctored"
    write_records(out)
    write_case(out, local_manifest(base, head, evidence_modes=modes[:1]), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 1, "contains": [
            "FAIL evidence_modes: manifest evidence_modes (seq=1 write_once) disagrees with the evidence-mode "
            "seals in the pack's records (seq=1 write_once, seq=4 local_chain)"]},
    ]})


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "local-chain"
    if root.exists():
        shutil.rmtree(root)
    anchored_cases(root)
    mode_cases(root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
