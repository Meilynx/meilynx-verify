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
- The judgment-verdict cases are another such chain: two model requests and
  three v1.21 verdict receipts, each linked to the request it judged (a
  scored FLAG whose judged record is uploaded under another id, a scored
  PASS whose judged record is not uploaded, and a pack_unavailable verdict
  that names no pack version). Each receipt stores its uploaded form, the
  receipt without the judge's reason and spans, and its local part, the
  reason and spans, in the shape the proxy writes them.
- The v1.22 judgment-verdict cases are a third such chain: a model request,
  an MCP tool call and four v1.22 verdict receipts whose uploaded form is
  judgment_verdict.v2 and whose local part is judgment_verdict_local.v2 (a
  FLAG judged on raw input under a grant, on the complete candidate reply; a
  PASS judged on the redacted forwarded request; a PASS judged on the tool
  call's arguments; and a raw_input_not_permitted verdict, which reached no
  backend).
- The control-probe cases are a fourth such chain: two v1.23
  control_probe.run records, a run in shadow mode that passed every case and
  an enforcing run with one failed case, each storing its set references and
  its case results beside the hash, in the shape the proxy writes them.

The cases (each case's expect.json lists its runs):

  clean               records 0..4, anchors at 2 and 4                 exit 0 / 3
  earlier-pack        records 0..2, its anchor at 2, and the later
                      anchor at 4 supplied with it                     exit 4
  claim-relabelled    earlier-pack with its claim changed to interval  exit 1
  evidence-modes      two boots, write_once then local_chain           exit 0
  evidence-modes-doctored
                      the same records, the manifest's list of modes
                      missing the change                               exit 1
  judgment-verdicts   two requests and three verdict receipts          exit 0 / 3
  judgment-verdicts-edited
                      the same records, one receipt's uploaded form
                      and another's reason edited after sealing        exit 1
  judgment-verdicts-relinked
                      a receipt sealed with a link to another record
                      than the one at the sequence it names            exit 1
  judgment-verdicts-v2
                      a request, a tool call and four v1.22 receipts   exit 0 / 3
  judgment-verdicts-v2-malformed
                      the same chain sealed with four receipts that
                      break the v1.22 rules (no grant on a raw
                      judgment, an unknown key in the uploaded form,
                      a tool snapshot judging a model request, a
                      floor trigger carrying text)                     exit 1
  judgment-verdicts-v2-relabelled
                      the clean v1.22 chain with one receipt's stamp
                      edited to v1.21 after sealing                    exit 1
  control-probe-runs  two v1.23 probe runs, one with a failed case     exit 0 / 3
  control-probe-runs-edited
                      the same records, a failed case result edited
                      to pass after sealing                            exit 1
  control-probe-runs-miscounted
                      a run sealed with counts its results do not
                      add up to                                        exit 1

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


def unanchored_base(genesis, records, pack_id, generated_at):
    """The manifest of an unanchored pack holding `records`, before
    `local_manifest` relabels it."""
    head = records[-1]["sequence_number"]
    return {
        "schema_version": "1.4", "pack_id": pack_id, "window": "A",
        "signing_deferred": True, "generated_at": generated_at, "generator_version": "fixture",
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


def write_records(out, records):
    (out / "records").mkdir(parents=True)
    for r in records:
        (out / "records" / vp.record_file_name(r["sequence_number"])).write_bytes(
            json.dumps(r, indent=1).encode("utf-8"))


def mode_cases(root):
    genesis, records = mode_chain()
    head = records[-1]["sequence_number"]
    modes = [{"sequence": 1, "mode": "write_once", "source": "derived"},
             {"sequence": 4, "mode": "local_chain", "source": "configured"}]
    base = unanchored_base(genesis, records, "00000000-0000-4000-8000-0000000e0f00", "2026-11-02T10:00:00Z")

    out = root / "evidence-modes"
    write_records(out, records)
    write_case(out, local_manifest(base, head, evidence_modes=modes), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 0, "contains": [
            "EVIDENCE MODE seq=1: write_once (derived)",
            "EVIDENCE MODE CHANGED at seq=4: write_once -> local_chain (configured)",
            "CLAIM: the whole chain proxy from seq=0 up to its head at seq=5"],
         "absent": ["FAIL"]},
    ]})

    out = root / "evidence-modes-doctored"
    write_records(out, records)
    write_case(out, local_manifest(base, head, evidence_modes=modes[:1]), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 1, "contains": [
            "FAIL evidence_modes: manifest evidence_modes (seq=1 write_once) disagrees with the evidence-mode "
            "seals in the pack's records (seq=1 write_once, seq=4 local_chain)"]},
    ]})


# Synthetic judgment ids and digests. The pack digests and clause digests
# name no real pack: the verifier checks a receipt against the chain, not
# against a pack.
PACK_SHA256 = "5" * 64
CLAUSE_SHA256 = "6" * 64
BACKEND = {
    "id": "fixture:judge@1", "distribution": "native", "validated": True,
    "prompt_version": "judge_prompt.v1", "prompt_sha256": "7" * 64,
    "validation_run": "vr_01JFIXTURE", "validation_sha256": "8" * 64,
}


def verdict_receipt(n, ts, judged, upload_id, rule_id, judgment, verdict, reason_code, questions,
                    reason_text, spans, link=None):
    """One v1.21 judgment.verdict record judging the request record `judged`.

    The uploaded form is the receipt without its reason and spans, stored as
    RFC 8785 text; it names the judged record by `upload_id`, the id that
    record is uploaded under (its chain id when nothing is uploaded for it).
    The local part holds the reason and the spans. `link` replaces the three
    link values the receipt seals (judged event id, event hash, sequence)."""
    hexid = f"{n:032x}"
    verdict_id = f"jv_{hexid}"
    unavailable = reason_code == vp.JUDGMENT_VERDICT_NO_PACK_VERSION_REASON
    source = "none" if unavailable else "judge"
    uploaded = {
        "schema": "judgment_verdict.v1", "verdict_id": verdict_id, "judged_event_id": upload_id,
        "rule_id": rule_id, "judgment": judgment,
        "pack": {"version": None if unavailable else 3, "sha256": PACK_SHA256},
        "verdict": verdict, "source": source, "reason_code": reason_code, "enforceable": True,
        "questions": questions, "execution": "gateway", "backend": None if unavailable else BACKEND,
        "timing": "after_delivery", "rollout_stage": "shadow", "action_taken": "allow",
        "latency_ms": 0 if unavailable else 180 + n, "evaluated_at": ts[:19] + "Z",
    }
    local = {"schema": vp.JUDGMENT_VERDICT_LOCAL_SCHEMA, "reason_text": reason_text,
             "reason_text_withheld": False, "spans": spans, "floor_unavailable": False}
    uploaded_json = vp.jcs_dumps(uploaded)
    judged_id, judged_hash, judged_seq = link or (judged["event_id"], judged["event_hash"],
                                                  judged["sequence_number"])
    uuid = f"{hexid[:8]}-{hexid[8:12]}-{hexid[12:16]}-{hexid[16:20]}-{hexid[20:]}"
    return {
        "schema_version": "v1.21", "event_kind": "judgment_verdict", "timestamp_utc": ts,
        "event_id": uuid, "request_id": uuid, "model_requested": "", "action": "allow",
        "input_tokens": 0, "output_tokens": 0, "estimated_cost_usd": None,
        "judgment_verdict": {
            "verdict_id": verdict_id, "judged_event_id": judged_id, "judged_upload_event_id": upload_id,
            "judged_event_hash": judged_hash, "judged_sequence_number": judged_seq,
            "rule_id": rule_id, "judgment": judgment, "pack_sha256": PACK_SHA256, "verdict": verdict,
            "source": source, "reason_code": reason_code, "enforceable": True,
            "uploaded_sha256": vp.judgment_verdict_uploaded_sha256(uploaded_json),
            "local_sha256": vp.sha256_jcs(local), "uploaded_json": uploaded_json,
        },
        "raw_response": local,
    }


def verdict_chain(relinked=False):
    """Two requests and three receipts: a FLAG on the first request (its
    record uploaded under another id), then a PASS and a pack_unavailable
    verdict of two rules on the second (its record not uploaded). With
    `relinked`, the first receipt is sealed naming the first request's
    sequence with another record's event id and a hash no record has."""
    genesis = vp.genesis_hash()
    records, prev = [], genesis

    def seal(event):
        nonlocal prev
        event["sequence_number"] = len(records)
        event["previous_hash"] = prev
        event["event_hash"] = vp.recompute_event_hash(event, event["sequence_number"], prev)
        prev = event["event_hash"]
        records.append(event)
        return event

    def request(ts, n):
        return {
            "schema_version": "v1.1", "timestamp_utc": ts,
            "event_id": f"00000000-0000-4000-8000-0000000f00{n:02d}",
            "request_id": f"00000000-0000-4000-8000-0000000f10{n:02d}",
            "model_requested": "gpt-4.1-mini", "model_executed": "gpt-4.1-mini-2025-04-14",
            "provider": "openai", "action": "allow", "input_tokens": 12, "output_tokens": 30,
            "total_tokens": 42, "estimated_cost_usd": 5.4e-05, "policy_version": "0" * 64,
            "findings": [], "messages": [{"role": "user", "content": "Synthetic request."}],
            "response_text": "Synthetic response.",
        }

    def question(qid, outcome, p, p_pass):
        return {"id": qid, "clause_sha256": CLAUSE_SHA256, "outcome": outcome, "p": p, "p_pass": p_pass,
                "flag_at": 0.8, "pass_at": 0.1}

    first = seal(request("2026-11-03T09:00:00.000000000Z", 0))
    # Relinked: sequence 0, named with the second request's event id and a
    # hash no record of the chain has.
    second_link = ("00000000-0000-4000-8000-0000000f0002", "9" * 64, 0) if relinked else None
    seal(verdict_receipt(
        1, "2026-11-03T09:00:01.000000000Z", first, "3f9a1c0b7e2d4a65", "judgment.scope-boundary",
        "scope-boundary@2", "FLAG", "clause_violated", [question("Q-SCOPE-1-a", "FLAG", 0.93, 0.05)],
        "Q-SCOPE-1-a: synthetic reason.", [{"input": "reply", "start": 0, "end": 19}], link=second_link))
    second = seal(request("2026-11-03T09:01:00.000000000Z", 2))
    seal(verdict_receipt(
        3, "2026-11-03T09:01:01.000000000Z", second, second["event_id"], "judgment.scope-boundary",
        "scope-boundary@2", "PASS", "ok", [question("Q-SCOPE-1-a", "PASS", 0.04, 0.95)],
        "Q-SCOPE-1-a: synthetic reason.", []))
    seal(verdict_receipt(
        4, "2026-11-03T09:01:01.500000000Z", second, second["event_id"], "judgment.disclosure",
        "disclosure@1", "INDETERMINATE", vp.JUDGMENT_VERDICT_NO_PACK_VERSION_REASON, [], None, []))
    return genesis, records


def verdict_cases(root):
    genesis, records = verdict_chain()
    head = records[-1]["sequence_number"]
    base = unanchored_base(genesis, records, "00000000-0000-4000-8000-0000000f0f00", "2026-11-03T10:00:00Z")
    receipts = {r["sequence_number"]: r["judgment_verdict"]["verdict_id"]
                for r in records if r.get("event_kind") == "judgment_verdict"}

    out = root / "judgment-verdicts"
    write_records(out, records)
    write_case(out, local_manifest(base, head), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 0, "contains": [
            "CLAIM: the whole chain proxy from seq=0 up to its head at seq=4",
            "AUTHENTICITY NOT ESTABLISHED"],
         "absent": ["FAIL"]},
        {"args": [], "exit": 3, "contains": ["AUTHENTICITY NOT ESTABLISHED"], "absent": ["FAIL"]},
    ]})

    # The same records, edited after sealing in the two parts of a receipt
    # that sit beside its hash: the first receipt's uploaded form turned from
    # FLAG to PASS, and the second receipt's reason text. No hash changes.
    edited = [json.loads(json.dumps(r)) for r in records]
    form = edited[1]["judgment_verdict"]
    form["uploaded_json"] = form["uploaded_json"].replace('"verdict":"FLAG"', '"verdict":"PASS"')
    edited[3]["raw_response"]["reason_text"] = "Another reason."
    out = root / "judgment-verdicts-edited"
    write_records(out, edited)
    write_case(out, local_manifest(base, head), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 1, "contains": [
            f"FAIL seq=1: verdict receipt {receipts[1]}: the stored uploaded form hashes to",
            f"FAIL seq=1: verdict receipt {receipts[1]}: the sealed `verdict` is not the `verdict` of the "
            "stored uploaded form",
            f"FAIL seq=3: verdict receipt {receipts[3]}: the stored local part hashes to"]},
    ]})

    # A chain whose first receipt was sealed naming sequence 0 with another
    # record's event id and a hash no record has. Every hash recomputes; the
    # link does not.
    genesis, relinked = verdict_chain(relinked=True)
    base = unanchored_base(genesis, relinked, "00000000-0000-4000-8000-0000000f0f01", "2026-11-03T10:00:00Z")
    out = root / "judgment-verdicts-relinked"
    write_records(out, relinked)
    write_case(out, local_manifest(base, head), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 1, "contains": [
            f"FAIL seq=1: verdict receipt {receipts[1]}: does not link to the pack's record at sequence 0: "
            "that record has another event id or event hash"]},
    ]})


RULE_SHA256 = "4" * 64
GRANT_ID = "rig_01JFIXTURE0000000000000001"


def verdict_v2_receipt(n, ts, judged, rule_id, judgment, verdict, reason_code, questions, reason_text, spans,
                       stage, input_form, snapshot, backend=BACKEND, floor_triggers=(), form_edit=None):
    """One v1.22 judgment.verdict record judging the record `judged`.

    The uploaded form is judgment_verdict.v2: the v1 form plus the rule
    digest, the stage, the input form, the snapshot and, on a raw judgment
    a backend answered, the grant that covered the backend. The local part is
    judgment_verdict_local.v2: the v1 part plus the digest of the judged input
    block (null when no backend was sent one) and the trigger-floor ids.
    `form_edit(uploaded, local)` changes the two forms before the receipt is
    sealed, as a gateway that broke the rules would."""
    hexid = f"{n:032x}"
    verdict_id = f"jv_{hexid}"
    source = "judge" if backend is not None else "none"
    uploaded = {
        "schema": vp.JUDGMENT_VERDICT_UPLOADED_SCHEMA_V2, "verdict_id": verdict_id,
        "judged_event_id": judged["event_id"], "rule_id": rule_id, "rule_sha256": RULE_SHA256,
        "judgment": judgment, "pack": {"version": 3, "sha256": PACK_SHA256},
        "verdict": verdict, "source": source, "reason_code": reason_code, "enforceable": True,
        "questions": questions, "execution": "gateway", "pool_verdict_id": None,
        "backend": backend,
        "timing": "after_delivery", "rollout_stage": "shadow", "action_taken": "allow",
        "stage": stage, "input_form": input_form, "snapshot": snapshot,
        "latency_ms": 0 if backend is None else 180 + n, "evaluated_at": ts[:19] + "Z",
    }
    if input_form == "raw" and backend is not None:
        uploaded["raw_input_grant"] = GRANT_ID
    local = {"schema": vp.JUDGMENT_VERDICT_LOCAL_SCHEMA_V2, "reason_text": reason_text,
             "reason_text_withheld": False, "spans": spans, "floor_unavailable": False,
             "judged_input_sha256": None if backend is None else f"{n:x}" * 64,
             "floor_triggers": [dict(t) for t in floor_triggers]}
    if form_edit is not None:
        form_edit(uploaded, local)
    uploaded_json = vp.jcs_dumps(uploaded)
    uuid = f"{hexid[:8]}-{hexid[8:12]}-{hexid[12:16]}-{hexid[16:20]}-{hexid[20:]}"
    return {
        "schema_version": "v1.22", "event_kind": "judgment_verdict", "timestamp_utc": ts,
        "event_id": uuid, "request_id": uuid, "model_requested": "", "action": "allow",
        "input_tokens": 0, "output_tokens": 0, "estimated_cost_usd": None,
        "judgment_verdict": {
            "verdict_id": verdict_id, "judged_event_id": judged["event_id"],
            "judged_upload_event_id": judged["event_id"], "judged_event_hash": judged["event_hash"],
            "judged_sequence_number": judged["sequence_number"], "rule_id": rule_id, "judgment": judgment,
            "pack_sha256": PACK_SHA256, "verdict": uploaded["verdict"], "source": uploaded["source"],
            "reason_code": uploaded["reason_code"], "enforceable": True,
            "uploaded_sha256": vp.judgment_verdict_uploaded_sha256(uploaded_json),
            "local_sha256": vp.sha256_jcs(local), "uploaded_json": uploaded_json,
        },
        "raw_response": local,
    }


def verdict_v2_chain(malformed=False):
    """A model request (0), a raw-input FLAG on its candidate reply (1), a
    redacted PASS on its forwarded request (2), an MCP tool call (3), a PASS
    on the call's arguments (4) and a raw_input_not_permitted verdict on the
    request's partial reply (5). With `malformed`, receipts 1, 2, 4 and 5 are
    sealed breaking one v1.22 rule each: 1 names no grant, 2 carries an
    unknown key, 4 judges the model request with a tool snapshot, 5 holds a
    floor trigger with text. Each receipt names the stage it ran at: the
    post-response stage for 1 and 5, pre-request for 2, tool call for 4."""
    genesis = vp.genesis_hash()
    records, prev = [], genesis

    def seal(event):
        nonlocal prev
        event["sequence_number"] = len(records)
        event["previous_hash"] = prev
        event["event_hash"] = vp.recompute_event_hash(event, event["sequence_number"], prev)
        prev = event["event_hash"]
        records.append(event)
        return event

    def question(qid, outcome, p, p_pass):
        return {"id": qid, "clause_sha256": CLAUSE_SHA256, "outcome": outcome, "p": p, "p_pass": p_pass,
                "flag_at": 0.8, "pass_at": 0.1}

    def edit(fn):
        return fn if malformed else None

    def drop_grant(uploaded, local):
        del uploaded["raw_input_grant"]

    def unknown_key(uploaded, local):
        uploaded["input_text"] = "Synthetic request."

    def trigger_text(uploaded, local):
        local["floor_triggers"][0]["matched"] = "synthetic term"

    trigger = {"rule_id": "floor.scope-terms", "term_id": "scope-term-2", "language": "en"}
    request = seal({
        "schema_version": "v1.1", "timestamp_utc": "2026-11-04T09:00:00.000000000Z",
        "event_id": "00000000-0000-4000-8000-0000000f2000",
        "request_id": "00000000-0000-4000-8000-0000000f2100",
        "model_requested": "gpt-4.1-mini", "model_executed": "gpt-4.1-mini-2025-04-14",
        "provider": "openai", "action": "allow", "input_tokens": 12, "output_tokens": 30,
        "total_tokens": 42, "estimated_cost_usd": 5.4e-05, "policy_version": "0" * 64,
        "findings": [], "messages": [{"role": "user", "content": "Synthetic request."}],
        "response_text": "Synthetic response.",
    })
    seal(verdict_v2_receipt(
        1, "2026-11-04T09:00:01.000000000Z", request, "judgment.scope-boundary", "scope-boundary@2", "FLAG",
        "clause_violated", [question("Q-SCOPE-1-a", "FLAG", 0.93, 0.05)], "Q-SCOPE-1-a: synthetic reason.",
        [{"input": "reply", "start": 0, "end": 19}], "post_response", "raw", "candidate_reply",
        floor_triggers=[trigger],
        form_edit=edit(drop_grant)))
    seal(verdict_v2_receipt(
        2, "2026-11-04T09:00:01.500000000Z", request, "judgment.disclosure", "disclosure@1", "PASS", "ok",
        [question("Q-DISC-1", "PASS", 0.02, 0.97)], "Q-DISC-1: synthetic reason.", [], "pre_request",
        "redacted", "forwarded_request", form_edit=edit(unknown_key)))
    tool_call = seal({
        "schema_version": "v1.4", "event_kind": "mcp_tool_call", "timestamp_utc": "2026-11-04T09:01:00.000000000Z",
        "event_id": "00000000-0000-4000-8000-0000000f2003",
        "request_id": "00000000-0000-4000-8000-0000000f2103",
        "model_requested": "", "action": "allow", "input_tokens": 0, "output_tokens": 0,
        "estimated_cost_usd": None, "findings": [], "messages": [], "response_text": None,
        "mcp_event": {
            "virtual_server": "research", "upstream_slug": "market-data", "method": "tools/call",
            "tool_name": "market-data__get_positions", "jsonrpc_id": "7", "protocol_version": "2026-07-28",
            "decision": None, "reason": None,
            "payload_sha256_jcs": vp.sha256_jcs({"name": "market-data__get_positions",
                                                 "arguments": {"portfolio": "model"}}),
            "mcp_bundle_sha256": "a" * 64, "correlated_event_id": None, "error_code": None,
            "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        },
    })
    seal(verdict_v2_receipt(
        4, "2026-11-04T09:01:00.500000000Z", request if malformed else tool_call, "judgment.tool-scope",
        "tool-scope@1", "PASS", "ok", [question("Q-TOOL-1", "PASS", 0.03, 0.96)], "Q-TOOL-1: synthetic reason.",
        [], "tool_call", "redacted", "tool_arguments"))
    seal(verdict_v2_receipt(
        5, "2026-11-04T09:01:02.000000000Z", request, "judgment.scope-boundary", "scope-boundary@2",
        "INDETERMINATE", vp.JUDGMENT_VERDICT_RAW_INPUT_NOT_PERMITTED, [], None, [], "post_response", "raw",
        "candidate_reply_partial", backend=None, floor_triggers=[trigger], form_edit=edit(trigger_text)))
    return genesis, records


def verdict_v2_cases(root):
    genesis, records = verdict_v2_chain()
    head = records[-1]["sequence_number"]
    base = unanchored_base(genesis, records, "00000000-0000-4000-8000-0000000f2f00", "2026-11-04T10:00:00Z")
    receipts = {r["sequence_number"]: r["judgment_verdict"]["verdict_id"]
                for r in records if r.get("event_kind") == "judgment_verdict"}

    out = root / "judgment-verdicts-v2"
    write_records(out, records)
    write_case(out, local_manifest(base, head), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 0, "contains": [
            "CLAIM: the whole chain proxy from seq=0 up to its head at seq=5",
            "AUTHENTICITY NOT ESTABLISHED"],
         "absent": ["FAIL"]},
        {"args": [], "exit": 3, "contains": ["AUTHENTICITY NOT ESTABLISHED"], "absent": ["FAIL"]},
    ]})

    # The same chain sealed by a gateway that broke the v1.22 rules. Every
    # hash and every stored digest recomputes; the closed checks do not pass.
    genesis, malformed = verdict_v2_chain(malformed=True)
    base_m = unanchored_base(genesis, malformed, "00000000-0000-4000-8000-0000000f2f01", "2026-11-04T10:00:00Z")
    form = "the stored uploaded form is not a judgment_verdict.v2 form"
    out = root / "judgment-verdicts-v2-malformed"
    write_records(out, malformed)
    write_case(out, local_manifest(base_m, head), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 1, "contains": [
            f"FAIL seq=1: verdict receipt {receipts[1]}: {form}: `raw_input_grant` is not present exactly "
            "when the input form is raw and a backend answered",
            f"FAIL seq=2: verdict receipt {receipts[2]}: {form}: the form carries the unknown key(s) input_text",
            f"FAIL seq=4: verdict receipt {receipts[4]}: its snapshot `tool_arguments` judges a record of kind "
            "mcp.tool_call, but the pack's record at sequence 0 has kind llm_request",
            f"FAIL seq=4: verdict receipt {receipts[4]}: its stage `tool_call` judges a record of kind "
            "mcp.tool_call, but the pack's record at sequence 0 has kind llm_request",
            f"FAIL seq=5: verdict receipt {receipts[5]}: the stored local part is not a "
            "judgment_verdict_local.v2 object: `floor_triggers[0]` carries the unknown key(s) matched"]},
    ]})

    # The clean chain with the first receipt's stamp edited to v1.21 after
    # sealing. The stamp is outside the hash, so every hash recomputes; the
    # stored v2 forms say the record is v1.22.
    relabelled = [json.loads(json.dumps(r)) for r in records]
    relabelled[1]["schema_version"] = "v1.21"
    out = root / "judgment-verdicts-v2-relabelled"
    write_records(out, relabelled)
    write_case(out, local_manifest(base, head), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 1, "contains": [
            f"FAIL seq=1: verdict receipt {receipts[1]}: a v1.21 record stores a judgment_verdict.v2 form, "
            "which only a v1.22 record carries"]},
    ]})


# Synthetic probe set digests and bundle digest: the verifier checks a run
# against its own stored parts, not against a delivered set or bundle.
PROBE_SETS = [
    {"set_id": "phi-detection", "version": 1, "sha256": "c" * 64},
    {"set_id": "secrets-detection", "version": 1, "sha256": "d" * 64},
]


def probe_result(set_id, case_id, action, expected, detected, decision, outcome, shadow):
    return {"set_id": set_id, "case_id": case_id, "rule_instance": set_id, "configured_action": action,
            "expected_detected": expected, "actual_detected": detected, "actual_decision": decision,
            "outcome": outcome, "shadow": shadow}


def probe_run_record(n, run_id, started, finished, results, evidence_mode, counts=None):
    """One v1.23 control_probe.run record with its stored set references and
    case results. `counts` overrides the counts the hash binds (passed,
    failed, not_applicable), for a run that misstates them."""
    sets_json = vp.jcs_dumps(sorted(PROBE_SETS, key=lambda x: (x["set_id"], x["version"], x["sha256"])))
    ordered = sorted(results, key=lambda r: (r["set_id"], r["case_id"], r["rule_instance"]))
    results_json = vp.jcs_dumps(ordered)
    if counts is None:
        counts = tuple(sum(1 for r in results if r["outcome"] == o) for o in vp.CONTROL_PROBE_OUTCOMES)
    return {
        "schema_version": "v1.23", "event_kind": "control_probe_run", "timestamp_utc": finished,
        "event_id": f"00000000-0000-4000-8000-0000000f30{n:02d}",
        "request_id": f"00000000-0000-4000-8000-0000000f31{n:02d}",
        "model_requested": "", "action": "allow", "input_tokens": 0, "output_tokens": 0,
        "estimated_cost_usd": None, "findings": [], "messages": [], "response_text": None,
        "control_probe_run": {
            "run_id": run_id, "started_at": started, "finished_at": finished,
            "bundle_sha256": "e" * 64, "policy_version": "v3", "evidence_mode": evidence_mode,
            "shadow_mode": any(r["shadow"] for r in results),
            "sets_sha256": vp.hashlib.sha256(sets_json.encode("utf-8")).hexdigest(),
            "passed": counts[0], "failed": counts[1], "not_applicable": counts[2],
            "results_sha256": vp.hashlib.sha256(results_json.encode("utf-8")).hexdigest(),
            "sets_json": sets_json, "results_json": results_json,
        },
    }


SHADOW_RUN = "6c1d9f4a-3e2b-4d66-8b88-1a2b3c4d5e01"
ENFORCING_RUN = "6c1d9f4a-3e2b-4d66-8b88-1a2b3c4d5e02"


def probe_chain(miscounted=False):
    """A run in shadow mode on a local_chain gateway that passed every case
    (0) and an enforcing run on the same gateway with one failed case and one
    case that did not apply (1). With `miscounted`, run 1 is sealed with
    counts that say every case passed."""
    genesis = vp.genesis_hash()
    records, prev = [], genesis
    shadow = [
        probe_result("phi-detection", "mrn-in-user-turn", "redact", True, True, "redact", "pass", True),
        probe_result("phi-detection", "benign-scheduling", "redact", False, False, "allow", "pass", True),
        probe_result("secrets-detection", "cloud-key-in-tool-args", "block", True, True, "block", "pass", True),
    ]
    enforcing = [
        probe_result("phi-detection", "mrn-in-user-turn", "redact", True, True, "redact", "pass", False),
        probe_result("phi-detection", "dob-and-name", "redact", True, False, "allow", "fail", False),
        probe_result("secrets-detection", "cloud-key-in-tool-args", "block", True, False, "allow",
                     "not_applicable", False),
    ]
    runs = [
        probe_run_record(0, SHADOW_RUN, "2026-11-21T10:00:00Z", "2026-11-21T10:00:01Z", shadow, "local_chain"),
        probe_run_record(1, ENFORCING_RUN, "2026-11-22T10:00:00Z", "2026-11-22T10:00:01Z", enforcing,
                         "local_chain", counts=(3, 0, 0) if miscounted else None),
    ]
    for event in runs:
        event["sequence_number"] = len(records)
        event["previous_hash"] = prev
        event["event_hash"] = vp.recompute_event_hash(event, event["sequence_number"], prev)
        prev = event["event_hash"]
        records.append(event)
    return genesis, records


def probe_cases(root):
    genesis, records = probe_chain()
    head = records[-1]["sequence_number"]
    base = unanchored_base(genesis, records, "00000000-0000-4000-8000-0000000f3f00", "2026-11-22T11:00:00Z")

    out = root / "control-probe-runs"
    write_records(out, records)
    write_case(out, local_manifest(base, head), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 0, "contains": [
            f"CLAIM: the whole chain proxy from seq=0 up to its head at seq={head}",
            "AUTHENTICITY NOT ESTABLISHED"],
         "absent": ["FAIL", "NOTE seq="]},
        {"args": [], "exit": 3, "contains": ["AUTHENTICITY NOT ESTABLISHED"], "absent": ["FAIL"]},
    ]})

    # The failed case's result edited to pass after sealing. The record's
    # hash still recomputes (the stored results ride beside it); the stored
    # results no longer hash to the results_sha256 it binds.
    edited = [json.loads(json.dumps(r)) for r in records]
    fields = edited[1]["control_probe_run"]
    fields["results_json"] = fields["results_json"].replace('"fail"', '"pass"', 1)
    out = root / "control-probe-runs-edited"
    write_records(out, edited)
    write_case(out, local_manifest(base, head), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 1, "contains": [
            f"FAIL seq=1: probe run {ENFORCING_RUN}: the stored case results do not hash to results_sha256"],
         "absent": ["FAIL seq=0"]},
    ]})

    # A gateway that sealed a run whose counts say every case passed. Every
    # hash and stored digest recomputes; the counts are not its results'.
    genesis, miscounted = probe_chain(miscounted=True)
    base_m = unanchored_base(genesis, miscounted, "00000000-0000-4000-8000-0000000f3f01", "2026-11-22T11:00:00Z")
    out = root / "control-probe-runs-miscounted"
    write_records(out, miscounted)
    write_case(out, local_manifest(base_m, head), {"runs": [
        {"args": ["--allow-unsigned"], "exit": 1, "contains": [
            f"FAIL seq=1: probe run {ENFORCING_RUN}: passed, failed and not_applicable are not the counts "
            "of its results"],
         "absent": ["FAIL seq=0"]},
    ]})


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "local-chain"
    if root.exists():
        shutil.rmtree(root)
    anchored_cases(root)
    mode_cases(root)
    verdict_cases(root)
    verdict_v2_cases(root)
    probe_cases(root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
