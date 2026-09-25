#!/usr/bin/env python3
"""Generate the fixture chain in this directory from the verifier's own hash
functions, so the shipped sample is provably the format the verifier checks.

    python3 fixtures/generate.py            # rewrites fixtures/records + manifest.json
    python3 fixtures/generate.py --out DIR  # writes DIR/*.bin and DIR.manifest.json

The chain is synthetic: three records with fixed timestamps and ids, no real
prompt content. Record 0 is the proxy's own start-up marker (an admin action,
as on a real chain), record 1 an allowed LLM request, record 2 a blocked one.
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify_pack", HERE.parent / "verify-pack.py")
vp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vp)


def build_chain():
    genesis = vp.genesis_hash()
    records = []
    prev = genesis

    def seal(event):
        nonlocal prev
        event["previous_hash"] = prev
        event["event_hash"] = vp.recompute_event_hash(event, event["sequence_number"], prev)
        prev = event["event_hash"]
        records.append(event)

    seal({
        "schema_version": "v1.3",
        "event_kind": "admin_action",
        "sequence_number": 0,
        "timestamp_utc": "2026-09-01T09:00:00.000000000Z",
        "event_id": "00000000-0000-4000-8000-000000000000",
        "request_id": "00000000-0000-4000-8000-000000000000",
        "model_requested": "",
        "action": "allow",
        "input_tokens": 0, "output_tokens": 0,
        "estimated_cost_usd": None,
        "findings": [], "messages": [], "response_text": None,
        "admin_action": {
            "action_type": "proxy_startup",
            "actor": "system:pid:1",
            "description": "Proxy server started",
            "metadata_json": "{\"proxy_version\":\"fixture\"}",
        },
    })
    seal({
        "schema_version": "v1.1",
        "sequence_number": 1,
        "timestamp_utc": "2026-09-01T09:00:05.000000000Z",
        "event_id": "00000000-0000-4000-8000-000000000001",
        "request_id": "11111111-1111-4111-8111-111111111111",
        "model_requested": "gpt-4.1-mini",
        "model_executed": "gpt-4.1-mini-2025-04-14",
        "provider": "openai",
        "workflow": "advisor-copilot",
        "action": "allow",
        "input_tokens": 19, "output_tokens": 46, "total_tokens": 65,
        "cached_input_tokens": 0, "reasoning_tokens": 0,
        "estimated_cost_usd": 8.1e-05,
        "policy_version": "0000000000000000000000000000000000000000000000000000000000000000",
        "findings": [],
        "messages": [{"role": "user", "content": "In two sentences, what is a rebalancing review?"}],
        "response_text": "A rebalancing review checks a portfolio's current allocation against its target and adjusts positions to bring it back in line.",
    })
    seal({
        "schema_version": "v1.1",
        "sequence_number": 2,
        "timestamp_utc": "2026-09-01T09:00:09.000000000Z",
        "event_id": "00000000-0000-4000-8000-000000000002",
        "request_id": "22222222-2222-4222-8222-222222222222",
        "model_requested": "gpt-4.1-mini",
        "model_executed": None,
        "provider": None,
        "workflow": "advisor-copilot",
        "action": "block",
        "policy_reason": "Blocked by rule 'PII detection'",
        "input_tokens": 38, "output_tokens": 0,
        "estimated_cost_usd": 1.5e-05,
        "policy_version": "0000000000000000000000000000000000000000000000000000000000000000",
        "findings": [{
            "validator": "pii-detection", "severity": "medium",
            "message": "Potential ssn detected — [PII:ssn] (11 chars)",
            "code": "pii-ssn", "category": "pii", "locus": "user",
        }],
        "messages": [{"role": "user", "content": "Her SSN is 000-00-0000; summarize what I should verify."}],
        "response_text": None,
    })
    return genesis, records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="records directory to write (manifest goes to <out>.manifest.json)")
    args = ap.parse_args()
    genesis, records = build_chain()
    out = Path(args.out) if args.out else HERE / "records"
    manifest_path = Path(str(out) + ".manifest.json") if args.out else HERE / "manifest.json"
    out.mkdir(parents=True, exist_ok=True)
    for r in records:
        (out / vp.record_file_name(r["sequence_number"])).write_bytes(json.dumps(r, indent=1).encode("utf-8"))
    manifest = {
        "schema_version": "1.0",
        "pack_id": "00000000-0000-4000-8000-00000000f1f0",
        "window": "A",
        "signing_deferred": True,
        "generated_at": "2026-09-01T09:01:00Z",
        "generator_version": "fixture",
        "substrate_name": "fixture",
        "bucket": "fixture",
        "prefix": "audit/fixture/",
        "from_sequence": 0,
        "to_sequence": records[-1]["sequence_number"],
        "hash_algorithm": "sha256",
        "hash_version": "v1",
        "genesis_hash": genesis,
        "verified": True,
        "records_checked": len(records),
        "first_sequence": 0,
        "last_sequence": records[-1]["sequence_number"],
        "break_at_sequence": None,
        "violation_kind": None,
        "error": None,
        "events": [{
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
        } for r in records],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(records)} records to {out} and {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
