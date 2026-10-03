#!/usr/bin/env python3
"""Generate the fixture chains in this directory from the verifier's own hash
functions, so the shipped samples are provably the format the verifier checks.

    python3 fixtures/generate.py            # rewrites the fixtures in place
    python3 fixtures/generate.py --out DIR  # writes the same layout under DIR

Layout (under fixtures/, or under DIR with --out):

    records/<seq>.bin, manifest.json                  the request chain
    coverage/records/<seq>.bin, coverage/manifest.json the coverage chain

Both chains are synthetic: fixed timestamps and ids, no real prompt content.

The request chain is what a proxy writes for model calls and MCP tool calls.
Record 0 is the proxy's own start-up marker (an admin action, as on a real
chain), record 1 an allowed LLM request, record 2 a blocked one. Records 3 to 5
carry a sealed caller identity (v1.12): an agent's model call under a `full`
capture policy, the same agent's MCP tool call on behalf of a verified user,
and a project-key call with no capture policy.

The coverage chain is the separate per-tenant chain the proxy writes for
shadow-AI coverage: a v1.8 reconciliation and a v1.13 provider-key inventory.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify_pack", HERE.parent / "verify-pack.py")
vp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vp)

POLICY_VERSION = "0000000000000000000000000000000000000000000000000000000000000000"
AGENT_ID = "agt_01J9ZK3Q7R8S9T0V1W2X3Y4Z5A"


def sealer():
    genesis = vp.genesis_hash()
    records = []
    prev = genesis

    def seal(event):
        nonlocal prev
        event["previous_hash"] = prev
        event["event_hash"] = vp.recompute_event_hash(event, event["sequence_number"], prev)
        prev = event["event_hash"]
        records.append(event)

    return genesis, records, seal


def present(d):
    """The proxy omits an absent optional field rather than writing null."""
    return {k: v for k, v in d.items() if v is not None}


def identity(tier, credential_kind, credential_kid, asserted, agent_id=None, delegated_human=None):
    """The sealed identity block as a v1.12 record stores it: the six hashed
    fields, plus the asserted labels stored beside their digest."""
    asserted = present(asserted)
    return present({
        "agent_id": agent_id,
        "tier": tier,
        "credential_kind": credential_kind,
        "credential_kid": credential_kid,
        "delegated_human": delegated_human,
        "asserted_digest": vp.asserted_claims_digest(asserted),
        "asserted": asserted,
    })


def build_chain():
    genesis, records, seal = sealer()

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
        "policy_version": POLICY_VERSION,
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
        "policy_version": POLICY_VERSION,
        "findings": [{
            "validator": "pii-detection", "severity": "medium",
            "message": "Potential ssn detected — [PII:ssn] (11 chars)",
            "code": "pii-ssn", "category": "pii", "locus": "user",
        }],
        "messages": [{"role": "user", "content": "Her SSN is 000-00-0000; summarize what I should verify."}],
        "response_text": None,
    })

    # v1.12: an agent (T1, its own agent key) calls the model under a `full`
    # capture policy. The content digests are inside the hash; the prompt,
    # response and findings they cover are beside it (SPEC §4.4).
    agent_asserted = {
        "agent_name": "research-assistant",
        "client_info": {"name": "research-assistant", "version": "1.4.0"},
        "user_agent_family": {"family": "openai-python", "major": 1},
        "on_behalf_of": None,
    }
    messages = [{"role": "user", "content": "List the three largest positions in the model portfolio."}]
    response = "The three largest positions are the broad-market index fund, the short-term treasury fund and the investment-grade bond fund."
    response_digest = hashlib.sha256(response.encode("utf-8")).hexdigest()
    seal({
        "schema_version": "v1.12",
        "event_kind": "llm_request",
        "sequence_number": 3,
        "timestamp_utc": "2026-10-01T14:00:00.000000000Z",
        "event_id": "00000000-0000-4000-8000-000000000003",
        "request_id": "33333333-3333-4333-8333-333333333333",
        "model_requested": "gpt-4.1-mini",
        "model_executed": "gpt-4.1-mini-2025-04-14",
        "provider": "openai",
        "workflow": "research-assistant",
        "action": "allow",
        "input_tokens": 21, "output_tokens": 29, "total_tokens": 50,
        "estimated_cost_usd": 6.5e-05,
        "policy_version": POLICY_VERSION,
        "findings": [],
        "messages": messages,
        "response_text": response,
        "join_context": {"correlation_id": "corr-fixture-1", "session_id": "sess-fixture-1", "agent_name": "research-assistant"},
        "content": {
            "capture_policy": "full",
            "prompt_sha256_jcs": vp.sha256_jcs(messages),
            "response_sha256": response_digest,
            "stored_prompt_sha256_jcs": vp.sha256_jcs(messages),
            "stored_response_sha256": response_digest,
            "findings_sha256_jcs": vp.sha256_jcs([]),
        },
        "identity": identity("t1", "agent_key", "a7f3k2m9p4q8r1s6", agent_asserted, agent_id=AGENT_ID),
    })

    # v1.12: the same agent calls an MCP tool on behalf of a user whose token
    # the proxy verified (T2). The hashed `delegated_human` and the stored
    # `on_behalf_of_attestation` marker must agree.
    delegated_asserted = dict(agent_asserted, on_behalf_of="user-fixture")
    seal({
        "schema_version": "v1.12",
        "event_kind": "mcp_tool_call",
        "sequence_number": 4,
        "timestamp_utc": "2026-10-01T14:00:03.000000000Z",
        "event_id": "00000000-0000-4000-8000-000000000004",
        "request_id": "44444444-4444-4444-8444-444444444444",
        "model_requested": "",
        "action": "allow",
        "input_tokens": 0, "output_tokens": 0,
        "estimated_cost_usd": None,
        "findings": [], "messages": [], "response_text": None,
        "mcp_event": present({
            "virtual_server": "research",
            "upstream_slug": "market-data",
            "method": "tools/call",
            "tool_name": "market-data__get_positions",
            "jsonrpc_id": "7",
            "protocol_version": "2026-07-28",
            "decision": None,
            "reason": None,
            "payload_sha256_jcs": vp.sha256_jcs({"name": "market-data__get_positions", "arguments": {"portfolio": "model"}}),
            "mcp_bundle_sha256": "a" * 64,
            "correlated_event_id": None,
            "error_code": None,
            "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "principal_chain": {
                "authenticated": {"kind": "agent", "agent_ref": AGENT_ID},
                "on_behalf_of": {"kind": "human_user", "subject": "user-fixture", "issuer": "https://idp.example"},
                "on_behalf_of_attestation": "verified",
            },
            "redacted_payload_sha256_jcs": None,
            "redaction_pre_sha256_jcs": None,
            "redaction_post_sha256_jcs": None,
            "hold_id": None,
        }),
        "join_context": {"correlation_id": "corr-fixture-1", "session_id": "sess-fixture-1", "agent_name": "research-assistant"},
        "identity": identity(
            "t2", "agent_key", "a7f3k2m9p4q8r1s6", delegated_asserted, agent_id=AGENT_ID,
            delegated_human={"subject": "user-fixture", "issuer": "https://idp.example"},
        ),
    })

    # v1.12: an application calls with the project key (T3) and no capture
    # policy. The record has no content block (its presence tag is 0x00), so
    # its prompt and response are stored unhashed, as before v1.10.
    seal({
        "schema_version": "v1.12",
        "event_kind": "llm_request",
        "sequence_number": 5,
        "timestamp_utc": "2026-10-01T14:00:07.000000000Z",
        "event_id": "00000000-0000-4000-8000-000000000005",
        "request_id": "55555555-5555-4555-8555-555555555555",
        "model_requested": "gpt-4.1-mini",
        "model_executed": "gpt-4.1-mini-2025-04-14",
        "provider": "openai",
        "workflow": "advisor-copilot",
        "action": "allow",
        "input_tokens": 14, "output_tokens": 22, "total_tokens": 36,
        "estimated_cost_usd": 4.7e-05,
        "policy_version": POLICY_VERSION,
        "findings": [],
        "messages": [{"role": "user", "content": "Define tracking error in one sentence."}],
        "response_text": "Tracking error is the standard deviation of the difference between a portfolio's returns and its benchmark's returns.",
        "identity": identity(
            "t3", "project_key", "pk:0123456789abcdef",
            {"agent_name": None, "client_info": None, "user_agent_family": {"family": "openai-python", "major": 1}, "on_behalf_of": None},
        ),
    })
    return genesis, records


def build_coverage_chain():
    genesis, records, seal = sealer()

    seal({
        "schema_version": "v1.8",
        "event_kind": "coverage_computed",
        "sequence_number": 0,
        "timestamp_utc": "2026-10-01T01:00:00.000000000Z",
        "event_id": "00000000-0000-4000-8000-00000000c000",
        "request_id": "00000000-0000-4000-8000-00000000c000",
        "model_requested": "",
        "action": "allow",
        "input_tokens": 0, "output_tokens": 0,
        "estimated_cost_usd": None,
        "findings": [], "messages": [], "response_text": None,
        "coverage": {
            "provider": "openai",
            "day": "2026-09-30",
            "tier": "A",
            "reconciliation_unit": "requests",
            "proxy_attributed": 40,
            "provider_reported": 52,
            "delta_classification": "bypass_signal",
            "bypass_rate_ppm": 230769,
            "tolerance_band_json": "{\"relative\":0.02,\"unit\":\"requests\"}",
            "claim_language_key": "coverage.tier_a.org_administered_accounts",
            "registry_version": "2026.10.01-1",
            "numerator_source": "instance_sqlite",
            "denominator_fetched_at": "2026-10-01T01:00:00Z",
        },
    })
    # v1.13: the provider-key inventory for the same day. `keys_json` is
    # hashed verbatim, so every listed key and its usage is covered.
    keys = [
        {"key_id": "key_gov", "key_suffix": "abcd", "key_name": "proxy-routing",
         "external_scope_id": "proj_1", "owner_type": "service_account", "owner_id": "svc_1",
         "key_created_at": "2026-09-01T00:00:00Z", "key_last_used_at": None, "listed": True,
         "governed": True, "requests": 40, "input_tokens": 4000, "output_tokens": 900},
        {"key_id": "key_shadow", "key_suffix": "wxyz", "key_name": "laptop",
         "external_scope_id": "proj_1", "owner_type": "user", "owner_id": "user_9",
         "key_created_at": "2026-09-20T00:00:00Z", "key_last_used_at": None, "listed": True,
         "governed": False, "requests": 12, "input_tokens": 1200, "output_tokens": 300},
    ]
    seal({
        "schema_version": "v1.13",
        "event_kind": "coverage_key_inventory",
        "sequence_number": 1,
        "timestamp_utc": "2026-10-01T01:00:01.000000000Z",
        "event_id": "00000000-0000-4000-8000-00000000c001",
        "request_id": "00000000-0000-4000-8000-00000000c001",
        "model_requested": "",
        "action": "allow",
        "input_tokens": 0, "output_tokens": 0,
        "estimated_cost_usd": None,
        "findings": [], "messages": [], "response_text": None,
        "coverage_key_inventory": {
            "provider": "openai",
            "day": "2026-09-30",
            "attribution_unit": "requests",
            "claim_language_key": "coverage.tier_a.org_administered_accounts",
            "registry_version": "2026.10.01-1",
            "proxy_key_count": 1,
            "unresolved_proxy_key_count": 0,
            "governed_key_count": 1,
            "ungoverned_key_count": 1,
            "listing_fetched_at": "2026-10-01T01:00:00Z",
            "keys_json": json.dumps(keys, separators=(",", ":")),
        },
    })
    return genesis, records


def manifest_for(genesis, records, pack_id, prefix):
    return {
        "schema_version": "1.0",
        "pack_id": pack_id,
        "window": "A",
        "signing_deferred": True,
        "generated_at": "2026-10-01T15:00:00Z",
        "generator_version": "fixture",
        "substrate_name": "fixture",
        "bucket": "fixture",
        "prefix": prefix,
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


def write_chain(base, genesis, records, pack_id, prefix):
    out = base / "records"
    out.mkdir(parents=True, exist_ok=True)
    for r in records:
        (out / vp.record_file_name(r["sequence_number"])).write_bytes(json.dumps(r, indent=1).encode("utf-8"))
    manifest = manifest_for(genesis, records, pack_id, prefix)
    (base / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(records)} records to {out} and {base / 'manifest.json'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="directory to write the fixture layout under (default: this directory)")
    args = ap.parse_args()
    base = Path(args.out) if args.out else HERE
    write_chain(base, *build_chain(), "00000000-0000-4000-8000-00000000f1f0", "audit/fixture/")
    write_chain(base / "coverage", *build_coverage_chain(), "00000000-0000-4000-8000-00000000f1f1", "coverage/fixture/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
