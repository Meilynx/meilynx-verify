#!/usr/bin/env python3
"""
Meilynx Integrity Pack — Window A reproducer script (MEI-422).

Independently re-fetches each audit event from GCS and recomputes its
SHA-256 chain hash using the same 15-field encoding as the Rust substrate
(meilynx-proxy/crates/meilynx-audit/src/sqlite.rs::compute_event_hash).

This file is the canonical source. It is embedded in generated .zip bundles
via include_str! in meilynx-integrity-pack/src/lib.rs, and copied verbatim
to meilynx-platform/tools/audit/verify-pack.py. Both copies must be
byte-identical; a drift-catcher test in the crate's test suite enforces this.

Usage (online — re-fetch each record from the WORM bucket):
    python verify-pack.py \\
        --bucket <audit-bucket-name> \\
        --manifest manifest.json

    # Or from inside a pack zip:
    unzip integrity-pack-*.zip
    python verify-pack.py \\
        --bucket <audit-bucket-name> \\
        --manifest manifest.json

    # Export the fetched records for a reviewer who has no bucket access:
    python verify-pack.py --bucket <audit-bucket-name> --manifest manifest.json \\
        --export-records ./records

Usage (offline — the records were handed to you with the manifest):
    python verify-pack.py --records ./records --manifest manifest.json

    `--records` takes a directory of `<seq:020d>.bin` files (the bucket's
    own layout) or a single `.jsonl` / `.json` file of records. Offline mode
    needs nothing beyond the Python standard library: no network, no Google
    client library, no credentials — the verdict is computed entirely from
    the bytes on your disk.

Prerequisites (online mode only):
    pip install google-cloud-storage
    gcloud auth application-default login

Exit code 0 = verified. Exit code 1 = chain break or hash mismatch.

The GCS bucket uses CMEK encryption; decryption is handled transparently
by GCS when you authenticate with credentials that have storage.objects.get.

Self-test (encoding drift check):
  Run `python verify-pack.py --self-test` to check the encoding against the
  substrate's reference values. Exercises both the +00:00 fixture and the
  Z-suffix normalization path. Should always pass; if it fails, the hash
  encoding has drifted from the Rust substrate.
"""

import argparse
import datetime
import hashlib
import json
import struct
import sys
from pathlib import Path

GENESIS_STRING = "meilynx-genesis-v1"
SUPPORTED_HASH_VERSIONS = {"v1"}

# ---------------------------------------------------------------------------
# Timestamp normalization
# ---------------------------------------------------------------------------

def normalize_timestamp(ts):
    """
    Normalize a UTC timestamp string to the canonical +00:00 form.

    Rust's chrono::DateTime<Utc> serializes to JSON with a 'Z' suffix
    (chrono serde default), but compute_event_hash receives the output of
    to_rfc3339() which produces '+00:00'. A reproducer reading from the GCS
    object body must apply this normalization before hashing.

    'Z' and '+00:00' are semantically equivalent RFC 3339 forms but produce
    different byte sequences — and therefore different SHA-256 hashes.
    """
    if ts.endswith('Z'):
        return ts[:-1] + '+00:00'
    return ts

# ---------------------------------------------------------------------------
# Hash computation — must match sqlite.rs::compute_event_hash exactly.
#
# hash_version v1 field encoding:
#   sequence_number              u64 little-endian (8 bytes)
#   timestamp_utc                UTF-8 bytes of normalize_timestamp() output
#   event_id                     UTF-8 bytes
#   request_id                   UTF-8 bytes
#   model_requested              UTF-8 bytes
#   action                       UTF-8 bytes ("Allow","Warn","Redact","MaskOutput","Block")
#   input_tokens                 u32 little-endian (4 bytes)
#   output_tokens                u32 little-endian (4 bytes)
#   total_tokens                 presence byte (0=None, 1=Some) + u64 LE if Some
#   cache_creation_input_tokens  presence byte + u64 LE if Some
#   cache_read_input_tokens      presence byte + u64 LE if Some
#   cached_input_tokens          presence byte + u64 LE if Some
#   reasoning_tokens             presence byte + u64 LE if Some
#   estimated_cost_usd           f64 LE of value (or 0.0 if None) — NO presence byte
#   previous_hash                UTF-8 bytes
# ---------------------------------------------------------------------------

def encode_optional_u64(v):
    """Presence byte (0=None, 1=Some) + u64 little-endian if Some."""
    if v is None:
        return b'\x00'
    return b'\x01' + struct.pack('<Q', int(v))


def compute_event_hash(
    sequence_number,
    timestamp_utc,
    event_id,
    request_id,
    model_requested,
    action,
    input_tokens,
    output_tokens,
    total_tokens,
    cache_creation_input_tokens,
    cache_read_input_tokens,
    cached_input_tokens,
    reasoning_tokens,
    estimated_cost_usd,
    previous_hash,
):
    h = hashlib.sha256()
    h.update(struct.pack('<Q', sequence_number))
    h.update(timestamp_utc.encode('utf-8'))
    h.update(event_id.encode('utf-8'))
    h.update(request_id.encode('utf-8'))
    h.update(model_requested.encode('utf-8'))
    h.update(action.encode('utf-8'))
    h.update(struct.pack('<I', input_tokens))
    h.update(struct.pack('<I', output_tokens))
    h.update(encode_optional_u64(total_tokens))
    h.update(encode_optional_u64(cache_creation_input_tokens))
    h.update(encode_optional_u64(cache_read_input_tokens))
    h.update(encode_optional_u64(cached_input_tokens))
    h.update(encode_optional_u64(reasoning_tokens))
    cost = float(estimated_cost_usd) if estimated_cost_usd is not None else 0.0
    h.update(struct.pack('<d', cost))
    h.update(previous_hash.encode('utf-8'))
    return h.hexdigest()


def genesis_hash():
    return hashlib.sha256(GENESIS_STRING.encode('utf-8')).hexdigest()


# ---------------------------------------------------------------------------
# MEI-639 — v1.2 hash path (schema_version-versioned dispatch).
#
# MUST mirror compute_event_hash_v1_2_* in
# meilynx-proxy/crates/meilynx-audit/src/sqlite.rs exactly. Drift between
# the Rust and Python implementations is itself an integrity finding: if
# the SOC 2 examiner runs either verifier and they disagree on whether a
# v1.2 event is valid, the chain attestation is meaningless.
#
# As with v1: this code is INTENTIONALLY NOT shared with the v1 path
# (`compute_event_hash` above). The slight duplication of the prefix
# byte feed is correct duplication — the structural seam that
# guarantees a v1.2 change can never silently alter v1 output.
# Do not refactor to a shared helper.
# ---------------------------------------------------------------------------

# EventKind wire-names — must match `EventKind::wire_name()` in
# meilynx-core/src/types/audit.rs.
EVENT_KIND_LLM_REQUEST = 'llm_request'
EVENT_KIND_AUTH_SESSION_STARTED = 'auth.session_started'
# MEI-1048 — admin.action wire-name (the hash-preimage form). The exported
# WORM JSON carries event_kind in its serde snake_case form ('admin_action',
# 'auth_session_started') or omits it for the default LlmRequest; the hash
# preimage feeds EventKind::wire_name() ('admin.action', 'auth.session_started').
# recompute_event_hash maps the JSON form to the wire name before dispatch.
EVENT_KIND_ADMIN_ACTION = 'admin.action'
# MEI-925 — the five v1.4 MCP gateway kinds (hash-preimage wire names).
EVENT_KIND_MCP_TOOL_CALL = 'mcp.tool_call'
EVENT_KIND_MCP_POLICY_DECISION = 'mcp.policy_decision'
EVENT_KIND_MCP_TOOL_RESULT = 'mcp.tool_result'
EVENT_KIND_MCP_TOOLS_LIST_SERVED = 'mcp.tools_list.served'
EVENT_KIND_MCP_ERROR = 'mcp.error'
# MEI-1064 — the catalog-drift adjudication kind; shares the MCP payload +
# v1.4/v1.5 hash path (the wire-name in the preimage disambiguates it).
EVENT_KIND_MCP_CATALOG_DRIFT = 'mcp.catalog_drift'
# MEI-1955 (ADR-0052) — the coverage-reconciliation kind (v1.8 bucket).
EVENT_KIND_COVERAGE_COMPUTED = 'coverage.computed'

MCP_EVENT_KINDS = {
    EVENT_KIND_MCP_TOOL_CALL,
    EVENT_KIND_MCP_POLICY_DECISION,
    EVENT_KIND_MCP_TOOL_RESULT,
    EVENT_KIND_MCP_TOOLS_LIST_SERVED,
    EVENT_KIND_MCP_ERROR,
    EVENT_KIND_MCP_CATALOG_DRIFT,
}

SERDE_EVENT_KIND_TO_WIRE = {
    None: EVENT_KIND_LLM_REQUEST,           # field omitted → default LlmRequest
    'llm_request': EVENT_KIND_LLM_REQUEST,
    'auth_session_started': EVENT_KIND_AUTH_SESSION_STARTED,
    'admin_action': EVENT_KIND_ADMIN_ACTION,
    # MEI-925 — serde snake_case forms of the v1.4 kinds.
    'mcp_tool_call': EVENT_KIND_MCP_TOOL_CALL,
    'mcp_policy_decision': EVENT_KIND_MCP_POLICY_DECISION,
    'mcp_tool_result': EVENT_KIND_MCP_TOOL_RESULT,
    'mcp_tools_list_served': EVENT_KIND_MCP_TOOLS_LIST_SERVED,
    'mcp_error': EVENT_KIND_MCP_ERROR,
    'mcp_catalog_drift': EVENT_KIND_MCP_CATALOG_DRIFT,
    # MEI-1955 — serde snake_case form of the v1.8 kind.
    'coverage_computed': EVENT_KIND_COVERAGE_COMPUTED,
}


def encode_optional_str(s):
    """Presence byte (0=None, 1=Some) + utf-8 bytes if Some.
    Mirror of `feed_optional_str` in sqlite.rs."""
    if s is None:
        return b'\x00'
    return b'\x01' + s.encode('utf-8')


def _v1_2_prefix_hash(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
):
    """Internal — feeds the 15 v1-shape fields. Mirror of
    `v1_2_prefix_hasher` in sqlite.rs. Returns the partial digest
    state via a new hasher object."""
    h = hashlib.sha256()
    h.update(struct.pack('<Q', sequence_number))
    h.update(timestamp_utc.encode('utf-8'))
    h.update(event_id.encode('utf-8'))
    h.update(request_id.encode('utf-8'))
    h.update(model_requested.encode('utf-8'))
    h.update(action.encode('utf-8'))
    h.update(struct.pack('<I', input_tokens))
    h.update(struct.pack('<I', output_tokens))
    h.update(encode_optional_u64(total_tokens))
    h.update(encode_optional_u64(cache_creation_input_tokens))
    h.update(encode_optional_u64(cache_read_input_tokens))
    h.update(encode_optional_u64(cached_input_tokens))
    h.update(encode_optional_u64(reasoning_tokens))
    cost = float(estimated_cost_usd) if estimated_cost_usd is not None else 0.0
    h.update(struct.pack('<d', cost))
    h.update(previous_hash.encode('utf-8'))
    return h


def compute_event_hash_v1_2_llm_request(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
):
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(EVENT_KIND_LLM_REQUEST.encode('utf-8'))
    return h.hexdigest()


def compute_event_hash_v1_2_auth_session_started(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    auth_session,
):
    """auth_session is a dict matching `AuthSessionStartedFields`."""
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(EVENT_KIND_AUTH_SESSION_STARTED.encode('utf-8'))
    h.update(encode_optional_str(auth_session.get('user_email')))
    h.update(auth_session['user_id'].encode('utf-8'))
    h.update(auth_session['project_id'].encode('utf-8'))
    h.update(auth_session['proxy_id'].encode('utf-8'))
    h.update(struct.pack('<q', int(auth_session['session_expires_at'])))
    h.update(auth_session['identity_provenance'].encode('utf-8'))
    h.update(auth_session['jti'].encode('utf-8'))
    h.update(auth_session['signing_key_fingerprint'].encode('utf-8'))
    return h.hexdigest()


def compute_event_hash_v1_3_admin_action(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    admin_action,
):
    """MEI-1048 — v1.3 admin.action hash. admin_action is a dict matching
    `AdminActionFields`. Mirror of `compute_event_hash_v1_3_admin_action` in
    sqlite.rs: the SAME v1.2 prefix (Rust reuses `v1_2_prefix_hasher` for v1.3),
    then the event_kind wire-name, then the 4 admin payload fields. Reusing
    `_v1_2_prefix_hash` here mirrors that intentional Rust sharing — it is NOT
    the v1/v1.2 seam the module comment forbids collapsing."""
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(EVENT_KIND_ADMIN_ACTION.encode('utf-8'))
    h.update(admin_action['action_type'].encode('utf-8'))
    h.update(admin_action['actor'].encode('utf-8'))
    h.update(admin_action['description'].encode('utf-8'))
    h.update(admin_action['metadata_json'].encode('utf-8'))
    return h.hexdigest()


def encode_optional_i64(v):
    """Presence byte (0=None, 1=Some) + little-endian signed 64-bit if Some.
    Mirror of the error_code feed in compute_event_hash_v1_4_mcp (sqlite.rs)."""
    if v is None:
        return b'\x00'
    return b'\x01' + struct.pack('<q', int(v))


def compute_event_hash_v1_4_mcp(
    event_kind,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    mcp_event,
):
    """MEI-925 — v1.4 mcp.* hash, shared by all five MCP kinds. mcp_event is
    a dict matching `McpEventFields`. Mirror of `compute_event_hash_v1_4_mcp`
    in sqlite.rs: the SAME v1.2 prefix, then the specific kind's wire-name
    (the preimage's kind attestation — two identical payloads of different
    kinds hash differently), then the 13 payload fields in struct order.
    Optional strings use the 1-byte presence tag; error_code uses presence
    tag + little-endian i64."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"MEI-925: compute_event_hash_v1_4_mcp called with non-MCP kind {event_kind!r}"
        )
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(event_kind.encode('utf-8'))
    h.update(mcp_event['virtual_server'].encode('utf-8'))
    h.update(mcp_event['upstream_slug'].encode('utf-8'))
    h.update(mcp_event['method'].encode('utf-8'))
    h.update(encode_optional_str(mcp_event.get('tool_name')))
    h.update(encode_optional_str(mcp_event.get('jsonrpc_id')))
    h.update(mcp_event['protocol_version'].encode('utf-8'))
    h.update(encode_optional_str(mcp_event.get('decision')))
    h.update(encode_optional_str(mcp_event.get('reason')))
    h.update(encode_optional_str(mcp_event.get('payload_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('mcp_bundle_sha256')))
    h.update(encode_optional_str(mcp_event.get('correlated_event_id')))
    h.update(encode_optional_i64(mcp_event.get('error_code')))
    h.update(mcp_event['traceparent'].encode('utf-8'))
    return h.hexdigest()


def encode_principal(p):
    """MEI-804 — 1-byte shape tag then the shape's string fields. Mirror of
    `feed_principal` in sqlite.rs. `p` is a dict matching the serde-tagged
    `Principal` (`{"kind": "human_user", "subject", "issuer"?}` or
    `{"kind": "agent", "agent_ref"}`). The tag pins the variant so a human and
    an agent with the same string can never hash alike."""
    kind = p['kind']
    if kind == 'human_user':
        # tag 1, then subject, then optional issuer (presence-tagged).
        return b'\x01' + p['subject'].encode('utf-8') + encode_optional_str(p.get('issuer'))
    if kind == 'agent':
        # tag 2, then agent_ref.
        return b'\x02' + p['agent_ref'].encode('utf-8')
    raise ValueError(f"MEI-804: unknown principal kind {kind!r}")


def encode_principal_chain(chain):
    """MEI-804 — the authenticated principal, then a 1-byte presence tag for
    on_behalf_of (0=bare agent, 1=on-behalf-of chain) plus the acted-for
    principal when present. Mirror of `feed_principal_chain` in sqlite.rs."""
    out = encode_principal(chain['authenticated'])
    obo = chain.get('on_behalf_of')
    if obo is None:
        return out + b'\x00'
    return out + b'\x01' + encode_principal(obo)


def compute_event_hash_v1_5_mcp(
    event_kind,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    mcp_event,
):
    """MEI-804 — v1.5 mcp.* hash: the v1.4 preimage plus the trailing principal
    chain (design §5.6). Mirror of `compute_event_hash_v1_5_mcp` in sqlite.rs.
    The 13 McpEventFields feeds are DUPLICATED from
    `compute_event_hash_v1_4_mcp`, not shared — same structural seam as the Rust
    side: a v1.5-only encoding change must never be able to alter v1.4 output
    (which would invalidate every historical v1.4 record). Do not refactor the
    shared 13-field feed into a helper the v1.4 function also calls."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"MEI-804: compute_event_hash_v1_5_mcp called with non-MCP kind {event_kind!r}"
        )
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(event_kind.encode('utf-8'))
    h.update(mcp_event['virtual_server'].encode('utf-8'))
    h.update(mcp_event['upstream_slug'].encode('utf-8'))
    h.update(mcp_event['method'].encode('utf-8'))
    h.update(encode_optional_str(mcp_event.get('tool_name')))
    h.update(encode_optional_str(mcp_event.get('jsonrpc_id')))
    h.update(mcp_event['protocol_version'].encode('utf-8'))
    h.update(encode_optional_str(mcp_event.get('decision')))
    h.update(encode_optional_str(mcp_event.get('reason')))
    h.update(encode_optional_str(mcp_event.get('payload_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('mcp_bundle_sha256')))
    h.update(encode_optional_str(mcp_event.get('correlated_event_id')))
    h.update(encode_optional_i64(mcp_event.get('error_code')))
    h.update(mcp_event['traceparent'].encode('utf-8'))
    # MEI-804 — the v1.5 addition: the full principal chain.
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    return h.hexdigest()


def compute_event_hash_v1_6_mcp(
    event_kind,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    mcp_event,
):
    """MEI-1189 — v1.6 mcp.* hash: the v1.5 preimage plus one trailing feed, the
    redacted-payload content address (`redacted_payload_sha256_jcs`). Mirror of
    `compute_event_hash_v1_6_mcp` in sqlite.rs. `payload_sha256_jcs` still carries
    the ORIGINAL (pre-redaction) hash, so the preimage binds both digests (two-hash
    binding, ADR-0037 D2 amendment). The field feeds are DUPLICATED from
    `compute_event_hash_v1_5_mcp`, not shared — same structural seam as the Rust
    side: a v1.6-only encoding change must never be able to alter v1.5/v1.4 output."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"MEI-1189: compute_event_hash_v1_6_mcp called with non-MCP kind {event_kind!r}"
        )
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(event_kind.encode('utf-8'))
    h.update(mcp_event['virtual_server'].encode('utf-8'))
    h.update(mcp_event['upstream_slug'].encode('utf-8'))
    h.update(mcp_event['method'].encode('utf-8'))
    h.update(encode_optional_str(mcp_event.get('tool_name')))
    h.update(encode_optional_str(mcp_event.get('jsonrpc_id')))
    h.update(mcp_event['protocol_version'].encode('utf-8'))
    h.update(encode_optional_str(mcp_event.get('decision')))
    h.update(encode_optional_str(mcp_event.get('reason')))
    h.update(encode_optional_str(mcp_event.get('payload_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('mcp_bundle_sha256')))
    h.update(encode_optional_str(mcp_event.get('correlated_event_id')))
    h.update(encode_optional_i64(mcp_event.get('error_code')))
    h.update(mcp_event['traceparent'].encode('utf-8'))
    # MEI-804 — the v1.5 principal chain (carried forward into v1.6).
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    # MEI-1189 — the v1.6 addition: the redacted-payload content address.
    h.update(encode_optional_str(mcp_event.get('redacted_payload_sha256_jcs')))
    return h.hexdigest()


def compute_event_hash_v1_7_mcp(
    event_kind,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    mcp_event,
):
    """MEI-1063 — v1.7 mcp.* hash: the v1.6 preimage plus the two trailing
    ENFORCEMENT-axis redaction hashes (`redaction_pre_sha256_jcs`,
    `redaction_post_sha256_jcs`) — the digests of the payload before/after the
    redact transform the gateway applied to the FORWARDED content. Mirror of
    `compute_event_hash_v1_7_mcp` in sqlite.rs. Distinct axis from the v1.6
    capture-axis `redacted_payload_sha256_jcs`, which is None on an enforcement
    record (the two axes are mutually exclusive per record, but it is still fed
    for byte-position parity with v1.6). The field feeds are DUPLICATED from
    `compute_event_hash_v1_6_mcp`, not shared — same structural seam as the Rust
    side: a v1.7-only encoding change must never alter v1.4/v1.5/v1.6 output."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"MEI-1063: compute_event_hash_v1_7_mcp called with non-MCP kind {event_kind!r}"
        )
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(event_kind.encode('utf-8'))
    h.update(mcp_event['virtual_server'].encode('utf-8'))
    h.update(mcp_event['upstream_slug'].encode('utf-8'))
    h.update(mcp_event['method'].encode('utf-8'))
    h.update(encode_optional_str(mcp_event.get('tool_name')))
    h.update(encode_optional_str(mcp_event.get('jsonrpc_id')))
    h.update(mcp_event['protocol_version'].encode('utf-8'))
    h.update(encode_optional_str(mcp_event.get('decision')))
    h.update(encode_optional_str(mcp_event.get('reason')))
    h.update(encode_optional_str(mcp_event.get('payload_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('mcp_bundle_sha256')))
    h.update(encode_optional_str(mcp_event.get('correlated_event_id')))
    h.update(encode_optional_i64(mcp_event.get('error_code')))
    h.update(mcp_event['traceparent'].encode('utf-8'))
    # MEI-804 — the v1.5 principal chain (carried forward into v1.7).
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    # MEI-1189 — the v1.6 capture-axis redacted-payload content address
    # (carried forward; None on enforcement records but fed for byte-position
    # stability with v1.6).
    h.update(encode_optional_str(mcp_event.get('redacted_payload_sha256_jcs')))
    # MEI-1063 — the v1.7 addition: the enforcement-axis fields, in order. The
    # two redaction hashes (redact verdict) and the hold_id (hold verdict) are
    # the three mutually-scoped enforcement-axis discriminators; a redact record
    # feeds hold_id=None and a hold record feeds both redaction hashes=None.
    h.update(encode_optional_str(mcp_event.get('redaction_pre_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_post_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('hold_id')))
    return h.hexdigest()


def compute_event_hash_v1_8_coverage(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    coverage,
):
    """MEI-1955 (ADR-0052) — v1.8 coverage.computed hash. `coverage` is a dict
    matching `CoverageComputedFields`. Mirror of
    `compute_event_hash_v1_8_coverage` in sqlite.rs: the SAME v1.2 prefix, then
    the event_kind wire-name, then the 13 coverage payload fields in
    struct-definition order. Strings feed as raw utf-8; the three i64 fields
    (`proxy_attributed`, `provider_reported`, `bypass_rate_ppm`) feed as
    little-endian signed 64-bit with NO presence tag — they are required on
    the Rust struct, -1 is the "not available" sentinel."""
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(EVENT_KIND_COVERAGE_COMPUTED.encode('utf-8'))
    h.update(coverage['provider'].encode('utf-8'))
    h.update(coverage['day'].encode('utf-8'))
    h.update(coverage['tier'].encode('utf-8'))
    h.update(coverage['reconciliation_unit'].encode('utf-8'))
    h.update(struct.pack('<q', int(coverage['proxy_attributed'])))
    h.update(struct.pack('<q', int(coverage['provider_reported'])))
    h.update(coverage['delta_classification'].encode('utf-8'))
    h.update(struct.pack('<q', int(coverage['bypass_rate_ppm'])))
    h.update(coverage['tolerance_band_json'].encode('utf-8'))
    h.update(coverage['claim_language_key'].encode('utf-8'))
    h.update(coverage['registry_version'].encode('utf-8'))
    h.update(coverage['numerator_source'].encode('utf-8'))
    h.update(coverage['denominator_fetched_at'].encode('utf-8'))
    return h.hexdigest()


def compute_event_hash_v1_9_llm_request(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    join_context,
):
    """MEI-2151 — v1.9 llm_request hash: the v1.2 LlmRequest preimage (v1.2
    prefix + event_kind wire name) plus the three caller-asserted cross-lane
    join keys, each with the same 1-byte presence tag every other optional
    string uses. Mirror of `compute_event_hash_v1_9_llm_request` in sqlite.rs.

    `join_context` is a dict matching `CallerJoinContext`. It is only ever
    present when the CALLER asserted a join key on `x-meilynx-context` — an
    auto-minted correlation id never reaches this bucket, which is why an
    uncorrelated LLM event stays on v1.1 and hashes byte-identically to every
    record written before this field existed."""
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(EVENT_KIND_LLM_REQUEST.encode('utf-8'))
    # MEI-2151 — the v1.9 addition, in CallerJoinContext struct-definition order.
    h.update(encode_optional_str(join_context.get('correlation_id')))
    h.update(encode_optional_str(join_context.get('session_id')))
    h.update(encode_optional_str(join_context.get('agent_name')))
    return h.hexdigest()


def compute_event_hash_v1_9_mcp(
    event_kind,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    mcp_event, join_context,
):
    """MEI-2151 — v1.9 mcp.* hash: the v1.7 preimage (which carries the v1.5
    principal chain and the v1.6 capture-axis address forward, fed even when
    None) plus the three caller-asserted join keys. Mirror of
    `compute_event_hash_v1_9_mcp` in sqlite.rs.

    The v1.4-v1.7 field feeds are DUPLICATED here, not shared — same structural
    seam as every earlier MCP hasher on this side and the Rust side: a
    v1.9-only encoding change must never alter v1.4/v1.5/v1.6/v1.7 output,
    which would silently invalidate every historical record."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"MEI-2151: compute_event_hash_v1_9_mcp called with non-MCP kind {event_kind!r}"
        )
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(event_kind.encode('utf-8'))
    h.update(mcp_event['virtual_server'].encode('utf-8'))
    h.update(mcp_event['upstream_slug'].encode('utf-8'))
    h.update(mcp_event['method'].encode('utf-8'))
    h.update(encode_optional_str(mcp_event.get('tool_name')))
    h.update(encode_optional_str(mcp_event.get('jsonrpc_id')))
    h.update(mcp_event['protocol_version'].encode('utf-8'))
    h.update(encode_optional_str(mcp_event.get('decision')))
    h.update(encode_optional_str(mcp_event.get('reason')))
    h.update(encode_optional_str(mcp_event.get('payload_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('mcp_bundle_sha256')))
    h.update(encode_optional_str(mcp_event.get('correlated_event_id')))
    h.update(encode_optional_i64(mcp_event.get('error_code')))
    h.update(mcp_event['traceparent'].encode('utf-8'))
    # MEI-804 — the v1.5 principal chain (carried forward into v1.9).
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    # MEI-1189 — the v1.6 capture-axis address (carried forward, fed even when
    # None for byte-position stability with v1.6/v1.7).
    h.update(encode_optional_str(mcp_event.get('redacted_payload_sha256_jcs')))
    # MEI-1063 — the v1.7 enforcement-axis fields (carried forward, fed even
    # when None for byte-position stability with v1.7).
    h.update(encode_optional_str(mcp_event.get('redaction_pre_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_post_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('hold_id')))
    # MEI-2151 — the v1.9 addition, in CallerJoinContext struct-definition order.
    h.update(encode_optional_str(join_context.get('correlation_id')))
    h.update(encode_optional_str(join_context.get('session_id')))
    h.update(encode_optional_str(join_context.get('agent_name')))
    return h.hexdigest()


def compute_event_hash_dispatch(
    schema_version,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    event_kind=EVENT_KIND_LLM_REQUEST, auth_session=None, admin_action=None,
    mcp_event=None, coverage=None, join_context=None,
):
    """MEI-639 — Python mirror of compute_event_hash_dispatch in sqlite.rs.

    Backwards compatibility contract:
      - "v1" / "v1.1" → legacy compute_event_hash (15-field, frozen).
      - "v1.2" → compute_event_hash_v1_2_* based on event_kind.
      - Unknown → raise ValueError (forward-compat guard, matches Rust).
    """
    # MEI-2151 — fail-closed invariant, mirror of the Rust dispatcher: a
    # caller-asserted join key may only ride the one bucket whose preimage
    # contains it. An event carrying join_context on an older schema_version
    # would be presenting an UNHASHED join key as evidence — rewritable after
    # the fact without breaking the chain.
    if join_context is not None and schema_version != 'v1.9':
        raise ValueError(
            f"MEI-2151: join_context present on a {schema_version!r} event — "
            f"caller-asserted join keys are hashed only in the v1.9 bucket."
        )
    if schema_version in ('v1', 'v1.1'):
        return compute_event_hash(
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
        )
    if schema_version == 'v1.2':
        if event_kind == EVENT_KIND_LLM_REQUEST:
            return compute_event_hash_v1_2_llm_request(
                sequence_number, timestamp_utc, event_id, request_id,
                model_requested, action, input_tokens, output_tokens,
                total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
                cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            )
        if event_kind == EVENT_KIND_AUTH_SESSION_STARTED:
            if auth_session is None:
                raise ValueError(
                    "MEI-639: AuthSessionStarted event missing auth_session payload"
                )
            return compute_event_hash_v1_2_auth_session_started(
                sequence_number, timestamp_utc, event_id, request_id,
                model_requested, action, input_tokens, output_tokens,
                total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
                cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
                auth_session,
            )
        if event_kind == EVENT_KIND_ADMIN_ACTION:
            raise ValueError(
                "MEI-1048: AdminAction events require schema_version v1.3, got v1.2"
            )
        raise ValueError(f"MEI-639: unknown event_kind {event_kind!r}")
    if schema_version == 'v1.3':
        if event_kind != EVENT_KIND_ADMIN_ACTION:
            raise ValueError(
                f"MEI-1048: schema_version v1.3 is defined only for admin.action "
                f"events; got event_kind {event_kind!r}"
            )
        if admin_action is None:
            raise ValueError(
                "MEI-1048: AdminAction event missing admin_action payload"
            )
        return compute_event_hash_v1_3_admin_action(
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            admin_action,
        )
    if schema_version == 'v1.4':
        if event_kind not in MCP_EVENT_KINDS:
            raise ValueError(
                f"MEI-925: schema_version v1.4 is defined only for mcp.* "
                f"events; got event_kind {event_kind!r}"
            )
        if mcp_event is None:
            raise ValueError(
                f"MEI-925: {event_kind!r} event missing mcp_event payload"
            )
        return compute_event_hash_v1_4_mcp(
            event_kind,
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            mcp_event,
        )
    if schema_version == 'v1.5':
        # MEI-804 — v1.5 extends the MCP bucket with the principal chain. Same
        # mcp-only gate + payload-required posture as v1.4.
        if event_kind not in MCP_EVENT_KINDS:
            raise ValueError(
                f"MEI-804: schema_version v1.5 is defined only for mcp.* "
                f"events; got event_kind {event_kind!r}"
            )
        if mcp_event is None:
            raise ValueError(
                f"MEI-804: {event_kind!r} event missing mcp_event payload"
            )
        return compute_event_hash_v1_5_mcp(
            event_kind,
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            mcp_event,
        )
    if schema_version == 'v1.6':
        # MEI-1189 — v1.6 extends the MCP bucket with the redacted-payload
        # content address (redacted capture, two-hash binding). Same mcp-only
        # gate + payload-required posture as v1.4/v1.5.
        if event_kind not in MCP_EVENT_KINDS:
            raise ValueError(
                f"MEI-1189: schema_version v1.6 is defined only for mcp.* "
                f"events; got event_kind {event_kind!r}"
            )
        if mcp_event is None:
            raise ValueError(
                f"MEI-1189: {event_kind!r} event missing mcp_event payload"
            )
        return compute_event_hash_v1_6_mcp(
            event_kind,
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            mcp_event,
        )
    if schema_version == 'v1.7':
        # MEI-1063 — v1.7 extends the MCP bucket with the enforcement-axis
        # redaction pre/post hashes (redact enforcement). Same mcp-only gate +
        # payload-required posture as v1.4/v1.5/v1.6.
        if event_kind not in MCP_EVENT_KINDS:
            raise ValueError(
                f"MEI-1063: schema_version v1.7 is defined only for mcp.* "
                f"events; got event_kind {event_kind!r}"
            )
        if mcp_event is None:
            raise ValueError(
                f"MEI-1063: {event_kind!r} event missing mcp_event payload"
            )
        return compute_event_hash_v1_7_mcp(
            event_kind,
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            mcp_event,
        )
    if schema_version == 'v1.8':
        # MEI-1955 — v1.8 introduces exactly one new event class:
        # coverage.computed. Same kind-only gate posture as v1.3.
        if event_kind != EVENT_KIND_COVERAGE_COMPUTED:
            raise ValueError(
                f"MEI-1955: schema_version v1.8 is defined only for "
                f"coverage.computed events; got event_kind {event_kind!r}"
            )
        if coverage is None:
            raise ValueError(
                "MEI-1955: CoverageComputed event missing coverage payload"
            )
        return compute_event_hash_v1_8_coverage(
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            coverage,
        )
    if schema_version == 'v1.9':
        # MEI-2151 — v1.9 is the first bucket that is NOT keyed to a new event
        # class: it is the existing llm_request / mcp.* preimages plus the
        # caller-asserted cross-lane join keys, selected by presence of
        # join_context. Uncorrelated traffic on both lanes stays in its
        # existing bucket and is byte-stable.
        if join_context is None:
            raise ValueError(
                "MEI-2151: schema_version v1.9 requires a join_context payload; "
                "an event with no caller-asserted join key must stay in its "
                "pre-v1.9 bucket."
            )
        if event_kind == EVENT_KIND_LLM_REQUEST:
            return compute_event_hash_v1_9_llm_request(
                sequence_number, timestamp_utc, event_id, request_id,
                model_requested, action, input_tokens, output_tokens,
                total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
                cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
                join_context,
            )
        if event_kind in MCP_EVENT_KINDS:
            if mcp_event is None:
                raise ValueError(
                    f"MEI-2151: {event_kind!r} event missing mcp_event payload"
                )
            return compute_event_hash_v1_9_mcp(
                event_kind,
                sequence_number, timestamp_utc, event_id, request_id,
                model_requested, action, input_tokens, output_tokens,
                total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
                cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
                mcp_event, join_context,
            )
        raise ValueError(
            f"MEI-2151: schema_version v1.9 is defined only for llm_request "
            f"and mcp.* events; got event_kind {event_kind!r}"
        )
    raise ValueError(
        f"MEI-639: unknown schema_version {schema_version!r} — "
        f"this verifier has no hash branch for it. Update verify-pack.py."
    )


# ---------------------------------------------------------------------------
# Self-test (Safeguard 1 + normalization coverage)
#
# FIXTURE_HASH must match FIXTURE_HASH in:
#   meilynx-integrity-pack/tests/drift_catchers.rs::mei422_hash_fixture_pinning
# Update both if HASH_INPUT_FIELDS changes (and bump hash_version in manifest).
# ---------------------------------------------------------------------------

FIXTURE_HASH = "ba7a7f3d8213b99aaee3833c2eb6f23fa0bef46a4bf76d2ebf18aa7565bee031"

# Fixture inputs shared by both self-test assertions.
_FIXTURE = dict(
    sequence_number=42,
    event_id="evt-fixture-001",
    request_id="req-fixture-001",
    model_requested="claude-sonnet-4-6",
    action="Allow",
    input_tokens=100,
    output_tokens=200,
    total_tokens=300,
    cache_creation_input_tokens=None,
    cache_read_input_tokens=None,
    cached_input_tokens=None,
    reasoning_tokens=None,
    estimated_cost_usd=0.0042,
    # Deliberately synthetic previous_hash — NOT the real genesis (c2989403cf897dac...).
    # Uses the "dead beef" convention to be unambiguously non-production state. (MEI-493)
    previous_hash="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
)


def run_self_test():
    """
    Two assertions covering Safeguard 1 (encoding correctness) and
    the Z-suffix normalization path (MEI-492):

    Assertion 1 — +00:00 fixture:
      Known input with +00:00 timestamp produces the pinned FIXTURE_HASH.
      Fails if compute_event_hash encoding drifts.

    Assertion 2 — Z-suffix normalization:
      The same logical timestamp as Z-suffix, passed through normalize_timestamp(),
      produces the same FIXTURE_HASH. Also asserts that the raw (un-normalized)
      Z-suffix produces a DIFFERENT hash — proving normalization is load-bearing.
      Fails if normalize_timestamp() is broken or removed.
    """
    ok = True

    # Assertion 1: +00:00 fixture.
    got_plus = compute_event_hash(timestamp_utc="2026-05-17T00:00:00+00:00", **_FIXTURE)
    if got_plus == FIXTURE_HASH:
        print("SELF-TEST assertion 1 PASS: +00:00 fixture hash matches")
    else:
        print("SELF-TEST assertion 1 FAIL: +00:00 fixture hash mismatch", file=sys.stderr)
        print(f"  expected: {FIXTURE_HASH}", file=sys.stderr)
        print(f"  got:      {got_plus}", file=sys.stderr)
        ok = False

    # Assertion 2a: Z-suffix after normalization must equal +00:00 hash.
    ts_z = "2026-05-17T00:00:00Z"
    got_z_normalized = compute_event_hash(
        timestamp_utc=normalize_timestamp(ts_z), **_FIXTURE
    )
    if got_z_normalized == FIXTURE_HASH:
        print("SELF-TEST assertion 2a PASS: Z-suffix after normalization matches +00:00 hash")
    else:
        print("SELF-TEST assertion 2a FAIL: normalize_timestamp() is broken", file=sys.stderr)
        print(f"  expected: {FIXTURE_HASH}", file=sys.stderr)
        print(f"  got:      {got_z_normalized}", file=sys.stderr)
        ok = False

    # Assertion 2b: raw Z-suffix (NOT normalized) must produce a DIFFERENT hash.
    # This proves that normalization is load-bearing, not a no-op.
    got_z_raw = compute_event_hash(timestamp_utc=ts_z, **_FIXTURE)
    if got_z_raw != FIXTURE_HASH:
        print("SELF-TEST assertion 2b PASS: raw Z-suffix hash differs from +00:00 (normalization is necessary)")
    else:
        print("SELF-TEST assertion 2b FAIL: Z and +00:00 produced the same hash — normalization is a no-op, which is wrong", file=sys.stderr)
        ok = False

    # MEI-639 Assertion 3 — dispatcher's v1 branch byte-identical.
    # Same canonical input as assertion 1, but routed through the new
    # schema_version dispatcher. Must produce FIXTURE_HASH bit-for-bit,
    # proving the Python dispatcher's v1 path doesn't drift from the
    # legacy function in any subtle way (reordered field, separator,
    # null treatment). Mirror of `mei639_dispatcher_v1_branch_is_byte_identical_to_compute_event_hash`
    # on the Rust side.
    got_dispatch_v1 = compute_event_hash_dispatch(
        'v1', timestamp_utc="2026-05-17T00:00:00+00:00", **_FIXTURE,
    )
    if got_dispatch_v1 == FIXTURE_HASH:
        print("SELF-TEST assertion 3 PASS: dispatcher v1 branch is byte-identical to compute_event_hash")
    else:
        print("SELF-TEST assertion 3 FAIL: dispatcher v1 branch DIVERGED from compute_event_hash", file=sys.stderr)
        print(f"  expected: {FIXTURE_HASH}", file=sys.stderr)
        print(f"  got:      {got_dispatch_v1}", file=sys.stderr)
        ok = False

    # MEI-639 Assertion 4 — v1 path ignores event_kind / auth_session.
    # Passing AuthSessionStarted + a fake payload to the v1 branch must
    # still produce FIXTURE_HASH. Proves the v1 path CANNOT be contaminated
    # by v1.2-only fields. Mirror of the third sub-assertion in the
    # Rust test.
    got_dispatch_v1_with_v12_args = compute_event_hash_dispatch(
        'v1', timestamp_utc="2026-05-17T00:00:00+00:00",
        event_kind=EVENT_KIND_AUTH_SESSION_STARTED,
        auth_session=dict(
            user_email="ghost@example.test",
            user_id="fake-user", project_id="fake-proj", proxy_id="fake-proxy",
            session_expires_at=0, identity_provenance="meilynx-cp-handoff",
            jti="fake-jti", signing_key_fingerprint="abcd",
        ),
        **_FIXTURE,
    )
    if got_dispatch_v1_with_v12_args == FIXTURE_HASH:
        print("SELF-TEST assertion 4 PASS: v1 path provably ignores event_kind + auth_session bytes")
    else:
        print("SELF-TEST assertion 4 FAIL: v1 path is being contaminated by v1.2-only fields", file=sys.stderr)
        print(f"  expected: {FIXTURE_HASH}", file=sys.stderr)
        print(f"  got:      {got_dispatch_v1_with_v12_args}", file=sys.stderr)
        ok = False

    # MEI-639 Assertion 5 — Rust/Python agreement on v1.2 LlmRequest.
    # Pinned v1.2 LlmRequest fixture hash. The Rust drift_catchers.rs
    # has a paired test asserting the SAME hash from the SAME inputs;
    # neither side is allowed to drift independently.
    got_v12_llm = compute_event_hash_v1_2_llm_request(
        timestamp_utc="2026-05-17T00:00:00+00:00", **_FIXTURE,
    )
    if got_v12_llm == V1_2_LLM_REQUEST_FIXTURE_HASH:
        print("SELF-TEST assertion 5 PASS: v1.2 LlmRequest fixture hash matches")
    else:
        print("SELF-TEST assertion 5 FAIL: v1.2 LlmRequest fixture drift", file=sys.stderr)
        print(f"  expected: {V1_2_LLM_REQUEST_FIXTURE_HASH}", file=sys.stderr)
        print(f"  got:      {got_v12_llm}", file=sys.stderr)
        ok = False

    # MEI-639 Assertion 6 — Rust/Python agreement on v1.2 AuthSessionStarted.
    # Same input + auth payload exists in the Rust paired test.
    got_v12_auth = compute_event_hash_v1_2_auth_session_started(
        timestamp_utc="2026-05-17T00:00:00+00:00",
        auth_session=_V1_2_AUTH_FIXTURE_PAYLOAD,
        **_FIXTURE,
    )
    if got_v12_auth == V1_2_AUTH_SESSION_STARTED_FIXTURE_HASH:
        print("SELF-TEST assertion 6 PASS: v1.2 AuthSessionStarted fixture hash matches")
    else:
        print("SELF-TEST assertion 6 FAIL: v1.2 AuthSessionStarted fixture drift", file=sys.stderr)
        print(f"  expected: {V1_2_AUTH_SESSION_STARTED_FIXTURE_HASH}", file=sys.stderr)
        print(f"  got:      {got_v12_auth}", file=sys.stderr)
        ok = False

    # MEI-1048 Assertion 7 — v1.3 admin.action fixture (direct fn), paired
    # with the Rust mei1048_v1_3_admin_action_fixture_hash_pinned literal.
    ts_1760 = datetime.datetime.fromtimestamp(
        1_760_000_000, datetime.timezone.utc).isoformat()
    got_v13 = compute_event_hash_v1_3_admin_action(
        sequence_number=7, timestamp_utc=ts_1760, event_id='evt-fixture',
        request_id='req-fixture', model_requested='', action='allow',
        input_tokens=0, output_tokens=0, total_tokens=None,
        cache_creation_input_tokens=None, cache_read_input_tokens=None,
        cached_input_tokens=None, reasoning_tokens=None,
        estimated_cost_usd=None, previous_hash='prev-fixture',
        admin_action=_V1_3_ADMIN_FIXTURE_PAYLOAD,
    )
    if got_v13 == V1_3_ADMIN_ACTION_FIXTURE_HASH:
        print('SELF-TEST assertion 7 PASS: v1.3 admin.action fixture hash matches')
    else:
        print('SELF-TEST assertion 7 FAIL: v1.3 admin.action fixture drift', file=sys.stderr)
        print(f'  expected: {V1_3_ADMIN_ACTION_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v13}', file=sys.stderr)
        ok = False

    # MEI-1096 Assertion 8 — the SAME v1.3 event, but recomputed through
    # recompute_event_hash (the production path verify_manifest walks) from a
    # synthetic exported-JSON body: event_kind in serde snake_case ('admin_action'),
    # Z-suffix timestamp, nested admin_action payload. This is the regression
    # that would have caught MEI-1096 — the record loop used to ignore all of it
    # and compute a frozen v1 hash. Exercises serde->wire mapping + schema
    # dispatch + timestamp normalization + payload feed end-to-end.
    synthetic_admin_event = dict(
        schema_version='v1.3',
        event_kind='admin_action',
        timestamp_utc=ts_1760.replace('+00:00', 'Z'),
        event_id='evt-fixture', request_id='req-fixture', model_requested='',
        action='allow', input_tokens=0, output_tokens=0,
        admin_action=dict(_V1_3_ADMIN_FIXTURE_PAYLOAD),
    )
    got_v13_loop = recompute_event_hash(synthetic_admin_event, 7, 'prev-fixture')
    if got_v13_loop == V1_3_ADMIN_ACTION_FIXTURE_HASH:
        print('SELF-TEST assertion 8 PASS: verify_manifest recompute path handles v1.3 admin.action')
    else:
        print('SELF-TEST assertion 8 FAIL: recompute_event_hash mis-hashes v1.3 admin.action (MEI-1096 regression)', file=sys.stderr)
        print(f'  expected: {V1_3_ADMIN_ACTION_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v13_loop}', file=sys.stderr)
        ok = False

    # MEI-1096 Assertion 9 — the same production-path check for v1.2 auth,
    # proving the record loop no longer silently downgrades v1.2 to v1 either.
    synthetic_auth_event = dict(
        schema_version='v1.2',
        event_kind='auth_session_started',
        timestamp_utc='2026-05-17T00:00:00Z',
        event_id=_FIXTURE['event_id'], request_id=_FIXTURE['request_id'],
        model_requested=_FIXTURE['model_requested'], action=_FIXTURE['action'],
        input_tokens=_FIXTURE['input_tokens'], output_tokens=_FIXTURE['output_tokens'],
        total_tokens=_FIXTURE['total_tokens'],
        estimated_cost_usd=_FIXTURE['estimated_cost_usd'],
        auth_session=dict(_V1_2_AUTH_FIXTURE_PAYLOAD),
    )
    got_v12_loop = recompute_event_hash(
        synthetic_auth_event, _FIXTURE['sequence_number'], _FIXTURE['previous_hash'])
    if got_v12_loop == V1_2_AUTH_SESSION_STARTED_FIXTURE_HASH:
        print('SELF-TEST assertion 9 PASS: verify_manifest recompute path handles v1.2 auth.session_started')
    else:
        print('SELF-TEST assertion 9 FAIL: recompute_event_hash mis-hashes v1.2 auth (MEI-1096 regression)', file=sys.stderr)
        print(f'  expected: {V1_2_AUTH_SESSION_STARTED_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v12_loop}', file=sys.stderr)
        ok = False

    # MEI-925 Assertions 10a-10c — v1.4 mcp.* fixtures (direct fn), paired
    # with the Rust mei925_v1_4_*_fixture_hash_pinned literals in
    # meilynx-audit/tests/mei925_mcp_chain_round_trip.rs. Three shapes cover
    # the distinct byte encodings: required strings + Some-optionals
    # (tool_call), decision/reason/correlation Some + payload None
    # (policy_decision), and the presence-tagged i64 error_code (error).
    ts_1760 = datetime.datetime.fromtimestamp(
        1_760_000_000, datetime.timezone.utc).isoformat()
    mcp_fixture_args = dict(
        sequence_number=11, timestamp_utc=ts_1760, event_id='evt-mcp-fixture',
        request_id='req-mcp-fixture', model_requested='', action='allow',
        input_tokens=0, output_tokens=0, total_tokens=None,
        cache_creation_input_tokens=None, cache_read_input_tokens=None,
        cached_input_tokens=None, reasoning_tokens=None,
        estimated_cost_usd=None, previous_hash='prev-fixture',
    )
    for label, kind, payload, expected in (
        ('10a', EVENT_KIND_MCP_TOOL_CALL, _V1_4_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
         V1_4_MCP_TOOL_CALL_FIXTURE_HASH),
        ('10b', EVENT_KIND_MCP_POLICY_DECISION, _V1_4_MCP_DECISION_FIXTURE_PAYLOAD,
         V1_4_MCP_POLICY_DECISION_FIXTURE_HASH),
        ('10c', EVENT_KIND_MCP_ERROR, _V1_4_MCP_ERROR_FIXTURE_PAYLOAD,
         V1_4_MCP_ERROR_FIXTURE_HASH),
    ):
        got = compute_event_hash_v1_4_mcp(kind, mcp_event=payload, **mcp_fixture_args)
        if got == expected:
            print(f'SELF-TEST assertion {label} PASS: v1.4 {kind} fixture hash matches')
        else:
            print(f'SELF-TEST assertion {label} FAIL: v1.4 {kind} fixture drift', file=sys.stderr)
            print(f'  expected: {expected}', file=sys.stderr)
            print(f'  got:      {got}', file=sys.stderr)
            ok = False

    # MEI-925 Assertion 11 — the tool_call fixture recomputed through
    # recompute_event_hash (the production path verify_manifest walks) from a
    # synthetic exported-JSON body: event_kind in serde snake_case
    # ('mcp_tool_call'), Z-suffix timestamp, nested mcp_event payload — the
    # MEI-1096 regression class applied to the v1.4 bucket.
    synthetic_mcp_event = dict(
        schema_version='v1.4',
        event_kind='mcp_tool_call',
        timestamp_utc=ts_1760.replace('+00:00', 'Z'),
        event_id='evt-mcp-fixture', request_id='req-mcp-fixture',
        model_requested='', action='allow', input_tokens=0, output_tokens=0,
        mcp_event=dict(_V1_4_MCP_TOOL_CALL_FIXTURE_PAYLOAD),
    )
    got_v14_loop = recompute_event_hash(synthetic_mcp_event, 11, 'prev-fixture')
    if got_v14_loop == V1_4_MCP_TOOL_CALL_FIXTURE_HASH:
        print('SELF-TEST assertion 11 PASS: verify_manifest recompute path handles v1.4 mcp.tool_call')
    else:
        print('SELF-TEST assertion 11 FAIL: recompute_event_hash mis-hashes v1.4 mcp.tool_call', file=sys.stderr)
        print(f'  expected: {V1_4_MCP_TOOL_CALL_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v14_loop}', file=sys.stderr)
        ok = False

    # MEI-804 Assertions 12a-12d — v1.5 mcp.* fixtures (direct fn), paired with
    # the Rust mei925_v1_5_*_fixture_hash_pinned literals. v1.5 = the v1.4
    # preimage plus the trailing principal chain. 12a-12c reuse the three v1.4
    # shapes with an on-behalf-of chain (agent authenticated + human acted-for,
    # issuer present); 12d is the bare-agent chain (on_behalf_of None, no issuer)
    # to cover the absent principal-chain branches.
    for label, kind, payload, expected in (
        ('12a', EVENT_KIND_MCP_TOOL_CALL, _V1_5_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
         V1_5_MCP_TOOL_CALL_FIXTURE_HASH),
        ('12b', EVENT_KIND_MCP_POLICY_DECISION, _V1_5_MCP_DECISION_FIXTURE_PAYLOAD,
         V1_5_MCP_POLICY_DECISION_FIXTURE_HASH),
        ('12c', EVENT_KIND_MCP_ERROR, _V1_5_MCP_ERROR_FIXTURE_PAYLOAD,
         V1_5_MCP_ERROR_FIXTURE_HASH),
        ('12d', EVENT_KIND_MCP_TOOL_CALL, _V1_5_MCP_BARE_AGENT_FIXTURE_PAYLOAD,
         V1_5_MCP_BARE_AGENT_FIXTURE_HASH),
    ):
        got = compute_event_hash_v1_5_mcp(kind, mcp_event=payload, **mcp_fixture_args)
        if got == expected:
            print(f'SELF-TEST assertion {label} PASS: v1.5 {kind} fixture hash matches')
        else:
            print(f'SELF-TEST assertion {label} FAIL: v1.5 {kind} fixture drift', file=sys.stderr)
            print(f'  expected: {expected}', file=sys.stderr)
            print(f'  got:      {got}', file=sys.stderr)
            ok = False

    # MEI-804 Assertion 13 — the v1.5 tool_call fixture recomputed through
    # recompute_event_hash (the production path verify_manifest walks): serde
    # snake_case event_kind, Z-suffix timestamp, nested mcp_event carrying the
    # principal_chain. Confirms the schema_version='v1.5' dispatch branch is
    # reachable end-to-end from an exported-JSON body.
    synthetic_mcp_v15_event = dict(
        schema_version='v1.5',
        event_kind='mcp_tool_call',
        timestamp_utc=ts_1760.replace('+00:00', 'Z'),
        event_id='evt-mcp-fixture', request_id='req-mcp-fixture',
        model_requested='', action='allow', input_tokens=0, output_tokens=0,
        mcp_event=dict(_V1_5_MCP_TOOL_CALL_FIXTURE_PAYLOAD),
    )
    got_v15_loop = recompute_event_hash(synthetic_mcp_v15_event, 11, 'prev-fixture')
    if got_v15_loop == V1_5_MCP_TOOL_CALL_FIXTURE_HASH:
        print('SELF-TEST assertion 13 PASS: verify_manifest recompute path handles v1.5 mcp.tool_call')
    else:
        print('SELF-TEST assertion 13 FAIL: recompute_event_hash mis-hashes v1.5 mcp.tool_call', file=sys.stderr)
        print(f'  expected: {V1_5_MCP_TOOL_CALL_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v15_loop}', file=sys.stderr)
        ok = False

    # MEI-1189 Assertion 14a — v1.6 redacted tool_call fixture via the direct
    # compute function. Cross-pinned with the Rust
    # mei1189_v1_6_redacted_tool_call_fixture_hash_pinned literal.
    got_v16 = compute_event_hash_v1_6_mcp(
        EVENT_KIND_MCP_TOOL_CALL,
        mcp_event=_V1_6_MCP_TOOL_CALL_FIXTURE_PAYLOAD, **mcp_fixture_args
    )
    if got_v16 == V1_6_MCP_TOOL_CALL_FIXTURE_HASH:
        print('SELF-TEST assertion 14a PASS: v1.6 mcp.tool_call (redacted) fixture hash matches')
    else:
        print('SELF-TEST assertion 14a FAIL: v1.6 mcp.tool_call fixture drift', file=sys.stderr)
        print(f'  expected: {V1_6_MCP_TOOL_CALL_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v16}', file=sys.stderr)
        ok = False

    # MEI-1189 Assertion 14b — the same v1.6 fixture recomputed through the
    # production recompute_event_hash path (schema_version='v1.6' dispatch,
    # nested mcp_event carrying the redacted content address). Confirms the v1.6
    # branch is reachable end-to-end from an exported-JSON body.
    synthetic_mcp_v16_event = dict(
        schema_version='v1.6',
        event_kind='mcp_tool_call',
        timestamp_utc=ts_1760.replace('+00:00', 'Z'),
        event_id='evt-mcp-fixture', request_id='req-mcp-fixture',
        model_requested='', action='allow', input_tokens=0, output_tokens=0,
        mcp_event=dict(_V1_6_MCP_TOOL_CALL_FIXTURE_PAYLOAD),
    )
    got_v16_loop = recompute_event_hash(synthetic_mcp_v16_event, 11, 'prev-fixture')
    if got_v16_loop == V1_6_MCP_TOOL_CALL_FIXTURE_HASH:
        print('SELF-TEST assertion 14b PASS: verify_manifest recompute path handles v1.6 mcp.tool_call')
    else:
        print('SELF-TEST assertion 14b FAIL: recompute_event_hash mis-hashes v1.6 mcp.tool_call', file=sys.stderr)
        print(f'  expected: {V1_6_MCP_TOOL_CALL_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v16_loop}', file=sys.stderr)
        ok = False

    # MEI-1063 Assertion 15a — v1.7 enforcement tool_call fixture via the direct
    # compute function. Cross-pinned with the Rust
    # mei1063_v1_7_enforcement_tool_call_fixture_hash_pinned literal.
    got_v17 = compute_event_hash_v1_7_mcp(
        EVENT_KIND_MCP_TOOL_CALL,
        mcp_event=_V1_7_MCP_TOOL_CALL_FIXTURE_PAYLOAD, **mcp_fixture_args
    )
    if got_v17 == V1_7_MCP_TOOL_CALL_FIXTURE_HASH:
        print('SELF-TEST assertion 15a PASS: v1.7 mcp.tool_call (enforcement) fixture hash matches')
    else:
        print('SELF-TEST assertion 15a FAIL: v1.7 mcp.tool_call fixture drift', file=sys.stderr)
        print(f'  expected: {V1_7_MCP_TOOL_CALL_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v17}', file=sys.stderr)
        ok = False

    # MEI-1063 Assertion 15b — the same v1.7 fixture recomputed through the
    # production recompute_event_hash path (schema_version='v1.7' dispatch,
    # nested mcp_event carrying the enforcement redaction hashes). Confirms the
    # v1.7 branch is reachable end-to-end from an exported-JSON body.
    synthetic_mcp_v17_event = dict(
        schema_version='v1.7',
        event_kind='mcp_tool_call',
        timestamp_utc=ts_1760.replace('+00:00', 'Z'),
        event_id='evt-mcp-fixture', request_id='req-mcp-fixture',
        model_requested='', action='allow', input_tokens=0, output_tokens=0,
        mcp_event=dict(_V1_7_MCP_TOOL_CALL_FIXTURE_PAYLOAD),
    )
    got_v17_loop = recompute_event_hash(synthetic_mcp_v17_event, 11, 'prev-fixture')
    if got_v17_loop == V1_7_MCP_TOOL_CALL_FIXTURE_HASH:
        print('SELF-TEST assertion 15b PASS: verify_manifest recompute path handles v1.7 mcp.tool_call')
    else:
        print('SELF-TEST assertion 15b FAIL: recompute_event_hash mis-hashes v1.7 mcp.tool_call', file=sys.stderr)
        print(f'  expected: {V1_7_MCP_TOOL_CALL_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v17_loop}', file=sys.stderr)
        ok = False

    # MEI-1063 Assertion 15c — v1.7 HOLD policy_decision fixture via the direct
    # compute function. Cross-pinned with the Rust
    # mei1063_v1_7_hold_fixture_hash_pinned literal. The structural inverse of
    # 15a: hold_id set, both redaction hashes absent.
    got_v17_hold = compute_event_hash_v1_7_mcp(
        EVENT_KIND_MCP_POLICY_DECISION,
        mcp_event=_V1_7_MCP_HOLD_FIXTURE_PAYLOAD, **mcp_fixture_args
    )
    if got_v17_hold == V1_7_MCP_HOLD_FIXTURE_HASH:
        print('SELF-TEST assertion 15c PASS: v1.7 mcp.policy_decision (hold) fixture hash matches')
    else:
        print('SELF-TEST assertion 15c FAIL: v1.7 mcp hold fixture drift', file=sys.stderr)
        print(f'  expected: {V1_7_MCP_HOLD_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v17_hold}', file=sys.stderr)
        ok = False

    # MEI-1063 Assertion 15d — the same v1.7 hold fixture recomputed through the
    # production recompute_event_hash path (schema_version='v1.7' dispatch,
    # nested mcp_event carrying the hold_id). Confirms the hold record is
    # reachable end-to-end from an exported-JSON body.
    synthetic_mcp_hold_event = dict(
        schema_version='v1.7',
        event_kind='mcp_policy_decision',
        timestamp_utc=ts_1760.replace('+00:00', 'Z'),
        event_id='evt-mcp-fixture', request_id='req-mcp-fixture',
        model_requested='', action='allow', input_tokens=0, output_tokens=0,
        mcp_event=dict(_V1_7_MCP_HOLD_FIXTURE_PAYLOAD),
    )
    got_v17_hold_loop = recompute_event_hash(synthetic_mcp_hold_event, 11, 'prev-fixture')
    if got_v17_hold_loop == V1_7_MCP_HOLD_FIXTURE_HASH:
        print('SELF-TEST assertion 15d PASS: verify_manifest recompute path handles v1.7 mcp hold')
    else:
        print('SELF-TEST assertion 15d FAIL: recompute_event_hash mis-hashes v1.7 mcp hold', file=sys.stderr)
        print(f'  expected: {V1_7_MCP_HOLD_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v17_hold_loop}', file=sys.stderr)
        ok = False

    # MEI-1955 Assertion 16a — v1.8 coverage.computed fixture (direct fn),
    # paired with the Rust mei1955_v1_8_coverage_fixture_hash_pinned literal in
    # meilynx-audit/tests/mei1955_coverage_chain_round_trip.rs.
    got_v18 = compute_event_hash_v1_8_coverage(
        sequence_number=7, timestamp_utc=ts_1760, event_id='evt-fixture',
        request_id='req-fixture', model_requested='', action='allow',
        input_tokens=0, output_tokens=0, total_tokens=None,
        cache_creation_input_tokens=None, cache_read_input_tokens=None,
        cached_input_tokens=None, reasoning_tokens=None,
        estimated_cost_usd=None, previous_hash='prev-fixture',
        coverage=_V1_8_COVERAGE_FIXTURE_PAYLOAD,
    )
    if got_v18 == V1_8_COVERAGE_COMPUTED_FIXTURE_HASH:
        print('SELF-TEST assertion 16a PASS: v1.8 coverage.computed fixture hash matches')
    else:
        print('SELF-TEST assertion 16a FAIL: v1.8 coverage.computed fixture drift', file=sys.stderr)
        print(f'  expected: {V1_8_COVERAGE_COMPUTED_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v18}', file=sys.stderr)
        ok = False

    # MEI-1955 Assertion 16b — the same v1.8 event recomputed through
    # recompute_event_hash (the production path verify_manifest walks) from a
    # synthetic exported-JSON body: event_kind in serde snake_case
    # ('coverage_computed'), Z-suffix timestamp, nested coverage payload — the
    # MEI-1096 regression class applied to the v1.8 bucket.
    synthetic_coverage_event = dict(
        schema_version='v1.8',
        event_kind='coverage_computed',
        timestamp_utc=ts_1760.replace('+00:00', 'Z'),
        event_id='evt-fixture', request_id='req-fixture', model_requested='',
        action='allow', input_tokens=0, output_tokens=0,
        coverage=dict(_V1_8_COVERAGE_FIXTURE_PAYLOAD),
    )
    got_v18_loop = recompute_event_hash(synthetic_coverage_event, 7, 'prev-fixture')
    if got_v18_loop == V1_8_COVERAGE_COMPUTED_FIXTURE_HASH:
        print('SELF-TEST assertion 16b PASS: verify_manifest recompute path handles v1.8 coverage.computed')
    else:
        print('SELF-TEST assertion 16b FAIL: recompute_event_hash mis-hashes v1.8 coverage.computed', file=sys.stderr)
        print(f'  expected: {V1_8_COVERAGE_COMPUTED_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v18_loop}', file=sys.stderr)
        ok = False

    # MEI-2151 Assertion 17a — v1.9 llm_request fixture (direct fn), paired
    # with the Rust mei2151_v1_9_llm_request_fixture_hash_pinned literal.
    got_v19_llm = compute_event_hash_v1_9_llm_request(
        timestamp_utc="2026-05-17T00:00:00+00:00",
        join_context=_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD,
        **_FIXTURE,
    )
    if got_v19_llm == V1_9_LLM_REQUEST_FIXTURE_HASH:
        print('SELF-TEST assertion 17a PASS: v1.9 llm_request fixture hash matches')
    else:
        print('SELF-TEST assertion 17a FAIL: v1.9 llm_request fixture drift', file=sys.stderr)
        print(f'  expected: {V1_9_LLM_REQUEST_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v19_llm}', file=sys.stderr)
        ok = False

    # MEI-2151 Assertion 17b — the same v1.9 LLM event through the production
    # recompute path from a synthetic exported-JSON body (MEI-1096 class).
    synthetic_llm_v19_event = dict(
        schema_version='v1.9',
        event_kind='llm_request',
        timestamp_utc='2026-05-17T00:00:00Z',
        event_id=_FIXTURE['event_id'], request_id=_FIXTURE['request_id'],
        model_requested=_FIXTURE['model_requested'], action=_FIXTURE['action'],
        input_tokens=_FIXTURE['input_tokens'], output_tokens=_FIXTURE['output_tokens'],
        total_tokens=_FIXTURE['total_tokens'],
        estimated_cost_usd=_FIXTURE['estimated_cost_usd'],
        join_context=dict(_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD),
    )
    got_v19_llm_loop = recompute_event_hash(
        synthetic_llm_v19_event, _FIXTURE['sequence_number'], _FIXTURE['previous_hash'])
    if got_v19_llm_loop == V1_9_LLM_REQUEST_FIXTURE_HASH:
        print('SELF-TEST assertion 17b PASS: verify_manifest recompute path handles v1.9 llm_request')
    else:
        print('SELF-TEST assertion 17b FAIL: recompute_event_hash mis-hashes v1.9 llm_request', file=sys.stderr)
        print(f'  expected: {V1_9_LLM_REQUEST_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v19_llm_loop}', file=sys.stderr)
        ok = False

    # MEI-2151 Assertion 17c — v1.9 mcp.tool_call fixture (direct fn), paired
    # with the Rust mei2151_v1_9_mcp_tool_call_fixture_hash_pinned literal.
    # Built on the v1.7 ENFORCEMENT payload on purpose: it proves v1.9 carries
    # both the v1.6 capture axis and the v1.7 enforcement axis forward rather
    # than replacing them.
    got_v19_mcp = compute_event_hash_v1_9_mcp(
        EVENT_KIND_MCP_TOOL_CALL,
        mcp_event=_V1_7_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
        join_context=_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD,
        **mcp_fixture_args
    )
    if got_v19_mcp == V1_9_MCP_TOOL_CALL_FIXTURE_HASH:
        print('SELF-TEST assertion 17c PASS: v1.9 mcp.tool_call fixture hash matches')
    else:
        print('SELF-TEST assertion 17c FAIL: v1.9 mcp.tool_call fixture drift', file=sys.stderr)
        print(f'  expected: {V1_9_MCP_TOOL_CALL_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v19_mcp}', file=sys.stderr)
        ok = False

    # MEI-2151 Assertion 17d — the same v1.9 MCP event through the production
    # recompute path from a synthetic exported-JSON body (MEI-1096 class).
    synthetic_mcp_v19_event = dict(
        schema_version='v1.9',
        event_kind='mcp_tool_call',
        timestamp_utc=ts_1760.replace('+00:00', 'Z'),
        event_id='evt-mcp-fixture', request_id='req-mcp-fixture',
        model_requested='', action='allow', input_tokens=0, output_tokens=0,
        mcp_event=dict(_V1_7_MCP_TOOL_CALL_FIXTURE_PAYLOAD),
        join_context=dict(_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD),
    )
    got_v19_mcp_loop = recompute_event_hash(synthetic_mcp_v19_event, 11, 'prev-fixture')
    if got_v19_mcp_loop == V1_9_MCP_TOOL_CALL_FIXTURE_HASH:
        print('SELF-TEST assertion 17d PASS: verify_manifest recompute path handles v1.9 mcp.tool_call')
    else:
        print('SELF-TEST assertion 17d FAIL: recompute_event_hash mis-hashes v1.9 mcp.tool_call', file=sys.stderr)
        print(f'  expected: {V1_9_MCP_TOOL_CALL_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v19_mcp_loop}', file=sys.stderr)
        ok = False

    # MEI-2151 Assertion 17e — the fail-closed invariant: a join_context on any
    # bucket other than v1.9 is a hard error, not a silently-unhashed field.
    # Mirror of the Rust dispatcher guard. This is the assertion that would
    # have caught the original defect class had it existed: a join key sealed
    # into evidence without entering the preimage.
    for stale_version in ('v1', 'v1.1', 'v1.2', 'v1.7'):
        try:
            compute_event_hash_dispatch(
                stale_version,
                42, '2026-05-17T00:00:00+00:00', 'e', 'r', 'm', 'Allow', 0, 0,
                None, None, None, None, None, None, 'prev',
                join_context=_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD,
            )
        except ValueError:
            pass
        else:
            print(
                f'SELF-TEST assertion 17e FAIL: dispatcher accepted a join_context '
                f'on {stale_version} — the join key would ride unhashed',
                file=sys.stderr,
            )
            ok = False
    else:
        print('SELF-TEST assertion 17e PASS: join_context outside v1.9 is rejected')

    return ok


# MEI-639 — v1.2 fixture hashes. Pinned in BOTH this Python file and
# the Rust drift_catchers.rs (and verify-pack.py in meilynx-platform per
# MEI-492). If you change the v1.2 encoding, update all three. The
# legacy v1 FIXTURE_HASH above stays at ba7a7f3d… (the v1 path is
# frozen; no encoding change can ever bump it).
V1_2_LLM_REQUEST_FIXTURE_HASH = "5f85e27ee519003176c2acb8dd287a9c9dfdd1ba0cc41ec3c92e1c56c9869456"
V1_2_AUTH_SESSION_STARTED_FIXTURE_HASH = "1f3d58eaaf32e85fa96105e66a71943de4ce865d64d896ef1f4afde25aeea7af"
# MEI-1048 — v1.3 admin.action fixture. Paired with
# meilynx-audit/tests/mei1048_admin_chain_round_trip.rs::mei1048_v1_3_admin_action_fixture_hash_pinned;
# neither side may drift independently.
V1_3_ADMIN_ACTION_FIXTURE_HASH = "eb3899be87ed811f84b5616289f0b3dde43344359ca5d772bcb6637d02fb11ea"
# MEI-925 — v1.4 mcp.* fixtures. Paired with
# meilynx-audit/tests/mei925_mcp_chain_round_trip.rs::mei925_v1_4_*_fixture_hash_pinned;
# neither side may drift independently.
V1_4_MCP_TOOL_CALL_FIXTURE_HASH = "3563b67d9185df93bf551fec5d2b4e7db82513dcd2805d4708f69958aa6f5525"
V1_4_MCP_POLICY_DECISION_FIXTURE_HASH = "c6f953f0cbd417e335aa79420786ec54ec6dcb5a244d9d38228977e5fab491a2"
V1_4_MCP_ERROR_FIXTURE_HASH = "58d66632c7d40c54c6ae6befa21893789e098ed66afb9e9d109babe904bcc1d3"
_V1_4_MCP_TOOL_CALL_FIXTURE_PAYLOAD = dict(
    virtual_server='crm',
    upstream_slug='crm',
    method='tools/call',
    tool_name='crm__lookup_account',
    jsonrpc_id='42',
    protocol_version='2026-07-28',
    decision=None,
    reason=None,
    payload_sha256_jcs='9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    mcp_bundle_sha256='2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    correlated_event_id=None,
    error_code=None,
    traceparent='00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
)
_V1_4_MCP_DECISION_FIXTURE_PAYLOAD = dict(
    _V1_4_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
    decision='allow',
    reason='passthrough_p1',
    payload_sha256_jcs=None,
    correlated_event_id='evt-mcp-fixture',
)
_V1_4_MCP_ERROR_FIXTURE_PAYLOAD = dict(
    _V1_4_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
    tool_name=None,
    payload_sha256_jcs=None,
    reason='upstream_unreachable',
    correlated_event_id='evt-mcp-fixture',
    error_code=-32000,
)
# MEI-804 — v1.5 mcp.* fixtures. Paired with
# meilynx-audit/tests/mei925_mcp_chain_round_trip.rs::mei925_v1_5_*_fixture_hash_pinned
# (and the bare-agent pin); neither side may drift independently. v1.5 = v1.4
# preimage + the principal chain, so the payloads add `principal_chain` and the
# hashes differ from the v1.4 pins above.
V1_5_MCP_TOOL_CALL_FIXTURE_HASH = "e9eb51fb403f4a270f56a303e626334cf80fdd4cd55ca55b61d251b3264a8e99"
V1_5_MCP_POLICY_DECISION_FIXTURE_HASH = "78f277e6691936ae7668442b0994762d49507c960b67d1486eac57daeeca0c58"
V1_5_MCP_ERROR_FIXTURE_HASH = "9e03b31f64d8131e12a7d02684d4e548f6f190a5c78ba0e15daa76356718e8ff"
V1_5_MCP_BARE_AGENT_FIXTURE_HASH = "49db2fe1ef86c3348d68d7a6401584185331aa98631dd1aec03c56ecf043863c"
# The on-behalf-of chain exercises every principal-chain branch: agent leg
# (tag 2 + agent_ref), on_behalf_of present (tag 1), human leg (tag 1 +
# subject + issuer present). Mirror of `fixture_principal_chain()` in the Rust
# test.
_FIXTURE_PRINCIPAL_CHAIN = dict(
    authenticated=dict(kind='agent', agent_ref='pk:0123456789abcdef'),
    on_behalf_of=dict(kind='human_user', subject='user-alice', issuer='https://idp.example'),
)
# The bare-agent chain exercises the absent branches (on_behalf_of None, no
# issuer). Mirror of `fixture_bare_agent_chain()`.
_FIXTURE_BARE_AGENT_CHAIN = dict(
    authenticated=dict(kind='agent', agent_ref='pk:0123456789abcdef'),
    on_behalf_of=None,
)
_V1_5_MCP_TOOL_CALL_FIXTURE_PAYLOAD = dict(
    _V1_4_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
    principal_chain=_FIXTURE_PRINCIPAL_CHAIN,
)
_V1_5_MCP_DECISION_FIXTURE_PAYLOAD = dict(
    _V1_4_MCP_DECISION_FIXTURE_PAYLOAD,
    principal_chain=_FIXTURE_PRINCIPAL_CHAIN,
)
_V1_5_MCP_ERROR_FIXTURE_PAYLOAD = dict(
    _V1_4_MCP_ERROR_FIXTURE_PAYLOAD,
    principal_chain=_FIXTURE_PRINCIPAL_CHAIN,
)
_V1_5_MCP_BARE_AGENT_FIXTURE_PAYLOAD = dict(
    _V1_4_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
    principal_chain=_FIXTURE_BARE_AGENT_CHAIN,
)
# MEI-1189 — v1.6 mcp.* fixture. Paired with
# meilynx-audit/tests/mei925_mcp_chain_round_trip.rs::mei1189_v1_6_redacted_tool_call_fixture_hash_pinned;
# neither side may drift independently. v1.6 = v1.5 preimage + the redacted
# content address, so the payload adds `redacted_payload_sha256_jcs` and the
# hash differs from the v1.5 pins above. `payload_sha256_jcs` (the ORIGINAL
# hash) stays set — the two-hash binding rides the preimage.
V1_6_MCP_TOOL_CALL_FIXTURE_HASH = "d64fc79d7f60c8355d30f5ab17679ac389117cbb1d08d1e285b928d127328709"
_V1_6_MCP_TOOL_CALL_FIXTURE_PAYLOAD = dict(
    _V1_5_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
    redacted_payload_sha256_jcs='5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef',
)
# MEI-1063 — v1.7 mcp.* enforcement (redact) fixture. Paired with
# meilynx-audit/tests/mei925_mcp_chain_round_trip.rs::mei1063_v1_7_enforcement_tool_call_fixture_hash_pinned;
# neither side may drift independently. v1.7 = v1.6 preimage + the three
# enforcement-axis fields (two redaction hashes + hold_id). The payload builds
# on the v1.5 tool_call base (redacted_payload absent → the capture axis stays
# None, mutually exclusive with the enforcement axis) and adds the two
# enforcement digests; hold_id stays absent (a redact record, not a hold). The
# two 64-hex values mirror the Rust FIXTURE_REDACTION_PRE/POST constants; their
# exact values are arbitrary — they pin the encoding only.
V1_7_MCP_TOOL_CALL_FIXTURE_HASH = "db08c9a2da429f2ff484f8803515d4a3a7693af31a386abcbc3b7e6ec6bad97c"
_V1_7_MCP_TOOL_CALL_FIXTURE_PAYLOAD = dict(
    _V1_5_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
    redaction_pre_sha256_jcs='0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f',
    redaction_post_sha256_jcs='f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0',
)
# MEI-1063 — v1.7 mcp.* HOLD fixture. Paired with
# meilynx-audit/tests/mei925_mcp_chain_round_trip.rs::mei1063_v1_7_hold_fixture_hash_pinned;
# neither side may drift independently. The structural inverse of the redact
# fixture: hold_id is set, both redaction hashes stay absent (a hold is a
# suspension — no forwarded content was transformed). Uses the policy_decision
# kind and the require_approval decision/reason the proxy seals on a held call.
V1_7_MCP_HOLD_FIXTURE_HASH = "d2939297294de47066bb7ae7782d563cca640e2bc40f1fc3820fb87ff81135c9"
_V1_7_MCP_HOLD_FIXTURE_PAYLOAD = dict(
    _V1_5_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
    decision='require_approval',
    reason='rbac_require_approval_hold:rule-42',
    correlated_event_id='evt-mcp-fixture',
    hold_id='hold-0123456789abcdef0123456789abcdef',
)
_V1_3_ADMIN_FIXTURE_PAYLOAD = dict(
    action_type="encryption_key_rotated",
    actor="internal-key:ab12",
    description="rotated audit encryption key",
    metadata_json='{"key_version":"3"}',
)
# MEI-1955 — v1.8 coverage.computed fixture. Paired with
# meilynx-audit/tests/mei1955_coverage_chain_round_trip.rs::mei1955_v1_8_coverage_fixture_hash_pinned;
# neither side may drift independently.
V1_8_COVERAGE_COMPUTED_FIXTURE_HASH = "0a8cbfc4c91c111f11d4ce404d8c20ecfdcca076e74de380565448d19800652e"
_V1_8_COVERAGE_FIXTURE_PAYLOAD = dict(
    provider='openai',
    day='2026-08-18',
    tier='A',
    reconciliation_unit='requests',
    proxy_attributed=980,
    provider_reported=1000,
    delta_classification='bypass_signal',
    bypass_rate_ppm=20000,
    tolerance_band_json='{"relative":0.02,"unit":"requests"}',
    claim_language_key='coverage.tier_a.org_administered_accounts',
    registry_version='2026.08.20-1',
    numerator_source='instance_sqlite',
    denominator_fetched_at='2026-08-19T01:00:00Z',
)
# MEI-2151 — v1.9 fixtures: the caller-asserted cross-lane join keys appended
# to the v1.2-LlmRequest and v1.7-mcp preimages. Paired with
# meilynx-audit/tests/mei2151_join_context_chain_round_trip.rs; neither side
# may drift independently.
#
# The payload deliberately sets only two of the three fields: a real caller
# very often sends `correlation_id` alone, and the fixture must pin the
# encoding of an ABSENT field (the 1-byte presence tag) as much as a present
# one — that is the byte the whole presence-gated design rests on.
_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD = dict(
    correlation_id='corr-0123456789abcdef',
    session_id='sess-fedcba9876543210',
)
V1_9_LLM_REQUEST_FIXTURE_HASH = "7b48689b1658d27c27e149d182297cfd10a168769e50097a482e7dbebbefaf0a"
V1_9_MCP_TOOL_CALL_FIXTURE_HASH = "d6a68730a4ad2aa3e2ddb8c1534e1f22ff4a5b99a0bce678fdfd5bc12d0e2a14"

_V1_2_AUTH_FIXTURE_PAYLOAD = dict(
    user_email="cassio@meilynx.com",
    user_id="9382725d-3bc4-4c88-9655-3f743b0e13f9",
    project_id="proj-fixture-001",
    proxy_id="pxy_fixture001",
    session_expires_at=1748655920,
    identity_provenance="meilynx-cp-handoff",
    jti="ffffffff-0000-0000-0000-000000000042",
    signing_key_fingerprint="abcd",
)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def action_str(event):
    """
    Extract the action string from the stored event JSON.
    GovernanceAction serializes as a string: "Allow", "Warn", "Redact",
    "MaskOutput", "Block".
    """
    a = event.get('action', 'Allow')
    if isinstance(a, str):
        return a
    mapping = {0: 'Allow', 1: 'Warn', 2: 'Redact', 3: 'MaskOutput', 4: 'Block'}
    return mapping.get(a, 'Allow')


def recompute_event_hash(event, seq, previous_hash):
    """MEI-1096 — recompute one event's hash from its exported WORM JSON,
    dispatching on schema_version + event_kind exactly as the Rust writer /
    verifier does (compute_event_hash_dispatch in sqlite.rs).

    THIS is the production recompute path verify_manifest walks. Before
    MEI-1096 the record loop called the frozen v1 `compute_event_hash`
    unconditionally, so every v1.2 auth.session_started and v1.3 admin.action
    event in a real pack failed verification even though the chain was intact
    — the reproducer's own self-test exercised the dispatch functions but not
    this loop (MEI-618 class: the test never traversed the production path).
    run_self_test now drives THIS helper with synthetic v1.2/v1.3 events.
    """
    ts = normalize_timestamp(event.get('timestamp_utc', ''))
    schema_version = event.get('schema_version') or 'v1'
    serde_kind = event.get('event_kind')  # None → default LlmRequest (field omitted)
    if serde_kind not in SERDE_EVENT_KIND_TO_WIRE:
        raise ValueError(
            f"MEI-1096: unknown event_kind {serde_kind!r} in exported event — "
            f"this reproducer has no hash branch for it. Update verify-pack.py."
        )
    return compute_event_hash_dispatch(
        schema_version,
        seq, ts,
        event.get('event_id', ''),
        event.get('request_id', ''),
        event.get('model_requested', ''),
        action_str(event),
        int(event.get('input_tokens', 0)),
        int(event.get('output_tokens', 0)),
        event.get('total_tokens'),
        event.get('cache_creation_input_tokens'),
        event.get('cache_read_input_tokens'),
        event.get('cached_input_tokens'),
        event.get('reasoning_tokens'),
        event.get('estimated_cost_usd'),
        previous_hash,
        event_kind=SERDE_EVENT_KIND_TO_WIRE[serde_kind],
        auth_session=event.get('auth_session'),
        admin_action=event.get('admin_action'),
        mcp_event=event.get('mcp_event'),
        coverage=event.get('coverage'),
        join_context=event.get('join_context'),
    )


def record_file_name(seq):
    """Object / file name of one chain record: `<seq:020d>.bin`, the same
    layout the WORM bucket uses under the chain prefix. An offline records
    directory mirrors that layout so a bucket listing can be copied 1:1."""
    return f"{seq:020d}.bin"


def gcs_fetcher(bucket_name, prefix, storage_client):
    """Return `fetch(seq) -> bytes` that reads `<prefix><seq>.bin` from GCS
    (CMEK decrypts transparently for a principal with storage.objects.get)."""
    bucket = storage_client.bucket(bucket_name)

    def fetch(seq):
        return bucket.blob(f"{prefix}{record_file_name(seq)}").download_as_bytes()

    return fetch


def local_fetcher(records_path):
    """Return `fetch(seq) -> bytes` that reads chain records from disk, with
    no network and no Google client library — the path an examiner or a
    third-party reviewer runs when they were handed the records alongside
    the manifest.

    `records_path` is either:
      - a directory holding one file per record named `<seq:020d>.bin` (or
        `.json`), exactly as exported from the bucket; or
      - a single `.jsonl` file (one record per line) / `.json` file (an
        array of records), each record carrying its own `sequence_number`.
    """
    path = Path(records_path)
    if path.is_dir():
        def fetch(seq):
            for name in (record_file_name(seq), f"{seq:020d}.json"):
                candidate = path / name
                if candidate.exists():
                    return candidate.read_bytes()
            raise FileNotFoundError(f"no record file for seq={seq} under {path}")
        return fetch

    if not path.exists():
        raise FileNotFoundError(f"records path not found: {path}")

    text = path.read_text(encoding='utf-8')
    if path.suffix.lower() == '.jsonl':
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        loaded = json.loads(text)
        records = loaded if isinstance(loaded, list) else loaded.get('records', [])
    by_seq = {}
    for rec in records:
        if 'sequence_number' not in rec:
            raise ValueError("every record in a JSON/JSONL records file needs a sequence_number")
        by_seq[int(rec['sequence_number'])] = json.dumps(rec).encode('utf-8')

    def fetch(seq):
        if seq not in by_seq:
            raise FileNotFoundError(f"no record for seq={seq} in {path}")
        return by_seq[seq]

    return fetch


def exporting_fetcher(fetch, export_dir):
    """Wrap `fetch` so every record body it returns is also written to
    `export_dir/<seq:020d>.bin` — the way to hand a verified chain to a
    reviewer who has no bucket access (they then run `--records export_dir`)."""
    out = Path(export_dir)
    out.mkdir(parents=True, exist_ok=True)

    def fetch_and_export(seq):
        raw = fetch(seq)
        (out / record_file_name(seq)).write_bytes(raw)
        return raw

    return fetch_and_export


def verify_manifest(bucket_name, manifest, storage_client):
    """Walk each event in the manifest, re-fetch from GCS, recompute hash."""
    prefix = manifest.get('prefix', 'audit/')
    return verify_manifest_with(gcs_fetcher(bucket_name, prefix, storage_client), manifest)


def verify_manifest_with(fetch, manifest, quiet=False):
    """Walk each event in the manifest, fetch its record through `fetch(seq)`,
    recompute the hash and check the chain linkage. Source-agnostic: `fetch`
    is the only thing that differs between the GCS and the offline path, so
    both walk the identical verification loop."""
    hash_version = manifest.get('hash_version', '')
    if hash_version not in SUPPORTED_HASH_VERSIONS:
        print(
            f"ERROR: This reproducer supports hash_version {SUPPORTED_HASH_VERSIONS}. "
            f"The manifest specifies '{hash_version}'. Re-run with the updated reproducer.",
            file=sys.stderr,
        )
        sys.exit(2)

    genesis = genesis_hash()
    expected_prev_hash = genesis

    all_passed = True
    events_in_manifest = manifest.get('events', [])
    if not events_in_manifest:
        print("WARN: manifest.events is empty — nothing to verify.")
        return True

    def report(line):
        if not quiet:
            print(line)

    for entry in sorted(events_in_manifest, key=lambda e: e['sequence']):
        seq = entry['sequence']

        try:
            raw = fetch(seq)
        except Exception as exc:
            report(f"FAIL seq={seq}: record fetch error: {exc}")
            all_passed = False
            continue

        try:
            event = json.loads(raw)
        except Exception as exc:
            report(f"FAIL seq={seq}: JSON parse error: {exc}")
            all_passed = False
            continue

        stored_prev = event.get('previous_hash', '')
        stored_hash = event.get('event_hash', '')

        # MEI-1096 — dispatch on the event's own schema_version + event_kind
        # (v1/v1.1 llm, v1.2 auth, v1.3 admin), the same recompute path
        # run_self_test exercises. Timestamp normalization + action extraction
        # happen inside recompute_event_hash.
        try:
            recomputed = recompute_event_hash(event, seq, stored_prev)
        except ValueError as exc:
            report(f"FAIL seq={seq}: {exc}")
            all_passed = False
            continue

        hash_ok = (recomputed == stored_hash)
        chain_ok = (stored_prev == expected_prev_hash)

        manifest_recomputed = entry.get('recomputed_event_hash', '')
        if manifest_recomputed and recomputed != manifest_recomputed:
            report(
                f"FAIL seq={seq}: hash recomputation disagrees with manifest. "
                f"Our: {recomputed[:16]}... Manifest: {manifest_recomputed[:16]}..."
            )
            all_passed = False
            continue

        if hash_ok and chain_ok:
            report(f"PASS seq={seq} hash={stored_hash[:16]}... chain_ok")
        else:
            if not hash_ok:
                report(
                    f"FAIL seq={seq}: hash mismatch. "
                    f"stored={stored_hash[:16]}... recomputed={recomputed[:16]}..."
                )
            if not chain_ok:
                report(
                    f"FAIL seq={seq}: chain break. "
                    f"previous_hash={stored_prev[:16]}... expected={expected_prev_hash[:16]}..."
                )
            all_passed = False

        expected_prev_hash = recomputed if hash_ok else stored_hash

    return all_passed


def offline_self_test():
    """Exercise the offline (`--records`) path end to end on a synthetic
    two-record v1 chain: a clean chain verifies, a one-byte tamper to the
    first record's token count fails at that record AND breaks linkage at
    the next. Runs with no network and no Google client library, so a
    reviewer can confirm the offline verifier itself works before trusting
    its verdict on a real pack."""
    import tempfile

    genesis = genesis_hash()

    def make_event(seq, prev, input_tokens):
        event = {
            'schema_version': 'v1',
            'sequence_number': seq,
            'timestamp_utc': f'2026-01-01T00:00:0{seq}+00:00',
            'event_id': f'evt-{seq}',
            'request_id': f'req-{seq}',
            'model_requested': 'gpt-4.1-mini',
            'action': 'allow',
            'input_tokens': input_tokens,
            'output_tokens': 7,
            'total_tokens': input_tokens + 7,
            'cache_creation_input_tokens': None,
            'cache_read_input_tokens': None,
            'cached_input_tokens': None,
            'reasoning_tokens': None,
            'estimated_cost_usd': 0.000123,
            'previous_hash': prev,
        }
        event['event_hash'] = recompute_event_hash(event, seq, prev)
        return event

    first = make_event(0, genesis, 11)
    second = make_event(1, first['event_hash'], 13)
    manifest = {
        'hash_version': 'v1',
        'prefix': 'audit/self-test/',
        'events': [
            {'sequence': 0, 'recomputed_event_hash': first['event_hash']},
            {'sequence': 1, 'recomputed_event_hash': second['event_hash']},
        ],
    }

    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        records = Path(tmp) / 'records'
        records.mkdir()
        for ev in (first, second):
            (records / record_file_name(ev['sequence_number'])).write_bytes(json.dumps(ev).encode('utf-8'))

        clean = verify_manifest_with(local_fetcher(records), manifest, quiet=True)
        print(f"SELF-TEST assertion 18a {'PASS' if clean else 'FAIL'}: offline records directory verifies a clean chain")
        ok = ok and clean

        # JSONL form of the same chain must verify identically.
        jsonl = Path(tmp) / 'records.jsonl'
        jsonl.write_text('\n'.join(json.dumps(ev) for ev in (first, second)) + '\n', encoding='utf-8')
        clean_jsonl = verify_manifest_with(local_fetcher(jsonl), manifest, quiet=True)
        print(f"SELF-TEST assertion 18b {'PASS' if clean_jsonl else 'FAIL'}: offline JSONL records file verifies a clean chain")
        ok = ok and clean_jsonl

        # Tamper: change one hashed field of record 0 after the fact. The
        # stored hash no longer matches, and record 1's previous_hash no
        # longer links to what record 0 now hashes to.
        tampered = dict(first)
        tampered['input_tokens'] = 12
        (records / record_file_name(0)).write_bytes(json.dumps(tampered).encode('utf-8'))
        detected = not verify_manifest_with(local_fetcher(records), manifest, quiet=True)
        print(f"SELF-TEST assertion 18c {'PASS' if detected else 'FAIL'}: offline verification detects a tampered record")
        ok = ok and detected

        # A missing record is a failure, never a silent skip.
        (records / record_file_name(1)).unlink()
        missing = not verify_manifest_with(local_fetcher(records), manifest, quiet=True)
        print(f"SELF-TEST assertion 18d {'PASS' if missing else 'FAIL'}: offline verification fails on a missing record")
        ok = ok and missing

    return ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Meilynx Integrity Pack reproducer — independently verifies GCS WORM audit chain.'
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--bucket', help='GCS bucket name (no gs:// prefix) — online mode')
    source.add_argument(
        '--records',
        help=(
            'Offline mode: a directory of exported chain records (<seq:020d>.bin), '
            'or a .jsonl / .json file of records. No network, no Google client library.'
        ),
    )
    parser.add_argument('--manifest', help='Path to manifest.json')
    parser.add_argument(
        '--export-records',
        metavar='DIR',
        help=(
            'Online mode only: also write every fetched record to DIR/<seq:020d>.bin, '
            'so the verified chain can be handed to a reviewer who has no bucket access '
            '(they then run --records DIR).'
        ),
    )
    parser.add_argument(
        '--self-test',
        action='store_true',
        help=(
            'Run encoding self-test against the substrate fixture hashes and exit. '
            'Exercises both the +00:00 fixture and the Z-suffix normalization path, '
            'and the offline --records path on a synthetic chain.'
        ),
    )
    args = parser.parse_args()

    if args.self_test:
        ok = run_self_test()
        ok = offline_self_test() and ok
        sys.exit(0 if ok else 1)

    if not (args.bucket or args.records) or not args.manifest:
        parser.error("--manifest plus one of --bucket / --records is required (or use --self-test)")
    if args.export_records and not args.bucket:
        parser.error("--export-records only applies with --bucket")

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"ERROR: manifest not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    if args.records:
        try:
            fetch = local_fetcher(args.records)
        except (FileNotFoundError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
        print(f"Offline verification: records from {args.records}")
    else:
        try:
            from google.cloud import storage as gcs
        except ImportError:
            print(
                "ERROR: google-cloud-storage not installed. Run: pip install google-cloud-storage "
                "(or verify offline with --records).",
                file=sys.stderr,
            )
            sys.exit(1)

        fetch = gcs_fetcher(args.bucket, manifest.get('prefix', 'audit/'), gcs.Client())
        if args.export_records:
            fetch = exporting_fetcher(fetch, args.export_records)

    passed = verify_manifest_with(fetch, manifest)

    if passed:
        print(f"\nOK: all {len(manifest.get('events', []))} events verified.")
        sys.exit(0)
    else:
        print("\nFAIL: one or more events failed verification.", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
