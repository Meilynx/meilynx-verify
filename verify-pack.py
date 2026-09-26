#!/usr/bin/env python3
"""
Meilynx Integrity Pack verifier (MEI-422; signed packs MEI-922).

Independently re-fetches each audit event from GCS and recomputes its
SHA-256 chain hash using the same 15-field encoding as the Rust substrate
(meilynx-proxy/crates/meilynx-audit/src/sqlite.rs::compute_event_hash).
On a signed (window B) pack it also verifies the signature over
manifest.json, using the Python standard library only.

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

Signed packs (window B):
    A signed pack carries `manifest.json.sigstore.json` next to
    manifest.json: a Sigstore bundle (media type v0.3) holding a cosign
    keyless signature over the exact bytes of manifest.json, the short-lived
    Fulcio signing certificate, and the Rekor v1 transparency-log entry with
    its signed entry timestamp, inclusion proof and signed checkpoint. The
    signature is checked before the records, offline, with no extra install.
    A manifest that says it is signed (window "B", or `signing_deferred` not
    true, or a `signature` descriptor) fails without a valid bundle.

    The signer must be the Meilynx signing workflow, dispatched from main:
        --certificate-identity     (default: PINNED_SIGNER_IDENTITY below)
        --certificate-oidc-issuer  (default: PINNED_OIDC_ISSUER below)
    The trust anchors (Fulcio CA certificates and the Rekor log key) are
    embedded below as SIGSTORE_PUBLIC_GOOD_TRUST_ROOT, copied from
    github.com/sigstore/root-signing targets/trusted_root.json (commit noted
    there). Pass `--trusted-root trusted_root.json` to use a copy you fetched
    and checked yourself instead. When Sigstore rotates an anchor, packs
    signed under the new one need a verifier release carrying it, or
    --trusted-root; packs signed under an embedded anchor keep verifying.

    Independent cross-check with cosign (optional; the same assertion):
        cosign verify-blob --bundle manifest.json.sigstore.json \\
            --certificate-identity <PINNED_SIGNER_IDENTITY> \\
            --certificate-oidc-issuer <PINNED_OIDC_ISSUER> manifest.json

Exit codes (the same in --bucket and --records mode; when several apply,
1 outranks 2, which outranks 3):
    0  verified: every record, and for a signed pack the signature. An
       unsigned pack exits 0 only with --allow-unsigned, and still prints
       that authenticity is not established.
    1  verification failed: a record (hash mismatch, chain break, missing or
       unreadable record, content check) or the signature, with the reason:
         signature required by manifest but missing
         manifest bytes changed since signing
         untrusted certificate chain
         signer identity mismatch
         OIDC issuer mismatch
         invalid transparency-log proof
         transparency-log entry does not match this signature
         signed outside certificate validity
         malformed signature material
    2  cannot evaluate: an unsupported hash_version, signature method or
       bundle format (update this verifier), an unusable --trusted-root, or
       a command-line usage error.
    3  unsigned pack: the chain verified, but no signature establishes who
       produced the manifest. Pass --allow-unsigned to accept it. A signed
       pack stripped of its signature and relabelled window A lands here,
       not at 0.

The GCS bucket uses CMEK encryption; decryption is handled transparently
by GCS when you authenticate with credentials that have storage.objects.get.

Self-test (encoding drift check):
  Run `python verify-pack.py --self-test` to check the encoding against the
  substrate's reference values. Exercises both the +00:00 fixture and the
  Z-suffix normalization path, the offline --records path, and the
  signature checks (ECDSA test vectors, a synthetic signed pack with one
  tampered variant per failure reason, and a real Sigstore public-good
  bundle). Should always pass; if it fails, the verifier has drifted.
"""

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

GENESIS_STRING = "meilynx-genesis-v1"
SUPPORTED_HASH_VERSIONS = {"v1"}

# Exit codes (listed in the module docstring).
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_CANNOT_EVALUATE = 2
EXIT_UNSIGNED = 3

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


# ---------------------------------------------------------------------------
# MEI-2424 — RFC 8785 (JCS) canonical JSON, for the v1.10 content digests.
#
# The proxy computes `stored_prompt_sha256_jcs` / `findings_sha256_jcs` with
# serde_jcs over the record's own `messages` / `findings`. Recomputing them
# here is what lets this reproducer check that the content a record carries
# is the content it was sealed over. JCS is not "sorted keys, compact": keys
# sort by UTF-16 code units and numbers use the ECMAScript form (1.0 -> 1,
# 1e-7 -> 1e-7, 1e21 -> 1e+21), which is where a naive json.dumps diverges.
# ---------------------------------------------------------------------------

def _jcs_number(x):
    if isinstance(x, bool):
        raise ValueError('JCS: bool is not a number')
    if isinstance(x, int):
        if abs(x) < 2 ** 53:
            return str(x)
        x = float(x)
    if x != x or x in (float('inf'), float('-inf')):
        raise ValueError('JCS: NaN and infinities are not representable')
    if x == 0:
        return '0'
    sign = '-' if x < 0 else ''
    r = repr(abs(x))  # shortest round-trip digits, as ECMAScript uses
    mant, _, exp = r.partition('e')
    exp = int(exp) if exp else 0
    ip, _, fp = mant.partition('.')
    ip = ip.lstrip('0')
    if ip:
        n = len(ip) + exp
        digits = (ip + fp).rstrip('0')
    else:
        stripped = fp.lstrip('0')
        n = exp - (len(fp) - len(stripped))
        digits = stripped.rstrip('0')
    k = len(digits)
    if k <= n <= 21:
        out = digits + '0' * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + '.' + digits[n:]
    elif -6 < n <= 0:
        out = '0.' + '0' * (-n) + digits
    else:
        e = n - 1
        out = digits[0] + ('.' + digits[1:] if k > 1 else '') + 'e' + ('+' if e >= 0 else '-') + str(abs(e))
    return sign + out


def jcs_dumps(value):
    """RFC 8785 canonical form of a JSON value parsed by the json module."""
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return '[' + ','.join(jcs_dumps(v) for v in value) + ']'
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=lambda k: k.encode('utf-16-be'))
        return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + jcs_dumps(value[k]) for k in keys) + '}'
    raise ValueError(f'JCS: unsupported type {type(value).__name__}')


def sha256_jcs(value):
    return hashlib.sha256(jcs_dumps(value).encode('utf-8')).hexdigest()


def compute_event_hash_v1_10_llm_request(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    join_context, content,
):
    """MEI-2424 — v1.10 llm_request hash: the v1.9 layout (v1.2 prefix + kind
    + the three join keys, fed with presence tags even when no join key was
    asserted) followed by the six content-attestation fields in
    `LlmContentFields::HASH_FEED_ORDER`. `capture_policy` is a required
    string; the five digests are optional strings. Mirror of
    `compute_event_hash_v1_10_llm_request` in sqlite.rs.

    The prompt, response and findings stay outside the preimage; their
    digests are inside it. `check_llm_content` closes the loop by
    recomputing the stored digests from the record's own content."""
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(EVENT_KIND_LLM_REQUEST.encode('utf-8'))
    join = join_context or {}
    h.update(encode_optional_str(join.get('correlation_id')))
    h.update(encode_optional_str(join.get('session_id')))
    h.update(encode_optional_str(join.get('agent_name')))
    h.update(content['capture_policy'].encode('utf-8'))
    h.update(encode_optional_str(content.get('prompt_sha256_jcs')))
    h.update(encode_optional_str(content.get('response_sha256')))
    h.update(encode_optional_str(content.get('stored_prompt_sha256_jcs')))
    h.update(encode_optional_str(content.get('stored_response_sha256')))
    h.update(encode_optional_str(content.get('findings_sha256_jcs')))
    return h.hexdigest()


def check_llm_content(event):
    """MEI-2424 — for a v1.10 record, check that the content it carries is the
    content it was sealed over: the stored-prompt, stored-response and
    findings digests (all inside the hash) must match the record's own
    `messages`, `response_text` and `findings`. A digest that is absent means
    nothing was retained, so the record must carry no content on that axis.
    Returns a list of problems; empty means the content checks out. Records
    on older schema versions carry no digests and return no problems."""
    if (event.get('schema_version') or 'v1') != 'v1.10':
        return []
    content = event.get('content')
    if not isinstance(content, dict):
        return ['v1.10 record has no content payload']
    problems = []
    messages = event.get('messages') or []
    stored_prompt = content.get('stored_prompt_sha256_jcs')
    if stored_prompt is not None:
        if sha256_jcs(messages) != stored_prompt:
            problems.append('messages do not match stored_prompt_sha256_jcs (the prompt was changed after sealing)')
    elif messages:
        problems.append('messages present but no stored_prompt_sha256_jcs was sealed')
    response_text = event.get('response_text')
    stored_response = content.get('stored_response_sha256')
    if stored_response is not None:
        if response_text is None or hashlib.sha256(response_text.encode('utf-8')).hexdigest() != stored_response:
            problems.append('response_text does not match stored_response_sha256 (the response was changed after sealing)')
    elif response_text is not None:
        problems.append('response_text present but no stored_response_sha256 was sealed')
    findings_digest = content.get('findings_sha256_jcs')
    if findings_digest is not None and sha256_jcs(event.get('findings') or []) != findings_digest:
        problems.append('findings do not match findings_sha256_jcs (the findings were changed after sealing)')
    return problems


def compute_event_hash_dispatch(
    schema_version,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    event_kind=EVENT_KIND_LLM_REQUEST, auth_session=None, admin_action=None,
    mcp_event=None, coverage=None, join_context=None, content=None,
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
    # MEI-2424 — the same rule for the content attestation: its digests are
    # hashed only in the v1.10 bucket.
    if content is not None and schema_version != 'v1.10':
        raise ValueError(
            f"MEI-2424: content attestation present on a {schema_version!r} event — "
            f"content digests are hashed only in the v1.10 bucket."
        )
    if join_context is not None and schema_version not in ('v1.9', 'v1.10'):
        raise ValueError(
            f"MEI-2151: join_context present on a {schema_version!r} event — "
            f"caller-asserted join keys are hashed only in the v1.9 and v1.10 buckets."
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
    if schema_version == 'v1.10':
        # MEI-2424 — llm_request sealed under a declared capture policy. The
        # join keys are optional here (presence-tagged either way).
        if content is None:
            raise ValueError(
                "MEI-2424: schema_version v1.10 requires a content payload; an "
                "LLM event sealed with no capture policy must stay in its "
                "pre-v1.10 bucket."
            )
        if event_kind != EVENT_KIND_LLM_REQUEST:
            raise ValueError(
                f"MEI-2424: schema_version v1.10 is defined only for llm_request "
                f"events; got event_kind {event_kind!r}"
            )
        return compute_event_hash_v1_10_llm_request(
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            join_context, content,
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

# MEI-2424 — v1.10 llm_request fixtures. Paired with
# meilynx-audit/tests/mei2424_content_chain_round_trip.rs; neither side may
# drift independently. The stored response digest is deliberately absent so
# the pin covers its presence tag.
_V1_10_CONTENT_FIXTURE_PAYLOAD = dict(
    capture_policy='redacted',
    prompt_sha256_jcs='1' * 64,
    response_sha256='2' * 64,
    stored_prompt_sha256_jcs='3' * 64,
    findings_sha256_jcs='5' * 64,
)
V1_10_LLM_REQUEST_FIXTURE_HASH = "e6a655927bfc7e6933aa020de625e3459cd4ce1158dc26c2d564eed923c7eb43"
V1_10_LLM_REQUEST_JOIN_FIXTURE_HASH = "86b2ab42b6c2cb7b28c750de2d3466210509bcda0ace58fc3340db0d1587214e"

# MEI-2424 — content-digest fixtures. Paired with
# meilynx-proxy/src/audit_capture.rs::content_digests_are_pinned_for_the_verifier:
# the record's `messages` / `response_text` / `findings` exactly as the proxy
# serializes them, and the digests the proxy seals over them.
_V1_10_DIGEST_FIXTURE_RECORD = {
    'messages': [{'role': 'user', 'content': 'R\u00e9sum\u00e9 for client caf\u00e9, SSN 123-45-6789.'}],
    'response_text': 'Noted.',
    # Parsed from the proxy's exact serialization: `score` is written 1.0 and
    # must canonicalize to 1 (the ES6 number rule a naive dump gets wrong).
    'findings': json.loads(
        '[{"validator":"pii-detection","severity":"high","message":"SSN detected",'
        '"code":"pii-ssn","category":"pii","latency_ms":0,"locus":"user","score":1.0}]'
    ),
}
V1_10_DIGEST_FIXTURE_PROMPT = "ba5adc603cb95f7951ed1e2bfb3de1b66d9eeb232ff94af907fa933ff03260f6"
V1_10_DIGEST_FIXTURE_RESPONSE = "ad49d1a5366d1125bfd9a017997b7a28a9de6c669288ec46d42eab12351ecc05"
V1_10_DIGEST_FIXTURE_FINDINGS = "c39486077115ab8f01410a60ab472c0e7b6e948a59950b4a98d1be5b9b44111b"

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
        content=event.get('content'),
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


def verify_manifest_with(fetch, manifest, quiet=False, require_manifest_hash=False):
    """Walk each event in the manifest, fetch its record through `fetch(seq)`,
    recompute the hash and check the chain linkage. Source-agnostic: `fetch`
    is the only thing that differs between the GCS and the offline path, so
    both walk the identical verification loop.

    `require_manifest_hash` is set for signed packs: every entry must carry
    `recomputed_event_hash`. That field is the only link from the signed
    manifest to the record bytes, so an entry without it would leave its
    record outside what the signature covers."""
    hash_version = manifest.get('hash_version', '')
    if hash_version not in SUPPORTED_HASH_VERSIONS:
        print(
            f"ERROR: This reproducer supports hash_version {SUPPORTED_HASH_VERSIONS}. "
            f"The manifest specifies '{hash_version}'. Re-run with the updated reproducer.",
            file=sys.stderr,
        )
        sys.exit(EXIT_CANNOT_EVALUATE)

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

        # MEI-2424 — a v1.10 record's hash covers the digests of its content;
        # this checks the content itself still matches them.
        for problem in check_llm_content(event):
            report(f"FAIL seq={seq}: {problem}")
            all_passed = False

        manifest_recomputed = entry.get('recomputed_event_hash', '')
        if require_manifest_hash and not manifest_recomputed:
            report(
                f"FAIL seq={seq}: manifest entry has no recomputed_event_hash, "
                f"so the manifest signature does not cover this record."
            )
            all_passed = False
            continue
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


# ---------------------------------------------------------------------------
# Signed packs (window B): Sigstore bundle verification (MEI-922)
#
# A window B pack ships `manifest.json.sigstore.json`: a Sigstore bundle
# (media type v0.3) that cosign writes when it signs `manifest.json`
# keylessly. This section checks that bundle with the standard library only:
#
#   1. the signature verifies over the exact bytes of manifest.json, under the
#      key in the bundle's signing certificate;
#   2. the transparency-log entry is authentic: the Rekor signed entry
#      timestamp (SET) verifies, the Merkle inclusion proof reaches the logged
#      tree root, and the checkpoint over that root is signed by the log;
#   3. the logged entry is this signature: same manifest digest, same
#      signature bytes, same certificate;
#   4. the certificate chains to a trusted Fulcio CA;
#   5. the entry was logged while the short-lived certificate was valid;
#   6. the certificate names the expected signer identity and OIDC issuer.
#
# Trust anchors (Fulcio CA certificates and the Rekor log key) come only from
# SIGSTORE_PUBLIC_GOOD_TRUST_ROOT below or from a --trusted-root file, never
# from the bundle. Only ECDSA P-256 and P-384 with SHA-256 / SHA-384 are
# implemented, which is everything the pinned format uses. Certificate
# Transparency SCTs embedded in the certificate are not checked; the Rekor
# entry, which contains the certificate, is.
# ---------------------------------------------------------------------------

# The identity that signs production packs: the integrity-pack-signed.yml
# workflow in the meilynx-proxy repository, dispatched from main. A pack
# signed from any other ref or workflow fails the identity check. Pinned
# against the generator's SIGNER_IDENTITY / SIGNER_OIDC_ISSUER by a drift
# catcher in the meilynx-integrity-pack crate.
PINNED_SIGNER_IDENTITY = "https://github.com/Meilynx/meilynx-proxy/.github/workflows/integrity-pack-signed.yml@refs/heads/main"
PINNED_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

SIGNATURE_METHOD_COSIGN_KEYLESS = "cosign-sigstore-keyless"
SIGSTORE_BUNDLE_MEDIA_TYPES = {
    "application/vnd.dev.sigstore.bundle.v0.3+json",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
}

# Verdict reasons. Each failed signature check reports exactly one of these,
# followed by a detail string.
REASON_SIGNATURE_MISSING = "signature required by manifest but missing"
REASON_MANIFEST_CHANGED = "manifest bytes changed since signing"
REASON_UNTRUSTED_CHAIN = "untrusted certificate chain"
REASON_IDENTITY_MISMATCH = "signer identity mismatch"
REASON_ISSUER_MISMATCH = "OIDC issuer mismatch"
REASON_TLOG_INVALID = "invalid transparency-log proof"
REASON_TLOG_ENTRY_MISMATCH = "transparency-log entry does not match this signature"
REASON_OUTSIDE_VALIDITY = "signed outside certificate validity"
REASON_MALFORMED = "malformed signature material"


class SignatureInvalid(Exception):
    """The pack's signature does not verify. Exit 1."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class SignatureUnsupported(Exception):
    """The signature uses a method or format this verifier does not know.
    Exit 2, the same as an unknown hash_version: update the verifier."""


# Sigstore public-good trust anchors, copied from sigstore/root-signing
# targets/trusted_root.json at commit c9bda74ad2221f938f7d2e0295ca3aad2da710a8
# (2025-09-22). Only what the pinned format needs: the Fulcio CA chains
# (intermediate first, root last) and the Rekor v1 log key. Compare these
# values against that file, or pass your own copy with --trusted-root.
# Rotation: Sigstore publishes new anchors through that repository. A pack
# signed under a new anchor needs a verifier release that carries it (or
# --trusted-root); packs signed under an anchor listed here keep verifying,
# because each anchor is checked against the time its entry was logged.
SIGSTORE_PUBLIC_GOOD_TRUST_ROOT = {
    "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
    "tlogs": [
        {
            "baseUrl": "https://rekor.sigstore.dev",
            "hashAlgorithm": "SHA2_256",
            "publicKey": {
                "rawBytes": (
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr"
                    "kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=="
                ),
                "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                "validFor": {"start": "2021-01-12T11:53:27Z"},
            },
            "logId": {"keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="},
        },
    ],
    "certificateAuthorities": [
        {
            "uri": "https://fulcio.sigstore.dev",
            "certChain": {"certificates": [
                {"rawBytes": (
                    "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAq"
                    "MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx"
                    "MDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUu"
                    "ZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSy"
                    "A7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0Jcas"
                    "taRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6Nm"
                    "MGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE"
                    "FMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2u"
                    "Su1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJx"
                    "Ve/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uup"
                    "Hr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ=="
                )},
            ]},
            "validFor": {"start": "2021-03-07T03:20:29Z", "end": "2022-12-31T23:59:59.999Z"},
        },
        {
            "uri": "https://fulcio.sigstore.dev",
            "certChain": {"certificates": [
                {"rawBytes": (
                    "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw"
                    "KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y"
                    "MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl"
                    "LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C"
                    "AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7"
                    "7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS"
                    "0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB"
                    "BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp"
                    "KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI"
                    "zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR"
                    "nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP"
                    "mygUY7Ii2zbdCdliiow="
                )},
                {"rawBytes": (
                    "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw"
                    "KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y"
                    "MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl"
                    "LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7"
                    "XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex"
                    "X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j"
                    "YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY"
                    "wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ"
                    "KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM"
                    "WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9"
                    "TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ"
                )},
            ]},
            "validFor": {"start": "2022-04-13T20:06:15Z"},
        },
    ],
}


# ── DER ────────────────────────────────────────────────────────────────────
# A strict reader: definite lengths in minimal form, single-byte tags, no
# trailing bytes. Anything else is rejected rather than interpreted.

class DerError(ValueError):
    pass


def _der_tlv(buf, pos, limit):
    """Read one TLV at buf[pos:limit]. Returns (tag, content_start, end)."""
    if pos + 2 > limit:
        raise DerError("truncated element")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise DerError("multi-byte tags are not supported")
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise DerError("indefinite or oversized length")
        if pos + count > limit:
            raise DerError("truncated length")
        if buf[pos] == 0:
            raise DerError("non-minimal length")
        length = int.from_bytes(buf[pos:pos + count], "big")
        if length < 0x80:
            raise DerError("non-minimal length")
        pos += count
    end = pos + length
    if end > limit:
        raise DerError("element overruns its container")
    return tag, pos, end


def _der_children(buf, start, end):
    """Children of a constructed element as (tag, content_start, end, tlv_start)."""
    out = []
    pos = start
    while pos < end:
        tag, cs, ce = _der_tlv(buf, pos, end)
        out.append((tag, cs, ce, pos))
        pos = ce
    return out


def _der_expect(buf, pos, limit, tag):
    t, cs, ce = _der_tlv(buf, pos, limit)
    if t != tag:
        raise DerError(f"expected tag 0x{tag:02x}, found 0x{t:02x}")
    return cs, ce


def _der_positive_int(content):
    if not content:
        raise DerError("empty INTEGER")
    if content[0] & 0x80:
        raise DerError("negative INTEGER")
    if len(content) > 1 and content[0] == 0 and not content[1] & 0x80:
        raise DerError("non-minimal INTEGER")
    return int.from_bytes(content, "big")


def _der_oid(content):
    if not content or content[-1] & 0x80:
        raise DerError("malformed OBJECT IDENTIFIER")
    arcs = []
    value = 0
    fresh = True
    for byte in content:
        if fresh and byte == 0x80:
            raise DerError("non-minimal OBJECT IDENTIFIER arc")
        value = (value << 7) | (byte & 0x7F)
        fresh = not byte & 0x80
        if fresh:
            arcs.append(value)
            value = 0
    first = arcs[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return ".".join(str(a) for a in head + arcs[1:])


def _der_time(tag, content):
    text = content.decode("ascii")
    if tag == 0x17 and len(text) == 13 and text.endswith("Z"):
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        rest = text[2:12]
    elif tag == 0x18 and len(text) == 15 and text.endswith("Z"):
        year = int(text[0:4])
        rest = text[4:14]
    else:
        raise DerError("unsupported time encoding")
    if not rest.isdigit():
        raise DerError("malformed time")
    moment = datetime.datetime(
        year, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8]), int(rest[8:10]),
        tzinfo=datetime.timezone.utc,
    )
    return int(moment.timestamp())


def _der_signature_rs(sig):
    """ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }, strict DER."""
    cs, ce = _der_expect(sig, 0, len(sig), 0x30)
    if ce != len(sig):
        raise DerError("trailing bytes after signature")
    r_cs, r_ce = _der_expect(sig, cs, ce, 0x02)
    s_cs, s_ce = _der_expect(sig, r_ce, ce, 0x02)
    if s_ce != ce:
        raise DerError("trailing bytes inside signature")
    return _der_positive_int(sig[r_cs:r_ce]), _der_positive_int(sig[s_cs:s_ce])


# ── ECDSA over P-256 / P-384 ───────────────────────────────────────────────
# Verification only: every input is public, so plain integer arithmetic is
# fine. Jacobian coordinates, a = -3 on both curves.

class _Curve:
    def __init__(self, name, oid, p, b, gx, gy, n):
        self.name, self.oid, self.p, self.b, self.n = name, oid, p, b, n
        self.g = (gx, gy)
        self.size = (p.bit_length() + 7) // 8


P256 = _Curve(
    "P-256", "1.2.840.10045.3.1.7",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)
P384 = _Curve(
    "P-384", "1.3.132.0.34",
    p=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
          "FFFFFFFF0000000000000000FFFFFFFF", 16),
    b=int("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
          "C656398D8A2ED19D2A85C8EDD3EC2AEF", 16),
    gx=int("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
           "5502F25DBF55296C3A545E3872760AB7", 16),
    gy=int("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
           "0A60B1CE1D7E819D7A431D7C90EA0E5F", 16),
    n=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
          "581A0DB248B0A77AECEC196ACCC52973", 16),
)
CURVES_BY_OID = {P256.oid: P256, P384.oid: P384}

_INFINITY = (0, 1, 0)


def _jacobian_double(c, pt):
    x, y, z = pt
    if z == 0 or y == 0:
        return _INFINITY
    p = c.p
    delta = z * z % p
    gamma = y * y % p
    beta = x * gamma % p
    alpha = 3 * (x - delta) * (x + delta) % p
    x3 = (alpha * alpha - 8 * beta) % p
    z3 = ((y + z) * (y + z) - gamma - delta) % p
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % p
    return (x3, y3, z3)


def _jacobian_add(c, p1, p2):
    if p1[2] == 0:
        return p2
    if p2[2] == 0:
        return p1
    p = c.p
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    z1z1 = z1 * z1 % p
    z2z2 = z2 * z2 % p
    u1 = x1 * z2z2 % p
    u2 = x2 * z1z1 % p
    s1 = y1 * z2 * z2z2 % p
    s2 = y2 * z1 * z1z1 % p
    if u1 == u2:
        return _jacobian_double(c, p1) if s1 == s2 else _INFINITY
    h = (u2 - u1) % p
    r = (s2 - s1) % p
    hh = h * h % p
    hhh = h * hh % p
    v = u1 * hh % p
    x3 = (r * r - hhh - 2 * v) % p
    y3 = (r * (v - x3) - s1 * hhh) % p
    z3 = h * z1 * z2 % p
    return (x3, y3, z3)


def _on_curve(c, point):
    x, y = point
    if not (0 <= x < c.p and 0 <= y < c.p):
        return False
    return (y * y - (x * x * x - 3 * x + c.b)) % c.p == 0


def ecdsa_verify(c, public_point, digest, r, s):
    """True iff (r, s) is a valid ECDSA signature over `digest` (the already
    hashed message) under `public_point` on curve `c`."""
    if not (1 <= r < c.n and 1 <= s < c.n):
        return False
    if not _on_curve(c, public_point):
        return False
    e = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - c.n.bit_length()
    if excess > 0:
        e >>= excess
    w = pow(s, -1, c.n)
    u1 = e * w % c.n
    u2 = r * w % c.n
    g = (c.g[0], c.g[1], 1)
    q = (public_point[0], public_point[1], 1)
    gq = _jacobian_add(c, g, q)
    acc = _INFINITY
    for i in range(max(u1.bit_length(), u2.bit_length()) - 1, -1, -1):
        acc = _jacobian_double(c, acc)
        b1 = (u1 >> i) & 1
        b2 = (u2 >> i) & 1
        if b1 and b2:
            acc = _jacobian_add(c, acc, gq)
        elif b1:
            acc = _jacobian_add(c, acc, g)
        elif b2:
            acc = _jacobian_add(c, acc, q)
    x, _, z = acc
    if z == 0:
        return False
    affine_x = x * pow(z * z % c.p, -1, c.p) % c.p
    return affine_x % c.n == r


def ecdsa_verify_der(c, public_point, digest, signature_der):
    try:
        r, s = _der_signature_rs(signature_der)
    except DerError:
        return False
    return ecdsa_verify(c, public_point, digest, r, s)


OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
SIGNATURE_HASHES = {
    "1.2.840.10045.4.3.2": hashlib.sha256,  # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": hashlib.sha384,  # ecdsa-with-SHA384
}


def parse_ec_public_key(spki):
    """SubjectPublicKeyInfo (DER) -> (curve, (x, y)). Uncompressed points only."""
    cs, ce = _der_expect(spki, 0, len(spki), 0x30)
    if ce != len(spki):
        raise DerError("trailing bytes after public key")
    kids = _der_children(spki, cs, ce)
    if len(kids) != 2 or kids[0][0] != 0x30 or kids[1][0] != 0x03:
        raise DerError("malformed SubjectPublicKeyInfo")
    alg = _der_children(spki, kids[0][1], kids[0][2])
    if len(alg) != 2 or alg[0][0] != 0x06 or alg[1][0] != 0x06:
        raise DerError("unsupported public key algorithm parameters")
    if _der_oid(spki[alg[0][1]:alg[0][2]]) != OID_EC_PUBLIC_KEY:
        raise DerError("public key is not an EC key")
    curve = CURVES_BY_OID.get(_der_oid(spki[alg[1][1]:alg[1][2]]))
    if curve is None:
        raise DerError("unsupported EC curve")
    bits = spki[kids[1][1]:kids[1][2]]
    if len(bits) != 2 + 2 * curve.size or bits[0] != 0 or bits[1] != 0x04:
        raise DerError("public key is not an uncompressed point")
    point = (
        int.from_bytes(bits[2:2 + curve.size], "big"),
        int.from_bytes(bits[2 + curve.size:], "big"),
    )
    if not _on_curve(curve, point):
        raise DerError("public key point is not on the curve")
    return curve, point


# ── X.509 ──────────────────────────────────────────────────────────────────

OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_SUBJECT_ALT_NAME = "2.5.29.17"
OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
OID_FULCIO_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1"
OID_FULCIO_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8"
# Extensions this verifier understands, so they may be marked critical.
UNDERSTOOD_CRITICAL_EXTENSIONS = {
    OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, OID_EXT_KEY_USAGE, OID_SUBJECT_ALT_NAME,
}


class Certificate:
    def __init__(self, der):
        self.der = der
        cs, ce = _der_expect(der, 0, len(der), 0x30)
        if ce != len(der):
            raise DerError("trailing bytes after certificate")
        kids = _der_children(der, cs, ce)
        if len(kids) != 3 or kids[0][0] != 0x30 or kids[1][0] != 0x30 or kids[2][0] != 0x03:
            raise DerError("malformed Certificate")
        self.tbs = der[kids[0][3]:kids[0][2]]
        outer_alg = der[kids[1][3]:kids[1][2]]
        self.signature_algorithm = self._signature_algorithm(der, kids[1])
        bits = der[kids[2][1]:kids[2][2]]
        if not bits or bits[0] != 0:
            raise DerError("malformed signature BIT STRING")
        self.signature = bits[1:]

        tbs = _der_children(der, kids[0][1], kids[0][2])
        if len(tbs) < 7 or tbs[0][0] != 0xA0:
            raise DerError("only X.509 v3 certificates are supported")
        v_cs, v_ce = _der_expect(der, tbs[0][1], tbs[0][2], 0x02)
        if v_ce != tbs[0][2] or _der_positive_int(der[v_cs:v_ce]) != 2:
            raise DerError("only X.509 v3 certificates are supported")
        if tbs[1][0] != 0x02:
            raise DerError("malformed serial number")
        if tbs[2][0] != 0x30 or der[tbs[2][3]:tbs[2][2]] != outer_alg:
            raise DerError("TBS signature algorithm differs from the outer one")
        if tbs[3][0] != 0x30 or tbs[5][0] != 0x30 or tbs[4][0] != 0x30 or tbs[6][0] != 0x30:
            raise DerError("malformed TBSCertificate")
        self.issuer = der[tbs[3][3]:tbs[3][2]]
        self.subject = der[tbs[5][3]:tbs[5][2]]
        validity = _der_children(der, tbs[4][1], tbs[4][2])
        if len(validity) != 2:
            raise DerError("malformed Validity")
        self.not_before = _der_time(validity[0][0], der[validity[0][1]:validity[0][2]])
        self.not_after = _der_time(validity[1][0], der[validity[1][1]:validity[1][2]])
        self.spki = der[tbs[6][3]:tbs[6][2]]
        self.curve, self.public_point = parse_ec_public_key(self.spki)

        self.extensions = {}
        rest = tbs[7:]
        if len(rest) > 1 or (rest and rest[0][0] != 0xA3):
            raise DerError("unexpected fields after SubjectPublicKeyInfo")
        if rest:
            seq_cs, seq_ce = _der_expect(der, rest[0][1], rest[0][2], 0x30)
            if seq_ce != rest[0][2]:
                raise DerError("malformed extensions")
            for ext in _der_children(der, seq_cs, seq_ce):
                if ext[0] != 0x30:
                    raise DerError("malformed extension")
                parts = _der_children(der, ext[1], ext[2])
                critical = False
                if len(parts) == 3 and parts[1][0] == 0x01:
                    flag = der[parts[1][1]:parts[1][2]]
                    if flag not in (b"\x00", b"\xff"):
                        raise DerError("malformed critical flag")
                    critical = flag == b"\xff"
                    parts = [parts[0], parts[2]]
                if len(parts) != 2 or parts[0][0] != 0x06 or parts[1][0] != 0x04:
                    raise DerError("malformed extension")
                oid = _der_oid(der[parts[0][1]:parts[0][2]])
                if oid in self.extensions:
                    raise DerError(f"duplicate extension {oid}")
                self.extensions[oid] = (critical, der[parts[1][1]:parts[1][2]])

    @staticmethod
    def _signature_algorithm(der, node):
        alg = _der_children(der, node[1], node[2])
        if len(alg) != 1 or alg[0][0] != 0x06:
            raise DerError("unsupported signature algorithm parameters")
        oid = _der_oid(der[alg[0][1]:alg[0][2]])
        if oid not in SIGNATURE_HASHES:
            raise DerError(f"unsupported signature algorithm {oid}")
        return oid

    def unknown_critical_extensions(self):
        return sorted(o for o, (crit, _) in self.extensions.items()
                      if crit and o not in UNDERSTOOD_CRITICAL_EXTENSIONS)

    def basic_constraints(self):
        """(is_ca, path_len or None); (False, None) when the extension is absent."""
        ext = self.extensions.get(OID_BASIC_CONSTRAINTS)
        if ext is None:
            return False, None
        value = ext[1]
        cs, ce = _der_expect(value, 0, len(value), 0x30)
        if ce != len(value):
            raise DerError("malformed basicConstraints")
        is_ca, path_len = False, None
        for tag, vcs, vce, _ in _der_children(value, cs, ce):
            if tag == 0x01 and vce - vcs == 1 and value[vcs] in (0x00, 0xFF):
                is_ca = value[vcs] == 0xFF
            elif tag == 0x02:
                path_len = _der_positive_int(value[vcs:vce])
            else:
                raise DerError("malformed basicConstraints")
        return is_ca, path_len

    def key_usage_bits(self):
        """The keyUsage BIT STRING as an int (bit 0 = digitalSignature is the
        most significant bit of the first byte), or None when absent."""
        ext = self.extensions.get(OID_KEY_USAGE)
        if ext is None:
            return None
        value = ext[1]
        cs, ce = _der_expect(value, 0, len(value), 0x03)
        if ce != len(value) or ce - cs < 2 or value[cs] > 7:
            raise DerError("malformed keyUsage")
        return int.from_bytes(value[cs + 1:ce].ljust(2, b"\x00")[:2], "big")

    def extended_key_usages(self):
        ext = self.extensions.get(OID_EXT_KEY_USAGE)
        if ext is None:
            return set()
        value = ext[1]
        cs, ce = _der_expect(value, 0, len(value), 0x30)
        if ce != len(value):
            raise DerError("malformed extKeyUsage")
        out = set()
        for tag, vcs, vce, _ in _der_children(value, cs, ce):
            if tag != 0x06:
                raise DerError("malformed extKeyUsage")
            out.add(_der_oid(value[vcs:vce]))
        return out

    def san_values(self):
        """URI and email subjectAltName values."""
        ext = self.extensions.get(OID_SUBJECT_ALT_NAME)
        if ext is None:
            return []
        value = ext[1]
        cs, ce = _der_expect(value, 0, len(value), 0x30)
        if ce != len(value):
            raise DerError("malformed subjectAltName")
        out = []
        for tag, vcs, vce, _ in _der_children(value, cs, ce):
            if tag in (0x81, 0x86):  # rfc822Name, uniformResourceIdentifier
                out.append(value[vcs:vce].decode("ascii"))
        return out

    def fulcio_issuer(self):
        """The OIDC issuer Fulcio recorded: the v2 extension (a DER UTF8String)
        when present, else the v1 extension (raw bytes)."""
        v2 = self.extensions.get(OID_FULCIO_ISSUER_V2)
        if v2 is not None:
            value = v2[1]
            cs, ce = _der_expect(value, 0, len(value), 0x0C)
            if ce != len(value):
                raise DerError("malformed Fulcio issuer extension")
            return value[cs:ce].decode("utf-8")
        v1 = self.extensions.get(OID_FULCIO_ISSUER_V1)
        if v1 is not None:
            return v1[1].decode("utf-8")
        return None

    def signed_by(self, issuer_cert):
        digest = SIGNATURE_HASHES[self.signature_algorithm](self.tbs).digest()
        return ecdsa_verify_der(issuer_cert.curve, issuer_cert.public_point, digest, self.signature)


KEY_USAGE_DIGITAL_SIGNATURE = 0x8000
KEY_USAGE_KEY_CERT_SIGN = 0x0400


def verify_certificate_chain(leaf, chain, at_time):
    """Check leaf -> chain[0] -> ... -> chain[-1] (the trust anchor) at `at_time`.
    Returns None when valid, else a short reason."""
    try:
        for cert in [leaf] + chain:
            unknown = cert.unknown_critical_extensions()
            if unknown:
                return f"unknown critical extension {unknown[0]}"
        for position, (child, parent) in enumerate(zip([leaf] + chain, chain)):
            is_ca, path_len = parent.basic_constraints()
            if not is_ca:
                return "an issuing certificate is not a CA"
            usage = parent.key_usage_bits()
            if usage is None or not usage & KEY_USAGE_KEY_CERT_SIGN:
                return "an issuing certificate may not sign certificates"
            if path_len is not None and position > path_len:
                return "path length constraint exceeded"
            if child.issuer != parent.subject:
                return "issuer name does not chain"
            if not child.signed_by(parent):
                return "certificate signature does not verify"
        for cert in chain:
            if not cert.not_before <= at_time <= cert.not_after:
                return "a CA certificate was not valid when the entry was logged"
        if leaf.basic_constraints()[0]:
            return "signing certificate is a CA"
        usage = leaf.key_usage_bits()
        if usage is None or not usage & KEY_USAGE_DIGITAL_SIGNATURE:
            return "signing certificate lacks the digitalSignature key usage"
        if OID_CODE_SIGNING not in leaf.extended_key_usages():
            return "signing certificate lacks the codeSigning extended key usage"
    except DerError as exc:
        return f"malformed certificate extension ({exc})"
    return None


# ── Trusted root ───────────────────────────────────────────────────────────

def _rfc3339_to_epoch(text):
    m = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)", text)
    if not m:
        raise ValueError(f"malformed timestamp {text!r}")
    moment = datetime.datetime(*(int(m.group(i)) for i in range(1, 7)), tzinfo=datetime.timezone.utc)
    seconds = moment.timestamp() + (float(m.group(7)) if m.group(7) else 0.0)
    if m.group(8) != "Z":
        sign = 1 if m.group(8)[0] == "+" else -1
        seconds -= sign * (int(m.group(8)[1:3]) * 3600 + int(m.group(8)[4:6]) * 60)
    return seconds


def _valid_for(obj):
    valid_for = obj.get("validFor") or {}
    if "start" not in valid_for:
        raise ValueError("trusted root entry has no validFor.start")
    start = _rfc3339_to_epoch(valid_for["start"])
    end = _rfc3339_to_epoch(valid_for["end"]) if valid_for.get("end") else float("inf")
    return start, end


def load_trusted_root(obj):
    """Parse a Sigstore trusted_root.json object into the anchors this verifier
    uses. Transparency logs with key types other than ECDSA P-256/P-384, and
    CAs whose certificates use other algorithms, are skipped: they can never
    make a signature verify. Raises ValueError on anything malformed."""
    if not str(obj.get("mediaType", "")).startswith("application/vnd.dev.sigstore.trustedroot"):
        raise ValueError("not a Sigstore trusted root")
    tlogs = {}
    for log in obj.get("tlogs") or []:
        key = log["publicKey"]
        if key.get("keyDetails") not in ("PKIX_ECDSA_P256_SHA_256", "PKIX_ECDSA_P384_SHA_384"):
            continue
        spki = base64.b64decode(key["rawBytes"], validate=True)
        curve, point = parse_ec_public_key(spki)
        key_id = hashlib.sha256(spki).digest()
        if base64.b64decode(log["logId"]["keyId"], validate=True) != key_id:
            raise ValueError("trusted root log id does not match its key")
        start, end = _valid_for(key)
        tlogs[key_id] = {"curve": curve, "point": point, "start": start, "end": end,
                         "url": log.get("baseUrl", "")}
    cas = []
    for ca in obj.get("certificateAuthorities") or []:
        try:
            certs = [Certificate(base64.b64decode(c["rawBytes"], validate=True))
                     for c in ca["certChain"]["certificates"]]
        except DerError:
            continue  # an algorithm this verifier does not implement: unusable, never trusted
        if not certs:
            raise ValueError("trusted root CA has an empty chain")
        start, end = _valid_for(ca)
        cas.append({"chain": certs, "start": start, "end": end, "uri": ca.get("uri", "")})
    if not tlogs or not cas:
        raise ValueError("trusted root has no usable transparency log or CA")
    return {"tlogs": tlogs, "cas": cas}


# ── Transparency log ───────────────────────────────────────────────────────

def _merkle_node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion_proof(index, tree_size, leaf_hash, proof, root):
    """RFC 9162 section 2.1.3.2."""
    if not 0 <= index < tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _merkle_node(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _merkle_node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_checkpoint(envelope, log, key_id, tree_size, root):
    """A Rekor v1 checkpoint: a signed note whose body is the origin line, the
    tree size and the base64 root hash. Returns None when it is signed by the
    log and commits to (tree_size, root), else a short reason."""
    body, sep, signatures = envelope.partition("\n\n")
    if not sep:
        return "checkpoint has no signature block"
    body += "\n"
    lines = body.split("\n")
    if len(lines) < 4:
        return "checkpoint body is truncated"
    if lines[1] != str(tree_size):
        return "checkpoint tree size differs from the inclusion proof"
    try:
        if base64.b64decode(lines[2], validate=True) != root:
            return "checkpoint root hash differs from the inclusion proof"
    except (ValueError, binascii.Error):
        return "checkpoint root hash is not base64"
    digest = hashlib.sha256(body.encode("utf-8")).digest()
    for line in signatures.split("\n"):
        if not line.startswith("\u2014 "):
            continue
        parts = line.split(" ")
        if len(parts) != 3:
            continue
        try:
            raw = base64.b64decode(parts[2], validate=True)
        except (ValueError, binascii.Error):
            continue
        if raw[:4] == key_id[:4] and ecdsa_verify_der(log["curve"], log["point"], digest, raw[4:]):
            return None
    return "checkpoint is not signed by the transparency log"


def _b64(value, what):
    try:
        return base64.b64decode(value, validate=True)
    except (TypeError, ValueError, binascii.Error):
        raise SignatureInvalid(REASON_MALFORMED, f"{what} is not base64")


def _decimal(value, what):
    text = str(value)
    if not text.isdigit():
        raise SignatureInvalid(REASON_MALFORMED, f"{what} is not a non-negative integer")
    return int(text)


def _pem_to_der(pem):
    text = pem.decode("ascii").strip()
    head, tail = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    if not (text.startswith(head) and text.endswith(tail)):
        raise ValueError("not a PEM certificate")
    return base64.b64decode("".join(text[len(head):-len(tail)].split()), validate=True)


def _utc(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Bundle ─────────────────────────────────────────────────────────────────

def verify_sigstore_bundle(bundle, artifact_digest, expected_identity, expected_issuer, trust):
    """Verify a Sigstore bundle (v0.3, hashedrekord, Rekor v1) over an artifact
    whose SHA-256 is `artifact_digest`. Returns a dict describing the verified
    signer. Raises SignatureInvalid (with one of the REASON_* values) or
    SignatureUnsupported."""
    if not isinstance(bundle, dict):
        raise SignatureInvalid(REASON_MALFORMED, "bundle is not a JSON object")
    media_type = bundle.get("mediaType")
    if media_type not in SIGSTORE_BUNDLE_MEDIA_TYPES:
        raise SignatureUnsupported(f"unsupported Sigstore bundle media type {media_type!r}")
    if "messageSignature" not in bundle:
        raise SignatureUnsupported("bundle does not carry a message signature (DSSE is not supported)")
    material = bundle.get("verificationMaterial")
    if not isinstance(material, dict) or not isinstance(bundle["messageSignature"], dict):
        raise SignatureInvalid(REASON_MALFORMED, "bundle verificationMaterial or messageSignature is not an object")
    if "certificate" not in material:
        raise SignatureUnsupported("bundle does not carry a single signing certificate")
    entries = material.get("tlogEntries") or []
    if len(entries) != 1:
        raise SignatureInvalid(REASON_TLOG_INVALID, "expected exactly one transparency-log entry")
    entry = entries[0]
    kind = entry.get("kindVersion") or {}
    if (kind.get("kind"), kind.get("version")) != ("hashedrekord", "0.0.1"):
        raise SignatureUnsupported(f"unsupported transparency-log entry type {kind!r}")

    # 1. The signature over the artifact.
    try:
        leaf = Certificate(_b64(material["certificate"].get("rawBytes"), "certificate"))
    except DerError as exc:
        raise SignatureInvalid(REASON_MALFORMED, f"signing certificate: {exc}")
    if leaf.curve is not P256:
        raise SignatureUnsupported(f"unsupported signing key curve {leaf.curve.name}")
    message = bundle["messageSignature"]
    digest_info = message.get("messageDigest") or {}
    if digest_info.get("algorithm") != "SHA2_256":
        raise SignatureUnsupported("unsupported message digest algorithm")
    signature = _b64(message.get("signature"), "signature")
    if _b64(digest_info.get("digest"), "message digest") != artifact_digest:
        raise SignatureInvalid(REASON_MANIFEST_CHANGED, "the digest recorded in the bundle differs from manifest.json")
    if not ecdsa_verify_der(leaf.curve, leaf.public_point, artifact_digest, signature):
        raise SignatureInvalid(REASON_MANIFEST_CHANGED, "the signature does not verify over manifest.json")

    # 2. The transparency-log entry is authentic.
    key_id = _b64((entry.get("logId") or {}).get("keyId"), "log id")
    log = trust["tlogs"].get(key_id)
    if log is None:
        raise SignatureInvalid(REASON_TLOG_INVALID, "entry is from a transparency log that is not trusted")
    integrated_time = _decimal(entry.get("integratedTime"), "integratedTime")
    log_index = _decimal(entry.get("logIndex"), "logIndex")
    if not log["start"] <= integrated_time <= log["end"]:
        raise SignatureInvalid(REASON_TLOG_INVALID, "entry was logged outside the log key's validity")
    body_b64 = entry.get("canonicalizedBody")
    body = _b64(body_b64, "canonicalizedBody")
    promise = (entry.get("inclusionPromise") or {}).get("signedEntryTimestamp")
    if not promise:
        raise SignatureInvalid(REASON_TLOG_INVALID, "entry has no signed entry timestamp")
    set_payload = jcs_dumps({
        "body": body_b64, "integratedTime": integrated_time,
        "logID": key_id.hex(), "logIndex": log_index,
    }).encode("utf-8")
    if not ecdsa_verify_der(log["curve"], log["point"], hashlib.sha256(set_payload).digest(),
                            _b64(promise, "signed entry timestamp")):
        raise SignatureInvalid(REASON_TLOG_INVALID, "signed entry timestamp does not verify")
    proof = entry.get("inclusionProof")
    if not proof:
        raise SignatureInvalid(REASON_TLOG_INVALID, "entry has no inclusion proof")
    root = _b64(proof.get("rootHash"), "inclusion proof root hash")
    hashes = [_b64(h, "inclusion proof hash") for h in proof.get("hashes") or []]
    tree_size = _decimal(proof.get("treeSize"), "treeSize")
    proof_index = _decimal(proof.get("logIndex"), "inclusion proof logIndex")
    leaf_hash = hashlib.sha256(b"\x00" + body).digest()
    if not verify_inclusion_proof(proof_index, tree_size, leaf_hash, hashes, root):
        raise SignatureInvalid(REASON_TLOG_INVALID, "inclusion proof does not reach the tree root")
    envelope = (proof.get("checkpoint") or {}).get("envelope")
    if not isinstance(envelope, str):
        raise SignatureInvalid(REASON_TLOG_INVALID, "inclusion proof has no checkpoint")
    problem = verify_checkpoint(envelope, log, key_id, tree_size, root)
    if problem:
        raise SignatureInvalid(REASON_TLOG_INVALID, problem)

    # 3. The logged entry is this signature.
    try:
        logged = json.loads(body)
        spec = logged["spec"]
        logged_hash = spec["data"]["hash"]
        logged_signature = spec["signature"]
        if (logged.get("kind"), logged.get("apiVersion")) != ("hashedrekord", "0.0.1"):
            raise KeyError("kind")
    except (ValueError, KeyError, TypeError):
        raise SignatureInvalid(REASON_TLOG_ENTRY_MISMATCH, "logged entry is not a hashedrekord 0.0.1 record")
    if logged_hash.get("algorithm") != "sha256" or logged_hash.get("value") != artifact_digest.hex():
        raise SignatureInvalid(REASON_TLOG_ENTRY_MISMATCH, "the logged entry records a different artifact digest")
    if _b64(logged_signature.get("content"), "logged signature") != signature:
        raise SignatureInvalid(REASON_TLOG_ENTRY_MISMATCH, "the logged entry records a different signature")
    try:
        logged_cert = _pem_to_der(_b64((logged_signature.get("publicKey") or {}).get("content"), "logged certificate"))
    except (ValueError, UnicodeDecodeError):
        raise SignatureInvalid(REASON_TLOG_ENTRY_MISMATCH, "the logged entry does not carry a certificate")
    if logged_cert != leaf.der:
        raise SignatureInvalid(REASON_TLOG_ENTRY_MISMATCH, "the logged entry records a different certificate")

    # 4. The certificate chains to a trusted Fulcio CA at the logged time.
    problems = []
    for ca in trust["cas"]:
        if not ca["start"] <= integrated_time <= ca["end"]:
            continue
        problem = verify_certificate_chain(leaf, ca["chain"], integrated_time)
        if problem is None:
            break
        problems.append(problem)
    else:
        raise SignatureInvalid(REASON_UNTRUSTED_CHAIN, problems[0] if problems else "no trusted CA was valid when the entry was logged")

    # 5. The entry was logged while the certificate was valid.
    if not leaf.not_before <= integrated_time <= leaf.not_after:
        raise SignatureInvalid(
            REASON_OUTSIDE_VALIDITY,
            f"logged at {_utc(integrated_time)}, certificate valid {_utc(leaf.not_before)} to {_utc(leaf.not_after)}",
        )

    # 6. The certificate names the expected signer.
    try:
        identities = leaf.san_values()
        issuer = leaf.fulcio_issuer()
    except (DerError, UnicodeDecodeError) as exc:
        raise SignatureInvalid(REASON_MALFORMED, f"signing certificate identity: {exc}")
    if expected_identity not in identities:
        raise SignatureInvalid(
            REASON_IDENTITY_MISMATCH,
            f"signed by {', '.join(identities) or 'no identity'}; expected {expected_identity}",
        )
    if issuer != expected_issuer:
        raise SignatureInvalid(REASON_ISSUER_MISMATCH, f"issuer {issuer}; expected {expected_issuer}")

    return {
        "identity": expected_identity,
        "issuer": issuer,
        "integrated_time": integrated_time,
        "log_index": log_index,
        "log_url": log["url"],
    }


# ── Pack level ─────────────────────────────────────────────────────────────

def pack_is_signed(manifest):
    """Signed mode, mirroring the generator's `signed_mode` (lib.rs): window
    "B", or signing not deferred, or a signature descriptor present. A missing
    `signing_deferred` counts as signed, so deleting the field cannot turn a
    signed pack into an unsigned one."""
    return (
        manifest.get("window") == "B"
        or manifest.get("signing_deferred") is not True
        or manifest.get("signature") is not None
    )


def check_pack_signature(manifest, manifest_bytes, read_sibling, expected_identity,
                         expected_issuer, trust):
    """Verify a signed pack's signature. `read_sibling(name)` returns the bytes
    of a file next to manifest.json, or None when it does not exist."""
    descriptor = manifest.get("signature")
    if not isinstance(descriptor, dict):
        raise SignatureInvalid(REASON_SIGNATURE_MISSING, "the manifest is signed-mode but has no signature descriptor")
    method = descriptor.get("method")
    if method != SIGNATURE_METHOD_COSIGN_KEYLESS:
        raise SignatureUnsupported(f"unsupported signature method {method!r}")
    name = descriptor.get("signature_file")
    if not isinstance(name, str) or not name or "/" in name or "\\" in name or name in (".", ".."):
        raise SignatureInvalid(REASON_MALFORMED, "signature_file is not a plain file name")
    raw = read_sibling(name)
    if raw is None:
        raise SignatureInvalid(REASON_SIGNATURE_MISSING, f"{name} is not next to manifest.json")
    try:
        bundle = json.loads(raw)
    except ValueError:
        raise SignatureInvalid(REASON_MALFORMED, f"{name} is not JSON")
    try:
        return verify_sigstore_bundle(
            bundle, hashlib.sha256(manifest_bytes).digest(), expected_identity, expected_issuer, trust,
        )
    except (AttributeError, TypeError, KeyError, IndexError, ValueError, UnicodeDecodeError) as exc:
        # A bundle whose structure is not what the format defines (a field of
        # the wrong type, a missing object). Never a pass. SignatureInvalid and
        # SignatureUnsupported are not in this tuple and propagate unchanged.
        raise SignatureInvalid(REASON_MALFORMED, f"{name}: unexpected structure ({type(exc).__name__})")


PASSED = "passed"
FAILED = "failed"
UNSIGNED = "unsigned"
CANNOT_EVALUATE = "cannot evaluate"


def final_exit_code(chain_status, signature_status, allow_unsigned):
    """The overall verdict, the same in --bucket and --records mode.

    `chain_status` is PASSED, FAILED or CANNOT_EVALUATE; `signature_status`
    is PASSED, FAILED, UNSIGNED or CANNOT_EVALUATE. Precedence: a failure of
    either check (EXIT_FAIL) outranks a check that could not be evaluated
    (EXIT_CANNOT_EVALUATE), which outranks a pack with no signature
    (EXIT_UNSIGNED). An unsigned pack whose chain verifies exits 0 only when
    the caller accepts unsigned packs with --allow-unsigned."""
    if FAILED in (chain_status, signature_status):
        return EXIT_FAIL
    if CANNOT_EVALUATE in (chain_status, signature_status):
        return EXIT_CANNOT_EVALUATE
    if signature_status == UNSIGNED and not allow_unsigned:
        return EXIT_UNSIGNED
    return EXIT_OK


UNSIGNED_NOTICE = (
    "AUTHENTICITY NOT ESTABLISHED: this pack carries no signature (window A). "
    "The chain check shows the records are intact and correctly linked. "
    "It cannot show who produced this manifest."
)


def report_pack_signature(manifest, manifest_bytes, manifest_path, args):
    """Verify a signed pack's signature and print the verdict. Returns PASSED,
    FAILED, or CANNOT_EVALUATE (a signature method or format this verifier
    does not know, or a --trusted-root file it cannot use)."""
    if args.trusted_root:
        try:
            with open(args.trusted_root, 'rb') as f:
                trust = load_trusted_root(json.load(f))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"ERROR: cannot use --trusted-root {args.trusted_root}: {exc}", file=sys.stderr)
            return CANNOT_EVALUATE
    else:
        trust = load_trusted_root(SIGSTORE_PUBLIC_GOOD_TRUST_ROOT)
    if args.certificate_identity != PINNED_SIGNER_IDENTITY:
        print(f"NOTE: expecting signer identity {args.certificate_identity} (--certificate-identity). "
              f"Production packs are signed by {PINNED_SIGNER_IDENTITY}.")

    def read_sibling(name):
        path = manifest_path.parent / name
        return path.read_bytes() if path.is_file() else None

    try:
        signer = check_pack_signature(
            manifest, manifest_bytes, read_sibling,
            args.certificate_identity, args.certificate_oidc_issuer, trust,
        )
    except SignatureUnsupported as exc:
        print(
            f"ERROR: {exc}. This verifier checks cosign keyless signatures stored as a "
            f"Sigstore v0.3 bundle; re-run with an updated verify-pack.py.",
            file=sys.stderr,
        )
        return CANNOT_EVALUATE
    except SignatureInvalid as exc:
        print(f"FAIL signature: {exc}")
        return FAILED
    print(f"SIGNATURE OK: manifest.json is signed by {signer['identity']}")
    print(f"  OIDC issuer: {signer['issuer']}")
    print(f"  logged in {signer['log_url'] or 'the transparency log'} at "
          f"{_utc(signer['integrated_time'])} (log index {signer['log_index']})")
    return PASSED


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


def content_self_test():
    """MEI-2424 — the v1.10 content attestation: fixture hashes paired with the
    Rust tests, the production recompute path, the fail-closed dispatcher
    guards, the JCS digests paired with the proxy's sealer, and the offline
    content check (a record whose prompt was edited after sealing fails even
    though its hash still verifies)."""
    import tempfile

    ok = True

    def check(label, passed, detail=''):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}{': ' + detail if detail else ''}")
        ok = ok and passed

    # 19a / 19b — direct fn, without and with a join key.
    got = compute_event_hash_v1_10_llm_request(
        timestamp_utc="2026-05-17T00:00:00+00:00", join_context=None,
        content=_V1_10_CONTENT_FIXTURE_PAYLOAD, **_FIXTURE,
    )
    check('19a', got == V1_10_LLM_REQUEST_FIXTURE_HASH, 'v1.10 llm_request fixture hash matches')
    got = compute_event_hash_v1_10_llm_request(
        timestamp_utc="2026-05-17T00:00:00+00:00", join_context=_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD,
        content=_V1_10_CONTENT_FIXTURE_PAYLOAD, **_FIXTURE,
    )
    check('19b', got == V1_10_LLM_REQUEST_JOIN_FIXTURE_HASH, 'v1.10 llm_request fixture hash (with join) matches')

    # 19c — the production recompute path.
    event = dict(
        schema_version='v1.10', timestamp_utc='2026-05-17T00:00:00Z',
        event_id=_FIXTURE['event_id'], request_id=_FIXTURE['request_id'],
        model_requested=_FIXTURE['model_requested'], action=_FIXTURE['action'],
        input_tokens=_FIXTURE['input_tokens'], output_tokens=_FIXTURE['output_tokens'],
        total_tokens=_FIXTURE['total_tokens'], estimated_cost_usd=_FIXTURE['estimated_cost_usd'],
        content=dict(_V1_10_CONTENT_FIXTURE_PAYLOAD),
    )
    got = recompute_event_hash(event, _FIXTURE['sequence_number'], _FIXTURE['previous_hash'])
    check('19c', got == V1_10_LLM_REQUEST_FIXTURE_HASH, 'verify_manifest recompute path handles v1.10 llm_request')

    # 19d — fail closed: content outside v1.10, and v1.10 without content.
    rejected = True
    for stale in ('v1', 'v1.1', 'v1.2', 'v1.9'):
        try:
            compute_event_hash_dispatch(
                stale, 42, '2026-05-17T00:00:00+00:00', 'e', 'r', 'm', 'Allow', 0, 0,
                None, None, None, None, None, None, 'prev',
                join_context=_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD if stale == 'v1.9' else None,
                content=_V1_10_CONTENT_FIXTURE_PAYLOAD,
            )
            rejected = False
        except ValueError:
            pass
    try:
        compute_event_hash_dispatch(
            'v1.10', 42, '2026-05-17T00:00:00+00:00', 'e', 'r', 'm', 'Allow', 0, 0,
            None, None, None, None, None, None, 'prev',
        )
        rejected = False
    except ValueError:
        pass
    check('19d', rejected, 'content outside v1.10, and v1.10 without content, are rejected')

    # 19e — the JCS digests match the proxy's sealer on the same record.
    rec = _V1_10_DIGEST_FIXTURE_RECORD
    digests_ok = (
        sha256_jcs(rec['messages']) == V1_10_DIGEST_FIXTURE_PROMPT
        and hashlib.sha256(rec['response_text'].encode('utf-8')).hexdigest() == V1_10_DIGEST_FIXTURE_RESPONSE
        and sha256_jcs(rec['findings']) == V1_10_DIGEST_FIXTURE_FINDINGS
    )
    check('19e', digests_ok, 'JCS content digests match the proxy sealer')

    # 19f / 19g — offline: a sealed v1.10 record verifies; the same record with
    # its prompt edited after sealing still hash-verifies (the prompt is
    # outside the preimage) but fails the content check.
    genesis = genesis_hash()
    sealed = dict(
        schema_version='v1.10', sequence_number=0, timestamp_utc='2026-01-01T00:00:00+00:00',
        event_id='evt-0', request_id='req-0', model_requested='gpt-4.1-mini', action='Block',
        input_tokens=11, output_tokens=0, estimated_cost_usd=None, previous_hash=genesis,
        messages=rec['messages'], response_text=rec['response_text'], findings=rec['findings'],
        content=dict(
            capture_policy='full',
            prompt_sha256_jcs=V1_10_DIGEST_FIXTURE_PROMPT,
            response_sha256=V1_10_DIGEST_FIXTURE_RESPONSE,
            stored_prompt_sha256_jcs=V1_10_DIGEST_FIXTURE_PROMPT,
            stored_response_sha256=V1_10_DIGEST_FIXTURE_RESPONSE,
            findings_sha256_jcs=V1_10_DIGEST_FIXTURE_FINDINGS,
        ),
    )
    sealed['event_hash'] = recompute_event_hash(sealed, 0, genesis)
    manifest = {'hash_version': 'v1', 'prefix': 'audit/self-test/',
                'events': [{'sequence': 0, 'recomputed_event_hash': sealed['event_hash']}]}
    with tempfile.TemporaryDirectory() as tmp:
        records = Path(tmp) / 'records'
        records.mkdir()
        path = records / record_file_name(0)
        path.write_bytes(json.dumps(sealed).encode('utf-8'))
        check('19f', verify_manifest_with(local_fetcher(records), manifest, quiet=True),
              'offline verification passes a sealed v1.10 record')
        edited = json.loads(json.dumps(sealed))
        edited['messages'][0]['content'] = edited['messages'][0]['content'].replace('123-45-6789', '[PII:ssn]')
        path.write_bytes(json.dumps(edited).encode('utf-8'))
        still_hashes = recompute_event_hash(edited, 0, genesis) == sealed['event_hash']
        detected = not verify_manifest_with(local_fetcher(records), manifest, quiet=True)
        check('19g', still_hashes and detected,
              'a prompt edited after sealing is detected by the content check')

    return ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

# BEGIN GENERATED SIGNATURE VECTORS (fixtures/generate-signature-vectors.py; do not edit by hand)
# TEST-ONLY keys, certificates and log. Never part of the default trust root.
_SELFTEST_SIGNATURE_VECTORS = {
    "identity": "https://selftest.invalid/meilynx-verify/test-only-signer",
    "issuer": "https://selftest.invalid/test-only-oidc-issuer",
    "manifest": (
        "ewogICJzY2hlbWFfdmVyc2lvbiI6ICIxLjAiLAogICJwYWNrX2lkIjogIjAwMDAwMDAwLTAw"
        "MDAtNDAwMC04MDAwLTAwMDAwMDAwMDkyMiIsCiAgIndpbmRvdyI6ICJCIiwKICAic2lnbmlu"
        "Z19kZWZlcnJlZCI6IGZhbHNlLAogICJnZW5lcmF0ZWRfYXQiOiAiMjAyNi0wOS0yMVQxNDox"
        "MzowMFoiLAogICJnZW5lcmF0b3JfdmVyc2lvbiI6ICJ0ZXN0LW9ubHkiLAogICJzdWJzdHJh"
        "dGVfbmFtZSI6ICJtZWlseW54LXZlcmlmeSBzZWxmLXRlc3QgKFRFU1QtT05MWSkiLAogICJi"
        "dWNrZXQiOiAic2VsZnRlc3QuaW52YWxpZCIsCiAgInByZWZpeCI6ICJhdWRpdC9zZWxmLXRl"
        "c3QvIiwKICAiZnJvbV9zZXF1ZW5jZSI6IDAsCiAgInRvX3NlcXVlbmNlIjogMSwKICAiaGFz"
        "aF9hbGdvcml0aG0iOiAic2hhMjU2IiwKICAiaGFzaF92ZXJzaW9uIjogInYxIiwKICAiZ2Vu"
        "ZXNpc19oYXNoIjogImMyOTg5NDAzY2Y4OTdkYWNjZDgyNWNjNDEzNzdiODA0MzQzYzVhNDg1"
        "MWVhYzFkYWYzMmI1OGViMWZhNGVkZjgiLAogICJ2ZXJpZmllZCI6IHRydWUsCiAgInJlY29y"
        "ZHNfY2hlY2tlZCI6IDIsCiAgImZpcnN0X3NlcXVlbmNlIjogMCwKICAibGFzdF9zZXF1ZW5j"
        "ZSI6IDEsCiAgImJyZWFrX2F0X3NlcXVlbmNlIjogbnVsbCwKICAidmlvbGF0aW9uX2tpbmQi"
        "OiBudWxsLAogICJlcnJvciI6IG51bGwsCiAgInNpZ25hdHVyZSI6IHsKICAgICJtZXRob2Qi"
        "OiAiY29zaWduLXNpZ3N0b3JlLWtleWxlc3MiLAogICAgInNpZ25lZF9hcnRpZmFjdCI6ICJt"
        "YW5pZmVzdC5qc29uIiwKICAgICJzaWduYXR1cmVfZmlsZSI6ICJtYW5pZmVzdC5qc29uLnNp"
        "Z3N0b3JlLmpzb24iLAogICAgImJ1bmRsZV9maWxlIjogbnVsbCwKICAgICJ0cmFuc3BhcmVu"
        "Y3lfbG9nIjogInJla29yIgogIH0sCiAgImV2ZW50cyI6IFsKICAgIHsKICAgICAgInNlcXVl"
        "bmNlIjogMCwKICAgICAgInRpbWVzdGFtcF91dGMiOiAiMjAyNi0wOS0yMVQxNDowMDowMCsw"
        "MDowMCIsCiAgICAgICJhY3Rpb24iOiAiYWxsb3ciLAogICAgICAibW9kZWxfcmVxdWVzdGVk"
        "IjogImdwdC00LjEtbWluaSIsCiAgICAgICJwcm9qZWN0X2lkIjogbnVsbCwKICAgICAgInJl"
        "cXVlc3RfaWQiOiAicmVxLXNlbGZ0ZXN0LTAiLAogICAgICAiZXZlbnRfaWQiOiAiZXZ0LXNl"
        "bGZ0ZXN0LTAiLAogICAgICAic3RvcmVkX2V2ZW50X2hhc2giOiAiYjIyZjIyYzgyYjI5ZmNh"
        "MjE0MjZkNzkzNzdmYTIwNTEyYTQzNjA3NjAwZWRmMDNmYmZlMGJmOGEwYWVmMGQyOSIsCiAg"
        "ICAgICJyZWNvbXB1dGVkX2V2ZW50X2hhc2giOiAiYjIyZjIyYzgyYjI5ZmNhMjE0MjZkNzkz"
        "NzdmYTIwNTEyYTQzNjA3NjAwZWRmMDNmYmZlMGJmOGEwYWVmMGQyOSIsCiAgICAgICJoYXNo"
        "X21hdGNoIjogdHJ1ZSwKICAgICAgInByZXZpb3VzX2hhc2hfbWF0Y2giOiB0cnVlCiAgICB9"
        "LAogICAgewogICAgICAic2VxdWVuY2UiOiAxLAogICAgICAidGltZXN0YW1wX3V0YyI6ICIy"
        "MDI2LTA5LTIxVDE0OjAwOjAxKzAwOjAwIiwKICAgICAgImFjdGlvbiI6ICJhbGxvdyIsCiAg"
        "ICAgICJtb2RlbF9yZXF1ZXN0ZWQiOiAiZ3B0LTQuMS1taW5pIiwKICAgICAgInByb2plY3Rf"
        "aWQiOiBudWxsLAogICAgICAicmVxdWVzdF9pZCI6ICJyZXEtc2VsZnRlc3QtMSIsCiAgICAg"
        "ICJldmVudF9pZCI6ICJldnQtc2VsZnRlc3QtMSIsCiAgICAgICJzdG9yZWRfZXZlbnRfaGFz"
        "aCI6ICIyZjVkYTVmZDM4YTQ0OWU1NWFjZDgzMTY5MmZkMzNhMWExYWU2MDQ3NDQyOTY0ZTdk"
        "NDFmMDk1ODgzMGM5ZWRlIiwKICAgICAgInJlY29tcHV0ZWRfZXZlbnRfaGFzaCI6ICIyZjVk"
        "YTVmZDM4YTQ0OWU1NWFjZDgzMTY5MmZkMzNhMWExYWU2MDQ3NDQyOTY0ZTdkNDFmMDk1ODgz"
        "MGM5ZWRlIiwKICAgICAgImhhc2hfbWF0Y2giOiB0cnVlLAogICAgICAicHJldmlvdXNfaGFz"
        "aF9tYXRjaCI6IHRydWUKICAgIH0KICBdCn0K"
    ),
    "records": (
        "[{\"action\":\"allow\",\"cache_creation_input_tokens\":null,\"cache_read_input_"
        "tokens\":null,\"cached_input_tokens\":null,\"estimated_cost_usd\":0.000123,\"e"
        "vent_hash\":\"b22f22c82b29fca21426d79377fa20512a43607600edf03fbfe0bf8a0aef"
        "0d29\",\"event_id\":\"evt-selftest-0\",\"input_tokens\":11,\"model_requested\":\"g"
        "pt-4.1-mini\",\"output_tokens\":7,\"previous_hash\":\"c2989403cf897daccd825cc4"
        "1377b804343c5a4851eac1daf32b58eb1fa4edf8\",\"reasoning_tokens\":null,\"reque"
        "st_id\":\"req-selftest-0\",\"schema_version\":\"v1\",\"sequence_number\":0,\"times"
        "tamp_utc\":\"2026-09-21T14:00:00+00:00\",\"total_tokens\":18},{\"action\":\"allo"
        "w\",\"cache_creation_input_tokens\":null,\"cache_read_input_tokens\":null,\"ca"
        "ched_input_tokens\":null,\"estimated_cost_usd\":0.000123,\"event_hash\":\"2f5d"
        "a5fd38a449e55acd831692fd33a1a1ae6047442964e7d41f0958830c9ede\",\"event_id\""
        ":\"evt-selftest-1\",\"input_tokens\":13,\"model_requested\":\"gpt-4.1-mini\",\"ou"
        "tput_tokens\":7,\"previous_hash\":\"b22f22c82b29fca21426d79377fa20512a436076"
        "00edf03fbfe0bf8a0aef0d29\",\"reasoning_tokens\":null,\"request_id\":\"req-self"
        "test-1\",\"schema_version\":\"v1\",\"sequence_number\":1,\"timestamp_utc\":\"2026-"
        "09-21T14:00:01+00:00\",\"total_tokens\":20}]"
    ),
    "trusted_root": (
        "{\"certificateAuthorities\":[{\"certChain\":{\"certificates\":[{\"rawBytes\":\"MI"
        "IB8TCCAXegAwIBAgIBAjAKBggqhkjOPQQDAzBBMSEwHwYDVQQKDBhtZWlseW54LXZlcmlmeS"
        "BzZWxmLXRlc3QxHDAaBgNVBAMME1RFU1QtT05MWSBDQS1BIHJvb3QwHhcNMjYwNTI4MjAyNj"
        "QwWhcNMjcwMTE1MDgwMDAwWjBJMSEwHwYDVQQKDBhtZWlseW54LXZlcmlmeSBzZWxmLXRlc3"
        "QxJDAiBgNVBAMMG1RFU1QtT05MWSBDQS1BIGludGVybWVkaWF0ZTB2MBAGByqGSM49AgEGBS"
        "uBBAAiA2IABNSWaOySuBtgJ5eX6xX+AjY82tXdYNlHuSVZqYX4WizrJTBGcZRC2sayc1/RNw"
        "xVPGi0cR2SI9sPwIOGu615VGQB/umkX9pdSyuSl0/yh/KNjbyBkW2KFsD1OjACDzciTqM7MD"
        "kwDgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBIGA1UdEwEB/wQIMAYBAf"
        "8CAQAwCgYIKoZIzj0EAwMDaAAwZQIwLwGs8Yw5+4lTwrleTUpPdWsVhBJTW1Md1yMfmnF1Zt"
        "+5QB+bJBFv669+lCVuAPTdAjEAvvsTv/jIjWOBsOlAnY3oIAOFy7wO3vn7jeLfRBoPC8W7Tv"
        "Z/Tyj/LezaqQFmbsM4\"},{\"rawBytes\":\"MIIB1DCCAVqgAwIBAgIBATAKBggqhkjOPQQDAz"
        "BBMSEwHwYDVQQKDBhtZWlseW54LXZlcmlmeSBzZWxmLXRlc3QxHDAaBgNVBAMME1RFU1QtT0"
        "5MWSBDQS1BIHJvb3QwHhcNMjYwNTI4MjAyNjQwWhcNMjcwMTE1MDgwMDAwWjBBMSEwHwYDVQ"
        "QKDBhtZWlseW54LXZlcmlmeSBzZWxmLXRlc3QxHDAaBgNVBAMME1RFU1QtT05MWSBDQS1BIH"
        "Jvb3QwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATqaRCsNQdFl71dnLSwmdVdMpH850uRw4ZI7E"
        "65Ne+Se9Y3SwctKtLZvswc7F6frvzjTx0eVzqE7L9gguSoofUaj6pH1nkoC2MqiXJd3RsIoM"
        "1m1Hpc5S3EFzNn1vneXvyjJjAkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/Ag"
        "EBMAoGCCqGSM49BAMDA2gAMGUCMQDorxA8y3EFLMEUTCP9TNpjoSNPHsYX5yZXIqeTsi2Gq9"
        "SSIIefDmPALu1r3Vwc8jMCMF+krqbD1v/SMFavkNWJ5jGy3ofpXmhfxBpDJXvhbJtBkqiuPb"
        "H+3CwAH/t0mL7wng==\"}]},\"subject\":{\"commonName\":\"TEST-ONLY\",\"organization"
        "\":\"meilynx-verify self-test\"},\"uri\":\"https://selftest.invalid/fulcio\",\"v"
        "alidFor\":{\"start\":\"2026-01-01T00:00:00Z\"}}],\"ctlogs\":[],\"mediaType\":\"app"
        "lication/vnd.dev.sigstore.trustedroot+json;version=0.1\",\"timestampAuthor"
        "ities\":[],\"tlogs\":[{\"baseUrl\":\"https://selftest.invalid/rekor\",\"hashAlgo"
        "rithm\":\"SHA2_256\",\"logId\":{\"keyId\":\"pIdAtgmNH6Fr/ATdjpQQKG5cR/b+kGJsY28Z"
        "+DigQas=\"},\"publicKey\":{\"keyDetails\":\"PKIX_ECDSA_P256_SHA_256\",\"rawBytes"
        "\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfd2zMlDZZcHj50/PvH4w3+nfUHnKwF8j6"
        "yw5SRcbhmA8NS9h0Doop423aGpVlWV1mDiPppebkFx6q7h9Jqvq0Q==\",\"validFor\":{\"st"
        "art\":\"2026-01-01T00:00:00Z\"}}}]}"
    ),
    "foreign_trusted_root": (
        "{\"certificateAuthorities\":[{\"certChain\":{\"certificates\":[{\"rawBytes\":\"MI"
        "IB8TCCAXegAwIBAgIBAjAKBggqhkjOPQQDAzBBMSEwHwYDVQQKDBhtZWlseW54LXZlcmlmeS"
        "BzZWxmLXRlc3QxHDAaBgNVBAMME1RFU1QtT05MWSBDQS1CIHJvb3QwHhcNMjYwNTI4MjAyNj"
        "QwWhcNMjcwMTE1MDgwMDAwWjBJMSEwHwYDVQQKDBhtZWlseW54LXZlcmlmeSBzZWxmLXRlc3"
        "QxJDAiBgNVBAMMG1RFU1QtT05MWSBDQS1CIGludGVybWVkaWF0ZTB2MBAGByqGSM49AgEGBS"
        "uBBAAiA2IABORtdcOui3hhclDNKB6m0TNxmlBxy7NH86ND0bKJBXBvarXrnm91tcDn2aJGef"
        "dGTPkRu81J1Z022qmff2I2EUKjPL/aAqQMkAvP6cuoHqWgoinNbXf0zD5atJZdFF61cqM7MD"
        "kwDgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBIGA1UdEwEB/wQIMAYBAf"
        "8CAQAwCgYIKoZIzj0EAwMDaAAwZQIxAOF6dpnIK7+gYPKoU06nZtYtKqXvxqjDTWyr8BN/8+"
        "+51obzVtyXQNDIXyWRHBL/GgIwcztA+J34C96OHXcKd9mtQs3OqQVKu7L1KAKQC5H41LvkMU"
        "2pgOWYe9IG5Qrsu7R3\"},{\"rawBytes\":\"MIIB1DCCAVqgAwIBAgIBATAKBggqhkjOPQQDAz"
        "BBMSEwHwYDVQQKDBhtZWlseW54LXZlcmlmeSBzZWxmLXRlc3QxHDAaBgNVBAMME1RFU1QtT0"
        "5MWSBDQS1CIHJvb3QwHhcNMjYwNTI4MjAyNjQwWhcNMjcwMTE1MDgwMDAwWjBBMSEwHwYDVQ"
        "QKDBhtZWlseW54LXZlcmlmeSBzZWxmLXRlc3QxHDAaBgNVBAMME1RFU1QtT05MWSBDQS1CIH"
        "Jvb3QwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQ6Uxga7pprz4HCE9hEP74ItaaB6vArGzyDwC"
        "4LxpO0wb0YSNyMJpuaMCmpWgjzQUxY6+0TBMUkCrpoCcSlUmOqt1CysgUrh6ExGrf6boNBRz"
        "kkbClAnRUPzYVhsegxEu2jJjAkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/Ag"
        "EBMAoGCCqGSM49BAMDA2gAMGUCMQCWRibt3/sutmuUEca+x2OTb0Th/eQBby/beOyJFsdc0i"
        "V7Fms1WfIv8OyZQMFoVfwCMGaLVNZ6OssJuKd8+U7r0Fs10yrnZcAkCDhCQdQszo7WBHRJ0e"
        "Z/yYOm0X0UaY8BtA==\"}]},\"subject\":{\"commonName\":\"TEST-ONLY\",\"organization"
        "\":\"meilynx-verify self-test\"},\"uri\":\"https://selftest.invalid/fulcio\",\"v"
        "alidFor\":{\"start\":\"2026-01-01T00:00:00Z\"}}],\"ctlogs\":[],\"mediaType\":\"app"
        "lication/vnd.dev.sigstore.trustedroot+json;version=0.1\",\"timestampAuthor"
        "ities\":[],\"tlogs\":[{\"baseUrl\":\"https://selftest.invalid/rekor\",\"hashAlgo"
        "rithm\":\"SHA2_256\",\"logId\":{\"keyId\":\"pIdAtgmNH6Fr/ATdjpQQKG5cR/b+kGJsY28Z"
        "+DigQas=\"},\"publicKey\":{\"keyDetails\":\"PKIX_ECDSA_P256_SHA_256\",\"rawBytes"
        "\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfd2zMlDZZcHj50/PvH4w3+nfUHnKwF8j6"
        "yw5SRcbhmA8NS9h0Doop423aGpVlWV1mDiPppebkFx6q7h9Jqvq0Q==\",\"validFor\":{\"st"
        "art\":\"2026-01-01T00:00:00Z\"}}}]}"
    ),
    "bundle_valid": (
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"messageSig"
        "nature\":{\"messageDigest\":{\"algorithm\":\"SHA2_256\",\"digest\":\"bpi+S48etrwDu"
        "pdIzI5ir900sclwkY9ArAckfn+HkMc=\"},\"signature\":\"MEUCIBWDS9HRGvV7HsOjTGGXT"
        "rOgcGWEC0040U+YxDq8qfnrAiEAk8KJKGClx3rRSy7xRnV8TSYxSbp6d5CvIzBWH6WVzfc=\""
        "},\"verificationMaterial\":{\"certificate\":{\"rawBytes\":\"MIICRzCCAc6gAwIBAgI"
        "CA+kwCgYIKoZIzj0EAwMwSTEhMB8GA1UECgwYbWVpbHlueC12ZXJpZnkgc2VsZi10ZXN0MSQ"
        "wIgYDVQQDDBtURVNULU9OTFkgQ0EtQSBpbnRlcm1lZGlhdGUwHhcNMjYwOTIxMTQxMjIwWhc"
        "NMjYwOTIxMTQyMjIwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa8DfuCe/XUHqG7Q"
        "+ZKGnDKkv3hxlEMhkEDzEiZL2fLxggFC1lAUm/X+wD0OcuwLAOw/2V5qPBwbU+ctJ04R/DaO"
        "B7jCB6zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwRgYDVR0RAQH/BDw"
        "wOoY4aHR0cHM6Ly9zZWxmdGVzdC5pbnZhbGlkL21laWx5bngtdmVyaWZ5L3Rlc3Qtb25seS1"
        "zaWduZXIwPAYKKwYBBAGDvzABAQQuaHR0cHM6Ly9zZWxmdGVzdC5pbnZhbGlkL3Rlc3Qtb25"
        "seS1vaWRjLWlzc3VlcjA+BgorBgEEAYO/MAEIBDAMLmh0dHBzOi8vc2VsZnRlc3QuaW52YWx"
        "pZC90ZXN0LW9ubHktb2lkYy1pc3N1ZXIwCgYIKoZIzj0EAwMDZwAwZAIwDj5NxMOYe4yiyw6"
        "jdG1yBWq4hnNYnSnGTVrN6EIY1t72TwExy/73+hE/bsWskfRcAjBzWFHV3uBQJn+hBCvEQSd"
        "17MOEOMXERzVeLADWFncupB/+TtaXPoA3rYMTjQ2T9fA=\"},\"tlogEntries\":[{\"canonic"
        "alizedBody\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiw"
        "ic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI"
        "2ZTk4YmU0YjhmMWViNmJjMDNiYTk3NDhjYzhlNjJhZmRkMzRiMWM5NzA5MThmNDBhYzA3MjQ"
        "3ZTdmODc5MGM3In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJQldEUzlIUkd2Vjd"
        "Ic09qVEdHWFRyT2djR1dFQzAwNDBVK1l4RHE4cWZuckFpRUFrOEtKS0dDbHgzclJTeTd4Um5"
        "WOFRTWXhTYnA2ZDVDdkl6QldINldWemZjPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFM"
        "wdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTlNla05EUVdNMlowRjN"
        "TVUpCWjBsRFFTdHJkME5uV1VsTGIxcEplbW93UlVGM1RYZFRWRVZvVFVJNFIwRXhWVVZEWjN"
        "kWllsZFdjR0pJYkhVS1pVTXhNbHBZU25CYWJtdG5ZekpXYzFwcE1UQmFXRTR3VFZOUmQwbG5"
        "XVVJXVVZGRVJFSjBWVkpXVGxWTVZUbFBWRVpyWjFFd1JYUlJVMEp3WW01U2JBcGpiVEZzV2t"
        "kc2FHUkhWWGRJYUdOT1RXcFpkMDlVU1hoTlZGRjRUV3BKZDFkb1kwNU5hbGwzVDFSSmVFMVV"
        "VWGxOYWtsM1YycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZ"
        "GalJGRm5RVVZoT0VSbWRVTmxMMWhWU0hGSE4xRXJXa3RIYmtSTGEzWXphSGhzUlUxb2EwVkV"
        "la1VLYVZwTU1tWk1lR2RuUmtNeGJFRlZiUzlZSzNkRU1FOWpkWGRNUVU5M0x6SldOWEZRUW5"
        "kaVZTdGpkRW93TkZJdlJHRlBRamRxUTBJMmVrRlBRbWRPVmdwSVVUaENRV1k0UlVKQlRVTkN"
        "ORUYzUlhkWlJGWlNNR3hDUVhkM1EyZFpTVXQzV1VKQ1VWVklRWGROZDFKbldVUldVakJTUVZ"
        "GSUwwSkVkM2RQYjFrMENtRklVakJqU0UwMlRIazVlbHBYZUcxa1IxWjZaRU0xY0dKdVdtaGl"
        "SMnhyVERJeGJHRlhlRFZpYm1kMFpHMVdlV0ZYV2pWTU0xSnNZek5SZEdJeU5YTUtaVk14ZW1"
        "GWFpIVmFXRWwzVUVGWlMwdDNXVUpDUVVkRWRucEJRa0ZSVVhWaFNGSXdZMGhOTmt4NU9YcGF"
        "WM2h0WkVkV2VtUkROWEJpYmxwb1lrZHNhd3BNTTFKc1l6TlJkR0l5TlhObFV6RjJZVmRTYWt"
        "4WGJIcGpNMVpzWTJwQkswSm5iM0pDWjBWRlFWbFBMMDFCUlVsQ1JFRk5URzFvTUdSSVFucFB"
        "hVGgyQ21NeVZuTmFibEpzWXpOUmRXRlhOVEpaVjNod1drTTVNRnBZVGpCTVZ6bDFZa2hyZEd"
        "JeWJHdFplVEZ3WXpOT01WcFlTWGREWjFsSlMyOWFTWHBxTUVVS1FYZE5SRnAzUVhkYVFVbDN"
        "SR28xVG5oTlQxbGxOSGxwZVhjMmFtUkhNWGxDVjNFMGFHNU9XVzVUYmtkVVZuSk9Oa1ZKV1R"
        "GME56SlVkMFY0ZVM4M013b3JhRVV2WW5OWGMydG1VbU5CYWtKNlYwWklWak4xUWxGS2JpdG9"
        "Ra04yUlZGVFpERTNUVTlGVDAxWVJWSjZWbVZNUVVSWFJtNWpkWEJDTHl0VWRHRllDbEJ2UVR"
        "OeVdVMVVhbEV5VkRsbVFUMEtMUzB0TFMxRlRrUWdRMFZTVkVsR1NVTkJWRVV0TFMwdExRbz0"
        "ifX19fQ==\",\"inclusionPromise\":{\"signedEntryTimestamp\":\"MEUCIQDfvqiue3EiY"
        "11W965J2VcwgQPg0/1z4QEvlRnER6Dq9wIgGurs5HnW+5qoGdfxNGQMqIkmlp73HY1WvsoA1"
        "zV9+SY=\"},\"inclusionProof\":{\"checkpoint\":{\"envelope\":\"selftest.invalid -"
        " 1\\n14\\nMh6MI16i1mVZ2V13PKg0/Qvc1PUOPtsqgcIRyztB6y0=\\n\\n\\u2014 selftest."
        "invalid pIdAtjBFAiEAhfSk0IrGO/u8uZPBKHBfSwcpcheJrJb/MR44XpCqkY8CIDjpwnYu"
        "1X6AX4P378EZwgX2btNsLAVKG75k5E3nmGqT\\n\"},\"hashes\":[\"lTzkWsbNmuhIvi/mgMPp"
        "r6d5J8t6xXXgutIDAS4L97A=\",\"F18l+W8Xr/hsLE0CMl/oc3X6AMWpgnmjcnoVYH2kGxs=\""
        ",\"kDtFsD2vdXIoKxMLYl/1liFDgPr/lqqXn58MgDRiPsc=\",\"PBeZC6orPSRXZ67IEMXIhvT"
        "TyQrAQ9E43sfLiA0OtEM=\"],\"logIndex\":\"0\",\"rootHash\":\"Mh6MI16i1mVZ2V13PKg0/"
        "Qvc1PUOPtsqgcIRyztB6y0=\",\"treeSize\":\"14\"},\"integratedTime\":\"1790000000\","
        "\"kindVersion\":{\"kind\":\"hashedrekord\",\"version\":\"0.0.1\"},\"logId\":{\"keyId\""
        ":\"pIdAtgmNH6Fr/ATdjpQQKG5cR/b+kGJsY28Z+DigQas=\"},\"logIndex\":\"0\"}]}}"
    ),
    "bundle_entry_mismatch": (
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"messageSig"
        "nature\":{\"messageDigest\":{\"algorithm\":\"SHA2_256\",\"digest\":\"bpi+S48etrwDu"
        "pdIzI5ir900sclwkY9ArAckfn+HkMc=\"},\"signature\":\"MEUCIBWDS9HRGvV7HsOjTGGXT"
        "rOgcGWEC0040U+YxDq8qfnrAiEAk8KJKGClx3rRSy7xRnV8TSYxSbp6d5CvIzBWH6WVzfc=\""
        "},\"verificationMaterial\":{\"certificate\":{\"rawBytes\":\"MIICRzCCAc6gAwIBAgI"
        "CA+kwCgYIKoZIzj0EAwMwSTEhMB8GA1UECgwYbWVpbHlueC12ZXJpZnkgc2VsZi10ZXN0MSQ"
        "wIgYDVQQDDBtURVNULU9OTFkgQ0EtQSBpbnRlcm1lZGlhdGUwHhcNMjYwOTIxMTQxMjIwWhc"
        "NMjYwOTIxMTQyMjIwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa8DfuCe/XUHqG7Q"
        "+ZKGnDKkv3hxlEMhkEDzEiZL2fLxggFC1lAUm/X+wD0OcuwLAOw/2V5qPBwbU+ctJ04R/DaO"
        "B7jCB6zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwRgYDVR0RAQH/BDw"
        "wOoY4aHR0cHM6Ly9zZWxmdGVzdC5pbnZhbGlkL21laWx5bngtdmVyaWZ5L3Rlc3Qtb25seS1"
        "zaWduZXIwPAYKKwYBBAGDvzABAQQuaHR0cHM6Ly9zZWxmdGVzdC5pbnZhbGlkL3Rlc3Qtb25"
        "seS1vaWRjLWlzc3VlcjA+BgorBgEEAYO/MAEIBDAMLmh0dHBzOi8vc2VsZnRlc3QuaW52YWx"
        "pZC90ZXN0LW9ubHktb2lkYy1pc3N1ZXIwCgYIKoZIzj0EAwMDZwAwZAIwDj5NxMOYe4yiyw6"
        "jdG1yBWq4hnNYnSnGTVrN6EIY1t72TwExy/73+hE/bsWskfRcAjBzWFHV3uBQJn+hBCvEQSd"
        "17MOEOMXERzVeLADWFncupB/+TtaXPoA3rYMTjQ2T9fA=\"},\"tlogEntries\":[{\"canonic"
        "alizedBody\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiw"
        "ic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJ"
        "lMTQ0MWQxZmU5MGJkOTdiNmEzNGQ4YzgzMjFlZmEyZDIzZmQ5M2E0ZTZmNWUzYmEwMzI4ZmF"
        "iZGFlYjg4YWE0In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJRk9sMEo0TmlHVGV"
        "Td0U4M05sZFJ6K2Vwdkl5K3cvRDkwOHFWRSttc05HQkFpQTk2YU5McU5HRGFDcy84d1hmWDB"
        "GMVVMNWpNc1NhWkV6ZkU0dUg5cWR4VGc9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFM"
        "wdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTlNla05EUVdNMlowRjN"
        "TVUpCWjBsRFFTdHJkME5uV1VsTGIxcEplbW93UlVGM1RYZFRWRVZvVFVJNFIwRXhWVVZEWjN"
        "kWllsZFdjR0pJYkhVS1pVTXhNbHBZU25CYWJtdG5ZekpXYzFwcE1UQmFXRTR3VFZOUmQwbG5"
        "XVVJXVVZGRVJFSjBWVkpXVGxWTVZUbFBWRVpyWjFFd1JYUlJVMEp3WW01U2JBcGpiVEZzV2t"
        "kc2FHUkhWWGRJYUdOT1RXcFpkMDlVU1hoTlZGRjRUV3BKZDFkb1kwNU5hbGwzVDFSSmVFMVV"
        "VWGxOYWtsM1YycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZ"
        "GalJGRm5RVVZoT0VSbWRVTmxMMWhWU0hGSE4xRXJXa3RIYmtSTGEzWXphSGhzUlUxb2EwVkV"
        "la1VLYVZwTU1tWk1lR2RuUmtNeGJFRlZiUzlZSzNkRU1FOWpkWGRNUVU5M0x6SldOWEZRUW5"
        "kaVZTdGpkRW93TkZJdlJHRlBRamRxUTBJMmVrRlBRbWRPVmdwSVVUaENRV1k0UlVKQlRVTkN"
        "ORUYzUlhkWlJGWlNNR3hDUVhkM1EyZFpTVXQzV1VKQ1VWVklRWGROZDFKbldVUldVakJTUVZ"
        "GSUwwSkVkM2RQYjFrMENtRklVakJqU0UwMlRIazVlbHBYZUcxa1IxWjZaRU0xY0dKdVdtaGl"
        "SMnhyVERJeGJHRlhlRFZpYm1kMFpHMVdlV0ZYV2pWTU0xSnNZek5SZEdJeU5YTUtaVk14ZW1"
        "GWFpIVmFXRWwzVUVGWlMwdDNXVUpDUVVkRWRucEJRa0ZSVVhWaFNGSXdZMGhOTmt4NU9YcGF"
        "WM2h0WkVkV2VtUkROWEJpYmxwb1lrZHNhd3BNTTFKc1l6TlJkR0l5TlhObFV6RjJZVmRTYWt"
        "4WGJIcGpNMVpzWTJwQkswSm5iM0pDWjBWRlFWbFBMMDFCUlVsQ1JFRk5URzFvTUdSSVFucFB"
        "hVGgyQ21NeVZuTmFibEpzWXpOUmRXRlhOVEpaVjNod1drTTVNRnBZVGpCTVZ6bDFZa2hyZEd"
        "JeWJHdFplVEZ3WXpOT01WcFlTWGREWjFsSlMyOWFTWHBxTUVVS1FYZE5SRnAzUVhkYVFVbDN"
        "SR28xVG5oTlQxbGxOSGxwZVhjMmFtUkhNWGxDVjNFMGFHNU9XVzVUYmtkVVZuSk9Oa1ZKV1R"
        "GME56SlVkMFY0ZVM4M013b3JhRVV2WW5OWGMydG1VbU5CYWtKNlYwWklWak4xUWxGS2JpdG9"
        "Ra04yUlZGVFpERTNUVTlGVDAxWVJWSjZWbVZNUVVSWFJtNWpkWEJDTHl0VWRHRllDbEJ2UVR"
        "OeVdVMVVhbEV5VkRsbVFUMEtMUzB0TFMxRlRrUWdRMFZTVkVsR1NVTkJWRVV0TFMwdExRbz0"
        "ifX19fQ==\",\"inclusionPromise\":{\"signedEntryTimestamp\":\"MEQCIBdbeCFbqS67c"
        "fZeA3hFNIoxPZL+/wHtTu4buH+/t3N5AiAoACNhzgyVhUXbD1kCzx2jYcIT7bh+8hAEuvkGn"
        "h0isw==\"},\"inclusionProof\":{\"checkpoint\":{\"envelope\":\"selftest.invalid -"
        " 1\\n14\\nMh6MI16i1mVZ2V13PKg0/Qvc1PUOPtsqgcIRyztB6y0=\\n\\n\\u2014 selftest."
        "invalid pIdAtjBFAiEAhfSk0IrGO/u8uZPBKHBfSwcpcheJrJb/MR44XpCqkY8CIDjpwnYu"
        "1X6AX4P378EZwgX2btNsLAVKG75k5E3nmGqT\\n\"},\"hashes\":[\"SFlDUHGh8k6WPibTOBwV"
        "/j85wNS9xkmiIuXHR0s5MyI=\",\"F18l+W8Xr/hsLE0CMl/oc3X6AMWpgnmjcnoVYH2kGxs=\""
        ",\"kDtFsD2vdXIoKxMLYl/1liFDgPr/lqqXn58MgDRiPsc=\",\"PBeZC6orPSRXZ67IEMXIhvT"
        "TyQrAQ9E43sfLiA0OtEM=\"],\"logIndex\":\"1\",\"rootHash\":\"Mh6MI16i1mVZ2V13PKg0/"
        "Qvc1PUOPtsqgcIRyztB6y0=\",\"treeSize\":\"14\"},\"integratedTime\":\"1790000000\","
        "\"kindVersion\":{\"kind\":\"hashedrekord\",\"version\":\"0.0.1\"},\"logId\":{\"keyId\""
        ":\"pIdAtgmNH6Fr/ATdjpQQKG5cR/b+kGJsY28Z+DigQas=\"},\"logIndex\":\"1\"}]}}"
    ),
    "bundle_outside_validity": (
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"messageSig"
        "nature\":{\"messageDigest\":{\"algorithm\":\"SHA2_256\",\"digest\":\"bpi+S48etrwDu"
        "pdIzI5ir900sclwkY9ArAckfn+HkMc=\"},\"signature\":\"MEUCIQC1tQsxefutQGa1gvnNw"
        "7zvM/s4sxUwfZdCdZBBYbGM0AIgPy8G/QZ5SL46DnqbGYhj0tKebtGLTFZwQFyTfe1y7dk=\""
        "},\"verificationMaterial\":{\"certificate\":{\"rawBytes\":\"MIICSTCCAc6gAwIBAgI"
        "CA+owCgYIKoZIzj0EAwMwSTEhMB8GA1UECgwYbWVpbHlueC12ZXJpZnkgc2VsZi10ZXN0MSQ"
        "wIgYDVQQDDBtURVNULU9OTFkgQ0EtQSBpbnRlcm1lZGlhdGUwHhcNMjYwOTIxMTM1MzIwWhc"
        "NMjYwOTIxMTQwMzIwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3ic9K8A8NS/lKry"
        "ZWox3BOLrgv5sWbagqGogoJyVuPZ8jjNDasffD/ckGEpYKIVwSKCLR8JbNhIy11zQvq+TP6O"
        "B7jCB6zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwRgYDVR0RAQH/BDw"
        "wOoY4aHR0cHM6Ly9zZWxmdGVzdC5pbnZhbGlkL21laWx5bngtdmVyaWZ5L3Rlc3Qtb25seS1"
        "zaWduZXIwPAYKKwYBBAGDvzABAQQuaHR0cHM6Ly9zZWxmdGVzdC5pbnZhbGlkL3Rlc3Qtb25"
        "seS1vaWRjLWlzc3VlcjA+BgorBgEEAYO/MAEIBDAMLmh0dHBzOi8vc2VsZnRlc3QuaW52YWx"
        "pZC90ZXN0LW9ubHktb2lkYy1pc3N1ZXIwCgYIKoZIzj0EAwMDaQAwZgIxAIVH7C1Ab1PSSOC"
        "Gk9GtDSDkoSVyYTY/nd/kJQkcZBCLj6IifKL8+uu5aML7e8LWyQIxANzfEsSmLzjS3Kg886m"
        "61W02on+XLh4ZH5V1JLn+jYg3XZGcwyqL7MdovHdGQsKacw==\"},\"tlogEntries\":[{\"can"
        "onicalizedBody\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3J"
        "kIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWU"
        "iOiI2ZTk4YmU0YjhmMWViNmJjMDNiYTk3NDhjYzhlNjJhZmRkMzRiMWM5NzA5MThmNDBhYzA"
        "3MjQ3ZTdmODc5MGM3In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJUUMxdFFzeGV"
        "mdXRRR2ExZ3ZuTnc3enZNL3M0c3hVd2ZaZENkWkJCWWJHTTBBSWdQeThHL1FaNVNMNDZEbnF"
        "iR1loajB0S2VidEdMVEZad1FGeVRmZTF5N2RrPSIsInB1YmxpY0tleSI6eyJjb250ZW50Ijo"
        "iTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTlRWRU5EUVdNMlo"
        "wRjNTVUpCWjBsRFFTdHZkME5uV1VsTGIxcEplbW93UlVGM1RYZFRWRVZvVFVJNFIwRXhWVVZ"
        "EWjNkWllsZFdjR0pJYkhVS1pVTXhNbHBZU25CYWJtdG5ZekpXYzFwcE1UQmFXRTR3VFZOUmQ"
        "wbG5XVVJXVVZGRVJFSjBWVkpXVGxWTVZUbFBWRVpyWjFFd1JYUlJVMEp3WW01U2JBcGpiVEZ"
        "zV2tkc2FHUkhWWGRJYUdOT1RXcFpkMDlVU1hoTlZFMHhUWHBKZDFkb1kwNU5hbGwzVDFSSmV"
        "FMVVVWGROZWtsM1YycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJ"
        "FUVZGalJGRm5RVVV6YVdNNVN6aEJPRTVUTDJ4TGNubGFWMjk0TTBKUFRISm5kalZ6VjJKaFo"
        "zRkhiMmNLYjBwNVZuVlFXamhxYWs1RVlYTm1aa1F2WTJ0SFJYQlpTMGxXZDFOTFEweFNPRXB"
        "pVG1oSmVURXhlbEYyY1N0VVVEWlBRamRxUTBJMmVrRlBRbWRPVmdwSVVUaENRV1k0UlVKQlR"
        "VTkNORUYzUlhkWlJGWlNNR3hDUVhkM1EyZFpTVXQzV1VKQ1VWVklRWGROZDFKbldVUldVakJ"
        "TUVZGSUwwSkVkM2RQYjFrMENtRklVakJqU0UwMlRIazVlbHBYZUcxa1IxWjZaRU0xY0dKdVd"
        "taGlSMnhyVERJeGJHRlhlRFZpYm1kMFpHMVdlV0ZYV2pWTU0xSnNZek5SZEdJeU5YTUtaVk1"
        "4ZW1GWFpIVmFXRWwzVUVGWlMwdDNXVUpDUVVkRWRucEJRa0ZSVVhWaFNGSXdZMGhOTmt4NU9"
        "YcGFWM2h0WkVkV2VtUkROWEJpYmxwb1lrZHNhd3BNTTFKc1l6TlJkR0l5TlhObFV6RjJZVmR"
        "TYWt4WGJIcGpNMVpzWTJwQkswSm5iM0pDWjBWRlFWbFBMMDFCUlVsQ1JFRk5URzFvTUdSSVF"
        "ucFBhVGgyQ21NeVZuTmFibEpzWXpOUmRXRlhOVEpaVjNod1drTTVNRnBZVGpCTVZ6bDFZa2h"
        "yZEdJeWJHdFplVEZ3WXpOT01WcFlTWGREWjFsSlMyOWFTWHBxTUVVS1FYZE5SR0ZSUVhkYVo"
        "wbDRRVWxXU0RkRE1VRmlNVkJUVTA5RFIyczVSM1JFVTBScmIxTldlVmxVV1M5dVpDOXJTbEZ"
        "yWTFwQ1EweHFOa2xwWmt0TU9Bb3JkWFUxWVUxTU4yVTRURmQ1VVVsNFFVNTZaa1Z6VTIxTWV"
        "tcFRNMHRuT0RnMmJUWXhWekF5YjI0cldFeG9ORnBJTlZZeFNreHVLMnBaWnpOWVdrZGpDbmQ"
        "1Y1V3M1RXUnZka2hrUjFGelMyRmpkejA5Q2kwdExTMHRSVTVFSUVORlVsUkpSa2xEUVZSRkx"
        "TMHRMUzBLIn19fX0=\",\"inclusionPromise\":{\"signedEntryTimestamp\":\"MEYCIQC0J"
        "qv4DxJvAV9qlb/VjkCDa9d8F30Qe6kR/M0R8sEj8AIhAIzgaM9EDwzobFVCuslp3ndHEAVoV"
        "GoGIv92lukDEIOF\"},\"inclusionProof\":{\"checkpoint\":{\"envelope\":\"selftest.i"
        "nvalid - 1\\n14\\nMh6MI16i1mVZ2V13PKg0/Qvc1PUOPtsqgcIRyztB6y0=\\n\\n\\u2014 s"
        "elftest.invalid pIdAtjBFAiEAhfSk0IrGO/u8uZPBKHBfSwcpcheJrJb/MR44XpCqkY8C"
        "IDjpwnYu1X6AX4P378EZwgX2btNsLAVKG75k5E3nmGqT\\n\"},\"hashes\":[\"UY7XppO+FCT5"
        "rw/vzG/q7Gyhue0dgV/CsbqSkwWdR1U=\",\"Z3h2u2ZzCbD/kWQdwmhMtVbctx+GoaxrN2XUA"
        "ThVMmM=\",\"kDtFsD2vdXIoKxMLYl/1liFDgPr/lqqXn58MgDRiPsc=\",\"PBeZC6orPSRXZ67"
        "IEMXIhvTTyQrAQ9E43sfLiA0OtEM=\"],\"logIndex\":\"2\",\"rootHash\":\"Mh6MI16i1mVZ2"
        "V13PKg0/Qvc1PUOPtsqgcIRyztB6y0=\",\"treeSize\":\"14\"},\"integratedTime\":\"1790"
        "000000\",\"kindVersion\":{\"kind\":\"hashedrekord\",\"version\":\"0.0.1\"},\"logId\":"
        "{\"keyId\":\"pIdAtgmNH6Fr/ATdjpQQKG5cR/b+kGJsY28Z+DigQas=\"},\"logIndex\":\"2\"}"
        "]}}"
    ),
}
# END GENERATED SIGNATURE VECTORS


# ECDSA edge cases: the first vector for each Wycheproof flag, per curve, plus
# tcId 25 (bytes appended after the signature), from
# github.com/C2SP/wycheproof commit 3fa63dd0344abb611f1fb1d77e119938603ea230,
# testvectors_v1/ecdsa_secp256r1_sha256_test.json and
# ecdsa_secp384r1_sha384_test.json (Apache-2.0). (tcId, msg, DER sig, valid)
_SELFTEST_WYCHEPROOF = [
    ("P-256", "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
     "0087d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d", [
        (1, "", "3045022100b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a02200177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2", True),
    ]),
    ("P-256", "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
     "00c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e", [
        (6, "313233343030", "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e180220b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db", False),
        (8, "313233343030", "30814502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db", False),
        (10, "313233343030", "304602202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db", False),
        (23, "313233343030", "304702202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db0000", False),
        (25, "313233343030", "304502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db0000", False),
        (152, "313233343030", "30460221012ba3a8bd6b94d5ed80a6d9d1190a436ebccc0833490686deac8635bcb9bf5369022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db", False),
        (155, "313233343030", "30450220d45c5741946b2a137f59262ee6f5bc91001af27a5e1117a64733950642a3d1e8022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db", False),
        (158, "313233343030", "30460221012ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db", False),
        (168, "313233343030", "3006020100020100", False),
        (232, "313233343030", "3008020100090380fe01", False),
        (295, "3639383139", "3044022064a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e02206af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b", True),
        (296, "343236343739373234", "3044022016aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf2660220252cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9", True),
    ]),
    ("P-256", "0ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103",
     "00c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e", [
        (350, "313233343030", "303502104319055358e8617b0c46353d039cdaab022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e", True),
    ]),
    ("P-256", "00a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957",
     "5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b", [
        (355, "313233343030", "3006020105020101", True),
    ]),
    ("P-256", "61722eaba731c697c7a9ba4d0afdbb5713d8aa12b0eab601bb33dbaf792c5adc",
     "272cd993b2b663aba5b3a26c101182ff178684945e83879e71598b95fe647dfc", [
        (377, "313233343030", "30440220555555550000000055555555555555553ef7a8e48d07df81a693439654210c70022002f676969f451a8ccafa4c4f09791810e6d632dbd60b1d5540f3284fbe1889b0", True),
    ]),
    ("P-256", "00b533d4695dd5b8c5e07757e55e6e516f7e2c88fa0239e23f60e8ec07dd70f287",
     "1b134ee58cc583278456863f33c3a85d881f7d4a39850143e29d4eaf009afe47", [
        (392, "313233343030", "304402207fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a80220555555550000000055555555555555553ef7a8e48d07df81a693439654210c70", False),
    ]),
    ("P-256", "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
     "00ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685", [
        (448, "4d657373616765", "3046022100d434e262a49eab7781e353a3565e482550dd0fd5defa013c7f29745eff3569f10221009b0c0a93f267fb6052fd8077be769c2b98953195d7bc10de844218305c6ba17a", True),
    ]),
    ("P-384", "29bdb76d5fa741bfd70233cb3a66cc7d44beb3b0663d92a8136650478bcefb61ef182e155a54345a5e8e5e88f064e5bc",
     "009a525ab7f764dad3dae1468c2b419f3b62b9ba917d5e8c4fb1ec47404a3fc76474b2713081be9db4c00e043ada9fc4a3", [
        (1, "", "3064023032401249714e9091f05a5e109d5c1216fdc05e98614261aa0dbd9e9cd4415dee29238afbd3b103c1e40ee5c9144aee0f02304326756fb2c4fd726360dd6479b5849478c7a9d054a833a58c1631c33b63c3441336ddf2c7fe0ed129aae6d4ddfeb753", True),
    ]),
    ("P-384", "2da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa",
     "4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f", [
        (6, "313233343030", "3064023012b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d70230e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82", False),
        (8, "313233343030", "308165023012b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d7023100e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82", False),
        (10, "313233343030", "3066023012b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d7023100e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82", False),
        (23, "313233343030", "3067023012b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d7023100e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f820000", False),
        (25, "313233343030", "3065023012b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d7023100e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f820000", False),
        (152, "313233343030", "306602310112b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19a25617aad7485e6312a8589714f647acf7a94cffbe8a724a023100e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82", False),
        (155, "313233343030", "30650230ed4cf541094ab8901949ed51aa83fbda99e1d94bb4e401e6250d35d71ceecf7c4571b51b33ba5fcdf542cc6b0e3ab729023100e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82", False),
        (158, "313233343030", "306602310112b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d7023100e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82", False),
        (168, "313233343030", "3006020100020100", False),
        (232, "313233343030", "3008020100090380fe01", False),
        (295, "3133323237", "3066023100ac042e13ab83394692019170707bc21dd3d7b8d233d11b651757085bdd5767eabbb85322984f14437335de0cdf565684023100bd770d3ee4beadbabe7ca46e8c4702783435228d46e2dd360e322fe61c86926fa49c8116ec940f72ac8c30d9beb3e12f", True),
        (296, "31373530353531383135", "3066023100d3298a0193c4316b34e3833ff764a82cff4ef57b5dd79ed6237b51ff76ceab13bf92131f41030515b7e012d2ba857830023100bfc7518d2ad20ed5f58f3be79720f1866f7a23b3bd1bf913d3916819d008497a071046311d3c2fd05fc284c964a39617", True),
    ]),
    ("P-384", "4bf4e52f958427ebb5915fb8c9595551b4d3a3fdab67badd9d6c3093f425ba43630df71f42f0eb7ceaa94d9f6448a85d",
     "00d30331588249fd2fdc0b309ec7ed8481bc16f27800c13d7db700fc82e1b1c8545aa0c0d3b56e3bfe789fc18a916887c2", [
        (382, "313233343030", "304d0218389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68b023100ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52970", True),
    ]),
    ("P-384", "554f2fd0b700a9f4568752b673d9c0d29dc96c10fe67e38c6d6d339bfafe05f970da8c3d2164e82031307a44bd322511",
     "71312b61b59113ff0bd3b8a9a4934df262aa8096f840e9d8bffa5d7491ded87b38c496f9b9e4f0ba1089f8d3ffc88a9f", [
        (387, "313233343030", "3006020102020101", True),
    ]),
    ("P-384", "5abbf618a084f67138c418a896d61af3af1826040835b73e7619846b495eba6f7eeaa2e9cc61c85f6100fedc25c16743",
     "00b065a427bc503139529e4faa63dda553aed2696fd02c2b6ceb2d941d2c4363cf9ac7a6759d50e8b9d07fe286f17cef5c", [
        (407, "313233343030", "3064023055555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec63260230427f8227a67d9422557647d27945a90ae1d2ec2931f90113cd5b407099e3d8f5a889d62069e64c0e1c4efe29690b0992", True),
    ]),
    ("P-384", "00f896353cc3a8afdd543ec3aef062ca97bc32ed1724ea38b940b8c0ea0e23b34187afbe70daf8dbaa5b511557e5d2bdda",
     "00c4bd265da67ceeafca636f6f4c0472f22a9d02e2289184f73bbb700ae8fc921eff4920f290bfcb49fbb232cc13a21028", [
        (422, "313233343030", "306402307fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9023055555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326", False),
    ]),
    ("P-384", "00ffffffffaa63f1a239ac70197c6ebfcea5756dc012123f82c51fa874d66028be00e976a1080606737cc75c40bdfe4aac",
     "00acbd85389088a62a6398384c22b52d492f23f46e4a27a4724ad55551da5c483438095a247cb0c3378f1f52c3425ff9f1", [
        (474, "4d657373616765", "3065023007648b6660d01ba2520a09d298adf3b1a02c32744bd2877208f5a4162f6c984373139d800a4cdc1ffea15bce4871a0ed02310099fd367012cb9e02cde2749455e0d495c52818f3c14f6e6aad105b0925e2a7290ac4a06d9fadf4b15b578556fe332a5f", True),
    ]),
]


# A real Sigstore public-good bundle in the pinned format (v0.3, hashedrekord,
# Rekor v1), signed by the sigstore-conformance test beacon. Source:
# github.com/sigstore/sigstore-conformance, commit 767b4a7316a1186f0a5b4387d877f51d2a33c59f,
# test/assets/bundle-verify/happy-path-v0.3/bundle.sigstore.json (Apache-2.0). It
# signs test/assets/bundle-verify/a.txt; only that file's SHA-256 is kept here.
_SELFTEST_SIGSTORE_INTEROP = {
    "artifact_sha256": "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf",
    "identity": (
        "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/"
        ".github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
    ),
    "issuer": "https://token.actions.githubusercontent.com",
    "bundle": (
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle+json;version=0.3\",\"mes"
        "sageSignature\":{\"messageDigest\":{\"algorithm\":\"SHA2_256\",\"digest\":\"oM/HEn"
        "HW4njlfNMy/5V8P3BD/do1TEy7GQow1W76Ab8=\"},\"signature\":\"MEUCICYFq/4bTEdlur"
        "gqVuNmwCcIWu3NKOCgveWAJBiezJ0uAiEA2i7U18+aRpFxLYksr5HKBQQy08zE050WIc0RzK"
        "unDIA=\"},\"verificationMaterial\":{\"certificate\":{\"rawBytes\":\"MIIIMTCCB7eg"
        "AwIBAgIUaL/tsmQTHk21mt1Uuk+w7avDBz4wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2ln"
        "c3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjQwMzE5MTcy"
        "NjI2WhcNMjQwMzE5MTczNjI2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE22S1j/Nk"
        "EXzBPQAuamHXLpwx+RPnnzZQl/pkEZ8xorvKnzujCS1mVTBo9kBxmYWo2DHtyVyfgnuOqVTz"
        "LYmho6OCBtYwggbSMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNV"
        "HQ4EFgQUFv1SCziEKN2rRyrjeVlFbSLg1/QwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWi"
        "xi4YZD8wgaUGA1UdEQEB/wSBmjCBl4aBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1j"
        "b25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0"
        "aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZz"
        "L2hlYWRzL21haW4wOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1"
        "YnVzZXJjb250ZW50LmNvbTAfBgorBgEEAYO/MAECBBF3b3JrZmxvd19kaXNwYXRjaDA2Bgor"
        "BgEEAYO/MAEDBChjN2IzZGZiMzM1ZjA1MWUxYzg2YmRhNGM3MTZmYWM5N2RmNjJhZDgxMC0G"
        "CisGAQQBg78wAQQEH0V4dHJlbWVseSBkYW5nZXJvdXMgT0lEQyBiZWFjb24wSQYKKwYBBAGD"
        "vzABBQQ7c2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMt"
        "b2lkYy1iZWFjb24wHQYKKwYBBAGDvzABBgQPcmVmcy9oZWFkcy9tYWluMDsGCisGAQQBg78w"
        "AQgELQwraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTCBpgYK"
        "KwYBBAGDvzABCQSBlwyBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5j"
        "ZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtm"
        "bG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21h"
        "aW4wOAYKKwYBBAGDvzABCgQqDChjN2IzZGZiMzM1ZjA1MWUxYzg2YmRhNGM3MTZmYWM5N2Rm"
        "NjJhZDgxMB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDBeBgorBgEEAYO/MAEMBFAM"
        "Tmh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFu"
        "Z2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbjA4BgorBgEEAYO/MAENBCoMKGM3YjNkZmIzMzVm"
        "MDUxZTFjODZiZGE0YzcxNmZhYzk3ZGY2MmFkODEwHwYKKwYBBAGDvzABDgQRDA9yZWZzL2hl"
        "YWRzL21haW4wGQYKKwYBBAGDvzABDwQLDAk2MzI1OTY4OTcwNwYKKwYBBAGDvzABEAQpDCdo"
        "dHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UwGQYKKwYBBAGDvzABEQQL"
        "DAkxMzE4MDQ1NjMwgaYGCisGAQQBg78wARIEgZcMgZRodHRwczovL2dpdGh1Yi5jb20vc2ln"
        "c3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFj"
        "b24vLmdpdGh1Yi93b3JrZmxvd3MvZXh0cmVtZWx5LWRhbmdlcm91cy1vaWRjLWJlYWNvbi55"
        "bWxAcmVmcy9oZWFkcy9tYWluMDgGCisGAQQBg78wARMEKgwoYzdiM2RmYjMzNWYwNTFlMWM4"
        "NmJkYTRjNzE2ZmFjOTdkZjYyYWQ4MTAhBgorBgEEAYO/MAEUBBMMEXdvcmtmbG93X2Rpc3Bh"
        "dGNoMIGBBgorBgEEAYO/MAEVBHMMcWh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25m"
        "b3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi9hY3Rpb25z"
        "L3J1bnMvODM0NzQ4MTYyOC9hdHRlbXB0cy8xMBYGCisGAQQBg78wARYECAwGcHVibGljMIGK"
        "BgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4A"
        "AAGOV8AHpgAABAMARzBFAiBFeMbpFarlPwb0naTr4mjWDvXApOd9ORqOk36Brt9SmwIhAJJv"
        "jor+DXUXr7S3Vm9jVFT3CL0BxcKGj86m5mYzQvubMAoGCCqGSM49BAMDA2gAMGUCMA8lTixd"
        "S4iN9mAUduObcSJmhZLyvK7zaX05DLEDCgPWxDHk+JBZUKYRIuHHgwFnOwIxALMamo9dfENM"
        "zRgNCzYfp/y+rSOhVjXXE9mCn6BuJETlpRDfGvxUg/5LF9f4lYqozA==\"},\"tlogEntries\""
        ":[{\"canonicalizedBody\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVk"
        "cmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2Iiwi"
        "dmFsdWUiOiJhMGNmYzcxMjcxZDZlMjc4ZTU3Y2QzMzJmZjk1N2MzZjcwNDNmZGRhMzU0YzRj"
        "YmIxOTBhMzBkNTZlZmEwMWJmIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJQ1lG"
        "cS80YlRFZGx1cmdxVnVObXdDY0lXdTNOS09DZ3ZlV0FKQmllekowdUFpRUEyaTdVMTgrYVJw"
        "RnhMWWtzcjVIS0JRUXkwOHpFMDUwV0ljMFJ6S3VuRElBPSIsInB1YmxpY0tleSI6eyJjb250"
        "ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVbE5WRU5E"
        "UWpkbFowRjNTVUpCWjBsVllVd3ZkSE50VVZSSWF6SXhiWFF4VlhWckszYzNZWFpFUW5vMGQw"
        "Tm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoy"
        "WTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JB"
        "cGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcFJkMDE2UlRWTlZHTjVUbXBKTWxkb1kwNU5hbEYz"
        "VFhwRk5VMVVZM3BPYWtreVYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldr"
        "bDZhakJFUVZGalJGRm5RVVV5TWxNeGFpOU9hMFZZZWtKUVVVRjFZVzFJV0V4d2QzZ3JVbEJ1"
        "Ym5wYVVXd3ZjR3NLUlZvNGVHOXlka3R1ZW5WcVExTXhiVlpVUW04NWEwSjRiVmxYYnpKRVNI"
        "UjVWbmxtWjI1MVQzRldWSHBNV1cxb2J6WlBRMEowV1hkbloySlRUVUUwUndwQk1WVmtSSGRG"
        "UWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFX"
        "UkNaMDVXU0ZFMFJVWm5VVlZHZGpGVENrTjZhVVZMVGpKeVVubHlhbVZXYkVaaVUweG5NUzlS"
        "ZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5G"
        "a0tXa1E0ZDJkaFZVZEJNVlZrUlZGRlFpOTNVMEp0YWtOQ2JEUmhRbXhIYURCa1NFSjZUMms0"
        "ZGxveWJEQmhTRlpwVEcxT2RtSlRPWHBoVjJSNlpFYzVlUXBhVXpGcVlqSTFiV0l6U25SWlZ6"
        "VnFXbE01YkdWSVVubGFWekZzWWtocmRGcEhSblZhTWxaNVlqTldla3hZUWpGWmJYaHdXWGt4"
        "ZG1GWFVtcE1WMHBzQ2xsWFRuWmlhVGgxV2pKc01HRklWbWxNTTJSMlkyMTBiV0pIT1ROamVU"
        "bHNaVWhTZVZwWE1XeGlTR3QwV2tkR2RWb3lWbmxpTTFaNlRGYzVjRnBIVFhRS1dXMVdhRmt5"
        "T1hWTWJteDBZa1ZDZVZwWFducE1NbWhzV1ZkU2Vrd3lNV2hoVnpSM1QxRlpTMHQzV1VKQ1FV"
        "ZEVkbnBCUWtGUlVYSmhTRkl3WTBoTk5ncE1lVGt3WWpKMGJHSnBOV2haTTFKd1lqSTFla3h0"
        "WkhCa1IyZ3hXVzVXZWxwWVNtcGlNalV3V2xjMU1FeHRUblppVkVGbVFtZHZja0puUlVWQldV"
        "OHZDazFCUlVOQ1FrWXpZak5LY2xwdGVIWmtNVGxyWVZoT2QxbFlVbXBoUkVFeVFtZHZja0pu"
        "UlVWQldVOHZUVUZGUkVKRGFHcE9Na2w2V2tkYWFVMTZUVEVLV21wQk1VMVhWWGhaZW1jeVdX"
        "MVNhRTVIVFROTlZGcHRXVmROTlU0eVVtMU9ha3BvV2tSbmVFMURNRWREYVhOSFFWRlJRbWMz"
        "T0hkQlVWRkZTREJXTkFwa1NFcHNZbGRXYzJWVFFtdFpWelZ1V2xoS2RtUllUV2RVTUd4RlVY"
        "bENhVnBYUm1waU1qUjNVMUZaUzB0M1dVSkNRVWRFZG5wQlFrSlJVVGRqTW14dUNtTXpVblpq"
        "YlZWMFdUSTVkVnB0T1hsaVYwWjFXVEpWZGxwWWFEQmpiVlowV2xkNE5VeFhVbWhpYldSc1ky"
        "MDVNV041TVhka1YwcHpZVmROZEdJeWJHc0tXWGt4YVZwWFJtcGlNalIzU0ZGWlMwdDNXVUpD"
        "UVVkRWRucEJRa0puVVZCamJWWnRZM2s1YjFwWFJtdGplVGwwV1Zkc2RVMUVjMGREYVhOSFFW"
        "RlJRZ3BuTnpoM1FWRm5SVXhSZDNKaFNGSXdZMGhOTmt4NU9UQmlNblJzWW1rMWFGa3pVbkJp"
        "TWpWNlRHMWtjR1JIYURGWmJsWjZXbGhLYW1JeU5UQmFWelV3Q2t4dFRuWmlWRU5DY0dkWlMw"
        "dDNXVUpDUVVkRWRucEJRa05SVTBKc2QzbENiRWRvTUdSSVFucFBhVGgyV2pKc01HRklWbWxN"
        "YlU1MllsTTVlbUZYWkhvS1pFYzVlVnBUTVdwaU1qVnRZak5LZEZsWE5XcGFVemxzWlVoU2VW"
        "cFhNV3hpU0d0MFdrZEdkVm95Vm5saU0xWjZURmhDTVZsdGVIQlplVEYyWVZkU2FncE1WMHBz"
        "V1ZkT2RtSnBPSFZhTW13d1lVaFdhVXd6WkhaamJYUnRZa2M1TTJONU9XeGxTRko1V2xjeGJH"
        "SklhM1JhUjBaMVdqSldlV0l6Vm5wTVZ6bHdDbHBIVFhSWmJWWm9XVEk1ZFV4dWJIUmlSVUo1"
        "V2xkYWVrd3lhR3haVjFKNlRESXhhR0ZYTkhkUFFWbExTM2RaUWtKQlIwUjJla0ZDUTJkUmNV"
        "UkRhR29LVGpKSmVscEhXbWxOZWsweFdtcEJNVTFYVlhoWmVtY3lXVzFTYUU1SFRUTk5WRnB0"
        "V1ZkTk5VNHlVbTFPYWtwb1drUm5lRTFDTUVkRGFYTkhRVkZSUWdwbk56aDNRVkZ6UlVSM2Qw"
        "NWFNbXd3WVVoV2FVeFhhSFpqTTFKc1drUkNaVUpuYjNKQ1owVkZRVmxQTDAxQlJVMUNSa0ZO"
        "Vkcxb01HUklRbnBQYVRoMkNsb3liREJoU0ZacFRHMU9kbUpUT1hwaFYyUjZaRWM1ZVZwVE1X"
        "cGlNalZ0WWpOS2RGbFhOV3BhVXpsc1pVaFNlVnBYTVd4aVNHdDBXa2RHZFZveVZua0tZak5X"
        "ZWt4WVFqRlpiWGh3V1hreGRtRlhVbXBNVjBwc1dWZE9kbUpxUVRSQ1oyOXlRbWRGUlVGWlR5"
        "OU5RVVZPUWtOdlRVdEhUVE5aYWs1cldtMUplZ3BOZWxadFRVUlZlRnBVUm1wUFJGcHBXa2RG"
        "TUZsNlkzaE9iVnBvV1hwck0xcEhXVEpOYlVaclQwUkZkMGgzV1V0TGQxbENRa0ZIUkhaNlFV"
        "SkVaMUZTQ2tSQk9YbGFWMXA2VERKb2JGbFhVbnBNTWpGb1lWYzBkMGRSV1V0TGQxbENRa0ZI"
        "UkhaNlFVSkVkMUZNUkVGck1rMTZTVEZQVkZrMFQxUmpkMDUzV1VzS1MzZFpRa0pCUjBSMmVr"
        "RkNSVUZSY0VSRFpHOWtTRkozWTNwdmRrd3laSEJrUjJneFdXazFhbUl5TUhaak1teHVZek5T"
        "ZG1OdFZYUlpNamwxV20wNWVRcGlWMFoxV1RKVmQwZFJXVXRMZDFsQ1FrRkhSSFo2UVVKRlVW"
        "Rk1SRUZyZUUxNlJUUk5SRkV4VG1wTmQyZGhXVWREYVhOSFFWRlJRbWMzT0hkQlVrbEZDbWRh"
        "WTAxbldsSnZaRWhTZDJONmIzWk1NbVJ3WkVkb01WbHBOV3BpTWpCMll6SnNibU16VW5aamJW"
        "VjBXVEk1ZFZwdE9YbGlWMFoxV1RKVmRscFlhREFLWTIxV2RGcFhlRFZNVjFKb1ltMWtiR050"
        "T1RGamVURjNaRmRLYzJGWFRYUmlNbXhyV1hreGFWcFhSbXBpTWpSMlRHMWtjR1JIYURGWmFU"
        "a3pZak5LY2dwYWJYaDJaRE5OZGxwWWFEQmpiVlowV2xkNE5VeFhVbWhpYldSc1kyMDVNV041"
        "TVhaaFYxSnFURmRLYkZsWFRuWmlhVFUxWWxkNFFXTnRWbTFqZVRsdkNscFhSbXRqZVRsMFdW"
        "ZHNkVTFFWjBkRGFYTkhRVkZSUW1jM09IZEJVazFGUzJkM2IxbDZaR2xOTWxKdFdXcE5lazVY"
        "V1hkT1ZFWnNUVmROTkU1dFNtc0tXVlJTYWs1NlJUSmFiVVpxVDFSa2ExcHFXWGxaVjFFMFRW"
        "UkJhRUpuYjNKQ1owVkZRVmxQTDAxQlJWVkNRazFOUlZoa2RtTnRkRzFpUnpreldESlNjQXBq"
        "TTBKb1pFZE9iMDFKUjBKQ1oyOXlRbWRGUlVGWlR5OU5RVVZXUWtoTlRXTlhhREJrU0VKNlQy"
        "azRkbG95YkRCaFNGWnBURzFPZG1KVE9YcGhWMlI2Q21SSE9YbGFVekZxWWpJMWJXSXpTblJa"
        "VnpWcVdsTTViR1ZJVW5sYVZ6RnNZa2hyZEZwSFJuVmFNbFo1WWpOV2VreFlRakZaYlhod1dY"
        "a3hkbUZYVW1vS1RGZEtiRmxYVG5aaWFUbG9XVE5TY0dJeU5YcE1NMG94WW01TmRrOUVUVEJP"
        "ZWxFMFRWUlplVTlET1doa1NGSnNZbGhDTUdONU9IaE5RbGxIUTJselJ3cEJVVkZDWnpjNGQw"
        "RlNXVVZEUVhkSFkwaFdhV0pIYkdwTlNVZExRbWR2Y2tKblJVVkJaRm8xUVdkUlEwSklkMFZs"
        "WjBJMFFVaFpRVE5VTUhkaGMySklDa1ZVU21wSFVqUmpiVmRqTTBGeFNrdFljbXBsVUVzekwy"
        "ZzBjSGxuUXpod04yODBRVUZCUjA5V09FRkljR2RCUVVKQlRVRlNla0pHUVdsQ1JtVk5ZbkFL"
        "Um1GeWJGQjNZakJ1WVZSeU5HMXFWMFIyV0VGd1QyUTVUMUp4VDJzek5rSnlkRGxUYlhkSmFF"
        "RktTblpxYjNJclJGaFZXSEkzVXpOV2JUbHFWa1pVTXdwRFREQkNlR05MUjJvNE5tMDFiVmw2"
        "VVhaMVlrMUJiMGREUTNGSFUwMDBPVUpCVFVSQk1tZEJUVWRWUTAxQk9HeFVhWGhrVXpScFRq"
        "bHRRVlZrZFU5aUNtTlRTbTFvV2t4NWRrczNlbUZZTURWRVRFVkVRMmRRVjNoRVNHc3JTa0ph"
        "VlV0WlVrbDFTRWhuZDBadVQzZEplRUZNVFdGdGJ6bGtaa1ZPVFhwU1owNEtRM3BaWm5BdmVT"
        "dHlVMDlvVm1wWVdFVTViVU51TmtKMVNrVlViSEJTUkdaSGRuaFZaeTgxVEVZNVpqUnNXWEZ2"
        "ZWtFOVBRb3RMUzB0TFVWT1JDQkRSVkpVU1VaSlEwRlVSUzB0TFMwdENnPT0ifX19fQ==\",\"i"
        "nclusionPromise\":{\"signedEntryTimestamp\":\"MEYCIQDMNM49CNrcrpuvB9G3likdSs"
        "e0miAkY0ILCqzRGP5ZJQIhAKnSS9GUSFVCar1+Sq3qoRtJIJ8x9tqRnQ8kuS1ojtTH\"},\"in"
        "clusionProof\":{\"checkpoint\":{\"envelope\":\"rekor.sigstore.dev - 2605736670"
        "972794746\\n75408393\\nFnnj13Uu1jdksPc4HZLapKX329dVlD5+MGNsiqBq1XM=\\n\\n\\u2"
        "014 rekor.sigstore.dev wNI9ajBFAiBTyiBM9WtyOTgohje6QZ5rFGJUdMq7Wk3A6oThE"
        "98SUgIhAMvxDwa7FyqRqg+YV3rdPPrfS23w19iK+piMSGVOmP5w\\n\"},\"hashes\":[\"1J7hR"
        "IEGvYdAyzEs+GhAE9L+38oHye3BhalgoQRZoo4=\",\"W/OUCkh/lqDDwbBkZgP7eTV/wx4Wif"
        "D1wtfRLbavfxI=\",\"9wya2BEhfLGDfDRVN46OU2RXkozWCM1Z4qMu6SPiWoY=\",\"ZRs3lKAI"
        "lu0t0GtLupAcOu1y20nOaOshSKosWAqFO+w=\",\"BGqH+LzVuhuqCLiUvBJaB2hlsvtu2a15q"
        "q1WGw6mG44=\",\"OeS7D4kPES7ChE7kWSEmhbAMqBcKVj/z8/afMK4Y3pI=\",\"JtjqvAqFyXX"
        "YjWlZfDzElHpEzdBjsz1LmGFJuYx0kTU=\",\"s/ZIVcfcD4/nuZwUtQf4ydGsIAkGTPTzk3b0"
        "zhUC95k=\",\"YU1jZY/fp5tJdGF/i+/7ez8107O4/lOUp7acMPFEaOA=\",\"7Z18YLBAvejEV4"
        "nJHIKoks/xlijnhR005qTW2w4QtHg=\",\"98enzMaC+x5oCMvIZQA5z8vu2apDMCFvE/935Nf"
        "uPw8=\"],\"logIndex\":\"75408392\",\"rootHash\":\"Fnnj13Uu1jdksPc4HZLapKX329dVlD"
        "5+MGNsiqBq1XM=\",\"treeSize\":\"75408393\"},\"integratedTime\":\"1710869186\",\"ki"
        "ndVersion\":{\"kind\":\"hashedrekord\",\"version\":\"0.0.1\"},\"logId\":{\"keyId\":\"w"
        "NI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=\"},\"logIndex\":\"79571823\"}]}}"
    ),
}


def signature_self_test():
    """MEI-922: the signed-pack checks. ECDSA edge cases from Wycheproof; a
    synthetic signed pack (test-only CA, log and signer from
    fixtures/generate-signature-vectors.py) that must verify, with one
    tampered variant per failure reason, each rejected for exactly that
    reason; and a real Sigstore public-good bundle checked against the
    embedded production trust anchors."""
    ok = True

    def check(label, passed, what):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}: {what}")
        ok = ok and passed

    # 20a: ECDSA against Wycheproof (C2SP/wycheproof, Apache-2.0).
    curves = {"P-256": (P256, hashlib.sha256), "P-384": (P384, hashlib.sha384)}
    wrong = []
    total = 0
    for curve_name, wx, wy, tests in _SELFTEST_WYCHEPROOF:
        curve, hash_fn = curves[curve_name]
        point = (int(wx, 16), int(wy, 16))
        for tc_id, msg, sig, valid in tests:
            total += 1
            got = ecdsa_verify_der(curve, point, hash_fn(bytes.fromhex(msg)).digest(), bytes.fromhex(sig))
            if got != valid:
                wrong.append(f"{curve_name}#{tc_id}")
    check("20a", not wrong, f"ECDSA agrees with {total} Wycheproof vectors (P-256, P-384)"
          + (f"; disagrees on {', '.join(wrong)}" if wrong else ""))

    # 20b: a public key off the curve is rejected, both as a parsed key and at
    # verification, even alongside a signature that is valid for the real key.
    _, wx, wy, tests = _SELFTEST_WYCHEPROOF[0]
    _, msg, sig, _ = next(t for t in tests if t[3])
    x, y = int(wx, 16), int(wy, 16)
    digest = hashlib.sha256(bytes.fromhex(msg)).digest()
    genuine = ecdsa_verify_der(P256, (x, y), digest, bytes.fromhex(sig))
    off_curve = not ecdsa_verify_der(P256, (x, (y + 1) % P256.p), digest, bytes.fromhex(sig))
    spki_prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
    try:
        parse_ec_public_key(spki_prefix + b"\x04" + x.to_bytes(32, "big") + ((y + 1) % P256.p).to_bytes(32, "big"))
        parse_rejects = False
    except DerError:
        parse_rejects = True
    check("20b", genuine and off_curve and parse_rejects,
          "a public key that is not on the curve is rejected when parsed and when verifying")

    vectors = _SELFTEST_SIGNATURE_VECTORS
    manifest_bytes = base64.b64decode(vectors["manifest"])
    manifest = json.loads(manifest_bytes)
    trust = load_trusted_root(json.loads(vectors["trusted_root"]))
    foreign = load_trusted_root(json.loads(vectors["foreign_trusted_root"]))
    identity, issuer = vectors["identity"], vectors["issuer"]

    def outcome(bundle, *, manifest_obj=None, raw_manifest=None, trust_root=None,
                expect_identity=None, expect_issuer=None, sibling=True):
        """Run check_pack_signature on a variant; return "verified", a
        REASON_* value, or "unsupported"."""
        body = json.dumps(bundle).encode("utf-8")
        try:
            check_pack_signature(
                manifest if manifest_obj is None else manifest_obj,
                manifest_bytes if raw_manifest is None else raw_manifest,
                lambda name: body if sibling and name == "manifest.json.sigstore.json" else None,
                identity if expect_identity is None else expect_identity,
                issuer if expect_issuer is None else expect_issuer,
                trust if trust_root is None else trust_root,
            )
            return "verified"
        except SignatureInvalid as exc:
            return exc.reason
        except SignatureUnsupported:
            return "unsupported"

    def fresh(key="bundle_valid"):
        return json.loads(vectors[key])

    def flip_b64(value, index=10):
        raw = bytearray(base64.b64decode(value))
        raw[index] ^= 0x01
        return base64.b64encode(bytes(raw)).decode("ascii")

    def entry(bundle):
        return bundle["verificationMaterial"]["tlogEntries"][0]

    check("20c", outcome(fresh()) == "verified",
          "a correctly signed synthetic pack verifies")

    flipped = bytearray(manifest_bytes)
    flipped[manifest_bytes.index(b'"records_checked": 2') + len('"records_checked": ')] = ord("3")
    check("20d", outcome(fresh(), raw_manifest=bytes(flipped)) == REASON_MANIFEST_CHANGED,
          "one changed byte in manifest.json fails as 'manifest bytes changed since signing'")

    check("20e", outcome(fresh(), expect_identity=PINNED_SIGNER_IDENTITY) == REASON_IDENTITY_MISMATCH,
          "a valid signature by a different identity fails as 'signer identity mismatch'")

    check("20f", outcome(fresh(), expect_issuer=PINNED_OIDC_ISSUER) == REASON_ISSUER_MISMATCH,
          "a valid signature from a different OIDC issuer fails as 'OIDC issuer mismatch'")

    check("20g", outcome(fresh(), trust_root=foreign) == REASON_UNTRUSTED_CHAIN,
          "a certificate from a CA outside the trust root fails as 'untrusted certificate chain'")

    corrupt_set = fresh()
    promise = entry(corrupt_set)["inclusionPromise"]
    promise["signedEntryTimestamp"] = flip_b64(promise["signedEntryTimestamp"])
    corrupt_proof = fresh()
    proof = entry(corrupt_proof)["inclusionProof"]
    proof["hashes"][0] = flip_b64(proof["hashes"][0], 0)
    corrupt_checkpoint = fresh()
    envelope = entry(corrupt_checkpoint)["inclusionProof"]["checkpoint"]["envelope"]
    head, _, sig_line = envelope.rpartition(" ")
    entry(corrupt_checkpoint)["inclusionProof"]["checkpoint"]["envelope"] = (
        head + " " + flip_b64(sig_line.strip(), 12) + "\n")
    check("20h", all(outcome(b) == REASON_TLOG_INVALID for b in (corrupt_set, corrupt_proof, corrupt_checkpoint)),
          "a corrupted signed entry timestamp, inclusion proof or checkpoint fails as 'invalid transparency-log proof'")

    check("20i", outcome(fresh("bundle_entry_mismatch")) == REASON_TLOG_ENTRY_MISMATCH,
          "a valid log proof for a different entry fails as 'transparency-log entry does not match this signature'")

    check("20j", outcome(fresh(), sibling=False) == REASON_SIGNATURE_MISSING,
          "a signed-mode pack without its bundle fails as 'signature required by manifest but missing'")

    check("20k", outcome(fresh("bundle_outside_validity")) == REASON_OUTSIDE_VALIDITY,
          "an entry logged after the certificate expired fails as 'signed outside certificate validity'")

    downgraded = dict(manifest)
    del downgraded["signing_deferred"]
    downgraded["window"] = "A"
    downgraded["signature"] = None
    check("20l", pack_is_signed(downgraded) and outcome(fresh(), manifest_obj=downgraded) == REASON_SIGNATURE_MISSING,
          "deleting signing_deferred and the descriptor leaves the pack signed-mode, failing as 'signature required by manifest but missing'")

    unknown_method = dict(manifest, signature=dict(manifest["signature"], method="pgp"))
    unknown_media = fresh()
    unknown_media["mediaType"] = "application/vnd.dev.sigstore.bundle.v9.9+json"
    check("20m", outcome(fresh(), manifest_obj=unknown_method) == "unsupported"
          and outcome(unknown_media) == "unsupported",
          "an unknown signature method or bundle media type is 'cannot evaluate' (exit 2), never a pass")

    records = {r["sequence_number"]: json.dumps(r) for r in json.loads(vectors["records"])}
    clean = verify_manifest_with(lambda s: records[s], manifest, quiet=True, require_manifest_hash=True)
    unbound = dict(manifest, events=[dict(manifest["events"][0], recomputed_event_hash="")] + manifest["events"][1:])
    rejected = not verify_manifest_with(lambda s: records[s], unbound, quiet=True, require_manifest_hash=True)
    check("20n", clean and rejected,
          "a signed pack's chain verifies, and an entry without recomputed_event_hash fails it")

    interop = _SELFTEST_SIGSTORE_INTEROP
    production = load_trusted_root(SIGSTORE_PUBLIC_GOOD_TRUST_ROOT)
    real = json.loads(interop["bundle"])
    digest = bytes.fromhex(interop["artifact_sha256"])
    try:
        verify_sigstore_bundle(real, digest, interop["identity"], interop["issuer"], production)
        real_ok = True
    except (SignatureInvalid, SignatureUnsupported) as exc:
        real_ok = False
        print(f"  {exc}", file=sys.stderr)
    try:
        verify_sigstore_bundle(real, digest, PINNED_SIGNER_IDENTITY, PINNED_OIDC_ISSUER, production)
        pinned_rejects = False
    except SignatureInvalid as exc:
        pinned_rejects = exc.reason == REASON_IDENTITY_MISMATCH
    check("20o", real_ok and pinned_rejects,
          "a real Sigstore public-good bundle verifies against the embedded trust anchors, "
          "and fails the pinned Meilynx identity")

    # Trust anchors count only while they were valid: the log key and the CA
    # must both cover the time the entry was logged.
    logged_at = int(entry(fresh())["integratedTime"])
    late_log = {"tlogs": {k: dict(v, start=logged_at + 1) for k, v in trust["tlogs"].items()},
                "cas": trust["cas"]}
    retired_ca = {"tlogs": trust["tlogs"],
                  "cas": [dict(ca, end=logged_at - 1) for ca in trust["cas"]]}
    check("20p", outcome(fresh(), trust_root=late_log) == REASON_TLOG_INVALID
          and outcome(fresh(), trust_root=retired_ca) == REASON_UNTRUSTED_CHAIN,
          "a log key or CA that was not valid when the entry was logged is not trusted")

    table = [
        ((PASSED, PASSED, False), EXIT_OK),
        ((PASSED, FAILED, True), EXIT_FAIL),
        ((FAILED, PASSED, True), EXIT_FAIL),
        ((FAILED, CANNOT_EVALUATE, True), EXIT_FAIL),
        ((CANNOT_EVALUATE, FAILED, True), EXIT_FAIL),
        ((PASSED, CANNOT_EVALUATE, True), EXIT_CANNOT_EVALUATE),
        ((CANNOT_EVALUATE, UNSIGNED, True), EXIT_CANNOT_EVALUATE),
        ((PASSED, UNSIGNED, False), EXIT_UNSIGNED),
        ((PASSED, UNSIGNED, True), EXIT_OK),
        ((FAILED, UNSIGNED, True), EXIT_FAIL),
    ]
    check("20q", all(final_exit_code(*args) == want for args, want in table),
          "exit codes: failure 1 outranks cannot-evaluate 2 outranks unsigned 3; unsigned is 0 only with --allow-unsigned")

    # 20r: the downgrade, end to end at the command line in --records mode.
    # A signed pack stripped of its bundle and relabelled window A verifies
    # as a chain but exits 3; --allow-unsigned turns that into 0 with the
    # notice; the untouched signed pack exits 0 as signed.
    import subprocess
    import tempfile
    relabelled = dict(manifest, window="A", signing_deferred=True, signature=None)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "records").mkdir()
        for seq_no, raw in records.items():
            (tmp / "records" / record_file_name(seq_no)).write_text(raw)
        (tmp / "trusted_root.json").write_text(vectors["trusted_root"])
        (tmp / "signed").mkdir()
        (tmp / "signed" / "manifest.json").write_bytes(manifest_bytes)
        (tmp / "signed" / "manifest.json.sigstore.json").write_text(vectors["bundle_valid"])
        (tmp / "relabelled").mkdir()
        (tmp / "relabelled" / "manifest.json").write_text(json.dumps(relabelled, indent=2))

        def cli(pack, *extra):
            run = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--records", str(tmp / "records"),
                 "--manifest", str(tmp / pack / "manifest.json"), "--trusted-root", str(tmp / "trusted_root.json"),
                 "--certificate-identity", identity, "--certificate-oidc-issuer", issuer, *extra],
                capture_output=True, text=True,
            )
            return run.returncode, run.stdout + run.stderr

        stripped_code, _ = cli("relabelled")
        allowed_code, allowed_out = cli("relabelled", "--allow-unsigned")
        signed_code, signed_out = cli("signed")
    check("20r", pack_is_signed(relabelled) is False and stripped_code == EXIT_UNSIGNED
          and allowed_code == EXIT_OK and "AUTHENTICITY NOT ESTABLISHED" in allowed_out
          and signed_code == EXIT_OK and "SIGNATURE OK" in signed_out,
          "--records: a stripped, relabelled signed pack exits 3; with --allow-unsigned 0 and the notice; signed 0")

    return ok


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
            'the offline --records path on a synthetic chain, and the signature '
            'checks (ECDSA test vectors, a tamper matrix, a real Sigstore bundle).'
        ),
    )
    parser.add_argument(
        '--certificate-identity',
        default=PINNED_SIGNER_IDENTITY,
        metavar='IDENTITY',
        help=f'Signer identity a signed pack must carry. Default: {PINNED_SIGNER_IDENTITY}',
    )
    parser.add_argument(
        '--certificate-oidc-issuer',
        default=PINNED_OIDC_ISSUER,
        metavar='ISSUER',
        help=f'OIDC issuer a signed pack must carry. Default: {PINNED_OIDC_ISSUER}',
    )
    parser.add_argument(
        '--trusted-root',
        metavar='FILE',
        help=(
            'A Sigstore trusted_root.json to use instead of the public-good trust '
            'anchors embedded in this file, e.g. a copy you fetched and checked yourself.'
        ),
    )
    parser.add_argument(
        '--allow-unsigned',
        action='store_true',
        help=(
            f'Exit 0 for an unsigned (window A) pack whose chain verifies. Without it, '
            f'such a pack exits {EXIT_UNSIGNED}, in --bucket and --records mode alike. '
            f'Has no effect on a signed pack, which must carry a valid signature.'
        ),
    )
    args = parser.parse_args()

    if args.self_test:
        ok = run_self_test()
        ok = offline_self_test() and ok
        ok = content_self_test() and ok
        ok = signature_self_test() and ok
        sys.exit(0 if ok else 1)

    if not (args.bucket or args.records) or not args.manifest:
        parser.error("--manifest plus one of --bucket / --records is required (or use --self-test)")
    if args.export_records and not args.bucket:
        parser.error("--export-records only applies with --bucket")

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"ERROR: manifest not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)

    # The signature covers these exact bytes, so read them once and parse
    # the same buffer.
    manifest_bytes = manifest_path.read_bytes()
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        print(f"ERROR: manifest is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(EXIT_FAIL)

    signed = pack_is_signed(manifest)
    signature_status = (
        report_pack_signature(manifest, manifest_bytes, manifest_path, args) if signed else UNSIGNED
    )

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

    hash_version = manifest.get('hash_version', '')
    if hash_version not in SUPPORTED_HASH_VERSIONS:
        print(
            f"ERROR: This reproducer supports hash_version {SUPPORTED_HASH_VERSIONS}. "
            f"The manifest specifies '{hash_version}'. Re-run with the updated reproducer.",
            file=sys.stderr,
        )
        chain_status = CANNOT_EVALUATE
    else:
        passed = verify_manifest_with(fetch, manifest, require_manifest_hash=signed)
        chain_status = PASSED if passed else FAILED
    count = len(manifest.get('events', []))
    code = final_exit_code(chain_status, signature_status, bool(args.allow_unsigned))

    if code == EXIT_FAIL:
        if chain_status == FAILED:
            print("\nFAIL: one or more events failed verification.", file=sys.stderr)
        if signature_status == FAILED:
            print("\nFAIL: the manifest signature did not verify (see above).", file=sys.stderr)
    elif code == EXIT_CANNOT_EVALUATE:
        print("\nCANNOT EVALUATE: this verifier does not support part of this pack (see above).",
              file=sys.stderr)
    elif signature_status == PASSED:
        print(f"\nOK: all {count} events verified, and the manifest signature verified.")
    else:
        print(f"\n{UNSIGNED_NOTICE}")
        if code == EXIT_OK:
            print(f"OK: all {count} events verified. Authenticity not established (unsigned pack, "
                  f"accepted with --allow-unsigned).")
        else:
            print(
                f"CHAIN OK, AUTHENTICITY NOT ESTABLISHED: all {count} events verified, but the pack "
                f"is unsigned. Pass --allow-unsigned to accept an unsigned pack.",
                file=sys.stderr,
            )
    sys.exit(code)


if __name__ == '__main__':
    main()
