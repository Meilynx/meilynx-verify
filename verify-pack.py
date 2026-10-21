#!/usr/bin/env python3
"""
Meilynx Integrity Pack verifier.

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

Segment objects:
    A managed proxy's run chain may store records as segment objects,
    `<first:020d>-<last:020d>.seg`, each holding up to 1,024 consecutive
    records separated by line feeds. --bucket and a --records directory read
    both layouts, in any mix. --export-records writes one
    `<seq:020d>.bin` file per record, byte-identical to a per-record object,
    from either source. A sequence held by two objects with identical bytes
    prints `WARN ... segment_overlap` and still verifies; with different
    bytes it fails (`segment_fork`).

Control-plane chain (manifest 1.3):
    A pack may also carry the bucket's control-plane chain: the control
    plane's attributed record of human compliance actions (a held call
    released, denied or expired; a review disposition), one JSON object per
    record at control-plane/<seq:020d>.json. --bucket reads them from the
    bucket; --records reads them from <records>/control-plane/; and
    --export-records writes them there. Every record from sequence 0 to the
    last listed is recomputed (recipe control-plane-v1, see
    control_plane_event_hash_v1) and linked from genesis. A decision receipt
    whose cp_anchor_event_id names a control-plane event in the pack must
    carry that event's event_hash as cp_anchor_event_hash; one naming no
    event in the pack prints WARN receipt_anchor_outside_pack and verifies.

OCSF evidence export:
    A proxy configured with [audit.ocsf] writes its sealed records to a
    customer sink as OCSF events: gzip NDJSON objects named by chain
    coordinates, each with a `.manifest.json` (RFC 8785 bytes) and, when the
    proxy holds a signing key, a detached `.manifest.sig` (ECDSA P-256,
    r || s, standard base64, the identity-bundle format). The export is a
    copy; the chain is the record. Pass `--ocsf-export PATH` with the pack
    (PATH is a `.manifest.json`, a day's `index.json`, or a directory that
    is searched for manifests; objects and signatures are read beside each
    manifest) and the verifier checks the copy against the pack: each
    object's SHA-256 against its manifest; the manifest signature when
    `--ocsf-public-key JWK` names the proxy's export key (a manifest that
    says it is signed but has no `.sig` fails; one with no key given, or an
    unsigned one, lands at exit 3); every event's chain coordinates
    (event_id, event_hash) and every digest it carries against the pack
    record at that sequence (a mismatch fails, naming the object, the line
    and the field); an event on a chain or a sequence the pack does not
    hold prints WARN export_record_outside_pack and verifies; a gap between
    consecutive manifests of one chain prints WARN export_gap. The verifier
    cannot recompute an event hash from the export alone (content fields
    are excluded by design); it checks the export against the pack.
        python verify-pack.py --records ./records --manifest manifest.json \\
            --ocsf-export ./export/ocsf/v1/<proxy>/<chain>/2026/10/11/index.json \\
            --ocsf-public-key ocsf-export-key.jwk

Evidence class (manifest 1.4):
    A 1.4 manifest labels what kind of evidence the pack holds
    (`evidence_class`, inside the signed bytes). `sandbox-non-production`
    marks evidence sealed on a self-serve sandbox project. The verifier
    prints the label before the records and on every verdict line; an
    unknown label, or a 1.4 manifest without one, cannot be evaluated.

Content-stripped Exchange pack (manifest 1.5):
    A pack an Evidence Exchange subscriber receives carries no captured
    content and no personal data. Its 1.5 manifest says `content: stripped`
    and lists `removed_fields` (STRIPPED_FIELDS below), inside the signed
    bytes. None of those fields is in any record version's hash, so every
    record still recomputes to its stored hash, and a record that sealed its
    content (v1.10 onward) is checked against the digests it sealed, not
    against the removed content. The verifier prints the content line before
    the records and on every verdict line, and cannot evaluate (exit 2) a
    stripped pack that still carries a removed field or a personal identifier
    the profile withholds (WITHHELD_FIELDS). A record that cannot be stripped
    and still verify ships as a hash-only stub: its
    STUB_FIELDS and nothing of its body, listed with the reason in the
    manifest's `stubs`. The verifier checks that a stub's event_hash is the
    one the manifest signs and that the chain links through it, without
    recomputing its hash; it prints a STUB line for each, counts them on the
    verdict, and fails (exit 1) a stub whose hashes break the link or that
    carries more than its coordinates. A stripped pack is verified from its
    own records (--records); --bucket would read the holder's full records
    and is refused (exit 2).

Customer conditions verdict:
    A bank that proposed conditions a vendor accepted holds the SHA-256 of
    its condition set. `--conditions-sha256 HEX` adds one verdict line:
        conditions: set <HEX> accepted at seq N; M of T records in the
        window sealed under a governance version carrying it; E exceptions;
        compiled by the holder's control plane
    The acceptance (`exchange.conditions_accepted`, control-plane seq N) is
    read from the pack's control-plane chain. A pack that does not carry it
    (a per-tenant export, an Exchange pack) cannot evaluate the verdict
    (exit 2, "acceptance not in this pack") unless the stored record is
    given with `--conditions-acceptance FILE`: its hash is recomputed, and
    the verdict says its link into the holder's chain is not in the pack.
    The window is the model-request and MCP records sealed at or after the
    acceptance. A record counts toward M only by sealed evidence: an MCP
    record's hashed mcp_bundle_sha256 equal to the compiled MCP bundle, or a
    model request whose digest-bound evaluation trace ran one of the set's
    instances (<family>@cust_<12 hex>). Every other record is a GAP line
    with its coordinates; a model request whose unhashed policy_version
    names the compiled governance version is noted apart. EXCEPTION lines
    name each record whose findings or decisions name one of the set's
    instances, and whether a sealed digest binds them. The line's last
    clause is what the pack cannot show: the compile runs in the holder's
    control plane, and the pack carries bundle digests, not bundles.

Prerequisites (online mode only):
    pip install google-cloud-storage
    gcloud auth application-default login
    The principal needs storage.objects.list and storage.objects.get on the
    bucket (roles/storage.objectViewer has both).

Signed packs (window B):
    A signed pack carries `manifest.json.sigstore.json` next to
    manifest.json: a Sigstore bundle (media type v0.3) holding a cosign
    keyless signature over the exact bytes of manifest.json, the short-lived
    Fulcio signing certificate, and the Rekor v1 transparency-log entry with
    its signed entry timestamp, inclusion proof and signed checkpoint. The
    signature is checked before the records, offline, with no extra install.
    A manifest that says it is signed (window "B", or `signing_deferred` not
    true, or a `signature` descriptor) fails without a valid bundle.

    By default the signer must be the Meilynx signing workflow, dispatched
    from main:
        --certificate-identity     (default: PINNED_SIGNER_IDENTITY below)
        --certificate-oidc-issuer  (default: PINNED_OIDC_ISSUER below)
    A pack exported from a customer project is signed instead by that
    project's own signer, a Google service account that can read only that
    project's audit bucket (issuer GOOGLE_OIDC_ISSUER). Pass the exact email
    the evidence holder published for the project; the issuer follows:
        --certificate-identity ps-xxxxxxxxxx@<signer project>.iam.gserviceaccount.com
    Without it such a pack cannot be evaluated (exit 2), because nothing in
    the pack can say whose signer it is. There is no pattern match.
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
       unreadable record, content check, two objects holding different
       bytes for one sequence) or the signature, with the reason:
         signature required by manifest but missing
         manifest bytes changed since signing
         untrusted certificate chain
         signer identity mismatch
         OIDC issuer mismatch
         invalid transparency-log proof
         transparency-log entry does not match this signature
         signed outside certificate validity
         malformed signature material
       With --conditions-sha256, also: an acceptance record that does not
       verify, or one given with --conditions-acceptance that does not
       recompute or is not the acceptance of that set.
    2  cannot evaluate: an unsupported hash_version, manifest
       schema_version, storage_layout, evidence_class, signature method or
       bundle format (update this verifier), a pack signed by a per-tenant
       signer checked without --certificate-identity, an unusable
       --trusted-root, a content-stripped pack (manifest 1.5) whose content
       claim or removed-field list this verifier does not read, whose records
       still carry a removed field, or that is checked with --bucket, a
       --conditions-sha256 verdict whose acceptance is not in the pack and
       was not given with --conditions-acceptance, or a command-line usage
       error.
    3  unsigned pack: the chain verified, but no signature establishes who
       produced the manifest. Pass --allow-unsigned to accept it. A signed
       pack stripped of its signature and relabelled window A lands here,
       not at 0.

The GCS bucket uses CMEK encryption; decryption is handled transparently
by GCS when you authenticate with credentials that have storage.objects.get.

Self-test (encoding drift check):
  Run `python verify-pack.py --self-test` to check the encoding against the
  substrate's reference values. Exercises both the +00:00 fixture and the
  Z-suffix normalization path, the offline --records path, segment
  objects, and the signature checks (ECDSA test vectors, a synthetic signed pack with one
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
# Manifest schema versions this verifier understands. 1.1 adds the
# `anchoring` section (chain-head anchors). 1.2 adds
# `storage_layout` and a per-entry `object` reference, for a chain stored as
# segment objects. 1.3 adds the `control_plane`
# section, the bucket's control-plane chain; its `storage_layout`
# and per-entry `object` are as in 1.2 when present, and absent for a
# per-record chain. 1.4 adds the required `evidence_class` label:
# what kind of evidence the pack holds, inside the signed
# bytes; `storage_layout`, `object` and `control_plane` are as in 1.3, each
# present only when the pack has them. 1.5 is a content-stripped Exchange
# pack: `content: stripped`, `removed_fields`, and an optional
# `stubs` list; the 1.4 fields as in 1.4, `evidence_class` optional.
SUPPORTED_MANIFEST_SCHEMA_VERSIONS = ("1.0", "1.1", "1.2", "1.3", "1.4", "1.5")
# The manifest 1.4 evidence classes this verifier reads, with the sentence it
# prints beside every verdict. A class not listed here cannot be evaluated
# (exit 2): a label this verifier does not know is never ignored.
EVIDENCE_CLASSES = {
    "sandbox-non-production": (
        "evidence sealed on a sandbox project, a self-serve evaluation tenant; "
        "it is not production evidence"
    ),
}
# Pack features this verifier checks, read by the release-sync gate
# (check-meilynx-verify-sync.sh --covers) so a generator never ships a
# feature the public verifier would silently skip. `segmented-records-v1`
# reads segment objects; the gate requires it of the public release once a
# proxy build contains crates/meilynx-audit/src/segment_writer.rs.
# `decision-receipts-v1` reads v1.15 decision.receipt
# records, recomputes their evidence-set digest and clock arithmetic, checks
# each evidence entry against the pack record it cites, and checks the
# manifest's `decision_receipts` index against the receipts in the pack.
# `evaluation-trace-v1` reads v1.16 llm_request records
# and recomputes their evaluation outcome digest.
# `data-reach-evidence-v1` reads v1.17
# mcp.policy_decision records and checks the shape of their data_reach block.
# `control-plane-chain-v1` reads a manifest 1.3 `control_plane`
# section: re-reads every control-plane record, recomputes it under the
# control-plane-v1 recipe, walks the chain from genesis, and checks each
# decision receipt's cp_anchor_event_hash against the control-plane event its
# cp_anchor_event_id names when that event is in the pack.
# `ocsf-export-v1` reads an OCSF export beside the
# pack (`--ocsf-export`): object digests against their manifests, the
# detached manifest signatures, and every exported event's chain coordinates
# and digests against the pack record at that sequence.
# `customer-scope-v1` reads v1.18 records on
# both lanes and checks the shape of their customer block.
# `per-tenant-signer-v1` checks a pack
# signed by a per-tenant signer (GOOGLE_OIDC_ISSUER) against the exact
# identity the reader supplies, and refuses to evaluate one without it.
# `evidence-class-v1` reads manifest 1.4 and
# prints its evidence_class on every verdict.
# `content-stripped-v1` reads manifest 1.5: verifies a stripped
# Exchange pack from the sealed digests, refuses one that still carries a
# removed field, links the chain through hash-only stubs, and prints the
# content line and the stub count on every verdict.
# `customer-conditions-v1` gives the
# customer-conditions verdict for `--conditions-sha256`: the acceptance on
# the control-plane chain, the window's records sealed under the compiled
# set, its gaps and its exceptions.
VERIFIER_CAPABILITIES = frozenset(
    {"chain-anchors-v1", "segmented-records-v1", "decision-receipts-v1", "evaluation-trace-v1",
     "data-reach-evidence-v1", "control-plane-chain-v1", "ocsf-export-v1", "customer-scope-v1",
     "per-tenant-signer-v1", "evidence-class-v1", "content-stripped-v1", "customer-conditions-v1"}
)
# The stripped profile of a manifest 1.5 Exchange pack. Mirror of
# `exchange::STRIPPED_FIELDS` / `WITHHELD_FIELDS` / `STUB_FIELDS` /
# `STUB_REASONS` in the meilynx-integrity-pack crate (a drift catcher there
# pins the four sets and the schema's enums). STRIPPED_FIELDS are removed
# from every record; a dotted name is a member of a nested object.
# WITHHELD_FIELDS hold a personal identifier inside a record's hash, so a
# record with one set ships as a hash-only stub: STUB_FIELDS, nothing else.
CONTENT_STRIPPED = "stripped"
STRIPPED_FIELDS = (
    "customer_id",
    "end_user_id",
    "identity.asserted",
    "messages",
    "raw_request",
    "raw_response",
    "response_text",
    "tags_json",
    "tool_calls",
)
WITHHELD_FIELDS = ("auth_session.user_email",)
STUB_FIELDS = (
    "sequence_number",
    "event_hash",
    "previous_hash",
    "schema_version",
)
STUB_REASONS = {
    "sealed_personal_identifier": "seals a personal identifier inside its hash",
    "email_address": "keeps an email address in a field its hash or a sealed digest covers",
    "unreadable_record": "does not parse",
}
# OCSF mapping contract versions this verifier reads (contracts/ocsf-mapping.v1.json).
SUPPORTED_OCSF_MAPPING_VERSIONS = ("1",)

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
#   action                       UTF-8 bytes of the stored snake_case string ("allow", "warn",
#                                "redact", "mask_output", "hold", "block")
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
# v1.2 hash path (schema_version-versioned dispatch).
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
# admin.action wire-name (the hash-preimage form). The exported
# WORM JSON carries event_kind in its serde snake_case form ('admin_action',
# 'auth_session_started') or omits it for the default LlmRequest; the hash
# preimage feeds EventKind::wire_name() ('admin.action', 'auth.session_started').
# recompute_event_hash maps the JSON form to the wire name before dispatch.
EVENT_KIND_ADMIN_ACTION = 'admin.action'
# The five v1.4 MCP gateway kinds (hash-preimage wire names).
EVENT_KIND_MCP_TOOL_CALL = 'mcp.tool_call'
EVENT_KIND_MCP_POLICY_DECISION = 'mcp.policy_decision'
EVENT_KIND_MCP_TOOL_RESULT = 'mcp.tool_result'
EVENT_KIND_MCP_TOOLS_LIST_SERVED = 'mcp.tools_list.served'
EVENT_KIND_MCP_ERROR = 'mcp.error'
# The catalog-drift adjudication kind; shares the MCP payload +
# v1.4/v1.5 hash path (the wire-name in the preimage disambiguates it).
EVENT_KIND_MCP_CATALOG_DRIFT = 'mcp.catalog_drift'
# The coverage-reconciliation kind (v1.8 bucket).
EVENT_KIND_COVERAGE_COMPUTED = 'coverage.computed'
# The provider-key inventory kind
# (v1.13 bucket).
EVENT_KIND_COVERAGE_KEY_INVENTORY = 'coverage.key_inventory'
# The decision receipt kind (v1.15 bucket).
EVENT_KIND_DECISION_RECEIPT = 'decision.receipt'

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
    # Serde snake_case forms of the v1.4 kinds.
    'mcp_tool_call': EVENT_KIND_MCP_TOOL_CALL,
    'mcp_policy_decision': EVENT_KIND_MCP_POLICY_DECISION,
    'mcp_tool_result': EVENT_KIND_MCP_TOOL_RESULT,
    'mcp_tools_list_served': EVENT_KIND_MCP_TOOLS_LIST_SERVED,
    'mcp_error': EVENT_KIND_MCP_ERROR,
    'mcp_catalog_drift': EVENT_KIND_MCP_CATALOG_DRIFT,
    # Serde snake_case form of the v1.8 kind.
    'coverage_computed': EVENT_KIND_COVERAGE_COMPUTED,
    # Serde snake_case form of the v1.13 kind.
    'coverage_key_inventory': EVENT_KIND_COVERAGE_KEY_INVENTORY,
    # Serde snake_case form of the v1.15 kind.
    'decision_receipt': EVENT_KIND_DECISION_RECEIPT,
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
    """v1.3 admin.action hash. admin_action is a dict matching
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
    """v1.4 mcp.* hash, shared by all five MCP kinds. mcp_event is
    a dict matching `McpEventFields`. Mirror of `compute_event_hash_v1_4_mcp`
    in sqlite.rs: the SAME v1.2 prefix, then the specific kind's wire-name
    (the preimage's kind attestation — two identical payloads of different
    kinds hash differently), then the 13 payload fields in struct order.
    Optional strings use the 1-byte presence tag; error_code uses presence
    tag + little-endian i64."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"compute_event_hash_v1_4_mcp called with non-MCP kind {event_kind!r}"
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
    """1-byte shape tag then the shape's string fields. Mirror of
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
    raise ValueError(f"unknown principal kind {kind!r}")


def encode_principal_chain(chain):
    """The authenticated principal, then a 1-byte presence tag for
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
    """v1.5 mcp.* hash: the v1.4 preimage plus the trailing principal
    chain (design §5.6). Mirror of `compute_event_hash_v1_5_mcp` in sqlite.rs.
    The 13 McpEventFields feeds are DUPLICATED from
    `compute_event_hash_v1_4_mcp`, not shared — same structural seam as the Rust
    side: a v1.5-only encoding change must never be able to alter v1.4 output
    (which would invalidate every historical v1.4 record). Do not refactor the
    shared 13-field feed into a helper the v1.4 function also calls."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"compute_event_hash_v1_5_mcp called with non-MCP kind {event_kind!r}"
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
    # The v1.5 addition: the full principal chain.
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
    """v1.6 mcp.* hash: the v1.5 preimage plus one trailing feed, the
    redacted-payload content address (`redacted_payload_sha256_jcs`). Mirror of
    `compute_event_hash_v1_6_mcp` in sqlite.rs. `payload_sha256_jcs` still carries
    the ORIGINAL (pre-redaction) hash, so the preimage binds both digests (two-hash
    binding). The field feeds are DUPLICATED from
    `compute_event_hash_v1_5_mcp`, not shared — same structural seam as the Rust
    side: a v1.6-only encoding change must never be able to alter v1.5/v1.4 output."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"compute_event_hash_v1_6_mcp called with non-MCP kind {event_kind!r}"
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
    # The v1.5 principal chain (carried forward into v1.6).
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    # The v1.6 addition: the redacted-payload content address.
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
    """v1.7 mcp.* hash: the v1.6 preimage plus the two trailing
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
            f"compute_event_hash_v1_7_mcp called with non-MCP kind {event_kind!r}"
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
    # The v1.5 principal chain (carried forward into v1.7).
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    # The v1.6 capture-axis redacted-payload content address
    # (carried forward; None on enforcement records but fed for byte-position
    # stability with v1.6).
    h.update(encode_optional_str(mcp_event.get('redacted_payload_sha256_jcs')))
    # The v1.7 addition: the enforcement-axis fields, in order. The
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
    """v1.8 coverage.computed hash. `coverage` is a dict
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


def compute_event_hash_v1_13_coverage_key_inventory(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    inventory,
):
    """v1.13 coverage.key_inventory
    hash. `inventory` is a dict matching `CoverageKeyInventoryFields`. Mirror of
    `compute_event_hash_v1_13_coverage_key_inventory` in sqlite.rs: the SAME
    v1.2 prefix, then the event_kind wire-name, then the 11 payload fields in
    struct-definition order. Strings feed as raw utf-8 (`keys_json` verbatim,
    as stored, never re-serialized); the four counts feed as little-endian
    signed 64-bit with no presence tag."""
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(EVENT_KIND_COVERAGE_KEY_INVENTORY.encode('utf-8'))
    h.update(inventory['provider'].encode('utf-8'))
    h.update(inventory['day'].encode('utf-8'))
    h.update(inventory['attribution_unit'].encode('utf-8'))
    h.update(inventory['claim_language_key'].encode('utf-8'))
    h.update(inventory['registry_version'].encode('utf-8'))
    h.update(struct.pack('<q', int(inventory['proxy_key_count'])))
    h.update(struct.pack('<q', int(inventory['unresolved_proxy_key_count'])))
    h.update(struct.pack('<q', int(inventory['governed_key_count'])))
    h.update(struct.pack('<q', int(inventory['ungoverned_key_count'])))
    h.update(inventory['listing_fetched_at'].encode('utf-8'))
    h.update(inventory['keys_json'].encode('utf-8'))
    return h.hexdigest()


# The 36 receipt fields in preimage order, with how
# each feeds: required utf-8 string, optional string (presence tag), required
# i64 LE, optional i64 (presence tag + LE), optional bool (presence tag + byte).
DECISION_RECEIPT_FEED = (
    ('receipt_id', 'str'), ('receipt_type', 'str'), ('receipt_type_version', 'str'),
    ('registry_digest', 'str'), ('source_kind', 'str'), ('source_ref', 'str'),
    ('subject_ref_sha256', 'opt_str'), ('evidence_set_sha256', 'str'),
    ('policy_version', 'opt_str'), ('outcome', 'str'),
    ('outcome_reason_code', 'opt_str'), ('outcome_reason_sha256', 'opt_str'),
    ('decider_user_id', 'opt_str'), ('decider_role', 'opt_str'),
    ('decider_identity_provenance', 'opt_str'), ('credential_status', 'str'),
    ('credential_class', 'opt_str'), ('credential_registry', 'opt_str'),
    ('credential_verified_at', 'opt_i64'), ('procedure_status', 'str'),
    ('procedure_id', 'opt_str'), ('procedure_version', 'opt_str'),
    ('procedure_document_sha256', 'opt_str'), ('procedure_effective_at', 'opt_i64'),
    ('clock_rule', 'str'), ('clock_start_basis', 'str'),
    ('clock_started_at', 'i64'), ('clock_deadline_at', 'i64'),
    ('clock_decided_at', 'opt_i64'), ('clock_elapsed_seconds', 'opt_i64'),
    ('clock_status', 'str'), ('held_before_use', 'opt_bool'),
    ('supersedes_receipt_id', 'opt_str'), ('cp_anchor_event_id', 'str'),
    ('cp_anchor_event_hash', 'str'), ('issued_at', 'i64'),
)


def compute_event_hash_v1_15_decision_receipt(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    receipt,
):
    """v1.15 decision.receipt hash. `receipt` is a
    dict matching `DecisionReceiptFields`. Mirror of
    `compute_event_hash_v1_15_decision_receipt` in sqlite.rs and
    `DecisionReceiptChainHasher.ComputeV115` on the control plane: the SAME
    v1.2 prefix, then the event_kind wire-name, then the 36 receipt fields in
    `DECISION_RECEIPT_FEED` order. The stored `evidence` list is outside the
    preimage; `evidence_set_sha256` binds it (see `check_decision_receipt`)."""
    h = _v1_2_prefix_hash(
        sequence_number, timestamp_utc, event_id, request_id,
        model_requested, action, input_tokens, output_tokens,
        total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    )
    h.update(EVENT_KIND_DECISION_RECEIPT.encode('utf-8'))
    for name, kind in DECISION_RECEIPT_FEED:
        value = receipt.get(name)
        if kind == 'str':
            h.update(str(value if value is not None else '').encode('utf-8'))
        elif kind == 'opt_str':
            h.update(encode_optional_str(value))
        elif kind == 'i64':
            h.update(struct.pack('<q', int(value)))
        elif kind == 'opt_i64':
            if value is None:
                h.update(b'\x00')
            else:
                h.update(b'\x01' + struct.pack('<q', int(value)))
        elif kind == 'opt_bool':
            if value is None:
                h.update(b'\x00')
            else:
                h.update(b'\x01' + (b'\x01' if bool(value) else b'\x00'))
    return h.hexdigest()


RECEIPT_OUTCOME_TO_ACTION = {'approved': 'allow', 'escalated': 'hold', 'rejected': 'block', 'lapsed': 'block'}


def check_decision_receipt(event):
    """For a v1.15 record, check what the hash alone
    cannot: the stored `evidence` list hashes to `evidence_set_sha256`; the
    sealed clock arithmetic (`clock_elapsed_seconds`, `clock_status`) follows
    from the three timestamps; a `verified` credential carries its class,
    registry and verification time; a `recorded` procedure carries its id and
    version; a decider is present exactly when someone decided; a lapse was
    issued no earlier than its deadline; and the base `action` is the
    outcome's projection. Returns a list of problems; empty means the receipt
    checks out. Records on any other schema version carry no receipt and
    return no problems."""
    if (event.get('schema_version') or 'v1') != 'v1.15':
        return []
    receipt = event.get('decision_receipt')
    if not isinstance(receipt, dict):
        return ['v1.15 record carries no decision_receipt payload']
    problems = []
    rid = receipt.get('receipt_id', '?')

    evidence = receipt.get('evidence')
    if evidence is None:
        evidence = []
    recomputed = sha256_jcs(evidence)
    if recomputed != receipt.get('evidence_set_sha256'):
        problems.append(
            f"decision receipt {rid}: stored evidence list hashes to {recomputed}, "
            f"not the sealed evidence_set_sha256 {receipt.get('evidence_set_sha256')}"
        )

    outcome = receipt.get('outcome')
    decided = receipt.get('clock_decided_at')
    started = receipt.get('clock_started_at')
    deadline = receipt.get('clock_deadline_at')
    status = receipt.get('clock_status')
    if outcome == 'lapsed':
        if receipt.get('decider_user_id') is not None:
            problems.append(f"decision receipt {rid}: a lapsed receipt names a decider")
        if decided is not None or receipt.get('clock_elapsed_seconds') is not None:
            problems.append(f"decision receipt {rid}: a lapsed receipt carries a decision time")
        if status != 'lapsed':
            problems.append(f"decision receipt {rid}: outcome lapsed but clock_status {status!r}")
    else:
        if receipt.get('decider_user_id') is None:
            problems.append(f"decision receipt {rid}: a decided receipt names no decider")
        if decided is None or started is None or deadline is None:
            problems.append(f"decision receipt {rid}: a decided receipt is missing a clock timestamp")
        else:
            elapsed = int(decided) - int(started)
            if receipt.get('clock_elapsed_seconds') != elapsed:
                problems.append(
                    f"decision receipt {rid}: sealed clock_elapsed_seconds "
                    f"{receipt.get('clock_elapsed_seconds')} but the timestamps give {elapsed}"
                )
            expected = 'within' if int(decided) <= int(deadline) else 'breached'
            if status != expected:
                problems.append(
                    f"decision receipt {rid}: sealed clock_status {status!r} but the timestamps give {expected!r}"
                )

    # A lapse is "no decision was made and the deadline has
    # passed", so a receipt that says it lapsed must have been issued no
    # earlier than its deadline.
    if outcome == 'lapsed' or status == 'lapsed':
        issued = receipt.get('issued_at')
        if issued is None or deadline is None:
            problems.append(f"decision receipt {rid}: a lapsed receipt is missing issued_at or clock_deadline_at")
        elif int(issued) < int(deadline):
            problems.append(
                f"decision receipt {rid}: lapsed before its deadline "
                f"(issued_at {int(issued)} < clock_deadline_at {int(deadline)})"
            )

    if receipt.get('credential_status') == 'verified' and (
        receipt.get('credential_class') is None or receipt.get('credential_registry') is None
        or receipt.get('credential_verified_at') is None
    ):
        problems.append(f"decision receipt {rid}: credential_status verified without class, registry and verification time")
    if receipt.get('procedure_status') == 'recorded' and (
        receipt.get('procedure_id') is None or receipt.get('procedure_version') is None
    ):
        problems.append(f"decision receipt {rid}: procedure_status recorded without id and version")

    expected_action = RECEIPT_OUTCOME_TO_ACTION.get(outcome)
    if expected_action is None:
        problems.append(f"decision receipt {rid}: unknown outcome {outcome!r}")
    elif action_str(event) != expected_action:
        problems.append(
            f"decision receipt {rid}: base action {action_str(event)!r} is not the projection of outcome {outcome!r} ({expected_action!r})"
        )
    return problems


# The internal chain ids a proxy uses inside one boot.
# An evidence entry carrying one of them names no chain an examiner can find.
INTERNAL_CHAIN_IDS = frozenset({'proxy', 'shadow'})


def evidence_chain_relation(chain_id, pack_chain):
    """How a receipt evidence entry's
    `chain_id` relates to the chain this pack covers, which the verifier knows
    only from the manifest prefix (`chain_for_prefix`): records carry no chain
    id of their own.

    'same': the entry names this pack's chain. A run-scoped pack
    (`audit/chain_tnt_{proxy}_proxy_run_{run}/`) is named by that externalized
    id, the one the proxy stamps on the evidence it pushes. The flat `audit/`
    chain (legacy-flat) belongs to a proxy without run-scoped chains, which
    pushes its evidence under the tenant-scoped id `chain_tnt_{proxy}_proxy`.

    'unnamed': the entry names no chain (a review disposition cites its LLM
    record by sequence and hash only), or an internal id that means nothing
    outside one proxy boot. Such an entry is in the pack only when the pack
    holds a record at its sequence with its event_hash: a SHA-256 chain hash
    identifies the record it was computed over.

    'other': any other chain."""
    if not isinstance(chain_id, str) or not chain_id or chain_id in INTERNAL_CHAIN_IDS:
        return 'unnamed'
    if pack_chain is not None and chain_id == pack_chain:
        return 'same'
    if (pack_chain == LEGACY_FLAT_CHAIN
            and re.fullmatch(r'chain_tnt_[A-Za-z0-9_.\-]+_proxy', chain_id)
            and '_proxy_run_' not in chain_id):
        return 'same'
    return 'other'


def receipt_evidence_findings(receipt_seq, receipt, pack_chain, pack_records, window_seqs):
    """Cross-check a decision receipt's stored
    `evidence` list against the records in this pack.

    For each entry whose record is in the pack, the pack record's `event_id`
    and `event_hash` must equal the entry's (an entry that carries no
    `event_id` is checked on its hash alone). A disagreement means the receipt
    cites a record other than the one the chain holds: a failure naming the
    receipt record and the field. An entry whose record is not in the pack is
    a `WARN receipt_evidence_outside_pack` with its coordinates, and verifies:
    an examiner can fetch the cited chain.

    `pack_records` maps each sequence read in this pack to its record's
    (event_id, event_hash); `window_seqs` is every sequence the manifest lists,
    read or not. Returns (failures, warnings), lists of strings."""
    failures, warnings = [], []
    rid = receipt.get('receipt_id', '?')
    evidence = receipt.get('evidence')
    if evidence is None:
        evidence = []
    if not isinstance(evidence, list):
        return [f"decision receipt {rid}: stored evidence is not a list"], []
    for i, entry in enumerate(evidence):
        if not isinstance(entry, dict):
            failures.append(f"decision receipt {rid}: evidence[{i}] is not an object")
            continue
        chain = entry.get('chain_id')
        seq = entry.get('sequence_number')
        event_id = entry.get('event_id')
        event_hash = entry.get('event_hash')
        relation = evidence_chain_relation(chain, pack_chain)
        held = pack_records.get(seq) if type(seq) is int else None
        if relation == 'same' and held is None and seq in window_seqs:
            # The cited record is in this pack's window but could not be read;
            # the walk has already failed it.
            warnings.append(
                f"WARN seq={receipt_seq}: decision receipt {rid} evidence[{i}] (sequence={seq}) "
                f"was not checked, because that record failed above."
            )
            continue
        in_pack = held is not None and (relation == 'same' or (relation == 'unnamed' and held[1] == event_hash))
        if not in_pack:
            warnings.append(
                f"WARN receipt_evidence_outside_pack seq={receipt_seq} receipt={rid} evidence[{i}] "
                f"chain={chain or '(not recorded)'} sequence={seq} event_id={event_id or '(not recorded)'}: "
                f"the cited record is not in this pack; verify that chain to check it."
            )
            continue
        held_id, held_hash = held
        # A hash-only stub: its hash is checked, its event_id is
        # not in the pack.
        if held_id is STUB_EVENT_ID:
            if event_hash != held_hash:
                failures.append(
                    f"decision receipt {rid}: evidence[{i}] (sequence={seq}) event_hash {str(event_hash)[:16]}... "
                    f"is not the event_hash {str(held_hash)[:16]}... of that record's hash-only stub"
                )
            else:
                warnings.append(
                    f"NOTE seq={receipt_seq}: decision receipt {rid} evidence[{i}] (sequence={seq}) cites a hash-only "
                    f"stub: its event_hash matches; its event_id is not in this pack."
                )
            continue
        if event_id is not None and event_id != held_id:
            failures.append(
                f"decision receipt {rid}: evidence[{i}] (sequence={seq}) event_id {event_id!r} "
                f"is not the pack record's event_id {held_id!r}"
            )
        if event_hash != held_hash:
            failures.append(
                f"decision receipt {rid}: evidence[{i}] (sequence={seq}) event_hash {str(event_hash)[:16]}... "
                f"is not the pack record's event_hash {str(held_hash)[:16]}..."
            )
    return failures, warnings


# The fields of one manifest `decision_receipts` index
# entry, each equal to the sealed record's (`sequence` locates it).
RECEIPT_INDEX_FIELDS = ('sequence', 'receipt_id', 'receipt_type', 'clock_status')


def receipt_index_findings(manifest, receipts, window_seqs, read_seqs):
    """Check the manifest's `decision_receipts` index
    against the decision receipts actually in the pack: every receipt listed,
    nothing extra, and each entry's fields equal to the sealed record's.

    A manifest without the key comes from a generator that predates the index
    and is accepted with a note; a receipt-free pack carries no key, so its
    manifest is byte-identical to one from an older generator. `receipts` maps
    each receipt record's sequence to its sealed `decision_receipt` payload.
    Returns (failures, lines), the lines to print when nothing failed."""
    if 'decision_receipts' not in manifest:
        if not receipts:
            return [], []
        return [], [
            f"NOTE: the manifest has no decision_receipts index (its generator predates it); "
            f"{len(receipts)} decision receipt(s) in this pack were checked as records."
        ]
    index = manifest['decision_receipts']
    if not isinstance(index, list):
        return ["manifest decision_receipts is not a list"], []
    failures = []
    listed = {}
    for i, entry in enumerate(index):
        if not isinstance(entry, dict) or set(entry) != set(RECEIPT_INDEX_FIELDS):
            failures.append(
                f"manifest decision_receipts[{i}] must carry exactly {', '.join(RECEIPT_INDEX_FIELDS)}"
            )
            continue
        seq = entry['sequence']
        if type(seq) is not int:
            failures.append(f"manifest decision_receipts[{i}] sequence {seq!r} is not an integer")
            continue
        if seq in listed:
            failures.append(f"manifest decision_receipts lists seq={seq} twice")
            continue
        listed[seq] = entry
    for seq, entry in sorted(listed.items()):
        receipt = receipts.get(seq)
        if receipt is None:
            if seq in window_seqs and seq not in read_seqs:
                continue  # the record could not be read; the walk has failed it
            failures.append(
                f"manifest decision_receipts lists seq={seq}, which is not a decision receipt record in this pack"
            )
            continue
        for field in RECEIPT_INDEX_FIELDS[1:]:
            if entry[field] != receipt.get(field):
                failures.append(
                    f"manifest decision_receipts entry seq={seq} has {field} {entry[field]!r}, "
                    f"but the sealed record says {receipt.get(field)!r}"
                )
    for seq, receipt in sorted(receipts.items()):
        if seq not in listed:
            failures.append(
                f"decision receipt at seq={seq} ({receipt.get('receipt_id', '?')}) is not listed in the "
                f"manifest's decision_receipts index"
            )
    if failures:
        return failures, []
    lines = [f"RECEIPT seq={seq} type={e['receipt_type']} clock_status={e['clock_status']} receipt_id={e['receipt_id']}"
             for seq, e in sorted(listed.items())]
    lines.append(f"RECEIPTS INDEX OK: {len(listed)} decision receipt(s) listed, each matching its sealed record")
    return [], lines


# ---------------------------------------------------------------------------
# The control-plane chain (manifest 1.3 `control_plane` section).
#
# The control plane records the human half of governance decisions (a held
# tool call released, denied or expired; a supervisory review disposition; an
# examination package generated) on its own chain, one JSON object per record
# at control-plane/<seq:020d>.json in the same bucket. Recipe control-plane-v1
# (records with schema_version "v1"), written by the control plane's
# ControlPlaneAuditChain and mirrored by the generator's control_plane.rs:
#
#   event_hash = hex(SHA-256( i64 LE sequence_number
#                           || UTF-8 bytes of previous_hash (the hex text)
#                           || canonical(H) ))
#   H = {actor_user_id, correlation_id, event_id, event_kind, occurred_at,
#        payload, project_id, schema_version, target_resource_id},
#       each read from the stored record, JSON null when absent.
#
# canonical(): object members ordered by key compared as UTF-16 code units, no
# whitespace, strings escaping only '"', '\' and U+0000..U+001F ('\b' '\f'
# '\n' '\r' '\t', else '\u00xx' lowercase) with every other character as
# UTF-8, null/true/false literally, arrays in order. Numbers are copied
# VERBATIM from the record: the record is written by the same canonicalizer
# as the hash input, so its number tokens are the hashed bytes ('1E-05',
# '0.00001', '42'); re-formatting a parsed float would not reproduce them.
# The genesis is the proxy chain's (meilynx-genesis-v1).
# ---------------------------------------------------------------------------

CONTROL_PLANE_PREFIX = 'control-plane/'
CONTROL_PLANE_CHAIN_FAMILY = 'control-plane'
CONTROL_PLANE_SCHEMA_V1 = 'v1'
CONTROL_PLANE_HASHED_FIELDS = (
    'actor_user_id', 'correlation_id', 'event_id', 'event_kind', 'occurred_at',
    'payload', 'project_id', 'schema_version', 'target_resource_id',
)


class ControlPlaneNumber(str):
    """A JSON number token kept exactly as it appears in a control-plane record."""


def _cp_reject_constant(name):
    raise ValueError(f"{name} is not a JSON number")


def _cp_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key {key!r}")
        obj[key] = value
    return obj


def load_control_plane_record(raw):
    """Parse a stored control-plane record (bytes), keeping number tokens
    verbatim. Refuses duplicate keys, NaN/Infinity and a non-object."""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode('utf-8')
    record = json.loads(raw, parse_float=ControlPlaneNumber, parse_int=ControlPlaneNumber,
                        parse_constant=_cp_reject_constant, object_pairs_hook=_cp_object)
    if not isinstance(record, dict):
        raise ValueError("a control-plane record is a JSON object")
    return record


def _cp_emit_str(s):
    out = ['"']
    for c in s:
        if c == '\\':
            out.append('\\\\')
        elif c == '"':
            out.append('\\"')
        elif c == '\b':
            out.append('\\b')
        elif c == '\f':
            out.append('\\f')
        elif c == '\n':
            out.append('\\n')
        elif c == '\r':
            out.append('\\r')
        elif c == '\t':
            out.append('\\t')
        elif ord(c) < 0x20:
            out.append(f'\\u{ord(c):04x}')
        else:
            out.append(c)
    out.append('"')
    return ''.join(out)


def control_plane_canonical(value):
    """The control plane's canonical JSON text for a value parsed by
    load_control_plane_record (see the section comment)."""
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, ControlPlaneNumber):
        return str.__str__(value)
    if isinstance(value, str):
        return _cp_emit_str(value)
    if isinstance(value, list):
        return '[' + ','.join(control_plane_canonical(v) for v in value) + ']'
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: kv[0].encode('utf-16-be', 'surrogatepass'))
        return '{' + ','.join(f"{_cp_emit_str(k)}:{control_plane_canonical(v)}" for k, v in members) + '}'
    raise ValueError(f"a control-plane record cannot hold a {type(value).__name__}")


def control_plane_sequence(record):
    """The record's sequence_number as an int, or None when it is not a plain
    integer token."""
    seq = record.get('sequence_number')
    if isinstance(seq, ControlPlaneNumber) and re.fullmatch(r'-?[0-9]+', seq):
        return int(seq)
    return None


def control_plane_event_hash_v1(record):
    """Recompute a control-plane record's event_hash (recipe control-plane-v1).
    Raises ValueError naming why it cannot: an unpublished schema_version, a
    missing chain field, or text that does not encode."""
    version = record.get('schema_version')
    if version != CONTROL_PLANE_SCHEMA_V1:
        raise ValueError(f"schema_version {version!r} is not a published control-plane preimage "
                         f"(only {CONTROL_PLANE_SCHEMA_V1!r})")
    seq = control_plane_sequence(record)
    if seq is None:
        raise ValueError("sequence_number is not an integer")
    if not -2**63 <= seq < 2**63:
        raise ValueError(f"sequence_number {seq} is outside the signed 64-bit range the preimage encodes")
    prev = record.get('previous_hash')
    if not isinstance(prev, str) or isinstance(prev, ControlPlaneNumber):
        raise ValueError("previous_hash is not a string")
    preimage = control_plane_canonical({k: record.get(k) for k in CONTROL_PLANE_HASHED_FIELDS})
    try:
        preimage_bytes = preimage.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ValueError(f"the record holds text that is not valid Unicode: {exc}") from exc
    h = hashlib.sha256()
    h.update(struct.pack('<q', seq))
    h.update(prev.encode('utf-8'))
    h.update(preimage_bytes)
    return h.hexdigest()


def control_plane_record_name(seq):
    return f"{seq:020d}.json"


def control_plane_gcs_fetcher(bucket_name, storage_client):
    """fetch(seq) -> bytes of control-plane/<seq:020d>.json in the bucket."""
    bucket = storage_client.bucket(bucket_name)

    def fetch(seq):
        return bucket.blob(f"{CONTROL_PLANE_PREFIX}{control_plane_record_name(seq)}").download_as_bytes()

    return fetch


def control_plane_local_fetcher(records_path):
    """fetch(seq) -> bytes of <records>/control-plane/<seq:020d>.json. A
    records path that is not a directory holds no control-plane records."""
    base = Path(records_path) / 'control-plane'

    def fetch(seq):
        if not Path(records_path).is_dir():
            raise FileNotFoundError(
                f"--records {records_path} is a file; control-plane records are read from a records "
                f"directory, under control-plane/")
        return (base / control_plane_record_name(seq)).read_bytes()

    return fetch


def control_plane_exporting_fetcher(fetch, export_dir):
    """Wrap `fetch` so every control-plane record read is also written to
    export_dir/control-plane/<seq:020d>.json."""
    out = Path(export_dir) / 'control-plane'

    def fetch_and_export(seq):
        raw = fetch(seq)
        # Created on first write, so a pack without the control-plane chain
        # exports exactly what it did before 1.3.
        out.mkdir(parents=True, exist_ok=True)
        (out / control_plane_record_name(seq)).write_bytes(raw)
        return raw

    return fetch_and_export


def control_plane_manifest_problem(manifest):
    """None when the manifest's control_plane section is where its version
    says (exactly in 1.3) and names the chain this verifier reads, else the
    problem (a verification failure)."""
    version = manifest.get('schema_version', '1.0')
    section = manifest.get('control_plane')
    if version not in ('1.3', '1.4', '1.5'):
        if section is not None:
            return f"manifest {version} carries a control_plane section, which only 1.3, 1.4 and 1.5 define"
        return None
    if version in ('1.4', '1.5') and section is None:
        return None
    if section is None:
        return f"manifest {version} has no control_plane section"
    if not isinstance(section, dict):
        return f"manifest {version} control_plane section is not an object"
    if section.get('chain_family') != CONTROL_PLANE_CHAIN_FAMILY or section.get('prefix') != CONTROL_PLANE_PREFIX:
        return (f"control_plane section names chain_family {section.get('chain_family')!r} at prefix "
                f"{section.get('prefix')!r}; this verifier reads {CONTROL_PLANE_CHAIN_FAMILY!r} at "
                f"{CONTROL_PLANE_PREFIX!r}")
    if section.get('hash_version') != CONTROL_PLANE_SCHEMA_V1:
        return f"control_plane hash_version {section.get('hash_version')!r} is not {CONTROL_PLANE_SCHEMA_V1!r}"
    if section.get('genesis_hash') != genesis_hash():
        return "control_plane genesis_hash is not SHA-256 of meilynx-genesis-v1"
    entries = section.get('events')
    if not isinstance(entries, list):
        return "control_plane events is not a list"
    seqs = [e.get('sequence') if isinstance(e, dict) else None for e in entries]
    if seqs != list(range(len(entries))):
        return "control_plane events must list every sequence from 0, in order"
    return None


def verify_control_plane_chain(fetch, manifest, report=print, records_out=None):
    """Walk the manifest's control_plane entries from genesis: fetch each
    record, recompute its hash, check it against the stored event_hash and the
    manifest entry, and check the link to the record before it. Returns
    (passed, records), where records maps each readable record's event_id to
    (sequence, event_hash, verified) for the receipt anchor check.
    `records_out`, when given, is filled with sequence -> (record, verified)
    for every readable record (the customer-conditions verdict)."""
    problem = control_plane_manifest_problem(manifest)
    if problem:
        report(f"FAIL control_plane: {problem}")
        return False, {}
    section = manifest.get('control_plane')
    if section is None:
        return True, {}
    entries = section['events']
    if not entries:
        report("CONTROL-PLANE: the control-plane chain holds no records.")
        return True, {}

    passed = True
    records = {}
    next_link = {genesis_hash()}
    for entry in entries:
        seq = entry['sequence']
        link_targets = next_link
        next_link = {h for h in (entry.get('stored_event_hash'), entry.get('recomputed_event_hash'))
                     if isinstance(h, str) and h}
        try:
            record = load_control_plane_record(fetch(seq))
        except Exception as exc:  # Propagate loud — the record fails, the walk goes on
            report(f"FAIL control-plane seq={seq}: record unreadable: {exc}")
            passed = False
            continue
        stored_hash = record.get('event_hash') if isinstance(record.get('event_hash'), str) else ''
        stored_prev = record.get('previous_hash') if isinstance(record.get('previous_hash'), str) else ''
        event_id = record.get('event_id') if isinstance(record.get('event_id'), str) else ''
        next_link = next_link | ({stored_hash} if stored_hash else set())
        if records_out is not None:
            records_out[seq] = (record, False)
        try:
            recomputed = control_plane_event_hash_v1(record)
        except ValueError as exc:
            report(f"FAIL control-plane seq={seq}: {exc}")
            passed = False
            records.setdefault(event_id, (seq, stored_hash, False))
            continue
        # One FAIL line per record, naming every problem with it (as the
        # proxy chain walk reports one tampered record once).
        problems = []
        if control_plane_sequence(record) != seq:
            problems.append(f"the record says sequence_number {record.get('sequence_number')!r}")
        if recomputed != stored_hash:
            problems.append(f"hash mismatch. stored={stored_hash[:16]}... recomputed={recomputed[:16]}...")
        manifest_recomputed = entry.get('recomputed_event_hash', '')
        if manifest_recomputed and recomputed != manifest_recomputed:
            problems.append(f"hash recomputation disagrees with manifest. "
                            f"Our: {recomputed[:16]}... Manifest: {str(manifest_recomputed)[:16]}...")
        if entry.get('event_id') and entry.get('event_id') != event_id:
            problems.append(f"manifest names event_id {entry.get('event_id')!r}, the record {event_id!r}")
        if link_targets and stored_prev not in link_targets:
            expected = ' or '.join(f"{h[:16]}..." for h in sorted(link_targets))
            problems.append(f"chain break. previous_hash={stored_prev[:16]}... expected={expected}")
        if problems:
            report(f"FAIL control-plane seq={seq}: {'; '.join(problems)}")
        elif not link_targets:
            report(f"WARN control-plane seq={seq}: hash={stored_hash[:16]}... verified, but its chain link "
                   f"was not checked, because the record before it failed and nothing in the pack attests "
                   f"its hash.")
        ok = not problems
        if ok and link_targets:
            report(f"PASS control-plane seq={seq} {record.get('event_kind')} hash={stored_hash[:16]}... chain_ok")
            next_link = {stored_hash}
        else:
            passed = False
        records[event_id] = (seq, stored_hash, ok and bool(link_targets))
        if records_out is not None:
            records_out[seq] = (record, ok and bool(link_targets))
    if passed:
        report(f"CONTROL-PLANE OK: {len(entries)} control-plane record(s) verified from genesis")
    return passed, records


def receipt_anchor_findings(receipts, control_plane_records):
    """Each decision receipt's cp_anchor_event_id
    and cp_anchor_event_hash against the pack's control-plane chain. A receipt
    whose anchor id names a verified control-plane record must carry that
    record's event_hash (else a failure naming the receipt and both hashes);
    one naming a record that failed above is not checked (WARN); one naming no
    record in the pack is WARN receipt_anchor_outside_pack (a receipt anchored
    to the control plane's Postgres chain, or an event after the pack's last).
    `receipts` maps each receipt record's sequence to its payload. Returns
    (failures, warnings, lines)."""
    failures, warnings, lines = [], [], []
    for seq, receipt in sorted(receipts.items()):
        rid = receipt.get('receipt_id', '?')
        anchor_id = receipt.get('cp_anchor_event_id')
        anchor_hash = receipt.get('cp_anchor_event_hash')
        held = control_plane_records.get(anchor_id) if isinstance(anchor_id, str) and anchor_id else None
        if held is None:
            warnings.append(
                f"WARN receipt_anchor_outside_pack seq={seq} receipt={rid} cp_anchor_event_id={anchor_id}: "
                f"no record in this pack's control-plane chain has that event id.")
            continue
        cp_seq, cp_hash, cp_ok = held
        if not cp_ok:
            warnings.append(
                f"WARN seq={seq}: decision receipt {rid} cites control-plane seq={cp_seq}, which failed "
                f"above, so its anchor was not checked.")
            continue
        if anchor_hash != cp_hash:
            failures.append(
                f"decision receipt {rid}: cp_anchor_event_hash {str(anchor_hash)[:16]}... is not the "
                f"event_hash {cp_hash[:16]}... of control-plane seq={cp_seq} ({anchor_id})")
            continue
        lines.append(f"RECEIPT ANCHOR OK seq={seq} receipt={rid} control-plane seq={cp_seq}")
    return failures, warnings, lines


def verify_control_plane_section(manifest, receipts, fetch, report=print, records_out=None):
    """The control-plane chain a 1.3 manifest carries, then each decision
    receipt's anchor against it. True when both pass. `records_out` as in
    verify_control_plane_chain."""
    passed, records = verify_control_plane_chain(fetch, manifest, report, records_out)
    if manifest.get('control_plane') is None or control_plane_manifest_problem(manifest):
        return passed
    failures, warnings, lines = receipt_anchor_findings(receipts, records)
    for line in warnings:
        report(line)
    for problem in failures:
        report(f"FAIL receipt anchor: {problem}")
    if failures:
        return False
    for line in lines:
        report(line)
    return passed


# ---------------------------------------------------------------------------
# Customer conditions verdict
#
# A bank subscribed to a vendor's evidence can propose conditions
# the vendor's proxy enforces. An accepted set compiles into the holder's
# governance and MCP bundles as rule instances `<family>@cust_<12 hex>` and
# matrix rows `cust_<12 hex>.…` (the first 12 hex digits of the relationship
# id), and the acceptance is sealed on the holder's control-plane chain as
# `exchange.conditions_accepted`, with `conditions_sha256` (the digest the
# bank holds of its own set) and the compiled `compiled_governance_sha256` /
# `compiled_mcp_sha256`. `--conditions-sha256` asks this verifier to check,
# from the pack alone:
#
#   1. the acceptance: a verified `exchange.conditions_accepted` record of
#      that digest in the pack's control-plane chain. A pack without the
#      control-plane chain (every per-tenant export, Exchange packs included)
#      does not carry it; `--conditions-acceptance FILE` then takes the stored
#      record (`control-plane/<seq:020d>.json`) from outside the pack, whose
#      hash is recomputed but whose link into the chain the pack cannot show.
#      With neither, the verdict says "acceptance not in this pack" and cannot
#      be evaluated (exit 2), and only the instances the pack names are
#      counted.
#   2. the window: proxy records sealed at or after the acceptance (and
#      before a release of the set, when the pack shows one). Each model
#      request and MCP record in it either carries the compiled set by sealed
#      evidence (an MCP record's hashed `mcp_bundle_sha256` equal to the
#      compiled MCP bundle; a model request whose digest-bound evaluation
#      trace ran an instance with the set's suffix) or is a gap, printed with
#      its coordinates. A model request's `policy_version` is stored outside
#      the record's hash, so a match there alone is counted apart, never as
#      sealed.
#   3. the exceptions: records in the window whose findings, evaluation-trace
#      decision or MCP finding summary name one of the set's rule instances,
#      each printed with whether a sealed digest binds it. A hold a human
#      released is the condition working, not an exception; a hold that
#      lapsed is (D7), but no sealed field ties a lapsed decision receipt to
#      the set, so it is not counted here.
#
# What it cannot check, stated on the verdict: that the compiled bundles are
# what the set says. The compile runs in the holder's control plane, and the
# pack carries bundle digests, not bundles.
# ---------------------------------------------------------------------------

CONDITIONS_ACCEPTED_KIND = 'exchange.conditions_accepted'
CONDITIONS_RELEASED_KIND = 'exchange.conditions_released'
CONDITIONS_INSTANCE_PREFIX = 'cust_'
_SHA256_HEX = re.compile(r'[0-9a-f]{64}')
_UTC_TEXT = re.compile(r'(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)?')


def conditions_instance_suffix(relationship_id):
    """`cust_<12 hex>`: the instance suffix the holder's control plane compiles
    a relationship's set under (the first 12 hex digits of its id), or None
    when the id is not a UUID."""
    if not isinstance(relationship_id, str):
        return None
    hexed = relationship_id.replace('-', '').lower()
    if not re.fullmatch(r'[0-9a-f]{32}', hexed):
        return None
    return CONDITIONS_INSTANCE_PREFIX + hexed[:12]


def utc_microseconds(text):
    """An RFC 3339 timestamp as integer microseconds since the epoch (a
    fraction past six digits is truncated), or None."""
    m = _UTC_TEXT.fullmatch(text.strip()) if isinstance(text, str) else None
    if not m:
        return None
    year, month, day, hour, minute, second, fraction, zone = m.groups()
    try:
        moment = datetime.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second),
                                   tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    micros = int(((fraction or '') + '000000')[:6])
    offset = 0
    if zone and zone != 'Z':
        sign = 1 if zone[0] == '+' else -1
        offset = sign * (int(zone[1:3]) * 3600 + int(zone[4:6]) * 60)
    return (int((moment - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds())
            - offset) * 1_000_000 + micros


def _payload_str(record, key):
    payload = record.get('payload')
    value = payload.get(key) if isinstance(payload, dict) else None
    return str.__str__(value) if isinstance(value, str) else None


def acceptance_problem(record, digest):
    """None when a control-plane record is an acceptance of `digest` that
    names what the verdict needs, else why not."""
    if record.get('event_kind') != CONDITIONS_ACCEPTED_KIND:
        return f"it is {record.get('event_kind')!r}, not {CONDITIONS_ACCEPTED_KIND!r}"
    if _payload_str(record, 'conditions_sha256') != digest:
        return f"it accepts set {_payload_str(record, 'conditions_sha256')!r}, not {digest}"
    if conditions_instance_suffix(_payload_str(record, 'relationship_id')) is None:
        return "its payload names no relationship_id"
    if utc_microseconds(record.get('occurred_at')) is None:
        return "its occurred_at is not a timestamp"
    if not any(_SHA256_HEX.fullmatch(_payload_str(record, k) or '')
               for k in ('compiled_governance_sha256', 'compiled_mcp_sha256')):
        return "its payload names no compiled governance or MCP bundle digest"
    return None


def find_acceptance(cp_records, digest):
    """The last verified acceptance of `digest` in a control-plane chain
    (sequence -> (record, verified)), as (seq, record, verified, end_us) where
    end_us is when a later record released or superseded it, or None; None
    when the chain holds no acceptance of the digest."""
    found = None
    for seq in sorted(cp_records):
        record, verified = cp_records[seq]
        if record.get('event_kind') == CONDITIONS_ACCEPTED_KIND and \
                _payload_str(record, 'conditions_sha256') == digest:
            found = (seq, record, verified)
    if found is None:
        return None
    seq, record, verified = found
    relationship = _payload_str(record, 'relationship_id')
    end_us = None
    for later in sorted(s for s in cp_records if s > seq):
        other, _ = cp_records[later]
        kind = other.get('event_kind')
        same_set = _payload_str(other, 'conditions_sha256') == digest
        superseded = (kind == CONDITIONS_ACCEPTED_KIND and not same_set
                      and _payload_str(other, 'relationship_id') == relationship)
        if (kind == CONDITIONS_RELEASED_KIND and same_set) or superseded:
            end_us = utc_microseconds(other.get('occurred_at'))
            break
    return seq, record, verified, end_us


def _record_kind(record):
    kind = record.get('event_kind')
    if kind in (None, 'llm_request'):
        return 'llm'
    if isinstance(kind, str) and kind.startswith('mcp_'):
        return 'mcp'
    return None


def _trace_rules(record):
    """(rule ids, deciding rule id) of a sealed evaluation trace, else ((), None)."""
    trace = record.get('evaluation_trace')
    outcomes = trace.get('outcomes') if isinstance(trace, dict) else None
    if record.get('schema_version') not in ('v1.16', 'v1.18') or not isinstance(outcomes, dict):
        return (), None
    rules = outcomes.get('rules')
    ids = tuple(r.get('rule_id') for r in rules if isinstance(r, dict)) if isinstance(rules, list) else ()
    return ids, outcomes.get('deciding_rule_id')


def _names_instance(rule_id, suffix):
    """Whether a rule id is one of the set's rule instances
    (`<family>@cust_<12 hex>`); with suffix None, any customer-condition
    instance. A compiled MCP matrix row (`cust_<12 hex>.…`) is not one: a hold
    it raises and a human releases is the condition working, not an
    exception."""
    if not isinstance(rule_id, str):
        return False
    if suffix is None:
        return f'@{CONDITIONS_INSTANCE_PREFIX}' in rule_id
    return rule_id.endswith('@' + suffix)


def condition_exceptions(record, suffix):
    """What in a record names one of the set's instances (any customer-condition
    instance with suffix None): a list of (description, sealing)."""
    found = []
    findings = record.get('findings')
    bound = isinstance(record.get('content'), dict) and record['content'].get('findings_sha256_jcs') is not None
    for finding in findings if isinstance(findings, list) else ():
        if isinstance(finding, dict) and _names_instance(finding.get('validator'), suffix):
            found.append((f"finding {finding.get('validator')} {finding.get('code', '')}".rstrip(),
                          'bound by content.findings_sha256_jcs' if bound else 'stored, not hashed'))
    _, deciding = _trace_rules(record)
    if _names_instance(deciding, suffix):
        found.append((f"decision by {deciding}", 'bound by evaluation_trace.outcomes_sha256_jcs'))
    mcp = record.get('mcp_event') if isinstance(record.get('mcp_event'), dict) else {}
    summary = mcp.get('finding_summary')
    for item in summary if isinstance(summary, list) else ():
        if isinstance(item, dict) and (_names_instance(item.get('rule_id'), suffix)
                                       or _names_instance(item.get('detector'), suffix)):
            found.append((f"MCP finding {item.get('rule_id') or item.get('detector')} {item.get('code', '')}".rstrip(),
                          'stored, not hashed'))
    return found


def conditions_verdict(digest, manifest, records, cp_records, supplied=None, report=print, label=''):
    """The customer-conditions verdict for the set
    whose digest is `digest`, over the proxy records the walk read (`records`:
    sequence -> record) and the pack's control-plane chain (`cp_records`:
    sequence -> (record, verified), empty when the pack has none). `supplied`
    is (record, path) of an acceptance given outside the pack. Prints the
    lines and the verdict line; returns PASSED, FAILED or CANNOT_EVALUATE."""
    report(f"CONDITIONS: set {digest}")
    # A hash-only stub has no timestamp, kind or findings: it cannot
    # be placed in the window or read for an instance, so it is named here and
    # counted nowhere else.
    stubbed = sorted(manifest_stubs(manifest))
    if stubbed:
        shown = ', '.join(map(str, stubbed[:20])) + (', ...' if len(stubbed) > 20 else '')
        report(f"NOTE: {len(stubbed)} hash-only stub(s) (seq {shown}) carry no timestamp, kind or findings, so the "
               f"conditions verdict does not place them in the window or count them.")
    in_pack = find_acceptance(cp_records, digest) if cp_records else None
    status = PASSED
    where = None
    if in_pack is not None:
        seq, acceptance, verified, end_us = in_pack
        if supplied is not None:
            report("NOTE: the pack's control-plane chain holds the acceptance; --conditions-acceptance is not used.")
        if not verified:
            report(f"FAIL conditions: the acceptance at control-plane seq={seq} did not verify (see above).")
            status = FAILED
        where = f"seq {seq}"
    elif supplied is not None:
        acceptance, path = supplied
        end_us = None
        seq = control_plane_sequence(acceptance)
        try:
            recomputed = control_plane_event_hash_v1(acceptance)
        except ValueError as exc:
            recomputed = None
            report(f"FAIL conditions: the acceptance in {path} cannot be recomputed: {exc}")
            status = FAILED
        if recomputed is not None and recomputed != acceptance.get('event_hash'):
            report(f"FAIL conditions: the acceptance in {path} does not recompute to its event_hash "
                   f"(stored={str(acceptance.get('event_hash'))[:16]}... recomputed={recomputed[:16]}...)")
            status = FAILED
        held = [r for r, _ in cp_records.values() if r.get('event_id') == acceptance.get('event_id')]
        if held and held[0].get('event_hash') != acceptance.get('event_hash'):
            report(f"FAIL conditions: the acceptance in {path} is not the record this pack's control-plane "
                   f"chain holds for event {acceptance.get('event_id')}")
            status = FAILED
        where = (f"seq {seq} (supplied outside this pack: its hash recomputes, its link into the holder's "
                 f"control-plane chain is not in this pack)")
    else:
        acceptance = None
    if acceptance is not None:
        problem = acceptance_problem(acceptance, digest)
        if problem:
            report(f"FAIL conditions: the acceptance at control-plane {where} is not usable: {problem}")
            return FAILED if status == FAILED or in_pack is None else CANNOT_EVALUATE

    governed = {s: r for s, r in records.items() if _record_kind(r)}
    if acceptance is None:
        why = ("this pack's control-plane chain holds no acceptance of the set" if cp_records
               else "acceptance not in this pack")
        report(f"CANNOT EVALUATE conditions: {why}. The compiled versions and the set's instance suffix are in "
               f"the acceptance, so no record is checked against them. Pass the acceptance record with "
               f"--conditions-acceptance FILE, or verify a pack that carries the holder's control-plane chain.")
        named = {}
        for s in sorted(governed):
            for what, sealing in condition_exceptions(governed[s], None):
                named[s] = named.get(s, []) + [f"{what} ({sealing})"]
        for s, whats in named.items():
            report(f"INSTANCE seq={s}: {'; '.join(whats)}")
        report(f"conditions: set {digest} {why}; {len(governed)} records in the pack not checked against a "
               f"compiled version; {len(named)} records name a customer-condition instance; compiled by the "
               f"holder's control plane{label}")
        return CANNOT_EVALUATE

    suffix = conditions_instance_suffix(_payload_str(acceptance, 'relationship_id'))
    start_us = utc_microseconds(acceptance.get('occurred_at'))
    governance = _payload_str(acceptance, 'compiled_governance_sha256')
    mcp_bundle = _payload_str(acceptance, 'compiled_mcp_sha256')
    report(f"CONDITIONS: accepted at control-plane {where}, {acceptance.get('occurred_at')}: relationship "
           f"{_payload_str(acceptance, 'relationship_id')}, instances {suffix}, compiled governance "
           f"{(governance or 'none')[:16]}..., compiled MCP bundle {(mcp_bundle or 'none')[:16]}...")
    window = {}
    for s, r in governed.items():
        at = utc_microseconds(normalize_timestamp(r.get('timestamp_utc', '')))
        if at is not None and at >= start_us and (end_us is None or at < end_us):
            window[s] = r
    if end_us is not None:
        report("CONDITIONS: the set was released or superseded later in the control-plane chain; the window "
               "ends there.")
    carried, unsealed, gaps, exceptions = 0, [], [], []
    for s in sorted(window):
        r = window[s]
        if _record_kind(r) == 'mcp':
            mcp = r.get('mcp_event') if isinstance(r.get('mcp_event'), dict) else {}
            observed = mcp.get('mcp_bundle_sha256')
            if mcp_bundle and observed == mcp_bundle:
                carried += 1
            else:
                gaps.append((s, r, 'MCP bundle', observed, mcp_bundle))
        else:
            rule_ids, _ = _trace_rules(r)
            if any(_names_instance(i, suffix) for i in rule_ids):
                carried += 1
            elif governance and r.get('policy_version') == governance:
                unsealed.append(s)
            else:
                gaps.append((s, r, 'governance', r.get('policy_version'), governance))
        for what, sealing in condition_exceptions(r, suffix):
            exceptions.append((s, r, what, sealing))
    for s, r, lane, observed, compiled in gaps:
        report(f"GAP seq={s} hash={str(r.get('event_hash', ''))[:16]}...: sealed under {lane} "
               f"{(observed or 'none')[:16]}..., not the compiled {(compiled or 'none')[:16]}...")
    if unsealed:
        report(f"NOTE: {len(unsealed)} model request(s) in the window (seq {', '.join(map(str, unsealed))}) name "
               f"the compiled governance version only in policy_version, which their hash does not cover; "
               f"they are not counted as sealed.")
    for s, r, what, sealing in exceptions:
        report(f"EXCEPTION seq={s} hash={str(r.get('event_hash', ''))[:16]}...: {what} ({sealing})")
    excepted = len({s for s, *_ in exceptions})
    report(f"conditions: set {digest} accepted at {where.split(' (')[0]}; {carried} of {len(window)} records in "
           f"the window sealed under a governance version carrying it; {excepted} exceptions; compiled by the "
           f"holder's control plane{label}")
    return status


def compute_event_hash_v1_9_llm_request(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    join_context,
):
    """v1.9 llm_request hash: the v1.2 LlmRequest preimage (v1.2
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
    # The v1.9 addition, in CallerJoinContext struct-definition order.
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
    """v1.9 mcp.* hash: the v1.7 preimage (which carries the v1.5
    principal chain and the v1.6 capture-axis address forward, fed even when
    None) plus the three caller-asserted join keys. Mirror of
    `compute_event_hash_v1_9_mcp` in sqlite.rs.

    The v1.4-v1.7 field feeds are DUPLICATED here, not shared — same structural
    seam as every earlier MCP hasher on this side and the Rust side: a
    v1.9-only encoding change must never alter v1.4/v1.5/v1.6/v1.7 output,
    which would silently invalidate every historical record."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"compute_event_hash_v1_9_mcp called with non-MCP kind {event_kind!r}"
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
    # The v1.5 principal chain (carried forward into v1.9).
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    # The v1.6 capture-axis address (carried forward, fed even when
    # None for byte-position stability with v1.6/v1.7).
    h.update(encode_optional_str(mcp_event.get('redacted_payload_sha256_jcs')))
    # The v1.7 enforcement-axis fields (carried forward, fed even
    # when None for byte-position stability with v1.7).
    h.update(encode_optional_str(mcp_event.get('redaction_pre_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_post_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('hold_id')))
    # The v1.9 addition, in CallerJoinContext struct-definition order.
    h.update(encode_optional_str(join_context.get('correlation_id')))
    h.update(encode_optional_str(join_context.get('session_id')))
    h.update(encode_optional_str(join_context.get('agent_name')))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# RFC 8785 (JCS) canonical JSON, for the v1.10 content digests.
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
    """v1.10 llm_request hash: the v1.9 layout (v1.2 prefix + kind
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


def compute_event_hash_v1_11_llm_request(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    join_context, content,
):
    """v1.11 llm_request hash: the v1.10 layout followed by the two
    tool-call digests (`tool_calls_sha256_jcs`, then
    `stored_tool_calls_sha256_jcs`), each an optional string. Mirror of
    `compute_event_hash_v1_11_llm_request` in sqlite.rs.

    The v1.10 feeds are duplicated rather than shared with
    compute_event_hash_v1_10_llm_request, as every bucket duplicates its
    predecessor, so a v1.11 change can never move a v1.10 hash. The tool calls
    themselves stay outside the preimage; `check_llm_content` recomputes the
    stored digest from the record's own `tool_calls`."""
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
    h.update(encode_optional_str(content.get('tool_calls_sha256_jcs')))
    h.update(encode_optional_str(content.get('stored_tool_calls_sha256_jcs')))
    return h.hexdigest()


def _has_tool_call_digests(content):
    return isinstance(content, dict) and (
        content.get('tool_calls_sha256_jcs') is not None
        or content.get('stored_tool_calls_sha256_jcs') is not None
    )


def check_llm_content(event, stripped=frozenset()):
    """For a v1.10, v1.11 or v1.12 record, check that the content it
    carries is the content it was sealed over: the stored-prompt,
    stored-response, findings and stored-tool-calls digests (all
    inside the hash) must match the record's own `messages`, `response_text`,
    `findings` and `tool_calls`. A digest that is absent means nothing was
    retained, so the record must carry no content on that axis; a v1.10
    record has no tool-call digest, so tool calls on one are unattested.
    Returns a list of problems; empty means the content checks out. Records
    on older schema versions carry no digests and return no problems.

    v1.12 carries the v1.11 content block forward, presence-tagged:
    a v1.12 record with a content block gets the same check, and one sealed
    with no capture policy has none and stores its content unhashed, as before
    v1.10.

    `stripped` names the fields a content-stripped Exchange pack
    removed (STRIPPED_FIELDS). An axis whose content was removed is not
    re-derived: its sealed digest is inside the hash, which the walk
    recomputes, and that is all a stripped pack can show of it. The findings
    axis is kept and checked.

    v1.16 and v1.18 carry the same presence-tagged content block
    forward (CONTENT_ATTESTATION_VERSIONS), so their records get the v1.12
    check: a block is re-derived, no block means no capture policy."""
    schema_version = event.get('schema_version') or 'v1'
    if schema_version not in CONTENT_ATTESTATION_VERSIONS:
        return []
    content = event.get('content')
    if schema_version in CONTENT_PRESENCE_TAGGED_VERSIONS and content is None:
        return []
    if not isinstance(content, dict):
        return [f'{schema_version} record has no content payload']
    problems = []
    messages = event.get('messages') or []
    stored_prompt = content.get('stored_prompt_sha256_jcs')
    if 'messages' in stripped:
        pass
    elif stored_prompt is not None:
        if sha256_jcs(messages) != stored_prompt:
            problems.append('messages do not match stored_prompt_sha256_jcs (the prompt was changed after sealing)')
    elif messages:
        problems.append('messages present but no stored_prompt_sha256_jcs was sealed')
    response_text = event.get('response_text')
    stored_response = content.get('stored_response_sha256')
    if 'response_text' in stripped:
        pass
    elif stored_response is not None:
        if response_text is None or hashlib.sha256(response_text.encode('utf-8')).hexdigest() != stored_response:
            problems.append('response_text does not match stored_response_sha256 (the response was changed after sealing)')
    elif response_text is not None:
        problems.append('response_text present but no stored_response_sha256 was sealed')
    findings_digest = content.get('findings_sha256_jcs')
    if findings_digest is not None and sha256_jcs(event.get('findings') or []) != findings_digest:
        problems.append('findings do not match findings_sha256_jcs (the findings were changed after sealing)')
    tool_calls = event.get('tool_calls')
    stored_tool_calls = content.get('stored_tool_calls_sha256_jcs')
    if 'tool_calls' in stripped:
        pass
    elif stored_tool_calls is not None:
        if tool_calls is None or sha256_jcs(tool_calls) != stored_tool_calls:
            problems.append('tool_calls do not match stored_tool_calls_sha256_jcs (the tool calls were changed after sealing)')
    elif tool_calls is not None:
        problems.append('tool_calls present but no stored_tool_calls_sha256_jcs was sealed')
    return problems


def encode_sealed_identity(identity):
    """The sealed identity feed shared by the v1.12 hashers of both
    lanes. Mirror of `feed_sealed_identity` in sqlite.rs: `SealedIdentity`
    definition order; optional strings carry the 1-byte presence tag;
    `delegated_human` is a presence tag followed by `subject` then `issuer`.
    `tier` and `credential_kind` are fed in their wire spelling (`t1`,
    `project_key`, …), which is how the record stores them."""
    out = encode_optional_str(identity.get('agent_id'))
    out += identity['tier'].encode('utf-8')
    out += identity['credential_kind'].encode('utf-8')
    out += encode_optional_str(identity.get('credential_kid'))
    human = identity.get('delegated_human')
    if human is None:
        out += b'\x00'
    else:
        out += b'\x01' + human['subject'].encode('utf-8') + human['issuer'].encode('utf-8')
    out += identity['asserted_digest'].encode('utf-8')
    return out


def asserted_claims_digest(asserted):
    """Lowercase hex SHA-256 over the RFC 8785 canonical JSON of the
    stored `identity.asserted` object. Mirror of `asserted_claims_digest` in
    meilynx-core (serde_jcs over the same object the record stores)."""
    return sha256_jcs(asserted)


def check_sealed_identity(event, stripped=frozenset()):
    """For a v1.12 record, check that the stored asserted labels
    are the labels the record was sealed over: recompute `asserted_digest`
    from `identity.asserted`. The labels are stored-not-hashed, so a rewritten
    label leaves the chain hash intact; this check is what catches it. Returns
    a list of problems; empty means the identity checks out. A
    v1.14 MCP record carries the identity forward, optionally: checked when
    present; so does a v1.17 record. Records on any other schema version carry no identity and return
    no problems. When a content-stripped Exchange pack removed the
    labels (`identity.asserted` in `stripped`), their sealed digest is inside
    the hash and is not re-derived."""
    version = event.get('schema_version') or 'v1'
    identity = event.get('identity')
    if version in ('v1.14', 'v1.17', 'v1.18') and identity is None:
        return []
    if version not in ('v1.12', 'v1.14', 'v1.17', 'v1.18'):
        return []
    if not isinstance(identity, dict):
        return [f"{version} record has no identity block"]
    if 'identity.asserted' in stripped:
        return []
    problems = []
    asserted = identity.get('asserted')
    if not isinstance(asserted, dict):
        problems.append("identity has no stored asserted-claims object")
    else:
        expected = asserted_claims_digest(asserted)
        if identity.get('asserted_digest') != expected:
            problems.append(
                f"identity.asserted_digest {identity.get('asserted_digest')!r} does not match "
                f"the stored asserted labels (recomputed {expected!r}) — a label was rewritten "
                f"after sealing"
            )
    return problems


def compute_event_hash_v1_12_llm_request(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    join_context, content, identity,
):
    """v1.12 llm_request hash: the v1.11 layout with the content
    block presence-tagged (`content` may be None: every LLM record is v1.12
    once the resolver produced an identity, whether or not a capture policy is
    in force), followed by the sealed identity block. Mirror of
    `compute_event_hash_v1_12_llm_request` in sqlite.rs. The v1.11 feeds are
    duplicated, not shared, so a v1.12 change can never move a v1.11 hash."""
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
    if content is None:
        h.update(b'\x00')
    else:
        h.update(b'\x01')
        h.update(content['capture_policy'].encode('utf-8'))
        h.update(encode_optional_str(content.get('prompt_sha256_jcs')))
        h.update(encode_optional_str(content.get('response_sha256')))
        h.update(encode_optional_str(content.get('stored_prompt_sha256_jcs')))
        h.update(encode_optional_str(content.get('stored_response_sha256')))
        h.update(encode_optional_str(content.get('findings_sha256_jcs')))
        h.update(encode_optional_str(content.get('tool_calls_sha256_jcs')))
        h.update(encode_optional_str(content.get('stored_tool_calls_sha256_jcs')))
    # The v1.12 addition.
    h.update(encode_sealed_identity(identity))
    return h.hexdigest()


def compute_event_hash_v1_16_llm_request(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    join_context, content, identity, evaluation_trace,
):
    """v1.16 llm_request hash: the v1.12 layout with the
    identity block presence-tagged (an evaluated request can carry no
    identity), followed by the evaluation outcome digest. The stored outcomes
    are bound by that digest (`check_evaluation_trace`); the trace's timing is
    outside the hash. Mirror of `compute_event_hash_v1_16_llm_request` in
    sqlite.rs. The v1.12 feeds are duplicated, not shared, so a v1.16 change
    can never move a v1.12 hash."""
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
    if content is None:
        h.update(b'\x00')
    else:
        h.update(b'\x01')
        h.update(content['capture_policy'].encode('utf-8'))
        h.update(encode_optional_str(content.get('prompt_sha256_jcs')))
        h.update(encode_optional_str(content.get('response_sha256')))
        h.update(encode_optional_str(content.get('stored_prompt_sha256_jcs')))
        h.update(encode_optional_str(content.get('stored_response_sha256')))
        h.update(encode_optional_str(content.get('findings_sha256_jcs')))
        h.update(encode_optional_str(content.get('tool_calls_sha256_jcs')))
        h.update(encode_optional_str(content.get('stored_tool_calls_sha256_jcs')))
    if identity is None:
        h.update(b'\x00')
    else:
        h.update(b'\x01')
        h.update(encode_sealed_identity(identity))
    # The v1.16 addition.
    h.update(evaluation_trace['outcomes_sha256_jcs'].encode('utf-8'))
    return h.hexdigest()


# The customer block vocabulary. Mirror
# of `CustomerSource::ALL` in meilynx-core/src/types/customer_scope.rs.
CUSTOMER_SOURCES = ('credential', 'asserted', 'none')


def customer_shape_problem(block):
    """Why a customer block is not one the resolver produces, or
    None. Mirror of `SealedCustomer::shape_error` in meilynx-core: `none`
    carries no digest and no kid; `asserted` carries a digest and no kid;
    `credential` carries a digest and a non-blank kid; a digest is 64
    lowercase hex."""
    if not isinstance(block, dict):
        return 'customer is not an object'
    source = block.get('source')
    if source not in CUSTOMER_SOURCES:
        return f'customer.source {source!r} is not one of {CUSTOMER_SOURCES}'
    digest = block.get('label_sha256')
    kid = block.get('credential_kid')
    if digest is not None and not (
        isinstance(digest, str) and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest)
    ):
        return 'label_sha256 is not 64 lowercase hex'
    if source == 'none':
        if digest is not None:
            return 'source `none` carries a label digest'
        if kid is not None:
            return 'source `none` carries a credential kid'
    elif source == 'asserted':
        if kid is not None:
            return 'source `asserted` carries a credential kid'
        if digest is None:
            return 'source `asserted` has no label digest'
    else:
        if digest is None:
            return 'source `credential` has no label digest'
        if kid is None:
            return 'source `credential` has no credential kid'
        if not isinstance(kid, str) or not kid.strip():
            return 'credential kid is empty'
    return None


def customer_label_sha256(label):
    """Lowercase hex SHA-256 over the UTF-8 bytes of a customer label."""
    return hashlib.sha256(label.encode('utf-8')).hexdigest()


def encode_sealed_customer(customer):
    """The customer block feed shared by the v1.18 hashers of both
    lanes. Mirror of `feed_sealed_customer` in sqlite.rs: a 1-byte presence
    tag (always 1 in a v1.18 preimage), `label_sha256` (presence-tagged),
    `source` (wire spelling), `credential_kid` (presence-tagged)."""
    out = b'\x01'
    out += encode_optional_str(customer.get('label_sha256'))
    out += customer['source'].encode('utf-8')
    out += encode_optional_str(customer.get('credential_kid'))
    return out


def check_customer_scope(event):
    """For a v1.18 record, check the customer block is one the
    resolver produces and, when the record stores the plain label beside it
    (`customer_id`, stored-not-hashed), that the sealed digest is that
    label's. A rewritten label leaves the chain hash intact; this check is
    what catches it. A pack produced for one customer carries other
    customers' records as hash-only stubs with no label, so a missing
    `customer_id` is not a problem. Returns a list of problems."""
    version = event.get('schema_version') or 'v1'
    customer = event.get('customer')
    if version != 'v1.18':
        if customer is not None:
            return [f'{version} record carries a customer block; it is hashed only in the v1.18 bucket']
        return []
    if customer is None:
        return ['v1.18 record has no customer block']
    problem = customer_shape_problem(customer)
    if problem is not None:
        return [f'malformed customer block: {problem}']
    label = event.get('customer_id')
    if customer['source'] == 'asserted' and isinstance(label, str) and label:
        expected = customer_label_sha256(label)
        if customer.get('label_sha256') != expected:
            return [
                f"customer.label_sha256 {customer.get('label_sha256')!r} does not match the stored "
                f"asserted label (recomputed {expected!r}) — the label was rewritten after sealing"
            ]
    return []


def compute_event_hash_v1_18_llm_request(
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    join_context, content, identity, evaluation_trace, customer,
):
    """v1.18 llm_request hash: the v1.16
    layout with the evaluation trace presence-tagged (a request refused
    before evaluation carries none), then the customer block. Mirror of
    `compute_event_hash_v1_18_llm_request` in sqlite.rs. The v1.16 feeds are
    duplicated, not shared, so a v1.18 change can never move a v1.16 hash."""
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
    if content is None:
        h.update(b'\x00')
    else:
        h.update(b'\x01')
        h.update(content['capture_policy'].encode('utf-8'))
        h.update(encode_optional_str(content.get('prompt_sha256_jcs')))
        h.update(encode_optional_str(content.get('response_sha256')))
        h.update(encode_optional_str(content.get('stored_prompt_sha256_jcs')))
        h.update(encode_optional_str(content.get('stored_response_sha256')))
        h.update(encode_optional_str(content.get('findings_sha256_jcs')))
        h.update(encode_optional_str(content.get('tool_calls_sha256_jcs')))
        h.update(encode_optional_str(content.get('stored_tool_calls_sha256_jcs')))
    if identity is None:
        h.update(b'\x00')
    else:
        h.update(b'\x01')
        h.update(encode_sealed_identity(identity))
    # The trace is presence-tagged in v1.18 (v1.16 required it).
    if evaluation_trace is None:
        h.update(b'\x00')
    else:
        h.update(b'\x01')
        h.update(evaluation_trace['outcomes_sha256_jcs'].encode('utf-8'))
    # The v1.18 addition.
    h.update(encode_sealed_customer(customer))
    return h.hexdigest()


def check_evaluation_trace(event):
    """A v1.16 record's hash covers the digest of its
    evaluation outcomes, not the outcomes themselves. Recompute the digest from
    the stored outcomes so an edit after sealing is caught; refuse a trace on
    any other version (it would ride the record unhashed). The timing half is
    not checked: it is outside the hash by design. Mirror of
    `check_evaluation_trace` in meilynx-audit/src/evaluation_trace.rs."""
    version = event.get('schema_version') or 'v1'
    trace = event.get('evaluation_trace')
    if version not in ('v1.16', 'v1.18'):
        if trace is not None:
            return [f'{version} record carries an evaluation_trace; it is hashed only in the v1.16 and v1.18 buckets']
        return []
    if trace is None:
        # v1.18 presence-tags the trace: a refusal sealed before
        # evaluation carries none and is whole.
        return [] if version == 'v1.18' else ['v1.16 record has no evaluation_trace']
    sealed = trace.get('outcomes_sha256_jcs')
    if not isinstance(sealed, str):
        return ['evaluation_trace has no outcomes_sha256_jcs']
    outcomes = trace.get('outcomes')
    if not isinstance(outcomes, dict):
        return ['evaluation_trace has no outcomes']
    if sha256_jcs(outcomes) != sealed:
        return ['evaluation outcomes do not match outcomes_sha256_jcs (the outcomes were changed after sealing)']
    return []


def compute_event_hash_v1_12_mcp(
    event_kind,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    mcp_event, join_context, identity,
):
    """v1.12 mcp.* hash: the v1.9 layout with the join keys
    presence-tagged whether or not the caller asserted any (`join_context`
    may be None), then the sealed identity block. Mirror of
    `compute_event_hash_v1_12_mcp` in sqlite.rs. One number for both lanes:
    v1.10 and v1.11 are LLM content buckets, so the MCP lane skips to v1.12.
    The v1.4-v1.9 feeds are DUPLICATED here, not shared."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"compute_event_hash_v1_12_mcp called with non-MCP kind {event_kind!r}"
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
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    h.update(encode_optional_str(mcp_event.get('redacted_payload_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_pre_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_post_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('hold_id')))
    join = join_context or {}
    h.update(encode_optional_str(join.get('correlation_id')))
    h.update(encode_optional_str(join.get('session_id')))
    h.update(encode_optional_str(join.get('agent_name')))
    # The v1.12 addition.
    h.update(encode_sealed_identity(identity))
    return h.hexdigest()


MCP_DECISION_STAGES = ('access', 'limit', 'tool_call', 'tool_result', 'taint', 'adapter_fail_open')


def compute_event_hash_v1_14_mcp(
    event_kind,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    mcp_event, join_context, identity,
):
    """v1.14 mcp.* hash: the v1.12 layout with the identity block
    presence-tagged (1-byte tag, then the block; 0 alone when absent), then
    the decision stage's wire name with the same presence tag every optional
    string uses. Mirror of `compute_event_hash_v1_14_mcp` in sqlite.rs.
    v1.13 is the coverage key-inventory bucket, so the MCP lane skips to
    v1.14. The v1.12 feeds are DUPLICATED here, not shared."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(
            f"compute_event_hash_v1_14_mcp called with non-MCP kind {event_kind!r}"
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
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    h.update(encode_optional_str(mcp_event.get('redacted_payload_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_pre_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_post_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('hold_id')))
    join = join_context or {}
    h.update(encode_optional_str(join.get('correlation_id')))
    h.update(encode_optional_str(join.get('session_id')))
    h.update(encode_optional_str(join.get('agent_name')))
    if identity is None:
        h.update(b'\x00')
    else:
        h.update(b'\x01')
        h.update(encode_sealed_identity(identity))
    # The v1.14 addition.
    h.update(encode_optional_str(mcp_event.get('stage')))
    return h.hexdigest()


# The data_reach block vocabulary.
DATA_REACH_UNBOUND = 'unbound'
DATA_REACH_ACCESS = ('read', 'write')
DATA_REACH_OUTCOMES = ('matched', 'no_match', 'error')
DATA_REACH_MAX_ARG_KEYS = 32
DATA_REACH_MAX_ARG_KEY_CHARS = 64
_DATA_REACH_BINDING_ID = re.compile(r'rb_[0-9a-f]{16}')


def data_reach_shape_problem(block):
    """Mirror of `McpDataReach::shape_error`: the shape every sealed
    block has. A binding id the control plane minted exactly when a binding
    matched (`unbound` otherwise), an access exactly then, a known outcome, and
    argument names within the caps, non-empty, strictly ascending in UTF-8 byte
    order. Returns a problem string, or None."""
    if not isinstance(block, dict):
        return 'data_reach is not an object'
    outcome = block.get('outcome')
    if outcome not in DATA_REACH_OUTCOMES:
        return f'outcome {outcome!r} is not one of {DATA_REACH_OUTCOMES}'
    matched = outcome == 'matched'
    binding_id = block.get('binding_id')
    minted = isinstance(binding_id, str) and _DATA_REACH_BINDING_ID.fullmatch(binding_id) is not None
    if matched != minted or (not matched and binding_id != DATA_REACH_UNBOUND):
        return f'binding_id {binding_id!r} does not fit outcome {outcome!r}'
    access = block.get('access')
    if matched != (access is not None) or (access is not None and access not in DATA_REACH_ACCESS):
        return f'access {access!r} is set exactly when a binding matched (outcome {outcome!r})'
    if not isinstance(block.get('schema_known'), bool):
        return 'schema_known is not a boolean'
    keys = block.get('arg_keys')
    if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
        return 'arg_keys is not a list of names'
    if len(keys) > DATA_REACH_MAX_ARG_KEYS:
        return f'{len(keys)} key names sealed; at most {DATA_REACH_MAX_ARG_KEYS}'
    if any(k == '' or len(k) > DATA_REACH_MAX_ARG_KEY_CHARS for k in keys):
        return f'a key name is empty or longer than {DATA_REACH_MAX_ARG_KEY_CHARS} characters'
    encoded = [k.encode('utf-8') for k in keys]
    if any(a >= b for a, b in zip(encoded, encoded[1:])):
        return 'key names are not strictly ascending in byte order'
    omitted = block.get('arg_keys_omitted')
    if isinstance(omitted, bool) or not isinstance(omitted, int) or not 0 <= omitted <= 0xFFFFFFFF:
        return 'arg_keys_omitted is not a u32'
    return None


def compute_event_hash_v1_18_mcp(
    event_kind,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    mcp_event, join_context, identity, customer,
):
    """v1.18 mcp.* hash for every MCP kind
    and stage: the v1.14 layout (identity presence-tagged, the stage
    optional), then the data_reach block presence-tagged (its members fed
    byte for byte as v1.17 feeds them, and allowed only on a tool_call-stage
    mcp.policy_decision), then the customer block. Mirror of
    `compute_event_hash_v1_18_mcp` in sqlite.rs and
    `McpEvidenceChainHasher.ComputeV118` in the control plane. The v1.14
    feeds are duplicated, not shared."""
    if event_kind not in MCP_EVENT_KINDS:
        raise ValueError(f"compute_event_hash_v1_18_mcp is defined only for mcp.* kinds; got {event_kind!r}")
    reach = mcp_event.get('data_reach')
    if reach is not None:
        if event_kind != EVENT_KIND_MCP_POLICY_DECISION or mcp_event.get('stage') != 'tool_call':
            raise ValueError(
                f"a data_reach block is sealed only on a tool_call-stage mcp.policy_decision; "
                f"got {event_kind!r} at stage {mcp_event.get('stage')!r}"
            )
        problem = data_reach_shape_problem(reach)
        if problem is not None:
            raise ValueError(f"refusing to seal a malformed data_reach block: {problem}")
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
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    h.update(encode_optional_str(mcp_event.get('redacted_payload_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_pre_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_post_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('hold_id')))
    join = join_context or {}
    h.update(encode_optional_str(join.get('correlation_id')))
    h.update(encode_optional_str(join.get('session_id')))
    h.update(encode_optional_str(join.get('agent_name')))
    if identity is None:
        h.update(b'\x00')
    else:
        h.update(b'\x01')
        h.update(encode_sealed_identity(identity))
    h.update(encode_optional_str(mcp_event.get('stage')))
    # The data-reach block, presence-tagged (v1.17 required it).
    if reach is None:
        h.update(b'\x00')
    else:
        h.update(b'\x01')
        h.update(reach['binding_id'].encode('utf-8'))
        h.update(encode_optional_str(reach.get('access')))
        h.update(reach['outcome'].encode('utf-8'))
        h.update(b'\x01' if reach['schema_known'] else b'\x00')
        keys = reach['arg_keys']
        h.update(struct.pack('<I', len(keys)))
        for key in keys:
            raw = key.encode('utf-8')
            h.update(struct.pack('<I', len(raw)))
            h.update(raw)
        h.update(struct.pack('<I', int(reach['arg_keys_omitted'])))
    # The v1.18 addition.
    h.update(encode_sealed_customer(customer))
    return h.hexdigest()


def compute_event_hash_v1_17_mcp(
    event_kind,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    mcp_event, join_context, identity,
):
    """v1.17 mcp.policy_decision hash: the v1.14 layout byte for
    byte, then the data_reach block in definition order: binding_id (raw
    UTF-8), access (presence-tagged), outcome (raw UTF-8), schema_known (one
    byte), arg_keys (u32 LE count, then each name as a u32 LE byte length and
    its UTF-8 bytes, so two names never read as one) and arg_keys_omitted
    (u32 LE). Mirror of `compute_event_hash_v1_17_mcp` in sqlite.rs and
    `McpEvidenceChainHasher.ComputeV117` (control plane). Defined only for a
    tool_call-stage mcp.policy_decision carrying a block. The v1.14 feeds are
    DUPLICATED here, not shared."""
    if event_kind != EVENT_KIND_MCP_POLICY_DECISION or mcp_event.get('stage') != 'tool_call':
        raise ValueError(
            f"compute_event_hash_v1_17_mcp is defined only for a tool_call-stage "
            f"mcp.policy_decision; got {event_kind!r} at stage {mcp_event.get('stage')!r}"
        )
    reach = mcp_event.get('data_reach')
    if reach is None:
        raise ValueError(
            "compute_event_hash_v1_17_mcp requires a data_reach block; a record "
            "sealed without one must stay in its pre-v1.17 bucket."
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
    h.update(encode_principal_chain(mcp_event['principal_chain']))
    h.update(encode_optional_str(mcp_event.get('redacted_payload_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_pre_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('redaction_post_sha256_jcs')))
    h.update(encode_optional_str(mcp_event.get('hold_id')))
    join = join_context or {}
    h.update(encode_optional_str(join.get('correlation_id')))
    h.update(encode_optional_str(join.get('session_id')))
    h.update(encode_optional_str(join.get('agent_name')))
    if identity is None:
        h.update(b'\x00')
    else:
        h.update(b'\x01')
        h.update(encode_sealed_identity(identity))
    h.update(encode_optional_str(mcp_event.get('stage')))
    # The v1.17 addition.
    h.update(reach['binding_id'].encode('utf-8'))
    h.update(encode_optional_str(reach.get('access')))
    h.update(reach['outcome'].encode('utf-8'))
    h.update(b'\x01' if reach['schema_known'] else b'\x00')
    keys = reach['arg_keys']
    h.update(struct.pack('<I', len(keys)))
    for key in keys:
        raw = key.encode('utf-8')
        h.update(struct.pack('<I', len(raw)))
        h.update(raw)
    h.update(struct.pack('<I', reach['arg_keys_omitted']))
    return h.hexdigest()


def _on_behalf_of_is_verified(mcp_event):
    """Mirror of `PrincipalChain::on_behalf_of_is_verified`: a verified leg is
    present AND marked `verified`; an unmarked leg is asserted (fail-safe)."""
    chain = mcp_event.get('principal_chain') or {}
    return chain.get('on_behalf_of') is not None and chain.get('on_behalf_of_attestation') == 'verified'


# Every bucket whose preimage reads the content
# attestation (`content.*`): the v1.10 and v1.11 llm_request hashers, and the
# v1.12, v1.16 and v1.18 ones that carry it forward. Mirror of the Rust guard
# in meilynx-audit/src/sqlite.rs (`llm_schema_version_with_content`); a new
# llm_request bucket that hashes `content.*` is added here and there together,
# and self-test assertion 31e pins the v1.18 member. `check_llm_content` reads
# the same tuple, so a bucket that seals the digests is also one whose stored
# content is re-derived from them (assertions 35a-35c).
CONTENT_ATTESTATION_VERSIONS = ('v1.10', 'v1.11', 'v1.12', 'v1.16', 'v1.18')
# The members whose preimage presence-tags the content block: a record sealed
# with no capture policy carries none and stores its content unhashed.
CONTENT_PRESENCE_TAGGED_VERSIONS = ('v1.12', 'v1.16', 'v1.18')


def compute_event_hash_dispatch(
    schema_version,
    sequence_number, timestamp_utc, event_id, request_id,
    model_requested, action, input_tokens, output_tokens,
    total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
    event_kind=EVENT_KIND_LLM_REQUEST, auth_session=None, admin_action=None,
    mcp_event=None, coverage=None, join_context=None, content=None,
    identity=None, coverage_key_inventory=None, decision_receipt=None,
    evaluation_trace=None, customer=None,
):
    """Python mirror of compute_event_hash_dispatch in sqlite.rs.

    Backwards compatibility contract:
      - "v1" / "v1.1" → legacy compute_event_hash (15-field, frozen).
      - "v1.2" → compute_event_hash_v1_2_* based on event_kind.
      - Unknown → raise ValueError (forward-compat guard, matches Rust).
    """
    # Fail closed. The customer block enters only the
    # v1.18 preimage (both lanes); anywhere else it would ride the record
    # unhashed, and a v1.18 tag without it has no defined preimage. A block the
    # resolver never produces is refused at the same point.
    if customer is not None:
        if schema_version != 'v1.18' or not (
            event_kind == EVENT_KIND_LLM_REQUEST or event_kind in MCP_EVENT_KINDS
        ):
            raise ValueError(
                f"customer block present on a {schema_version!r} {event_kind!r} "
                f"event — it is hashed only in the v1.18 bucket on the LLM and MCP lanes."
            )
        problem = customer_shape_problem(customer)
        if problem is not None:
            raise ValueError(f"refusing a malformed customer block: {problem}")
    # Fail closed. The evaluation outcome digest is
    # hashed only by the v1.16 llm_request hasher (and the v1.18 bucket that
    # carries it forward, presence-tagged); anywhere else the trace would sit
    # on the record unhashed.
    if evaluation_trace is not None and (
        schema_version not in ('v1.16', 'v1.18') or event_kind != EVENT_KIND_LLM_REQUEST
    ):
        raise ValueError(
            f"evaluation_trace present on a {schema_version!r} "
            f"{event_kind!r} event — it is hashed only in the v1.16 and v1.18 llm_request buckets."
        )
    # The hashers read the sealed digest; a trace without one has
    # no defined preimage and is a failed record, not a crash.
    if evaluation_trace is not None and not (
        isinstance(evaluation_trace, dict) and isinstance(evaluation_trace.get('outcomes_sha256_jcs'), str)
    ):
        raise ValueError("evaluation_trace has no outcomes_sha256_jcs, so the record has no defined preimage.")
    # Fail closed. The receipt payload is hashed only by
    # the v1.15 decision.receipt hasher; anywhere else it would sit on the record
    # unhashed. A decider on a lapse (or none on a decision) is malformed.
    if decision_receipt is not None and (
        schema_version != 'v1.15' or event_kind != EVENT_KIND_DECISION_RECEIPT
    ):
        raise ValueError(
            f"decision_receipt payload present on a {schema_version!r} "
            f"{event_kind!r} event — it is hashed only in the v1.15 decision.receipt bucket."
        )
    if decision_receipt is not None and (
        (decision_receipt.get('outcome') == 'lapsed') != (decision_receipt.get('decider_user_id') is None)
    ):
        raise ValueError(
            "a decision receipt has a decider exactly when someone decided."
        )
    # Fail closed. The key-inventory payload is hashed
    # only by the v1.13 coverage.key_inventory hasher; anywhere else it would
    # sit on the record unhashed.
    if coverage_key_inventory is not None and (
        schema_version != 'v1.13' or event_kind != EVENT_KIND_COVERAGE_KEY_INVENTORY
    ):
        raise ValueError(
            f"coverage_key_inventory payload present on a {schema_version!r} "
            f"{event_kind!r} event — it is hashed only in the v1.13 "
            f"coverage.key_inventory bucket."
        )
    # Fail-closed invariant, mirror of the Rust dispatcher: a
    # caller-asserted join key may only ride the one bucket whose preimage
    # contains it. An event carrying join_context on an older schema_version
    # would be presenting an UNHASHED join key as evidence — rewritable after
    # the fact without breaking the chain.
    # The same rule for the content attestation: its digests are
    # hashed only in the v1.10 and v1.11 buckets, carried forward by v1.12,
    # v1.16 and v1.18 (the mirror of the Rust guard in sqlite.rs).
    if content is not None and schema_version not in CONTENT_ATTESTATION_VERSIONS:
        raise ValueError(
            f"content attestation present on a {schema_version!r} event — "
            f"content digests are hashed only in the "
            f"{', '.join(CONTENT_ATTESTATION_VERSIONS[:-1])} and {CONTENT_ATTESTATION_VERSIONS[-1]} buckets."
        )
    # The guard above is by version, and v1.18 (like v1.12) is
    # defined on both lanes; only the llm_request preimage reads `content.*`.
    # The MCP hashers never do and the writer never seals a content block on
    # an MCP record, so one there would ride the record unhashed: refuse it.
    # v1.12 MCP keeps its historical behaviour (admitted, its stored content
    # checked against the unhashed digests) so packs already issued verify as
    # they did; a sealing build stamps every MCP record v1.18.
    if content is not None and schema_version == 'v1.18' and event_kind != EVENT_KIND_LLM_REQUEST:
        raise ValueError(
            f"content attestation present on a {schema_version!r} {event_kind!r} event — "
            f"content digests are hashed only on the llm_request lane, so this content is unattested."
        )
    if content is not None and not (isinstance(content, dict) and isinstance(content.get('capture_policy'), str)):
        raise ValueError("content attestation has no capture_policy, so the record has no defined preimage.")
    # And the tool-call digests only in v1.11: the v1.10 hash does
    # not read them, so a v1.10 record carrying one would present it unhashed.
    if _has_tool_call_digests(content) and schema_version not in ('v1.11', 'v1.12', 'v1.16', 'v1.18'):
        raise ValueError(
            f"tool-call digests present on a {schema_version!r} event — "
            f"they are hashed only in the v1.11, v1.12, v1.16 and v1.18 buckets."
        )
    # Fail closed. The sealed identity enters only the
    # v1.12 preimage (both lanes); on any other version it would sit on the
    # record unhashed, rewritable without breaking the chain.
    if identity is not None and schema_version not in ('v1.12', 'v1.14', 'v1.16', 'v1.17', 'v1.18'):
        raise ValueError(
            f"identity block present on a {schema_version!r} event — "
            f"it is hashed only in the v1.12 bucket (and the MCP v1.14 and v1.17, "
            f"LLM v1.16 and both-lane v1.18 buckets that carry it forward)."
        )
    # The decision stage enters only the v1.14 preimage (and the
    # v1.17 and v1.18 ones that carry it forward).
    if mcp_event is not None and mcp_event.get('stage') is not None and schema_version not in ('v1.14', 'v1.17', 'v1.18'):
        raise ValueError(
            f"decision stage present on a {schema_version!r} event — "
            f"it is hashed only in the v1.14, v1.17 and v1.18 buckets."
        )
    # Fail closed. The data_reach block enters only the
    # v1.17 preimage (and v1.18, presence-tagged), and only a tool_call-stage
    # policy decision carries one; a block the classifier never produces is
    # refused at the same point.
    if mcp_event is not None and mcp_event.get('data_reach') is not None:
        if (schema_version not in ('v1.17', 'v1.18') or event_kind != EVENT_KIND_MCP_POLICY_DECISION
                or mcp_event.get('stage') != 'tool_call'):
            raise ValueError(
                f"data_reach present on a {schema_version!r} {event_kind!r} event at "
                f"stage {mcp_event.get('stage')!r} — it is sealed only on a tool_call-stage "
                f"mcp.policy_decision in the v1.17 and v1.18 buckets."
            )
        problem = data_reach_shape_problem(mcp_event['data_reach'])
        if problem is not None:
            raise ValueError(f"refusing a malformed data_reach block: {problem}")
    # The hashed delegated_human and the stored-not-hashed
    # attestation marker must agree.
    if identity is not None and mcp_event is not None:
        if (identity.get('delegated_human') is not None) != _on_behalf_of_is_verified(mcp_event):
            raise ValueError(
                "identity.delegated_human disagrees with the principal chain's "
                "on_behalf_of_attestation — the two must agree"
            )
    if join_context is not None and schema_version not in ('v1.9', 'v1.10', 'v1.11', 'v1.12', 'v1.14', 'v1.16', 'v1.17', 'v1.18'):
        raise ValueError(
            f"join_context present on a {schema_version!r} event — "
            f"caller-asserted join keys are hashed only in the v1.9, v1.10, v1.11, v1.12, "
            f"v1.14, v1.16, v1.17 and v1.18 buckets."
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
                    "AuthSessionStarted event missing auth_session payload"
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
                "AdminAction events require schema_version v1.3, got v1.2"
            )
        raise ValueError(f"unknown event_kind {event_kind!r}")
    if schema_version == 'v1.3':
        if event_kind != EVENT_KIND_ADMIN_ACTION:
            raise ValueError(
                f"schema_version v1.3 is defined only for admin.action "
                f"events; got event_kind {event_kind!r}"
            )
        if admin_action is None:
            raise ValueError(
                "AdminAction event missing admin_action payload"
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
                f"schema_version v1.4 is defined only for mcp.* "
                f"events; got event_kind {event_kind!r}"
            )
        if mcp_event is None:
            raise ValueError(
                f"{event_kind!r} event missing mcp_event payload"
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
        # v1.5 extends the MCP bucket with the principal chain. Same
        # mcp-only gate + payload-required posture as v1.4.
        if event_kind not in MCP_EVENT_KINDS:
            raise ValueError(
                f"schema_version v1.5 is defined only for mcp.* "
                f"events; got event_kind {event_kind!r}"
            )
        if mcp_event is None:
            raise ValueError(
                f"{event_kind!r} event missing mcp_event payload"
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
        # v1.6 extends the MCP bucket with the redacted-payload
        # content address (redacted capture, two-hash binding). Same mcp-only
        # gate + payload-required posture as v1.4/v1.5.
        if event_kind not in MCP_EVENT_KINDS:
            raise ValueError(
                f"schema_version v1.6 is defined only for mcp.* "
                f"events; got event_kind {event_kind!r}"
            )
        if mcp_event is None:
            raise ValueError(
                f"{event_kind!r} event missing mcp_event payload"
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
        # v1.7 extends the MCP bucket with the enforcement-axis
        # redaction pre/post hashes (redact enforcement). Same mcp-only gate +
        # payload-required posture as v1.4/v1.5/v1.6.
        if event_kind not in MCP_EVENT_KINDS:
            raise ValueError(
                f"schema_version v1.7 is defined only for mcp.* "
                f"events; got event_kind {event_kind!r}"
            )
        if mcp_event is None:
            raise ValueError(
                f"{event_kind!r} event missing mcp_event payload"
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
        # v1.8 introduces exactly one new event class:
        # coverage.computed. Same kind-only gate posture as v1.3.
        if event_kind != EVENT_KIND_COVERAGE_COMPUTED:
            raise ValueError(
                f"schema_version v1.8 is defined only for "
                f"coverage.computed events; got event_kind {event_kind!r}"
            )
        if coverage is None:
            raise ValueError(
                "CoverageComputed event missing coverage payload"
            )
        return compute_event_hash_v1_8_coverage(
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            coverage,
        )
    if schema_version == 'v1.13':
        # v1.13 introduces exactly one new event class:
        # coverage.key_inventory. Same kind-only gate posture as v1.8.
        if event_kind != EVENT_KIND_COVERAGE_KEY_INVENTORY:
            raise ValueError(
                f"schema_version v1.13 is defined only for "
                f"coverage.key_inventory events; got event_kind {event_kind!r}"
            )
        if coverage_key_inventory is None:
            raise ValueError(
                "CoverageKeyInventory event missing coverage_key_inventory payload"
            )
        return compute_event_hash_v1_13_coverage_key_inventory(
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            coverage_key_inventory,
        )
    if schema_version == 'v1.15':
        # v1.15 introduces exactly one new event class:
        # decision.receipt. Same kind-only gate posture as v1.8 and v1.13.
        if event_kind != EVENT_KIND_DECISION_RECEIPT:
            raise ValueError(
                f"schema_version v1.15 is defined only for "
                f"decision.receipt events; got event_kind {event_kind!r}"
            )
        if decision_receipt is None:
            raise ValueError("DecisionReceipt event missing decision_receipt payload")
        return compute_event_hash_v1_15_decision_receipt(
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            decision_receipt,
        )
    if schema_version == 'v1.9':
        # v1.9 is the first bucket that is NOT keyed to a new event
        # class: it is the existing llm_request / mcp.* preimages plus the
        # caller-asserted cross-lane join keys, selected by presence of
        # join_context. Uncorrelated traffic on both lanes stays in its
        # existing bucket and is byte-stable.
        if join_context is None:
            raise ValueError(
                "schema_version v1.9 requires a join_context payload; "
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
                    f"{event_kind!r} event missing mcp_event payload"
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
            f"schema_version v1.9 is defined only for llm_request "
            f"and mcp.* events; got event_kind {event_kind!r}"
        )
    if schema_version == 'v1.10':
        # llm_request sealed under a declared capture policy. The
        # join keys are optional here (presence-tagged either way).
        if content is None:
            raise ValueError(
                "schema_version v1.10 requires a content payload; an "
                "LLM event sealed with no capture policy must stay in its "
                "pre-v1.10 bucket."
            )
        if event_kind != EVENT_KIND_LLM_REQUEST:
            raise ValueError(
                f"schema_version v1.10 is defined only for llm_request "
                f"events; got event_kind {event_kind!r}"
            )
        return compute_event_hash_v1_10_llm_request(
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            join_context, content,
        )
    if schema_version == 'v1.11':
        # v1.10 plus the tool-call digests. The writer stamps v1.11
        # exactly when the captured tool-call digest is present, so a v1.11
        # record without it has no defined preimage.
        if content is None or content.get('tool_calls_sha256_jcs') is None:
            raise ValueError(
                "schema_version v1.11 requires a content payload carrying "
                "tool_calls_sha256_jcs; a record whose response made no tool call "
                "stays in its v1.10 bucket."
            )
        if event_kind != EVENT_KIND_LLM_REQUEST:
            raise ValueError(
                f"schema_version v1.11 is defined only for llm_request "
                f"events; got event_kind {event_kind!r}"
            )
        return compute_event_hash_v1_11_llm_request(
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            join_context, content,
        )
    if schema_version == 'v1.16':
        # The LLM-lane evaluation bucket: the v1.12 llm_request
        # preimage with identity presence-tagged, then the evaluation outcome
        # digest. Stamped exactly when the record carries a trace.
        if event_kind != EVENT_KIND_LLM_REQUEST:
            raise ValueError(
                f"schema_version v1.16 is defined only for llm_request "
                f"events; got event_kind {event_kind!r}"
            )
        if evaluation_trace is None:
            raise ValueError(
                "schema_version v1.16 requires an evaluation_trace; a "
                "record sealed without one must stay in its pre-v1.16 bucket."
            )
        return compute_event_hash_v1_16_llm_request(
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            join_context, content, identity, evaluation_trace,
        )
    if schema_version == 'v1.12':
        # The identity bucket on BOTH lanes: the llm_request
        # preimage (v1.11 layout, content presence-tagged) or the mcp.*
        # preimage (v1.9 layout, join presence-tagged), then the sealed
        # identity block. Stamped exactly when the record carries an identity.
        if identity is None:
            raise ValueError(
                "schema_version v1.12 requires an identity block; a "
                "record sealed without one must stay in its pre-v1.12 bucket."
            )
        if event_kind == EVENT_KIND_LLM_REQUEST:
            return compute_event_hash_v1_12_llm_request(
                sequence_number, timestamp_utc, event_id, request_id,
                model_requested, action, input_tokens, output_tokens,
                total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
                cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
                join_context, content, identity,
            )
        if event_kind in MCP_EVENT_KINDS:
            if mcp_event is None:
                raise ValueError(f"{event_kind!r} event missing mcp_event payload")
            return compute_event_hash_v1_12_mcp(
                event_kind,
                sequence_number, timestamp_utc, event_id, request_id,
                model_requested, action, input_tokens, output_tokens,
                total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
                cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
                mcp_event, join_context, identity,
            )
        raise ValueError(
            f"schema_version v1.12 is defined only for llm_request "
            f"and mcp.* events; got event_kind {event_kind!r}"
        )
    if schema_version == 'v1.14':
        # The MCP decision-stage bucket: the v1.12 mcp.* preimage
        # with the identity block presence-tagged, then the stage. Stamped
        # exactly when the record carries a stage, which only
        # mcp.policy_decision records do.
        if event_kind not in MCP_EVENT_KINDS:
            raise ValueError(
                f"schema_version v1.14 is defined only for mcp.* events; "
                f"got event_kind {event_kind!r}"
            )
        if mcp_event is None:
            raise ValueError(f"{event_kind!r} event missing mcp_event payload")
        if mcp_event.get('stage') is None:
            raise ValueError(
                "schema_version v1.14 requires a decision stage; a record "
                "sealed without one must stay in its pre-v1.14 bucket."
            )
        return compute_event_hash_v1_14_mcp(
            event_kind,
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            mcp_event, join_context, identity,
        )
    if schema_version == 'v1.17':
        # The MCP data-reach bucket: the v1.14 preimage, then the
        # data_reach block. Defined only for a tool_call-stage
        # mcp.policy_decision carrying one.
        if event_kind != EVENT_KIND_MCP_POLICY_DECISION:
            raise ValueError(
                f"schema_version v1.17 is defined only for mcp.policy_decision "
                f"events; got event_kind {event_kind!r}"
            )
        if mcp_event is None:
            raise ValueError("mcp.policy_decision event missing mcp_event payload")
        return compute_event_hash_v1_17_mcp(
            event_kind,
            sequence_number, timestamp_utc, event_id, request_id,
            model_requested, action, input_tokens, output_tokens,
            total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
            cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
            mcp_event, join_context, identity,
        )
    if schema_version == 'v1.18':
        # The customer-scope bucket on both lanes: the v1.16
        # llm_request preimage (trace presence-tagged) or the v1.14 mcp.*
        # preimage (data_reach presence-tagged), then the customer block.
        # Stamped exactly when the record carries a block.
        if customer is None:
            raise ValueError(
                "schema_version v1.18 requires a customer block; a record "
                "sealed without one must stay in its pre-v1.18 bucket."
            )
        if event_kind == EVENT_KIND_LLM_REQUEST:
            return compute_event_hash_v1_18_llm_request(
                sequence_number, timestamp_utc, event_id, request_id,
                model_requested, action, input_tokens, output_tokens,
                total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
                cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
                join_context, content, identity, evaluation_trace, customer,
            )
        if event_kind in MCP_EVENT_KINDS:
            if mcp_event is None:
                raise ValueError(f"{event_kind!r} event missing mcp_event payload")
            return compute_event_hash_v1_18_mcp(
                event_kind,
                sequence_number, timestamp_utc, event_id, request_id,
                model_requested, action, input_tokens, output_tokens,
                total_tokens, cache_creation_input_tokens, cache_read_input_tokens,
                cached_input_tokens, reasoning_tokens, estimated_cost_usd, previous_hash,
                mcp_event, join_context, identity, customer,
            )
        raise ValueError(
            f"schema_version v1.18 is defined only for llm_request and mcp.* "
            f"events; got event_kind {event_kind!r}"
        )
    raise ValueError(
        f"unknown schema_version {schema_version!r} — "
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
    # Uses the "dead beef" convention to be unambiguously non-production state.
    previous_hash="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
)


def run_self_test():
    """
    Two assertions covering Safeguard 1 (encoding correctness) and
    the Z-suffix normalization path:

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

    # Assertion 3 — dispatcher's v1 branch byte-identical.
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

    # Assertion 4 — v1 path ignores event_kind / auth_session.
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

    # Assertion 5 — Rust/Python agreement on v1.2 LlmRequest.
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

    # Assertion 6 — Rust/Python agreement on v1.2 AuthSessionStarted.
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

    # Assertion 7 — v1.3 admin.action fixture (direct fn), paired
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

    # Assertion 8 — the SAME v1.3 event, but recomputed through
    # recompute_event_hash (the production path verify_manifest walks) from a
    # synthetic exported-JSON body: event_kind in serde snake_case ('admin_action'),
    # Z-suffix timestamp, nested admin_action payload. This is the regression
    # that would have caught it — the record loop used to ignore all of it
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
        print('SELF-TEST assertion 8 FAIL: recompute_event_hash mis-hashes v1.3 admin.action', file=sys.stderr)
        print(f'  expected: {V1_3_ADMIN_ACTION_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v13_loop}', file=sys.stderr)
        ok = False

    # Assertion 9 — the same production-path check for v1.2 auth,
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
        print('SELF-TEST assertion 9 FAIL: recompute_event_hash mis-hashes v1.2 auth', file=sys.stderr)
        print(f'  expected: {V1_2_AUTH_SESSION_STARTED_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v12_loop}', file=sys.stderr)
        ok = False

    # Assertions 10a-10c — v1.4 mcp.* fixtures (direct fn), paired
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

    # Assertion 11 — the tool_call fixture recomputed through
    # recompute_event_hash (the production path verify_manifest walks) from a
    # synthetic exported-JSON body: event_kind in serde snake_case
    # ('mcp_tool_call'), Z-suffix timestamp, nested mcp_event payload — the
    # same regression class applied to the v1.4 bucket.
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

    # Assertions 12a-12d — v1.5 mcp.* fixtures (direct fn), paired with
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

    # Assertion 13 — the v1.5 tool_call fixture recomputed through
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

    # Assertion 14a — v1.6 redacted tool_call fixture via the direct
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

    # Assertion 14b — the same v1.6 fixture recomputed through the
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

    # Assertion 15a — v1.7 enforcement tool_call fixture via the direct
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

    # Assertion 15b — the same v1.7 fixture recomputed through the
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

    # Assertion 15c — v1.7 HOLD policy_decision fixture via the direct
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

    # Assertion 15d — the same v1.7 hold fixture recomputed through the
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

    # Assertion 16a — v1.8 coverage.computed fixture (direct fn),
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

    # Assertion 16b — the same v1.8 event recomputed through
    # recompute_event_hash (the production path verify_manifest walks) from a
    # synthetic exported-JSON body: event_kind in serde snake_case
    # ('coverage_computed'), Z-suffix timestamp, nested coverage payload — the
    # same regression class applied to the v1.8 bucket.
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

    # Assertion 16c — v1.13 coverage.key_inventory fixture (direct
    # fn), paired with the Rust mei2641_v1_13_key_inventory_fixture_hash_pinned
    # literal in meilynx-audit/tests/mei2641_key_inventory_chain_round_trip.rs.
    got_v113 = compute_event_hash_v1_13_coverage_key_inventory(
        sequence_number=7, timestamp_utc=ts_1760, event_id='evt-fixture',
        request_id='req-fixture', model_requested='', action='allow',
        input_tokens=0, output_tokens=0, total_tokens=None,
        cache_creation_input_tokens=None, cache_read_input_tokens=None,
        cached_input_tokens=None, reasoning_tokens=None,
        estimated_cost_usd=None, previous_hash='prev-fixture',
        inventory=_V1_13_KEY_INVENTORY_FIXTURE_PAYLOAD,
    )
    if got_v113 == V1_13_COVERAGE_KEY_INVENTORY_FIXTURE_HASH:
        print('SELF-TEST assertion 16c PASS: v1.13 coverage.key_inventory fixture hash matches')
    else:
        print('SELF-TEST assertion 16c FAIL: v1.13 coverage.key_inventory fixture drift', file=sys.stderr)
        print(f'  expected: {V1_13_COVERAGE_KEY_INVENTORY_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v113}', file=sys.stderr)
        ok = False

    # Assertion 16d — the same v1.13 event through recompute_event_hash
    # (the production path) from a synthetic exported-JSON body, then a payload
    # outside its bucket must be refused rather than hashed without it.
    synthetic_inventory_event = dict(
        schema_version='v1.13',
        event_kind='coverage_key_inventory',
        timestamp_utc=ts_1760.replace('+00:00', 'Z'),
        event_id='evt-fixture', request_id='req-fixture', model_requested='',
        action='allow', input_tokens=0, output_tokens=0,
        coverage_key_inventory=dict(_V1_13_KEY_INVENTORY_FIXTURE_PAYLOAD),
    )
    got_v113_loop = recompute_event_hash(synthetic_inventory_event, 7, 'prev-fixture')
    misplaced = dict(synthetic_inventory_event, schema_version='v1.8', event_kind='coverage_computed')
    try:
        recompute_event_hash(misplaced, 7, 'prev-fixture')
        misplaced_rejected = False
    except ValueError:
        misplaced_rejected = True
    if got_v113_loop == V1_13_COVERAGE_KEY_INVENTORY_FIXTURE_HASH and misplaced_rejected:
        print('SELF-TEST assertion 16d PASS: verify_manifest recompute path handles v1.13 coverage.key_inventory')
    else:
        print('SELF-TEST assertion 16d FAIL: recompute_event_hash mis-handles v1.13 coverage.key_inventory', file=sys.stderr)
        print(f'  expected: {V1_13_COVERAGE_KEY_INVENTORY_FIXTURE_HASH} (misplaced payload rejected)', file=sys.stderr)
        print(f'  got:      {got_v113_loop} (misplaced rejected: {misplaced_rejected})', file=sys.stderr)
        ok = False

    # Assertion 28a — v1.15 decision.receipt fixture (direct fn),
    # paired with the Rust mei2989_v1_15_decision_receipt_fixture_hash_pinned
    # literal and the control plane's pinned vector.
    got_v115 = compute_event_hash_v1_15_decision_receipt(
        sequence_number=9, timestamp_utc='2026-10-01T15:00:31.000000+00:00',
        event_id='evt-receipt-1', request_id='evt-receipt-1', model_requested='',
        action='allow', input_tokens=0, output_tokens=0, total_tokens=None,
        cache_creation_input_tokens=None, cache_read_input_tokens=None,
        cached_input_tokens=None, reasoning_tokens=None, estimated_cost_usd=None,
        previous_hash='b' * 64, receipt=_V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD,
    )
    if got_v115 == V1_15_DECISION_RECEIPT_FIXTURE_HASH:
        print('SELF-TEST assertion 28a PASS: v1.15 decision.receipt fixture hash matches')
    else:
        print('SELF-TEST assertion 28a FAIL: v1.15 decision.receipt fixture drift', file=sys.stderr)
        print(f'  expected: {V1_15_DECISION_RECEIPT_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v115}', file=sys.stderr)
        ok = False

    # Assertion 28b — the same record through recompute_event_hash (the
    # production path) from a synthetic exported-JSON body with a Z-suffix
    # timestamp, and the receipt checks pass on the intact record.
    synthetic_receipt_event = dict(
        schema_version='v1.15',
        event_kind='decision_receipt',
        timestamp_utc='2026-10-01T15:00:31.000000Z',
        event_id='evt-receipt-1', request_id='evt-receipt-1', model_requested='',
        action='allow', input_tokens=0, output_tokens=0,
        decision_receipt=dict(_V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD),
    )
    got_v115_loop = recompute_event_hash(synthetic_receipt_event, 9, 'b' * 64)
    receipt_problems = check_decision_receipt(synthetic_receipt_event)
    if got_v115_loop == V1_15_DECISION_RECEIPT_FIXTURE_HASH and not receipt_problems:
        print('SELF-TEST assertion 28b PASS: verify_manifest recompute path handles v1.15 decision.receipt')
    else:
        print('SELF-TEST assertion 28b FAIL: recompute_event_hash or check_decision_receipt mis-handles v1.15', file=sys.stderr)
        print(f'  got: {got_v115_loop} problems: {receipt_problems}', file=sys.stderr)
        ok = False

    # Assertion 28c — the stored-not-hashed evidence list and the
    # sealed clock verdict are checked: an edited evidence entry, a decision
    # time moved past the deadline with the verdict left at `within`, and a
    # decider removed from a decided receipt are all caught.
    edited_evidence = dict(synthetic_receipt_event, decision_receipt=dict(
        _V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD,
        evidence=[dict(_V1_15_DECISION_RECEIPT_FIXTURE_EVIDENCE[0], event_hash='2' * 64), _V1_15_DECISION_RECEIPT_FIXTURE_EVIDENCE[1]],
    ))
    moved_clock = dict(synthetic_receipt_event, decision_receipt=dict(
        _V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD, clock_decided_at=1791021601,
    ))
    no_decider = dict(synthetic_receipt_event, decision_receipt=dict(
        _V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD, decider_user_id=None,
    ))
    wrong_action = dict(synthetic_receipt_event, action='block')
    caught = [bool(check_decision_receipt(e)) for e in (edited_evidence, moved_clock, no_decider, wrong_action)]
    if all(caught):
        print('SELF-TEST assertion 28c PASS: edited evidence, a moved clock, a missing decider and a wrong action are caught')
    else:
        print(f'SELF-TEST assertion 28c FAIL: only {sum(caught)} of 4 receipt edits caught', file=sys.stderr)
        ok = False

    # Assertion 28d — the fail-closed invariants: a receipt payload on
    # any other version or kind, v1.15 on another kind, v1.15 without a payload,
    # and a decider on a lapse are all refused by the dispatcher.
    rejected = 0
    for case in (
        dict(synthetic_receipt_event, schema_version='v1.13'),
        dict(synthetic_receipt_event, event_kind='coverage_key_inventory'),
        dict(synthetic_receipt_event, event_kind='llm_request', decision_receipt=None),
        dict(synthetic_receipt_event, decision_receipt=None),
        dict(synthetic_receipt_event, decision_receipt=dict(_V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD, outcome='lapsed')),
    ):
        try:
            recompute_event_hash(case, 9, 'b' * 64)
        except ValueError:
            rejected += 1
    if rejected == 5:
        print('SELF-TEST assertion 28d PASS: a receipt outside v1.15, v1.15 without a receipt, and a malformed receipt are refused')
    else:
        print(f'SELF-TEST assertion 28d FAIL: only {rejected} of 5 fail-closed cases rejected', file=sys.stderr)
        ok = False

    # Assertion 29a — the v1.16 fixtures (direct fn): the outcome
    # digest over the JCS form, and the hash with and without an identity
    # (the identity presence tag is new in v1.16).
    fixture_trace = {'outcomes_sha256_jcs': V1_16_OUTCOMES_DIGEST_FIXTURE}
    got_digest = sha256_jcs(_V1_16_OUTCOMES_FIXTURE)
    got_ident = compute_event_hash_v1_16_llm_request(
        *_V1_16_FIXTURE_ARGS, None, None, _V1_16_IDENTITY_FIXTURE, fixture_trace,
    )
    got_bare = compute_event_hash_v1_16_llm_request(*_V1_16_FIXTURE_ARGS, None, None, None, fixture_trace)
    if (got_digest, got_ident, got_bare) == (
        V1_16_OUTCOMES_DIGEST_FIXTURE, V1_16_LLM_REQUEST_FIXTURE_HASH, V1_16_LLM_REQUEST_BARE_FIXTURE_HASH,
    ):
        print('SELF-TEST assertion 29a PASS: v1.16 outcome digest and llm_request fixture hashes match')
    else:
        print('SELF-TEST assertion 29a FAIL: v1.16 fixture drift', file=sys.stderr)
        print(f'  digest {got_digest}\n  ident  {got_ident}\n  bare   {got_bare}', file=sys.stderr)
        ok = False

    # Assertion 29b — the production recompute path on an exported
    # v1.16 record, and the outcome check passing on it. Timing rides the
    # record outside the hash: editing it changes neither verdict.
    v116_event = dict(
        schema_version='v1.16', event_kind='llm_request', timestamp_utc='2026-10-09T16:21:00Z',
        event_id='evt-v116-fixture', request_id='req-v116-fixture', model_requested='gpt-6-luna',
        action='block', input_tokens=452, output_tokens=70, total_tokens=522,
        identity=dict(_V1_16_IDENTITY_FIXTURE),
        evaluation_trace={
            'outcomes_sha256_jcs': V1_16_OUTCOMES_DIGEST_FIXTURE,
            'outcomes': json.loads(json.dumps(_V1_16_OUTCOMES_FIXTURE)),
            'timing': {'stages': [{'name': 'upstream', 'offset_us': 16400, 'duration_us': 2193000}], 'rules': [
                {'offset_us': 2210200, 'duration_us': 22000}]},
        },
    )
    retimed = json.loads(json.dumps(v116_event))
    retimed['evaluation_trace']['timing']['rules'][0]['duration_us'] = 1
    try:
        recomputed = [recompute_event_hash(e, 7, 'deadbeef' * 8) for e in (v116_event, retimed)]
    except ValueError as exc:
        recomputed = [str(exc)]
    if (recomputed == [V1_16_LLM_REQUEST_FIXTURE_HASH] * 2
            and not check_evaluation_trace(v116_event) and not check_evaluation_trace(retimed)):
        print('SELF-TEST assertion 29b PASS: verify_manifest recompute path handles v1.16; timing is outside the hash')
    else:
        print(f'SELF-TEST assertion 29b FAIL: recompute {recomputed}, problems {check_evaluation_trace(v116_event)}', file=sys.stderr)
        ok = False

    # Assertion 29c — an outcome edited after sealing still hashes
    # (the preimage holds only the digest) and is caught by the outcome check.
    edits = []
    for mutate in (
        lambda o: o['rules'][0].update(outcome='clean'),
        lambda o: o['rules'][0].update(action='allow'),
        lambda o: o.update(deciding_rule_id=None),
        lambda o: o['delivery'].update(outcome='delivered'),
        lambda o: o['rules'].append(dict(o['rules'][0], rule_id='extra')),
    ):
        edited = json.loads(json.dumps(v116_event))
        mutate(edited['evaluation_trace']['outcomes'])
        edits.append(
            recompute_event_hash(edited, 7, 'deadbeef' * 8) == V1_16_LLM_REQUEST_FIXTURE_HASH
            and bool(check_evaluation_trace(edited))
        )
    if all(edits):
        print('SELF-TEST assertion 29c PASS: five outcome edits after sealing are caught by the outcome check')
    else:
        print(f'SELF-TEST assertion 29c FAIL: only {sum(edits)} of 5 outcome edits caught', file=sys.stderr)
        ok = False

    # Assertion 29d — the fail-closed invariants: a trace on any other
    # version, v1.16 on another kind and v1.16 without a trace are refused by
    # the dispatcher, and the record check flags a trace outside v1.16.
    rejected = 0
    for case in (
        dict(v116_event, schema_version='v1.12'),
        dict(v116_event, event_kind='mcp_tool_call'),
        dict(v116_event, evaluation_trace=None),
    ):
        try:
            recompute_event_hash(case, 7, 'deadbeef' * 8)
        except ValueError:
            rejected += 1
    if rejected == 3 and check_evaluation_trace(dict(v116_event, schema_version='v1.12')):
        print('SELF-TEST assertion 29d PASS: a trace outside v1.16 and v1.16 without a trace are refused')
    else:
        print(f'SELF-TEST assertion 29d FAIL: only {rejected} of 3 fail-closed cases rejected', file=sys.stderr)
        ok = False

    # Assertion 17a — v1.9 llm_request fixture (direct fn), paired
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

    # Assertion 17b — the same v1.9 LLM event through the production
    # recompute path from a synthetic exported-JSON body.
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

    # Assertion 17c — v1.9 mcp.tool_call fixture (direct fn), paired
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

    # Assertion 17d — the same v1.9 MCP event through the production
    # recompute path from a synthetic exported-JSON body.
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

    # Assertion 24a — the asserted-claims digest: RFC 8785 over the
    # stored labels. Paired with the Rust mei2646_asserted_digest_pinned literal;
    # this is the cross-language pin the stored-not-hashed labels rest on.
    got_digest = asserted_claims_digest(_V1_12_ASSERTED_FIXTURE_PAYLOAD)
    if got_digest == V1_12_ASSERTED_DIGEST:
        print('SELF-TEST assertion 24a PASS: v1.12 asserted-claims digest matches')
    else:
        print('SELF-TEST assertion 24a FAIL: v1.12 asserted-claims digest drift', file=sys.stderr)
        print(f'  expected: {V1_12_ASSERTED_DIGEST}', file=sys.stderr)
        print(f'  got:      {got_digest}', file=sys.stderr)
        ok = False

    # Assertion 24b — v1.12 llm_request fixtures (direct fn): the T1
    # agent with join keys and a content block, and the bare T3 project-key
    # record (absent join, absent content: both presence tags pinned). Paired
    # with mei2646_v1_12_llm_request_fixture_hash_pinned.
    for label, join, content, identity, expected in (
        ('24b', _V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD, _V1_12_CONTENT_FIXTURE_PAYLOAD,
         _V1_12_IDENTITY_T1_FIXTURE_PAYLOAD, V1_12_LLM_REQUEST_FIXTURE_HASH),
        ('24c', None, None, _V1_12_IDENTITY_T3_FIXTURE_PAYLOAD, V1_12_LLM_REQUEST_BARE_FIXTURE_HASH),
    ):
        got = compute_event_hash_v1_12_llm_request(
            timestamp_utc="2026-05-17T00:00:00+00:00",
            join_context=join, content=content, identity=identity, **_FIXTURE,
        )
        if got == expected:
            print(f'SELF-TEST assertion {label} PASS: v1.12 llm_request fixture hash matches')
        else:
            print(f'SELF-TEST assertion {label} FAIL: v1.12 llm_request fixture drift', file=sys.stderr)
            print(f'  expected: {expected}', file=sys.stderr)
            print(f'  got:      {got}', file=sys.stderr)
            ok = False

    # Assertion 24d — v1.12 mcp.tool_call fixture (direct fn): a T2
    # identity whose verified delegated human agrees with the chain's
    # `verified` attestation marker. Paired with
    # mei2646_v1_12_mcp_tool_call_fixture_hash_pinned.
    got_v112_mcp = compute_event_hash_v1_12_mcp(
        EVENT_KIND_MCP_TOOL_CALL,
        mcp_event=_V1_12_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
        join_context=_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD,
        identity=_V1_12_IDENTITY_T2_FIXTURE_PAYLOAD,
        **mcp_fixture_args,
    )
    if got_v112_mcp == V1_12_MCP_TOOL_CALL_FIXTURE_HASH:
        print('SELF-TEST assertion 24d PASS: v1.12 mcp.tool_call fixture hash matches')
    else:
        print('SELF-TEST assertion 24d FAIL: v1.12 mcp.tool_call fixture drift', file=sys.stderr)
        print(f'  expected: {V1_12_MCP_TOOL_CALL_FIXTURE_HASH}', file=sys.stderr)
        print(f'  got:      {got_v112_mcp}', file=sys.stderr)
        ok = False

    # Assertion 24e — both v1.12 fixtures through the production
    # recompute path from synthetic exported-JSON bodies.
    synthetic_llm_v112_event = dict(
        schema_version='v1.12',
        event_kind='llm_request',
        timestamp_utc='2026-05-17T00:00:00Z',
        event_id=_FIXTURE['event_id'], request_id=_FIXTURE['request_id'],
        model_requested=_FIXTURE['model_requested'], action=_FIXTURE['action'],
        input_tokens=_FIXTURE['input_tokens'], output_tokens=_FIXTURE['output_tokens'],
        total_tokens=_FIXTURE['total_tokens'],
        estimated_cost_usd=_FIXTURE['estimated_cost_usd'],
        join_context=dict(_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD),
        content=dict(_V1_12_CONTENT_FIXTURE_PAYLOAD),
        identity=dict(_V1_12_IDENTITY_T1_FIXTURE_PAYLOAD),
    )
    synthetic_mcp_v112_event = dict(
        schema_version='v1.12',
        event_kind='mcp_tool_call',
        timestamp_utc=ts_1760.replace('+00:00', 'Z'),
        event_id='evt-mcp-fixture', request_id='req-mcp-fixture',
        model_requested='', action='allow', input_tokens=0, output_tokens=0,
        mcp_event=dict(_V1_12_MCP_TOOL_CALL_FIXTURE_PAYLOAD),
        join_context=dict(_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD),
        identity=dict(_V1_12_IDENTITY_T2_FIXTURE_PAYLOAD),
    )
    for label, ev, seq, prev, expected in (
        ('24e-llm', synthetic_llm_v112_event, _FIXTURE['sequence_number'], _FIXTURE['previous_hash'],
         V1_12_LLM_REQUEST_FIXTURE_HASH),
        ('24e-mcp', synthetic_mcp_v112_event, 11, 'prev-fixture', V1_12_MCP_TOOL_CALL_FIXTURE_HASH),
    ):
        got = recompute_event_hash(ev, seq, prev)
        if got == expected:
            print(f'SELF-TEST assertion {label} PASS: verify_manifest recompute path handles v1.12')
        else:
            print(f'SELF-TEST assertion {label} FAIL: recompute_event_hash mis-hashes v1.12', file=sys.stderr)
            print(f'  expected: {expected}', file=sys.stderr)
            print(f'  got:      {got}', file=sys.stderr)
            ok = False
        if check_sealed_identity(ev):
            print(f'SELF-TEST assertion {label} FAIL: check_sealed_identity rejected an intact record', file=sys.stderr)
            ok = False

    # Assertion 24f — the fail-closed invariants: an identity on any
    # bucket other than v1.12 is a hard error; v1.12 without an identity is a
    # hard error; a delegated_human over an asserted on-behalf-of leg is a hard
    # error. Mirror of the Rust dispatcher guards.
    for stale_version in ('v1', 'v1.1', 'v1.9', 'v1.10', 'v1.11'):
        try:
            compute_event_hash_dispatch(
                stale_version, timestamp_utc="2026-05-17T00:00:00+00:00",
                event_kind=EVENT_KIND_LLM_REQUEST,
                identity=_V1_12_IDENTITY_T1_FIXTURE_PAYLOAD, **_FIXTURE,
            )
        except ValueError as e:
            if 'identity block present' not in str(e):
                print(f'SELF-TEST assertion 24f FAIL: wrong rejection for identity on {stale_version}: {e}', file=sys.stderr)
                ok = False
        else:
            print(f'SELF-TEST assertion 24f FAIL: dispatcher accepted an identity on {stale_version}', file=sys.stderr)
            ok = False
    try:
        compute_event_hash_dispatch(
            'v1.12', timestamp_utc="2026-05-17T00:00:00+00:00",
            event_kind=EVENT_KIND_LLM_REQUEST, **_FIXTURE,
        )
        print('SELF-TEST assertion 24f FAIL: dispatcher accepted v1.12 without an identity', file=sys.stderr)
        ok = False
    except ValueError:
        pass
    disagreeing = dict(_V1_12_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
                       principal_chain=dict(_V1_12_MCP_TOOL_CALL_FIXTURE_PAYLOAD['principal_chain'],
                                            on_behalf_of_attestation='asserted'))
    try:
        compute_event_hash_dispatch(
            'v1.12', event_kind=EVENT_KIND_MCP_TOOL_CALL, mcp_event=disagreeing,
            identity=_V1_12_IDENTITY_T2_FIXTURE_PAYLOAD, **mcp_fixture_args,
        )
        print('SELF-TEST assertion 24f FAIL: dispatcher accepted a delegated_human over an asserted leg', file=sys.stderr)
        ok = False
    except ValueError:
        print('SELF-TEST assertion 24f PASS: identity outside v1.12, v1.12 without identity, and a disagreeing delegation are rejected')

    # Assertion 24g — a rewritten stored label behind an intact digest
    # is caught by check_sealed_identity (the chain hash alone cannot see it).
    relabelled = dict(synthetic_llm_v112_event,
                      identity=dict(_V1_12_IDENTITY_T1_FIXTURE_PAYLOAD,
                                    asserted=dict(_V1_12_ASSERTED_FIXTURE_PAYLOAD, agent_name='impostor-agent')))
    same_hash = recompute_event_hash(relabelled, _FIXTURE['sequence_number'], _FIXTURE['previous_hash']) == V1_12_LLM_REQUEST_FIXTURE_HASH
    if same_hash and check_sealed_identity(relabelled):
        print('SELF-TEST assertion 24g PASS: a rewritten asserted label is caught by the digest recomputation')
    else:
        print('SELF-TEST assertion 24g FAIL: a rewritten asserted label went unnoticed', file=sys.stderr)
        ok = False

    # Assertion 24h — the stored-content check runs on v1.12 as on
    # v1.10/v1.11: offline, a sealed v1.12 record carrying content verifies;
    # the same record with its prompt edited after sealing still hash-verifies
    # but fails; a v1.12 record with no content block is not content-checked.
    import tempfile
    v112_messages = [{'role': 'user', 'content': 'Summarize the Q3 variance memo.'}]
    v112_response = 'Revenue was 4% under plan, driven by delayed renewals.'
    v112_sealed = dict(
        schema_version='v1.12', event_kind='llm_request', sequence_number=0,
        timestamp_utc='2026-10-01T00:00:00Z', event_id='evt-0', request_id='req-0',
        model_requested='gpt-4.1-mini', action='allow', input_tokens=12, output_tokens=14,
        estimated_cost_usd=None, previous_hash=genesis_hash(),
        messages=v112_messages, response_text=v112_response, findings=[],
        content=dict(
            capture_policy='full',
            prompt_sha256_jcs=sha256_jcs(v112_messages),
            response_sha256=hashlib.sha256(v112_response.encode('utf-8')).hexdigest(),
            stored_prompt_sha256_jcs=sha256_jcs(v112_messages),
            stored_response_sha256=hashlib.sha256(v112_response.encode('utf-8')).hexdigest(),
            findings_sha256_jcs=sha256_jcs([]),
        ),
        identity=dict(_V1_12_IDENTITY_T3_FIXTURE_PAYLOAD),
    )
    v112_sealed['event_hash'] = recompute_event_hash(v112_sealed, 0, genesis_hash())
    v112_manifest = {'hash_version': 'v1', 'prefix': 'audit/self-test/',
                     'events': [{'sequence': 0, 'recomputed_event_hash': v112_sealed['event_hash']}]}
    with tempfile.TemporaryDirectory() as tmp:
        records = Path(tmp) / 'records'
        records.mkdir()
        path = records / record_file_name(0)
        path.write_bytes(json.dumps(v112_sealed).encode('utf-8'))
        intact_passes = verify_manifest_with(local_fetcher(records), v112_manifest, quiet=True)
        edited = json.loads(json.dumps(v112_sealed))
        edited['messages'][0]['content'] = 'Wire the Q3 bonus pool to account 4471.'
        path.write_bytes(json.dumps(edited).encode('utf-8'))
        edited_still_hashes = recompute_event_hash(edited, 0, genesis_hash()) == v112_sealed['event_hash']
        edited_detected = not verify_manifest_with(local_fetcher(records), v112_manifest, quiet=True)
    bare = dict(v112_sealed)
    del bare['content']
    if intact_passes and edited_still_hashes and edited_detected and not check_llm_content(bare):
        print('SELF-TEST assertion 24h PASS: a v1.12 prompt edited after sealing is detected by the content check')
    else:
        print('SELF-TEST assertion 24h FAIL: the v1.12 stored-content check is not applied as on v1.10/v1.11', file=sys.stderr)
        print(f'  intact passes: {intact_passes}, edited still hashes: {edited_still_hashes}, '
              f'edited detected: {edited_detected}, bare problems: {check_llm_content(bare)}', file=sys.stderr)
        ok = False

    # Assertion 27a — the v1.14 mcp.policy_decision fixtures (direct
    # fn): every earlier axis carried forward under a tool_result-stage allow,
    # and the bare shape (absent identity and join keys) of a call held at the
    # access stage with action "hold". Paired with
    # mei2898_v1_14_fixture_hashes_pinned.
    for label, payload, join, identity, action, expected in (
        ('27a', _V1_14_MCP_DECISION_FIXTURE_PAYLOAD, _V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD,
         _V1_12_IDENTITY_T2_FIXTURE_PAYLOAD, 'allow', V1_14_MCP_DECISION_FIXTURE_HASH),
        ('27a-hold', _V1_14_MCP_HOLD_FIXTURE_PAYLOAD, None, None, 'hold', V1_14_MCP_HOLD_FIXTURE_HASH),
    ):
        got = compute_event_hash_v1_14_mcp(
            EVENT_KIND_MCP_POLICY_DECISION, mcp_event=payload, join_context=join,
            identity=identity, **dict(mcp_fixture_args, action=action),
        )
        if got == expected:
            print(f'SELF-TEST assertion {label} PASS: v1.14 mcp.policy_decision fixture hash matches')
        else:
            print(f'SELF-TEST assertion {label} FAIL: v1.14 mcp.policy_decision fixture drift', file=sys.stderr)
            print(f'  expected: {expected}', file=sys.stderr)
            print(f'  got:      {got}', file=sys.stderr)
            ok = False

    # Assertion 27b — both fixtures through the production recompute
    # path from synthetic exported-JSON bodies, and the identity label check
    # on a v1.14 record (present: checked; absent: nothing to check).
    for label, payload, join, identity, action, expected in (
        ('27b', _V1_14_MCP_DECISION_FIXTURE_PAYLOAD, _V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD,
         _V1_12_IDENTITY_T2_FIXTURE_PAYLOAD, 'allow', V1_14_MCP_DECISION_FIXTURE_HASH),
        ('27b-hold', _V1_14_MCP_HOLD_FIXTURE_PAYLOAD, None, None, 'hold', V1_14_MCP_HOLD_FIXTURE_HASH),
    ):
        ev = dict(
            schema_version='v1.14', event_kind='mcp_policy_decision',
            timestamp_utc=ts_1760.replace('+00:00', 'Z'),
            event_id='evt-mcp-fixture', request_id='req-mcp-fixture',
            model_requested='', action=action, input_tokens=0, output_tokens=0,
            mcp_event=dict(payload),
        )
        if join is not None:
            ev['join_context'] = dict(join)
        if identity is not None:
            ev['identity'] = dict(identity)
        got = recompute_event_hash(ev, 11, 'prev-fixture')
        if got == expected and not check_sealed_identity(ev):
            print(f'SELF-TEST assertion {label} PASS: verify_manifest recompute path handles v1.14')
        else:
            print(f'SELF-TEST assertion {label} FAIL: recompute_event_hash mis-hashes v1.14 '
                  f'or the identity check rejected an intact record', file=sys.stderr)
            print(f'  expected: {expected}', file=sys.stderr)
            print(f'  got:      {got}', file=sys.stderr)
            ok = False

    # Assertion 27c — the stage is attested: each stage, and its
    # absence, gives a different hash; and the action is attested too, so a
    # hold rewritten to block (or the reverse) breaks the chain.
    seen = set()
    for stage in MCP_DECISION_STAGES:
        seen.add(compute_event_hash_v1_14_mcp(
            EVENT_KIND_MCP_POLICY_DECISION, mcp_event=dict(_V1_14_MCP_HOLD_FIXTURE_PAYLOAD, stage=stage),
            join_context=None, identity=None, **dict(mcp_fixture_args, action='hold'),
        ))
    seen.add(compute_event_hash_v1_14_mcp(
        EVENT_KIND_MCP_POLICY_DECISION, mcp_event=dict(_V1_14_MCP_HOLD_FIXTURE_PAYLOAD, stage=None),
        join_context=None, identity=None, **dict(mcp_fixture_args, action='hold'),
    ))
    as_block = compute_event_hash_v1_14_mcp(
        EVENT_KIND_MCP_POLICY_DECISION, mcp_event=_V1_14_MCP_HOLD_FIXTURE_PAYLOAD,
        join_context=None, identity=None, **dict(mcp_fixture_args, action='block'),
    )
    if len(seen) == len(MCP_DECISION_STAGES) + 1 and as_block != V1_14_MCP_HOLD_FIXTURE_HASH:
        print('SELF-TEST assertion 27c PASS: every stage and the hold action are attested')
    else:
        print('SELF-TEST assertion 27c FAIL: two stages (or hold and block) hash the same', file=sys.stderr)
        ok = False

    # Assertion 27d — the fail-closed invariants: a stage on any other
    # bucket is a hard error, v1.14 without a stage is a hard error, and v1.14
    # is defined only for mcp.* events.
    rejected = 0
    for version in ('v1.5', 'v1.7', 'v1.9', 'v1.12'):
        try:
            compute_event_hash_dispatch(
                version, event_kind=EVENT_KIND_MCP_POLICY_DECISION,
                mcp_event=_V1_14_MCP_HOLD_FIXTURE_PAYLOAD, **mcp_fixture_args,
            )
        except ValueError as e:
            rejected += 'decision stage' in str(e) or 'schema_version v1.14' in str(e)
    for kwargs in (
        dict(event_kind=EVENT_KIND_MCP_POLICY_DECISION,
             mcp_event=dict(_V1_14_MCP_HOLD_FIXTURE_PAYLOAD, stage=None)),
        dict(event_kind=EVENT_KIND_LLM_REQUEST),
    ):
        try:
            compute_event_hash_dispatch('v1.14', **kwargs, **mcp_fixture_args)
        except ValueError as e:
            rejected += 'decision stage' in str(e) or 'schema_version v1.14' in str(e)
    if rejected == 6:
        print('SELF-TEST assertion 27d PASS: a stage outside v1.14, v1.14 without a stage, '
              'and v1.14 on a non-MCP kind are rejected')
    else:
        print(f'SELF-TEST assertion 27d FAIL: only {rejected} of 6 fail-closed cases rejected', file=sys.stderr)
        ok = False

    # Assertion 30a — the v1.17 data-reach fixtures (direct fn).
    # Paired with mei2987_v1_17_fixture_hashes_pinned and the control plane's
    # DataReach_Matched_And_NoMatch_MatchPinnedV117Fixtures.
    for label, payload, join, identity, action, expected in (
        ('30a', _V1_17_MCP_MATCHED_FIXTURE_PAYLOAD, _V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD,
         _V1_12_IDENTITY_T2_FIXTURE_PAYLOAD, 'allow', V1_17_MCP_MATCHED_FIXTURE_HASH),
        ('30a-no-match', _V1_17_MCP_NO_MATCH_FIXTURE_PAYLOAD, None, None, 'block', V1_17_MCP_NO_MATCH_FIXTURE_HASH),
    ):
        got = compute_event_hash_v1_17_mcp(
            EVENT_KIND_MCP_POLICY_DECISION, mcp_event=payload, join_context=join,
            identity=identity, **dict(mcp_fixture_args, action=action),
        )
        if got == expected:
            print(f'SELF-TEST assertion {label} PASS: v1.17 data-reach fixture hash matches')
        else:
            print(f'SELF-TEST assertion {label} FAIL: v1.17 data-reach fixture drift', file=sys.stderr)
            print(f'  expected: {expected}', file=sys.stderr)
            print(f'  got:      {got}', file=sys.stderr)
            ok = False

    # Assertion 30b — both fixtures through the production recompute
    # path from synthetic exported-JSON bodies.
    for label, payload, join, identity, action, expected in (
        ('30b', _V1_17_MCP_MATCHED_FIXTURE_PAYLOAD, _V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD,
         _V1_12_IDENTITY_T2_FIXTURE_PAYLOAD, 'allow', V1_17_MCP_MATCHED_FIXTURE_HASH),
        ('30b-no-match', _V1_17_MCP_NO_MATCH_FIXTURE_PAYLOAD, None, None, 'block', V1_17_MCP_NO_MATCH_FIXTURE_HASH),
    ):
        ev = dict(
            schema_version='v1.17', event_kind='mcp_policy_decision',
            timestamp_utc=ts_1760.replace('+00:00', 'Z'),
            event_id='evt-mcp-fixture', request_id='req-mcp-fixture',
            model_requested='', action=action, input_tokens=0, output_tokens=0,
            mcp_event=json.loads(json.dumps(payload)),
        )
        if join is not None:
            ev['join_context'] = dict(join)
        if identity is not None:
            ev['identity'] = dict(identity)
        got = recompute_event_hash(ev, 11, 'prev-fixture')
        if got == expected and not check_sealed_identity(ev):
            print(f'SELF-TEST assertion {label} PASS: verify_manifest recompute path handles v1.17')
        else:
            print(f'SELF-TEST assertion {label} FAIL: recompute_event_hash mis-hashes v1.17', file=sys.stderr)
            print(f'  expected: {expected}', file=sys.stderr)
            print(f'  got:      {got}', file=sys.stderr)
            ok = False

    # Assertion 30c — every member of the block is attested: a
    # tampered binding, access, outcome, schema flag, name, name order, name
    # count or omitted count each changes the hash, and two names never hash
    # like their concatenation (the length prefix).
    base = _V1_17_MCP_MATCHED_FIXTURE_PAYLOAD['data_reach']
    tampered = (
        dict(base, binding_id='rb_0000000000000000'), dict(base, access='write'), dict(base, access=None),
        dict(base, outcome='no_match'), dict(base, outcome='error'), dict(base, schema_known=False),
        dict(base, arg_keys=['account_id', 'fields']), dict(base, arg_keys=['account_id', 'fields', 'region']),
        dict(base, arg_keys=['account_idfields', 'r\u00e9gion']),
        dict(base, arg_keys_omitted=0), dict(base, arg_keys_omitted=2),
    )
    seen = {V1_17_MCP_MATCHED_FIXTURE_HASH}
    for block in tampered:
        seen.add(compute_event_hash_v1_17_mcp(
            EVENT_KIND_MCP_POLICY_DECISION, mcp_event=dict(_V1_17_MCP_MATCHED_FIXTURE_PAYLOAD, data_reach=block),
            join_context=_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD, identity=_V1_12_IDENTITY_T2_FIXTURE_PAYLOAD,
            **dict(mcp_fixture_args, action='allow'),
        ))
    if len(seen) == len(tampered) + 1:
        print('SELF-TEST assertion 30c PASS: every member of the data_reach block is attested')
    else:
        print('SELF-TEST assertion 30c FAIL: two different data_reach blocks hash the same', file=sys.stderr)
        ok = False

    # Assertion 30d — the fail-closed invariants: the block on any
    # other bucket, v1.17 on another kind or stage or without a block, and a
    # block the classifier never produces are all hard errors.
    no_match = _V1_17_MCP_NO_MATCH_FIXTURE_PAYLOAD
    cases = [
        (version, dict(event_kind=EVENT_KIND_MCP_POLICY_DECISION, mcp_event=no_match))
        for version in ('v1.5', 'v1.7', 'v1.12', 'v1.14')
    ] + [
        ('v1.17', dict(event_kind=kind, mcp_event=no_match))
        for kind in (EVENT_KIND_MCP_TOOL_CALL, EVENT_KIND_MCP_TOOL_RESULT, EVENT_KIND_MCP_ERROR, EVENT_KIND_LLM_REQUEST)
    ] + [
        ('v1.17', dict(event_kind=EVENT_KIND_MCP_POLICY_DECISION, mcp_event=dict(no_match, stage=stage)))
        for stage in MCP_DECISION_STAGES if stage != 'tool_call'
    ] + [
        ('v1.17', dict(event_kind=EVENT_KIND_MCP_POLICY_DECISION, mcp_event=dict(no_match, data_reach=None))),
    ] + [
        ('v1.17', dict(event_kind=EVENT_KIND_MCP_POLICY_DECISION, mcp_event=dict(no_match, data_reach=block)))
        for block in (
            dict(no_match['data_reach'], binding_id='rb_5c1d0e3a7b9f2468'),
            dict(base, binding_id='unbound'), dict(base, binding_id='rb_123-45-6789'),
            dict(base, access=None), dict(no_match['data_reach'], access='read'),
            dict(base, access='admin'), dict(base, outcome='maybe'),
            dict(base, arg_keys=[f'k{i:02d}' for i in range(33)]),
            dict(base, arg_keys=['a' * 65]), dict(base, arg_keys=['']),
            dict(base, arg_keys=['fields', 'account_id']), dict(base, arg_keys=['fields', 'fields']),
            dict(base, arg_keys_omitted=-1),
        )
    ]
    rejected = 0
    for version, kwargs in cases:
        try:
            compute_event_hash_dispatch(version, **kwargs, **mcp_fixture_args)
        except ValueError as e:
            rejected += any(s in str(e) for s in ('data_reach present', 'compute_event_hash_v1_17_mcp',
                                                  'malformed data_reach block', 'decision stage', 'schema_version v1.14'))
    if rejected == len(cases):
        print(f'SELF-TEST assertion 30d PASS: all {len(cases)} misplaced, incomplete or malformed '
              'data_reach shapes are rejected')
    else:
        print(f'SELF-TEST assertion 30d FAIL: only {rejected} of {len(cases)} fail-closed cases rejected', file=sys.stderr)
        ok = False

    # Assertion 31a — the v1.18 fixtures on both lanes (direct fns).
    # Paired with mei3097_customer_scope_chain_round_trip.rs and the control
    # plane's hasher tests; a disagreement here is the drift the examiner
    # would otherwise find first.
    fixture_trace = {'outcomes_sha256_jcs': V1_16_OUTCOMES_DIGEST_FIXTURE}
    got_cred = compute_event_hash_v1_18_llm_request(
        *_V1_16_FIXTURE_ARGS, None, None, _V1_16_IDENTITY_FIXTURE, fixture_trace, _V1_18_CUSTOMER_CREDENTIAL_FIXTURE,
    )
    got_asserted = compute_event_hash_v1_18_llm_request(
        *_V1_16_FIXTURE_ARGS, None, None, _V1_16_IDENTITY_FIXTURE, fixture_trace, _V1_18_CUSTOMER_ASSERTED_FIXTURE,
    )
    got_bare = compute_event_hash_v1_18_llm_request(
        *_V1_16_FIXTURE_ARGS, None, None, None, None, _V1_18_CUSTOMER_NONE_FIXTURE,
    )
    got_mcp_matched = compute_event_hash_v1_18_mcp(
        EVENT_KIND_MCP_POLICY_DECISION, 7, '2026-10-10T12:00:01+00:00', 'evt-reach-matched', 'req-reach-7', '',
        'allow', 0, 0, None, None, None, None, None, None, 'deadbeef' * 8,
        _V1_17_MCP_MATCHED_FIXTURE_PAYLOAD, _V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD, _V1_12_IDENTITY_T2_FIXTURE_PAYLOAD,
        _V1_18_MCP_CUSTOMER_CREDENTIAL_FIXTURE,
    )
    got_mcp_tool_call = compute_event_hash_v1_18_mcp(
        EVENT_KIND_MCP_TOOL_CALL, 7, '2026-10-10T12:00:01+00:00', 'evt-tool-call', 'req-tool-7', '',
        'allow', 0, 0, None, None, None, None, None, None, 'deadbeef' * 8,
        _V1_5_MCP_TOOL_CALL_FIXTURE_PAYLOAD, None, None, _V1_18_CUSTOMER_NONE_FIXTURE,
    )
    expected = [V1_18_LLM_CREDENTIAL_FIXTURE_HASH, V1_18_LLM_ASSERTED_FIXTURE_HASH, V1_18_LLM_BARE_FIXTURE_HASH,
                V1_18_MCP_MATCHED_CREDENTIAL_FIXTURE_HASH, V1_18_MCP_TOOL_CALL_NONE_FIXTURE_HASH]
    got = [got_cred, got_asserted, got_bare, got_mcp_matched, got_mcp_tool_call]
    if (got == expected and customer_label_sha256('bank-a') == V1_18_CUSTOMER_LABEL_FIXTURE_DIGEST
            and len(set(got)) == 5):
        print('SELF-TEST assertion 31a PASS: v1.18 fixture hashes match on both lanes')
    else:
        print(f'SELF-TEST assertion 31a FAIL: v1.18 fixture drift: {got} != {expected}', file=sys.stderr)
        ok = False

    # Assertion 31b — the production recompute path (recompute_event_hash
    # over an exported record) selects the v1.18 arms, and the record check
    # catches a rewritten asserted label behind an unchanged digest.
    v118_llm = dict(
        schema_version='v1.18', event_id='evt-v116-fixture', request_id='req-v116-fixture',
        timestamp_utc='2026-10-09T16:21:00Z', model_requested='gpt-6-luna', action='block',
        input_tokens=452, output_tokens=70, total_tokens=522,
        identity=dict(_V1_16_IDENTITY_FIXTURE, asserted={}),
        evaluation_trace={'outcomes_sha256_jcs': V1_16_OUTCOMES_DIGEST_FIXTURE,
                          'outcomes': json.loads(json.dumps(_V1_16_OUTCOMES_FIXTURE))},
        customer=dict(_V1_18_CUSTOMER_ASSERTED_FIXTURE), customer_id='bank-b',
    )
    v118_mcp = dict(
        schema_version='v1.18', event_kind='mcp_tool_call', event_id='evt-tool-call', request_id='req-tool-7',
        timestamp_utc='2026-10-10T12:00:01Z', model_requested='', action='allow', input_tokens=0, output_tokens=0,
        mcp_event=dict(_V1_5_MCP_TOOL_CALL_FIXTURE_PAYLOAD), customer=dict(_V1_18_CUSTOMER_NONE_FIXTURE),
    )
    recomputed = [recompute_event_hash(v118_llm, 7, 'deadbeef' * 8), recompute_event_hash(v118_mcp, 7, 'deadbeef' * 8)]
    rewritten = dict(v118_llm, customer_id='bank-c')
    v118_llm['identity']['asserted_digest'] = asserted_claims_digest({})
    if (recomputed == [V1_18_LLM_ASSERTED_FIXTURE_HASH, V1_18_MCP_TOOL_CALL_NONE_FIXTURE_HASH]
            and check_customer_scope(v118_llm) == [] and check_customer_scope(v118_mcp) == []
            and len(check_customer_scope(rewritten)) == 1
            and check_evaluation_trace(dict(v118_mcp, event_kind=None, schema_version='v1.18',
                                            customer=dict(_V1_18_CUSTOMER_NONE_FIXTURE))) == []):
        print('SELF-TEST assertion 31b PASS: verify_manifest recompute path handles v1.18; a rewritten asserted label is caught')
    else:
        print(f'SELF-TEST assertion 31b FAIL: recompute {recomputed}, problems {check_customer_scope(rewritten)}', file=sys.stderr)
        ok = False

    # Assertion 31c — every member of the customer block is attested:
    # changing the digest, the source or the kid moves the hash.
    variants = [
        dict(_V1_18_CUSTOMER_CREDENTIAL_FIXTURE, label_sha256='b' * 64),
        dict(_V1_18_CUSTOMER_CREDENTIAL_FIXTURE, credential_kid='other-kid'),
        {'label_sha256': V1_18_CUSTOMER_LABEL_FIXTURE_DIGEST, 'source': 'asserted'},
    ]
    seen = {V1_18_LLM_CREDENTIAL_FIXTURE_HASH}
    for block in variants:
        seen.add(compute_event_hash_v1_18_llm_request(
            *_V1_16_FIXTURE_ARGS, None, None, _V1_16_IDENTITY_FIXTURE, fixture_trace, block,
        ))
    if len(seen) == 1 + len(variants):
        print('SELF-TEST assertion 31c PASS: every member of the customer block is attested')
    else:
        print('SELF-TEST assertion 31c FAIL: two different customer blocks hash the same', file=sys.stderr)
        ok = False

    # Assertion 31d — fail closed: a customer block on another bucket,
    # v1.18 without a block, v1.18 on a non-lane kind, and malformed blocks.
    cases = [
        ('v1.16', dict(event_kind=EVENT_KIND_LLM_REQUEST, identity=_V1_16_IDENTITY_FIXTURE,
                       evaluation_trace=fixture_trace, customer=_V1_18_CUSTOMER_NONE_FIXTURE)),
        ('v1.17', dict(event_kind=EVENT_KIND_MCP_POLICY_DECISION, mcp_event=_V1_17_MCP_MATCHED_FIXTURE_PAYLOAD,
                       customer=_V1_18_CUSTOMER_NONE_FIXTURE)),
        ('v1.18', dict(event_kind=EVENT_KIND_LLM_REQUEST)),
        ('v1.18', dict(event_kind=EVENT_KIND_ADMIN_ACTION, customer=_V1_18_CUSTOMER_NONE_FIXTURE)),
        ('v1.18', dict(event_kind=EVENT_KIND_LLM_REQUEST, customer={'source': 'none', 'label_sha256': 'a' * 64})),
        ('v1.18', dict(event_kind=EVENT_KIND_LLM_REQUEST, customer={'source': 'asserted'})),
        ('v1.18', dict(event_kind=EVENT_KIND_LLM_REQUEST, customer={'source': 'credential', 'label_sha256': 'a' * 64})),
        ('v1.18', dict(event_kind=EVENT_KIND_LLM_REQUEST, customer={'source': 'credential', 'label_sha256': 'A' * 64, 'credential_kid': 'k'})),
        ('v1.18', dict(event_kind=EVENT_KIND_LLM_REQUEST, customer={'source': 'tenant', 'label_sha256': 'a' * 64})),
        ('v1.18', dict(event_kind=EVENT_KIND_MCP_TOOL_CALL, mcp_event=_V1_17_MCP_MATCHED_FIXTURE_PAYLOAD,
                       customer=_V1_18_CUSTOMER_NONE_FIXTURE)),
    ]
    rejected = 0
    for version, kwargs in cases:
        try:
            compute_event_hash_dispatch(version, 7, '2026-10-10T12:00:01+00:00', 'e', 'r', '', 'allow',
                                        0, 0, None, None, None, None, None, None, 'deadbeef' * 8, **kwargs)
        except ValueError as e:
            rejected += any(s in str(e) for s in ('customer block', 'schema_version v1.18', 'data_reach present',
                                                  'compute_event_hash_v1_17_mcp', 'malformed data_reach block'))
    if rejected == len(cases):
        print(f'SELF-TEST assertion 31d PASS: all {len(cases)} misplaced, incomplete or malformed customer shapes are rejected')
    else:
        print(f'SELF-TEST assertion 31d FAIL: only {rejected} of {len(cases)} fail-closed cases rejected', file=sys.stderr)
        ok = False

    # Assertion 31e — a v1.18 llm_request carries its content
    # attestation (the v1.18 preimage hashes content.*), so the fail-closed
    # guard must admit it; a bucket that does not hash it still refuses.
    try:
        compute_event_hash_dispatch('v1.18', 7, '2026-10-10T12:00:01+00:00', 'e', 'r', 'gpt-4.1-mini', 'allow',
                                    0, 0, None, None, None, None, None, None, 'deadbeef' * 8,
                                    event_kind=EVENT_KIND_LLM_REQUEST, identity=_V1_16_IDENTITY_FIXTURE,
                                    evaluation_trace=fixture_trace, customer=_V1_18_CUSTOMER_NONE_FIXTURE,
                                    content=dict(_V1_12_CONTENT_FIXTURE_PAYLOAD))
        admitted = True
    except ValueError as e:
        admitted = False
        print(f'SELF-TEST assertion 31e FAIL: a v1.18 llm_request with a content attestation was refused: {e}', file=sys.stderr)
    refused = 0
    for version in ('v1.9', 'v1.14', 'v1.17'):
        try:
            compute_event_hash_dispatch(version, 7, '2026-10-10T12:00:01+00:00', 'e', 'r', 'gpt-4.1-mini', 'allow',
                                        0, 0, None, None, None, None, None, None, 'deadbeef' * 8,
                                        event_kind=EVENT_KIND_LLM_REQUEST, content=dict(_V1_12_CONTENT_FIXTURE_PAYLOAD))
        except ValueError as e:
            refused += 'content attestation present' in str(e)
    if admitted and refused == 3:
        print('SELF-TEST assertion 31e PASS: a v1.18 llm_request keeps its content attestation; v1.9, v1.14 and v1.17 refuse one')
    else:
        if admitted:
            print(f'SELF-TEST assertion 31e FAIL: only {refused} of 3 buckets without content.* in their preimage refused a content attestation', file=sys.stderr)
        ok = False

    # Assertion 17e — the fail-closed invariant: a join_context on any
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


# v1.2 fixture hashes. Pinned in BOTH this Python file and
# the Rust drift_catchers.rs (and verify-pack.py in meilynx-platform).
# If you change the v1.2 encoding, update all three. The
# legacy v1 FIXTURE_HASH above stays at ba7a7f3d… (the v1 path is
# frozen; no encoding change can ever bump it).
V1_2_LLM_REQUEST_FIXTURE_HASH = "5f85e27ee519003176c2acb8dd287a9c9dfdd1ba0cc41ec3c92e1c56c9869456"
V1_2_AUTH_SESSION_STARTED_FIXTURE_HASH = "1f3d58eaaf32e85fa96105e66a71943de4ce865d64d896ef1f4afde25aeea7af"
# v1.3 admin.action fixture. Paired with
# meilynx-audit/tests/mei1048_admin_chain_round_trip.rs::mei1048_v1_3_admin_action_fixture_hash_pinned;
# neither side may drift independently.
V1_3_ADMIN_ACTION_FIXTURE_HASH = "eb3899be87ed811f84b5616289f0b3dde43344359ca5d772bcb6637d02fb11ea"
# v1.4 mcp.* fixtures. Paired with
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
# v1.5 mcp.* fixtures. Paired with
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
# v1.6 mcp.* fixture. Paired with
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
# v1.7 mcp.* enforcement (redact) fixture. Paired with
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
# v1.7 mcp.* HOLD fixture. Paired with
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
# v1.8 coverage.computed fixture. Paired with
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
# v1.15 decision.receipt fixture. Paired with
# meilynx-audit/tests/mei2989_decision_receipt_chain_round_trip.rs::mei2989_v1_15_decision_receipt_fixture_hash_pinned
# and the control plane's Mei2989DecisionReceiptSealingTests.PinnedVectorHash;
# no side may drift independently.
# v1.16 llm_request fixtures. Paired with the same
# constants in meilynx-audit (`evaluation_trace.rs` for the outcome digest,
# `tests/mei3037_evaluation_trace_chain_round_trip.rs` for the hashes);
# neither side may drift independently.
_V1_16_OUTCOMES_FIXTURE = {
    'v': 1,
    'rules': [{
        'rule_id': 'payment-risk-policy', 'rule_name': 'Payment risk policy',
        'stage': 'post_response', 'validator_kind': 'webhook',
        'outcome': 'matched', 'action': 'block',
    }],
    'deciding_rule_id': 'payment-risk-policy',
    'delivery': {'mode': 'non_streaming', 'outcome': 'withheld'},
}
V1_16_OUTCOMES_DIGEST_FIXTURE = "7feba313b876be8fb7cb1efcd2bc6fea4a2650aaed592946047471d3dd9cba38"
_V1_16_IDENTITY_FIXTURE = {
    'agent_id': 'agt_fixture', 'tier': 't1', 'credential_kind': 'agent_key',
    'credential_kid': 'kid-fixture', 'delegated_human': None, 'asserted_digest': 'a' * 64,
}
_V1_16_FIXTURE_ARGS = (
    7, '2026-10-09T16:21:00+00:00', 'evt-v116-fixture', 'req-v116-fixture',
    'gpt-6-luna', 'block', 452, 70, 522, None, None, None, None, None, 'deadbeef' * 8,
)
V1_16_LLM_REQUEST_FIXTURE_HASH = "985cec7081f7c4efab7a745fba9f3aa73e68ea1f9b3f42dc8a51cc38359173cc"
V1_16_LLM_REQUEST_BARE_FIXTURE_HASH = "254d2401a772b260d64d6fd843b17f0c0147b3306f57af6a35d25ae3c4115bef"

V1_15_DECISION_RECEIPT_FIXTURE_HASH = "4e93ecd462a3acd7a0a73e1fe98317a35fe0da3c1876e8389d4b63c668450682"
_V1_15_DECISION_RECEIPT_FIXTURE_EVIDENCE = [
    {"chain_id": "chain-1", "content_digests": {"payload_sha256_jcs": "c" * 64}, "event_hash": "1" * 64,
     "event_id": "evt-toolcall-1", "role": "ai_contribution", "sequence_number": 6},
    {"chain_id": "chain-1", "content_digests": {}, "event_hash": "a" * 64,
     "event_id": "evt-decision-1", "role": "hold", "sequence_number": 7},
]
_V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD = dict(
    receipt_id='0f0e0d0c-0b0a-4908-8706-050403020100',
    receipt_type='finra-communication-review',
    receipt_type_version='1',
    registry_digest='5' * 64,
    source_kind='mcp_hold',
    source_ref='hold-' + '7' * 32,
    subject_ref_sha256=None,
    evidence_set_sha256=hashlib.sha256(json.dumps(
        _V1_15_DECISION_RECEIPT_FIXTURE_EVIDENCE, separators=(',', ':'), sort_keys=True, ensure_ascii=False,
    ).encode('utf-8')).hexdigest(),
    policy_version='d' * 64,
    outcome='approved',
    outcome_reason_code=None,
    outcome_reason_sha256=None,
    decider_user_id='11111111-2222-4333-8444-555555555555',
    decider_role='compliance-officer',
    decider_identity_provenance=None,
    credential_status='not_verified',
    credential_class='registered_principal',
    credential_registry=None,
    credential_verified_at=None,
    procedure_status='not_recorded',
    procedure_id=None,
    procedure_version=None,
    procedure_document_sha256=None,
    procedure_effective_at=None,
    clock_rule='finra-3110-review-window@P2D',
    clock_start_basis='sealed_record',
    clock_started_at=1790848800,   # 2026-10-01T10:00:00Z
    clock_deadline_at=1791021600,  # 2026-10-03T10:00:00Z
    clock_decided_at=1790866800,   # 2026-10-01T15:00:00Z
    clock_elapsed_seconds=18000,
    clock_status='within',
    held_before_use=True,
    supersedes_receipt_id=None,
    cp_anchor_event_id='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
    cp_anchor_event_hash='e' * 64,
    issued_at=1790866801,          # 2026-10-01T15:00:01Z
    evidence=_V1_15_DECISION_RECEIPT_FIXTURE_EVIDENCE,
)
# The lapsed half of the cross-language fixture: the
# approved fixture with no decision. Paired with
# mei2989_decision_receipt_chain_round_trip.rs::mei2989_v1_15_lapsed_receipt_fixture_hash_pinned
# and the control plane's Mei2989DecisionReceiptSealingTests; none may drift
# independently.
V1_15_LAPSED_RECEIPT_FIXTURE_HASH = "95439e39ec1b44781952e9a62b56b5acf042f17a774d073cee7e67b9a516090f"
_V1_15_LAPSED_RECEIPT_FIXTURE_PAYLOAD = dict(
    _V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD,
    receipt_id='1f1e1d1c-1b1a-4918-8716-151413121110',
    outcome='lapsed',
    decider_user_id=None,
    decider_role=None,
    clock_decided_at=None,
    clock_elapsed_seconds=None,
    clock_status='lapsed',
    cp_anchor_event_id='bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
    cp_anchor_event_hash='f' * 64,
    issued_at=1791021660,          # 2026-10-03T10:01:00Z, a minute past the deadline
)
# v1.13 coverage.key_inventory fixture. Paired with
# meilynx-audit/tests/mei2641_key_inventory_chain_round_trip.rs::mei2641_v1_13_key_inventory_fixture_hash_pinned;
# neither side may drift independently.
V1_13_COVERAGE_KEY_INVENTORY_FIXTURE_HASH = "92b5fcefc0b1269fd79c3665243219b81ee712372e10d6d0d322a77266bae2b6"
_V1_13_KEY_INVENTORY_FIXTURE_PAYLOAD = dict(
    provider='openai',
    day='2026-09-30',
    attribution_unit='requests',
    claim_language_key='coverage.tier_a.org_administered_accounts',
    registry_version='2026.10.01-1',
    proxy_key_count=1,
    unresolved_proxy_key_count=0,
    governed_key_count=1,
    ungoverned_key_count=1,
    listing_fetched_at='2026-10-01T01:00:00Z',
    keys_json=(
        '[{"key_id":"key_gov","key_suffix":"abcd","key_name":"proxy-routing",'
        '"external_scope_id":"proj_1","owner_type":"service_account","owner_id":"svc_1",'
        '"key_created_at":"2026-09-01T00:00:00Z","key_last_used_at":null,"listed":true,'
        '"governed":true,"requests":40,"input_tokens":4000,"output_tokens":900},'
        '{"key_id":"key_shadow","key_suffix":"wxyz","key_name":"laptop",'
        '"external_scope_id":"proj_1","owner_type":"user","owner_id":"user_9",'
        '"key_created_at":"2026-09-20T00:00:00Z","key_last_used_at":null,"listed":true,'
        '"governed":false,"requests":12,"input_tokens":1200,"output_tokens":300}]'
    ),
)
# v1.9 fixtures: the caller-asserted cross-lane join keys appended
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

# v1.10 llm_request fixtures. Paired with
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

# Content-digest fixtures. Paired with
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

# v1.11 llm_request fixtures. Paired with
# meilynx-audit/tests/mei2456_tool_calls_chain_round_trip.rs; neither side may
# drift independently. The first pin carries both tool-call digests; the join
# pin carries a hash_only-shaped payload (stored digests absent) so the
# presence tag of a missing stored tool-call digest is covered too.
_V1_11_CONTENT_FIXTURE_PAYLOAD = dict(
    _V1_10_CONTENT_FIXTURE_PAYLOAD,
    tool_calls_sha256_jcs='6' * 64,
    stored_tool_calls_sha256_jcs='7' * 64,
)
_V1_11_HASH_ONLY_CONTENT_FIXTURE_PAYLOAD = dict(
    capture_policy='hash_only',
    prompt_sha256_jcs='1' * 64,
    response_sha256=None,
    findings_sha256_jcs='5' * 64,
    tool_calls_sha256_jcs='6' * 64,
)
V1_11_LLM_REQUEST_FIXTURE_HASH = "afd2d6fa30b6de48b227afdec6291e889919af46dc382d96476bd8ebaa2fc2d8"
V1_11_LLM_REQUEST_JOIN_HASH_ONLY_FIXTURE_HASH = "20da367bc79f4e9f1bfdb4203885b8ce5378c6ad9da33e1536935265f4a3bbfa"

# v1.12 fixtures (both lanes). Paired with
# meilynx-audit/tests/mei2646_identity_chain_round_trip.rs; neither side may
# drift independently. The asserted labels are a fully populated object so the
# RFC 8785 canonicalisation of every field is what the digest pins.
_V1_12_ASSERTED_FIXTURE_PAYLOAD = dict(
    agent_name='billing-bot',
    client_info=dict(name='claude-code', version='2.1.0'),
    user_agent_family=dict(family='openai-python', major=1),
    on_behalf_of='user-alice',
)
V1_12_ASSERTED_DIGEST = "a252c2c4569f366ffe2b3bb10a2d5f1802112351238ae747da108a5b303bd4cf"
_V1_12_IDENTITY_T1_FIXTURE_PAYLOAD = dict(
    agent_id='agt_01J9ZK3Q7R8S9T0V1W2X3Y4Z5A',
    tier='t1',
    credential_kind='agent_key',
    credential_kid='a7f3k2m9p4q8r1s6',
    asserted_digest=V1_12_ASSERTED_DIGEST,
    asserted=_V1_12_ASSERTED_FIXTURE_PAYLOAD,
)
_V1_12_IDENTITY_T2_FIXTURE_PAYLOAD = dict(
    _V1_12_IDENTITY_T1_FIXTURE_PAYLOAD,
    tier='t2',
    delegated_human=dict(subject='user-alice', issuer='https://idp.example'),
)
_V1_12_IDENTITY_T3_FIXTURE_PAYLOAD = dict(
    tier='t3',
    credential_kind='project_key',
    credential_kid='pk:0123456789abcdef',
    asserted_digest=V1_12_ASSERTED_DIGEST,
    asserted=_V1_12_ASSERTED_FIXTURE_PAYLOAD,
)
_V1_12_CONTENT_FIXTURE_PAYLOAD = dict(
    capture_policy='hash_only',
    prompt_sha256_jcs='1' * 64,
    response_sha256='2' * 64,
    findings_sha256_jcs='3' * 64,
    tool_calls_sha256_jcs='4' * 64,
)
_V1_12_MCP_TOOL_CALL_FIXTURE_PAYLOAD = dict(
    virtual_server='crm',
    upstream_slug='crm',
    method='tools/call',
    tool_name='crm__lookup_account',
    jsonrpc_id='42',
    protocol_version='2026-07-28',
    payload_sha256_jcs='9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    mcp_bundle_sha256='a' * 64,
    traceparent='00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
    principal_chain=dict(
        authenticated=dict(kind='agent', agent_ref='agt_01J9ZK3Q7R8S9T0V1W2X3Y4Z5A'),
        on_behalf_of=dict(kind='human_user', subject='user-alice', issuer='https://idp.example'),
        on_behalf_of_attestation='verified',
    ),
    redacted_payload_sha256_jcs='b' * 64,
    redaction_pre_sha256_jcs='c' * 64,
    redaction_post_sha256_jcs='d' * 64,
)
V1_12_LLM_REQUEST_FIXTURE_HASH = "62826a249c726dd87608fa0c05db6387b045b9583e76fa5631fcf902456bc235"
V1_12_LLM_REQUEST_BARE_FIXTURE_HASH = "99ab7d921ff414be33abe689efb6671b13b32a274c868c72b4868461c2f29e96"
V1_12_MCP_TOOL_CALL_FIXTURE_HASH = "c2f71dbf0ff7e00ac709c6b5a4f44222edf2d1ef29324252f6961f8cc6311780"

# v1.14 mcp.policy_decision fixtures. Paired with
# meilynx-audit/tests/mei2898_decision_stage_chain_round_trip.rs and the
# control plane's McpEvidenceChainHasherTests. The first carries every axis
# forward (redaction, join, a T2 identity) under a tool_result-stage allow; the
# second is the bare shape (no identity, no join keys: both presence tags
# absent) of a call held at the access stage, sealed with action "hold".
_V1_14_MCP_DECISION_FIXTURE_PAYLOAD = dict(
    _V1_12_MCP_TOOL_CALL_FIXTURE_PAYLOAD,
    decision='allow',
    reason='allow',
    correlated_event_id='evt-mcp-result',
    stage='tool_result',
)
_V1_14_MCP_HOLD_FIXTURE_PAYLOAD = dict(
    virtual_server='crm',
    upstream_slug='crm',
    method='tools/call',
    tool_name='crm__send_client_email',
    jsonrpc_id='43',
    protocol_version='2026-07-28',
    decision='require_approval',
    reason='rbac_require_approval_hold:rule-42',
    correlated_event_id='evt-mcp-call',
    mcp_bundle_sha256='a' * 64,
    traceparent='00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
    principal_chain=dict(
        authenticated=dict(kind='agent', agent_ref='agt_01J9ZK3Q7R8S9T0V1W2X3Y4Z5A'),
    ),
    hold_id='hold-0123456789abcdef',
    stage='access',
)
V1_14_MCP_DECISION_FIXTURE_HASH = "d36fa042cb3e49ada8f7b1807e10251a1a7dd64b9e40317990e38e9aaa3476e6"
V1_14_MCP_HOLD_FIXTURE_HASH = "b0a1b82c017b9385df9e8e056fc42d23e3e86ff220d947828d5b34c0353e94f2"

# v1.17 data-reach fixtures. Paired with
# meilynx-audit/tests/mei2987_data_reach_chain_round_trip.rs and the control
# plane's McpEvidenceChainHasherTests. The first is the v1.14 decision fixture
# as a tool_call-stage allow that matched a declared read binding (every
# earlier axis carried forward, one non-ASCII name so the length prefix is
# pinned in UTF-8 bytes); the second is the bare shape of a call the merged
# reach rule refused because no binding matched, with no advertised schema.
_V1_17_MCP_MATCHED_FIXTURE_PAYLOAD = dict(
    _V1_14_MCP_DECISION_FIXTURE_PAYLOAD,
    correlated_event_id='evt-mcp-call',
    stage='tool_call',
    data_reach=dict(
        binding_id='rb_5c1d0e3a7b9f2468', access='read', outcome='matched', schema_known=True,
        arg_keys=['account_id', 'fields', 'r\u00e9gion'], arg_keys_omitted=1,
    ),
)
_V1_17_MCP_NO_MATCH_FIXTURE_PAYLOAD = dict(
    _V1_14_MCP_HOLD_FIXTURE_PAYLOAD,
    tool_name='crm__lookup_account',
    decision='block',
    reason='blocked_by_rule:agt_01J9ZK3Q7R8S9T0V1W2X3Y4Z5A.reach.crm__lookup_account',
    hold_id=None,
    stage='tool_call',
    data_reach=dict(
        binding_id='unbound', access=None, outcome='no_match', schema_known=False,
        arg_keys=[], arg_keys_omitted=3,
    ),
)
V1_17_MCP_MATCHED_FIXTURE_HASH = "ef39155a691caddfc9e43e16526688b75d1ebf303c0aab019cfebad455c6cdfb"
V1_17_MCP_NO_MATCH_FIXTURE_HASH = "e4f901d2b831615de9c6ef666f63c1240c4815a5407f8951135a85b55480c91d"
# v1.18 fixtures on both lanes. Paired with
# meilynx-audit/tests/mei3097_customer_scope_chain_round_trip.rs and the
# control plane's McpEvidenceChainHasherTests (v1.18); no side may drift
# independently. `bank-a`'s digest is the known answer every side pins.
V1_18_CUSTOMER_LABEL_FIXTURE_DIGEST = "c21eb9bf8ae659a9e14fe4ee47dfeb9e2c56af8d865ad3e3edf26107919c2e59"
_V1_18_CUSTOMER_CREDENTIAL_FIXTURE = {
    'label_sha256': V1_18_CUSTOMER_LABEL_FIXTURE_DIGEST, 'source': 'credential', 'credential_kid': 'kid-fixture',
}
_V1_18_CUSTOMER_ASSERTED_FIXTURE = {
    'label_sha256': "077e4916f96423e22060e2a7445e6eace3dd4e7319bc0edb5957770185f95a4a", 'source': 'asserted',
}
_V1_18_CUSTOMER_NONE_FIXTURE = {'source': 'none'}
# LLM lane: the v1.16 evaluated request, credential-bound (the identity's kid
# carries the label); the same request asserted-only; a refusal sealed before
# evaluation (no identity, no trace) with no label.
V1_18_LLM_CREDENTIAL_FIXTURE_HASH = "2b80c5920d2eb52f890cab191a866b402fa2827bef69bed9d5960873735fa396"
V1_18_LLM_ASSERTED_FIXTURE_HASH = "6dd5a049c7a2297e009996c4701d4d419fb37d2768771c43c9977ad2cc80c2c4"
V1_18_LLM_BARE_FIXTURE_HASH = "7a362892cf3a8690454411162f92fe217658445c03ea0774d17e33d3104c3509"
# MCP lane: the v1.17 matched decision (T2 identity, join keys, data_reach)
# credential-bound; a bare v1.5-shaped tool_call record (no identity, no
# stage, no reach) with no label.
_V1_18_MCP_CUSTOMER_CREDENTIAL_FIXTURE = {
    'label_sha256': V1_18_CUSTOMER_LABEL_FIXTURE_DIGEST, 'source': 'credential', 'credential_kid': 'a7f3k2m9p4q8r1s6',
}
V1_18_MCP_MATCHED_CREDENTIAL_FIXTURE_HASH = "1545ab0c02e19d6651d9ba2d4c9041c4482903fb7f7a41ebd590b7c93c700194"
V1_18_MCP_TOOL_CALL_NONE_FIXTURE_HASH = "a19ca9ced54f811a0c2f0b84e86e3d7541272e28f12b12f5d5c0aafb9ad113e6"

# Tool-call digest fixture. Paired with
# meilynx-proxy/src/audit_capture.rs::tool_call_digests_are_pinned_for_the_verifier:
# the record's `tool_calls` exactly as the proxy serializes them, and the
# digests the proxy seals over them (as captured, and under `redacted`, where
# every `input` is null). The input exercises the JCS cases a naive dump gets
# wrong: 1.0 -> 1, 1e21 -> 1e+21, an integer past 2**53 (rendered through a
# double), -0.0 -> 0, 1e-7, key order by UTF-16 code unit across non-ASCII and
# astral keys, and non-ASCII / control characters in strings.
V1_11_DIGEST_FIXTURE_TOOL_CALLS_JSON = (
    '[{"id":"toolu_01","name":"Read","input":{"file_path":"/work/café/naïve ☕.py",'
    '"ratio":1.0,"big":1e21,"huge":12345678901234567890,"neg_zero":-0.0,"tiny":1e-7,'
    '"n":[0.1,100,2.5e-8],"keys":{"é":1,"e":2,"\U0001F600":3,"｡":4},'
    '"ctrl":"line\\nbreak\\t\\u0001"}},'
    '{"id":"srvtoolu_02","name":"web_search","input":{"query":"東京 weather"}}]'
)
V1_11_DIGEST_FIXTURE_TOOL_CALLS = "656300fbe1f68f78edee99a3c826fbb4fbdd14793e5b9f07eda08bc3f83b5476"
V1_11_DIGEST_FIXTURE_TOOL_CALLS_REDACTED = "29257c956f8d4585d7fbe2d7bafe2d83dd65852ff44e88e2a3327f3b6100174b"

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
    GovernanceAction serializes as its snake_case string ("allow", "warn",
    "redact", "mask_output", "hold", "block") and is hashed verbatim.
    "hold" is a held MCP call waiting on approval; records sealed
    before it carry "block" for a held call, with mcp_event.decision
    "require_approval" and an rbac_require_approval_hold reason.
    """
    a = event.get('action', 'Allow')
    if isinstance(a, str):
        return a
    mapping = {0: 'Allow', 1: 'Warn', 2: 'Redact', 3: 'MaskOutput', 4: 'Block'}
    return mapping.get(a, 'Allow')


def recompute_event_hash(event, seq, previous_hash):
    """Recompute one event's hash from its exported WORM JSON,
    dispatching on schema_version + event_kind exactly as the Rust writer /
    verifier does (compute_event_hash_dispatch in sqlite.rs).

    THIS is the production recompute path verify_manifest walks. Before
    the fix the record loop called the frozen v1 `compute_event_hash`
    unconditionally, so every v1.2 auth.session_started and v1.3 admin.action
    event in a real pack failed verification even though the chain was intact
    — the reproducer's own self-test exercised the dispatch functions but not
    this loop (the test never traversed the production path).
    run_self_test now drives THIS helper with synthetic v1.2/v1.3 events.
    """
    ts = normalize_timestamp(event.get('timestamp_utc', ''))
    schema_version = event.get('schema_version') or 'v1'
    serde_kind = event.get('event_kind')  # None → default LlmRequest (field omitted)
    if serde_kind not in SERDE_EVENT_KIND_TO_WIRE:
        raise ValueError(
            f"unknown event_kind {serde_kind!r} in exported event — "
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
        identity=event.get('identity'),
        coverage_key_inventory=event.get('coverage_key_inventory'),
        decision_receipt=event.get('decision_receipt'),
        evaluation_trace=event.get('evaluation_trace'),
        customer=event.get('customer'),
    )


def record_file_name(seq):
    """Object / file name of one chain record: `<seq:020d>.bin`, the same
    layout the WORM bucket uses under the chain prefix. An offline records
    directory mirrors that layout so a bucket listing can be copied 1:1."""
    return f"{seq:020d}.bin"


# ---------------------------------------------------------------------------
# Record objects: per-record and segment layouts
#
# A managed proxy's run chain may store its records as segment objects, each
# holding a contiguous range of records: `{first:020}-{last:020}.seg`, whose
# body is every record's bytes (exactly what a `{seq:020}.bin` object holds)
# followed by one line feed, in sequence order. Every reader parses an object
# name under the chain prefix into a range through one parser, so a chain
# that mixes both layouts reads without special handling (D6).
#
# Verdicts when two objects hold the same sequence (D7): byte-identical
# copies are a WARN `segment_overlap`, not a failure; differing copies are a
# `segment_fork` FAIL. A hole between ranges fails through the chain linkage
# (the record after it does not link to the record before it), and a chain
# whose ranges stop early verifies on the records present: that shortfall is
# a completeness verdict, not an integrity one.
# ---------------------------------------------------------------------------

SEGMENT_MAX_RECORDS = 1024
STORAGE_LAYOUTS = ("per-record", "segmented-v1")
_RECORD_OBJECT_NAME = re.compile(r"(\d{20})\.bin")
_SEGMENT_OBJECT_NAME = re.compile(r"(\d{20})-(\d{20})\.seg")
_SEGMENT_CACHE_SIZE = 8


def record_object_range(name):
    """The inclusive range [first, last] of sequences the object
    `name` (relative to the chain prefix) holds, or None when it is not a
    record object. `{n:020}.bin` holds [n, n]; `{a:020}-{b:020}.seg` holds
    [a, b] when a <= b and it holds at most SEGMENT_MAX_RECORDS records."""
    m = _RECORD_OBJECT_NAME.fullmatch(name)
    if m:
        n = int(m.group(1))
        return n, n
    m = _SEGMENT_OBJECT_NAME.fullmatch(name)
    if m:
        first, last = int(m.group(1)), int(m.group(2))
        if first <= last and last - first + 1 <= SEGMENT_MAX_RECORDS:
            return first, last
    return None


def split_segment(body, first, last):
    """The records a segment body holds, in sequence order, each
    byte-identical to the `{seq:020}.bin` object it replaces. Compact JSON
    escapes line feeds inside strings, so splitting on 0x0A is exact. Raises
    ValueError unless the body holds exactly last - first + 1 records, each
    followed by one line feed."""
    expected = last - first + 1
    if not body.endswith(b"\n"):
        raise ValueError("its body does not end with a line feed")
    records = body[:-1].split(b"\n")
    if len(records) != expected:
        raise ValueError(f"its body holds {len(records)} record(s), its name says {expected}")
    return records


class RecordNotFound(FileNotFoundError):
    """No record object holds the sequence."""


class SegmentFork(ValueError):
    """Two objects hold different bytes for one sequence."""


class ChainRecords:
    """The record objects under one chain prefix, in either layout, and
    `self(seq) -> bytes` over them: the fetch function the chain walk, the
    anchor check and --export-records read through.

    `list_names(lo, hi)` returns the names (relative to the chain prefix)
    among which every object holding a sequence in [lo, hi] is found; extra
    names are ignored. `read(name)` returns one object's bytes. `report`
    prints the overlap WARN, once per sequence."""

    def __init__(self, list_names, read, report=print):
        self._list_names = list_names
        self._read = read
        self._report = report
        self._holders = {}  # seq -> [object name, ...]
        self._indexed = set()
        self._listed = []  # [(lo, hi)] windows already listed
        self._expected = []  # [(lo, hi)] windows to list in one pass when first read
        self._failed = []  # [(lo, hi, error)] windows whose listing failed
        self._segments = {}  # name -> [record bytes] | ValueError, most recent last
        self._warned = set()

    def expect(self, lo, hi):
        """List [lo, hi] in one pass the first time a sequence in it is read,
        rather than one listing per sequence."""
        self._expected.append((lo, hi))

    def list_window(self, lo, hi):
        """Index every record object that can hold a sequence in [lo, hi]."""
        try:
            names = self._list_names(lo, hi)
        except Exception as exc:  # Propagate loud — every record in the window then fails its fetch
            self._failed.append((lo, hi, exc))
            raise OSError(f"cannot list the chain's record objects: {exc}") from exc
        for name in names:
            if name in self._indexed:
                continue
            span = record_object_range(name)
            if span is None:
                if _SEGMENT_OBJECT_NAME.fullmatch(name):
                    self._report(f"NOTICE: {name} is not a record object: a segment holds from 1 to "
                                 f"{SEGMENT_MAX_RECORDS} records, first <= last")
                self._indexed.add(name)
                continue
            self._indexed.add(name)
            for seq in range(span[0], span[1] + 1):
                self._holders.setdefault(seq, []).append(name)
        self._listed.append((lo, hi))

    def holders(self, seq):
        """The names of every object holding `seq`, in name order."""
        if not any(lo <= seq <= hi for lo, hi in self._listed):
            for lo, hi, exc in self._failed:
                if lo <= seq <= hi:
                    raise OSError(f"cannot list the chain's record objects: {exc}")
            window = next((w for w in self._expected if w[0] <= seq <= w[1]), (seq, seq))
            if window in self._expected:
                self._expected.remove(window)
            self.list_window(*window)
        return sorted(self._holders.get(seq, ()))

    def _record(self, name, seq):
        first, last = record_object_range(name)
        if first == last and name.endswith(".bin"):
            return self._read(name)
        records = self._segments.pop(name, None)
        if records is None:
            try:
                records = split_segment(self._read(name), first, last)
            except ValueError as exc:
                records = exc
        self._segments[name] = records
        while len(self._segments) > _SEGMENT_CACHE_SIZE:
            del self._segments[next(iter(self._segments))]
        if isinstance(records, ValueError):
            raise ValueError(f"segment {name} is malformed: {records}") from records
        return records[seq - first]

    def __call__(self, seq):
        names = self.holders(seq)
        if not names:
            raise RecordNotFound(f"no record object holds seq={seq}")
        raw = self._record(names[0], seq)
        for name in names[1:]:
            if self._record(name, seq) != raw:
                raise SegmentFork(f"segment_fork: {names[0]} and {name} hold different bytes for seq={seq}")
        if len(names) > 1 and seq not in self._warned:
            self._warned.add(seq)
            self._report(f"WARN seq={seq}: segment_overlap: {' and '.join(names)} each hold this record, "
                         f"byte-identical")
        return raw


def gcs_fetcher(bucket_name, prefix, storage_client, report=print):
    """Return a ChainRecords over `<prefix>` in GCS (CMEK decrypts
    transparently for a principal with storage.objects.get and .list).

    Each listing is bounded by name: the objects that can hold a sequence in
    [lo, hi] start at most SEGMENT_MAX_RECORDS - 1 below lo and at most at hi,
    and zero padding keeps name order equal to sequence order."""
    bucket = storage_client.bucket(bucket_name)

    def list_names(lo, hi):
        blobs = storage_client.list_blobs(
            bucket_name,
            prefix=prefix,
            start_offset=f"{prefix}{max(0, lo - (SEGMENT_MAX_RECORDS - 1)):020d}",
            end_offset=f"{prefix}{hi + 1:020d}",
        )
        return [b.name[len(prefix):] for b in blobs]

    def read(name):
        return bucket.blob(f"{prefix}{name}").download_as_bytes()

    return ChainRecords(list_names, read, report)


def local_fetcher(records_path, report=print):
    """Return `fetch(seq) -> bytes` that reads chain records from disk, with
    no network and no Google client library — the path an examiner or a
    third-party reviewer runs when they were handed the records alongside
    the manifest.

    `records_path` is either:
      - a directory holding the chain's record objects as the bucket stores
        them, `<seq:020d>.bin` and `<first:020d>-<last:020d>.seg` in any mix,
        or files named `<seq:020d>.json`; or
      - a single `.jsonl` file (one record per line) / `.json` file (an
        array of records), each record carrying its own `sequence_number`.
    """
    path = Path(records_path)
    if path.is_dir():
        objects = ChainRecords(
            lambda lo, hi: sorted(p.name for p in path.iterdir() if p.is_file()),
            lambda name: (path / name).read_bytes(),
            report,
        )
        # One directory listing holds every sequence.
        objects.list_window(0, float("inf"))

        def fetch(seq):
            try:
                return objects(seq)
            except RecordNotFound:
                candidate = path / f"{seq:020d}.json"
                if candidate.exists():
                    return candidate.read_bytes()
                raise RecordNotFound(f"no record file for seq={seq} under {path}")

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


def timestamp_recording_fetcher(fetch, times):
    """Wrap `fetch` so the time of every record it returns is kept in
    `times` (seq -> epoch seconds), for the anchor clock check."""

    def fetch_and_record(seq):
        raw = fetch(seq)
        try:
            times[seq] = _epoch_of_record(json.loads(raw))
        except (ValueError, TypeError, AttributeError):
            pass  # Deliberately swallowed — the chain walk reports an unreadable record itself
        return raw

    return fetch_and_record


def verify_manifest(bucket_name, manifest, storage_client):
    """Walk each event in the manifest, re-fetch from GCS, recompute hash."""
    prefix = manifest.get('prefix', 'audit/')
    objects = gcs_fetcher(bucket_name, prefix, storage_client)
    objects.expect(*manifest_sequence_window(manifest))
    return verify_manifest_with(objects, manifest, holders=objects.holders)


def manifest_sequence_window(manifest):
    """(lowest, highest) sequence the manifest's events name, (0, 0) for none.
    A malformed entry is left to the chain walk to report."""
    seqs = [e['sequence'] for e in manifest.get('events', [])
            if isinstance(e, dict) and type(e.get('sequence')) is int] or [0]
    return min(seqs), max(seqs)


def manifest_storage_layout_error(manifest):
    """None when the manifest's storage layout is one this verifier reads (a
    manifest before 1.2 has none: its chain is per-record; a 1.3 manifest has
    one only when its chain is segmented), else the message to print
    before exiting 2."""
    version = manifest.get("schema_version")
    if version != "1.2" and not (version in ("1.3", "1.4", "1.5") and "storage_layout" in manifest):
        return None
    layout = manifest.get("storage_layout")
    if layout in STORAGE_LAYOUTS:
        return None
    return (f"manifest storage_layout {layout!r} is not one this verifier reads "
            f"({', '.join(STORAGE_LAYOUTS)}). Re-run with an updated verifier.")


def object_reference_problem(entry, holders=None):
    """Manifest 1.2: None when the entry's `object` reference
    names a record object that holds the entry's sequence at `index`, else
    the problem. With `holders` (--bucket mode) the bucket listing must also
    show that object holding the sequence. An offline directory is not
    consulted: it may hold the same records as per-record files written by
    --export-records."""
    seq = entry['sequence']
    ref = entry.get('object')
    if not isinstance(ref, dict) or 'name' not in ref or 'index' not in ref:
        return "manifest 1.2 entry has no object reference ({name, index})"
    name, index = ref['name'], ref['index']
    span = record_object_range(name) if isinstance(name, str) else None
    if (span is None or isinstance(index, bool) or not isinstance(index, int)
            or not span[0] <= seq <= span[1] or index != seq - span[0]):
        return f"manifest object reference {json.dumps(ref, sort_keys=True)} does not hold seq={seq}"
    if holders is not None and name not in holders(seq):
        return f"manifest names object {name} for this record, and the bucket holds no such object"
    return None


def manifest_references_objects(manifest):
    """Whether each manifest entry names the object holding its record: every
    1.2 manifest, and a 1.3, 1.4 or 1.5 manifest that has a storage_layout."""
    version = manifest.get('schema_version')
    return version == '1.2' or (version in ('1.3', '1.4', '1.5') and 'storage_layout' in manifest)


# The event_id a hash-only stub stands in with, for the decision
# receipt evidence check: its hash is in the pack, its event_id is not.
STUB_EVENT_ID = object()


def stub_problems(stub, seq, entry, require_manifest_hash=False):
    """What is wrong with a hash-only stub at `seq` against its
    manifest entry: members other than STUB_FIELDS, a missing hash, another
    sequence, or an event_hash that is not the one the manifest signs."""
    if not isinstance(stub, dict):
        return ["a hash-only stub is a JSON object"]
    problems = []
    extra = sorted(set(stub) - set(STUB_FIELDS))
    if extra:
        problems.append(f"it carries more than its coordinates ({', '.join(extra)})")
    missing = [k for k in ('sequence_number', 'event_hash', 'previous_hash') if not isinstance(stub.get(k), (str, int))
               or isinstance(stub.get(k), bool)]
    if missing:
        problems.append(f"it has no {', '.join(missing)}")
    if stub.get('sequence_number') != seq:
        problems.append(f"it says sequence_number {stub.get('sequence_number')!r}")
    stub_hash = stub.get('event_hash')
    manifest_recomputed = entry.get('recomputed_event_hash', '')
    if require_manifest_hash and not manifest_recomputed:
        problems.append("its manifest entry has no recomputed_event_hash, so the manifest signature does not cover it")
    for key in ('recomputed_event_hash', 'stored_event_hash'):
        held = entry.get(key, '')
        if held and stub_hash != held:
            problems.append(f"event_hash {str(stub_hash)[:16]}... is not the manifest's {key} {str(held)[:16]}...")
    return problems


def verify_manifest_with(fetch, manifest, quiet=False, require_manifest_hash=False, holders=None,
                         receipts_out=None, records_out=None, stripped=frozenset(), cannot_evaluate_out=None,
                         stubs=None):
    """Walk each event in the manifest, fetch its record through `fetch(seq)`,
    recompute the hash and check the chain linkage. Source-agnostic: `fetch`
    is the only thing that differs between the GCS and the offline path, so
    both walk the identical verification loop.

    `require_manifest_hash` is set for signed packs: every entry must carry
    `recomputed_event_hash`. That field is the only link from the signed
    manifest to the record bytes, so an entry without it would leave its
    record outside what the signature covers.

    `holders(seq)`, in --bucket mode, lists the objects holding a sequence,
    against which a manifest 1.2 entry's object reference is checked.

    `receipts_out`, when given, is filled with each decision receipt record's
    sequence -> payload, for the control-plane anchor check.

    `stripped` is the removed-field set of a content-stripped
    Exchange pack (STRIPPED_FIELDS), empty otherwise. Each record must then
    carry none of those fields and none of WITHHELD_FIELDS; every one it does
    carry is reported as CANNOT EVALUATE and appended, as (seq, problem), to
    `cannot_evaluate_out`, which the caller turns into exit 2. The content
    axes the pack removed are checked from their sealed digests only.

    `stubs` (sequence -> (reason, field), from manifest_stubs) are
    the records a stripped pack ships as hash-only stubs. A stub is checked
    by its coordinates: exactly STUB_FIELDS, its own sequence, the event_hash
    the manifest signs, and the link to the record before it. Its hash is not
    recomputed (that needs the body), and the record after it links to its
    event_hash. A stub of an unreadable record attests nothing and fails, as
    the record itself would."""
    stubs = stubs or {}
    hash_version = manifest.get('hash_version', '')
    if hash_version not in SUPPORTED_HASH_VERSIONS:
        print(
            f"ERROR: This reproducer supports hash_version {SUPPORTED_HASH_VERSIONS}. "
            f"The manifest specifies '{hash_version}'. Re-run with the updated reproducer.",
            file=sys.stderr,
        )
        sys.exit(EXIT_CANNOT_EVALUATE)

    genesis = genesis_hash()

    # The hashes the next record's previous_hash may link to. After
    # a record that passed, exactly the hash it verified at. After a record
    # that failed, every hash the pack commits to for it: its own event_hash
    # (when readable) and the manifest entry's stored_event_hash and
    # recomputed_event_hash. The failed record already has its FAIL line; its
    # successor is judged against what the chain claimed that record was, so
    # one tampered record yields one FAIL, not a second, false "chain break"
    # on the intact record after it.
    #
    # This cannot mask a tamper. The set widens only after a record has
    # already failed, and the successor's own bytes are still bound by its own
    # hash check: previous_hash is hashed, so editing it fails at the
    # successor against the manifest's recomputed_event_hash. A manifest that
    # carries no hashes adds nothing to the set, which is then the failed
    # record's own event_hash, as before. When nothing in the pack attests the
    # failed record's hash (such a manifest, and a record that is missing or
    # unreadable), the set is empty and the successor's link is reported as
    # not checked, never as passed.
    next_link = {genesis}
    prev_seq = None

    def committed_hashes(entry, event_hash=''):
        return {
            h for h in (event_hash, entry.get('stored_event_hash', ''), entry.get('recomputed_event_hash', ''))
            if isinstance(h, str) and h
        }

    all_passed = True
    references_objects = manifest_references_objects(manifest)
    events_in_manifest = manifest.get('events', [])
    if not events_in_manifest:
        print("WARN: manifest.events is empty — nothing to verify.")
        return True

    def report(line):
        if not quiet:
            print(line)

    # What the decision-receipt checks after the walk read: each
    # record's (event_id, event_hash) by sequence, and each receipt's payload.
    pack_records = {}
    receipts = {}

    for entry in sorted(events_in_manifest, key=lambda e: e['sequence']):
        seq = entry['sequence']
        # The links this record may make, and the record they point back to.
        # Until this record passes, the next one links against the hashes the
        # pack commits to for it.
        link_targets, link_seq = next_link, prev_seq
        next_link, prev_seq = committed_hashes(entry), seq

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

        # A hash-only stub: linked through, never recomputed.
        if seq in stubs:
            reason, field = stubs[seq]
            record = event if isinstance(event, dict) else {}
            if stripped:
                for problem in stripped_record_problems(record):
                    report(f"CANNOT EVALUATE seq={seq}: {problem}")
                    if cannot_evaluate_out is not None:
                        cannot_evaluate_out.append((seq, problem))
            stub_hash = record.get('event_hash') if isinstance(record.get('event_hash'), str) else ''
            stub_prev = record.get('previous_hash') if isinstance(record.get('previous_hash'), str) else ''
            pack_records[seq] = (STUB_EVENT_ID, stub_hash)
            next_link = committed_hashes(entry, stub_hash)
            if reason == 'unreadable_record':
                report(f"FAIL seq={seq}: hash-only stub of a record that does not parse (the chain's own break); "
                       f"nothing in the pack attests its hash.")
                all_passed = False
                continue
            problems = stub_problems(event, seq, entry, require_manifest_hash)
            if link_targets and stub_prev not in link_targets:
                expected = ' or '.join(f"{h[:16]}..." for h in sorted(link_targets))
                problems.append(f"chain break. previous_hash={stub_prev[:16]}... expected={expected}")
            if problems:
                report(f"FAIL seq={seq}: hash-only stub ({field}): {'; '.join(problems)}")
                all_passed = False
                continue
            if not link_targets:
                report(f"WARN seq={seq}: hash-only stub hash={stub_hash[:16]}..., but its chain link to "
                       f"seq={link_seq} was not checked, because that record failed and nothing in the pack "
                       f"attests its hash.")
            else:
                report(f"STUB seq={seq} hash={stub_hash[:16]}... chain_ok: hash-only stub, {field} "
                       f"({STUB_REASONS[reason]}); body withheld, hash not recomputed")
            next_link = {stub_hash}
            continue

        stored_prev = event.get('previous_hash', '')
        stored_hash = event.get('event_hash', '')
        next_link = committed_hashes(entry, stored_hash)
        pack_records[seq] = (event.get('event_id'), stored_hash)
        if records_out is not None:
            records_out[seq] = event
        if isinstance(event.get('decision_receipt'), dict):
            receipts[seq] = event['decision_receipt']
        # A stripped pack's record carries nothing the profile removes.
        if stripped:
            for problem in stripped_record_problems(event):
                report(f"CANNOT EVALUATE seq={seq}: {problem}")
                if cannot_evaluate_out is not None:
                    cannot_evaluate_out.append((seq, problem))

        # Dispatch on the event's own schema_version + event_kind
        # (v1/v1.1 llm, v1.2 auth, v1.3 admin), the same recompute path
        # run_self_test exercises. Timestamp normalization + action extraction
        # happen inside recompute_event_hash.
        try:
            recomputed = recompute_event_hash(event, seq, stored_prev)
        except ValueError as exc:
            report(f"FAIL seq={seq}: {exc}")
            all_passed = False
            continue
        except (KeyError, TypeError, AttributeError, struct.error) as exc:
            # A field the preimage reads is missing or has the wrong
            # shape: the record fails by name, never a traceback.
            report(f"FAIL seq={seq}: the record is malformed and has no defined preimage "
                   f"({type(exc).__name__}: {exc})")
            all_passed = False
            continue

        hash_ok = (recomputed == stored_hash)
        link_checked = bool(link_targets)
        chain_ok = not link_checked or (isinstance(stored_prev, str) and stored_prev in link_targets)

        # A v1.10 record's hash covers the digests of its content;
        # this checks the content itself still matches them.
        content_ok = True
        for problem in check_llm_content(event, stripped):
            report(f"FAIL seq={seq}: {problem}")
            all_passed = False
            content_ok = False
        # A v1.12 record's hash covers the digest of its asserted
        # labels; this checks the stored labels still match it.
        for problem in check_sealed_identity(event, stripped):
            report(f"FAIL seq={seq}: {problem}")
            all_passed = False
            content_ok = False
        # A v1.15 record's hash covers the digest of its evidence list
        # and its sealed clock verdict; this checks the stored list and the
        # arithmetic still match them.
        for problem in check_decision_receipt(event):
            report(f"FAIL seq={seq}: {problem}")
            all_passed = False
            content_ok = False
        # A v1.16 record's hash covers the digest of its evaluation
        # outcomes; this checks the stored outcomes still match it.
        for problem in check_evaluation_trace(event):
            report(f"FAIL seq={seq}: {problem}")
            all_passed = False
            content_ok = False
        # A v1.18 record's hash covers its customer block; this
        # checks the block is one the resolver produces and, when the plain
        # label is stored beside it, that the sealed digest is the label's.
        for problem in check_customer_scope(event):
            report(f"FAIL seq={seq}: {problem}")
            all_passed = False
            content_ok = False
        # A manifest 1.2 entry names the object holding its record.
        if references_objects:
            problem = object_reference_problem(entry, holders)
            if problem:
                report(f"FAIL seq={seq}: {problem}")
                all_passed = False
                content_ok = False

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

        if not link_checked:
            verified = f"hash={stored_hash[:16]}... verified, but its " if hash_ok else "its "
            report(
                f"WARN seq={seq}: {verified}chain link to seq={link_seq} was not checked, because "
                f"that record failed and nothing in the pack attests its hash."
            )
        elif hash_ok and chain_ok:
            report(f"PASS seq={seq} hash={stored_hash[:16]}... chain_ok")
        if not hash_ok:
            report(
                f"FAIL seq={seq}: hash mismatch. "
                f"stored={stored_hash[:16]}... recomputed={recomputed[:16]}..."
            )
        if not chain_ok:
            expected = ' or '.join(f"{h[:16]}..." for h in sorted(link_targets))
            report(
                f"FAIL seq={seq}: chain break. "
                f"previous_hash={stored_prev[:16]}... expected={expected}"
            )
        if not (hash_ok and chain_ok):
            all_passed = False
        elif content_ok:
            next_link = {stored_hash}

    # Each receipt's evidence against the records in
    # this pack, then the manifest's receipt index against the receipts.
    window_seqs = {e['sequence'] for e in events_in_manifest}
    pack_chain = chain_for_prefix(manifest.get('prefix', 'audit/'))
    for seq, receipt in sorted(receipts.items()):
        failures, warnings = receipt_evidence_findings(seq, receipt, pack_chain, pack_records, window_seqs)
        for line in warnings:
            report(line)
        for problem in failures:
            report(f"FAIL seq={seq}: {problem}")
            all_passed = False
    failures, lines = receipt_index_findings(manifest, receipts, window_seqs, set(pack_records))
    for problem in failures:
        report(f"FAIL decision_receipts: {problem}")
        all_passed = False
    for line in lines:
        report(line)
    if receipts_out is not None:
        receipts_out.update(receipts)

    return all_passed


# ---------------------------------------------------------------------------
# Signed packs (window B): Sigstore bundle verification
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

# The second identity class: a per-tenant signer, a Google service account that can read
# only its own tenant's audit bucket. Fulcio records Google's issuer and the
# account's email as an rfc822Name subjectAltName. There is no default for
# this class and no pattern: the reader passes the exact email the evidence
# holder published for the project (--certificate-identity), because anyone
# can create a Google service account, and only the published identity binds
# the pack to that tenant. A pack signed in this class without an identity
# from the reader cannot be evaluated (exit 2); it never passes.
GOOGLE_OIDC_ISSUER = "https://accounts.google.com"

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


class SignerIdentityRequired(Exception):
    """A valid signature by a per-tenant signer (GOOGLE_OIDC_ISSUER), checked
    without an identity from the reader. Exit 2: the verifier cannot decide
    whose pack this is, and the certificate cannot vouch for itself."""

    def __init__(self, identities):
        super().__init__(", ".join(identities) or "no identity")
        self.identities = identities


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


# ── RSA (PKCS#1 v1.5 and PSS) and the signature backend ───────────────────
# Verification only, over public inputs, for RFC 3161 timestamp tokens.
# PKCS#1 v1.5 rebuilds the whole k-byte encoding and compares it,
# never parsing the decrypted block, so there is no lenient-parser
# forgery surface (Bleichenbacher 2006). PSS is EMSA-PSS-VERIFY (RFC 8017
# §9.1.2) with MGF1 over the signature hash and a salt as long as that hash.

RSA_MIN_BITS = 2048
RSA_MAX_BITS = 8192
_RSA_HASH_LEN = {"sha256": 32, "sha384": 48, "sha512": 64}
_DIGEST_INFO_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def _rsa_public(n, e, signature):
    """s^e mod n as a k-byte string, or None when the signature is not a
    k-byte value below n (RFC 8017 §8.2.2 step 1, §5.2.2)."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return None
    s = int.from_bytes(signature, "big")
    if s >= n:
        return None
    return pow(s, e, n).to_bytes(k, "big")


def rsa_pkcs1v15_verify(n, e, hash_name, digest, signature):
    """True iff `signature` is RSASSA-PKCS1-v1_5 over the already hashed
    `digest` under (n, e)."""
    em = _rsa_public(n, e, signature)
    if em is None or len(digest) != _RSA_HASH_LEN[hash_name]:
        return False
    t = _DIGEST_INFO_PREFIX[hash_name] + digest
    k = len(em)
    if k < len(t) + 11:
        return False
    return em == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def _mgf1(hash_name, seed, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.new(hash_name, seed + struct.pack(">I", counter)).digest()
        counter += 1
    return out[:length]


def rsa_pss_verify(n, e, hash_name, digest, signature, salt_len):
    """True iff `signature` is RSASSA-PSS over the already hashed `digest`
    under (n, e), MGF1 with the same hash, and a salt of `salt_len` bytes."""
    em_full = _rsa_public(n, e, signature)
    h_len = _RSA_HASH_LEN[hash_name]
    if em_full is None or len(digest) != h_len:
        return False
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    em = em_full[len(em_full) - em_len:]
    if len(em_full) > em_len and em_full[0] != 0:
        return False
    if em_len < h_len + salt_len + 2 or em[-1] != 0xBC:
        return False
    masked_db, h = em[:em_len - h_len - 1], em[em_len - h_len - 1:-1]
    unused_bits = 8 * em_len - em_bits
    if unused_bits and masked_db[0] >> (8 - unused_bits):
        return False
    db = bytes(a ^ b for a, b in zip(masked_db, _mgf1(hash_name, h, len(masked_db))))
    db = bytes([db[0] & (0xFF >> unused_bits)]) + db[1:]
    pad_len = em_len - h_len - salt_len - 2
    if db[:pad_len] != b"\x00" * pad_len or db[pad_len] != 0x01:
        return False
    salt = db[len(db) - salt_len:] if salt_len else b""
    m_prime = b"\x00" * 8 + digest + salt
    return hashlib.new(hash_name, m_prime).digest() == h


class SigBackend:
    """The signature primitives every check goes through. One backend, so a
    reviewer reads one place to see which algorithms this verifier runs."""

    def ecdsa(self, curve, public_point, digest, signature_der):
        raise NotImplementedError

    def rsa_pkcs1v15(self, n, e, hash_name, digest, signature):
        raise NotImplementedError

    def rsa_pss(self, n, e, hash_name, digest, signature, salt_len):
        raise NotImplementedError


class StdlibBackend(SigBackend):
    """Pure-stdlib implementations (this file has no dependencies)."""

    def ecdsa(self, curve, public_point, digest, signature_der):
        return ecdsa_verify_der(curve, public_point, digest, signature_der)

    def rsa_pkcs1v15(self, n, e, hash_name, digest, signature):
        return rsa_pkcs1v15_verify(n, e, hash_name, digest, signature)

    def rsa_pss(self, n, e, hash_name, digest, signature, salt_len):
        return rsa_pss_verify(n, e, hash_name, digest, signature, salt_len)


SIG_BACKEND = StdlibBackend()


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
        self._load_public_key()

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

    def _load_public_key(self):
        """The Fulcio path accepts EC keys only (P-256 / P-384)."""
        self.key_kind = "ec"
        self.curve, self.public_point = parse_ec_public_key(self.spki)

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

    def san_values(self, tags=(0x81, 0x86)):
        """URI and email subjectAltName values; `tags=(0x81,)` for the email
        (rfc822Name) values only."""
        ext = self.extensions.get(OID_SUBJECT_ALT_NAME)
        if ext is None:
            return []
        value = ext[1]
        cs, ce = _der_expect(value, 0, len(value), 0x30)
        if ce != len(value):
            raise DerError("malformed subjectAltName")
        out = []
        for tag, vcs, vce, _ in _der_children(value, cs, ce):
            if tag in tags:  # 0x81 rfc822Name, 0x86 uniformResourceIdentifier
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
        return SIG_BACKEND.ecdsa(issuer_cert.curve, issuer_cert.public_point, digest, self.signature)


KEY_USAGE_DIGITAL_SIGNATURE = 0x8000
KEY_USAGE_KEY_CERT_SIGN = 0x0400


def verify_certificate_chain(leaf, chain, at_time):
    """Check leaf -> chain[0] -> ... -> chain[-1] (the trust anchor) at `at_time`.
    Returns None when valid, else a short reason."""
    try:
        for cert in [leaf] + chain:
            if cert.key_kind != "ec":
                return "certificate key is not an EC key"
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
        if raw[:4] == key_id[:4] and SIG_BACKEND.ecdsa(log["curve"], log["point"], digest, raw[4:]):
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

def verify_sigstore_bundle(bundle, artifact_digest, expected_identity, expected_issuer, trust,
                           identity_supplied=True):
    """Verify a Sigstore bundle (v0.3, hashedrekord, Rekor v1) over an artifact
    whose SHA-256 is `artifact_digest`. Returns a dict describing the verified
    signer. Raises SignatureInvalid (with one of the REASON_* values),
    SignatureUnsupported, or SignerIdentityRequired when the certificate is a
    per-tenant signer's (GOOGLE_OIDC_ISSUER) and `identity_supplied` is False:
    the reader gave no identity, so the default (the signing workflow) is all
    there is to compare with, and a per-tenant pack is checked only against
    the identity its holder published."""
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
    if not SIG_BACKEND.ecdsa(leaf.curve, leaf.public_point, artifact_digest, signature):
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
    if not SIG_BACKEND.ecdsa(log["curve"], log["point"], hashlib.sha256(set_payload).digest(),
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

    # 6. The certificate names the expected signer. A per-tenant signer
    # (Google issuer) is named by an email SAN only, and only an identity the
    # reader supplied can match it.
    try:
        issuer = leaf.fulcio_issuer()
        per_tenant = issuer == GOOGLE_OIDC_ISSUER
        identities = leaf.san_values((0x81,) if per_tenant else (0x81, 0x86))
    except (DerError, UnicodeDecodeError) as exc:
        raise SignatureInvalid(REASON_MALFORMED, f"signing certificate identity: {exc}")
    if per_tenant and not identity_supplied:
        raise SignerIdentityRequired(identities)
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
        "per_tenant": per_tenant,
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
                         expected_issuer, trust, identity_supplied=True):
    """Verify a signed pack's signature. `read_sibling(name)` returns the bytes
    of a file next to manifest.json, or None when it does not exist.
    `identity_supplied` is False when the reader passed no
    --certificate-identity (see verify_sigstore_bundle)."""
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
            identity_supplied=identity_supplied,
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


# ── Chain-head anchors ────────────────────────────────
# RFC 3161 timestamp tokens over chain-head statements, stored next to the
# chain as anchors/{chain}/{seq:020}.json (the statement) and
# anchors/{chain}/{seq:020}.{tsa_id}.tsr (one token per witness). Every rule
# below mirrors the proxy's verifier (crates/meilynx-audit/src/anchor/verify.rs)
# and is never weaker; failure codes use the same names, so a defect is
# reported identically by both. The two proxy-only checks (the request nonce
# and genTime against the live clock) cannot be made offline; in their place
# a record whose own clock is ahead of the anchor that covers it is a NOTICE.

ANCHOR_STATEMENT_VERSION = "meilynx.anchor.v1"
ANCHOR_HASH_ALG = "sha-256"
ANCHOR_IMPRINT_DOMAIN = b"meilynx-anchor-v1\n"
ANCHOR_CLOCK_TOLERANCE_SECONDS = 300
_JSON_SAFE_MAX = (1 << 53) - 1
LEGACY_FLAT_CHAIN = "legacy-flat"

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_ATTR_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_ATTR_SIGNING_CERT_V1 = "1.2.840.113549.1.9.16.2.12"
OID_ATTR_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_ATTR_CMS_ALG_PROTECTION = "1.2.840.113549.1.9.52"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"
OID_SUBJECT_KEY_ID = "2.5.29.14"
OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
TSA_DIGESTS = {OID_SHA256: "sha256", OID_SHA384: "sha384", OID_SHA512: "sha512"}
TSA_RSA_SIGNATURES = {
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}
TSA_ECDSA_SIGNATURES = {
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}
_TSA_ALLOWED_SIGNED_ATTRIBUTES = {
    OID_ATTR_CONTENT_TYPE, OID_ATTR_MESSAGE_DIGEST, OID_ATTR_SIGNING_TIME,
    OID_ATTR_SIGNING_CERT_V2, OID_ATTR_CMS_ALG_PROTECTION,
}
_TSA_MAX_PATH_DEPTH = 4


class AnchorFailure(Exception):
    """One anchor check failed. `code` matches the proxy's
    AnchorVerifyError::code() wherever the check is shared."""

    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _tsa_digest_alg(buf, node):
    """AlgorithmIdentifier of an allowlisted digest -> hashlib name. SHA-1,
    MD5 and anything else are refused; parameters must be absent or NULL."""
    kids = _der_children(buf, node[1], node[2])
    if not kids or kids[0][0] != 0x06 or len(kids) > 2:
        raise DerError("malformed AlgorithmIdentifier")
    oid = _der_oid(buf[kids[0][1]:kids[0][2]])
    if oid not in TSA_DIGESTS:
        raise AnchorFailure("algorithm_not_allowed", f"digest {oid}")
    if len(kids) == 2 and (kids[1][0] != 0x05 or kids[1][2] != kids[1][1]):
        raise DerError("unexpected digest algorithm parameters")
    return TSA_DIGESTS[oid]


def _tsa_alg_id(buf, node):
    """AlgorithmIdentifier -> (oid, params node or None)."""
    if node[0] != 0x30:
        raise DerError("AlgorithmIdentifier is not a SEQUENCE")
    kids = _der_children(buf, node[1], node[2])
    if not kids or kids[0][0] != 0x06 or len(kids) > 2:
        raise DerError("malformed AlgorithmIdentifier")
    return _der_oid(buf[kids[0][1]:kids[0][2]]), (kids[1] if len(kids) == 2 else None)


def _null_or_absent(buf, params):
    return params is None or (params[0] == 0x05 and params[1] == params[2])


def _tsa_pss_params(buf, params):
    """RSASSA-PSS-params: hash == MGF1 hash, salt == hash length, trailer 1.
    The DEFAULT values are SHA-1, so an omitted hash or MGF is refused."""
    if params is None or params[0] != 0x30:
        raise DerError("RSASSA-PSS-params missing")
    fields = _der_children(buf, params[1], params[2])
    i = 0
    if i < len(fields) and fields[i][0] == 0xA0:
        inner = _der_children(buf, fields[i][1], fields[i][2])
        if len(inner) != 1:
            raise DerError("malformed RSASSA-PSS hashAlgorithm")
        hash_name = _tsa_digest_alg(buf, inner[0])
        i += 1
    else:
        raise AnchorFailure("algorithm_not_allowed", "RSASSA-PSS default (SHA-1)")
    if i < len(fields) and fields[i][0] == 0xA1:
        inner = _der_children(buf, fields[i][1], fields[i][2])
        if len(inner) != 1:
            raise DerError("malformed RSASSA-PSS maskGenAlgorithm")
        mgf_oid, mgf_params = _tsa_alg_id(buf, inner[0])
        if mgf_oid != OID_MGF1:
            raise AnchorFailure("algorithm_not_allowed", f"MGF {mgf_oid}")
        if mgf_params is None:
            raise DerError("MGF1 without a hash")
        mgf_hash = _tsa_digest_alg(buf, mgf_params)
        i += 1
    else:
        raise AnchorFailure("algorithm_not_allowed", "MGF1 default (SHA-1)")
    salt = 20
    if i < len(fields) and fields[i][0] == 0xA2:
        inner = _der_children(buf, fields[i][1], fields[i][2])
        if len(inner) != 1 or inner[0][0] != 0x02:
            raise DerError("malformed RSASSA-PSS saltLength")
        salt = _der_positive_int(buf[inner[0][1]:inner[0][2]])
        i += 1
    if i < len(fields) and fields[i][0] == 0xA3:
        inner = _der_children(buf, fields[i][1], fields[i][2])
        if len(inner) != 1 or inner[0][0] != 0x02 or _der_positive_int(buf[inner[0][1]:inner[0][2]]) != 1:
            raise DerError("RSASSA-PSS trailer field is not 1")
        i += 1
    if i != len(fields):
        raise DerError("trailing RSASSA-PSS-params fields")
    if hash_name != mgf_hash or salt != _RSA_HASH_LEN[hash_name]:
        raise AnchorFailure("algorithm_not_allowed",
                            f"RSASSA-PSS hash {hash_name}, MGF1 {mgf_hash}, salt {salt}")
    return hash_name


def _pss_algorithm_identifier(hash_oid_hex, salt_len):
    """The one DER form of an RSASSA-PSS AlgorithmIdentifier that webpki
    accepts in a certificate: explicit hash with NULL parameters, MGF1 over
    the same hash, salt = hash length, no trailer field."""
    hash_alg = bytes.fromhex("300d0609" + hash_oid_hex + "0500")
    mgf = bytes.fromhex("301a06092a864886f70d010108") + hash_alg
    params = (b"\xa0\x0f" + hash_alg + b"\xa1\x1c" + mgf + bytes([0xA2, 0x03, 0x02, 0x01, salt_len]))
    body = bytes.fromhex("06092a864886f70d01010a") + b"\x30" + bytes([len(params)]) + params
    return b"\x30" + bytes([len(body)]) + body


_CERT_PSS_ALGORITHMS = {
    _pss_algorithm_identifier("608648016503040201", 32): "sha256",
    _pss_algorithm_identifier("608648016503040202", 48): "sha384",
    _pss_algorithm_identifier("608648016503040203", 64): "sha512",
}


class TsaCertificate(Certificate):
    """A certificate on a timestamp authority's path. Same strict parser as
    `Certificate` (the Fulcio path keeps that class, EC-only, unchanged);
    this one also accepts RSA keys and the TSA signature algorithms, and
    resolves the signature algorithm lazily so an off-allowlist one is an
    `algorithm_not_allowed` failure rather than a parse error."""

    def __init__(self, der):
        super().__init__(der)
        cert = _der_children(der, *_der_expect(der, 0, len(der), 0x30))
        tbs = _der_children(der, cert[0][1], cert[0][2])
        _der_positive_int(der[tbs[1][1]:tbs[1][2]])
        self.serial = _strip_zeros(der[tbs[1][1]:tbs[1][2]])

    def _load_public_key(self):
        self.key_kind, self.curve, self.public_point, self.rsa_n, self.rsa_e = "other", None, None, None, None
        cs, ce = _der_expect(self.spki, 0, len(self.spki), 0x30)
        kids = _der_children(self.spki, cs, ce)
        if len(kids) != 2 or kids[0][0] != 0x30 or kids[1][0] != 0x03:
            raise DerError("malformed SubjectPublicKeyInfo")
        oid, params = _tsa_alg_id(self.spki, kids[0])
        if oid == OID_EC_PUBLIC_KEY:
            try:
                self.curve, self.public_point = parse_ec_public_key(self.spki)
                self.key_kind = "ec"
            except DerError:
                self.key_kind = "other"  # a curve or point this verifier does not allow
        elif oid == OID_RSA_ENCRYPTION:
            if params is None or params[0] != 0x05 or params[1] != params[2]:
                return  # webpki only matches rsaEncryption with NULL parameters
            bits = self.spki[kids[1][1]:kids[1][2]]
            if not bits or bits[0] != 0:
                raise DerError("RSA key with unused bits")
            rcs, rce = _der_expect(bits, 1, len(bits), 0x30)
            if rce != len(bits):
                raise DerError("trailing bytes after RSAPublicKey")
            ints = _der_children(bits, rcs, rce)
            if len(ints) != 2 or ints[0][0] != 0x02 or ints[1][0] != 0x02:
                raise DerError("malformed RSAPublicKey")
            self.rsa_n = _der_positive_int(bits[ints[0][1]:ints[0][2]])
            self.rsa_e = _der_positive_int(bits[ints[1][1]:ints[1][2]])
            self.key_kind = "rsa"

    @staticmethod
    def _signature_algorithm(der, node):
        oid, params = _tsa_alg_id(der, node)
        if oid in TSA_RSA_SIGNATURES and _null_or_absent(der, params):
            return ("rsa", TSA_RSA_SIGNATURES[oid])
        if oid in TSA_ECDSA_SIGNATURES and params is None:
            return ("ecdsa", TSA_ECDSA_SIGNATURES[oid])
        if oid == OID_RSASSA_PSS and der[node[3]:node[2]] in _CERT_PSS_ALGORITHMS:
            return ("pss", _CERT_PSS_ALGORITHMS[der[node[3]:node[2]]])
        return ("unsupported", oid)

    def subject_key_id(self):
        ext = self.extensions.get(OID_SUBJECT_KEY_ID)
        if ext is None:
            return None
        value = ext[1]
        cs, ce = _der_expect(value, 0, len(value), 0x04)
        if ce != len(value):
            raise DerError("malformed subjectKeyIdentifier")
        return value[cs:ce]

    def eku_with_criticality(self):
        """(critical, [purpose OIDs]) or None. A list, not a set: a purpose
        listed twice is not "exactly id-kp-timeStamping"."""
        ext = self.extensions.get(OID_EXT_KEY_USAGE)
        if ext is None:
            return None
        value = ext[1]
        cs, ce = _der_expect(value, 0, len(value), 0x30)
        if ce != len(value):
            raise DerError("malformed extKeyUsage")
        purposes = []
        for tag, vcs, vce, _ in _der_children(value, cs, ce):
            if tag != 0x06:
                raise DerError("malformed extKeyUsage")
            purposes.append(_der_oid(value[vcs:vce]))
        return ext[0], purposes

    def rsa_bits(self):
        return self.rsa_n.bit_length() if self.key_kind == "rsa" else 0

    def signed_by(self, issuer_cert):
        """Verify this certificate's signature with `issuer_cert`'s key under
        the TSA allowlist. Raises AnchorFailure('algorithm_not_allowed') for an
        algorithm or key the allowlist refuses; returns False for a bad
        signature."""
        kind, hash_name = self.signature_algorithm
        if kind == "unsupported":
            raise AnchorFailure("algorithm_not_allowed", f"certificate signature {hash_name}")
        digest = hashlib.new(hash_name, self.tbs).digest()
        if kind in ("rsa", "pss"):
            if issuer_cert.key_kind != "rsa" or not RSA_MIN_BITS <= issuer_cert.rsa_bits() <= RSA_MAX_BITS:
                raise AnchorFailure("algorithm_not_allowed", "certificate signature key")
            if kind == "rsa":
                return SIG_BACKEND.rsa_pkcs1v15(issuer_cert.rsa_n, issuer_cert.rsa_e, hash_name, digest,
                                                self.signature)
            return SIG_BACKEND.rsa_pss(issuer_cert.rsa_n, issuer_cert.rsa_e, hash_name, digest,
                                       self.signature, _RSA_HASH_LEN[hash_name])
        if issuer_cert.key_kind != "ec":
            raise AnchorFailure("algorithm_not_allowed", "certificate signature key")
        return SIG_BACKEND.ecdsa(issuer_cert.curve, issuer_cert.public_point, digest, self.signature)


class TsaRoot:
    """A trusted TSA root and the window in which it is trusted. `supplied`
    marks a root the reviewer passed with --tsa-root rather than one pinned
    in this file; a token that verifies through it is reported by name."""

    def __init__(self, name, der, start, end, supplied=False):
        self.name = name
        self.cert = TsaCertificate(der)
        self.start = start
        self.end = end
        self.supplied = supplied
        self.fingerprint = hashlib.sha256(der).hexdigest().upper()

    def trusted_at(self, t):
        return self.start <= t <= self.end


# Pinned trust roots. Each root's SHA-256 is asserted when it is loaded.
TSA_TRUST_ROOTS = {
    "sigstore": [(
        "sigstore-tsa-selfsigned (sigstore/root-signing trusted_root.json @ c9bda74)",
        (
            "MIIB9zCCAXygAwIBAgIUV7f0GLDOoEzIh8LXSW80OJiUp14wCgYIKoZIzj0EAwMwOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2"
            "MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMDkxFTAT"
            "BgNVBAoTDHNpZ3N0b3JlLmRldjEgMB4GA1UEAxMXc2lnc3RvcmUtdHNhLXNlbGZzaWduZWQwdjAQBgcqhkjOPQIBBgUrgQQA"
            "IgNiAAQUQNtfRT/ou3YATa6wB/kKTe70cfJwyRIBovMnt8RcJph/COE82uyS6FmppLLL1VBPGcPfpQPYJNXzWwi8icwhKQ6W"
            "/Qe2h3oebBb2FHpwNJDqo+TMaC/tdfkv/ElJB72jRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G"
            "A1UdDgQWBBSY7AHvf7tR/9SVHm+KiJhTB4nOvzAKBggqhkjOPQQDAwNpADBmAjEAwGEGrfGZR1cen1R8/DTVMI943LssZmJR"
            "tDp/i7SfGHmGRP6gRbuj9vOK3b67Z0QQAjEAuT2H673LQEaHTcyQSZrkp4mX7WwkmF+sVbkYY5mXN+RMH13KUEHHOqASaemY"
            "WK/E"
        ),
        "2ACA8FEA5D3CE48B01CC77076293C280E6C23FFE44034757EE7833CA9F45D633",
        "2025-07-04T00:00:00Z", None,
    )],
    "globalsign-r45": [(
        "GlobalSign Root CA - R6",
        (
            "MIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/RVEwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290"
            "IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTQxMjEwMDAwMDAwWhcNMzQx"
            "MjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEG"
            "A1UEAxMKR2xvYmFsU2lnbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH6HPKZvnsFMp7PPcNCPG0RQssgrRI"
            "xutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay/xTOURQh7ErdG1rG1ofuTToVBu1kZguSgMpE3nOUTvOniX9PeGMIyBJQbUJm"
            "L025eShNUhqKGoC3GYEOfsSKvGRMIRxDaNc9PIrFsmbVkJq3MQbFvuJtMgamHvm566qjuL++gmNQ0PAYid/kD3n16qIfKtJw"
            "LnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqMPKq0pPbzlUoSB239jLKJz9CgYXfIWHSw1CM69106yqLbnQneXUQtkPGBzVeS+n68"
            "UARjNN9rkxi+azayOeSsJDa38O+2HBNXk7besvjihbdzorg1qkXy4J02oW9UivFyVm4uiMVRQkQVlO6jxTiWm05OWgtH8wY2"
            "SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQCTXTAFO39OfuD8l4UoQSwC+n+7o/hbguyCLNhZglqsQY6ZZZZwPA1/cnaKI0a"
            "EYdwgQqomnUdnjqGBQCe24DWJfncBZ4nWUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXKbWQULHpYT9NLCEnFlWQaYw55PfWzjMpY"
            "rZxCRXluDocZXFSxZba/jJvcE+kNb7gu3GduyYsRtYQUigAZcIN5kZeR1BonvzceMgfYFGM8KEyvAgMBAAGjYzBhMA4GA1Ud"
            "DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzWx/B/yGdToDAfBgNVHSMEGDAWgBSu"
            "bAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG9w0BAQwFAAOCAgEAgyXt6NH9lVLNnsAEoJFp5lzQhN7craJP6Ed41mWYqVuo"
            "PId8AorRbrcWc+ZfwFSY1XS+wc3iEZGtIxg93eFyRJa0lV7Ae46ZeBZDE1ZXs6KzO7V33EByrKPrmzU+sQghoefEQzd5Mr61"
            "55wsTLxDKZmOMNOsIeDjHfrYBzN2VAAiKrlNIC5waNrlU/yDXNOd8v9EDERm8tLjvUYAGm0CuiVdjaExUd1URhxN25mW7xoc"
            "BFymFe944Hn+Xds+qkxV/ZoVqW/hpvvfcDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54NMMl+68KnyBr3TsTjxKM4kEaSHpz"
            "oHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA/iU3/gKbaKxCXcPu9czc8FB10jZpnOZ7BN9uBmm23goJSFmH63sUYHpkqmlD"
            "75HHTOwY3WzvUy2MmeFe8nI+z1TIvWfspA9MRf/TuTAjB0yPEL+GltmZWrSZVxykzLsViVO6LAUP5MSeGbEYNNVMnbrt9x+v"
            "JJUEeKgDu+6B5dpffItKoZB0JaezPkvILFa9x8jvOOJckvB595yEunQtYQEgfn7R8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+t"
            "JDfLRVpOoERIyNiwmcUVhAn21klJwGW45hpxbqCo8YLoRT5s1gLXCmeDBVrJpBA="
        ),
        "2CABEAFE37D06CA22ABA7391C0033D25982952C453647349763A3AB5AD6CCF69",
        "2014-12-10T00:00:00Z", "2034-12-10T00:00:00Z",
    )],
}


def load_pinned_tsa_roots():
    """tsa_id -> [TsaRoot] for the built-in witnesses. Raises ValueError if
    a pinned root's fingerprint does not match (the file was edited)."""
    out = {}
    for tsa_id, entries in TSA_TRUST_ROOTS.items():
        roots = []
        for name, b64, fingerprint, start, end in entries:
            der = base64.b64decode(b64, validate=True)
            if hashlib.sha256(der).hexdigest().upper() != fingerprint:
                raise ValueError(f"pinned TSA root {name} does not match its fingerprint")
            roots.append(TsaRoot(name, der, _rfc3339_to_epoch(start),
                                 _rfc3339_to_epoch(end) if end else float("inf")))
        out[tsa_id] = roots
    return out


def load_tsa_roots_pem(tsa_id, text):
    """--tsa-root ID=FILE: PEM certificates trusted for witness `tsa_id`, each
    only within its own notBefore..notAfter."""
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)
    leftover = re.sub(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", "", text, flags=re.S)
    if not blocks or leftover.strip():
        raise ValueError(f"--tsa-root {tsa_id}: not a PEM certificate bundle")
    roots = []
    for i, block in enumerate(blocks):
        der = base64.b64decode("".join(block.split()), validate=True)
        cert = TsaCertificate(der)
        roots.append(TsaRoot(f"{tsa_id}-root-{i}", der, cert.not_before, cert.not_after, supplied=True))
    return roots


def _tsa_gen_time(content):
    """GeneralizedTime as RFC 3161 allows it: YYYYMMDDHHMMSS[.f+]Z, no
    trailing zero in the fraction. Returns epoch seconds (float)."""
    text = content.decode("ascii")
    m = re.fullmatch(r"(\d{14})(?:\.(\d{1,9}))?Z", text)
    if not m or (m.group(2) is not None and m.group(2).endswith("0")):
        raise DerError("malformed genTime")
    d = m.group(1)
    moment = datetime.datetime(int(d[0:4]), int(d[4:6]), int(d[6:8]), int(d[8:10]), int(d[10:12]),
                               int(d[12:14]), tzinfo=datetime.timezone.utc)
    frac = m.group(2) or ""
    return moment.timestamp() + (int(frac) / 10 ** len(frac) if frac else 0.0)


def _strip_zeros(b):
    return b.lstrip(b"\x00")


def verify_tsa_token(response, imprint, roots):
    """Fully verify one RFC 3161 TimeStampResp against `imprint` and the
    witness's `roots` ([TsaRoot]). Returns {'gen_time', 'signature_algorithm'}
    or raises AnchorFailure; malformed DER is AnchorFailure('malformed')."""
    try:
        return _verify_tsa_token(response, imprint, roots)
    except DerError as exc:
        raise AnchorFailure("malformed", str(exc))
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise AnchorFailure("malformed", str(exc))


def _verify_tsa_token(resp, imprint, roots):
    cs, ce = _der_expect(resp, 0, len(resp), 0x30)
    if ce != len(resp):
        raise DerError("trailing bytes after TimeStampResp")
    top = _der_children(resp, cs, ce)
    if not top or top[0][0] != 0x30:
        raise DerError("malformed PKIStatusInfo")
    status_info = _der_children(resp, top[0][1], top[0][2])
    if not status_info or status_info[0][0] != 0x02:
        raise DerError("malformed PKIStatus")
    status = _der_positive_int(resp[status_info[0][1]:status_info[0][2]])
    if status != 0:
        raise AnchorFailure("not_granted", f"PKIStatus {status}")
    if len(top) < 2:
        raise AnchorFailure("no_token")
    if len(top) > 2:
        raise DerError("trailing TimeStampResp fields")

    ci = _der_children(resp, top[1][1], top[1][2])
    if top[1][0] != 0x30 or len(ci) != 2 or ci[0][0] != 0x06 or ci[1][0] != 0xA0:
        raise DerError("malformed ContentInfo")
    if _der_oid(resp[ci[0][1]:ci[0][2]]) != OID_SIGNED_DATA:
        raise AnchorFailure("not_timestamp_token")
    wrapper = _der_children(resp, ci[1][1], ci[1][2])
    if len(wrapper) != 1 or wrapper[0][0] != 0x30:
        raise DerError("malformed SignedData wrapper")
    sd = _der_children(resp, wrapper[0][1], wrapper[0][2])
    if len(sd) < 4 or sd[0][0] != 0x02:
        raise DerError("malformed SignedData")
    sd_version = _der_positive_int(resp[sd[0][1]:sd[0][2]])
    if sd_version != 3:
        raise AnchorFailure("unsupported_version", f"SignedData {sd_version}")
    if sd[1][0] != 0x31:
        raise DerError("malformed digestAlgorithms")
    for alg in _der_children(resp, sd[1][1], sd[1][2]):
        _tsa_digest_alg(resp, alg)
    if sd[2][0] != 0x30:
        raise DerError("malformed EncapsulatedContentInfo")
    encap = _der_children(resp, sd[2][1], sd[2][2])
    if len(encap) != 2 or encap[0][0] != 0x06 or encap[1][0] != 0xA0:
        raise DerError("malformed EncapsulatedContentInfo")
    if _der_oid(resp[encap[0][1]:encap[0][2]]) != OID_CT_TST_INFO:
        raise AnchorFailure("not_timestamp_token")
    octets = _der_children(resp, encap[1][1], encap[1][2])
    if len(octets) != 1 or octets[0][0] != 0x04:
        raise DerError("malformed eContent")
    tst_der = resp[octets[0][1]:octets[0][2]]

    rest = sd[3:]
    certificates = []
    if rest and rest[0][0] == 0xA0:
        for cert in _der_children(resp, rest[0][1], rest[0][2]):
            if cert[0] != 0x30:
                raise DerError("only X.509 certificates are accepted")
            certificates.append(resp[cert[3]:cert[2]])
        rest = rest[1:]
    if rest and rest[0][0] == 0xA1:
        raise DerError("CRLs inside a timestamp token are not accepted")
    if len(rest) != 1 or rest[0][0] != 0x31:
        raise DerError("malformed signerInfos")
    signer_infos = _der_children(resp, rest[0][1], rest[0][2])
    if len(signer_infos) != 1:
        raise AnchorFailure("signer_info_count", str(len(signer_infos)))

    tst = _parse_tst_info(tst_der)
    if tst["imprint_alg"] != OID_SHA256:
        raise AnchorFailure("algorithm_not_allowed", f"message imprint algorithm {tst['imprint_alg']}")
    if tst["imprint"] != imprint:
        raise AnchorFailure("imprint_mismatch")
    if tst["nonce"] is None:
        raise AnchorFailure("nonce_missing")

    si = _parse_signer_info(resp, signer_infos[0])
    digest_name = _tsa_digest_alg(resp, si["digest_alg_node"])
    attrs = _parse_signed_attributes(resp, si["signed_attrs"])
    if attrs["content_type"] != OID_CT_TST_INFO:
        raise AnchorFailure("content_type_mismatch")
    if attrs["message_digest"] != hashlib.new(digest_name, tst_der).digest():
        raise AnchorFailure("message_digest_mismatch")
    if attrs["algorithm_protection"] is not None and attrs["algorithm_protection"] != (
            si["digest_alg_oid"], si["signature_alg_oid"]):
        raise AnchorFailure("algorithm_protection_mismatch")

    ess_hash, ess_cert_hash, ess_serial = attrs["ess"]
    signer_der = next((c for c in certificates if hashlib.new(ess_hash, c).digest() == ess_cert_hash), None)
    if signer_der is None:
        raise AnchorFailure("signer_certificate_not_found")
    signer = TsaCertificate(signer_der)
    if ess_serial is not None and ess_serial != signer.serial:
        raise AnchorFailure("signer_identifier_mismatch")
    if si["sid"][0] == "issuer_serial":
        if si["sid"][1] != signer.issuer or si["sid"][2] != signer.serial:
            raise AnchorFailure("signer_identifier_mismatch")
    elif signer.subject_key_id() != si["sid"][1]:
        raise AnchorFailure("signer_identifier_mismatch")

    sig_kind, sig_name = _tsa_signature_alg(resp, si, digest_name, signer)
    if signer.unknown_critical_extensions():
        raise AnchorFailure("untrusted_chain",
                            f"signer certificate: UnsupportedCriticalExtension "
                            f"{signer.unknown_critical_extensions()[0]}")
    signed_set = b"\x31" + resp[si["signed_attrs"][3] + 1:si["signed_attrs"][2]]
    digest = hashlib.new(digest_name, signed_set).digest()
    if sig_kind == "rsa":
        good = SIG_BACKEND.rsa_pkcs1v15(signer.rsa_n, signer.rsa_e, digest_name, digest, si["signature"])
    elif sig_kind == "pss":
        good = SIG_BACKEND.rsa_pss(signer.rsa_n, signer.rsa_e, digest_name, digest, si["signature"],
                                   _RSA_HASH_LEN[digest_name])
    else:
        good = SIG_BACKEND.ecdsa(signer.curve, signer.public_point, digest, si["signature"])
    if not good:
        raise AnchorFailure("signature_invalid")

    eku = signer.eku_with_criticality()
    if eku is None:
        raise AnchorFailure("timestamping_eku_missing")
    critical, purposes = eku
    if OID_TIME_STAMPING not in purposes:
        raise AnchorFailure("timestamping_eku_missing")
    if len(purposes) != 1:
        raise AnchorFailure("timestamping_eku_not_exclusive")
    if not critical:
        raise AnchorFailure("timestamping_eku_not_critical")

    gen_time = tst["gen_time"]
    trusted = [r for r in roots if r.trusted_at(gen_time)]
    if not trusted:
        raise AnchorFailure("no_root_trusted_at_gen_time", _iso(gen_time))
    pool = [TsaCertificate(c) for c in certificates if c != signer_der]
    root = build_tsa_path(signer, pool, trusted, int(gen_time))
    return {"gen_time": gen_time, "signature_algorithm": sig_name, "root": root}


def _parse_tst_info(der):
    cs, ce = _der_expect(der, 0, len(der), 0x30)
    if ce != len(der):
        raise DerError("trailing bytes after TSTInfo")
    f = _der_children(der, cs, ce)
    if len(f) < 5 or f[0][0] != 0x02 or f[1][0] != 0x06 or f[2][0] != 0x30 or f[3][0] != 0x02 or f[4][0] != 0x18:
        raise DerError("malformed TSTInfo")
    version = _der_positive_int(der[f[0][1]:f[0][2]])
    if version != 1:
        raise AnchorFailure("unsupported_version", f"TSTInfo {version}")
    _der_oid(der[f[1][1]:f[1][2]])
    mi = _der_children(der, f[2][1], f[2][2])
    if len(mi) != 2 or mi[1][0] != 0x04:
        raise DerError("malformed MessageImprint")
    imprint_oid, imprint_params = _tsa_alg_id(der, mi[0])
    if not _null_or_absent(der, imprint_params):
        raise DerError("unexpected MessageImprint parameters")
    _der_positive_int(der[f[3][1]:f[3][2]])
    gen_time = _tsa_gen_time(der[f[4][1]:f[4][2]])
    i = 5
    if i < len(f) and f[i][0] == 0x30:  # accuracy
        i += 1
    if i < len(f) and f[i][0] == 0x01:  # ordering
        i += 1
    nonce = None
    if i < len(f) and f[i][0] == 0x02:
        nonce = _strip_zeros(der[f[i][1]:f[i][2]])
        _der_positive_int(der[f[i][1]:f[i][2]])
        i += 1
    if i < len(f) and f[i][0] == 0xA0:  # tsa GeneralName
        i += 1
    if i < len(f) and f[i][0] == 0xA1:
        for ext in _der_children(der, f[i][1], f[i][2]):
            parts = _der_children(der, ext[1], ext[2]) if ext[0] == 0x30 else []
            if len(parts) < 2 or parts[0][0] != 0x06:
                raise DerError("malformed TSTInfo extension")
            if parts[1][0] == 0x01 and der[parts[1][1]:parts[1][2]] == b"\xff":
                raise DerError(f"unknown critical TSTInfo extension {_der_oid(der[parts[0][1]:parts[0][2]])}")
        i += 1
    if i != len(f):
        raise DerError("trailing TSTInfo fields")
    return {"imprint_alg": imprint_oid, "imprint": der[mi[1][1]:mi[1][2]], "gen_time": gen_time,
            "nonce": nonce}


def _parse_signer_info(buf, node):
    if node[0] != 0x30:
        raise DerError("SignerInfo is not a SEQUENCE")
    f = _der_children(buf, node[1], node[2])
    if len(f) < 5 or f[0][0] != 0x02:
        raise DerError("malformed SignerInfo")
    version = _der_positive_int(buf[f[0][1]:f[0][2]])
    if version == 1:
        if f[1][0] != 0x30:
            raise DerError("malformed IssuerAndSerialNumber")
        ias = _der_children(buf, f[1][1], f[1][2])
        if len(ias) != 2 or ias[0][0] != 0x30 or ias[1][0] != 0x02:
            raise DerError("malformed IssuerAndSerialNumber")
        _der_positive_int(buf[ias[1][1]:ias[1][2]])
        sid = ("issuer_serial", buf[ias[0][3]:ias[0][2]], _strip_zeros(buf[ias[1][1]:ias[1][2]]))
    elif version == 3:
        if f[1][0] != 0x80:
            raise DerError("malformed subjectKeyIdentifier")
        sid = ("ski", buf[f[1][1]:f[1][2]])
    else:
        raise AnchorFailure("unsupported_version", f"SignerInfo {version}")
    if f[2][0] != 0x30:
        raise DerError("malformed digestAlgorithm")
    if f[3][0] != 0xA0:
        raise AnchorFailure("missing_signed_attribute", "signedAttrs")
    if len(f) < 6 or f[4][0] != 0x30 or f[5][0] != 0x04:
        raise DerError("malformed SignerInfo")
    extra = f[6:]
    if extra and extra[0][0] == 0xA1:
        extra = extra[1:]
    if extra:
        raise DerError("trailing SignerInfo fields")
    sig_oid, sig_params = _tsa_alg_id(buf, f[4])
    digest_oid, _ = _tsa_alg_id(buf, f[2])
    return {"sid": sid, "digest_alg_node": f[2], "digest_alg_oid": digest_oid, "signed_attrs": f[3],
            "signature_alg_oid": sig_oid, "signature_alg_params": sig_params,
            "signature": buf[f[5][1]:f[5][2]]}


def _parse_signed_attributes(buf, node):
    seen = set()
    out = {"content_type": None, "message_digest": None, "ess": None, "algorithm_protection": None}
    for attr in _der_children(buf, node[1], node[2]):
        parts = _der_children(buf, attr[1], attr[2]) if attr[0] == 0x30 else []
        if len(parts) != 2 or parts[0][0] != 0x06 or parts[1][0] != 0x31:
            raise DerError("malformed signed attribute")
        oid = _der_oid(buf[parts[0][1]:parts[0][2]])
        if oid in seen:
            raise AnchorFailure("duplicate_signed_attribute", oid)
        seen.add(oid)
        values = _der_children(buf, parts[1][1], parts[1][2])
        if len(values) != 1:
            raise DerError("signed attribute must carry exactly one value")
        tag, vcs, vce, vstart = values[0]
        if oid == OID_ATTR_SIGNING_CERT_V1:
            raise AnchorFailure("ess_cert_id_v1")
        if oid == OID_ATTR_CONTENT_TYPE:
            if tag != 0x06:
                raise DerError("contentType")
            out["content_type"] = _der_oid(buf[vcs:vce])
        elif oid == OID_ATTR_MESSAGE_DIGEST:
            if tag != 0x04:
                raise DerError("messageDigest")
            out["message_digest"] = buf[vcs:vce]
        elif oid == OID_ATTR_SIGNING_TIME:
            if tag not in (0x17, 0x18):
                raise DerError("signingTime")
        elif oid == OID_ATTR_SIGNING_CERT_V2:
            out["ess"] = _parse_signing_certificate_v2(buf, values[0])
        elif oid == OID_ATTR_CMS_ALG_PROTECTION:
            out["algorithm_protection"] = _parse_algorithm_protection(buf, values[0])
        else:
            raise AnchorFailure("unexpected_signed_attribute", oid)
    if out["ess"] is None:
        raise AnchorFailure("missing_signed_attribute", "signingCertificateV2")
    if out["content_type"] is None:
        raise AnchorFailure("missing_signed_attribute", "contentType")
    if out["message_digest"] is None:
        raise AnchorFailure("missing_signed_attribute", "messageDigest")
    return out


def _parse_signing_certificate_v2(buf, node):
    if node[0] != 0x30:
        raise DerError("SigningCertificateV2")
    outer = _der_children(buf, node[1], node[2])
    if not outer or outer[0][0] != 0x30:
        raise DerError("SigningCertificateV2 certs")
    certs = _der_children(buf, outer[0][1], outer[0][2])
    if not certs or certs[0][0] != 0x30:
        raise DerError("ESSCertIDv2")
    e = _der_children(buf, certs[0][1], certs[0][2])
    i = 0
    hash_name = "sha256"
    if i < len(e) and e[i][0] == 0x30:
        oid, _ = _tsa_alg_id(buf, e[i])
        if oid == OID_SHA256:
            raise DerError("explicit DEFAULT sha256 in ESSCertIDv2")
        hash_name = _tsa_digest_alg(buf, e[i])
        i += 1
    if i >= len(e) or e[i][0] != 0x04:
        raise DerError("ESSCertIDv2 certHash")
    cert_hash = buf[e[i][1]:e[i][2]]
    i += 1
    serial = None
    if i < len(e) and e[i][0] == 0x30:
        isr = _der_children(buf, e[i][1], e[i][2])
        if len(isr) != 2 or isr[0][0] != 0x30 or isr[1][0] != 0x02:
            raise DerError("IssuerSerial")
        _der_positive_int(buf[isr[1][1]:isr[1][2]])
        serial = _strip_zeros(buf[isr[1][1]:isr[1][2]])
        i += 1
    if i != len(e):
        raise DerError("trailing ESSCertIDv2 fields")
    return hash_name, cert_hash, serial


def _parse_algorithm_protection(buf, node):
    if node[0] != 0x30:
        raise DerError("CMSAlgorithmProtection")
    f = _der_children(buf, node[1], node[2])
    if len(f) != 2 or f[1][0] != 0xA1:
        raise DerError("CMSAlgorithmProtection")
    digest_oid, _ = _tsa_alg_id(buf, f[0])
    inner = _der_children(buf, f[1][1], f[1][2])
    if not inner or inner[0][0] != 0x06 or len(inner) > 2:
        raise DerError("CMSAlgorithmProtection signatureAlgorithm")
    return digest_oid, _der_oid(buf[inner[0][1]:inner[0][2]])


def _tsa_signature_alg(buf, si, digest_name, signer):
    """The SignerInfo signature algorithm, the digest it must agree with and
    the signer's key -> ('rsa'|'pss'|'ecdsa', name). Mirrors signature_alg()
    in the proxy's verifier."""
    oid, params = si["signature_alg_oid"], si["signature_alg_params"]
    if oid == OID_RSA_ENCRYPTION or oid in TSA_RSA_SIGNATURES:
        if not _null_or_absent(buf, params):
            raise DerError("signature algorithm parameters")
        if oid in TSA_RSA_SIGNATURES and TSA_RSA_SIGNATURES[oid] != digest_name:
            raise AnchorFailure("algorithm_not_allowed", f"{oid} with digest {digest_name}")
        if signer.key_kind != "rsa":
            raise AnchorFailure("algorithm_not_allowed", f"{oid} with a non-RSA key")
        if not RSA_MIN_BITS <= signer.rsa_bits() <= RSA_MAX_BITS:
            raise AnchorFailure("algorithm_not_allowed", f"RSA-{signer.rsa_bits()}")
        return "rsa", f"rsa-pkcs1-{digest_name}"
    if oid == OID_RSASSA_PSS:
        if signer.key_kind != "rsa":
            raise AnchorFailure("algorithm_not_allowed", "RSASSA-PSS with a non-RSA key")
        if not RSA_MIN_BITS <= signer.rsa_bits() <= RSA_MAX_BITS:
            raise AnchorFailure("algorithm_not_allowed", f"RSA-{signer.rsa_bits()}")
        pss_hash = _tsa_pss_params(buf, params)
        if pss_hash != digest_name:
            raise AnchorFailure("algorithm_not_allowed", f"RSASSA-PSS({pss_hash}) with digest {digest_name}")
        return "pss", f"rsa-pss-{digest_name}"
    if oid in TSA_ECDSA_SIGNATURES:
        if params is not None:
            raise DerError("ECDSA with parameters")
        if TSA_ECDSA_SIGNATURES[oid] != digest_name:
            raise AnchorFailure("algorithm_not_allowed", f"{oid} with digest {digest_name}")
        if signer.key_kind != "ec":
            raise AnchorFailure("algorithm_not_allowed", "ECDSA with a non-EC key")
        curve = "p256" if signer.curve is P256 else "p384"
        return "ecdsa", f"ecdsa-{curve}-{digest_name}"
    raise AnchorFailure("algorithm_not_allowed", f"signature {oid}")


def build_tsa_path(leaf, pool, anchors, at_time):
    """Build leaf -> intermediates from the token -> a pinned root, valid at
    `at_time`. Roots never come from the token: a path ends only at one of
    `anchors`, so a cross-certificate to an unpinned root leads nowhere.
    Returns the TsaRoot the path ends at; raises
    AnchorFailure('untrusted_chain' or 'algorithm_not_allowed')."""
    errors = []

    def cert_usable(cert):
        if not cert.not_before <= at_time <= cert.not_after:
            errors.append("untrusted_chain")
            return False
        if cert.unknown_critical_extensions():
            errors.append("untrusted_chain")
            return False
        return True

    def signed(child, issuer):
        try:
            return child.signed_by(issuer)
        except AnchorFailure as exc:
            errors.append(exc.code)
            return False

    def walk(child, depth, used):
        for anchor in anchors:
            if child.issuer == anchor.cert.subject and signed(child, anchor.cert):
                return anchor
        if depth >= _TSA_MAX_PATH_DEPTH:
            return None
        for index, cand in enumerate(pool):
            if index in used or cand.subject != child.issuer:
                continue
            if not cert_usable(cand):
                continue
            is_ca, path_len = cand.basic_constraints()
            usage = cand.key_usage_bits()
            if not is_ca or (usage is not None and not usage & KEY_USAGE_KEY_CERT_SIGN):
                continue
            if path_len is not None and depth > path_len:
                continue
            purposes = cand.extended_key_usages()
            if purposes and OID_TIME_STAMPING not in purposes:
                continue
            if signed(child, cand):
                found = walk(cand, depth + 1, used | {index})
                if found is not None:
                    return found
        return None

    if leaf.basic_constraints()[0]:
        raise AnchorFailure("untrusted_chain", "signing certificate is a CA")
    if not leaf.not_before <= at_time <= leaf.not_after:
        raise AnchorFailure("untrusted_chain", "signing certificate not valid at genTime")
    root = walk(leaf, 0, frozenset())
    if root is not None:
        return root
    if "algorithm_not_allowed" in errors:
        raise AnchorFailure("algorithm_not_allowed", "certificate signature")
    raise AnchorFailure("untrusted_chain", "no path to a pinned root")


# ── anchor statements ──────────────────────────────────────────────────────

_CREATED_AT_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z")
_CHAIN_RE = re.compile(r"[A-Za-z0-9_.\-]{1,256}")
_EVENT_HASH_RE = re.compile(r"[0-9a-f]{64}")


def parse_anchor_statement(raw):
    """Validate stored statement bytes: exact fields, supported version and
    hash, and the canonical (JCS) byte form, so a statement has one imprint.
    Returns the parsed object; raises AnchorFailure."""
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AnchorFailure("statement_malformed", f"not JSON ({exc})")
    if not isinstance(obj, dict) or set(obj) != {"created_at", "hash_alg", "heads", "run_id", "v"}:
        raise AnchorFailure("statement_malformed", "unexpected or missing fields")
    if obj["v"] != ANCHOR_STATEMENT_VERSION:
        raise AnchorFailure("statement_malformed", f"unsupported version {obj['v']!r}")
    if obj["hash_alg"] != ANCHOR_HASH_ALG:
        raise AnchorFailure("statement_malformed", f"unsupported hash_alg {obj['hash_alg']!r}")
    if not isinstance(obj["created_at"], str) or not _CREATED_AT_RE.fullmatch(obj["created_at"]):
        raise AnchorFailure("statement_malformed", "created_at")
    try:
        datetime.datetime.strptime(obj["created_at"][:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise AnchorFailure("statement_malformed", "created_at is not a valid date-time")
    run_id = obj["run_id"]
    if not isinstance(run_id, str) or not 0 < len(run_id) <= 128 or not all(33 <= ord(c) <= 126 for c in run_id):
        raise AnchorFailure("statement_malformed", "run_id")
    heads = obj["heads"]
    if not isinstance(heads, list) or not heads:
        raise AnchorFailure("statement_malformed", "heads")
    chains = []
    for h in heads:
        if not isinstance(h, dict) or set(h) != {"chain", "event_hash", "seq"}:
            raise AnchorFailure("statement_malformed", "head fields")
        if not isinstance(h["chain"], str) or not _CHAIN_RE.fullmatch(h["chain"]) or h["chain"] in (".", ".."):
            raise AnchorFailure("statement_malformed", "chain name")
        if not isinstance(h["event_hash"], str) or not _EVENT_HASH_RE.fullmatch(h["event_hash"]):
            raise AnchorFailure("statement_malformed", "event_hash")
        if isinstance(h["seq"], bool) or not isinstance(h["seq"], int) or not 0 <= h["seq"] <= _JSON_SAFE_MAX:
            raise AnchorFailure("statement_malformed", "seq")
        chains.append(h["chain"].encode("utf-8"))
    if chains != sorted(chains) or len(set(chains)) != len(chains):
        raise AnchorFailure("statement_malformed", "heads not sorted by chain, or a chain repeats")
    if jcs_dumps(obj).encode("utf-8") != raw:
        raise AnchorFailure("statement_non_canonical")
    return obj


def anchor_imprint(raw):
    return hashlib.sha256(ANCHOR_IMPRINT_DOMAIN + raw).digest()


# ── anchor objects: bucket, offline directory, export ──────────────────────

_ANCHOR_STATEMENT_NAME = re.compile(r"(\d{20})\.json")
_ANCHOR_TOKEN_NAME = re.compile(r"(\d{20})\.([a-z0-9][a-z0-9-]{0,31})\.tsr")


class AnchorSourceError(OSError):
    """The anchor objects could not be read (not: an object is absent)."""


class AnchorSource:
    """Read access to anchors/{chain}/ for one chain. An absent object is
    None; any other read error raises OSError."""

    def list_names(self):
        raise NotImplementedError

    def get(self, name):
        raise NotImplementedError


class BucketAnchorSource(AnchorSource):
    def __init__(self, bucket_name, chain, storage_client):
        self.bucket = storage_client.bucket(bucket_name)
        self.client = storage_client
        self.bucket_name = bucket_name
        self.prefix = f"anchors/{chain}/"

    def list_names(self):
        try:
            blobs = self.client.list_blobs(self.bucket_name, prefix=self.prefix)
            return [b.name[len(self.prefix):] for b in blobs]
        except Exception as exc:  # Propagate loud — an unlistable bucket cannot be evaluated
            raise AnchorSourceError(f"cannot list gs://{self.bucket_name}/{self.prefix}: {exc}") from exc

    def get(self, name):
        try:
            return self.bucket.blob(self.prefix + name).download_as_bytes()
        except Exception as exc:  # NotFound is "absent" (judged as missing); anything else propagates
            if type(exc).__name__ == "NotFound":
                return None
            raise AnchorSourceError(f"cannot read gs://{self.bucket_name}/{self.prefix}{name}: {exc}") from exc


class DirectoryAnchorSource(AnchorSource):
    def __init__(self, directory):
        self.dir = Path(directory)

    def list_names(self):
        return sorted(p.name for p in self.dir.iterdir() if p.is_file()) if self.dir.is_dir() else []

    def get(self, name):
        path = self.dir / name
        return path.read_bytes() if path.is_file() else None


class ExportingAnchorSource(AnchorSource):
    """Write every anchor object read to export_dir/anchors/, the layout
    --records reads back."""

    def __init__(self, inner, export_dir):
        self.inner = inner
        self.out = Path(export_dir) / "anchors"
        self.out.mkdir(parents=True, exist_ok=True)

    def list_names(self):
        return self.inner.list_names()

    def get(self, name):
        raw = self.inner.get(name)
        if raw is not None:
            (self.out / name).write_bytes(raw)
        return raw


def chain_for_prefix(prefix):
    """The chain name anchors are stored under for a manifest prefix:
    `audit/` (the flat chain) -> legacy-flat; `audit/{chain}/` -> {chain}."""
    if prefix == "audit/":
        return LEGACY_FLAT_CHAIN
    m = re.fullmatch(r"audit/([A-Za-z0-9_.\-]{1,256})/", prefix or "")
    return m.group(1) if m else None


def _epoch_of_record(event):
    ts = normalize_timestamp(event.get("timestamp_utc", ""))
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", ts)
    if not m:
        raise ValueError("record timestamp")
    return _rfc3339_to_epoch(m.group(1) + "Z")


def _iso(t):
    return _utc(int(t))


def _read_record(record_fetch, seq, stubs=frozenset()):
    """(event, recomputed event hash) for the chain record at `seq`, or an
    AnchorFailure naming why it could not be read. For a hash-only
    stub (`seq` in `stubs`) the hash is the stub's event_hash, which the chain
    walk checks against the signed manifest and the link; a stub's hash cannot
    be recomputed without its body."""
    try:
        raw = record_fetch(seq)
    except Exception as exc:  # Fail-closed — any fetch error (GCS NotFound, OSError) fails the check
        raise AnchorFailure("record_unreadable", f"{type(exc).__name__}: {exc}")
    try:
        event = json.loads(raw)
        if seq in stubs:
            if not isinstance(event.get("event_hash"), str):
                raise ValueError("hash-only stub without an event_hash")
            return event, event["event_hash"]
        return event, recompute_event_hash(event, seq, event.get("previous_hash", ""))
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise AnchorFailure("record_unreadable", str(exc))


class _AnchorCheck:
    def __init__(self):
        self.failed = False
        self.cannot = False
        self.supplied_roots_seen = set()

    def supplied_root(self, tsa_id, root):
        """Print, once per witness and root, that trust came from --tsa-root."""
        if (tsa_id, root.fingerprint) not in self.supplied_roots_seen:
            self.supplied_roots_seen.add((tsa_id, root.fingerprint))
            print(supplied_root_notice(tsa_id, root))

    def fail(self, line):
        print(line)
        self.failed = True

    def cannot_evaluate(self, line):
        print(line, file=sys.stderr)
        self.cannot = True


def _verify_one_anchor(seq, chain, source, record_fetch, roots_for, listed_tokens, check, label, stubs=frozenset()):
    """Verify the statement and every token stored for `seq`. Returns
    (earliest gen_time, verified witness ids) or None after reporting."""
    raw = source.get(f"{seq:020d}.json")
    if raw is None:
        check.fail(f"FAIL anchor seq={seq}: {label}statement object is missing")
        return None
    if listed_tokens is not None and hashlib.sha256(raw).hexdigest() != listed_tokens["statement_sha256"]:
        check.fail(f"FAIL anchor seq={seq}: statement does not match the manifest's digest")
        return None
    try:
        statement = parse_anchor_statement(raw)
    except AnchorFailure as exc:
        check.fail(f"FAIL anchor seq={seq}: {label}{exc}")
        return None
    head = next((h for h in statement["heads"] if h["chain"] == chain and h["seq"] == seq), None)
    if head is None:
        check.fail(f"FAIL anchor seq={seq}: {label}statement does not name chain {chain} at this sequence")
        return None
    try:
        event, recomputed = _read_record(record_fetch, seq, stubs)
    except AnchorFailure as exc:
        check.fail(f"FAIL anchor seq={seq}: {label}cannot read the anchored record ({exc.detail})")
        return None
    if seq in stubs:
        print(f"NOTICE anchor seq={seq}: the anchored record is a hash-only stub; its event_hash is the one the "
              f"manifest signs and the chain links, not recomputed")
    if head["event_hash"] != recomputed or event.get("event_hash") != recomputed:
        check.fail(
            f"FAIL anchor seq={seq}: {label}anchored head event_hash does not match the record "
            f"(anchored {head['event_hash'][:16]}…, record {recomputed[:16]}…) — "
            f"the record changed after it was anchored"
        )
        return None
    imprint = anchor_imprint(raw)
    if listed_tokens is not None:
        tsa_ids = sorted(listed_tokens["tokens"])
    else:
        tsa_ids = sorted({m.group(2) for m in map(_ANCHOR_TOKEN_NAME.fullmatch, source.list_names())
                          if m and int(m.group(1)) == seq})
    if not tsa_ids:
        check.fail(f"FAIL anchor seq={seq}: {label}no witness token")
        return None
    gen_times, witnesses = [], []
    for tsa_id in tsa_ids:
        token = source.get(f"{seq:020d}.{tsa_id}.tsr")
        if token is None:
            check.fail(f"FAIL anchor seq={seq} tsa={tsa_id}: {label}token object is missing")
            continue
        listed = listed_tokens["tokens"][tsa_id] if listed_tokens is not None else None
        if listed is not None and hashlib.sha256(token).hexdigest() != listed["sha256"]:
            check.fail(f"FAIL anchor seq={seq} tsa={tsa_id}: token does not match the manifest's digest")
            continue
        roots = roots_for(tsa_id)
        if roots is None:
            check.cannot_evaluate(
                f"ERROR: anchor seq={seq} tsa={tsa_id}: no trust root for this witness; "
                f"pass --tsa-root {tsa_id}=FILE")
            continue
        try:
            result = verify_tsa_token(token, imprint, roots)
        except AnchorFailure as exc:
            if exc.code == "malformed":
                check.cannot_evaluate(f"ERROR: anchor seq={seq} tsa={tsa_id}: token cannot be parsed ({exc.detail})")
            else:
                check.fail(f"FAIL anchor seq={seq} tsa={tsa_id}: {label}{exc}")
            continue
        if listed is not None and listed["gen_time"] != _iso(result["gen_time"]):
            check.fail(f"FAIL anchor seq={seq} tsa={tsa_id}: manifest gen_time does not match the token")
            continue
        if result["root"].supplied:
            check.supplied_root(tsa_id, result["root"])
        gen_times.append(result["gen_time"])
        witnesses.append(f"{tsa_id} {_iso(result['gen_time'])} {result['signature_algorithm']}")
    if not gen_times or len(witnesses) != len(tsa_ids):
        return None
    return min(gen_times), witnesses


def supplied_root_notice(tsa_id, root):
    return (f"NOTICE: anchor tokens from witness {tsa_id} verified through a root supplied with --tsa-root, "
            f"not one pinned in this verifier: {root.name} SHA-256 {root.fingerprint}. Trusting it was "
            f"the reviewer's choice; check that fingerprint against the witness's published root.")


def records_clock_ahead(covering, lo, record_epoch):
    """Records whose own timestamp is more than ANCHOR_CLOCK_TOLERANCE_SECONDS
    after the genTime of the earliest anchor covering them. `covering` is
    [(anchor_seq, earliest genTime)] for the verified anchors; an anchor at S
    covers lo..S. `record_epoch(seq)` returns the record's time or raises
    ValueError. Returns (count ahead, first (seq, record time, genTime) or
    None, count of records whose time could not be read)."""
    if not covering:
        return 0, None, 0
    covering = sorted(covering)
    ahead, first, unreadable = 0, None, 0
    earliest = float("inf")
    index = len(covering) - 1
    for seq in range(covering[-1][0], lo - 1, -1):
        while index >= 0 and covering[index][0] >= seq:
            earliest = min(earliest, covering[index][1])
            index -= 1
        try:
            when = record_epoch(seq)
        except ValueError:
            unreadable += 1  # Deliberately counted, not failed — the chain check judges the record
            continue
        if when > earliest + ANCHOR_CLOCK_TOLERANCE_SECONDS:
            ahead += 1
            first = (seq, when, earliest)
    return ahead, first, unreadable


def _check_anchoring_shape(listed, seals):
    """Raise ValueError unless every listed anchor and seal has the fields
    and types the 1.1 schema defines (a pack may be checked without it)."""
    def is_seq(v):
        return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _JSON_SAFE_MAX

    def is_hex(v):
        return isinstance(v, str) and _EVENT_HASH_RE.fullmatch(v) is not None

    seen = set()
    for a in listed:
        if not is_seq(a["seq"]) or a["seq"] in seen:
            raise ValueError("anchor seq")
        seen.add(a["seq"])
        if not isinstance(a["statement"]["key"], str) or not is_hex(a["statement"]["sha256"]):
            raise ValueError("anchor statement")
        if not isinstance(a["tokens"], dict) or not a["tokens"]:
            raise ValueError("anchor tokens")
        for tsa_id, token in a["tokens"].items():
            if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", tsa_id) or not is_hex(token["sha256"])
                    or not isinstance(token["gen_time"], str)):
                raise ValueError("anchor token")
    for seal in seals:
        if (not is_seq(seal["seq"]) or not is_hex(seal["event_hash"])
                or seal["action_type"] not in ("audit_anchoring_disabled", "audit_anchoring_misconfigured")):
            raise ValueError("seal")


def verify_anchors(manifest, record_fetch, source, roots_for, record_times=None):
    """Verify the manifest's chain-head anchors. Returns PASSED, FAILED or
    CANNOT_EVALUATE and prints the coverage report. `record_times` (seq ->
    epoch, from timestamp_recording_fetcher) saves re-fetching records the
    chain walk already read."""
    version = manifest.get("schema_version", "1.0")
    if version == "1.0":
        print("ANCHORS: none (manifest 1.0 predates anchoring)")
        return PASSED
    check = _AnchorCheck()
    anchoring = manifest.get("anchoring")
    try:
        chains = anchoring["chains"]
        if anchoring["state"] not in ("anchored", "partially_anchored", "unanchored") or len(chains) != 1:
            raise ValueError("anchoring state or chains")
        entry = chains[0]
        chain = entry["chain"]
        if entry["reason"] not in ("anchored", "disabled", "misconfigured", "no_anchors_found"):
            raise ValueError("anchoring reason")
        listed = sorted(entry["anchors"], key=lambda a: a["seq"])
        seals = entry["seals"]
        _check_anchoring_shape(listed, seals)
        tail = entry["unanchored_tail"]
        if tail is not None and (set(tail) != {"from_seq", "to_seq"}
                                 or not all(isinstance(tail[k], int) for k in tail)):
            raise ValueError("unanchored_tail")
        through = entry["anchored_through_seq"]
        if through is not None and (isinstance(through, bool) or not isinstance(through, int)):
            raise ValueError("anchored_through_seq")
        lo, hi = int(manifest["from_sequence"]), int(manifest["to_sequence"])
    except (KeyError, TypeError, ValueError) as exc:
        print(f"ERROR: manifest anchoring section is malformed ({exc})", file=sys.stderr)
        return CANNOT_EVALUATE
    if chain != chain_for_prefix(manifest.get("prefix", "")):
        check.fail(f"FAIL anchoring: chain {chain} does not match the manifest prefix {manifest.get('prefix')!r}")
        return FAILED
    if source is None and (listed or anchoring["state"] != "unanchored"):
        print("ERROR: anchors need a records directory (--records DIR) or --bucket", file=sys.stderr)
        return CANNOT_EVALUATE
    try:
        return _verify_listed_and_found(anchoring, entry, listed, seals, (lo, hi), record_fetch, source,
                                        roots_for, check, record_times or {}, frozenset(manifest_stubs(manifest)))
    except OSError as exc:
        print(f"ERROR: cannot read the anchor objects ({exc})", file=sys.stderr)
        return CANNOT_EVALUATE


def _verify_listed_and_found(anchoring, entry, listed, seals, window, record_fetch, source, roots_for, check,
                             record_times, stubs=frozenset()):
    chain, reason = entry["chain"], entry["reason"]
    lo, hi = window
    covered = []
    covering = []
    listed_seqs = set()
    for a in listed:
        seq = a["seq"]
        listed_seqs.add(seq)
        if not lo <= seq <= hi:
            check.fail(f"FAIL anchor seq={seq}: listed anchor is outside the pack window {lo}..{hi}")
            continue
        if a["statement"]["key"] != f"anchors/{chain}/{seq:020d}.json":
            check.fail(f"FAIL anchor seq={seq}: statement key does not match the anchor layout")
            continue
        listed_tokens = {"statement_sha256": a["statement"]["sha256"], "tokens": a["tokens"]}
        result = _verify_one_anchor(seq, chain, source, record_fetch, roots_for, listed_tokens, check, "", stubs)
        if result is not None:
            covered.append(seq)
            covering.append((seq, result[0]))
            witness_count = (len(result[1]), len(a["tokens"]))
            print(f"PASS anchor seq={seq} witnesses={len(result[1])}/{len(a['tokens'])}: "
                  + "; ".join(result[1]))

    outside = 0
    if source is not None:
        discovered = set()
        for name in source.list_names():
            m = _ANCHOR_STATEMENT_NAME.fullmatch(name) or _ANCHOR_TOKEN_NAME.fullmatch(name)
            if m:
                discovered.add(int(m.group(1)))
        for seq in sorted(discovered - listed_seqs):
            if not lo <= seq <= hi:
                outside += 1
                continue
            result = _verify_one_anchor(seq, chain, source, record_fetch, roots_for, None, check,
                                        "discovered, not listed: ", stubs)
            if result is not None:
                print(f"NOTICE anchor seq={seq}: not listed in the manifest; found and verified "
                      f"({'; '.join(result[1])})")
        if outside:
            print(f"NOTICE: {outside} anchor(s) outside this pack's window {lo}..{hi} were not judged")

    seal_notes = []
    for seal in seals:
        try:
            event, recomputed = _read_record(record_fetch, seal["seq"], stubs)
        except AnchorFailure as exc:
            check.fail(f"FAIL anchoring seal seq={seal['seq']}: cannot read the record ({exc.detail})")
            continue
        # A seal shipped as a hash-only stub is checked by its hash;
        # its action type is the manifest's.
        if seal["seq"] in stubs:
            if recomputed != seal["event_hash"]:
                check.fail(f"FAIL anchoring seal seq={seal['seq']}: the hash-only stub is not the listed seal")
            else:
                seal_notes.append(_seal_note(seal['action_type'], seal['seq']) + " (hash-only stub)")
            continue
        action = (event.get("admin_action") or {}).get("action_type")
        if (recomputed != seal["event_hash"] or event.get("event_hash") != recomputed
                or event.get("event_kind") != "admin_action" or action != seal["action_type"]):
            check.fail(f"FAIL anchoring seal seq={seal['seq']}: the record is not the listed seal")
            continue
        seal_notes.append(_seal_note(action, seal['seq']))

    anchored_through = max(covered) if covered else None
    state = ("unanchored" if anchored_through is None
             else "anchored" if anchored_through >= hi else "partially_anchored")
    seal_actions = {s["action_type"] for s in seals}
    expected_reason = ("anchored" if listed
                       else "disabled" if "audit_anchoring_disabled" in seal_actions
                       else "misconfigured" if "audit_anchoring_misconfigured" in seal_actions
                       else "no_anchors_found")
    if not check.failed and not check.cannot:
        tail = entry.get("unanchored_tail")
        declared_tail = (tail["from_seq"], tail["to_seq"]) if tail else None
        actual_tail = None if anchored_through is not None and anchored_through >= hi else (
            (anchored_through + 1 if anchored_through is not None else lo), hi)
        if (anchoring["state"] != state or entry.get("anchored_through_seq") != anchored_through
                or declared_tail != actual_tail or reason != expected_reason):
            check.fail("FAIL anchoring: the manifest's anchoring summary does not match the anchors "
                       f"(declared {anchoring['state']}/{reason}, verified {state}/{expected_reason})")
    if check.failed:
        return FAILED
    if check.cannot:
        return CANNOT_EVALUATE
    def record_epoch(seq):
        if seq in record_times:
            return record_times[seq]
        try:
            return _epoch_of_record(json.loads(record_fetch(seq)))
        except Exception as exc:  # An unreadable record is counted as unchecked; the chain check fails it
            raise ValueError(str(exc))

    ahead, first, unreadable = records_clock_ahead(covering, lo, record_epoch)
    if ahead:
        seq, when, gen_time = first
        print(f"NOTICE: {ahead} record(s) carry a timestamp more than {ANCHOR_CLOCK_TOLERANCE_SECONDS // 60} min "
              f"after the anchor covering them (first seq={seq}: record {_iso(when)}, anchor {_iso(gen_time)})")
    if unreadable:
        print(f"NOTICE: the clock of {unreadable} anchored record(s) could not be read and was not compared")
    # One status line: what an anchor does and does not show is in SPEC §6.1.
    if state == "unanchored":
        line = "ANCHORS: none" + (f" ({'; '.join(seal_notes)})" if seal_notes else "")
    else:
        line = (f"ANCHORS OK: verified through seq={anchored_through}, "
                f"{witness_count[0]}/{witness_count[1]} witnesses")
        if state == "partially_anchored":
            line += f"; seq={anchored_through + 1}..{hi} not yet anchored"
        if seal_notes:
            line += "; " + "; ".join(seal_notes)
    print(line)
    return PASSED


def _seal_note(action_type, seq):
    what = "turned off" if action_type == "audit_anchoring_disabled" else "misconfigured"
    return f"anchoring {what} at seq={seq}"


def manifest_schema_version_error(manifest):
    """None when this verifier understands the manifest's schema_version
    (a manifest without one predates the field and reads as 1.0), else the
    message to print before exiting 2."""
    version = manifest.get("schema_version", "1.0")
    if version in SUPPORTED_MANIFEST_SCHEMA_VERSIONS:
        return None
    return (f"manifest schema_version {version!r} is not one this verifier supports "
            f"({', '.join(SUPPORTED_MANIFEST_SCHEMA_VERSIONS)}). Re-run with an updated verifier.")


def manifest_evidence_class_error(manifest):
    """None when the manifest's evidence label is where its version says
    (exactly in 1.4) and is one this verifier reads, else the
    message to print before exiting 2. A label is never ignored: an unknown
    one, a 1.4 manifest without one, or one on an earlier version cannot be
    evaluated."""
    version = manifest.get("schema_version", "1.0")
    label = manifest.get("evidence_class")
    # A 1.5 (stripped) pack carries the label when it has one.
    if version == "1.5" and "evidence_class" not in manifest:
        return None
    if version not in ("1.4", "1.5"):
        if "evidence_class" in manifest:
            return f"manifest {version} carries an evidence_class, which only 1.4 and 1.5 define"
        return None
    if label in EVIDENCE_CLASSES:
        return None
    return (f"manifest evidence_class {label!r} is not one this verifier reads "
            f"({', '.join(EVIDENCE_CLASSES)}). Re-run with an updated verifier.")


def evidence_class_suffix(manifest):
    """The label every verdict line carries for a 1.4 pack, else ''."""
    label = manifest.get("evidence_class")
    return f" [evidence class: {label}]" if label in EVIDENCE_CLASSES else ""


def stubs_problem(manifest):
    """None when a 1.5 manifest's `stubs` is absent, or lists
    distinct sequences of the pack's events in order, each with a reason this
    verifier reads and a field path; else the problem."""
    stubs = manifest.get("stubs")
    if stubs is None:
        return None
    if not isinstance(stubs, list) or not stubs:
        return "manifest 1.5 stubs is not a non-empty list"
    listed = {e.get("sequence") for e in manifest.get("events", []) if isinstance(e, dict)}
    previous = None
    for stub in stubs:
        if not isinstance(stub, dict) or set(stub) != {"sequence", "reason", "field"}:
            return "manifest 1.5 stubs entry is not {sequence, reason, field}"
        seq = stub["sequence"]
        if isinstance(seq, bool) or not isinstance(seq, int) or seq not in listed:
            return f"manifest 1.5 stub sequence {seq!r} is not a sequence of this pack's events"
        if previous is not None and seq <= previous:
            return "manifest 1.5 stubs are not distinct sequences in order"
        previous = seq
        if stub["reason"] not in STUB_REASONS:
            return (f"manifest 1.5 stub reason {stub['reason']!r} is not one this verifier reads "
                    f"({', '.join(STUB_REASONS)}). Re-run with an updated verifier.")
        if not isinstance(stub["field"], str) or not stub["field"]:
            return "manifest 1.5 stub field must be a non-empty string"
    return None


def manifest_content_error(manifest):
    """None when the manifest's content claim is where its version
    says (exactly in 1.5) and is the stripped profile this verifier reads,
    else the message to print before exiting 2. A claim is never ignored: an
    unknown content value, a removed-field list that is not this verifier's,
    a malformed stub list, or the fields on an earlier version cannot be
    evaluated."""
    version = manifest.get("schema_version", "1.0")
    present = [k for k in ("content", "removed_fields", "stubs") if k in manifest]
    if version != "1.5":
        if present:
            return f"manifest {version} carries {', '.join(present)}, which only 1.5 defines"
        return None
    if manifest.get("content") != CONTENT_STRIPPED:
        return (f"manifest 1.5 content {manifest.get('content')!r} is not one this verifier reads "
                f"({CONTENT_STRIPPED!r}). Re-run with an updated verifier.")
    removed = manifest.get("removed_fields")
    if (not isinstance(removed, list) or not all(isinstance(f, str) for f in removed)
            or len(set(removed)) != len(removed) or set(removed) != set(STRIPPED_FIELDS)):
        return (f"manifest 1.5 removed_fields {removed!r} is not the stripped profile this verifier reads "
                f"({', '.join(STRIPPED_FIELDS)}). Re-run with an updated verifier.")
    return stubs_problem(manifest)


def pack_is_stripped(manifest):
    """Whether the manifest says its records are content-stripped."""
    return manifest.get("schema_version") == "1.5" and manifest.get("content") == CONTENT_STRIPPED


def manifest_stubs(manifest):
    """Sequence -> (reason, field) of every hash-only stub a
    stripped pack lists; empty for any other pack."""
    if not pack_is_stripped(manifest) or not isinstance(manifest.get("stubs"), list):
        return {}
    return {s["sequence"]: (s["reason"], s["field"]) for s in manifest["stubs"] if isinstance(s, dict)}


def content_suffix(manifest):
    """What every verdict line of a stripped pack carries, else ''."""
    if not pack_is_stripped(manifest):
        return ""
    stubs = len(manifest_stubs(manifest))
    if stubs:
        return f" [content: stripped; {stubs} hash-only stub{'s' if stubs != 1 else ''}]"
    return " [content: stripped]"


def content_lines(manifest):
    """The lines printed before the records of a stripped pack."""
    if not pack_is_stripped(manifest):
        return []
    lines = [
        "CONTENT: stripped. This is a content-stripped pack: captured content and personal data were removed "
        f"from every record ({', '.join(STRIPPED_FIELDS)}). Each record keeps every field its hash covers, so "
        "the chain is verified from the sealed digests; the removed content itself cannot be shown."
    ]
    stubs = manifest_stubs(manifest)
    if stubs:
        lines.append(
            f"STUBS: {len(stubs)} record(s) cannot be stripped and still verify, and ship as hash-only stubs "
            f"({', '.join(STUB_FIELDS)}; nothing of the body). The chain is linked through each without "
            f"recomputing its hash.")
    return lines


def _record_path(event, path):
    """(present, value) of a dotted record path (`a` or `a.b`)."""
    node = event
    for part in path.split('.'):
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def stripped_record_problems(event):
    """What a record in a stripped pack carries that the stripped
    profile removes or withholds. Any is a contradiction of the signed
    content claim: the pack cannot be evaluated as what it says it is."""
    problems = []
    for path in STRIPPED_FIELDS:
        if _record_path(event, path)[0]:
            problems.append(f"the manifest says content stripped, and the record carries {path}")
    for path in WITHHELD_FIELDS:
        present, value = _record_path(event, path)
        if present and value is not None:
            problems.append(f"the manifest says content stripped, and the record carries {path}, a personal "
                            f"identifier the stripped profile withholds")
    return problems


def load_tsa_roots(specs):
    """The pinned public-witness roots plus every --tsa-root ID=FILE."""
    roots = load_pinned_tsa_roots()
    for spec in specs:
        tsa_id, sep, file_name = spec.partition("=")
        if not sep or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", tsa_id) or not file_name:
            raise ValueError(f"{spec!r} is not ID=FILE with a valid witness id")
        extra = load_tsa_roots_pem(tsa_id, Path(file_name).read_text(encoding="ascii"))
        roots.setdefault(tsa_id, []).extend(extra)
    return roots


def combine_with_anchor_status(chain_status, anchor_status):
    """Fold the anchor verdict into the chain verdict: a failure of either is
    a failure; otherwise a check that could not be evaluated wins."""
    if FAILED in (chain_status, anchor_status):
        return FAILED
    if CANNOT_EVALUATE in (chain_status, anchor_status):
        return CANNOT_EVALUATE
    return chain_status


def expected_signer(identity_arg, issuer_arg):
    """(identity, issuer, supplied) a signed pack is checked against, from
    --certificate-identity and --certificate-oidc-issuer (None when not given).
    No identity: the Meilynx signing workflow, and a per-tenant pack then
    cannot be evaluated. An email identity with no issuer is the per-tenant
    class, whose issuer is Google's; any other identity keeps the workflow's
    issuer. The issuer is still compared exactly with the certificate's."""
    supplied = identity_arg is not None
    identity = identity_arg if supplied else PINNED_SIGNER_IDENTITY
    if issuer_arg is not None:
        issuer = issuer_arg
    elif supplied and "@" in identity and "://" not in identity:
        issuer = GOOGLE_OIDC_ISSUER
    else:
        issuer = PINNED_OIDC_ISSUER
    return identity, issuer, supplied


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
    identity, issuer, supplied = expected_signer(args.certificate_identity, args.certificate_oidc_issuer)
    if issuer == GOOGLE_OIDC_ISSUER:
        print(f"NOTE: expecting the per-tenant signer {identity} (--certificate-identity), issuer {issuer}. "
              f"Compare it with the signer identity the evidence holder published for this project; "
              f"the pack cannot vouch for its own signer.")
    elif identity != PINNED_SIGNER_IDENTITY:
        print(f"NOTE: expecting signer identity {identity} (--certificate-identity). "
              f"Packs signed by the Meilynx signing workflow carry {PINNED_SIGNER_IDENTITY}.")

    def read_sibling(name):
        path = manifest_path.parent / name
        return path.read_bytes() if path.is_file() else None

    try:
        signer = check_pack_signature(
            manifest, manifest_bytes, read_sibling, identity, issuer, trust, identity_supplied=supplied,
        )
    except SignerIdentityRequired as exc:
        print(
            f"ERROR: this pack is signed by a per-tenant signer ({', '.join(exc.identities) or 'no identity'}, "
            f"issuer {GOOGLE_OIDC_ISSUER}). Its signature checks out, but whose pack it is can only be "
            f"established against the signer identity the evidence holder published for the project. "
            f"Re-run with --certificate-identity <that identity>.",
            file=sys.stderr,
        )
        return CANNOT_EVALUATE
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
    print(f"SIGNATURE OK: manifest.json is signed by {signer['identity']}"
          + (" (per-tenant signer, the identity you supplied)" if signer.get("per_tenant") else ""))
    print(f"  OIDC issuer: {signer['issuer']}")
    print(f"  logged in {signer['log_url'] or 'the transparency log'} at "
          f"{_utc(signer['integrated_time'])} (log index {signer['log_index']})")
    return PASSED


# contracts/control-plane-chain-v1.json, written by the control plane:
# (stored record text, event_hash), one chain from genesis. A drift catcher
# in the crate (mei3033_control_plane_chain.rs) holds these to the contract.
_CONTROL_PLANE_V1_VECTORS = (
    ('{"actor_user_id":"11111111-2222-4333-8444-555555555555","correlation_id":"c04e6a8b-0d1f-4a3c-8e5b-7d9f1b3d5f70","event_hash":"e8e8c864c95e924a25a25c79876f6740179ddc0cc629c94cc84ba0f0d42124f4","event_id":"2c4e6a8b-0d1f-4a3c-8e5b-7d9f1b3d5f70","event_kind":"mcp_approval.released","occurred_at":"2026-10-01T09:01:00.1234567Z","payload":{"actor_role":"member","actor_user_id":"11111111-2222-4333-8444-555555555555","approval_id":"0a0b0c0d-0e0f-4101-8202-030405060708","evidence_record_id":"9f8e7d6c-5b4a-4392-8180-706050403020","hold_id":"hold-77777777777777777777777777777777","reason":"rbac_require_approval_hold:rule-42","status":"Released","tool_name":"crm__send_client_email","upstream_slug":"crm-prod","virtual_server":"crm"},"previous_hash":"c2989403cf897daccd825cc41377b804343c5a4851eac1daf32b58eb1fa4edf8","project_id":"7d1c0b6a-5e4f-4a3b-9c2d-1e0f9a8b7c6d","schema_version":"v1","sequence_number":0,"target_resource_id":"0a0b0c0d-0e0f-4101-8202-030405060708"}',
     'e8e8c864c95e924a25a25c79876f6740179ddc0cc629c94cc84ba0f0d42124f4'),
    ('{"actor_user_id":null,"correlation_id":"c05f7b9c-1e2a-4b4d-9f6c-8e0a2c4e6a81","event_hash":"8dd16459c459840af14f12b0a9e3647724cdb0c85592024b4027dade8849bfae","event_id":"3d5f7b9c-1e2a-4b4d-9f6c-8e0a2c4e6a81","event_kind":"mcp_approval.expired","occurred_at":"2026-10-02T09:00:30.0000000Z","payload":{"actor_role":null,"actor_user_id":null,"approval_id":"1a1b1c1d-1e1f-4111-8212-131415161718","evidence_record_id":"9f8e7d6c-5b4a-4392-8180-706050403020","expires_at_utc":"2026-10-02T09:00:00.0000000Z","hold_id":"hold-88888888888888888888888888888888","reason":"rbac_require_approval_hold:rule-42","requested_at_utc":"2026-10-01T09:00:00.0000000Z","status":"Expired","tool_name":"crm__send_client_email","trigger":"sweep","upstream_slug":"crm-prod","virtual_server":"crm"},"previous_hash":"e8e8c864c95e924a25a25c79876f6740179ddc0cc629c94cc84ba0f0d42124f4","project_id":"7d1c0b6a-5e4f-4a3b-9c2d-1e0f9a8b7c6d","schema_version":"v1","sequence_number":1,"target_resource_id":"1a1b1c1d-1e1f-4111-8212-131415161718"}',
     '8dd16459c459840af14f12b0a9e3647724cdb0c85592024b4027dade8849bfae'),
    ('{"actor_user_id":"11111111-2222-4333-8444-555555555555","correlation_id":"c06a8c0d-2f3b-4c5e-8a7d-9f1b3d5f7b92","event_hash":"a574db394c58e51d08878473592f27c981137d70d8afa3dc9eacc48283eebc09","event_id":"4e6a8c0d-2f3b-4c5e-8a7d-9f1b3d5f7b92","event_kind":"supervisory-review.decision_recorded","occurred_at":"2026-10-03T14:30:00.0000001Z","payload":{"Apple":2,"_under":3,"banana":1,"decision":"approve","label":"Revisão — “quoted” \\\\ back\\nslash\\t\\u0001 😀 \x7f","notes_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","été":4,"😀smile":6,"～wave":5},"previous_hash":"8dd16459c459840af14f12b0a9e3647724cdb0c85592024b4027dade8849bfae","project_id":"7d1c0b6a-5e4f-4a3b-9c2d-1e0f9a8b7c6d","schema_version":"v1","sequence_number":2,"target_resource_id":"5f7b9d1e-3a4c-4d6f-9b8e-0a2c4e6a8ca3"}',
     'a574db394c58e51d08878473592f27c981137d70d8afa3dc9eacc48283eebc09'),
    ('{"actor_user_id":"11111111-2222-4333-8444-555555555555","correlation_id":"c07b9d1e-3a4c-4d6f-9b8e-0a2c4e6a8ca4","event_hash":"7365bfb06edeae54659f7d56c299564fe8bcb75894cefdd3f1008cd39b8186a9","event_id":"5f7b9d1e-3a4c-4d6f-9b8e-0a2c4e6a8ca4","event_kind":"compliance-report.generated","occurred_at":"2026-10-04T00:00:00.0000000Z","payload":{"decimal":1.5,"decimal_small":0.00001,"double_half":0.5,"double_integral":3,"double_large":1E+20,"double_small":1E-05,"int":42,"long":9223372036854775807,"neg":-7,"neg_zero":0,"nested":{"arr":[1,2.5,null,true,false,"x"],"empty_arr":[],"empty_obj":{}}},"previous_hash":"a574db394c58e51d08878473592f27c981137d70d8afa3dc9eacc48283eebc09","project_id":"7d1c0b6a-5e4f-4a3b-9c2d-1e0f9a8b7c6d","schema_version":"v1","sequence_number":3,"target_resource_id":"6a8c0e2f-4b5d-4e7a-8c9f-1b3d5f7b9db5"}',
     '7365bfb06edeae54659f7d56c299564fe8bcb75894cefdd3f1008cd39b8186a9'),
    ('{"actor_user_id":null,"correlation_id":"c08c0e2f-4b5d-4e7a-8c9f-1b3d5f7b9db6","event_hash":"eabf6b518391ea65e74e0edccb8809ba1fd1c99303e6369d0a9aec194761e789","event_id":"6a8c0e2f-4b5d-4e7a-8c9f-1b3d5f7b9db6","event_kind":"proxy.key_rotated","occurred_at":"2026-05-08T12:00:00.0000000Z","payload":null,"previous_hash":"7365bfb06edeae54659f7d56c299564fe8bcb75894cefdd3f1008cd39b8186a9","project_id":null,"schema_version":"v1","sequence_number":4,"target_resource_id":"7b9d1f3a-5c6e-4f8b-9d0a-2c4e6a8c0ec7"}',
     'eabf6b518391ea65e74e0edccb8809ba1fd1c99303e6369d0a9aec194761e789'),
)


def control_plane_self_test():
    """The control-plane chain: the cross-language vectors, the
    chain walk, the fail modes (a number rewritten to an equal value, a
    missing record, an unpublished schema_version, a malformed section) and
    each receipt's anchor against the chain."""
    ok = True
    sink = []

    def check(label, passed, what, detail=''):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}: {what}")
        if not passed:
            if detail:
                print(detail, file=sys.stderr)
            ok = False

    for i, (text, expected) in enumerate(_CONTROL_PLANE_V1_VECTORS):
        got = control_plane_event_hash_v1(load_control_plane_record(text.encode('utf-8')))
        check(f'cp1.{i}', got == expected, f"control-plane vector {i} recomputes to its event_hash",
              f"got {got}, want {expected}")

    def manifest_for(texts, version='1.3'):
        records = [load_control_plane_record(t.encode('utf-8')) for t in texts]
        return {'schema_version': version, 'control_plane': {
            'chain_family': 'control-plane', 'prefix': 'control-plane/', 'hash_algorithm': 'SHA-256',
            'hash_version': 'v1', 'genesis_hash': genesis_hash(), 'verified': True,
            'records_checked': len(records),
            'events': [{'sequence': n, 'event_id': r['event_id'], 'stored_event_hash': r['event_hash'],
                        'recomputed_event_hash': r['event_hash']} for n, r in enumerate(records)]}}

    def walk(texts, manifest=None, missing=()):
        def fetch(seq):
            if seq in missing:
                raise FileNotFoundError(f"no control-plane record {seq}")
            return texts[seq].encode('utf-8')
        sink.clear()
        return verify_control_plane_chain(fetch, manifest or manifest_for(texts), sink.append)

    texts = [t for t, _ in _CONTROL_PLANE_V1_VECTORS]
    passed, records = walk(texts)
    check('cp2', passed and len(records) == len(texts) and any(l.startswith('CONTROL-PLANE OK') for l in sink),
          "the five vectors walk as one chain from genesis", '\n'.join(sink))

    rewritten = list(texts)
    rewritten[3] = rewritten[3].replace('"double_small":1E-05', '"double_small":0.00001')
    passed, _ = walk(rewritten, manifest_for(texts))
    check('cp3', not passed and any('control-plane seq=3: hash mismatch' in l for l in sink),
          "a number rewritten to an equal value fails at its record", '\n'.join(sink))

    passed, _ = walk(texts, missing=(2,))
    check('cp4', not passed and any('control-plane seq=2: record unreadable' in l for l in sink),
          "a missing control-plane record fails the walk", '\n'.join(sink))

    v2 = json.loads(texts[0])
    v2['schema_version'] = 'v2'
    passed, _ = walk([json.dumps(v2)] + texts[1:], manifest_for(texts))
    check('cp5', not passed and any("schema_version 'v2' is not a published control-plane preimage" in l
                                    for l in sink),
          "an unpublished schema_version fails", '\n'.join(sink))

    no_section = {'schema_version': '1.3'}
    stray = dict(manifest_for(texts), schema_version='1.2')
    wrong_prefix = manifest_for(texts)
    wrong_prefix['control_plane']['prefix'] = 'audit/'
    check('cp6', all(control_plane_manifest_problem(m) for m in (no_section, stray, wrong_prefix))
          and control_plane_manifest_problem(manifest_for(texts)) is None,
          "a control_plane section is required in 1.3, refused elsewhere, and must name control-plane/")

    _, records = walk(texts)
    released = load_control_plane_record(texts[0].encode('utf-8'))
    receipts = {
        7: {'receipt_id': 'r-match', 'cp_anchor_event_id': released['event_id'],
            'cp_anchor_event_hash': released['event_hash']},
        8: {'receipt_id': 'r-mismatch', 'cp_anchor_event_id': released['event_id'],
            'cp_anchor_event_hash': 'f' * 64},
        9: {'receipt_id': 'r-outside', 'cp_anchor_event_id': 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
            'cp_anchor_event_hash': 'e' * 64},
    }
    failures, warnings, lines = receipt_anchor_findings(receipts, records)
    check('cp7', len(failures) == 1 and 'decision receipt r-mismatch' in failures[0]
          and len(warnings) == 1 and warnings[0].startswith('WARN receipt_anchor_outside_pack seq=9')
          and lines == ['RECEIPT ANCHOR OK seq=7 receipt=r-match control-plane seq=0'],
          "a receipt anchor matches, mismatches, or lies outside the pack",
          f"{failures}\n{warnings}\n{lines}")
    return ok

def offline_self_test():
    """Exercise the offline (`--records`) path end to end on a synthetic
    two-record v1 chain: a clean chain verifies, a one-byte tamper to the
    first record's token count fails verification, and a missing record is a
    failure. Runs with no network and no Google client library, so a
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

        # Tamper: change one hashed field of record 0 after the fact. Its
        # recomputed hash no longer matches the manifest. Which record each
        # FAIL line names is pinned by attribution_self_test (22a-22f).
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


def segment_self_test():
    """Segment objects. The range parser, the segment
    split, and the D7 verdicts on a synthetic five-record v1 chain stored as
    segments: clean, mixed, identical overlap (WARN), forked overlap (FAIL),
    gap (FAIL through the chain link), truncation (PASS on the records
    present), the manifest 1.2 object reference, and --export-records
    writing files byte-identical to per-record objects."""
    import contextlib
    import io
    import tempfile

    ok = True

    def check(label, passed, what, output=''):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}: {what}")
        if not passed and output:
            print('\n'.join(f"    | {line}" for line in output.splitlines()))
        ok = ok and passed

    def n(seq):
        return f"{seq:020d}"

    def seg(first, last):
        return f"{n(first)}-{n(last)}.seg"

    check('26a',
          record_object_range(f"{n(7)}.bin") == (7, 7)
          and record_object_range(f"{n(3)}-{n(3)}.seg") == (3, 3)
          and record_object_range(f"{n(1024)}-{n(2047)}.seg") == (1024, 2047)
          and record_object_range(f"{n(0)}-{n(1024)}.seg") is None
          and record_object_range(f"{n(5)}-{n(4)}.seg") is None
          and record_object_range(f"{n(5)}.seg") is None
          and record_object_range(f"{n(4)}-{n(5)}.bin") is None
          and record_object_range("7.bin") is None
          and record_object_range(f"{n(7)}.json") is None,
          "object names parse to ranges: <n>.bin is [n, n], <a>-<b>.seg is [a, b] with 1 to 1024 "
          "records, anything else is not a record")

    genesis = genesis_hash()
    events = []
    for seq in range(5):
        event = {
            'schema_version': 'v1',
            'sequence_number': seq,
            'timestamp_utc': f'2026-01-01T00:00:0{seq}+00:00',
            'event_id': f'evt-{seq}',
            'request_id': f'req-{seq}',
            'model_requested': 'gpt-4.1-mini',
            'action': 'allow',
            'input_tokens': 11,
            'output_tokens': 7,
            'total_tokens': 18,
            'cache_creation_input_tokens': None,
            'cache_read_input_tokens': None,
            'cached_input_tokens': None,
            'reasoning_tokens': None,
            'estimated_cost_usd': 0.000123,
            'policy_reason': 'line one\nline two',
            'previous_hash': events[-1]['event_hash'] if events else genesis,
        }
        event['event_hash'] = recompute_event_hash(event, seq, event['previous_hash'])
        events.append(event)
    raw = [json.dumps(e, separators=(',', ':')).encode('utf-8') for e in events]

    body = b''.join(r + b'\n' for r in raw[1:4])
    split_ok = split_segment(body, 1, 3) == raw[1:4]
    for bad in (body[:-1], body + raw[4] + b'\n'):
        try:
            split_segment(bad, 1, 3)
            split_ok = False
        except ValueError:
            pass
    check('26b', split_ok,
          "a segment body splits on 0x0A into records byte-identical to per-record objects (a line feed "
          "inside a string is escaped); a body that does not hold exactly its named count is malformed")

    def manifest_for(seqs, objects, version='1.2'):
        manifest = {'hash_version': 'v1', 'prefix': 'audit/self-test/', 'schema_version': version,
                    'storage_layout': 'segmented-v1', 'events': []}
        for seq in seqs:
            name = next(o for o in objects if record_object_range(o)[0] <= seq <= record_object_range(o)[1])
            manifest['events'].append({'sequence': seq, 'recomputed_event_hash': events[seq]['event_hash'],
                                       'object': {'name': name, 'index': seq - record_object_range(name)[0]}})
        return manifest

    def run(tmp, label, objects, seqs=range(5), fork=None, manifest=None, holders=None):
        """Write `objects` to a fresh records directory and verify. `fork`
        replaces one record's bytes in one object: (object name, seq)."""
        records = Path(tmp) / label
        records.mkdir()
        for name in objects:
            first, last = record_object_range(name)
            chosen = []
            for seq in range(first, last + 1):
                r = raw[seq]
                if fork == (name, seq):
                    r = r.replace(b'"input_tokens":11', b'"input_tokens":12')
                chosen.append(r)
            data = chosen[0] if name.endswith('.bin') else b''.join(r + b'\n' for r in chosen)
            (records / name).write_bytes(data)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            passed = verify_manifest_with(local_fetcher(records, report=print),
                                          manifest or manifest_for(seqs, objects), holders=holders)
        return passed, out.getvalue(), records

    with tempfile.TemporaryDirectory() as tmp:
        passed, out, records = run(tmp, 'segmented', [seg(0, 1), seg(2, 4)])
        check('26c', passed and out.count('PASS seq=') == 5, "a chain stored as segments verifies", out)

        passed, out, _ = run(tmp, 'mixed', [f"{n(0)}.bin", seg(1, 3), f"{n(4)}.bin"])
        check('26d', passed and out.count('PASS seq=') == 5,
              "a chain mixing per-record and segment objects verifies", out)

        passed, out, _ = run(tmp, 'overlap', [seg(0, 2), seg(2, 4)])
        check('26e', passed and out.count('WARN seq=2: segment_overlap') == 1 and 'FAIL' not in out,
              "a sequence held twice with identical bytes is one WARN segment_overlap, not a failure", out)

        passed, out, _ = run(tmp, 'fork', [seg(0, 2), seg(2, 4)], fork=(seg(2, 4), 2))
        check('26f', not passed and 'FAIL seq=2: record fetch error: segment_fork' in out
              and out.count('FAIL') == 1,
              "a sequence held twice with different bytes fails as segment_fork", out)

        passed, out, _ = run(tmp, 'gap', [seg(0, 1), seg(3, 4)], seqs=[0, 1, 3, 4])
        check('26g', not passed and 'FAIL seq=3: chain break' in out and out.count('FAIL') == 1,
              "a hole between segments fails: the record after it does not link to the one before", out)

        passed, out, _ = run(tmp, 'truncated', [seg(0, 1), seg(2, 3)], seqs=range(4))
        check('26h', passed and out.count('PASS seq=') == 4,
              "a chain whose segments stop early verifies on the records present", out)

        export = Path(tmp) / 'export'
        with contextlib.redirect_stdout(io.StringIO()):
            verify_manifest_with(exporting_fetcher(local_fetcher(records), export),
                                 manifest_for(range(5), [seg(0, 1), seg(2, 4)]), quiet=True)
        check('26i', all((export / record_file_name(s)).read_bytes() == raw[s] for s in range(5)),
              "--export-records splits segments into <seq>.bin files byte-identical to per-record objects")

        wrong = manifest_for(range(5), [seg(0, 1), seg(2, 4)])
        wrong['events'][3]['object'] = {'name': seg(0, 1), 'index': 1}
        del wrong['events'][4]['object']
        passed, out, _ = run(tmp, 'reference', [seg(0, 1), seg(2, 4)], manifest=wrong)
        elsewhere = manifest_for(range(5), [seg(0, 4)])
        objects = ChainRecords(lambda lo, hi: [seg(0, 1), seg(2, 4)], lambda name: b'')
        not_listed = object_reference_problem(elsewhere['events'][0], objects.holders)
        check('26j', not passed and 'FAIL seq=3: manifest object reference' in out
              and 'FAIL seq=4: manifest 1.2 entry has no object reference' in out
              and out.count('FAIL') == 2 and not_listed is not None
              and object_reference_problem(manifest_for([0], [seg(0, 1)])['events'][0], objects.holders) is None,
              "a manifest 1.2 object reference must hold its record, and in --bucket mode be listed", out)

        passed, out, records = run(tmp, 'malformed', [seg(0, 1), seg(2, 4)])
        (records / seg(2, 4)).write_bytes(raw[2] + b'\n' + raw[3] + b'\n')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            passed = verify_manifest_with(local_fetcher(records), manifest_for(range(5), [seg(0, 1), seg(2, 4)]))
        out = out.getvalue()
        check('26k', not passed and all(f'FAIL seq={s}: record fetch error: segment {seg(2, 4)} is malformed' in out
                                        for s in (2, 3, 4)),
              "a segment whose body does not hold its named count fails every record it names", out)

    layouts = (manifest_storage_layout_error({'schema_version': '1.1'}),
               manifest_storage_layout_error({'schema_version': '1.2', 'storage_layout': 'segmented-v1'}),
               manifest_storage_layout_error({'schema_version': '1.2', 'storage_layout': 'per-record'}),
               manifest_storage_layout_error({'schema_version': '1.2'}),
               manifest_storage_layout_error({'schema_version': '1.2', 'storage_layout': 'segmented-v2'}))
    check('26l', layouts[:3] == (None, None, None) and None not in layouts[3:],
          "a manifest 1.2 storage_layout is per-record or segmented-v1; absent or unknown is refused (exit 2)",
          repr(layouts))
    check('26m', 'segmented-records-v1' in VERIFIER_CAPABILITIES,
          "VERIFIER_CAPABILITIES advertises segmented-records-v1")
    return ok


def attribution_self_test():
    """Every FAIL line names the record that failed. A four-record
    v1 chain has record 1 tampered in one way per assertion. Each must print
    exactly one `FAIL seq=1` line and no FAIL for the intact record 2, whose
    previous_hash still names what the chain committed to for record 1. When
    nothing in the pack attests record 1's hash, record 2's link is reported
    as not checked, never as passed or broken."""
    import contextlib
    import io
    import tempfile

    ok = True

    def check(label, passed, what, output):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}: {what}")
        if not passed:
            print('\n'.join(f"    | {line}" for line in output.splitlines()))
        ok = ok and passed

    genesis = genesis_hash()
    events = []
    for seq in range(4):
        event = {
            'schema_version': 'v1',
            'sequence_number': seq,
            'timestamp_utc': f'2026-01-01T00:00:0{seq}+00:00',
            'event_id': f'evt-{seq}',
            'request_id': f'req-{seq}',
            'model_requested': 'gpt-4.1-mini',
            'action': 'allow',
            'input_tokens': 11,
            'output_tokens': 7,
            'total_tokens': 18,
            'cache_creation_input_tokens': None,
            'cache_read_input_tokens': None,
            'cached_input_tokens': None,
            'reasoning_tokens': None,
            'estimated_cost_usd': 0.000123,
            'previous_hash': events[-1]['event_hash'] if events else genesis,
        }
        event['event_hash'] = recompute_event_hash(event, seq, event['previous_hash'])
        events.append(event)

    def pack_manifest(with_hashes=True):
        return {
            'hash_version': 'v1',
            'prefix': 'audit/self-test/',
            'events': [
                {'sequence': ev['sequence_number'], 'stored_event_hash': ev['event_hash'],
                 'recomputed_event_hash': ev['event_hash']} if with_hashes
                else {'sequence': ev['sequence_number']}
                for ev in events
            ],
        }

    def tampered_content():
        record = dict(events[1], input_tokens=12)
        return json.dumps(record).encode('utf-8')

    def tampered_content_and_hash():
        record = dict(events[1], input_tokens=12)
        record['event_hash'] = recompute_event_hash(record, 1, record['previous_hash'])
        return json.dumps(record).encode('utf-8')

    def forged_manifest_entry():
        manifest = pack_manifest()
        manifest['events'][1].update(stored_event_hash='0' * 64, recomputed_event_hash='0' * 64)
        return manifest

    # (label, what, record 1 bytes or None when missing, manifest, record 2 unanchored)
    cases = [
        ('22a', 'a content edit to record 1', tampered_content(), pack_manifest(), False),
        ('22b', 'a content edit to record 1 with its event_hash rewritten to match',
         tampered_content_and_hash(), pack_manifest(), False),
        ('22c', "a changed manifest hash for record 1", None, forged_manifest_entry(), False),
        ('22d', 'a missing record 1', b'', pack_manifest(), False),
        ('22e', 'an unreadable record 1', b'{not json', pack_manifest(), False),
        ('22f', 'a missing record 1 with a manifest that carries no hashes', b'',
         pack_manifest(with_hashes=False), True),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        for label, what, record_one, manifest, unanchored in cases:
            records = Path(tmp) / label
            records.mkdir()
            for ev in events:
                (records / record_file_name(ev['sequence_number'])).write_bytes(json.dumps(ev).encode('utf-8'))
            if record_one == b'':
                (records / record_file_name(1)).unlink()
            elif record_one is not None:
                (records / record_file_name(1)).write_bytes(record_one)

            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                failed = not verify_manifest_with(local_fetcher(records), manifest)
            lines = out.getvalue().splitlines()
            fails = [line for line in lines if line.startswith('FAIL seq=')]
            one_fail_at_record_one = len(fails) == 1 and fails[0].startswith('FAIL seq=1:')
            if unanchored:
                successor_ok = (
                    any(line.startswith('WARN seq=2:') and 'not checked' in line for line in lines)
                    and not any(line.startswith('PASS seq=2 ') for line in lines)
                )
                verdict = "record 2's link reported as not checked"
            else:
                successor_ok = any(
                    line.startswith(f"PASS seq=2 hash={events[2]['event_hash'][:16]}... chain_ok")
                    for line in lines
                )
                verdict = 'record 2 passes'
            check(label, failed and one_fail_at_record_one and successor_ok,
                  f"{what} fails verification with exactly one FAIL line, at seq=1, and {verdict}",
                  out.getvalue())

    return ok


def receipt_self_test():
    """Decision receipts through the verification
    loop: the fail-mode tests D8 requires before a production roll, the lapsed
    half of the cross-language fixture, each evidence entry against the pack
    record it cites, and the manifest's `decision_receipts` index."""
    import contextlib
    import io

    ok = True

    def check(label, passed, what, detail=''):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}: {what}")
        if not passed:
            if detail:
                print(detail, file=sys.stderr)
            ok = False

    run_chain = 'chain_tnt_pxy_selftest_proxy_run_r1'
    genesis = genesis_hash()

    def llm(seq, prev):
        event = {
            'schema_version': 'v1', 'sequence_number': seq,
            'timestamp_utc': f'2026-10-01T10:00:0{seq}+00:00',
            'event_id': f'evt-{seq}', 'request_id': f'req-{seq}', 'model_requested': 'gpt-4.1-mini',
            'action': 'allow', 'input_tokens': 11, 'output_tokens': 7, 'total_tokens': 18,
            'estimated_cost_usd': None, 'previous_hash': prev,
        }
        event['event_hash'] = recompute_event_hash(event, seq, prev)
        return event

    def receipt_record(seq, prev, evidence, **fields):
        payload = dict(_V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD, evidence=evidence,
                       evidence_set_sha256=sha256_jcs(evidence), **fields)
        event = {
            'schema_version': 'v1.15', 'event_kind': 'decision_receipt', 'sequence_number': seq,
            'timestamp_utc': f'2026-10-01T15:00:3{seq}+00:00', 'event_id': f'evt-receipt-{seq}',
            'request_id': f'evt-receipt-{seq}', 'model_requested': '',
            'action': RECEIPT_OUTCOME_TO_ACTION[payload['outcome']],
            'input_tokens': 0, 'output_tokens': 0, 'previous_hash': prev, 'decision_receipt': payload,
        }
        event['event_hash'] = recompute_event_hash(event, seq, prev)
        return event

    def cite(event, chain, role):
        return {'chain_id': chain, 'content_digests': {}, 'event_hash': event['event_hash'],
                'event_id': event['event_id'], 'role': role, 'sequence_number': event['sequence_number']}

    def pack(prefix, evidence, index='auto', mutate=None, **fields):
        """A three-record chain (two LLM records, then a receipt citing
        `evidence(records)`) and its manifest. `index`: 'auto' lists the
        receipt, None omits the key, or a list to use verbatim."""
        first = llm(0, genesis)
        second = llm(1, first['event_hash'])
        receipt = receipt_record(2, second['event_hash'], evidence([first, second]), **fields)
        records = [first, second, receipt]
        if mutate:
            mutate(records)
        manifest = {'hash_version': 'v1', 'prefix': prefix,
                    'events': [{'sequence': r['sequence_number'], 'recomputed_event_hash': r['event_hash']}
                               for r in (first, second, receipt)]}
        if index == 'auto':
            p = receipt['decision_receipt']
            manifest['decision_receipts'] = [{'sequence': 2, 'receipt_id': p['receipt_id'],
                                              'receipt_type': p['receipt_type'], 'clock_status': p['clock_status']}]
        elif index is not None:
            manifest['decision_receipts'] = index
        raw = {r['sequence_number']: json.dumps(r).encode('utf-8') for r in records}
        return raw, manifest

    def verify(raw, manifest):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            passed = verify_manifest_with(lambda s: raw[s], manifest)
        return passed, out.getvalue()

    def lines(out, prefix):
        return [line for line in out.splitlines() if line.startswith(prefix)]

    on_chain = lambda recs: [cite(recs[0], run_chain, 'ai_contribution'), cite(recs[1], run_chain, 'hold')]
    run_prefix = f'audit/{run_chain}/'

    # 28e — D8: a tampered decider, outcome, deadline or credential status fails
    # verification at the receipt record (its stored hash kept).
    caught = []
    for name, value in (('decider_user_id', '22222222-2222-4333-8444-555555555555'), ('outcome', 'rejected'),
                        ('clock_deadline_at', 1791025200), ('credential_status', 'not_required')):
        def edit(records, name=name, value=value):
            records[2]['decision_receipt'][name] = value
        raw, manifest = pack(run_prefix, on_chain, mutate=edit)
        passed, out = verify(raw, manifest)
        caught.append(not passed and any(line.startswith('FAIL seq=2:') for line in out.splitlines()))
    check('28e', all(caught), 'a tampered decider_user_id, outcome, clock_deadline_at or credential_status fails at the receipt record',
          f'caught: {caught}')

    # 28f — D8: within with the decision after the deadline (elapsed kept
    # consistent, so only the status recomputation sees it), verified without a
    # verification time, and a decider on a lapse, each named.
    base = dict(_V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD)
    late = dict(base, clock_decided_at=base['clock_deadline_at'] + 1,
                clock_elapsed_seconds=base['clock_deadline_at'] + 1 - base['clock_started_at'])
    unverified = dict(base, credential_status='verified', credential_registry='registry_id')
    lapse_with_decider = dict(base, outcome='lapsed', clock_decided_at=None, clock_elapsed_seconds=None,
                              clock_status='lapsed', issued_at=base['clock_deadline_at'] + 60)
    problems = [
        check_decision_receipt({'schema_version': 'v1.15', 'action': a, 'decision_receipt': p})
        for p, a in ((late, 'allow'), (unverified, 'allow'), (lapse_with_decider, 'block'))
    ]
    check('28f', [len(p) for p in problems] == [1, 1, 1]
          and 'clock_status' in problems[0][0] and 'credential_status verified' in problems[1][0]
          and 'names a decider' in problems[2][0],
          'within after the deadline, verified without verified_at and a lapse with a decider each fail on their own',
          f'problems: {problems}')

    # 28g — D8: decision.receipt stamped v1.14, and v1.15 on mcp.policy_decision
    # (with or without the payload), are refused.
    receipt_event = dict(schema_version='v1.15', event_kind='decision_receipt',
                         timestamp_utc='2026-10-01T15:00:31.000000Z', event_id='e', request_id='e',
                         model_requested='', action='allow', input_tokens=0, output_tokens=0,
                         decision_receipt=dict(base))
    refused = 0
    for case in (dict(receipt_event, schema_version='v1.14'),
                 dict(receipt_event, event_kind='mcp_policy_decision'),
                 dict(receipt_event, event_kind='mcp_policy_decision', decision_receipt=None)):
        try:
            recompute_event_hash(case, 9, 'b' * 64)
        except ValueError:
            refused += 1
    check('28g', refused == 3, 'decision.receipt on v1.14 and v1.15 on mcp.policy_decision are refused',
          f'refused {refused} of 3')

    # 28h — the lapsed half of the cross-language fixture (D8), paired with
    # mei2989_v1_15_lapsed_receipt_fixture_hash_pinned and the control plane.
    got = compute_event_hash_v1_15_decision_receipt(
        sequence_number=10, timestamp_utc='2026-10-03T10:01:31.000000+00:00',
        event_id='evt-receipt-2', request_id='evt-receipt-2', model_requested='', action='block',
        input_tokens=0, output_tokens=0, total_tokens=None, cache_creation_input_tokens=None,
        cache_read_input_tokens=None, cached_input_tokens=None, reasoning_tokens=None,
        estimated_cost_usd=None, previous_hash='b' * 64, receipt=_V1_15_LAPSED_RECEIPT_FIXTURE_PAYLOAD,
    )
    lapsed_event = dict(receipt_event, timestamp_utc='2026-10-03T10:01:31.000000Z', event_id='evt-receipt-2',
                        request_id='evt-receipt-2', action='block',
                        decision_receipt=dict(_V1_15_LAPSED_RECEIPT_FIXTURE_PAYLOAD))
    check('28h', got == V1_15_LAPSED_RECEIPT_FIXTURE_HASH
          and recompute_event_hash(lapsed_event, 10, 'b' * 64) == V1_15_LAPSED_RECEIPT_FIXTURE_HASH
          and not check_decision_receipt(lapsed_event),
          'v1.15 lapsed decision.receipt fixture hash matches and the lapse checks out',
          f'expected {V1_15_LAPSED_RECEIPT_FIXTURE_HASH}, got {got}')

    # 28n — a lapse means the deadline passed with no decision, so
    # a receipt that lapsed (by outcome or clock status) before its deadline
    # fails, naming both fields; one issued at or after the deadline passes.
    lapse = dict(_V1_15_LAPSED_RECEIPT_FIXTURE_PAYLOAD)
    deadline = lapse['clock_deadline_at']
    early = [check_decision_receipt({'schema_version': 'v1.15', 'action': 'block',
                                     'decision_receipt': dict(lapse, issued_at=deadline - 1)}),
             check_decision_receipt({'schema_version': 'v1.15', 'action': 'block',
                                     'decision_receipt': dict(lapse, outcome='rejected', issued_at=deadline - 1)})]
    on_time = [check_decision_receipt({'schema_version': 'v1.15', 'action': 'block',
                                       'decision_receipt': dict(lapse, issued_at=t)}) for t in (deadline, deadline + 60)]
    check('28n', all(any('lapsed before its deadline' in p and 'issued_at' in p and 'clock_deadline_at' in p for p in e)
                     for e in early) and on_time == [[], []],
          'a lapse issued before its deadline fails, naming issued_at and clock_deadline_at; one at or after it passes',
          f'early: {early}, on time: {on_time}')
    # The same through the walk: the receipt record fails, its hash intact.
    raw, manifest = pack(run_prefix, on_chain, outcome='lapsed', decider_user_id=None, decider_role=None,
                         clock_decided_at=None, clock_elapsed_seconds=None, clock_status='lapsed',
                         issued_at=deadline - 3600)
    passed, out = verify(raw, manifest)
    fails = lines(out, 'FAIL seq=2:')
    check('28n2', not passed and len(fails) == 1 and 'lapsed before its deadline' in fails[0],
          'a pack holding a lapse issued before its deadline fails at that receipt', out)

    # 28i — evidence that cites records in this pack, by their chain's own id,
    # verifies with no warning, and the index lists the receipt.
    raw, manifest = pack(run_prefix, on_chain)
    passed, out = verify(raw, manifest)
    check('28i', passed and not lines(out, 'WARN') and not lines(out, 'FAIL')
          and 'RECEIPTS INDEX OK: 1 decision receipt(s)' in out,
          'receipt evidence matching the pack records verifies with no warning', out)

    # 28j — a receipt sealed citing a record by the wrong event_hash (or
    # event_id) fails at the receipt record, naming the field. The receipt is
    # internally consistent: its evidence digest and hash were computed over
    # the wrong citation, as a control plane that cited the wrong record would.
    def wrong(field, value):
        def evidence(recs):
            entries = on_chain(recs)
            entries[1][field] = value
            return entries
        return evidence
    results = []
    for field, value in (('event_hash', '2' * 64), ('event_id', 'evt-other')):
        raw, manifest = pack(run_prefix, wrong(field, value))
        passed, out = verify(raw, manifest)
        fails = lines(out, 'FAIL seq=2:')
        results.append(not passed and len(fails) == 1 and f'evidence[1] (sequence=1) {field}' in fails[0])
    check('28j', all(results), 'a receipt citing a pack record by the wrong event_hash or event_id fails, naming the field',
          f'results: {results}')

    # 28k — entries whose records are not in this pack (another run's chain, or
    # this chain beyond the window) warn with their coordinates and verify.
    def outside(recs):
        return [dict(cite(recs[0], 'chain_tnt_pxy_selftest_proxy_run_r0', 'ai_contribution'), sequence_number=7),
                dict(cite(recs[1], run_chain, 'hold'), sequence_number=5)]
    raw, manifest = pack(run_prefix, outside)
    passed, out = verify(raw, manifest)
    warns = lines(out, 'WARN receipt_evidence_outside_pack')
    check('28k', passed and len(warns) == 2 and not lines(out, 'FAIL')
          and 'chain=chain_tnt_pxy_selftest_proxy_run_r0 sequence=7 event_id=evt-0' in warns[0]
          and f'chain={run_chain} sequence=5 event_id=evt-1' in warns[1],
          'evidence outside the pack is WARN receipt_evidence_outside_pack with its coordinates, and verifies', out)

    # 28l — the flat `audit/` chain is cited by its tenant-scoped id and is
    # checked; an entry naming no chain is in the pack only when the record at
    # its sequence carries its hash, and warns otherwise.
    tenant = lambda recs: [cite(recs[0], 'chain_tnt_pxy_selftest_proxy', 'ai_contribution'),
                           cite(recs[1], 'chain_tnt_pxy_selftest_proxy', 'hold')]
    raw, manifest = pack('audit/', tenant)
    flat_ok, flat_out = verify(raw, manifest)
    raw, manifest = pack('audit/', lambda recs: [dict(e, event_hash='3' * 64) if e['role'] == 'hold' else e
                                                 for e in tenant(recs)])
    flat_bad, _ = verify(raw, manifest)
    unnamed = lambda recs: [dict(cite(recs[0], None, 'ai_contribution'), event_id=None),
                            dict(cite(recs[1], None, 'hold'), event_id=None, event_hash='4' * 64)]
    raw, manifest = pack(run_prefix, unnamed)
    unnamed_ok, unnamed_out = verify(raw, manifest)
    unnamed_warns = lines(unnamed_out, 'WARN receipt_evidence_outside_pack')
    check('28l', flat_ok and not lines(flat_out, 'WARN') and not flat_bad and unnamed_ok
          and len(unnamed_warns) == 1 and 'chain=(not recorded) sequence=1' in unnamed_warns[0],
          'the flat chain is checked under its tenant-scoped id, and an unnamed entry is matched by its hash or warned',
          f'{flat_out}\n{unnamed_out}')

    # 28m — the manifest's decision_receipts index: an older manifest without
    # it is accepted with a note; an unlisted receipt, an extra entry, a wrong
    # field or an unknown field fails; a receipt-free pack has no key.
    p = _V1_15_DECISION_RECEIPT_FIXTURE_PAYLOAD
    entry = {'sequence': 2, 'receipt_id': p['receipt_id'], 'receipt_type': p['receipt_type'], 'clock_status': 'within'}
    outcomes = {}
    raw, manifest = pack(run_prefix, on_chain, index=None)
    outcomes['absent'], out = verify(raw, manifest)
    absent_noted = 'NOTE: the manifest has no decision_receipts index' in out
    for label, index in (('unlisted', []),
                         ('extra', [entry, dict(entry, sequence=1)]),
                         ('wrong-status', [dict(entry, clock_status='breached')]),
                         ('wrong-type', [dict(entry, receipt_type='sar-narrative-signoff')]),
                         ('unknown-field', [dict(entry, outcome='approved')]),
                         ('duplicate', [entry, entry]),
                         ('not-a-list', {'2': entry})):
        raw, manifest = pack(run_prefix, on_chain, index=index)
        outcomes[label], out = verify(raw, manifest)
        outcomes[label] = outcomes[label] or not lines(out, 'FAIL decision_receipts:')
    receipt_free = {'hash_version': 'v1', 'prefix': run_prefix, 'events': []}
    first = llm(0, genesis)
    receipt_free['events'] = [{'sequence': 0, 'recomputed_event_hash': first['event_hash']}]
    free_raw = {0: json.dumps(first).encode('utf-8')}
    free_ok, free_out = verify(free_raw, receipt_free)
    free_extra, _ = verify(free_raw, dict(receipt_free, decision_receipts=[dict(entry, sequence=0)]))
    check('28m', outcomes['absent'] and absent_noted
          and not any(v for k, v in outcomes.items() if k != 'absent')
          and free_ok and 'RECEIPT' not in free_out and 'NOTE' not in free_out and not free_extra,
          'the decision_receipts index lists every receipt and nothing else, field for field; an older manifest without it is noted',
          f'outcomes (True = passed): {outcomes}, absent noted: {absent_noted}, free: {free_ok}/{free_extra}')

    return ok


def content_self_test():
    """The v1.10 content attestation: fixture hashes paired with the
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


def tool_calls_self_test():
    """The v1.11 tool-call attestation: fixture hashes paired with
    the Rust tests, the production recompute path, the fail-closed dispatcher
    guards, the JCS tool-call digests paired with the proxy's sealer, and the
    offline content check (a record whose tool input was edited after sealing
    fails even though its hash still verifies)."""
    import tempfile

    ok = True

    def check(label, passed, detail=''):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}{': ' + detail if detail else ''}")
        ok = ok and passed

    ts = "2026-05-17T00:00:00+00:00"

    # 21a / 21b — direct fn: both tool digests, no join; then a hash_only
    # payload (stored digests absent) with the join fixture.
    got = compute_event_hash_v1_11_llm_request(
        timestamp_utc=ts, join_context=None, content=_V1_11_CONTENT_FIXTURE_PAYLOAD, **_FIXTURE,
    )
    check('21a', got == V1_11_LLM_REQUEST_FIXTURE_HASH, f'v1.11 llm_request fixture hash matches (got {got})')
    got = compute_event_hash_v1_11_llm_request(
        timestamp_utc=ts, join_context=_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD,
        content=_V1_11_HASH_ONLY_CONTENT_FIXTURE_PAYLOAD, **_FIXTURE,
    )
    check('21b', got == V1_11_LLM_REQUEST_JOIN_HASH_ONLY_FIXTURE_HASH,
          f'v1.11 llm_request fixture hash (join, hash_only) matches (got {got})')

    # 21c — the production recompute path, and v1.11 differs from v1.10 on the
    # same v1.10 fields (the tool digests are entering the preimage).
    event = dict(
        schema_version='v1.11', timestamp_utc='2026-05-17T00:00:00Z',
        event_id=_FIXTURE['event_id'], request_id=_FIXTURE['request_id'],
        model_requested=_FIXTURE['model_requested'], action=_FIXTURE['action'],
        input_tokens=_FIXTURE['input_tokens'], output_tokens=_FIXTURE['output_tokens'],
        total_tokens=_FIXTURE['total_tokens'], estimated_cost_usd=_FIXTURE['estimated_cost_usd'],
        content=dict(_V1_11_CONTENT_FIXTURE_PAYLOAD),
    )
    got = recompute_event_hash(event, _FIXTURE['sequence_number'], _FIXTURE['previous_hash'])
    check('21c', got == V1_11_LLM_REQUEST_FIXTURE_HASH and got != V1_10_LLM_REQUEST_FIXTURE_HASH,
          'verify_manifest recompute path handles v1.11 llm_request, distinct from v1.10')

    # 21d — fail closed: tool digests outside v1.11, v1.11 without the
    # captured digest, and v1.11 on a non-LLM kind.
    rejected = True
    for stale in ('v1.1', 'v1.9', 'v1.10'):
        for payload in (_V1_11_CONTENT_FIXTURE_PAYLOAD,
                        dict(_V1_10_CONTENT_FIXTURE_PAYLOAD, stored_tool_calls_sha256_jcs='7' * 64)):
            try:
                compute_event_hash_dispatch(
                    stale, 42, ts, 'e', 'r', 'm', 'Allow', 0, 0,
                    None, None, None, None, None, None, 'prev',
                    join_context=_V1_9_JOIN_CONTEXT_FIXTURE_PAYLOAD if stale == 'v1.9' else None,
                    content=payload,
                )
                rejected = False
            except ValueError:
                pass
    for content in (None, _V1_10_CONTENT_FIXTURE_PAYLOAD,
                    dict(_V1_10_CONTENT_FIXTURE_PAYLOAD, stored_tool_calls_sha256_jcs='7' * 64)):
        try:
            compute_event_hash_dispatch(
                'v1.11', 42, ts, 'e', 'r', 'm', 'Allow', 0, 0,
                None, None, None, None, None, None, 'prev', content=content,
            )
            rejected = False
        except ValueError:
            pass
    try:
        compute_event_hash_dispatch(
            'v1.11', 42, ts, 'e', 'r', 'm', 'Allow', 0, 0,
            None, None, None, None, None, None, 'prev',
            event_kind='admin.action', content=_V1_11_CONTENT_FIXTURE_PAYLOAD,
        )
        rejected = False
    except ValueError:
        pass
    check('21d', rejected,
          'tool digests outside v1.11, v1.11 without the captured digest, and v1.11 on a non-LLM kind are rejected')

    # 21e — the JCS tool-call digests match the proxy's sealer on the same calls.
    calls = json.loads(V1_11_DIGEST_FIXTURE_TOOL_CALLS_JSON)
    redacted = [dict(c, input=None) for c in calls]
    got_full, got_redacted = sha256_jcs(calls), sha256_jcs(redacted)
    check('21e', got_full == V1_11_DIGEST_FIXTURE_TOOL_CALLS and got_redacted == V1_11_DIGEST_FIXTURE_TOOL_CALLS_REDACTED,
          f'JCS tool-call digests match the proxy sealer (got {got_full} / {got_redacted})')

    # 21f / 21g / 21h — offline: a sealed v1.11 record verifies; the same
    # record with a tool input edited after sealing still hash-verifies (the
    # calls are outside the preimage) but fails the content check; and tool
    # calls added to a sealed v1.10 record are unattested and fail too.
    genesis = genesis_hash()
    empty_digest = sha256_jcs([])
    sealed = dict(
        schema_version='v1.11', sequence_number=0, timestamp_utc='2026-01-01T00:00:00+00:00',
        event_id='evt-0', request_id='req-0', model_requested='claude-opus-5-5', action='Allow',
        input_tokens=11, output_tokens=5, estimated_cost_usd=None, previous_hash=genesis,
        messages=[], response_text=None, findings=[], tool_calls=calls,
        content=dict(
            capture_policy='full',
            prompt_sha256_jcs=empty_digest,
            stored_prompt_sha256_jcs=empty_digest,
            findings_sha256_jcs=empty_digest,
            tool_calls_sha256_jcs=V1_11_DIGEST_FIXTURE_TOOL_CALLS,
            stored_tool_calls_sha256_jcs=V1_11_DIGEST_FIXTURE_TOOL_CALLS,
        ),
    )
    sealed['event_hash'] = recompute_event_hash(sealed, 0, genesis)
    manifest = {'hash_version': 'v1', 'prefix': 'audit/self-test/',
                'events': [{'sequence': 0, 'recomputed_event_hash': sealed['event_hash']}]}
    with tempfile.TemporaryDirectory() as tmp:
        records = Path(tmp) / 'records'
        records.mkdir()
        path = records / record_file_name(0)
        path.write_bytes(json.dumps(sealed, ensure_ascii=False).encode('utf-8'))
        check('21f', verify_manifest_with(local_fetcher(records), manifest, quiet=True),
              'offline verification passes a sealed v1.11 record')
        edited = json.loads(json.dumps(sealed))
        edited['tool_calls'][0]['input']['file_path'] = '/etc/passwd'
        path.write_bytes(json.dumps(edited).encode('utf-8'))
        still_hashes = recompute_event_hash(edited, 0, genesis) == sealed['event_hash']
        detected = not verify_manifest_with(local_fetcher(records), manifest, quiet=True)
        check('21g', still_hashes and detected,
              'a tool input edited after sealing is detected by the content check')

        v1_10 = dict(sealed, schema_version='v1.10', tool_calls=None,
                     content={k: v for k, v in sealed['content'].items() if 'tool_calls' not in k})
        del v1_10['tool_calls']
        v1_10['event_hash'] = recompute_event_hash(v1_10, 0, genesis)
        v1_10_manifest = {'hash_version': 'v1', 'prefix': 'audit/self-test/',
                          'events': [{'sequence': 0, 'recomputed_event_hash': v1_10['event_hash']}]}
        path.write_bytes(json.dumps(v1_10).encode('utf-8'))
        clean = verify_manifest_with(local_fetcher(records), v1_10_manifest, quiet=True)
        path.write_bytes(json.dumps(dict(v1_10, tool_calls=calls)).encode('utf-8'))
        injected = not verify_manifest_with(local_fetcher(records), v1_10_manifest, quiet=True)
        check('21h', clean and injected,
              'tool calls added to a sealed v1.10 record are reported as unattested')

    return ok


# ── Content-stripped Exchange pack: TEST-ONLY vectors ─────────────
# A five-record chain, sealed in full and then stripped the way the exporter
# strips it (exchange::strip_record): a v1.1 record with unhashed content and
# identifiers; a v1.11 record that sealed digests of its prompt, response,
# findings and tool calls; a v1.12 record whose sealed identity has asserted
# labels naming an on-behalf-of subject; a v1.2 auth.session_started whose
# hash covers the user's email, which ships as a hash-only stub; and a v1.1
# record after it, which links to the stub. TEST-ONLY: synthetic values,
# never a real chain. EXCHANGE_SELFTEST_HEAD_HASH pins the last record's
# hash, so a change to any hash path these records cross fails here.
_EXCHANGE_SELFTEST_TOOL_CALLS = [{'id': 'toolu_1', 'name': 'Read', 'input': {'file_path': '/work/calc.py'}}]
_EXCHANGE_SELFTEST_ASSERTED = {'agent_name': 'billing-bot', 'on_behalf_of': 'subject-7f3a'}
_EXCHANGE_SELFTEST_PREFIX = 'audit/chain_tnt_selftest_run_x/'
_EXCHANGE_SELFTEST_STUB_SEQ = 3
EXCHANGE_SELFTEST_HEAD_HASH = "f6335bab3e50d9ee957ddaad940e51623046fd44e1b1d56a476975eb4c18205a"


def _exchange_selftest_chain():
    """The TEST-ONLY chain above, sealed in full: (records, shipped records),
    where the shipped records are stripped and seq 3 is its hash-only stub."""
    rec = _V1_10_DIGEST_FIXTURE_RECORD
    tool_digest = sha256_jcs(_EXCHANGE_SELFTEST_TOOL_CALLS)
    llm = dict(model_requested='gpt-4.1-mini', action='allow', input_tokens=11, output_tokens=7,
               estimated_cost_usd=0.000123, findings=[])
    records = [
        dict(llm, schema_version='v1.1', timestamp_utc='2026-10-01T00:00:00Z', event_id='evt-x0', request_id='req-x0',
             messages=rec['messages'], response_text=rec['response_text'],
             raw_request={'messages': rec['messages']}, raw_response={'id': 'resp-1'},
             end_user_id='user-4411', customer_id='acme-bank', tags_json='{"team":"risk"}'),
        dict(llm, schema_version='v1.11', timestamp_utc='2026-10-01T00:00:01Z', event_id='evt-x1', request_id='req-x1',
             messages=rec['messages'], response_text=rec['response_text'], findings=rec['findings'],
             tool_calls=_EXCHANGE_SELFTEST_TOOL_CALLS, raw_request=None, raw_response=None,
             content=dict(capture_policy='full',
                          prompt_sha256_jcs=V1_10_DIGEST_FIXTURE_PROMPT, response_sha256=V1_10_DIGEST_FIXTURE_RESPONSE,
                          stored_prompt_sha256_jcs=V1_10_DIGEST_FIXTURE_PROMPT,
                          stored_response_sha256=V1_10_DIGEST_FIXTURE_RESPONSE,
                          findings_sha256_jcs=V1_10_DIGEST_FIXTURE_FINDINGS,
                          tool_calls_sha256_jcs=tool_digest, stored_tool_calls_sha256_jcs=tool_digest)),
        dict(llm, schema_version='v1.12', timestamp_utc='2026-10-01T00:00:02Z', event_id='evt-x2', request_id='req-x2',
             messages=[], response_text=None, raw_request=None, raw_response=None,
             identity=dict(agent_id='agt_selftest', tier='t1', credential_kind='agent_key',
                           credential_kid='a7f3k2m9p4q8r1s6',
                           asserted_digest=asserted_claims_digest(_EXCHANGE_SELFTEST_ASSERTED),
                           asserted=dict(_EXCHANGE_SELFTEST_ASSERTED))),
        dict(schema_version='v1.2', event_kind='auth_session_started', timestamp_utc='2026-10-01T00:00:03Z',
             event_id='evt-x3', request_id='req-x3', model_requested='', action='allow', input_tokens=0,
             output_tokens=0, estimated_cost_usd=None, findings=[], messages=[], response_text=None,
             raw_request=None, raw_response=None, end_user_id='usr-01',
             auth_session=dict(user_email='ana.lima@bank.example', user_id='usr-01', project_id='proj-01',
                               proxy_id='pxy_01', session_expires_at=1790812800,
                               identity_provenance='meilynx-cp-handoff', jti='jti-01', signing_key_fingerprint='ab12')),
        dict(llm, schema_version='v1.1', timestamp_utc='2026-10-01T00:00:04Z', event_id='evt-x4', request_id='req-x4',
             messages=[{'role': 'user', 'content': 'after the session'}], response_text='ok'),
    ]
    prev = genesis_hash()
    for seq, record in enumerate(records):
        record['sequence_number'] = seq
        record['previous_hash'] = prev
        record['event_hash'] = recompute_event_hash(record, seq, prev)
        prev = record['event_hash']
    shipped = []
    for record in records:
        if record['sequence_number'] == _EXCHANGE_SELFTEST_STUB_SEQ:
            shipped.append({k: record[k] for k in STUB_FIELDS})
            continue
        out = json.loads(json.dumps(record))
        for path in STRIPPED_FIELDS:
            head, _, rest = path.partition('.')
            if not rest:
                out.pop(head, None)
            elif isinstance(out.get(head), dict):
                out[head].pop(rest, None)
        shipped.append(out)
    return records, shipped


_EXCHANGE_SELFTEST_STUB = {'sequence': _EXCHANGE_SELFTEST_STUB_SEQ, 'reason': 'sealed_personal_identifier',
                           'field': 'auth_session.user_email'}


def _exchange_selftest_manifest(records, stubs=(_EXCHANGE_SELFTEST_STUB,)):
    """A 1.5 manifest (unsigned, window A) over `records`, listing `stubs`."""
    last = records[-1]['sequence_number']
    chain = chain_for_prefix(_EXCHANGE_SELFTEST_PREFIX)
    manifest = {
        'schema_version': '1.5', 'window': 'A', 'signing_deferred': True, 'hash_version': 'v1',
        'prefix': _EXCHANGE_SELFTEST_PREFIX, 'from_sequence': 0, 'to_sequence': last,
        'content': CONTENT_STRIPPED, 'removed_fields': list(STRIPPED_FIELDS),
        'anchoring': {'state': 'unanchored', 'chains': [{
            'chain': chain, 'reason': 'no_anchors_found', 'anchored_through_seq': None,
            'unanchored_tail': {'from_seq': 0, 'to_seq': last}, 'anchors': [], 'seals': []}]},
        'events': [{'sequence': r['sequence_number'], 'stored_event_hash': r['event_hash'],
                    'recomputed_event_hash': r['event_hash']} for r in records],
    }
    if stubs:
        manifest['stubs'] = [dict(s) for s in stubs]
    return manifest


def content_carry_forward_self_test():
    """The stored-content check on every bucket that seals the
    content digests, and the malformed-input paths that must fail by name:
    v1.16 and v1.18 records get the v1.12 check (35a, 35b), a content-stripped
    axis reads the same on all three (35c), a content block on a v1.18 MCP
    record is refused while v1.12 MCP keeps its behaviour (35d), a trace with
    no sealed digest or a content block with no capture policy is a FAIL line
    (35e), and a control-plane sequence_number outside 64 bits is a FAIL line
    (35f)."""
    import contextlib
    import io
    import tempfile

    ok = True

    def check(label, passed, what, detail=''):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}: {what}")
        if not passed:
            if detail:
                print(detail, file=sys.stderr)
            ok = False

    messages = [{'role': 'user', 'content': 'Summarize the Q3 variance memo.'}]
    response = 'Revenue was 4% under plan, driven by delayed renewals.'
    calls = [{'id': 'call_1', 'name': 'lookup', 'input': {'account': 'acct-1'}}]
    content = dict(
        capture_policy='full',
        prompt_sha256_jcs=sha256_jcs(messages),
        response_sha256=hashlib.sha256(response.encode('utf-8')).hexdigest(),
        stored_prompt_sha256_jcs=sha256_jcs(messages),
        stored_response_sha256=hashlib.sha256(response.encode('utf-8')).hexdigest(),
        findings_sha256_jcs=sha256_jcs([]),
        tool_calls_sha256_jcs=sha256_jcs(calls),
        stored_tool_calls_sha256_jcs=sha256_jcs(calls),
    )
    trace = {'outcomes_sha256_jcs': V1_16_OUTCOMES_DIGEST_FIXTURE,
             'outcomes': json.loads(json.dumps(_V1_16_OUTCOMES_FIXTURE))}

    def sealed(version):
        record = dict(
            schema_version=version, event_kind='llm_request', sequence_number=0,
            timestamp_utc='2026-10-09T16:21:00Z', event_id='evt-0', request_id='req-0',
            model_requested='gpt-6-luna', action='allow', input_tokens=12, output_tokens=14,
            estimated_cost_usd=None, previous_hash=genesis_hash(),
            messages=json.loads(json.dumps(messages)), response_text=response, findings=[],
            tool_calls=json.loads(json.dumps(calls)), content=dict(content),
            evaluation_trace=json.loads(json.dumps(trace)),
        )
        if version == 'v1.18':
            record['customer'] = dict(_V1_18_CUSTOMER_NONE_FIXTURE)
        record['event_hash'] = recompute_event_hash(record, 0, genesis_hash())
        return record

    def walk(record, manifest_hash):
        manifest = {'hash_version': 'v1', 'prefix': 'audit/self-test/',
                    'events': [{'sequence': 0, 'recomputed_event_hash': manifest_hash}]}
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            records = Path(tmp) / 'records'
            records.mkdir()
            (records / record_file_name(0)).write_bytes(json.dumps(record).encode('utf-8'))
            try:
                with contextlib.redirect_stdout(out):
                    passed = verify_manifest_with(local_fetcher(records), manifest)
            except Exception as exc:  # the assertion is that nothing escapes the walk
                return None, [f'{type(exc).__name__}: {exc}']
        return passed, out.getvalue().splitlines()

    # 35a / 35b — intact passes; an edited prompt, response or tool call still
    # hash-verifies (outside the preimage) and fails the content check; no
    # content block means no capture policy, as on v1.12.
    for label, version in (('35a', 'v1.16'), ('35b', 'v1.18')):
        record = sealed(version)
        intact, intact_lines = walk(record, record['event_hash'])
        caught = []
        for field, edit in (('messages', lambda r: r['messages'][0].update(content='Wire the bonus pool.')),
                            ('response_text', lambda r: r.update(response_text='Revenue was on plan.')),
                            ('tool_calls', lambda r: r['tool_calls'][0]['input'].update(account='acct-2'))):
            edited = json.loads(json.dumps(record))
            edit(edited)
            still_hashes = recompute_event_hash(edited, 0, genesis_hash()) == record['event_hash']
            passed, lines = walk(edited, record['event_hash'])
            caught.append(still_hashes and passed is False
                          and any(l.startswith('FAIL seq=0:') and field in l for l in lines))
        bare = json.loads(json.dumps(record))
        del bare['content']
        check(label, intact is True and all(caught) and check_llm_content(bare) == [],
              f'a {version} record is content-checked as v1.12: intact passes, an edited prompt, response '
              f'or tool call fails, no content block is not checked',
              f'intact {intact} {intact_lines}, caught {caught}, bare {check_llm_content(bare)}')

    # 35c — a content-stripped axis is not re-derived on any of the three, and
    # the kept findings axis is still checked.
    stripped = frozenset(STRIPPED_FIELDS)
    verdicts = {}
    for version in ('v1.12', 'v1.16', 'v1.18'):
        record = sealed('v1.16')
        record['schema_version'] = version
        for field in ('messages', 'response_text', 'tool_calls'):
            record.pop(field, None)
        edited_findings = dict(record, findings=[{'validator': 'added-after-sealing'}])
        verdicts[version] = (check_llm_content(record, stripped), len(check_llm_content(edited_findings, stripped)))
    check('35c', len(set(map(repr, verdicts.values()))) == 1 and verdicts['v1.12'] == ([], 1),
          'a content-stripped axis reads the same on v1.12, v1.16 and v1.18; the findings axis is still checked',
          f'{verdicts}')

    # 35d — a v1.18 MCP record carrying a content block is refused (the MCP
    # preimage never reads it); a v1.12 MCP record keeps its behaviour.
    mcp_118 = dict(
        schema_version='v1.18', event_kind='mcp_tool_call', event_id='evt-tool-call', request_id='req-tool-7',
        timestamp_utc='2026-10-10T12:00:01Z', model_requested='', action='allow', input_tokens=0, output_tokens=0,
        mcp_event=dict(_V1_5_MCP_TOOL_CALL_FIXTURE_PAYLOAD), customer=dict(_V1_18_CUSTOMER_NONE_FIXTURE),
    )
    mcp_118['event_hash'] = recompute_event_hash(mcp_118, 0, genesis_hash())
    mcp_118['previous_hash'] = genesis_hash()
    carrying = dict(mcp_118, content=dict(content), messages=json.loads(json.dumps(messages)))
    passed, lines = walk(carrying, mcp_118['event_hash'])
    mcp_112 = dict(
        schema_version='v1.12', event_kind='mcp_tool_call', event_id='evt-mcp', request_id='req-mcp',
        timestamp_utc='2026-10-10T12:00:01Z', model_requested='', action='allow', input_tokens=0, output_tokens=0,
        mcp_event=dict(_V1_12_MCP_TOOL_CALL_FIXTURE_PAYLOAD), identity=dict(_V1_12_IDENTITY_T2_FIXTURE_PAYLOAD),
    )
    v112_hash = recompute_event_hash(mcp_112, 0, genesis_hash())
    v112_admitted = recompute_event_hash(dict(mcp_112, content=dict(content)), 0, genesis_hash()) == v112_hash
    check('35d', passed is False and v112_admitted
          and any(l.startswith('FAIL seq=0:') and 'hashed only on the llm_request lane' in l for l in lines),
          'a content block on a v1.18 MCP record fails as unattested; v1.12 MCP is unchanged',
          f'passed {passed}, lines {lines}, v1.12 admitted {v112_admitted}')

    # 35e — a trace with no sealed digest, or a content block with no capture
    # policy, fails by name instead of raising.
    cases = []
    record = sealed('v1.16')
    no_digest = json.loads(json.dumps(record))
    del no_digest['evaluation_trace']['outcomes_sha256_jcs']
    cases.append(('outcomes_sha256_jcs', no_digest))
    cases.append(('outcomes_sha256_jcs', dict(record, evaluation_trace='not a trace')))
    no_policy = json.loads(json.dumps(record))
    del no_policy['content']['capture_policy']
    cases.append(('capture_policy', no_policy))
    results = []
    for needle, case in cases:
        passed, lines = walk(case, record['event_hash'])
        results.append(passed is False and any(l.startswith('FAIL seq=0:') and needle in l for l in lines))
    check('35e', all(results),
          'a trace with no outcomes_sha256_jcs, or a content block with no capture_policy, is a named FAIL',
          f'{results}')

    # 35f — a control-plane sequence_number outside the signed 64-bit range
    # the preimage encodes is a named FAIL on the control-plane walk.
    results = []
    for seq in ('9223372036854775808', '-9223372036854775809', '18446744073709551616'):
        text = (_CONTROL_PLANE_V1_VECTORS[0][0]
                .replace('"sequence_number":0', f'"sequence_number":{seq}', 1))
        record = load_control_plane_record(text.encode('utf-8'))
        manifest = {'schema_version': '1.3', 'control_plane': {
            'chain_family': 'control-plane', 'prefix': 'control-plane/', 'hash_algorithm': 'SHA-256',
            'hash_version': 'v1', 'genesis_hash': genesis_hash(), 'verified': True, 'records_checked': 1,
            'events': [{'sequence': 0, 'event_id': record['event_id'], 'stored_event_hash': record['event_hash'],
                        'recomputed_event_hash': record['event_hash']}]}}
        lines = []
        try:
            passed, _ = verify_control_plane_chain(lambda _seq, text=text: text.encode('utf-8'), manifest, lines.append)
        except Exception as exc:  # the assertion is that nothing escapes the walk
            passed, lines = None, [f'{type(exc).__name__}: {exc}']
        results.append(passed is False and '"sequence_number":0' in _CONTROL_PLANE_V1_VECTORS[0][0]
                       and any(l.startswith('FAIL control-plane seq=0:') and '64-bit' in l for l in lines))
    check('35f', all(results),
          'a control-plane sequence_number outside the signed 64-bit range is a named FAIL', f'{results}')
    return ok


def exchange_self_test():
    """The content-stripped Exchange pack (manifest 1.5): the
    content claim and the stub list are read only where 1.5 puts them and only
    as this verifier's profile; a stripped chain verifies from its sealed
    digests and links through a hash-only stub without recomputing it; the
    same records read as a full pack fail; a stripped record that still
    carries a removed field or a withheld personal identifier cannot be
    evaluated; the findings a stripped record keeps are still checked; a stub
    whose hashes break the link, that carries more than its coordinates, that
    stands for an unreadable record, or that the manifest does not list fails;
    receipt evidence and an anchor that name a stub are checked by its hash;
    and the command line prints the content and stub lines, counts the stubs
    on the verdict, refuses --bucket, and exits 2 on a contradicted claim and
    1 on a broken stub."""
    import contextlib
    import io
    import subprocess
    import tempfile

    ok = True

    def check(label, passed, detail=''):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}{': ' + detail if detail else ''}")
        ok = ok and passed

    records, shipped = _exchange_selftest_chain()
    stub_seq = _EXCHANGE_SELFTEST_STUB_SEQ
    stub = shipped[stub_seq]
    check('32a', records[-1]['event_hash'] == EXCHANGE_SELFTEST_HEAD_HASH
          and list(stub) == list(STUB_FIELDS) and stub['event_hash'] == records[stub_seq]['event_hash']
          and all(recompute_event_hash(s, s['sequence_number'], s['previous_hash']) == s['event_hash']
                  for s in shipped if s is not stub),
          'the TEST-ONLY chain recomputes to its pinned head; every stripped record recomputes to its stored hash; '
          'the stub is the four coordinates of the sealed-email record')

    manifest = _exchange_selftest_manifest(shipped)
    stub_entry = dict(_EXCHANGE_SELFTEST_STUB)
    bad = [
        dict(manifest, content='full'),
        dict(manifest, removed_fields=list(STRIPPED_FIELDS)[1:]),
        dict(manifest, removed_fields=list(STRIPPED_FIELDS) + ['findings']),
        dict(manifest, removed_fields=list(STRIPPED_FIELDS) + ['messages']),
        {k: v for k, v in manifest.items() if k != 'content'},
        dict(manifest, schema_version='1.4', evidence_class='sandbox-non-production'),
        dict(manifest, stubs=[dict(stub_entry, reason='other')]),
        dict(manifest, stubs=[dict(stub_entry, sequence=9)]),
        dict(manifest, stubs=[stub_entry, stub_entry]),
        dict(manifest, stubs=[]),
        dict(manifest, stubs=[dict(stub_entry, statement='x')]),
    ]
    errors = [manifest_content_error(m) for m in bad]
    good = [manifest, _exchange_selftest_manifest(shipped, stubs=()),
            dict(manifest, evidence_class='sandbox-non-production'),
            dict(manifest, removed_fields=sorted(STRIPPED_FIELDS, reverse=True))]
    good_ok = (all(manifest_content_error(m) is None for m in good)
               and manifest_evidence_class_error(manifest) is None
               and manifest_evidence_class_error(good[2]) is None
               and manifest_evidence_class_error(dict(manifest, evidence_class='production')) is not None
               and manifest_storage_layout_error(manifest) is None
               and control_plane_manifest_problem(manifest) is None
               and manifest_schema_version_error(manifest) is None
               and manifest_stubs(manifest) == {stub_seq: ('sealed_personal_identifier', 'auth_session.user_email')}
               and manifest_stubs(dict(manifest, schema_version='1.4')) == {})
    if not (good_ok and all(errors)):
        print(f"  {errors!r}", file=sys.stderr)
    check('32b', good_ok and all(errors),
          'manifest 1.5: the stripped profile and the stub list are read (evidence_class, storage_layout, '
          'control_plane and stubs optional); another content value, a removed-field list that is not the profile, '
          'the fields on 1.4, a stub with an unknown reason, outside the events, repeated or with other keys, '
          'or an empty stub list, is refused (exit 2)')

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        rdir = tmp / 'records'
        rdir.mkdir()

        def write(recs):
            for f in rdir.glob('*.bin'):
                f.unlink()
            for seq, r in enumerate(recs):
                (rdir / record_file_name(seq)).write_bytes(json.dumps(r).encode('utf-8'))

        profile = frozenset(STRIPPED_FIELDS)

        def walk(m=manifest, with_stubs=True):
            problems, out = [], io.StringIO()
            with contextlib.redirect_stdout(out):
                passed = verify_manifest_with(local_fetcher(rdir), m, stripped=profile, cannot_evaluate_out=problems,
                                              stubs=manifest_stubs(m) if with_stubs else {})
            return passed, problems, out.getvalue()

        write(shipped)
        clean, problems, out = walk()
        stub_line = [l for l in out.splitlines() if l.startswith(f'STUB seq={stub_seq} ')]
        check('32c', clean and not problems and len(stub_line) == 1 and 'auth_session.user_email' in stub_line[0]
              and 'PASS seq=4 ' in out,
              'a stripped chain (v1.1, v1.11 with sealed content and tool-call digests, v1.12 with sealed identity) '
              'verifies from its digests, links through the hash-only stub at seq 3 on its own STUB line, and the '
              'record after the stub links to it')

        as_full = verify_manifest_with(local_fetcher(rdir), manifest, quiet=True)
        check('32d', not as_full,
              'the same records read as a full pack fail the content checks and the stub: the signed claim is what '
              'lets them verify')

        leaked = json.loads(json.dumps(shipped))
        leaked[1]['messages'] = records[1]['messages']
        leaked[stub_seq] = records[stub_seq]
        write(leaked)
        passed, problems, _ = walk()
        named = sorted((seq, p.rsplit(' carries ', 1)[1].split(',')[0]) for seq, p in problems)
        check('32e', not passed and (1, 'messages') in named and (stub_seq, 'auth_session.user_email') in named,
              f'a stripped record that keeps a removed field, or a stub that carries the withheld email, is refused '
              f'by name (got {named})')

        edited = json.loads(json.dumps(shipped))
        edited[1]['findings'][0]['severity'] = 'low'
        write(edited)
        passed, problems, _ = walk()
        check('32f', not passed and not problems,
              'findings a stripped record keeps are still checked against their sealed digest')

        broken = {}
        for label, change in (('hash', lambda s: s.update(event_hash='0' * 64)),
                              ('link', lambda s: s.update(previous_hash='0' * 64)),
                              ('body', lambda s: s.update(event_id='evt-x3')),
                              ('sequence', lambda s: s.update(sequence_number=7))):
            variant = json.loads(json.dumps(shipped))
            change(variant[stub_seq])
            write(variant)
            passed, _, out = walk()
            broken[label] = (not passed and f'FAIL seq={stub_seq}: hash-only stub' in out)
        write(shipped)
        unreadable = dict(manifest, stubs=[dict(stub_entry, reason='unreadable_record', field='record')])
        passed, _, out = walk(unreadable)
        broken['unreadable'] = not passed and f'FAIL seq={stub_seq}: hash-only stub of a record that does not parse' in out
        unlisted = _exchange_selftest_manifest(shipped, stubs=())
        passed, _, out = walk(unlisted)
        broken['unlisted'] = not passed and f'FAIL seq={stub_seq}: hash recomputation disagrees' in out
        if not all(broken.values()):
            print(f"  {broken!r}", file=sys.stderr)
        check('32g', all(broken.values()),
              'a stub whose event_hash is not the signed one, whose previous_hash breaks the link, that carries '
              'more than its coordinates or another sequence, that stands for an unreadable record, or that the '
              'manifest does not list, fails (exit 1)')

        held = {stub_seq: (STUB_EVENT_ID, stub['event_hash'])}
        cite = {'chain_id': chain_for_prefix(_EXCHANGE_SELFTEST_PREFIX), 'sequence_number': stub_seq, 'event_id': 'evt-x3', 'event_hash': stub['event_hash'],
                'role': 'ai_contribution'}
        pack_chain = chain_for_prefix(_EXCHANGE_SELFTEST_PREFIX)
        good_fail, good_warn = receipt_evidence_findings(9, {'receipt_id': 'r', 'evidence': [cite]}, pack_chain, held,
                                                         {stub_seq})
        bad_fail, _ = receipt_evidence_findings(9, {'receipt_id': 'r', 'evidence': [dict(cite, event_hash='1' * 64)]},
                                                pack_chain, held, {stub_seq})
        anchored, recomputed = _read_record(local_fetcher(rdir), stub_seq, frozenset({stub_seq}))
        try:
            _, not_stub = _read_record(local_fetcher(rdir), stub_seq)
        except AnchorFailure:
            not_stub = None
        check('32h', not good_fail and len(good_warn) == 1 and 'cites a hash-only stub' in good_warn[0]
              and len(bad_fail) == 1 and recomputed == stub['event_hash'] and not_stub != stub['event_hash'],
              'receipt evidence that cites a stub is checked by its hash (its event_id is not in the pack), and an '
              'anchor on a stub reads the hash the chain links, never a recompute of the missing body')

        # 32i — the command line, end to end.
        write(shipped)
        (tmp / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')

        def cli(*extra):
            run = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--manifest',
                                  str(tmp / 'manifest.json'), *extra], capture_output=True, text=True)
            return run.returncode, run.stdout + run.stderr

        code, out = cli('--records', str(rdir), '--allow-unsigned')
        before = (out.find('CONTENT: stripped') < out.find('STUBS: 1 record(s)') < out.find('PASS seq=0')
                  and f'STUB seq={stub_seq} ' in out)
        verdict = out.splitlines()[-1]
        verdict_ok = ('5 events verified, 1 of them as hash-only stubs' in verdict
                      and verdict.endswith('[content: stripped; 1 hash-only stub]'))
        kept_prompt = json.loads(json.dumps(shipped))
        kept_prompt[1]['messages'] = records[1]['messages']
        write(kept_prompt)
        leaked_code, leaked_out = cli('--records', str(rdir), '--allow-unsigned')
        tampered = json.loads(json.dumps(shipped))
        tampered[stub_seq]['event_hash'] = '0' * 64
        write(tampered)
        broken_code, broken_out = cli('--records', str(rdir), '--allow-unsigned')
        bucket_code, bucket_out = cli('--bucket', 'meilynx-audit-selftest-invalid', '--allow-unsigned')
    cli_ok = (code == EXIT_OK and before and verdict_ok
              and leaked_code == EXIT_CANNOT_EVALUATE and 'CANNOT EVALUATE seq=1' in leaked_out
              and broken_code == EXIT_FAIL and f'FAIL seq={stub_seq}: hash-only stub' in broken_out
              and bucket_code == EXIT_CANNOT_EVALUATE and '--records' in bucket_out)
    if not cli_ok:
        print(out + leaked_out + broken_out + bucket_out, file=sys.stderr)
    check('32i', cli_ok,
          '--records: a stripped pack with a stub exits 0, prints its content and stub lines before the records, '
          'and counts the stub on the verdict; one that still carries a removed field exits 2; a stub with a '
          'broken hash exits 1; --bucket on it exits 2')

    return ok


# ── Customer-conditions verdict: TEST-ONLY vectors ────────────────
# A holder's control-plane chain that receives and then accepts one condition
# set, and a proxy chain around the acceptance: a model request before it; an
# MCP call right after it still under the old MCP bundle (a gap); a v1.16
# model request whose sealed evaluation trace ran the set's instance; a v1.10
# model request whose policy_version names the compiled governance version
# (stored, not hashed) and whose digest-bound findings name the instance (an
# exception); and an MCP call under the compiled MCP bundle. TEST-ONLY:
# synthetic digests and ids, never a real set, relationship or chain.
CONDITIONS_SELFTEST_SET = hashlib.sha256(b'TEST-ONLY customer condition set').hexdigest()
_CONDITIONS_SELFTEST_RELATIONSHIP = '0a1b2c3d-4e5f-4061-8273-94a5b6c7d8e9'
_CONDITIONS_SELFTEST_SUFFIX = 'cust_0a1b2c3d4e5f'
_CONDITIONS_SELFTEST_GOVERNANCE = hashlib.sha256(b'TEST-ONLY compiled governance bundle').hexdigest()
_CONDITIONS_SELFTEST_MCP = hashlib.sha256(b'TEST-ONLY compiled MCP bundle').hexdigest()
_CONDITIONS_SELFTEST_OLD_GOVERNANCE = hashlib.sha256(b'TEST-ONLY earlier governance bundle').hexdigest()
_CONDITIONS_SELFTEST_OLD_MCP = hashlib.sha256(b'TEST-ONLY earlier MCP bundle').hexdigest()
CONDITIONS_SELFTEST_ACCEPTANCE_HASH = "d4a4d9c852850ab6b486a0bcefb0c0dd363aa2e450e592c453dfad9560381ece"
CONDITIONS_SELFTEST_HEAD_HASH = "f624f780c5b43d9d940f67f03174a0fd24ba06eb3eed5911ccb608dbd5c3259d"


def _conditions_selftest_control_plane():
    """The TEST-ONLY control-plane chain, as stored text, sealed from genesis."""
    def payload(**extra):
        base = {'relationship_id': _CONDITIONS_SELFTEST_RELATIONSHIP,
                'holder_project_id': '5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b',
                'subscriber_organization_id': '9f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a',
                'version': ControlPlaneNumber('1'), 'conditions_sha256': CONDITIONS_SELFTEST_SET,
                'condition_ids': ['approved-providers', 'sensitive-data']}
        base.update(extra)
        return base
    records = [
        dict(event_kind='exchange.conditions_received', occurred_at='2026-10-16T10:00:00.0000000Z',
             event_id='1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f', payload=payload(actorRole='owner')),
        dict(event_kind=CONDITIONS_ACCEPTED_KIND, occurred_at='2026-10-16T10:05:00.0000000Z',
             event_id='2d3e4f5a-6b7c-4d8e-9fa0-1b2c3d4e5f6a',
             payload=payload(compiled_governance_sha256=_CONDITIONS_SELFTEST_GOVERNANCE,
                             compiled_mcp_sha256=_CONDITIONS_SELFTEST_MCP,
                             compiled_artifacts_sha256=hashlib.sha256(b'TEST-ONLY artifacts').hexdigest(),
                             scope_kind='dedicated', acting_via_organization_id=None, supersedes_version=None,
                             actorRole='owner')),
    ]
    texts, prev = [], genesis_hash()
    for seq, r in enumerate(records):
        r.update(schema_version='v1', sequence_number=ControlPlaneNumber(str(seq)), previous_hash=prev,
                 actor_user_id='11111111-2222-4333-8444-555555555555',
                 correlation_id='3e4f5a6b-7c8d-4e9f-8a0b-1c2d3e4f5a6b',
                 project_id='5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b',
                 target_resource_id=_CONDITIONS_SELFTEST_RELATIONSHIP)
        r['event_hash'] = control_plane_event_hash_v1(r)
        prev = r['event_hash']
        texts.append(control_plane_canonical(r))
    return texts


def _conditions_selftest_records():
    """The TEST-ONLY proxy chain, sealed from genesis, as record dicts."""
    instance = f'pii-detection@{_CONDITIONS_SELFTEST_SUFFIX}'
    trace = {'v': 1, 'rules': [
        {'rule_id': 'pii-detection', 'rule_name': 'PII detection', 'stage': 'pre_request',
         'validator_kind': 'builtin', 'outcome': 'clean', 'action': 'allow'},
        {'rule_id': instance, 'rule_name': 'PII detection (customer condition)', 'stage': 'pre_request',
         'validator_kind': 'builtin', 'outcome': 'clean', 'action': 'allow'},
    ], 'deciding_rule_id': None, 'delivery': {'mode': 'non_streaming', 'outcome': 'delivered'}}
    finding = [{'validator': instance, 'severity': 'high', 'message': 'SSN detected', 'code': 'pii-ssn',
                'category': 'pii'}]
    llm = dict(model_requested='gpt-6-luna', action='allow', input_tokens=40, output_tokens=8,
               estimated_cost_usd=None, findings=[])
    mcp = lambda bundle: dict(_V1_5_MCP_BARE_AGENT_FIXTURE_PAYLOAD, mcp_bundle_sha256=bundle)
    records = [
        dict(llm, schema_version='v1.1', timestamp_utc='2026-10-16T10:00:30Z', event_id='evt-c0', request_id='req-c0',
             policy_version=_CONDITIONS_SELFTEST_OLD_GOVERNANCE, messages=[{'role': 'user', 'content': 'hi'}]),
        dict(schema_version='v1.5', event_kind='mcp_tool_call', timestamp_utc='2026-10-16T10:05:30Z',
             event_id='evt-c1', request_id='req-c1', model_requested='', action='allow', input_tokens=0,
             output_tokens=0, findings=[], mcp_event=mcp(_CONDITIONS_SELFTEST_OLD_MCP)),
        dict(llm, schema_version='v1.16', timestamp_utc='2026-10-16T10:06:00Z', event_id='evt-c2', request_id='req-c2',
             policy_version=_CONDITIONS_SELFTEST_GOVERNANCE,
             evaluation_trace={'outcomes_sha256_jcs': sha256_jcs(trace), 'outcomes': trace,
                               'timing': {'stages': [], 'rules': []}}),
        dict(llm, schema_version='v1.10', timestamp_utc='2026-10-16T10:07:00Z', event_id='evt-c3', request_id='req-c3',
             action='block', policy_version=_CONDITIONS_SELFTEST_GOVERNANCE, findings=finding,
             content={'capture_policy': 'hash_only', 'prompt_sha256_jcs': 'd' * 64,
                      'findings_sha256_jcs': sha256_jcs(finding)}),
        dict(schema_version='v1.5', event_kind='mcp_tool_call', timestamp_utc='2026-10-16T10:08:00Z',
             event_id='evt-c4', request_id='req-c4', model_requested='', action='allow', input_tokens=0,
             output_tokens=0, findings=[], mcp_event=mcp(_CONDITIONS_SELFTEST_MCP)),
    ]
    prev = genesis_hash()
    for seq, r in enumerate(records):
        r['sequence_number'] = seq
        r['previous_hash'] = prev
        r['event_hash'] = recompute_event_hash(r, seq, prev)
        prev = r['event_hash']
    return records


def conditions_self_test():
    """The customer-conditions verdict: on a pack
    that carries the holder's control-plane chain it finds the acceptance,
    counts the window's records sealed under the compiled set, names each gap
    and exception by its coordinates, and keeps an unsealed policy_version
    apart; the same verdict holds on the records stripped for an Exchange
    pack; a pack without the acceptance cannot evaluate it (exit 2) and still
    names the instances it holds; an acceptance supplied outside the pack is
    recomputed and a rewritten one fails; another set's digest is not
    accepted; and the command line prints the verdict line and combines its
    exit code."""
    import subprocess
    import tempfile

    ok = True

    def check(label, passed, detail=''):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}{': ' + detail if detail else ''}")
        ok = ok and passed

    cp_texts = _conditions_selftest_control_plane()
    cp_loaded = [load_control_plane_record(t.encode('utf-8')) for t in cp_texts]
    records = _conditions_selftest_records()
    check('33a', cp_loaded[1]['event_hash'] == CONDITIONS_SELFTEST_ACCEPTANCE_HASH
          and records[-1]['event_hash'] == CONDITIONS_SELFTEST_HEAD_HASH
          and conditions_instance_suffix(_CONDITIONS_SELFTEST_RELATIONSHIP) == _CONDITIONS_SELFTEST_SUFFIX
          and all(control_plane_event_hash_v1(r) == r['event_hash'] for r in cp_loaded),
          'the TEST-ONLY chains recompute to their pinned hashes; the instance suffix is cust_ + 12 hex of the '
          'relationship id')

    cp_records = {seq: (r, True) for seq, r in enumerate(cp_loaded)}
    by_seq = {r['sequence_number']: r for r in records}
    lines = []
    status = conditions_verdict(CONDITIONS_SELFTEST_SET, {}, by_seq, cp_records, report=lines.append)
    expected = (f"conditions: set {CONDITIONS_SELFTEST_SET} accepted at seq 1; 2 of 4 records in the window "
                f"sealed under a governance version carrying it; 1 exceptions; compiled by the holder's "
                f"control plane")
    in_pack_ok = (status == PASSED and lines[-1] == expected
                  and sum(l.startswith('GAP seq=1 ') for l in lines) == 1
                  and not any(l.startswith('GAP seq=') and not l.startswith('GAP seq=1 ') for l in lines)
                  and any(l.startswith('NOTE: 1 model request(s) in the window (seq 3)') for l in lines)
                  and any(l.startswith('EXCEPTION seq=3 ') and 'bound by content.findings_sha256_jcs' in l
                          for l in lines))
    if not in_pack_ok:
        print('\n'.join(lines), file=sys.stderr)
    check('33b', in_pack_ok,
          'acceptance in the pack: 2 of 4 window records sealed under the set, the stale MCP bundle a gap at '
          'seq 1, an unsealed policy_version kept apart, one digest-bound exception at seq 3')

    def strip(record):
        out = json.loads(json.dumps(record))
        for path in STRIPPED_FIELDS:
            head, _, rest = path.partition('.')
            if not rest:
                out.pop(head, None)
            elif isinstance(out.get(head), dict):
                out[head].pop(rest, None)
        return out

    stripped = {seq: strip(r) for seq, r in by_seq.items()}
    lines = []
    status = conditions_verdict(CONDITIONS_SELFTEST_SET, {}, stripped, cp_records, report=lines.append)
    check('33c', status == PASSED and lines[-1] == expected and 'messages' not in stripped[0],
          'the same verdict on the records of a content-stripped pack')

    lines = []
    status = conditions_verdict(CONDITIONS_SELFTEST_SET, {}, by_seq, {}, report=lines.append)
    absent_ok = (status == CANNOT_EVALUATE
                 and any('acceptance not in this pack' in l for l in lines)
                 and lines[-1].startswith(f"conditions: set {CONDITIONS_SELFTEST_SET} acceptance not in this pack;")
                 and '1 records name a customer-condition instance' in lines[-1]
                 and any(l.startswith('INSTANCE seq=3:') for l in lines))
    if not absent_ok:
        print('\n'.join(lines), file=sys.stderr)
    check('33d', absent_ok,
          'no control-plane chain and no acceptance supplied: acceptance not in this pack, cannot evaluate '
          '(exit 2), the instances the pack names are still listed')

    lines = []
    supplied_status = conditions_verdict(CONDITIONS_SELFTEST_SET, {}, stripped, {},
                                         supplied=(cp_loaded[1], 'acceptance.json'), report=lines.append)
    supplied_ok = supplied_status == PASSED and lines[-1] == expected and any(
        'supplied outside this pack' in l for l in lines)
    rewritten = json.loads(cp_texts[1])
    rewritten['payload']['compiled_mcp_sha256'] = _CONDITIONS_SELFTEST_OLD_MCP
    lines_bad = []
    bad_status = conditions_verdict(
        CONDITIONS_SELFTEST_SET, {}, stripped, {},
        supplied=(load_control_plane_record(json.dumps(rewritten).encode('utf-8')), 'acceptance.json'),
        report=lines_bad.append)
    other_set = hashlib.sha256(b'TEST-ONLY another set').hexdigest()
    lines_other = []
    other_status = conditions_verdict(other_set, {}, by_seq, cp_records, report=lines_other.append)
    check('33e', supplied_ok and bad_status == FAILED
          and any('does not recompute to its event_hash' in l for l in lines_bad)
          and other_status == CANNOT_EVALUATE
          and any("holds no acceptance of the set" in l for l in lines_other),
          'an acceptance supplied outside the pack is recomputed and read (verdict unchanged, residual named); '
          'a rewritten one fails; a set the chain never accepted cannot be evaluated')

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        rdir = tmp / 'records'
        (rdir / 'control-plane').mkdir(parents=True)
        for r in records:
            (rdir / record_file_name(r['sequence_number'])).write_bytes(json.dumps(r).encode('utf-8'))
        for seq, text in enumerate(cp_texts):
            (rdir / 'control-plane' / control_plane_record_name(seq)).write_text(text, encoding='utf-8')
        prefix = 'audit/chain_tnt_conditions_run_x/'
        manifest = {
            'schema_version': '1.3', 'window': 'A', 'signing_deferred': True, 'hash_version': 'v1',
            'prefix': prefix, 'from_sequence': 0, 'to_sequence': len(records) - 1,
            'anchoring': {'state': 'unanchored', 'chains': [{
                'chain': chain_for_prefix(prefix), 'reason': 'no_anchors_found', 'anchored_through_seq': None,
                'unanchored_tail': {'from_seq': 0, 'to_seq': len(records) - 1}, 'anchors': [], 'seals': []}]},
            'control_plane': {
                'chain_family': 'control-plane', 'prefix': 'control-plane/', 'hash_algorithm': 'SHA-256',
                'hash_version': 'v1', 'genesis_hash': genesis_hash(), 'verified': True,
                'records_checked': len(cp_loaded),
                'events': [{'sequence': n, 'event_id': r['event_id'], 'stored_event_hash': r['event_hash'],
                            'recomputed_event_hash': r['event_hash']} for n, r in enumerate(cp_loaded)]},
            'events': [{'sequence': r['sequence_number'], 'recomputed_event_hash': r['event_hash']} for r in records],
        }
        (tmp / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        (tmp / 'acceptance.json').write_text(cp_texts[1], encoding='utf-8')
        without = dict(manifest, schema_version='1.1')
        without.pop('control_plane')
        (tmp / 'without.json').write_text(json.dumps(without), encoding='utf-8')

        def cli(manifest_name, *extra):
            run = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--records', str(rdir),
                                  '--manifest', str(tmp / manifest_name), '--allow-unsigned', *extra],
                                 capture_output=True, text=True)
            return run.returncode, run.stdout + run.stderr

        code, out = cli('manifest.json', '--conditions-sha256', CONDITIONS_SELFTEST_SET)
        absent_code, absent_out = cli('without.json', '--conditions-sha256', CONDITIONS_SELFTEST_SET)
        supplied_code, supplied_out = cli('without.json', '--conditions-sha256', CONDITIONS_SELFTEST_SET,
                                          '--conditions-acceptance', str(tmp / 'acceptance.json'))
        bad_arg_code, _ = cli('manifest.json', '--conditions-sha256', 'ABC')
        plain_code, plain_out = cli('manifest.json')
    cli_ok = (code == EXIT_OK and expected in out
              and absent_code == EXIT_CANNOT_EVALUATE and 'acceptance not in this pack' in absent_out
              and supplied_code == EXIT_OK and expected in supplied_out
              and bad_arg_code == EXIT_CANNOT_EVALUATE
              and plain_code == EXIT_OK and 'conditions:' not in plain_out)
    if not cli_ok:
        print(out + absent_out + supplied_out + plain_out, file=sys.stderr)
    check('33f', cli_ok,
          '--records: the verdict line on a pack with the control-plane chain exits 0; without it exits 2 '
          '(acceptance not in this pack) unless --conditions-acceptance supplies it; a malformed digest is a '
          'usage error; without --conditions-sha256 nothing changes')

    # 33g — a stub in a stripped pack is named and counted nowhere.
    stub_manifest = {'schema_version': '1.5', 'content': CONTENT_STRIPPED,
                     'stubs': [{'sequence': 1, 'reason': 'email_address', 'field': 'mcp_event.reason'}]}
    without_stub = {seq: r for seq, r in stripped.items() if seq != 1}
    lines = []
    stub_status = conditions_verdict(CONDITIONS_SELFTEST_SET, stub_manifest, without_stub, cp_records,
                                     report=lines.append)
    check('33g', stub_status == PASSED
          and any(l.startswith('NOTE: 1 hash-only stub(s) (seq 1)') for l in lines)
          and '2 of 3 records in the window' in lines[-1],
          'a hash-only stub in a stripped pack is named and not placed in the window (2 of 3 without it)')

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
    "per_tenant_identity": "ps-selftest00@selftest-invalid.iam.gserviceaccount.com",
    "per_tenant_manifest": (
        "ewogICJzY2hlbWFfdmVyc2lvbiI6ICIxLjQiLAogICJwYWNrX2lkIjogIjAwMDAwMDAwLTAw"
        "MDAtNDAwMC04MDAwLTAwMDAwMDAwMjc0OSIsCiAgIndpbmRvdyI6ICJCIiwKICAic2lnbmlu"
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
        "aF9tYXRjaCI6IHRydWUKICAgIH0KICBdLAogICJldmlkZW5jZV9jbGFzcyI6ICJzYW5kYm94"
        "LW5vbi1wcm9kdWN0aW9uIiwKICAiYW5jaG9yaW5nIjogewogICAgInN0YXRlIjogInVuYW5j"
        "aG9yZWQiLAogICAgImNoYWlucyI6IFsKICAgICAgewogICAgICAgICJjaGFpbiI6ICJzZWxm"
        "LXRlc3QiLAogICAgICAgICJyZWFzb24iOiAibm9fYW5jaG9yc19mb3VuZCIsCiAgICAgICAg"
        "ImFuY2hvcmVkX3Rocm91Z2hfc2VxIjogbnVsbCwKICAgICAgICAidW5hbmNob3JlZF90YWls"
        "IjogewogICAgICAgICAgImZyb21fc2VxIjogMCwKICAgICAgICAgICJ0b19zZXEiOiAxCiAg"
        "ICAgICAgfSwKICAgICAgICAiYW5jaG9ycyI6IFtdLAogICAgICAgICJzZWFscyI6IFtdCiAg"
        "ICAgIH0KICAgIF0KICB9Cn0K"
    ),
    "bundle_per_tenant": (
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"messageSig"
        "nature\":{\"messageDigest\":{\"algorithm\":\"SHA2_256\",\"digest\":\"KMxDLjhPFb0sI"
        "zobSfhsZ6JY/BIqJExQ2UhaqhG36LQ=\"},\"signature\":\"MEUCIBMkgpIAM20u/pSCjNB21"
        "2S0qESddP7c9w1RUgd9c8cEAiEA7wmpyfnAaz/tqoEce2X7H/e2nNR0usf2RX0GyCvgEMs=\""
        "},\"verificationMaterial\":{\"certificate\":{\"rawBytes\":\"MIICHzCCAaagAwIBAgI"
        "CCr0wCgYIKoZIzj0EAwMwSTEhMB8GA1UECgwYbWVpbHlueC12ZXJpZnkgc2VsZi10ZXN0MSQ"
        "wIgYDVQQDDBtURVNULU9OTFkgQ0EtQSBpbnRlcm1lZGlhdGUwHhcNMjYwOTIxMTQxMjIwWhc"
        "NMjYwOTIxMTQyMjIwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdpmEw7v0OCAwg/1"
        "OJW1xmMiUEf2YOGDyspnHKbbB6jdgHMAnyWpI4ZDd3dnmt4zOP9kj5FzBV6rHhpmllqShoKO"
        "BxjCBwzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwRAYDVR0RAQH/BDo"
        "wOIE2cHMtc2VsZnRlc3QwMEBzZWxmdGVzdC1pbnZhbGlkLmlhbS5nc2VydmljZWFjY291bnQ"
        "uY29tMCkGCisGAQQBg78wAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTArBgorBgE"
        "EAYO/MAEIBB0MG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTAKBggqhkjOPQQDAwNnADB"
        "kAjAtd8GfPxm99Xbfu9j43ZZAp7gly1HtTKnD6qmDBzYJt+lEltYYuMaTWadWIiV1a2ECMAc"
        "4wuGB+3IzT1VzPPjIoDbT5HVagpRgYMZPvYE+7UXDP8g7Xz629dkZnvRlS3dfsQ==\"},\"tlo"
        "gEntries\":[{\"canonicalizedBody\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjo"
        "iaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2h"
        "hMjU2IiwidmFsdWUiOiIyOGNjNDMyZTM4NGYxNWJkMmMyMzNhMWI0OWY4NmM2N2EyNThmYzE"
        "yMmEyNDRjNTBkOTQ4NWFhYTExYjdlOGI0In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1"
        "FVUNJQk1rZ3BJQU0yMHUvcFNDak5CMjEyUzBxRVNkZFA3Yzl3MVJVZ2Q5YzhjRUFpRUE3d21"
        "weWZuQWF6L3Rxb0VjZTJYN0gvZTJuTlIwdXNmMlJYMEd5Q3ZnRU1zPSIsInB1YmxpY0tleSI"
        "6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlN"
        "VTklla05EUVdGaFowRjNTVUpCWjBsRFEzSXdkME5uV1VsTGIxcEplbW93UlVGM1RYZFRWRVZ"
        "vVFVJNFIwRXhWVVZEWjNkWllsZFdjR0pJYkhVS1pVTXhNbHBZU25CYWJtdG5ZekpXYzFwcE1"
        "UQmFXRTR3VFZOUmQwbG5XVVJXVVZGRVJFSjBWVkpXVGxWTVZUbFBWRVpyWjFFd1JYUlJVMEp"
        "3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcFpkMDlVU1hoTlZGRjRUV3BKZDFkb1k"
        "wNU5hbGwzVDFSSmVFMVVVWGxOYWtsM1YycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZ"
        "aU1V0dldrbDZhakJFUVZGalJGRm5RVVZrY0cxRmR6ZDJNRTlEUVhkbkx6RlBTbGN4ZUcxTmF"
        "WVkZaakpaVDBkRWVYTndia2dLUzJKaVFqWnFaR2RJVFVGdWVWZHdTVFJhUkdRelpHNXRkRFI"
        "2VDFBNWEybzFSbnBDVmpaeVNHaHdiV3hzY1ZOb2IwdFBRbmhxUTBKM2VrRlBRbWRPVmdwSVV"
        "UaENRV1k0UlVKQlRVTkNORUYzUlhkWlJGWlNNR3hDUVhkM1EyZFpTVXQzV1VKQ1VWVklRWGR"
        "OZDFKQldVUldVakJTUVZGSUwwSkViM2RQU1VVeUNtTklUWFJqTWxaeldtNVNiR016VVhkTlJ"
        "VSjZXbGQ0YldSSFZucGtRekZ3WW01YWFHSkhiR3RNYld4b1lsTTFibU15Vm5sa2JXeHFXbGR"
        "HYWxreU9URUtZbTVSZFZreU9YUk5RMnRIUTJselIwRlJVVUpuTnpoM1FWRkZSVWN5YURCa1N"
        "FSjZUMms0ZGxsWFRtcGlNMVoxWkVoTmRWb3lPWFphTW5oc1RHMU9kZ3BpVkVGeVFtZHZja0p"
        "uUlVWQldVOHZUVUZGU1VKQ01FMUhNbWd3WkVoQ2VrOXBPSFpaVjA1cVlqTldkV1JJVFhWYU1"
        "qbDJXako0YkV4dFRuWmlWRUZMQ2tKblozRm9hMnBQVUZGUlJFRjNUbTVCUkVKclFXcEJkR1E"
        "0UjJaUWVHMDVPVmhpWm5VNWFqUXpXbHBCY0RkbmJIa3hTSFJVUzI1RU5uRnRSRUo2V1VvS2R"
        "DdHNSV3gwV1ZsMVRXRlVWMkZrVjBscFZqRmhNa1ZEVFVGak5IZDFSMElyTTBsNlZERldlbEJ"
        "RYWtsdlJHSlVOVWhXWVdkd1VtZFpUVnBRZGxsRkt3bzNWVmhFVURobk4xaDZOakk1Wkd0YWJ"
        "uWlNiRk16WkdaelVUMDlDaTB0TFMwdFJVNUVJRU5GVWxSSlJrbERRVlJGTFMwdExTMEsifX1"
        "9fQ==\",\"inclusionPromise\":{\"signedEntryTimestamp\":\"MEUCIEMe+jJS2y5MfTsAf"
        "nntkINIOX/BQhi8/z4u6DqFbylpAiEAwTqJiBcaUP0yNPp2ITfm3ZBPcErmvN7lkpyu+yG7x"
        "eo=\"},\"inclusionProof\":{\"checkpoint\":{\"envelope\":\"selftest.invalid - 1\\n"
        "2\\nDEPFjKdNLcjGOcHIxTVu4FzxQ1JjIZNOq5Qe02cnJYU=\\n\\n\\u2014 selftest.inval"
        "id pIdAtjBFAiBjkj9LS2PsJMqrZ4ySlwBF0PYTJU+F3i9cHynyBJjmXQIhANH0JjfClpPU6"
        "slfimtxGuneBL7CVXaVgZWkAWGaHBQH\\n\"},\"hashes\":[\"hFBUv7btFXw2SOlMXOAqy4u5B"
        "ocZxl4OHHEij3KxFBI=\"],\"logIndex\":\"0\",\"rootHash\":\"DEPFjKdNLcjGOcHIxTVu4Fz"
        "xQ1JjIZNOq5Qe02cnJYU=\",\"treeSize\":\"2\"},\"integratedTime\":\"1790000000\",\"ki"
        "ndVersion\":{\"kind\":\"hashedrekord\",\"version\":\"0.0.1\"},\"logId\":{\"keyId\":\"p"
        "IdAtgmNH6Fr/ATdjpQQKG5cR/b+kGJsY28Z+DigQas=\"},\"logIndex\":\"0\"}]}}"
    ),
    "bundle_per_tenant_uri_san": (
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"messageSig"
        "nature\":{\"messageDigest\":{\"algorithm\":\"SHA2_256\",\"digest\":\"KMxDLjhPFb0sI"
        "zobSfhsZ6JY/BIqJExQ2UhaqhG36LQ=\"},\"signature\":\"MEUCIQCjCh6HJ7sc332Mdl82q"
        "FtwHYBCUB/0XqZHLtyg79sO7gIgG/zMGmtE9LxxOk9DtI4Bi7WZ61DU1s/mmMXsR69KSJg=\""
        "},\"verificationMaterial\":{\"certificate\":{\"rawBytes\":\"MIICIDCCAaagAwIBAgI"
        "CCr4wCgYIKoZIzj0EAwMwSTEhMB8GA1UECgwYbWVpbHlueC12ZXJpZnkgc2VsZi10ZXN0MSQ"
        "wIgYDVQQDDBtURVNULU9OTFkgQ0EtQSBpbnRlcm1lZGlhdGUwHhcNMjYwOTIxMTQxMjIwWhc"
        "NMjYwOTIxMTQyMjIwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh4HYkOZZYzCPShf"
        "/066xzXd5nwIQ4HuoeHuMWCXmXoXt8v+iuZImc57DamqMVGX0oFpMAWLXmvfdo7N5yS4+X6O"
        "BxjCBwzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwRAYDVR0RAQH/BDo"
        "wOIY2cHMtc2VsZnRlc3QwMEBzZWxmdGVzdC1pbnZhbGlkLmlhbS5nc2VydmljZWFjY291bnQ"
        "uY29tMCkGCisGAQQBg78wAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTArBgorBgE"
        "EAYO/MAEIBB0MG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTAKBggqhkjOPQQDAwNoADB"
        "lAjEA0Sa8Mr4UKNo899P4b6pxdO88tv0+eJj3lN2oC6L84+8d+iLB15/BwMTq7i3FeBQnAjB"
        "+sx1yKb32aG4BAmNBKecRh+7KF09Y8qb2OvML/Bb7WI8ZIe0r5wADrmLRV+mAuFk=\"},\"tlo"
        "gEntries\":[{\"canonicalizedBody\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjo"
        "iaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2h"
        "hMjU2IiwidmFsdWUiOiIyOGNjNDMyZTM4NGYxNWJkMmMyMzNhMWI0OWY4NmM2N2EyNThmYzE"
        "yMmEyNDRjNTBkOTQ4NWFhYTExYjdlOGI0In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1"
        "FVUNJUUNqQ2g2SEo3c2MzMzJNZGw4MnFGdHdIWUJDVUIvMFhxWkhMdHlnNzlzTzdnSWdHL3p"
        "NR210RTlMeHhPazlEdEk0Qmk3V1o2MURVMXMvbW1NWHNSNjlLU0pnPSIsInB1YmxpY0tleSI"
        "6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlN"
        "VTkpSRU5EUVdGaFowRjNTVUpCWjBsRFEzSTBkME5uV1VsTGIxcEplbW93UlVGM1RYZFRWRVZ"
        "vVFVJNFIwRXhWVVZEWjNkWllsZFdjR0pJYkhVS1pVTXhNbHBZU25CYWJtdG5ZekpXYzFwcE1"
        "UQmFXRTR3VFZOUmQwbG5XVVJXVVZGRVJFSjBWVkpXVGxWTVZUbFBWRVpyWjFFd1JYUlJVMEp"
        "3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcFpkMDlVU1hoTlZGRjRUV3BKZDFkb1k"
        "wNU5hbGwzVDFSSmVFMVVVWGxOYWtsM1YycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZ"
        "aU1V0dldrbDZhakJFUVZGalJGRm5RVVZvTkVoWmEwOWFXbGw2UTFCVGFHWXZNRFkyZUhwWVp"
        "EVnVkMGxSTkVoMWIyVklkVTBLVjBOWWJWaHZXSFE0ZGl0cGRWcEpiV00xTjBSaGJYRk5Wa2R"
        "ZTUc5R2NFMUJWMHhZYlhabVpHODNUalY1VXpRcldEWlBRbmhxUTBKM2VrRlBRbWRPVmdwSVV"
        "UaENRV1k0UlVKQlRVTkNORUYzUlhkWlJGWlNNR3hDUVhkM1EyZFpTVXQzV1VKQ1VWVklRWGR"
        "OZDFKQldVUldVakJTUVZGSUwwSkViM2RQU1ZreUNtTklUWFJqTWxaeldtNVNiR016VVhkTlJ"
        "VSjZXbGQ0YldSSFZucGtRekZ3WW01YWFHSkhiR3RNYld4b1lsTTFibU15Vm5sa2JXeHFXbGR"
        "HYWxreU9URUtZbTVSZFZreU9YUk5RMnRIUTJselIwRlJVVUpuTnpoM1FWRkZSVWN5YURCa1N"
        "FSjZUMms0ZGxsWFRtcGlNMVoxWkVoTmRWb3lPWFphTW5oc1RHMU9kZ3BpVkVGeVFtZHZja0p"
        "uUlVWQldVOHZUVUZGU1VKQ01FMUhNbWd3WkVoQ2VrOXBPSFpaVjA1cVlqTldkV1JJVFhWYU1"
        "qbDJXako0YkV4dFRuWmlWRUZMQ2tKblozRm9hMnBQVUZGUlJFRjNUbTlCUkVKc1FXcEZRVEJ"
        "UWVRoTmNqUlZTMDV2T0RrNVVEUmlObkI0WkU4NE9IUjJNQ3RsU21vemJFNHliME0yVERnS05"
        "DczRaQ3RwVEVJeE5TOUNkMDFVY1RkcE0wWmxRbEZ1UVdwQ0szTjRNWGxMWWpNeVlVYzBRa0Z"
        "0VGtKTFpXTlNhQ3MzUzBZd09WazRjV0l5VDNaTlRBb3ZRbUkzVjBrNFdrbGxNSEkxZDBGRWN"
        "tMU1VbFlyYlVGMVJtczlDaTB0TFMwdFJVNUVJRU5GVWxSSlJrbERRVlJGTFMwdExTMEsifX1"
        "9fQ==\",\"inclusionPromise\":{\"signedEntryTimestamp\":\"MEUCIQC0wfpU7nwfAG4GU"
        "+ph5O5hCNOtTi6t0RfmEjCIc/0yKwIgZKskzo979doBAJGmgdM7mKHoAx5oSyI11rP/LuUus"
        "XY=\"},\"inclusionProof\":{\"checkpoint\":{\"envelope\":\"selftest.invalid - 1\\n"
        "2\\nDEPFjKdNLcjGOcHIxTVu4FzxQ1JjIZNOq5Qe02cnJYU=\\n\\n\\u2014 selftest.inval"
        "id pIdAtjBFAiBjkj9LS2PsJMqrZ4ySlwBF0PYTJU+F3i9cHynyBJjmXQIhANH0JjfClpPU6"
        "slfimtxGuneBL7CVXaVgZWkAWGaHBQH\\n\"},\"hashes\":[\"motnOIkPCUEtE2P+bHTSFrwKo"
        "ydr2PiTkEvOV+B8AXk=\"],\"logIndex\":\"1\",\"rootHash\":\"DEPFjKdNLcjGOcHIxTVu4Fz"
        "xQ1JjIZNOq5Qe02cnJYU=\",\"treeSize\":\"2\"},\"integratedTime\":\"1790000000\",\"ki"
        "ndVersion\":{\"kind\":\"hashedrekord\",\"version\":\"0.0.1\"},\"logId\":{\"keyId\":\"p"
        "IdAtgmNH6Fr/ATdjpQQKG5cR/b+kGJsY28Z+DigQas=\"},\"logIndex\":\"1\"}]}}"
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
    """The signed-pack checks. ECDSA edge cases from Wycheproof; a
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

    # 20s-20x: the per-tenant signer class, and the manifest 1.4 evidence
    # label.
    tenant_identity = vectors["per_tenant_identity"]
    tenant_bytes = base64.b64decode(vectors["per_tenant_manifest"])
    tenant_manifest = json.loads(tenant_bytes)

    def tenant_outcome(key, identity=tenant_identity, issuer=GOOGLE_OIDC_ISSUER, supplied=True):
        body = vectors[key].encode("utf-8")
        try:
            check_pack_signature(tenant_manifest, tenant_bytes,
                                 lambda name: body if name == "manifest.json.sigstore.json" else None,
                                 identity, issuer, trust, identity_supplied=supplied)
            return "verified"
        except SignatureInvalid as exc:
            return exc.reason
        except SignerIdentityRequired as exc:
            return ("identity required", tuple(exc.identities))

    check("20s", tenant_outcome("bundle_per_tenant") == "verified",
          "a per-tenant pack (Google issuer, service-account email SAN) verifies against the identity the reader supplies")
    check("20t", tenant_outcome("bundle_per_tenant", PINNED_SIGNER_IDENTITY, PINNED_OIDC_ISSUER, supplied=False)
          == ("identity required", (tenant_identity,))
          and outcome(fresh(), expect_identity=identity, expect_issuer=issuer) == "verified",
          "a per-tenant pack checked with no reader-supplied identity cannot be evaluated (exit 2), naming its "
          "signer; the workflow class still verifies against the default")
    check("20u", tenant_outcome("bundle_per_tenant", "ps-other0000@selftest-invalid.iam.gserviceaccount.com")
          == REASON_IDENTITY_MISMATCH
          and tenant_outcome("bundle_per_tenant", issuer=PINNED_OIDC_ISSUER) == REASON_ISSUER_MISMATCH,
          "another tenant's identity fails as 'signer identity mismatch', and another issuer as 'OIDC issuer mismatch'")
    check("20v", tenant_outcome("bundle_per_tenant_uri_san") == REASON_IDENTITY_MISMATCH,
          "a per-tenant certificate that names the email as a URI SAN, not an rfc822Name, does not match")
    resolved = [
        expected_signer(None, None),
        expected_signer(tenant_identity, None),
        expected_signer("https://example.invalid/workflow", None),
        expected_signer(tenant_identity, "https://other.invalid"),
    ]
    check("20w", resolved == [
        (PINNED_SIGNER_IDENTITY, PINNED_OIDC_ISSUER, False),
        (tenant_identity, GOOGLE_OIDC_ISSUER, True),
        ("https://example.invalid/workflow", PINNED_OIDC_ISSUER, True),
        (tenant_identity, "https://other.invalid", True),
    ], "no identity means the signing workflow; an email identity means Google's issuer unless one is given")
    label_errors = [
        manifest_evidence_class_error(tenant_manifest),
        manifest_evidence_class_error(dict(tenant_manifest, evidence_class="production")),
        manifest_evidence_class_error({k: v for k, v in tenant_manifest.items() if k != "evidence_class"}),
        manifest_evidence_class_error(dict(tenant_manifest, schema_version="1.1")),
        manifest_evidence_class_error({"schema_version": "1.1"}),
        manifest_storage_layout_error({"schema_version": "1.4"}),
        manifest_storage_layout_error({"schema_version": "1.4", "storage_layout": "segmented-v9"}),
        control_plane_manifest_problem({"schema_version": "1.4"}),
    ]
    labels_ok = (label_errors[0] is None and all(e is not None for e in label_errors[1:4])
                 and label_errors[4] is None and label_errors[5] is None and label_errors[6] is not None
                 and label_errors[7] is None)
    if not labels_ok:
        print(f"  {label_errors!r}", file=sys.stderr)
    check("20x", labels_ok,
          "manifest 1.4: a known evidence_class is read; an unknown or missing one, or one on 1.1, is refused "
          "(exit 2); storage_layout and control_plane are optional as in 1.3")

    # 20y: the per-tenant class and the label end to end at the command line.
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "records" / "anchors").mkdir(parents=True)
        for seq_no, raw in records.items():
            (tmp / "records" / record_file_name(seq_no)).write_text(raw)
        (tmp / "trusted_root.json").write_text(vectors["trusted_root"])
        (tmp / "pack").mkdir()
        (tmp / "pack" / "manifest.json").write_bytes(tenant_bytes)
        (tmp / "pack" / "manifest.json.sigstore.json").write_text(vectors["bundle_per_tenant"])

        def tenant_cli(*extra):
            run = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--records", str(tmp / "records"),
                 "--manifest", str(tmp / "pack" / "manifest.json"),
                 "--trusted-root", str(tmp / "trusted_root.json"), *extra],
                capture_output=True, text=True,
            )
            return run.returncode, run.stdout + run.stderr

        named_code, named_out = tenant_cli("--certificate-identity", tenant_identity)
        bare_code, bare_out = tenant_cli()
    cli_ok = (named_code == EXIT_OK and "per-tenant signer" in named_out
              and "EVIDENCE CLASS: sandbox-non-production" in named_out
              and "manifest signature verified. [evidence class: sandbox-non-production]" in named_out
              and bare_code == EXIT_CANNOT_EVALUATE and tenant_identity in bare_out
              and "[evidence class: sandbox-non-production]" in bare_out)
    if not cli_ok:
        print(named_out + bare_out, file=sys.stderr)
    check("20y", cli_ok,
          "--records: a 1.4 per-tenant pack exits 0 with the supplied identity and prints its evidence class on "
          "the verdict; without an identity it exits 2 naming the signer")

    return ok


# ── anchor self-test data ──────────────────────────────────────
# RSA-2048 public key (SPKI) for the known-answer vectors below; OpenSSL-generated.
_KAT_RSA_SPKI = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA99gXa1HWWgLdl8EYk3o7Aoo9ZnNnxxuDDmT/2Dm1U8IOT8VpukeT",
    "u88R9BmMxjtfpb4xXDpv/jDRljwxG2CR5OX605HXWcDVv5nHoB7PV8zXxiTd3VVIQddmBpvMyeyXftN5+eZcA6hnoHpAErDO",
    "anzkJjsA0Plq7RH+4WtbqLc471I1vIvaBZIGuv4zF7fozblllWCG/XlbdfEikYz2d34pd4tNLsVX7miEBwH6zB8kcKGURjM8",
    "F2GmHTygw+Ldop0cU7QU8QmMECPrhXPo5PuPiW/CRl8gDwPjURCZcOCK2kEShqoYiJELaoJvjGcqRl6TfXuQgqeYl+mwlSur",
    "JwIDAQAB",
)
# RSASSA-PKCS1-v1_5 / SHA-256 over b'meilynx-anchor-rsa-kat-v1'.
_KAT_RSA_PKCS1_SHA256 = (
    "tdE7vo2te4c9k0nIzd5zIIPkJLv+Hgv32kUkZQOOR9t5NUXiFHSBt801jNFcmhWgZJ5HkIdAt2gAlYWv/KkKrCdDrmZc5SCh",
    "vNrXZZo1l2fBqXJnM7qyE3SR9wWCnLOBr0s/5cyRPBjBCf2pLsGk+zPcGWBCilVA3Es+zBeKRwYNRF6mGAoxzIGuoYcFgkvf",
    "NjyXY2EMgkVbuziQOU9DTO3gVeqqHQDTuOyk2BakVzpraf+iMpYrxJv1ab4l52wkqjKCnHD1vUhz5WZ+FbRSWoTiEefUXfWf",
    "Nso9Wu1PGgamLlmIX2iRiNNEcio2nvB9KUzD2ncwaKIkQFTnwJeflg==",
)
# RSASSA-PSS / SHA-256, MGF1-SHA-256, salt 32, same message.
_KAT_RSA_PSS_SHA256 = (
    "oM7y0GDZGDeQtDK/211iyqS4RZTEK9Mrc70KlDT4hQce9DTIliwJe8lJXS7aWoJ0pOyFixUekECC4NOsHp5TzWDoLUEsU+I2",
    "3cLek28zVawGuXrpmhE3WjqILNjStAY86RPxEAtwfZyoO8NSwj3xTShJPZMd15ERs5bBMzLZKVNAOAIx1CBo/6H7+eZoxeVr",
    "NCZIsqUFRNoqPyB97LAqYPZakRJvNDdrCGM860KxJc1yy+Gm/1b3xcprEOpCmbGL7kTa//3/pmrRp4JJXAZqRkz7GBVEm75M",
    "M7+eDQBRexup1id+9ZFzdnHnfFxM7APwDTLcV9h5o/3AG2YHgMcOmA==",
)
# RSASSA-PSS / SHA-384, MGF1-SHA-384, salt 48, same message.
_KAT_RSA_PSS_SHA384 = (
    "Y1te+e/z/xbI2UYDIEBKJgwtnZXVa0Z7CAkxPfgW2IGXYrK0iqUKp0V0agqihUHUaNzneRDPwI1gEduT79hn1+vMletWrDgk",
    "MNgVe19xlzRlgS1w7CRfxBv05hkEGD/eDQDgOrMoH7Z+CaHWXTaRvnl+ICuaf9ReeD5YjD0+remiK0+nopNSFrZUIuUlbYDg",
    "ukw7KUMV8bf3AumGSYPB2DfrDFyALMA0krdlZ3b8U84uzvVX9PZF7KnB2V+Mg4BvkqUG+CwxrMnij4JXcAsx2laJ7euy3ZS5",
    "zIMseduL2jAlR62jmmmHuX7n+hHrzh0TwrztIBx+ksT7RKDXCfcniQ==",
)
# Real TimeStampResp from timestamp.sigstore.dev, 2026-10-03T00:51:11Z, over
# SHA-256(b'meilynx-anchor-interop-probe-2026-10-02') (proxy fixture anchor/real/sigstore.tsr).
_REAL_SIGSTORE_TSR = (
    "MIIE6jADAgEAMIIE4QYJKoZIhvcNAQcCoIIE0jCCBM4CAQMxDTALBglghkgBZQMEAgEwgcIGCyqGSIb3DQEJEAEEoIGyBIGv",
    "MIGsAgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQg52KkYxzSouG/J+rJlOyheMGyiAPpIw3qxsqkzR/3JqMCFHqY",
    "fug4y7BNpMbV2Ko3sV8ymhH7GA8yMDI2MTAwMzAwNTExMVowAwIBAQIJAPgMSdy/ASM4oDKkMDAuMRUwEwYDVQQKEwxzaWdz",
    "dG9yZS5kZXYxFTATBgNVBAMTDHNpZ3N0b3JlLXRzYaCCAhQwggIQMIIBlqADAgECAhQ6E1QvDJBh7rzBQy/Lio6LKiOLDDAK",
    "BggqhkjOPQQDAzA5MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxIDAeBgNVBAMTF3NpZ3N0b3JlLXRzYS1zZWxmc2lnbmVkMB4X",
    "DTI1MDQwODA2NTk0M1oXDTM1MDQwNjA2NTk0M1owLjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MRUwEwYDVQQDEwxzaWdzdG9y",
    "ZS10c2EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATitrZnyEo2KDZP2QWMIBOgYbfSOTL5ZC/cHMv6Yq+HVIo1H9TC7Cx80KDi",
    "yvKhgB3wTqKyi9UDczhqg12b1AOLnRnydMTK+qB8M+1MjBci1+Jb8AV/VXu7CRuQCiPTHFyjajBoMA4GA1UdDwEB/wQEAwIH",
    "gDAdBgNVHQ4EFgQUif15Q4fP0GVGwwJGxyxzW3206wMwHwYDVR0jBBgwFoAUmOwB73+7Uf/UlR5vioiYUweJzr8wFgYDVR0l",
    "AQH/BAwwCgYIKwYBBQUHAwgwCgYIKoZIzj0EAwMDaAAwZQIwO2mxX/opo7SrIX9QyxfZpJRcpAV2gZOm1AZzR+2rVyy6Uc8Y",
    "bp2ybIw13ckH4bcRAjEA5qO8FyOkmYpvg2/7ZNqiPxRzn5vqKHoVcIIqtpKq6l7TvOqzAxxclN7VwTG8e++XMYIB2zCCAdcC",
    "AQEwUTA5MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxIDAeBgNVBAMTF3NpZ3N0b3JlLXRzYS1zZWxmc2lnbmVkAhQ6E1QvDJBh",
    "7rzBQy/Lio6LKiOLDDALBglghkgBZQMEAgGggfwwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEP",
    "Fw0yNjEwMDMwMDUxMTFaMC8GCSqGSIb3DQEJBDEiBCB+yIjEAzL2RUyLmCFlr9yRaRfpnqZvTCbRoFYCNZHg4jCBjgYLKoZI",
    "hvcNAQkQAi8xfzB9MHsweQQghfknvAerYsrDtENWwQ78gbLGiD/aernm2HDZ0TrNBbcwVTA9pDswOTEVMBMGA1UEChMMc2ln",
    "c3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZAIUOhNULwyQYe68wUMvy4qOiyojiwwwCgYIKoZI",
    "zj0EAwIEZzBlAjEA6xaSEkw0pBwQRk1J3qlGGBmCKL46kXrZuP1AGW3+ik+Qusv/88ELkefSjSnJYN+WAjBlDDvCxoQ2M6FF",
    "CG7dIHl6g0ouKE/mAvLApliUtg4O1iUvV0xhKLfME5ydi3jbvzE=",
)
# Real TimeStampResp from GlobalSign R45, 2026-10-03T00:56:22Z, same imprint
# (proxy fixture anchor/real/globalsign-r45.tsr).
_REAL_GLOBALSIGN_TSR = (
    "MIId6TADAgEAMIId4AYJKoZIhvcNAQcCoIId0TCCHc0CAQMxDTALBglghkgBZQMEAgIwge8GCyqGSIb3DQEJEAEEoIHfBIHc",
    "MIHZAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCGSAFlAwQCAQUABCDnYqRjHNKi4b8n6smU7KF4wbKIA+kjDerGyqTNH/cmowIU",
    "IY+pqwR12O/76j2cki6boSo/3jQYDzIwMjYxMDAzMDA1NjIyWjADAgEBAgkA+AxJ3L8BIzigXaRbMFkxCzAJBgNVBAYTAkJF",
    "MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS8wLQYDVQQDEyZHbG9iYWxzaWduIFI0NSBUU0EgZm9yIENvZGVTaWduIDIw",
    "MjUxMKCCGWAwggaKMIIEcqADAgECAhEAhHI/wZXMFvHbK6L2YN8r5DANBgkqhkiG9w0BAQwFADBeMQswCQYDVQQGEwJCRTEZ",
    "MBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5lIFI0NSBUaW1lc3RhbXBpbmcg",
    "Q0EgMjAyNTAeFw0yNTEwMTUwNzI1MDRaFw0zNzAxMTAwMDAwMDBaMFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxT",
    "aWduIG52LXNhMS8wLQYDVQQDEyZHbG9iYWxzaWduIFI0NSBUU0EgZm9yIENvZGVTaWduIDIwMjUxMDCCAaIwDQYJKoZIhvcN",
    "AQEBBQADggGPADCCAYoCggGBANFKjaGNhkBIKKMJBJzZExA88qiMT/F/hSKNrYmewntKeXaAOjEqND0dxTqtUPymDLWwEp1X",
    "G0ssWFjeDNj88DaLAizpnMKfGyG2NKGw3VHLNGvNzgWr7TFDHqoANQyf3qaocT/SiTncM9uakGSRQPK0Yzv2dB/D1ZXKZiAD",
    "5ORsDT9A6Y800khnoKNfS3fAl+EvRxqJe2EEEwRYrFPm/ZTtlFsKr8NUNcD2hfWIVUFVoGnHnswsvTSfIe7HQidhLtGvngze",
    "02Gbv7SZrGnJMVrnW5jU8e1Mky6n+XdEaihDljB4IfaEOhQ3Ao4LtCQVuSWE92rbsReS56Dyos6dEOZU7Wv4HXIwBuXpC5XQ",
    "v448HVIoEA+mYgWSWYnRKiJttSrGxPN6ON0j7LBAtRxeKWiDApawnjqHrCOVTkBWpPsUQFjNYJO3qF/tItBs8azTYFryhpo1",
    "+jRIv5oCk33iW4QH/C4TWWCm2tyQvNtCUKnno6CQAlimpi66L5N+54IhTQIDAQABo4IBxjCCAcIwDgYDVR0PAQH/BAQDAgeA",
    "MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDL60+EHaCeQawjSPx08jGU2KAYZMB8G",
    "A1UdIwQYMBaAFHcCOwExDx50d8NIyMMHY1WIpTuiMIGlBggrBgEFBQcBAQSBmDCBlTBCBggrBgEFBQcwAYY2aHR0cDovL29j",
    "c3AuZ2xvYmFsc2lnbi5jb20vZ3NvZmZsaW5lcjQ1dGltZXN0YW1wY2EyMDI1ME8GCCsGAQUFBzAChkNodHRwOi8vc2VjdXJl",
    "Lmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc29mZmxpbmVyNDV0aW1lc3RhbXBjYTIwMjUuY3J0MEoGA1UdHwRDMEEwP6A9oDuG",
    "OWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NvZmZsaW5lcjQ1dGltZXN0YW1wY2EyMDI1LmNybDBWBgNVHSAETzBNMAgG",
    "BmeBDAEEAjBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9y",
    "eS8wDQYJKoZIhvcNAQEMBQADggIBAI6ucKaPR4aRim6eLPr9YWb3WzoqOeGQwpiVtx+2CkwG2WHKxWeIQ58G+Fy+gVDDgA4c",
    "b01FW9mmQGdqDkO3UczcmDbWBFUIHAXI/URPwgPGh+VjHk4PhII0sezq8KDqsWQ1PzW/1nLy7TFfLdZug3mIr9JtOYsaoKsA",
    "YmKEsut8iG913BWt0HKIe14vGCO6BPolCiAJKgEXYmqYfRkEKXnXlu1tO5ZkutBSzm++Xaj3wx2O73LIlFYvM9VxSRGT13zE",
    "EGLrfwUE4C6jd9zJOEZyd7vBQ5r5OCGHAgdtnenFNimCjlwLERmwfwRfCJNRPAd/Sp6yyyD/Zd1wYfuzQBHhPI4nZCcBrJg4",
    "Az9c4HE3NRFCDiaEx08v8XxUIwqPeSglpVzHZqSHQHzaV79oFTyrY5r747A7CIcXl75/2b7KHJhvAZKiBYhXeGBGX5XIqtyH",
    "yC/fkUev9xXPyfT8I8ZFcaJglns/XA46Bh2QwPaIMpVhBvLkjH/EIHT+VIoueoSgV7N+acIlsaAAJWzAyzGEkRSO3ERxBz1p",
    "9qWd74g62zS//IJGKQmyeZVtLTHnQOTY4f5UKJT2z9fLOB8LtbOu1Dl2Ih1zYqyLckxMmbhrQuIQhlaK0Pn7o+iQ6RDz7flO",
    "wc7BSGzzsj/LImOUhmkBXg5/X8k3xtZUHcR2bhbOMIIGoDCCBIigAwIBAgIRAIPahje3nwyEDJR7hApSeB8wDQYJKoZIhvcN",
    "AQEMBQAwUzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2JhbFNpZ24gVGlt",
    "ZXN0YW1waW5nIFJvb3QgUjQ1MB4XDTI1MDcxNjAzMDUwNFoXDTQxMDcxNjAwMDAwMFowXjELMAkGA1UEBhMCQkUxGTAXBgNV",
    "BAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIw",
    "MjUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCkdxb47X2L4t0ChkVjNL7lf5Zi+dagWpcB+KvWHKeFRN0fhFbU",
    "Nv7I6atDbvmOWxDpvOhnec3QIydxlfgTRCGmnpC/Hbv5+Wl/N4xBpwPtVyJZSIXdMuK7vBPZsEJIQ1SfeF8Ywbg8m9gW87mj",
    "gMDWI28eEbihLNy2h2gl9vhzwSNVqELD80uLMHetr41Z7aBkFJpkqtozEW3rvrKrHtFxCeNsXhHQ4sai+xm3be9Tr0DkF2g/",
    "F0D3O72sz6pMGw8NVQl7FjARVTQZjsEnmZRZaeLIA8dbRa/gDOTm3sjRdQiMDf7Y4aSvR1UFdUEPIR4YFWthcR2F9UvC6Hoc",
    "EYkV0isRjkqgaWmhP7gEFB7hcIfmy/XlSj4zvZUpaM8DkTHed8UkLg/kVbVJHqiUJJoiu2dnNz7OCalLKIP4ZwTa51BFAdsO",
    "Lvh6deBrOTT6S2kdnVnyhO9JpIhESi9dItsfcoLy4UiRe5yXtc8ftkYiuYX14XjO6ijkUhSey9XrSQuoUPM+T5RsuaBkNQI+",
    "UUUEF6Fpo2+LETKbH043Ypd6/4x8ro5kKGoZus4LbC+8AUfIqVNltUd2o2K7S7lrZPUL11JNGfLX+HEvBzEv0FY/NAvCGyLJ",
    "epTMzu4PSUP349gxrFRiChVLGpvjG88KJWos1psj5a2MTNh9DQ/7q0FMWwIDAQABo4IBYjCCAV4wDgYDVR0PAQH/BAQDAgGG",
    "MBMGA1UdJQQMMAoGCCsGAQUFBwMIMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHcCOwExDx50d8NIyMMHY1WIpTui",
    "MB8GA1UdIwQYMBaAFEayHHfhexXwpTmhcN7RxC7qbbLeMIGOBggrBgEFBQcBAQSBgTB/MDcGCCsGAQUFBzABhitodHRwOi8v",
    "b2NzcC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1MEQGCCsGAQUFBzAChjhodHRwOi8vc2VjdXJlLmdsb2JhbHNp",
    "Z24uY29tL2NhY2VydC90aW1lc3RhbXByb290cjQ1LmNydDA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmdsb2JhbHNp",
    "Z24uY29tL3RpbWVzdGFtcHJvb3RyNDUuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAgEAMqPuftFu",
    "5GYxllheqUw9EmhHpfWf/+q5cYtV86kWhH1hrTkv3jDTLAGN6XIYZ/6cAH4JkVDuBQ53ZrZul+lbxfDkCsz5iM8R/wC0LgTp",
    "ivXTlTVg2OVNIRGhYkpzWGRI3mbh2mxi14XKTMVBXBfnSFgoffJnpVy7odrQQDmh/MumLaMraNtEMJdsU0uLmY7XEpF0HYDM",
    "AXR/kLTRvgfd3mwI4HyeNO8DBpMwYQx5OQtYzhn1j7dQ606mjVC7FdsOldWQtetobbmIvVW2+PEQDLjnfidQg0H3CE5GJwkl",
    "JMttrp84rZ//VAZYR17BYscDMT43mgfRCg1EAuknkmMh94ie876xB0GJ2c+4son3kdOPtfIy8mEVmO1sckaURbHhSApy40os",
    "MtdYAt/BAM3YN7LeRN93jLDidB2TU9y0ssrcXgvaecu/3gEySlj5F+Xneg4Q3jJO+3AJg/5UO5muS1zs1pyhNXFmcoaS/xrV",
    "qRyR07BBkL6LwDLVXLMwBf9Nvj6vdzrkHtykC2rc6hSKNdQmC9nFyLpNfvyyYvZNjLa1af7wbiSude/LYQtHZdicoQ5LgxWa",
    "tIKyMzmfFKuCETXRUNdBsR9r3eWGKR8Wgi4g0rNYMuq+7xm5ybES5/GkeM2edFVdf9m/kpCrym78xCg7PoMLvifn47ltLC9P",
    "myAwggajMIIEi6ADAgECAhB4SqqBc2ackAlU5CHJR+vAMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g",
    "Um9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTIwMTIwOTAwMDAwMFoX",
    "DTM0MTIxMDAwMDAwMFowUzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh",
    "bFNpZ24gVGltZXN0YW1waW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAunQz7CfcEjghG8XT",
    "YSjWWrxP34vMkYRDJFe8ZCG8OxwfPU+MrQe388XXAukRFIKaqrSUcjtxDRrvaGuFeY6vZupYmA26wXx50v/Ns28xRdAFdAQA",
    "cmonfrg3PzqI7ZeD9as1TQ+fWTv1L99ZxXylMnZglsjt7vgEfhlRcqi/REF6vHseOwCbvLrglr+Q/o2bw3KLABL4IDpgOPfB",
    "zIWK+4d5LqErIObLoIWRI7bEKAdUKN7sEDFPivLNFB8e3VUc6igxTPkhaqjN85Zn+gFBm80PC2h/u97xQ+oX5bDccCKzaTZZ",
    "dGvG5YkqfOULgV2rP4+40XZy83yiqeKXQb/MjEX+Ycn2bAcLAAToFSNPgiot9u/D+hE2SKHR/Xo5OjRdoywOm3dQIDRA3bED",
    "Ma1f6WKHc5YDYfeUsNlcbE/nFMXh8XsNI5zNcIwdat5KLYsqu9tCFAUHqvsU3DHT9h9sy75oZkRwTW0X+XHrBXOOkZJ162hc",
    "HvZEYRgpYt0XZojsKLpJb9s+d/65MR91HBiipke92O5IhTv9s+IPPyqYxpr6gm+xpaWGHVo6+qRsdA93UmFqf4cp3jmbi+6z",
    "RWAwJJcVEiqFMJMmrJamLehwbQupMq0smygKdkLyVWFRmJTe7fbFF288FRCwDq2w3sUW9GXRzC9aVgjPmcTwVZHCLHkCAwEA",
    "AaOCAXgwggF0MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW",
    "BBRGshx34XsV8KU5oXDe0cQu6m2y3jAfBgNVHSMEGDAWgBSubAWjkxPioufi1xzWx/B/yGdToDB7BggrBgEFBQcBAQRvMG0w",
    "LgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjYwOwYIKwYBBQUHMAKGL2h0dHA6Ly9zZWN1",
    "cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L3Jvb3QtcjYuY3J0MDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFs",
    "c2lnbi5jb20vcm9vdC1yNi5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh",
    "bHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4ICAQCLSLo2Vzxyxdp1+e8y9Ya93BIo44guTzZfJpnsDwEh",
    "EJaSOMZwa23zrtQOvSXvhn/iiY2VpX4pRANNqpio8bfc6iljIdztzYgKyxBpYXkpQgwjvOnF71IeLzM31U9memapR1Qzsd0W",
    "8thkcaMxlOVv9k1L4oRs0MklZ0/IS9DOSwXWPft9QfqKscAh4H4IsNlkK/nq8scK9M8uDDRg7my7kvA/8XtSEmh3WYH1HC6k",
    "Oow5Aw3t5cyvZkh5Y9VJuP9L0iVPSE6TO5N3sJpIbLagHbN0nl+9IgQ7fDcNhbXDmrvdnFoDjbQNn0x2NNWFrUV7tZ+7Lom7",
    "rMi/kmNIxj/KF6oNvAARX4vo40OEikM0zf07wKJ72x+4Z8iMFd4/pn/HKO+hb2+yQc8CIusB+EvI0nZvJd9e2mhoPXtEBMJB",
    "bkk7p5hWBO3RJisElNvk7WaOPYCdpKRVeVBe4/gaH8AWb5AVPIqmSKEMe7oq4LGphwVGm+0lVT03aZjtRpmYhUcKHmLb/Zzl",
    "wUNCjr3Pb/aMkf2C5J/sreOVVQXzSS9tNPf/Z+6ZQLvTmoBCQNojiWAfg3GStenmygr53cdsslhBnGaNmypvH29XBENcg107",
    "aZzeOfqETTXzextti/FvA8EpUuKUv3tUi99AegtwAnc/L4gHAgB10q/G1iIyGaM76DCCBYMwggNroAMCAQICDkXmuwODM8OF",
    "ZUjm/0VRMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i",
    "YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE0MTIxMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowTDEgMB4GA1UECxMX",
    "R2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wggIiMA0G",
    "CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCVB+hzymb57BTKezz3DQjxtEULLIK0SMbrWzyug7hBkjMUpG9/6SrMxrCIa8W2",
    "idHGsv8UzlEUIexK3RtaxtaH7k06FQbtZGYLkoDKRN5zlE7zp4l/T3hjCMgSUG1CZi9NuXkoTVIaihqAtxmBDn7EirxkTCEc",
    "Q2jXPTyKxbJm1ZCatzEGxb7ibTIGph75ueuqo7i/voJjUNDwGInf5A959eqiHyrScC5757yTu21T4kh8jBAHOP9msndhfuDq",
    "jDyqtKT285VKEgdt/Yyyic/QoGF3yFh0sNQjOvddOsqi250J3l1ELZDxgc1Xkvp+vFAEYzTfa5MYvms2sjnkrCQ2t/DvthwT",
    "V5O23rL44oW3c6K4NapF8uCdNqFvVIrxclZuLojFUUJEFZTuo8U4lptOTloLR/MGNkl3MLxxN+Wm7CEIdfzmYRY/d9XZkZeE",
    "CmzUAk10wBTt/Tn7g/JeFKEEsAvp/u6P4W4LsgizYWYJarEGOmWWWcDwNf3J2iiNGhGHcIEKqJp1HZ46hgUAntuA1iX53AWe",
    "J1lMdjlb6vmlodiDD9H/3zAR+YXPM0j1ym1kFCx6WE/TSwhJxZVkGmMOeT31s4zKWK2cQkV5bg6HGVxUsWW2v4yb3BPpDW+4",
    "LtxnbsmLEbWEFIoAGXCDeZGXkdQaJ783HjIH2BRjPChMrwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUw",
    "AwEB/zAdBgNVHQ4EFgQUrmwFo5MT4qLn4tcc1sfwf8hnU6AwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwDQYJ",
    "KoZIhvcNAQEMBQADggIBAIMl7ejR/ZVSzZ7ABKCRaeZc0ITe3K2iT+hHeNZlmKlbqDyHfAKK0W63FnPmX8BUmNV0vsHN4hGR",
    "rSMYPd3hckSWtJVewHuOmXgWQxNWV7Oiszu1d9xAcqyj65s1PrEIIaHnxEM3eTK+teecLEy8QymZjjDTrCHg4x362AczdlQA",
    "Iiq5TSAucGja5VP8g1zTnfL/RAxEZvLS471GABptArolXY2hMVHdVEYcTduZlu8aHARcphXveOB5/l3bPqpMVf2aFalv4ab7",
    "33Aw6cPuQkbtwpMFifp9Y3s/0HGBfADomK4OeDTDJfuvCp8ga907E48SjOJBGkh6c6B3ace2XH+CyB7+WBsoK6hsrV5twAXS",
    "e7frgP4lN/4Cm2isQl3D7vXM3PBQddI2aZzmewTfbgZptt4KCUhZh+t7FGB6ZKppQ++Rx0zsGN1s71MtjJnhXvJyPs9UyL1n",
    "7KQPTEX/07kwIwdMjxC/hpbZmVq0mVccpMy7FYlTuiwFD+TEnhmxGDTVTJ267fcfrySVBHioA7vugeXaX3yLSqGQdCWnsz5L",
    "yCxWvcfI7zjiXJLwefechLp0LWEBIH5+0fJPB1lfiy1DUutGDJTh9WZHeXfVVFsfrSQ3y0VaTqBESMjYsJnFFYQJ9tZJScBl",
    "uOYacW6gqPGC6EU+bNYC1wpngwVayaQQMYIDYTCCA10CAQEwczBeMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2ln",
    "biBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5lIFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx",
    "2yui9mDfK+QwCwYJYIZIAWUDBAICoIIBQTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDAL",
    "BglghkgBZQMEAgKhDQYJKoZIhvcNAQEMBQAwPwYJKoZIhvcNAQkEMTIEMIwOiJG3psabKcK7jd8sKtOkaXdueRAOhNoHdMuj",
    "v76IkjoRKTCYd2ISgyJqi0sxDjCBtAYLKoZIhvcNAQkQAi8xgaQwgaEwgZ4wgZsEIIMq1y5SP96sg/pGlLznxswmF2SIKGZW",
    "ZYjIrco6g4VRMHcwYqRgMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTQwMgYDVQQDEytHbG9i",
    "YWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFtcGluZyBDQSAyMDI1AhEAhHI/wZXMFvHbK6L2YN8r5DANBgkqhkiG9w0BAQwF",
    "AASCAYCn2faT1Idv520mtkdeUDDjMc9g4TQOs2NJi3g6i2k6djdN1ybWapUbV19feCerWvSL+bkd5vN8KSVX2nhg/nhQzmxp",
    "JIKbl/5SwpTCO36oLRjuv7EwJ6272zKHIq8TG5N6WBrSITnfwbaEimcNkxldUlFcfjFWKuLeNiFRFsOOj8wA09QWQDFj0IOu",
    "jF62RepvUXoJudbkNFUF19F14g547SZiCoLVoz/phKaklxECBpMHKMpfvL2xD4BbKb5LTXMuhaoCjvPyFlhURy36/JD2ed7W",
    "h6QBrzN8J0nShCFE1DfkjN+GR4eDDCYjSchP1LBOSOpgp1iq/wSGVYev6wMKBdOAZaQYJM8Xlv193dqX9n3eEi/fgt46Nbw+",
    "sqeXVqAVR+OjIqcvV2+1UpvTPS+CA9sQCYkPhldsMJkPFmW9CuZRBo6E5LsB/NWvh+3C5OrZ72A6e6FSW70MBgN8PGJTfb3X",
    "mdYLpX9PLXPqDSDVDKxSsAtv7JCxstB8pAwpOWg=",
)


def anchor_self_test():
    """Chain-head anchors. RSA known-answer vectors (PKCS#1 v1.5,
    PSS over SHA-256 and SHA-384), the pinned roots' fingerprints, the two
    real witness tokens captured in the 2026-10-02 interop probe (each passes
    against its own pinned root and fails against the other's, or when
    altered), anchor statement parsing, and verify_anchors on synthetic packs
    (unanchored, manifest 1.0, a tampered head, a missing statement, a summary
    that disagrees with the anchors, an unknown manifest version)."""
    import contextlib
    import io
    import tempfile

    ok = True

    def check(label, passed, what, output=""):
        nonlocal ok
        print(f"SELF-TEST assertion {label} {'PASS' if passed else 'FAIL'}: {what}")
        if not passed and output:
            print('\n'.join(f"    | {line}" for line in output.splitlines()))
        ok = ok and passed

    def code_of(fn):
        try:
            fn()
        except AnchorFailure as exc:
            return exc.code
        return "passed"

    # 25a-25c: RSA known-answer vectors (RSA-2048, e = 65537, generated with
    # OpenSSL over the message below), plus a flipped bit and a short input.
    spki = base64.b64decode("".join(_KAT_RSA_SPKI))
    cs, ce = _der_expect(spki, 0, len(spki), 0x30)
    kids = _der_children(spki, cs, ce)
    bits = spki[kids[1][1]:kids[1][2]]
    rcs, rce = _der_expect(bits, 1, len(bits), 0x30)
    ints = _der_children(bits, rcs, rce)
    n = _der_positive_int(bits[ints[0][1]:ints[0][2]])
    e = _der_positive_int(bits[ints[1][1]:ints[1][2]])
    message = b"meilynx-anchor-rsa-kat-v1"
    for label, kind, hash_name, sig_b64 in (
        ("25a", "v15", "sha256", "".join(_KAT_RSA_PKCS1_SHA256)),
        ("25b", "pss", "sha256", "".join(_KAT_RSA_PSS_SHA256)),
        ("25c", "pss", "sha384", "".join(_KAT_RSA_PSS_SHA384)),
    ):
        sig = base64.b64decode(sig_b64)
        digest = hashlib.new(hash_name, message).digest()
        if kind == "v15":
            run = lambda s: SIG_BACKEND.rsa_pkcs1v15(n, e, hash_name, digest, s)  # noqa: E731
        else:
            run = lambda s: SIG_BACKEND.rsa_pss(n, e, hash_name, digest, s, _RSA_HASH_LEN[hash_name])  # noqa: E731
        flipped = bytearray(sig)
        flipped[len(sig) // 2] ^= 0x01
        passed = run(sig) and not run(bytes(flipped)) and not run(sig[1:])
        check(label, passed, f"RSA {'PKCS#1 v1.5' if kind == 'v15' else 'PSS'} {hash_name} known-answer "
              f"vector verifies; a flipped bit and a truncated signature do not")

    # 25d: the pinned roots load and match their fingerprints.
    try:
        roots = load_pinned_tsa_roots()
        pinned = sorted(roots) == ["globalsign-r45", "sigstore"]
    except ValueError:
        roots, pinned = {}, False
    check("25d", pinned, "the pinned TSA roots (Sigstore, GlobalSign R6) match their SHA-256 fingerprints")
    if not pinned:
        return False

    # 25e-25f: the real probe tokens verify against their own pinned root.
    probe_imprint = hashlib.sha256(b"meilynx-anchor-interop-probe-2026-10-02").digest()
    real = {
        "sigstore": (base64.b64decode("".join(_REAL_SIGSTORE_TSR)), "2026-10-03T00:51:11Z", "ecdsa-p384-sha256"),
        "globalsign-r45": (base64.b64decode("".join(_REAL_GLOBALSIGN_TSR)), "2026-10-03T00:56:22Z",
                           "rsa-pkcs1-sha384"),
    }
    for label, tsa_id in (("25e", "sigstore"), ("25f", "globalsign-r45")):
        token, gen_time, algorithm = real[tsa_id]
        try:
            result = verify_tsa_token(token, probe_imprint, roots[tsa_id])
            passed = _iso(result["gen_time"]) == gen_time and result["signature_algorithm"] == algorithm
        except AnchorFailure as exc:
            passed, result = False, exc
        check(label, passed, f"the real {tsa_id} token verifies (genTime {gen_time}, {algorithm})", str(result))

    # 25g-25l: in-code mutations of the real tokens.
    def signer_signature_end(resp):
        top = _der_children(resp, *_der_expect(resp, 0, len(resp), 0x30))
        ci = _der_children(resp, top[1][1], top[1][2])
        sd = _der_children(resp, *_der_children(resp, ci[1][1], ci[1][2])[0][1:3])
        si = _der_children(resp, sd[-1][1], sd[-1][2])
        return _der_children(resp, si[0][1], si[0][2])[5][2]

    def tst_serial_end(resp):
        top = _der_children(resp, *_der_expect(resp, 0, len(resp), 0x30))
        ci = _der_children(resp, top[1][1], top[1][2])
        sd = _der_children(resp, *_der_children(resp, ci[1][1], ci[1][2])[0][1:3])
        encap = _der_children(resp, sd[2][1], sd[2][2])
        octets = _der_children(resp, encap[1][1], encap[1][2])[0]
        tst = _der_children(resp, *_der_expect(resp, octets[1], octets[2], 0x30))
        return tst[3][2]

    def flip(token, end):
        out = bytearray(token)
        out[end - 1] ^= 0x01
        return bytes(out)

    for tsa_id, other in (("sigstore", "globalsign-r45"), ("globalsign-r45", "sigstore")):
        token = real[tsa_id][0]
        roots_own = roots[tsa_id]
        cases = (
            ("against the other witness's pinned root", lambda: verify_tsa_token(token, probe_imprint, roots[other]),
             "untrusted_chain"),
            ("over a different imprint", lambda: verify_tsa_token(token, bytes(32), roots_own), "imprint_mismatch"),
            ("with one signature bit flipped",
             lambda: verify_tsa_token(flip(token, signer_signature_end(token)), probe_imprint, roots_own),
             "signature_invalid"),
            ("with the TSTInfo serial number altered",
             lambda: verify_tsa_token(flip(token, tst_serial_end(token)), probe_imprint, roots_own),
             "message_digest_mismatch"),
            ("truncated", lambda: verify_tsa_token(token[:-1], probe_imprint, roots_own), "malformed"),
            ("when the root's trust window has not opened at genTime",
             lambda: verify_tsa_token(token, probe_imprint, [
                 TsaRoot(r.name, r.cert.der, _rfc3339_to_epoch("2030-01-01T00:00:00Z"), float("inf"))
                 for r in roots_own]),
             "no_root_trusted_at_gen_time"),
        )
        for index, (what, fn, expected) in enumerate(cases):
            got = code_of(fn)
            label = f"25{'ghijkl'[index]}" + ("" if tsa_id == "sigstore" else "2")
            check(label, got == expected, f"the real {tsa_id} token fails {what} ({expected})", f"got {got}")

    # 25m: the Fulcio path's Certificate stays EC-only: an RSA certificate
    # from the GlobalSign token is refused there.
    gs = real["globalsign-r45"][0]
    rsa_cert = _tsa_certificates(gs)[0]
    try:
        Certificate(rsa_cert)
        refused = False
    except DerError:
        refused = True
    check("25m", refused and TsaCertificate(rsa_cert).key_kind == "rsa",
          "the Fulcio certificate parser still refuses an RSA key; the TSA parser reads it as RSA")

    # 25n: anchor statements — canonical bytes parse; a re-encoding, an
    # unknown field and an unsorted head list are refused.
    head0 = {"chain": "chain_a", "event_hash": "0" * 64, "seq": 7}
    head1 = {"chain": "chain_b", "event_hash": "1" * 64, "seq": 9}
    statement = {"created_at": "2026-10-02T12:00:00.123Z", "hash_alg": "sha-256", "heads": [head0, head1],
                 "run_id": "run-1", "v": "meilynx.anchor.v1"}
    canonical = jcs_dumps(statement).encode("utf-8")
    outcomes = (
        code_of(lambda: parse_anchor_statement(canonical)),
        code_of(lambda: parse_anchor_statement(json.dumps(statement).encode("utf-8"))),
        code_of(lambda: parse_anchor_statement(jcs_dumps(dict(statement, extra=1)).encode("utf-8"))),
        code_of(lambda: parse_anchor_statement(jcs_dumps(dict(statement, heads=[head1, head0])).encode("utf-8"))),
    )
    check("25n", outcomes == ("passed", "statement_non_canonical", "statement_malformed", "statement_malformed"),
          "anchor statements: canonical bytes parse; non-canonical, extra-field and unsorted statements fail",
          repr(outcomes))

    # 25o-25t: verify_anchors on a synthetic three-record chain.
    genesis = genesis_hash()
    events = []
    for seq in range(3):
        prev = events[-1]["event_hash"] if events else genesis
        event = {
            "schema_version": "v1", "sequence_number": seq, "timestamp_utc": f"2026-01-01T00:00:0{seq}+00:00",
            "event_id": f"evt-{seq}", "request_id": f"req-{seq}", "model_requested": "gpt-4.1-mini",
            "action": "allow", "input_tokens": 11, "output_tokens": 7, "total_tokens": 18,
            "cache_creation_input_tokens": None, "cache_read_input_tokens": None, "cached_input_tokens": None,
            "reasoning_tokens": None, "estimated_cost_usd": 0.000123, "previous_hash": prev,
        }
        event["event_hash"] = recompute_event_hash(event, seq, prev)
        events.append(event)
    head_statement = jcs_dumps({
        "created_at": "2026-01-01T00:00:05.000Z", "hash_alg": "sha-256",
        "heads": [{"chain": "self-test", "event_hash": events[2]["event_hash"], "seq": 2}],
        "run_id": "run-self-test", "v": "meilynx.anchor.v1"}).encode("utf-8")
    placeholder_token = b"not a token"

    def manifest_with(anchoring, version="1.1"):
        return {"schema_version": version, "hash_version": "v1", "prefix": "audit/self-test/",
                "from_sequence": 0, "to_sequence": 2, "anchoring": anchoring,
                "events": [{"sequence": s, "recomputed_event_hash": events[s]["event_hash"]} for s in range(3)]}

    unanchored = {"state": "unanchored", "chains": [{
        "chain": "self-test", "reason": "no_anchors_found", "anchored_through_seq": None,
        "unanchored_tail": {"from_seq": 0, "to_seq": 2}, "anchors": [], "seals": []}]}
    anchored = {"state": "anchored", "chains": [{
        "chain": "self-test", "reason": "anchored", "anchored_through_seq": 2, "unanchored_tail": None,
        "anchors": [{"seq": 2,
                     "statement": {"key": f"anchors/self-test/{2:020d}.json",
                                   "sha256": hashlib.sha256(head_statement).hexdigest()},
                     "tokens": {"sigstore": {"sha256": hashlib.sha256(placeholder_token).hexdigest(),
                                             "gen_time": "2026-01-01T00:00:05Z"}}}],
        "seals": []}]}

    with tempfile.TemporaryDirectory() as tmp:
        records = Path(tmp)
        anchors_dir = records / "anchors"
        anchors_dir.mkdir()
        for ev in events:
            (records / record_file_name(ev["sequence_number"])).write_bytes(json.dumps(ev).encode("utf-8"))

        def run(manifest, source=DirectoryAnchorSource(anchors_dir)):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                status = verify_anchors(manifest, local_fetcher(records), source, roots.get)
            return status, out.getvalue()

        status, output = run(manifest_with(unanchored))
        check("25o", status == PASSED and output == "ANCHORS: none\n",
              "a 1.1 pack with state unanchored passes with one ANCHORS: none line", output)

        status, output = run(dict(manifest_with(None, version="1.0")))
        check("25p", status == PASSED and output == "ANCHORS: none (manifest 1.0 predates anchoring)\n",
              "a 1.0 pack passes with one ANCHORS: none line", output)

        status, output = run(manifest_with(anchored))
        check("25q", status == FAILED and "FAIL anchor seq=2: statement object is missing" in output,
              "a listed anchor whose statement object is missing fails", output)

        (anchors_dir / f"{2:020d}.json").write_bytes(head_statement)
        (anchors_dir / f"{2:020d}.sigstore.tsr").write_bytes(placeholder_token)
        tampered = dict(events[2], input_tokens=12)
        tampered["event_hash"] = recompute_event_hash(tampered, 2, tampered["previous_hash"])
        (records / record_file_name(2)).write_bytes(json.dumps(tampered).encode("utf-8"))
        status, output = run(manifest_with(anchored))
        check("25r", status == FAILED and "the record changed after it was anchored" in output,
              "a record rewritten after its head was anchored fails, even with its own hash recomputed", output)

        (records / record_file_name(2)).write_bytes(json.dumps(events[2]).encode("utf-8"))
        status, output = run(manifest_with(anchored))
        check("25s", status == CANNOT_EVALUATE and "token cannot be parsed" in output,
              "an unparseable token cannot be evaluated (exit 2), never passes", output)

        claims_anchored = {"state": "anchored", "chains": [dict(unanchored["chains"][0], anchored_through_seq=2,
                                                                 unanchored_tail=None)]}
        status, output = run(manifest_with(claims_anchored), source=DirectoryAnchorSource(records / "none"))
        check("25t", status == FAILED and "anchoring summary does not match" in output,
              "a manifest claiming coverage that no anchor provides fails", output)

    # 25w: the clock check covers every anchored record, each against the
    # earliest anchor at or after it. Anchors at 2 (genTime 100) and 5
    # (genTime 50, an earlier token on a later head): records 0-5 all compare
    # with 50; records 3 and 5 are ahead, 4 is unreadable, 6 is uncovered.
    times = {0: 40, 1: 50, 2: 349, 3: 351, 5: 900, 6: 10_000}

    def epoch(seq):
        if seq not in times:
            raise ValueError("no timestamp")
        return times[seq]

    got = records_clock_ahead([(5, 50), (2, 100)], 0, epoch)
    check("25w", got == (2, (3, 351, 50), 1) and records_clock_ahead([], 0, epoch) == (0, None, 0),
          "the record clock check covers every anchored record against the earliest covering genTime", repr(got))

    # 25x: a token that verifies through a --tsa-root root reports that root;
    # through a pinned root it does not.
    sigstore_token = real["sigstore"][0]
    pinned_root = roots["sigstore"][0]
    supplied = TsaRoot("sigstore-root-0", pinned_root.cert.der, pinned_root.start, pinned_root.end, supplied=True)
    via_pinned = verify_tsa_token(sigstore_token, probe_imprint, roots["sigstore"])["root"]
    via_supplied = verify_tsa_token(sigstore_token, probe_imprint, [supplied])["root"]
    notice = supplied_root_notice("sigstore", via_supplied)
    check("25x", not via_pinned.supplied and via_supplied.supplied
          and "witness sigstore" in notice and pinned_root.fingerprint in notice,
          "a token verified through a --tsa-root root is reported with that root's SHA-256 and witness id",
          notice)

    errors = (manifest_schema_version_error({"schema_version": "1.1"}),
              manifest_schema_version_error({}),
              manifest_schema_version_error({"schema_version": "1.2"}),
              manifest_schema_version_error({"schema_version": "2.0"}))
    check("25u", errors[0] is None and errors[1] is None and errors[2] is None and errors[3] is not None,
          "manifest schema_version 1.0 / 1.1 / 1.2 / absent is understood; anything else is refused (exit 2)",
          repr(errors))
    check("25v", "chain-anchors-v1" in VERIFIER_CAPABILITIES,
          "VERIFIER_CAPABILITIES advertises chain-anchors-v1")
    return ok


def _tsa_certificates(resp):
    """The certificates carried in a TimeStampResp, as DER (self-test helper)."""
    top = _der_children(resp, *_der_expect(resp, 0, len(resp), 0x30))
    ci = _der_children(resp, top[1][1], top[1][2])
    sd = _der_children(resp, *_der_children(resp, ci[1][1], ci[1][2])[0][1:3])
    certs = next(f for f in sd[3:] if f[0] == 0xA0)
    return [resp[c[3]:c[2]] for c in _der_children(resp, certs[1], certs[2])]



# ---------------------------------------------------------------------------
# OCSF evidence export
# ---------------------------------------------------------------------------

# Where each digest an exported event carries lives on the pack record.
_OCSF_DIGEST_SOURCES = {
    'prompt_sha256_jcs': ('content',),
    'response_sha256': ('content',),
    'stored_prompt_sha256_jcs': ('content',),
    'stored_response_sha256': ('content',),
    'findings_sha256_jcs': ('content',),
    'tool_calls_sha256_jcs': ('content',),
    'stored_tool_calls_sha256_jcs': ('content',),
    'payload_sha256_jcs': ('mcp_event',),
    'redacted_payload_sha256_jcs': ('mcp_event',),
    'redaction_pre_sha256_jcs': ('mcp_event',),
    'redaction_post_sha256_jcs': ('mcp_event',),
    'mcp_bundle_sha256': ('mcp_event',),
    'evidence_set_sha256': ('decision_receipt',),
    'registry_digest': ('decision_receipt',),
    'outcomes_sha256_jcs': ('evaluation_trace',),
    'asserted_digest': ('identity',),
}


def _jwk_to_point(jwk):
    """A P-256 public JWK ({kty: EC, crv: P-256, x, y}) -> the affine point."""
    if not isinstance(jwk, dict) or jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256':
        raise ValueError('ocsf public key must be a P-256 EC JWK')

    def b64url(v):
        v = v + '=' * (-len(v) % 4)
        return base64.urlsafe_b64decode(v)

    x = int.from_bytes(b64url(jwk['x']), 'big')
    y = int.from_bytes(b64url(jwk['y']), 'big')
    point = (x, y)
    if not _on_curve(P256, point):
        raise ValueError('ocsf public key is not on P-256')
    return point


def verify_ocsf_manifest_signature(manifest_bytes, signature_b64, public_point):
    """True iff `signature_b64` (64 raw bytes r || s, standard base64) is a
    valid ECDSA P-256 signature over SHA-256 of `manifest_bytes`."""
    try:
        raw = base64.b64decode(signature_b64.strip(), validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(raw) != 64:
        return False
    r = int.from_bytes(raw[:32], 'big')
    s_ = int.from_bytes(raw[32:], 'big')
    return ecdsa_verify(P256, public_point, hashlib.sha256(manifest_bytes).digest(), r, s_)


def load_ocsf_export(path):
    """The export manifests `path` names: a `.manifest.json` file, a day's
    `index.json` (its `manifests` keys resolved against the sink root that
    holds them), or a directory searched for `*.manifest.json`. Returns
    [(manifest_path, manifest_bytes, manifest)] sorted by chain and
    first sequence."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"ocsf export not found at {path}")
    manifest_paths = []
    if path.is_dir():
        manifest_paths = sorted(path.rglob('*.manifest.json'))
    elif path.name == 'index.json':
        index = json.loads(path.read_bytes())
        keys = index.get('manifests') or []
        if not isinstance(keys, list):
            raise ValueError(f"{path}: index.json has no manifests list")
        for key in keys:
            # The key is sink-relative (`ocsf/v1/...`); find the ancestor of
            # the index that holds it.
            resolved = None
            for ancestor in [path.parent, *path.parent.parents]:
                candidate = ancestor / key
                if candidate.exists():
                    resolved = candidate
                    break
            manifest_paths.append(resolved if resolved is not None else path.parent / Path(key).name)
    else:
        manifest_paths = [path]
    out = []
    for mp in manifest_paths:
        if not Path(mp).exists():
            raise FileNotFoundError(f"ocsf export manifest not found: {mp}")
        raw = Path(mp).read_bytes()
        try:
            doc = json.loads(raw)
        except ValueError as exc:
            raise ValueError(f"{mp}: manifest is not valid JSON: {exc}") from exc
        out.append((Path(mp), raw, doc))
    out.sort(key=lambda t: (str(t[2].get('chain_id', '')), int(t[2].get('first_sequence', 0) or 0)))
    return out


def verify_ocsf_export(entries, pack_chain, pack_records, public_point=None, quiet=False):
    """Check an OCSF export against the pack. `entries` is what
    load_ocsf_export returned; `pack_chain` the pack's chain name;
    `pack_records` sequence -> the pack record (as verify_manifest_with
    read it). Returns (content_status, signature_status): content is
    PASSED, FAILED or CANNOT_EVALUATE; signature is PASSED (every manifest
    signed and verified), FAILED (a signature did not verify, or a manifest
    says it is signed and has no `.sig`), UNSIGNED (at least one manifest
    unsigned, or signed with no public key given), or CANNOT_EVALUATE."""
    import gzip

    def report(line):
        if not quiet:
            print(line)

    if not entries:
        report("WARN: no OCSF export manifest found — nothing to check.")
        return PASSED, UNSIGNED
    content_ok = True
    cannot = False
    sig_statuses = []
    last_by_chain = {}
    events_checked = 0
    outside = 0
    for mpath, mbytes, m in entries:
        label = m.get('object') or mpath.name
        version = str(m.get('mapping_version', ''))
        if version not in SUPPORTED_OCSF_MAPPING_VERSIONS:
            report(f"CANNOT EVALUATE {label}: ocsf mapping_version {version!r} is not one this verifier reads "
                   f"{SUPPORTED_OCSF_MAPPING_VERSIONS}")
            cannot = True
            continue
        chain_id = str(m.get('chain_id', ''))
        first_seq = m.get('first_sequence')
        last_seq = m.get('last_sequence')
        if not isinstance(first_seq, int) or not isinstance(last_seq, int):
            report(f"FAIL {label}: manifest first_sequence/last_sequence are not integers")
            content_ok = False
            continue
        # Gaps between consecutive manifests of one chain.
        prev_last = last_by_chain.get(chain_id)
        if prev_last is not None and first_seq != prev_last + 1:
            if first_seq > prev_last + 1:
                report(f"WARN export_gap chain={chain_id}: sequences {prev_last + 1}..{first_seq - 1} "
                       f"have no export manifest between the previous object and {label}")
            else:
                report(f"WARN export_overlap chain={chain_id}: {label} starts at {first_seq}, "
                       f"below the previous object's last sequence {prev_last}")
        last_by_chain[chain_id] = max(last_seq, prev_last if prev_last is not None else last_seq)

        # Signature.
        sig_path = mpath.with_name(mpath.name[:-len('.manifest.json')] + '.manifest.sig') \
            if mpath.name.endswith('.manifest.json') else mpath.with_suffix('.sig')
        if m.get('signed'):
            if not sig_path.exists():
                report(f"FAIL {label}: manifest says it is signed but {sig_path.name} is missing")
                sig_statuses.append(FAILED)
            elif public_point is None:
                report(f"UNSIGNED-CHECK {label}: manifest is signed (key id {m.get('public_key_id')!r}) but no "
                       f"--ocsf-public-key was given; authenticity not established")
                sig_statuses.append(UNSIGNED)
            else:
                sig_b64 = sig_path.read_text(encoding='utf-8')
                if verify_ocsf_manifest_signature(mbytes, sig_b64, public_point):
                    report(f"OK   {label}: manifest signature verified (key id {m.get('public_key_id')!r})")
                    sig_statuses.append(PASSED)
                else:
                    report(f"FAIL {label}: manifest signature does not verify under the given key")
                    sig_statuses.append(FAILED)
        else:
            report(f"UNSIGNED {label}: manifest carries no signature; authenticity not established")
            sig_statuses.append(UNSIGNED)

        # Object bytes.
        object_path = mpath.with_name(Path(str(m.get('object', ''))).name)
        if not object_path.exists():
            report(f"FAIL {label}: object {object_path.name} is missing beside its manifest")
            content_ok = False
            continue
        obj = object_path.read_bytes()
        digest = hashlib.sha256(obj).hexdigest()
        if digest != m.get('object_sha256'):
            report(f"FAIL {label}: object_sha256 mismatch (manifest {m.get('object_sha256')}, object {digest})")
            content_ok = False
            continue
        try:
            text = gzip.decompress(obj).decode('utf-8')
        except (OSError, EOFError, UnicodeDecodeError) as exc:
            report(f"FAIL {label}: object is not gzip NDJSON: {exc}")
            content_ok = False
            continue
        lines = [ln for ln in text.split('\n') if ln.strip()]
        if len(lines) != m.get('event_count'):
            report(f"FAIL {label}: event_count mismatch (manifest {m.get('event_count')}, object {len(lines)})")
            content_ok = False
        sequences = set()
        for n, line in enumerate(lines, start=1):
            try:
                ev = json.loads(line)
            except ValueError as exc:
                report(f"FAIL {label} line {n}: not JSON: {exc}")
                content_ok = False
                continue
            chain = ((ev.get('meilynx') or {}).get('chain')) or {}
            ev_chain = chain.get('chain_id')
            seq = chain.get('sequence_number')
            if ev_chain != chain_id:
                report(f"FAIL {label} line {n}: field meilynx.chain.chain_id is {ev_chain!r}, "
                       f"manifest chain is {chain_id!r}")
                content_ok = False
                continue
            if not isinstance(seq, int) or not (first_seq <= seq <= last_seq):
                report(f"FAIL {label} line {n}: field meilynx.chain.sequence_number {seq!r} is outside "
                       f"the manifest range {first_seq}..{last_seq}")
                content_ok = False
                continue
            sequences.add(seq)
            if chain_id != pack_chain or seq not in pack_records:
                outside += 1
                continue
            record = pack_records[seq]
            problems = []
            if chain.get('event_id') != record.get('event_id'):
                problems.append(f"meilynx.chain.event_id {chain.get('event_id')!r} != pack {record.get('event_id')!r}")
            if chain.get('event_hash') != record.get('event_hash'):
                problems.append(f"meilynx.chain.event_hash {chain.get('event_hash')!r} != pack {record.get('event_hash')!r}")
            if chain.get('previous_hash') is not None and chain.get('previous_hash') != record.get('previous_hash'):
                problems.append("meilynx.chain.previous_hash differs from the pack record")
            digests = (ev.get('meilynx') or {}).get('digests') or {}
            for key, value in digests.items():
                if value is None:
                    continue
                source = _OCSF_DIGEST_SOURCES.get(key)
                if source is None:
                    problems.append(f"meilynx.digests.{key} is not a digest this verifier knows")
                    continue
                holder = record.get(source[0]) or {}
                if holder.get(key) != value:
                    problems.append(f"meilynx.digests.{key} {value!r} != pack {holder.get(key)!r}")
            if problems:
                for problem in problems:
                    report(f"FAIL {label} line {n} seq={seq}: {problem}")
                content_ok = False
            else:
                events_checked += 1
        if len(sequences) != m.get('record_count'):
            report(f"FAIL {label}: record_count mismatch (manifest {m.get('record_count')}, object holds "
                   f"{len(sequences)} distinct sequences)")
            content_ok = False
        if sequences and (min(sequences) != first_seq or max(sequences) != last_seq):
            report(f"FAIL {label}: object sequences span {min(sequences)}..{max(sequences)}, manifest says "
                   f"{first_seq}..{last_seq}")
            content_ok = False
    if outside:
        report(f"WARN export_record_outside_pack: {outside} exported event(s) name a chain or sequence the pack "
               f"does not hold; not checked")
    report(f"OCSF export: {events_checked} event(s) checked against the pack across {len(entries)} manifest(s).")
    if cannot and content_ok:
        content_status = CANNOT_EVALUATE
    else:
        content_status = PASSED if content_ok else FAILED
    if FAILED in sig_statuses:
        signature_status = FAILED
    elif UNSIGNED in sig_statuses or not sig_statuses:
        signature_status = UNSIGNED
    else:
        signature_status = PASSED
    return content_status, signature_status


def _exit_code_rank(code):
    return {EXIT_FAIL: 3, EXIT_CANNOT_EVALUATE: 2, EXIT_UNSIGNED: 1, EXIT_OK: 0}[code]


def _ec_mul(c, k, point):
    """k * point on curve c, affine, for the self-test's signer."""
    acc = _INFINITY
    base = (point[0], point[1], 1)
    for i in range(k.bit_length() - 1, -1, -1):
        acc = _jacobian_double(c, acc)
        if (k >> i) & 1:
            acc = _jacobian_add(c, acc, base)
    x, y, z = acc
    if z == 0:
        raise ValueError('point at infinity')
    zinv = pow(z, -1, c.p)
    return (x * zinv * zinv % c.p, y * zinv * zinv * zinv % c.p)


def ocsf_export_self_test():
    """The export check end to end on a synthetic
    two-record chain and a synthetic export: a clean signed export verifies
    (34a); an edited line fails naming the line and the field (34b); a
    deleted object fails naming the object (34c); a manifest missing between
    two others is WARN export_gap and still verifies (34d); an unsigned
    manifest lands at UNSIGNED (34e); the wrong key fails (34f); a mapping
    version this verifier does not read is CANNOT EVALUATE (34g); an event
    on a sequence the pack does not hold is a WARN, not a failure (34h)."""
    import gzip
    import io
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
        # The export check compares digests against the pack record as read;
        # a v1 record hashes no content block, so it is attached after the
        # hash for the comparison only (the records are never re-hashed here).
        event['content'] = {'capture_policy': 'hash_only', 'prompt_sha256_jcs': 'd' * 64}
        return event

    chain = 'chain_tnt_selftest_proxy'
    first = make_event(0, genesis, 11)
    second = make_event(1, first['event_hash'], 13)
    third = make_event(2, second['event_hash'], 17)
    records = {0: first, 1: second, 2: third}
    # A test signing key (not a secret of anything): d and Q = d*G.
    d = 0x1F2E3D4C5B6A79880123456789ABCDEF0123456789ABCDEF0123456789ABCDE1
    q = _ec_mul(P256, d, P256.g)

    def sign(canonical_bytes):
        e = int.from_bytes(hashlib.sha256(canonical_bytes).digest(), 'big')
        k = 0x6A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F9 % P256.n
        r = _ec_mul(P256, k, P256.g)[0] % P256.n
        s_ = pow(k, -1, P256.n) * (e + r * d) % P256.n
        return base64.b64encode(r.to_bytes(32, 'big') + s_.to_bytes(32, 'big')).decode('ascii')

    def ocsf_event(ev):
        return {
            'class_uid': 6003, 'category_uid': 6, 'activity_id': 1, 'type_uid': 600301, 'severity_id': 1,
            'time': 0, 'metadata': {'version': '1.5.0', 'uid': ev['event_id']},
            'meilynx': {
                'chain': {'chain_id': chain, 'sequence_number': ev['sequence_number'], 'event_id': ev['event_id'],
                          'event_hash': ev['event_hash'], 'previous_hash': ev['previous_hash']},
                'digests': {'prompt_sha256_jcs': ev['content']['prompt_sha256_jcs'], 'response_sha256': None},
            },
        }

    def write_export(root, events, first_seq, last_seq, signed=True, key_d=None, mapping_version='1'):
        name = f'{first_seq:020d}-{last_seq:020d}.ndjson.gz'
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb', mtime=0) as gz:
            gz.write(('\n'.join(json.dumps(ocsf_event(e)) for e in events) + '\n').encode('utf-8'))
        obj = buf.getvalue()
        object_key = f'ocsf/v1/pxy_selftest/{chain}/2026/01/01/{name}'
        manifest = {
            'export_id': 'exp_selftest', 'proxy_external_id': 'pxy_selftest', 'chain_id': chain,
            'first_sequence': first_seq, 'last_sequence': last_seq, 'record_count': len(events),
            'event_count': len(events), 'object': object_key, 'object_sha256': hashlib.sha256(obj).hexdigest(),
            'ocsf_version': '1.5.0', 'semconv_version': '1.37.0', 'mapping_version': mapping_version,
            'generated_at': '2026-01-01T00:00:10Z', 'proxy_version': '0.0.0-selftest', 'image_digest': None,
            'chain_head': {'sequence': last_seq}, 'anchor': None, 'signed': signed, 'public_key_id': 'k1' if signed else None,
            'last_record': {'sequence': last_seq, 'event_id': events[-1]['event_id'], 'event_hash': events[-1]['event_hash']},
        }
        mbytes = jcs_dumps(manifest).encode('utf-8')
        day = root / 'ocsf' / 'v1' / 'pxy_selftest' / chain / '2026' / '01' / '01'
        day.mkdir(parents=True, exist_ok=True)
        (day / name).write_bytes(obj)
        (day / f'{name}.manifest.json').write_bytes(mbytes)
        if signed:
            (day / f'{name}.manifest.sig').write_text(sign(mbytes), encoding='utf-8')
        return day, name

    def check(tag, cond, text):
        print(f"SELF-TEST assertion {tag} {'PASS' if cond else 'FAIL'}: {text}")
        return cond

    ok = True
    jwk_point = q
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        day, name_a = write_export(root, [first, second], 0, 1)
        entries = load_ocsf_export(day / f'{name_a}.manifest.json')
        content, sig = verify_ocsf_export(entries, chain, records, public_point=jwk_point, quiet=True)
        ok = check('34a', (content, sig) == (PASSED, PASSED), "a clean signed export verifies against the pack") and ok

        # 29b: an edited line names the line and the field.
        tampered_lines = [json.dumps(ocsf_event(first)), json.dumps(ocsf_event(second)).replace(second['event_hash'], 'f' * 64)]
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb', mtime=0) as gz:
            gz.write(('\n'.join(tampered_lines) + '\n').encode('utf-8'))
        tampered_obj = buf.getvalue()
        m = json.loads((day / f'{name_a}.manifest.json').read_bytes())
        m['object_sha256'] = hashlib.sha256(tampered_obj).hexdigest()
        mbytes = jcs_dumps(m).encode('utf-8')
        tdir = root / 'tampered'
        tdir.mkdir()
        (tdir / name_a).write_bytes(tampered_obj)
        (tdir / f'{name_a}.manifest.json').write_bytes(mbytes)
        (tdir / f'{name_a}.manifest.sig').write_text(sign(mbytes), encoding='utf-8')
        captured = []
        real_print = print
        try:
            import builtins
            builtins.print = lambda *a, **k: captured.append(' '.join(str(x) for x in a))
            content, sig = verify_ocsf_export(load_ocsf_export(tdir), chain, records, public_point=jwk_point)
        finally:
            builtins.print = real_print
        named = any('line 2' in c and 'meilynx.chain.event_hash' in c and c.startswith('FAIL') for c in captured)
        ok = check('34b', content == FAILED and sig == PASSED and named,
                   "an edited exported line fails, naming the line and the field") and ok

        # 29c: a deleted object names the object.
        (day / name_a).unlink()
        captured.clear()
        try:
            builtins.print = lambda *a, **k: captured.append(' '.join(str(x) for x in a))
            content, _ = verify_ocsf_export(load_ocsf_export(day / f'{name_a}.manifest.json'), chain, records, public_point=jwk_point)
        finally:
            builtins.print = real_print
        ok = check('34c', content == FAILED and any(c.startswith('FAIL') and name_a in c and 'missing' in c for c in captured),
                   "a deleted export object fails, naming the object") and ok

        # 29d: a gap between manifests is a WARN and still verifies; 29h: a
        # sequence the pack does not hold is a WARN, not a failure.
        gap_root = root / 'gap'
        gap_root.mkdir()
        write_export(gap_root, [first], 0, 0)
        fourth = make_event(3, third['event_hash'], 19)
        gday, _ = write_export(gap_root, [third, fourth], 2, 3)
        captured.clear()
        try:
            builtins.print = lambda *a, **k: captured.append(' '.join(str(x) for x in a))
            content, sig = verify_ocsf_export(load_ocsf_export(gap_root), chain, records, public_point=jwk_point)
        finally:
            builtins.print = real_print
        ok = check('34d', content == PASSED and any('WARN export_gap' in c and '1..1' in c for c in captured),
                   "a manifest missing between two others is WARN export_gap and still verifies") and ok
        ok = check('34h', any('WARN export_record_outside_pack: 1' in c for c in captured),
                   "an exported event on a sequence the pack does not hold is a WARN, not a failure") and ok

        # 29e: unsigned lands at UNSIGNED; 29f: the wrong key fails.
        uroot = root / 'unsigned'
        uroot.mkdir()
        uday, uname = write_export(uroot, [first, second], 0, 1, signed=False)
        content, sig = verify_ocsf_export(load_ocsf_export(uday / f'{uname}.manifest.json'), chain, records, public_point=jwk_point, quiet=True)
        ok = check('34e', (content, sig) == (PASSED, UNSIGNED), "an unsigned manifest verifies its content and lands at UNSIGNED") and ok
        wrong = _ec_mul(P256, d + 1, P256.g)
        content, sig = verify_ocsf_export(load_ocsf_export(gday / f'{gday.name and sorted(p.name for p in gday.glob("*.manifest.json"))[0]}'), chain, records, public_point=wrong, quiet=True)
        ok = check('34f', sig == FAILED, "a manifest signed with another key fails") and ok
        content, sig = verify_ocsf_export(load_ocsf_export(gap_root), chain, records, public_point=None, quiet=True)
        ok = check('34i', sig == UNSIGNED and content == PASSED, "a signed manifest with no public key given is not verified, and says so") and ok

        # 29g: a mapping version this verifier does not read.
        vroot = root / 'version'
        vroot.mkdir()
        vday, vname = write_export(vroot, [first], 0, 0, mapping_version='9')
        content, _ = verify_ocsf_export(load_ocsf_export(vday / f'{vname}.manifest.json'), chain, records, public_point=jwk_point, quiet=True)
        ok = check('34g', content == CANNOT_EVALUATE, "an unknown ocsf mapping_version is CANNOT EVALUATE, never a pass") and ok

        # The index.json route resolves sink-relative keys.
        index = gday / 'index.json'
        index.write_text(json.dumps({'manifests': [f'ocsf/v1/pxy_selftest/{chain}/2026/01/01/{p.name}' for p in sorted(gday.glob('*.manifest.json'))]}), encoding='utf-8')
        ok = check('34j', len(load_ocsf_export(index)) == 2, "a day's index.json resolves its manifests against the sink root") and ok
    ok = check('34k', 'ocsf-export-v1' in VERIFIER_CAPABILITIES, "VERIFIER_CAPABILITIES advertises ocsf-export-v1") and ok
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
            'Offline mode: a directory of chain record objects as the bucket stores them '
            '(<seq:020d>.bin and <first:020d>-<last:020d>.seg, in any mix), '
            'or a .jsonl / .json file of records. No network, no Google client library.'
        ),
    )
    parser.add_argument('--manifest', help='Path to manifest.json')
    parser.add_argument(
        '--export-records',
        metavar='DIR',
        help=(
            'Also write every record read to DIR/<seq:020d>.bin, one file per record and '
            'byte-identical to a per-record object (segments are split), so the verified '
            'chain can be handed to a reviewer who has no bucket access (they then run '
            '--records DIR). With --bucket, or with a --records directory.'
        ),
    )
    parser.add_argument(
        '--self-test',
        action='store_true',
        help=(
            'Run encoding self-test against the substrate fixture hashes and exit. '
            'Exercises both the +00:00 fixture and the Z-suffix normalization path, '
            'the offline --records path on a synthetic chain, segment objects, and the signature '
            'checks (ECDSA test vectors, a tamper matrix, a real Sigstore bundle).'
        ),
    )
    parser.add_argument(
        '--certificate-identity',
        default=None,
        metavar='IDENTITY',
        help=(
            f'Signer identity a signed pack must carry. Default: {PINNED_SIGNER_IDENTITY}. '
            f'A pack signed by a per-tenant signer needs the exact service-account email the '
            f'evidence holder published for the project; without it the pack cannot be evaluated.'
        ),
    )
    parser.add_argument(
        '--certificate-oidc-issuer',
        default=None,
        metavar='ISSUER',
        help=(
            f'OIDC issuer a signed pack must carry. Default: {PINNED_OIDC_ISSUER}, or '
            f'{GOOGLE_OIDC_ISSUER} when --certificate-identity is an email address.'
        ),
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
        '--tsa-root',
        action='append',
        default=[],
        metavar='ID=FILE',
        help=(
            'PEM root certificate(s) to trust for chain-head anchor tokens from witness ID '
            '(a customer timestamp authority). Each certificate is trusted only within its own '
            'validity period. Repeatable. The public witnesses (sigstore, globalsign-r45) have '
            'pinned roots and need no flag.'
        ),
    )
    parser.add_argument(
        '--ocsf-export',
        metavar='PATH',
        help=(
            'Also check an OCSF evidence export against this pack: a .manifest.json, '
            'a day\'s index.json, or a directory of manifests, with objects and .manifest.sig files '
            'beside them. Object digests, manifest signatures (with --ocsf-public-key), and every '
            'exported event\'s chain coordinates and digests against the pack record.'
        ),
    )
    parser.add_argument(
        '--ocsf-public-key',
        metavar='JWK',
        help='The proxy\'s export signing public key as a P-256 EC JWK file, for --ocsf-export.',
    )
    parser.add_argument(
        '--conditions-sha256',
        metavar='HEX',
        help=(
            'Also give the customer-conditions verdict for the condition set whose SHA-256 you '
            'hold: its acceptance on the holder\'s control-plane chain, the records after it sealed under a '
            'governance version carrying it, and the exceptions its instances recorded.'
        ),
    )
    parser.add_argument(
        '--conditions-acceptance',
        metavar='FILE',
        help=(
            'The exchange.conditions_accepted control-plane record (control-plane/<seq:020d>.json, as stored), '
            'for a pack that does not carry the control-plane chain. Its hash is recomputed; its link into '
            'the chain is not in the pack, and the verdict says so.'
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
        ok = segment_self_test() and ok
        ok = attribution_self_test() and ok
        ok = content_self_test() and ok
        ok = receipt_self_test() and ok
        ok = control_plane_self_test() and ok
        ok = tool_calls_self_test() and ok
        ok = content_carry_forward_self_test() and ok
        ok = exchange_self_test() and ok
        ok = conditions_self_test() and ok
        ok = signature_self_test() and ok
        ok = anchor_self_test() and ok
        ok = ocsf_export_self_test() and ok
        sys.exit(0 if ok else 1)

    if not (args.bucket or args.records) or not args.manifest:
        parser.error("--manifest plus one of --bucket / --records is required (or use --self-test)")
    if args.conditions_sha256 is not None and not _SHA256_HEX.fullmatch(args.conditions_sha256):
        parser.error("--conditions-sha256 must be 64 lowercase hex characters")
    if args.conditions_acceptance and args.conditions_sha256 is None:
        parser.error("--conditions-acceptance needs --conditions-sha256")
    supplied_acceptance = None
    if args.conditions_acceptance:
        try:
            supplied_acceptance = (load_control_plane_record(Path(args.conditions_acceptance).read_bytes()),
                                   args.conditions_acceptance)
        except (OSError, ValueError) as exc:
            parser.error(f"--conditions-acceptance: cannot read a control-plane record ({exc})")
    if args.export_records and args.records:
        if not Path(args.records).is_dir():
            parser.error("--export-records with --records needs a records directory")
        if Path(args.export_records).resolve() == Path(args.records).resolve():
            parser.error("--export-records needs a directory other than --records")

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

    version_error = (manifest_schema_version_error(manifest) or manifest_storage_layout_error(manifest)
                     or manifest_evidence_class_error(manifest) or manifest_content_error(manifest))
    if version_error:
        print(f"ERROR: {version_error}", file=sys.stderr)
        sys.exit(EXIT_CANNOT_EVALUATE)
    if evidence_class_suffix(manifest):
        print(f"EVIDENCE CLASS: {manifest['evidence_class']} ({EVIDENCE_CLASSES[manifest['evidence_class']]}).")
    # A stripped Exchange pack says so before the records and on
    # every verdict line, and is verified from its own records only.
    label = evidence_class_suffix(manifest) + content_suffix(manifest)
    for line in content_lines(manifest):
        print(line)
    stripped = frozenset(STRIPPED_FIELDS) if pack_is_stripped(manifest) else frozenset()
    if stripped and args.bucket:
        print("ERROR: this pack's records are content-stripped (manifest 1.5); --bucket would read the holder's "
              "full records, which are not what the manifest describes. Verify the pack's own records with "
              "--records.", file=sys.stderr)
        sys.exit(EXIT_CANNOT_EVALUATE)
    try:
        tsa_roots = load_tsa_roots(args.tsa_root)
    except (OSError, ValueError, DerError) as exc:
        print(f"ERROR: unusable --tsa-root ({exc})", file=sys.stderr)
        sys.exit(EXIT_CANNOT_EVALUATE)

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
        anchors_dir = Path(args.records) / 'anchors'
        anchor_source = DirectoryAnchorSource(anchors_dir) if Path(args.records).is_dir() else None
        holders = None
        control_plane_fetch = control_plane_local_fetcher(args.records)
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

        client = gcs.Client()
        fetch = gcs_fetcher(args.bucket, manifest.get('prefix', 'audit/'), client)
        fetch.expect(*manifest_sequence_window(manifest))
        holders = fetch.holders
        anchor_chain = chain_for_prefix(manifest.get('prefix', 'audit/'))
        anchor_source = BucketAnchorSource(args.bucket, anchor_chain, client) if anchor_chain else None
        control_plane_fetch = control_plane_gcs_fetcher(args.bucket, client)
    if args.export_records:
        fetch = exporting_fetcher(fetch, args.export_records)
        if anchor_source is not None:
            anchor_source = ExportingAnchorSource(anchor_source, args.export_records)
        control_plane_fetch = control_plane_exporting_fetcher(control_plane_fetch, args.export_records)

    record_times = {}
    fetch = timestamp_recording_fetcher(fetch, record_times)

    hash_version = manifest.get('hash_version', '')
    pack_full_records = {}
    control_plane_records = {}
    if hash_version not in SUPPORTED_HASH_VERSIONS:
        print(
            f"ERROR: This reproducer supports hash_version {SUPPORTED_HASH_VERSIONS}. "
            f"The manifest specifies '{hash_version}'. Re-run with the updated reproducer.",
            file=sys.stderr,
        )
        chain_status = CANNOT_EVALUATE
        anchor_status = CANNOT_EVALUATE
    else:
        receipts = {}
        stripped_problems = []
        passed = verify_manifest_with(fetch, manifest, require_manifest_hash=signed, holders=holders,
                                      receipts_out=receipts, records_out=pack_full_records,
                                      stripped=stripped, cannot_evaluate_out=stripped_problems,
                                      stubs=manifest_stubs(manifest))
        # The control-plane chain a 1.3 pack carries, then each
        # decision receipt's anchor against it.
        if 'control_plane' in manifest or manifest.get('schema_version') == '1.3':
            print()
            passed = verify_control_plane_section(manifest, receipts, control_plane_fetch,
                                                  records_out=control_plane_records) and passed
        chain_status = PASSED if passed else FAILED
        # A record that contradicts the signed content claim makes
        # the pack one this verifier cannot evaluate as what it says it is.
        if stripped_problems and chain_status == PASSED:
            chain_status = CANNOT_EVALUATE
        print()
        anchor_status = verify_anchors(manifest, fetch, anchor_source, tsa_roots.get, record_times)
    count = len(manifest.get('events', []))
    # The verdict counts the hash-only stubs it linked through.
    stub_count = len(manifest_stubs(manifest))
    stubbed = (f", {stub_count} of them as hash-only stubs (linked, hash not recomputed)" if stub_count else "")
    code = final_exit_code(combine_with_anchor_status(chain_status, anchor_status), signature_status,
                           bool(args.allow_unsigned))
    # The OCSF export beside the pack. Its verdict
    # combines with the pack's by the same precedence (1 > 2 > 3 > 0).
    if args.ocsf_export:
        print()
        export_code = EXIT_CANNOT_EVALUATE
        if chain_status == CANNOT_EVALUATE:
            print("CANNOT EVALUATE: the OCSF export cannot be checked against a pack this verifier cannot evaluate.")
        else:
            try:
                public_point = None
                if args.ocsf_public_key:
                    public_point = _jwk_to_point(json.loads(Path(args.ocsf_public_key).read_text(encoding='utf-8')))
                entries = load_ocsf_export(args.ocsf_export)
            except (OSError, ValueError, KeyError) as exc:
                print(f"ERROR: unusable --ocsf-export / --ocsf-public-key ({exc})", file=sys.stderr)
                entries = None
            if entries is not None:
                export_content, export_signature = verify_ocsf_export(
                    entries, chain_for_prefix(manifest.get('prefix', 'audit/')), pack_full_records,
                    public_point=public_point)
                export_code = final_exit_code(export_content, export_signature, bool(args.allow_unsigned))
                if export_content == FAILED:
                    print("\nFAIL: the OCSF export does not match the pack (see above).", file=sys.stderr)
                elif export_signature == FAILED:
                    print("\nFAIL: an OCSF export manifest signature did not verify (see above).", file=sys.stderr)
                elif export_code == EXIT_UNSIGNED:
                    print("\nOCSF EXPORT OK, AUTHENTICITY NOT ESTABLISHED: the export matches the pack, but a manifest "
                          "is unsigned or its key was not given.", file=sys.stderr)
                elif export_code == EXIT_OK:
                    print("\nOK: the OCSF export matches the pack" + (" and its manifests are signed." if export_signature == PASSED else "."))
        if _exit_code_rank(export_code) > _exit_code_rank(code):
            code = export_code

    # The customer-conditions verdict, when asked
    # for. Its code combines with the pack's by the same precedence.
    conditions_status = None
    if args.conditions_sha256 is not None:
        print()
        if chain_status == CANNOT_EVALUATE and not pack_full_records:
            print("CANNOT EVALUATE conditions: the records of a pack this verifier cannot evaluate were not read.")
            conditions_status = CANNOT_EVALUATE
        else:
            conditions_status = conditions_verdict(args.conditions_sha256, manifest, pack_full_records,
                                                   control_plane_records, supplied_acceptance, label=label)
        conditions_code = final_exit_code(conditions_status, PASSED, True)
        if _exit_code_rank(conditions_code) > _exit_code_rank(code):
            code = conditions_code

    if code == EXIT_FAIL:
        if conditions_status == FAILED:
            print(f"\nFAIL: the customer-conditions verdict failed (see above).{label}", file=sys.stderr)
        if chain_status == FAILED:
            print(f"\nFAIL: one or more events failed verification.{label}", file=sys.stderr)
        if anchor_status == FAILED:
            print(f"\nFAIL: chain-head anchor verification failed (see above).{label}", file=sys.stderr)
        if signature_status == FAILED:
            print(f"\nFAIL: the manifest signature did not verify (see above).{label}", file=sys.stderr)
    elif code == EXIT_CANNOT_EVALUATE and conditions_status == CANNOT_EVALUATE and chain_status != CANNOT_EVALUATE:
        print(f"\nCANNOT EVALUATE: the customer-conditions verdict cannot be evaluated from this pack "
              f"(see above).{label}", file=sys.stderr)
    elif code == EXIT_CANNOT_EVALUATE:
        print(f"\nCANNOT EVALUATE: this verifier does not support part of this pack (see above).{label}",
              file=sys.stderr)
    elif signature_status == PASSED:
        print(f"\nOK: all {count} events verified{stubbed}, and the manifest signature verified.{label}")
    else:
        print(f"\n{UNSIGNED_NOTICE}")
        if code == EXIT_OK:
            print(f"OK: all {count} events verified{stubbed}. Authenticity not established (unsigned pack, "
                  f"accepted with --allow-unsigned).{label}")
        else:
            print(
                f"CHAIN OK, AUTHENTICITY NOT ESTABLISHED: all {count} events verified{stubbed}, but the pack "
                f"is unsigned. Pass --allow-unsigned to accept an unsigned pack.{label}",
                file=sys.stderr,
            )
    sys.exit(code)


if __name__ == '__main__':
    main()
