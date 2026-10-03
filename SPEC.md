# Meilynx audit chain format

This document describes the audit chain a Meilynx proxy writes, precisely
enough that a verifier can be written from it without reading Meilynx code.
`verify-pack.py` in this repository is one such verifier; its `--self-test`
pins the values below against fixture hashes.

Status: describes chain records with `schema_version` v1 through v1.13 and
pack manifest `schema_version` 1.0, as produced by meilynx-proxy at commit
`c1581f0` (2026-10-03).

## 1. Records

A chain is an ordered sequence of records. Each record is one JSON document
(UTF-8), stored as its own object in a write-once bucket under a chain
prefix, named by its sequence number zero-padded to 20 digits:

```
<prefix>/00000000000000000000.bin
<prefix>/00000000000000000001.bin
…
```

A chain begins at sequence `0` on every proxy instance start and runs until
that instance stops. Different instances write different chains (distinct
prefixes); a chain never spans instances. Model-call and MCP records share
the request chain; coverage records (`coverage_computed`,
`coverage_key_inventory`) are written to a separate per-tenant coverage chain
with the same format and genesis.

Every record carries at least these fields:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Which preimage layout below applies (`"v1"`, `"v1.1"`, `"v1.2"`, … `"v1.13"`). Absent means `"v1"`. |
| `event_kind` | string | Record kind in serde form (`llm_request`, `admin_action`, `auth_session_started`, `mcp_tool_call`, `mcp_policy_decision`, `mcp_tool_result`, `mcp_tools_list_served`, `mcp_error`, `mcp_catalog_drift`, `coverage_computed`, `coverage_key_inventory`). Absent means `llm_request`. |
| `sequence_number` | integer | Position in the chain, starting at 0. |
| `timestamp_utc` | string | RFC 3339 UTC timestamp, nanosecond precision, `Z` suffix. |
| `event_id` | string | Unique id of this record. |
| `request_id` | string | Id of the request that produced it. |
| `model_requested` | string | Model the caller asked for (empty for non-LLM kinds). |
| `action` | string | Governance decision: `allow`, `warn`, `redact`, `mask_output`, `block` (older records may carry `Allow`, `Warn`, `Redact`, `MaskOutput`, `Block`). |
| `input_tokens`, `output_tokens` | integer | Token counts, 0 when not applicable. |
| `total_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`, `cached_input_tokens`, `reasoning_tokens` | integer or absent | Optional token buckets. Absent and `0` hash differently (see §3). |
| `estimated_cost_usd` | number or null | Estimated cost. |
| `previous_hash` | string | Hex SHA-256 of the previous record, or the genesis hash for sequence 0. |
| `event_hash` | string | Hex SHA-256 of this record's preimage (§3). |

Kind-specific payloads live under `admin_action`, `auth_session`,
`mcp_event`, `coverage`, `coverage_key_inventory`, `join_context`, `content`
and `identity`. LLM records also carry
`messages`, `response_text`, `findings`, `policy_version`,
`raw_request`/`raw_response` and routing metadata; **only the fields listed
in the preimage tables (§4) are covered by `event_hash`**. From v1.10 the
content of an LLM record is bound through digests (§4.4).

## 2. Chain linkage and genesis

```
genesis_hash = SHA-256("meilynx-genesis-v1")            # hex
record[0].previous_hash  == genesis_hash
record[n].previous_hash  == record[n-1].event_hash       for n ≥ 1
record[n].event_hash     == SHA-256(preimage(record[n])) for all n
```

A verifier walks the records in sequence order, recomputes each
`event_hash`, checks it against the stored value, and checks the stored
`previous_hash` against the hash it recomputed for the preceding record
(genesis for the first). Any mismatch is a failure at that sequence number.
A missing sequence number is a failure, never a skip. A record whose
`schema_version` or `event_kind` the verifier does not know is a failure.

## 3. Byte encoding of preimage fields

The preimage is the concatenation, in the order given by the field table for
the record's version and kind, of each field encoded as follows. There are
no separators and no length prefixes.

| Kind of field | Encoding |
|---|---|
| string | UTF-8 bytes of the string. |
| optional string | one byte `0x00` if absent/null; otherwise `0x01` followed by the UTF-8 bytes. |
| u64 | 8 bytes little-endian. |
| u32 | 4 bytes little-endian. |
| i64 | 8 bytes little-endian, two's complement. |
| optional u64 | one byte `0x00` if absent/null; otherwise `0x01` followed by 8 bytes little-endian. |
| optional i64 | one byte `0x00` if absent/null; otherwise `0x01` followed by 8 bytes little-endian. |
| f64 | 8 bytes little-endian IEEE 754; `null` is fed as `0.0` with **no** presence byte. |
| principal | a tag byte then the principal's fields: `0x01` + `subject` (string) + `issuer` (optional string) for `{"kind":"human_user"}`; `0x02` + `agent_ref` (string) for `{"kind":"agent"}`. |
| principal chain | `authenticated` (principal) then `0x00` if `on_behalf_of` is absent, else `0x01` + `on_behalf_of` (principal). |
| sealed identity | `agent_id` (optional string), `tier` (string), `credential_kind` (string), `credential_kid` (optional string), then `0x00` if `delegated_human` is absent, else `0x01` + `subject` (string) + `issuer` (string), then `asserted_digest` (string). See §4.5. |

Two normalizations apply before hashing:

- **Timestamp.** The stored `timestamp_utc` ends in `Z`; the preimage uses the
  `+00:00` form. Replace a trailing `Z` with `+00:00`, leave everything else
  (including the nanosecond fraction) untouched.
- **Action.** Fed exactly as stored (`allow`, `block`, … or the older
  capitalized forms). No case folding.

## 4. Preimage field order per version

### 4.1 The 15-field base (v1, v1.1)

Every version starts with these fifteen fields in this order:

| # | Field | Encoding |
|---|---|---|
| 1 | `sequence_number` | u64 |
| 2 | `timestamp_utc` (normalized) | string |
| 3 | `event_id` | string |
| 4 | `request_id` | string |
| 5 | `model_requested` | string |
| 6 | `action` | string |
| 7 | `input_tokens` | u32 |
| 8 | `output_tokens` | u32 |
| 9 | `total_tokens` | optional u64 |
| 10 | `cache_creation_input_tokens` | optional u64 |
| 11 | `cache_read_input_tokens` | optional u64 |
| 12 | `cached_input_tokens` | optional u64 |
| 13 | `reasoning_tokens` | optional u64 |
| 14 | `estimated_cost_usd` | f64 (null → 0.0) |
| 15 | `previous_hash` | string |

`v1` and `v1.1` records hash exactly these fifteen fields.

### 4.2 Kind attestation (v1.2 and later)

From v1.2 on, field 16 is the record's **wire kind name** as a string. The
wire names differ from the serde `event_kind` values stored in the JSON:

| stored `event_kind` | wire name fed to the hash |
|---|---|
| absent or `llm_request` | `llm_request` |
| `auth_session_started` | `auth.session_started` |
| `admin_action` | `admin.action` |
| `mcp_tool_call` | `mcp.tool_call` |
| `mcp_policy_decision` | `mcp.policy_decision` |
| `mcp_tool_result` | `mcp.tool_result` |
| `mcp_tools_list_served` | `mcp.tools_list.served` |
| `mcp_error` | `mcp.error` |
| `mcp_catalog_drift` | `mcp.catalog_drift` |
| `coverage_computed` | `coverage.computed` |
| `coverage_key_inventory` | `coverage.key_inventory` |

### 4.3 Per-version suffixes

After field 16, each version and kind appends the fields below, in order.

**v1.2 `llm_request`** — nothing further (16 fields).

**v1.2 `auth.session_started`** — from `auth_session`:
`user_email` (optional string), `user_id` (string), `project_id` (string),
`proxy_id` (string), `session_expires_at` (i64, Unix seconds),
`identity_provenance` (string), `jti` (string), `signing_key_fingerprint`
(string). 24 fields.

**v1.3 `admin.action`** — from `admin_action`:
`action_type`, `actor`, `description`, `metadata_json` (all strings). 20 fields.

**v1.4 MCP kinds** — from `mcp_event`:
`virtual_server` (string), `upstream_slug` (string), `method` (string),
`tool_name` (optional string), `jsonrpc_id` (optional string),
`protocol_version` (string), `decision` (optional string), `reason`
(optional string), `payload_sha256_jcs` (optional string),
`mcp_bundle_sha256` (optional string), `correlated_event_id` (optional
string), `error_code` (optional i64), `traceparent` (string). 29 fields.

**v1.5 MCP kinds** — v1.4 fields, then `principal_chain` (principal chain). 31 fields.

**v1.6 MCP kinds** — v1.5 fields, then `redacted_payload_sha256_jcs`
(optional string). 32 fields.

**v1.7 MCP kinds** — v1.6 fields, then `redaction_pre_sha256_jcs`,
`redaction_post_sha256_jcs`, `hold_id` (all optional strings). 35 fields.

**v1.8 `coverage.computed`** — from `coverage`: `provider`, `day`, `tier`,
`reconciliation_unit` (strings), `proxy_attributed` (i64),
`provider_reported` (i64), `delta_classification` (string),
`bypass_rate_ppm` (i64), `tolerance_band_json`, `claim_language_key`,
`registry_version`, `numerator_source`, `denominator_fetched_at` (strings).
29 fields.

**v1.9 `llm_request`** — from `join_context`: `correlation_id`,
`session_id`, `agent_name` (all optional strings). 19 fields. A record
carries `join_context` only when the caller asserted at least one of these
keys; a `join_context` on any other version is invalid and fails
verification.

**v1.9 MCP kinds** — v1.7 fields, then the three `join_context` fields as
above. 38 fields.

**v1.10 `llm_request`** — the three `join_context` fields as in v1.9 (each
presence-tagged; a v1.10 record need not carry `join_context`, in which case
all three are fed as absent), then from `content`: `capture_policy`
(string), `prompt_sha256_jcs`, `response_sha256`,
`stored_prompt_sha256_jcs`, `stored_response_sha256`,
`findings_sha256_jcs` (all optional strings). 25 fields. A record carries
`content` only when the proxy's policy declared a capture policy; a
`content` payload on any other version, or a v1.10 record without one, is
invalid and fails verification.

**v1.11 `llm_request`**: the v1.10 fields, then from `content`:
`tool_calls_sha256_jcs` and `stored_tool_calls_sha256_jcs` (both optional
strings). 27 fields. A record is v1.11 exactly when the model's response made
at least one tool call; a record without tool calls stays v1.10. Tool-call
digests on any other version, or a v1.11 record without
`tool_calls_sha256_jcs`, are invalid and fail verification.

**v1.12 `llm_request`**: the three `join_context` fields as in v1.10, then
one presence byte for the `content` block: `0x00` if the record carries none,
else `0x01` followed by the eight v1.11 `content` fields in their v1.11
order. Then the sealed identity (§3, §4.5). A record carrying an `identity`
block is v1.12, whatever its join or content state; the proxy stamps it
whenever it resolved the caller's identity. 34 entries counting the presence
byte, when `content` is present.

**v1.12 MCP kinds**: the v1.9 MCP fields (with the three `join_context`
fields fed presence-tagged whether or not the caller asserted any), then the
sealed identity. 44 entries. One number covers both lanes: v1.10 and v1.11
are LLM content buckets, so the MCP lane goes from v1.9 to v1.12.

An `identity` block on any version other than v1.12, or a v1.12 record
without one, is invalid and fails verification, as is v1.12 on any kind
other than `llm_request` and the MCP kinds. On an MCP record, a
`delegated_human` must be present exactly when the principal chain's
stored `on_behalf_of_attestation` marker is `verified`; a record where the
two disagree fails verification.

**v1.13 `coverage.key_inventory`**: from `coverage_key_inventory`:
`provider`, `day`, `attribution_unit`, `claim_language_key`,
`registry_version` (strings), `proxy_key_count`,
`unresolved_proxy_key_count`, `governed_key_count`, `ungoverned_key_count`
(i64, no presence byte), `listing_fetched_at` (string), `keys_json`
(string, fed verbatim as stored, never re-serialized). 27 fields. One record
per provider and UTC day whose inventory changed: which provider API keys
reported usage, and whether each resolved to a key the proxy itself routes
with. `keys_json` holds key ids, the last four characters of each key, names
and usage counts, never key material. The payload on any other version or
kind, or v1.13 on any other kind, is invalid and fails verification.

MCP kinds are: `mcp.tool_call`, `mcp.policy_decision`, `mcp.tool_result`,
`mcp.tools_list.served`, `mcp.error`, `mcp.catalog_drift`. Any MCP hasher
called with a non-MCP kind is an error.

`*_sha256_jcs` values are hex SHA-256 digests over the JSON Canonicalization
Scheme (RFC 8785) serialization of the payload in question. For MCP records
the verifier checks that the digest string is what the record hashed; it does
not recompute the digest from a payload, because the payload is not part of
the record. For LLM records with a `content` block (v1.10, v1.11, v1.12) it
also recomputes the stored-content digests (§4.4), and for v1.12 records the
asserted-claims digest (§4.5).

### 4.4 LLM content attestation (v1.10, v1.11, v1.12)

`capture_policy` names what the record retains:

- `full`: the prompt and response as captured.
- `redacted`: the prompt and response with every span a detector located
  replaced by its placeholder; raw request/response copies are dropped, and
  tool-call inputs in the response are set to `null`. If the masking cannot
  be applied, that side is not retained at all.
- `hash_only`: no prompt, response or tool-call content; digests only.

The six `content` fields:

| Field | Digest of |
|---|---|
| `prompt_sha256_jcs` | JCS of the message list as captured, before the policy |
| `response_sha256` | UTF-8 bytes of the response text as captured; absent when there was no response (a block, a provider error) |
| `stored_prompt_sha256_jcs` | JCS of the record's own `messages`; absent when no prompt was retained |
| `stored_response_sha256` | UTF-8 bytes of the record's own `response_text`; absent when no response was retained |
| `findings_sha256_jcs` | JCS of the record's own `findings` |
| `tool_calls_sha256_jcs` (v1.11) | JCS of the response's tool calls as captured |
| `stored_tool_calls_sha256_jcs` (v1.11) | JCS of the record's own `tool_calls`; absent when none were retained |

Because the digests are in the preimage and the content they describe is in
the record, a verifier checks, for every v1.10 and v1.11 record and every
v1.12 record that carries a `content` block:

1. `stored_prompt_sha256_jcs`, when present, equals SHA-256(JCS(`messages`));
   when absent, `messages` is empty.
2. `stored_response_sha256`, when present, equals SHA-256(`response_text`);
   when absent, `response_text` is absent.
3. `findings_sha256_jcs`, when present, equals SHA-256(JCS(`findings`)).
4. `stored_tool_calls_sha256_jcs`, when present, equals
   SHA-256(JCS(`tool_calls`)); when absent, `tool_calls` is absent. On a
   v1.10 record, tool calls are not attested.

A record whose content was edited after sealing still hash-verifies (the
content is outside the preimage) and fails these checks. `prompt_sha256_jcs`
and `response_sha256` cover content the record may no longer hold: whoever
holds the original can show it is what the record was sealed over.

A v1.12 record with no `content` block was sealed with no capture policy.
Its prompt and response are stored but not bound, as before v1.10, and are
not checked.

JCS follows RFC 8785: object keys sorted by UTF-16 code units, no
whitespace, strings escaped as in RFC 8785 §3.2.2.2, numbers in ECMAScript
form (`1.0` → `1`, `1e-7` → `1e-7`, `1e21` → `1e+21`). A plain sorted-keys
JSON dump differs on numbers and must not be used.

### 4.5 Sealed identity (v1.12)

A v1.12 record carries an `identity` block naming who called the proxy:

| Field | Hashed | Meaning |
|---|---|---|
| `agent_id` | yes (optional string) | The registered agent the credential belongs to; absent for project-key traffic |
| `tier` | yes | How the caller was identified: `t1`, the agent's own credential (an agent key or a trusted workload token); `t2`, that credential plus a verified user token; `t3`, no agent credential, only labels the caller asserted (project-key traffic); `t4`, only signals the proxy inferred |
| `credential_kind` | yes | `agent_key`, `workload`, `project_key` or `none` |
| `credential_kid` | yes (optional string) | The credential's key id, or `pk:` and a fingerprint for the project key |
| `delegated_human` | yes (presence byte, then `subject` and `issuer`) | The user the agent acted for, present only when the proxy verified that user's token |
| `asserted_digest` | yes | Hex SHA-256 over the JCS form of `asserted` |
| `asserted` | no, bound through `asserted_digest` | What the caller claimed about itself, unverified: `agent_name`, `client_info`, `user_agent_family`, `on_behalf_of` (each omitted when absent) |

The asserted labels are stored beside their digest rather than hashed, so a
reader sees the values and the digest proves they are the ones the proxy
saw. A verifier therefore checks, for every v1.12 record, that
`asserted_digest` equals SHA-256(JCS(`asserted`)). A label rewritten after
sealing leaves the chain hash intact and fails this check. The labels are
claims a caller made, never evidence of who it was; only the hashed fields
record what the proxy verified.

## 5. Reference values

The verifier's self-test pins one fixture hash per version. Two of them,
useful for a from-scratch implementation:

- The v1 fixture (`--self-test` assertion 1) hashes to
  `ba7a7f3d…e031` (full value in `verify-pack.py`, `FIXTURE_HASH`).
- A `Z`-suffixed timestamp and its `+00:00` form produce the same hash
  (assertion 2); feeding the `Z` form unnormalized does not.

## 6. Pack manifest

`manifest.json` (schema_version `"1.0"`) describes one verification window
of one chain:

```json
{
  "schema_version": "1.0",
  "pack_id": "<uuid>",
  "window": "A" | "B",
  "signing_deferred": true | false,
  "generated_at": "<RFC 3339>",
  "generator_version": "<string>",
  "substrate_name": "<string or null>",
  "bucket": "<bucket name>",
  "prefix": "<chain prefix, ends with />",
  "from_sequence": 0,
  "to_sequence": 27,
  "hash_algorithm": "sha256",
  "hash_version": "v1",
  "genesis_hash": "<hex>",
  "verified": true,
  "records_checked": 28,
  "first_sequence": 0,
  "last_sequence": 27,
  "break_at_sequence": null,
  "violation_kind": null,
  "error": null,
  "signature": { … present on window B only … },
  "events": [
    {
      "sequence": 0,
      "timestamp_utc": "…",
      "action": "allow",
      "model_requested": "",
      "project_id": "<uuid or null>",
      "request_id": "…",
      "event_id": "…",
      "stored_event_hash": "<hex>",
      "recomputed_event_hash": "<hex>",
      "hash_match": true,
      "previous_hash_match": true
    }
  ]
}
```

`hash_version` names the version of the 15-field base layout (`"v1"`); the
per-record `schema_version` selects the suffix. `events[]` carries
identification and hash fields only: no prompt, response or payload content
ever appears in a manifest.

A verifier treats the manifest's `recomputed_event_hash` as a claim to check,
not as truth: it recomputes from the record bytes and reports disagreement
with the manifest as a failure.

## 7. Signed packs (window B)

### 7.1 Descriptor and bundle

A window B pack adds a signature over the exact bytes of `manifest.json`,
described inside the manifest itself:

```json
"signature": {
  "method": "cosign-sigstore-keyless",
  "signed_artifact": "manifest.json",
  "signature_file": "manifest.json.sigstore.json",
  "bundle_file": null,
  "transparency_log": "rekor"
}
```

`signature_file` names a file next to `manifest.json`: a Sigstore bundle
(media type `application/vnd.dev.sigstore.bundle.v0.3+json`) as written by
`cosign sign-blob --bundle`. It holds:

- a message signature over SHA-256 of `manifest.json`;
- the signing certificate (a short-lived Fulcio certificate, ECDSA P-256 key);
- exactly one Rekor v1 `hashedrekord` 0.0.1 entry, with its signed entry
  timestamp, inclusion proof and signed checkpoint.

`bundle_file` is `null`: the transparency-log proof travels inside the bundle.

A manifest is **signed-mode** when any of these holds:
- `window` is `"B"`;
- `signing_deferred` is not `true` (a missing field counts);
- it carries a `signature` descriptor.

A signed-mode manifest without a valid bundle fails. Every entry of a signed
manifest must carry `recomputed_event_hash`, because that field is what
extends the signature from the manifest to the records.

### 7.2 Verification

A verifier accepts the bundle only if every check below holds:

1. `messageSignature.messageDigest` is SHA-256 of the manifest bytes, and the
   ECDSA signature verifies over it under the certificate's key.
2. The log key is identified by `logId.keyId` (the SHA-256 of its DER public
   key) and is trusted and valid at `integratedTime`.
3. The signed entry timestamp verifies over the RFC 8785 JSON of `body`,
   `integratedTime`, `logID` (hex) and `logIndex`.
4. The inclusion proof, checked as in RFC 9162 §2.1.3.2 over
   `SHA-256(0x00 || body)`, reaches `rootHash`.
5. The checkpoint's tree size and root hash match the inclusion proof, and the
   checkpoint is signed by the log key.
6. The logged `hashedrekord` records this manifest's SHA-256, this signature,
   and this certificate.
7. The certificate chains to a trusted Fulcio CA that is valid at
   `integratedTime`, and every certificate in the chain is valid then. The
   signing certificate must carry the digitalSignature key usage and the
   codeSigning extended key usage, must not be a CA, and must have no unknown
   critical extensions.
8. `integratedTime` falls within the signing certificate's validity.
9. The certificate's subjectAltName equals the expected identity, and its
   Fulcio issuer extension (OID `1.3.6.1.4.1.57264.1.8`, falling back to
   `.1.1`) equals the expected issuer. For Meilynx packs these are:
   - identity `https://github.com/Meilynx/meilynx-proxy/.github/workflows/integrity-pack-signed.yml@refs/heads/main`
   - OIDC issuer `https://token.actions.githubusercontent.com`

Trust anchors (Fulcio CA chains and the Rekor log key, each with its
validity window) come from the Sigstore public-good `trusted_root.json`,
never from the bundle. `verify-pack.py` embeds a copy and accepts
`--trusted-root` to substitute another. Certificate Transparency timestamps
(SCTs) in the certificate are not checked. RFC 3161 timestamps, Rekor v2
entries and DSSE envelopes are outside this format: a verifier reports them
as unsupported, never as a pass.

### 7.3 Verdicts

| Exit | Meaning |
|---|---|
| 0 | Records verified, and for a signed pack the signature. An unsigned pack reaches 0 only when the reader passes `--allow-unsigned`. |
| 1 | A record or the signature failed. The reason is one of: signature required by manifest but missing; manifest bytes changed since signing; untrusted certificate chain; signer identity mismatch; OIDC issuer mismatch; invalid transparency-log proof; transparency-log entry does not match this signature; signed outside certificate validity; malformed signature material. |
| 2 | Cannot evaluate: unsupported hash version, signature method or bundle format, or unusable trust anchors. |
| 3 | Unsigned pack: records verified, authenticity not established. |

1 outranks 2, which outranks 3. The codes are the same whether the records
are read from the bucket or from an exported record set.

### 7.4 When this section changes

The following require a new verifier release:
- a Fulcio CA or Rekor key rotation;
- the end of Rekor v1 for new entries;
- any change to how packs are signed.

Packs signed under an anchor that a release carries keep verifying under
later releases.

Cross-check with cosign, which runs the same assertion (and also checks SCTs):

```
cosign verify-blob --bundle manifest.json.sigstore.json \
  --certificate-identity <identity above> \
  --certificate-oidc-issuer <issuer above> manifest.json
```

The signature attests who produced the manifest and that it has not changed
since; the chain hashes attest the records.

## 8. What the chain does not cover

- **Completeness.** The chain proves that the records it contains are intact
  and in order. It cannot show that an interaction which never reached the
  proxy was recorded.
- **Unhashed fields.** For LLM records before v1.10, `messages`,
  `response_text`, `findings`, `raw_request`, `raw_response` and routing
  metadata are stored in the record but not in the preimage. From v1.10 the
  prompt, response and findings are bound through their digests (§4.4), and
  from v1.11 the response's tool calls too, on records sealed under a
  capture policy; `raw_request`, `raw_response` and routing metadata remain
  unbound. For MCP records the payload is bound through its digest fields.
  On v1.12 records the caller's asserted labels are bound through
  `asserted_digest` (§4.5), and the principal chain's
  `on_behalf_of_attestation` marker is stored but not hashed; the hashed
  `delegated_human` must agree with it.
- **Whether a detector missed something.** Under `redacted`, only spans a
  detector located are masked. The stored copy can still contain sensitive
  text no detector recognized.
- **Authorship of the chain.** Only a signed pack (§7) binds an identity to
  a window.
