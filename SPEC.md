# Meilynx audit chain format

This document describes the audit chain a Meilynx proxy writes, precisely
enough that a verifier can be written from it without reading Meilynx code.
`verify-pack.py` in this repository is one such verifier; its `--self-test`
pins the values below against fixture hashes.

Status: describes chain records with `schema_version` v1 through v1.24, the
per-record and segment storage layouts, pack manifest `schema_version` 1.0
through 1.5, the control-plane chain a 1.3 manifest carries, the per-tenant
pack signature, the local-chain evidence class (§6.5), the manifest's
coverage claim (§6.7) and list of evidence modes (§6.8), the export copy a
pack can be checked against (§9), the customer-conditions verdict (§10),
record signatures (§11) and the gateway evidence key (§12), as read by
`verify-pack.py` from meilynx-proxy commit `f80356e` (2026-11-20). A chain written before the
segment rollout is per-record, and its packs carry manifest 1.0 or 1.1.

## 1. Records

A chain is an ordered sequence of records. Each record is one JSON document
(UTF-8), stored under a chain prefix: in a write-once bucket, or, for a
gateway with no write-once store, in the gateway's own audit database, from
which a local-chain pack (§6.5) copies it. The records are
held by objects of two kinds, each named by the sequence numbers it holds,
zero-padded to 20 digits:

- A **per-record object** `{seq:020}.bin` holds one record. Its bytes are the
  record's JSON document.
- A **segment object** `{first:020}-{last:020}.seg` holds the records `first`
  through `last`, inclusive, with `first ≤ last` and at most 1,024 records.
  Its body is each record's bytes, exactly as a per-record object would hold
  them, each followed by one line feed (`0x0A`), in sequence order. A
  one-record segment is `{n:020}-{n:020}.seg`.

A per-record chain:

```
<prefix>/00000000000000000000.bin
<prefix>/00000000000000000001.bin
…
```

The same chain in segments:

```
<prefix>/00000000000000000000-00000000000000001023.seg
<prefix>/00000000000000001024-00000000000000001530.seg
…
```

Records are written as compact JSON, which escapes a line feed inside a
string, so splitting a segment body on `0x0A` returns each record's bytes
unchanged. `event_hash` covers record fields (§3, §4), never object bytes:
a record hashes the same in either layout.

Writers close a segment at 1,024 records or 16 MiB of body, whichever comes
first; a verifier enforces the record cap only. A writer also sets object
metadata on each segment: `meilynx-segment-format` (`v1`),
`meilynx-first-sequence`, `meilynx-last-sequence`, `meilynx-record-count`,
`meilynx-first-previous-hash` (the first record's `previous_hash`),
`meilynx-last-event-hash` (the last record's `event_hash`) and
`meilynx-retention-horizon`. Metadata lets a reader with list access
cross-check a segment without opening it. A verifier does not rely on it:
the name and the body alone determine what a segment holds.

**Coverage.** Each object name under the chain prefix parses to an inclusive
range: `{n}.bin` is `[n, n]`, `{a}-{b}.seg` is `[a, b]`. Any other name is
not a record object; `verify-pack.py` prints a NOTICE for a `.seg` name whose
range is reversed or holds more than 1,024 records, and ignores it. The
records a chain holds are the union of its objects' ranges, so a verifier
reads both kinds under one prefix, in any mix. In a bucket, the objects that
can hold sequence `s` sort between `{max(0, s − 1023):020}` and
`{s + 1:020}` (exclusive), because zero padding keeps name order equal to
sequence order; one bounded listing finds them.

A verifier reads each sequence from every object whose range holds it, and
concludes:

| Finding | Verdict |
|---|---|
| The ranges cover every listed sequence, with no hole | Pass |
| Two objects hold the sequence with byte-identical records | Pass, with `WARN seq=<n>: segment_overlap` naming both objects. The record is verified once. |
| Two objects hold the sequence with different bytes | Fail (exit 1): `segment_fork`, naming both objects |
| A segment body that does not end in a line feed, or does not hold exactly the number of records its name says | Fail (exit 1) at every sequence the name covers: the segment is malformed |
| A sequence the manifest lists and no object holds | Fail (exit 1): missing record |
| **Gap:** no object holds a sequence, and later objects exist | Fail (exit 1) at the first record after the hole, which does not link to the last record before it (§2) |
| **Truncation:** the ranges cover a contiguous prefix and stop early | Pass on the records present, for a manifest that lists those records. The shortfall against the chain's final length is a completeness finding, not an integrity one (§8). |

A chain in a write-once bucket begins at sequence `0` on every proxy
instance start and runs until that instance stops. Different instances write
different chains (distinct prefixes); such a chain never spans instances. A
gateway's local chain (§6.5) is different: it lives in the gateway's audit
database and continues across restarts, so one local chain can hold the
startup records of several boots. Model-call and MCP records share
the request chain; coverage records (`coverage_computed`,
`coverage_key_inventory`) are written to a separate per-tenant coverage chain
with the same format and genesis.

Every record carries at least these fields:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Which preimage layout below applies (`"v1"`, `"v1.1"`, `"v1.2"`, … `"v1.24"`). Absent means `"v1"`. |
| `event_kind` | string | Record kind in serde form (`llm_request`, `admin_action`, `auth_session_started`, `mcp_tool_call`, `mcp_policy_decision`, `mcp_tool_result`, `mcp_tools_list_served`, `mcp_error`, `mcp_catalog_drift`, `coverage_computed`, `coverage_key_inventory`, `decision_receipt`, `compliance_record`, `judgment_verdict`). Absent means `llm_request`. |
| `sequence_number` | integer | Position in the chain, starting at 0. |
| `timestamp_utc` | string | RFC 3339 UTC timestamp, nanosecond precision, `Z` suffix. |
| `event_id` | string | Unique id of this record. |
| `request_id` | string | Id of the request that produced it. |
| `model_requested` | string | Model the caller asked for (empty for non-LLM kinds). |
| `action` | string | Governance decision: `allow`, `warn`, `redact`, `mask_output`, `hold`, `block` (older records may carry `Allow`, `Warn`, `Redact`, `MaskOutput`, `Block`). `hold` appears only on an MCP `mcp_policy_decision` for a tool call waiting on an approver; records sealed before it carry `block` for a held call, with `mcp_event.decision` `require_approval` and a reason starting `rbac_require_approval_hold`. |
| `input_tokens`, `output_tokens` | integer | Token counts, 0 when not applicable. |
| `total_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`, `cached_input_tokens`, `reasoning_tokens` | integer or absent | Optional token buckets. Absent and `0` hash differently (see §3). |
| `estimated_cost_usd` | number or null | Estimated cost. |
| `previous_hash` | string | Hex SHA-256 of the previous record, or the genesis hash for sequence 0. |
| `event_hash` | string | Hex SHA-256 of this record's preimage (§3). |
| `record_sig` | string or absent | Ed25519 signature over the record's chain coordinates, 128 lowercase hex characters (§11). Absent on a record sealed before the proxy had a chain signing key. Outside the preimage. |

Kind-specific payloads live under `admin_action`, `auth_session`,
`mcp_event`, `coverage`, `coverage_key_inventory`, `decision_receipt`,
`compliance_record`, `judgment_verdict`, `join_context`, `content`,
`identity`, `evaluation_trace` and `customer`.
LLM records also carry
`messages`, `response_text`, `findings`, `policy_version`,
`model_executed`, `raw_request`/`raw_response` and routing metadata; **only
the fields listed in the preimage tables (§4) are covered by `event_hash`**.
From v1.10 the content of an LLM record is bound through digests (§4.4).
From v1.19 `policy_version` and `model_executed` are in the preimage (§4.3).

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
no separators, and no length prefixes except where an encoding below gives
one.

| Kind of field | Encoding |
|---|---|
| string | UTF-8 bytes of the string. |
| optional string | one byte `0x00` if absent/null; otherwise `0x01` followed by the UTF-8 bytes. |
| u64 | 8 bytes little-endian. |
| u32 | 4 bytes little-endian. |
| length-prefixed string | the string's UTF-8 byte length as a u32, then the UTF-8 bytes. Used from v1.19 (§4.3). |
| i64 | 8 bytes little-endian, two's complement. |
| optional u64 | one byte `0x00` if absent/null; otherwise `0x01` followed by 8 bytes little-endian. |
| optional i64 | one byte `0x00` if absent/null; otherwise `0x01` followed by 8 bytes little-endian. |
| optional bool | one byte `0x00` if absent/null; otherwise `0x01` followed by one byte, `0x01` for true or `0x00` for false. |
| f64 | 8 bytes little-endian IEEE 754; `null` is fed as `0.0` with **no** presence byte. |
| principal | a tag byte then the principal's fields: `0x01` + `subject` (string) + `issuer` (optional string) for `{"kind":"human_user"}`; `0x02` + `agent_ref` (string) for `{"kind":"agent"}`. |
| principal chain | `authenticated` (principal) then `0x00` if `on_behalf_of` is absent, else `0x01` + `on_behalf_of` (principal). |
| sealed identity | `agent_id` (optional string), `tier` (string), `credential_kind` (string), `credential_kid` (optional string), then `0x00` if `delegated_human` is absent, else `0x01` + `subject` (string) + `issuer` (string), then `asserted_digest` (string). See §4.5. |
| sealed customer | one byte `0x01`, then `label_sha256` (optional string), `source` (string), `credential_kid` (optional string). See §4.6. |
| data reach | `binding_id` (string), `access` (optional string), `outcome` (string), `schema_known` (one byte, `0x01` for true or `0x00` for false), `arg_keys` (u32 count, then for each name a u32 byte length followed by its UTF-8 bytes), `arg_keys_omitted` (u32). See §4.7. |

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
| `decision_receipt` | `decision.receipt` |
| `compliance_record` | `compliance.record` |
| `judgment_verdict` | `judgment.verdict` |

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

**v1.14 MCP kinds**: the v1.12 MCP fields up to and including the three
`join_context` fields, then one presence byte for the `identity` block:
`0x00` if the record carries none, else `0x01` followed by the sealed
identity (§4.5). Then `mcp_event.stage` (optional string). 46 entries
counting the presence byte, when `identity` is present. A record is v1.14
exactly when it carries a stage, which only `mcp.policy_decision` records
do: the check the decision is, one of `access` (membership, session, the
approval matrix including holds and standing approvals), `limit` (rate limit
or quota), `tool_call` (content checks over the tool arguments),
`tool_result` (content checks over the tool result), `taint` (session taint)
and `adapter_fail_open` (not a proxy check: a coding-agent hook adapter's
replayed claim that it allowed the tool under fail-open). Every other MCP
record keeps its v1.12 (or earlier) bucket. A stage on any other version, or
a v1.14 record without one, is invalid and fails verification, as is v1.14
on any kind other than the MCP kinds. A v1.14 record's identity, when
present, is checked as in §4.5.

**v1.15 `decision.receipt`** — from `decision_receipt`, after the kind
attestation: `receipt_id`, `receipt_type`, `receipt_type_version`,
`registry_digest`, `source_kind`, `source_ref` (strings),
`subject_ref_sha256` (optional string), `evidence_set_sha256` (string),
`policy_version` (optional string), `outcome` (string),
`outcome_reason_code`, `outcome_reason_sha256`, `decider_user_id`,
`decider_role`, `decider_identity_provenance` (optional strings),
`credential_status` (string), `credential_class`, `credential_registry`
(optional strings), `credential_verified_at` (optional i64),
`procedure_status` (string), `procedure_id`, `procedure_version`,
`procedure_document_sha256` (optional strings), `procedure_effective_at`
(optional i64), `clock_rule`, `clock_start_basis` (strings),
`clock_started_at`, `clock_deadline_at` (i64, Unix seconds),
`clock_decided_at`, `clock_elapsed_seconds` (optional i64), `clock_status`
(string), `held_before_use` (optional bool), `supersedes_receipt_id`
(optional string), `cp_anchor_event_id`, `cp_anchor_event_hash` (strings),
`issued_at` (i64). 52 fields. A required string that is absent is fed as
the empty string. The stored `evidence` list is outside the preimage; the
verifier recomputes its RFC 8785 digest (an absent list is the empty list)
and requires it to equal `evidence_set_sha256`. It also requires:

- when `outcome` is `lapsed`: no `decider_user_id`, no `clock_decided_at`,
  no `clock_elapsed_seconds`, and `clock_status` `lapsed`;
- otherwise: a `decider_user_id`, all three of `clock_started_at`,
  `clock_deadline_at` and `clock_decided_at`, `clock_elapsed_seconds` equal
  to `clock_decided_at − clock_started_at`, and `clock_status` `within` when
  `clock_decided_at ≤ clock_deadline_at`, else `breached`;
- when `outcome` or `clock_status` is `lapsed`: `issued_at` and
  `clock_deadline_at` present, with `issued_at ≥ clock_deadline_at`;
- `credential_class`, `credential_registry` and `credential_verified_at`
  when `credential_status` is `verified`; `procedure_id` and
  `procedure_version` when `procedure_status` is `recorded`;
- `outcome` one of `approved`, `escalated`, `rejected`, `lapsed`, and the
  base `action` its projection (`approved` → `allow`, `escalated` → `hold`,
  `rejected` and `lapsed` → `block`).

Each `evidence` entry names a record by `chain_id`, `sequence_number`,
`event_id` and `event_hash`. An entry that names this pack's chain (the chain
the manifest `prefix` identifies; a chain under the flat `audit/` prefix is
named by a tenant-scoped id of the form `chain_tnt_<proxy>_proxy`) at a
sequence the pack holds must carry
that record's `event_hash` and, when it carries an `event_id`, that record's
`event_id`; a disagreement fails verification, naming the receipt and the
field. An entry with no `chain_id`, or an internal id (`proxy`, `shadow`),
names no chain; it is matched to the pack record at that sequence only when
its `event_hash` is that record's, and an `event_id` it carries must then
also be that record's. Any entry the pack cannot match prints `WARN
receipt_evidence_outside_pack` with its coordinates and verifies. An entry
that cites a hash-only stub (§6.6) is checked on its hash alone. The
receipt's `cp_anchor_event_id` and `cp_anchor_event_hash` are checked against
the control-plane chain when the pack carries one (§6.3), and the manifest's
`decision_receipts` index against the receipts in the pack (§6.4).
`decision.receipt` on any other version, v1.15 on any other kind, a v1.15
record without the payload, or a decider on a lapsed receipt (or none on a
decided one), is invalid and fails verification.

**v1.16 `llm_request`** — the v1.12 `llm_request` layout with the
`identity` block presence-tagged as in the v1.14 MCP kinds (`0x00` when the
record carries none, else `0x01` followed by the sealed identity, §4.5),
then `evaluation_trace.outcomes_sha256_jcs` (string). 36 entries counting
the two presence bytes, when `content` and `identity` are present. A record
is v1.16 when it carries an `evaluation_trace` and no `customer` block (a
record with both is v1.18): the per-rule
outcomes of the governance evaluation and the request's delivery outcome,
stored as an object under `evaluation_trace.outcomes` and bound by that
digest, which the verifier recomputes (RFC 8785). The trace's timing fields
are stored but not hashed. A trace on any version other than v1.16, v1.18 or v1.19,
a v1.16 record without one, a trace whose `outcomes_sha256_jcs` is not a
string, or v1.16 on any kind other than `llm_request`, is invalid and fails
verification. A v1.16 record's `content` block, when present, is checked as
in §4.4. Its identity, when present, is hashed as §4.5 gives; this release
does not re-derive a v1.16 identity's asserted-label digest (§4.5).

**v1.17 `mcp.policy_decision`** — the v1.14 MCP fields (identity
presence-tagged, then `stage`), then the data reach (§3, §4.7) from
`mcp_event.data_reach`: `binding_id` (string), `access` (optional string),
`outcome` (string), `schema_known` (one byte), `arg_keys` (u32 count, then
each name as a u32 byte length and its UTF-8 bytes), `arg_keys_omitted`
(u32). 52 entries counting the presence byte, when `identity` is present.
v1.17 is defined only for an `mcp.policy_decision` whose `stage` is
`tool_call` and which carries a `data_reach` block; a record sealed without
one stays in its earlier bucket. v1.17 on any other kind, a `data_reach`
block on any version other than v1.17 or v1.18, on any other kind or stage,
or one whose shape is not as §4.7 gives, is invalid and fails verification.
The identity, when present, is checked as in §4.5.

**v1.18 `llm_request`** — the v1.16 layout with the trace presence-tagged:
`0x00` when the record carries no `evaluation_trace` (a request refused
before evaluation), else `0x01` followed by `outcomes_sha256_jcs`. Then the
sealed customer (§3, §4.6). 41 entries counting the three presence bytes and
the customer block's leading tag byte, when `content`, `identity` and
`evaluation_trace` are all present. The trace,
when present, is checked as for v1.16; the content as in §4.4; the identity
as in §4.5.

**v1.18 MCP kinds** — the v1.14 MCP fields (identity presence-tagged, then
`stage`, an optional string that only `mcp.policy_decision` records carry),
then one presence byte for `mcp_event.data_reach`: `0x00` if the record
carries none, else `0x01` followed by the six v1.17 data-reach fields in
their v1.17 order. Then the sealed customer (§3, §4.6). 57 entries counting
the presence bytes and the customer block's leading tag byte, when
`identity` and `data_reach` are present. A
`data_reach` block is allowed only on a `tool_call`-stage
`mcp.policy_decision`, as in v1.17. A `content` block on a v1.18 MCP record
is invalid and fails verification: the MCP preimage never reads one.

An MCP record is v1.18 exactly when it carries a `customer` block, and so
is an `llm_request` sealed before v1.19. A `customer` block on any version
other than v1.18 or v1.19, a v1.18 record without one, a block whose shape
is not as §4.6 gives, or v1.18 on any kind other than `llm_request` and the
MCP kinds, is invalid and fails verification.

**v1.19 `llm_request`** — the v1.18 `llm_request` layout with the sealed
customer presence-tagged: `0x00` when the record carries no `customer`
block, else the sealed customer (§3, §4.6), whose leading `0x01` is its tag.
Then `policy_version` (length-prefixed string, §3), then `0x00` when the
record carries no `model_executed`, else `0x01` followed by
`model_executed` (length-prefixed string). 44 entries counting the four
presence bytes and the customer block's leading tag byte, when `content`,
`identity`, `evaluation_trace`, `customer` and `model_executed` are all
present. `policy_version` names the governance version in force when the
request was decided: a bundle's SHA-256, or `empty`,
`fail-closed-no-bundle` or `none-applied` when no bundle applied.
`model_executed` is the model the provider served; it is absent when none
was served (a block, a refusal). Both fields were stored but not hashed in
every earlier version. On a v1.19 record an edit to either, or adding or
removing `model_executed`, breaks the chain at that record. v1.19 is
defined only for `llm_request` and is stamped exactly when the record
carries a `policy_version`; a v1.19 record without one, or v1.19 on any
other kind, is invalid and fails verification. The trace, content,
identity and customer, when present, are checked as for v1.18.

**v1.20 `compliance.record`**: from `compliance_record`, after the kind
attestation: `vendor`, `api_surface`, `record_type`, `outcome` (strings),
`external_id`, `parent_id`, `external_type`, `external_created_at`,
`external_updated_at`, `organization_uuid`, `actor_type`, `actor_id`,
`error_class` (optional strings), `http_status` (optional i64),
`vendor_request_id`, `cursor_before`, `cursor_after` (optional strings),
`item_count`, `content_bytes` (i64), `content_sha256` (optional string),
`record_sha256`, `scan_status` (strings), `findings_count` (i64),
`findings_sha256` (string), `fetched_at` (i64, Unix seconds). 41 fields. A
required string that is absent is fed as the empty string.

A compliance record is one item a proxy retrieved from a vendor's compliance
API with the customer's own credential (an activity, a chat, a message, a
file and the like), or one polling run that failed, was partial or was
skipped. These records are sealed on their own chain, `compliance`, next to
the proxy's request chain. The item as received is stored in `raw_response`
and its findings in `findings`; both are outside the preimage and bound by
digests the verifier recomputes:

- `record_sha256` is the RFC 8785 digest of `raw_response` (of `null` when
  the record stores none);
- when `raw_response` carries `content_base64`, the decoded bytes must hash
  (SHA-256) to `content_sha256` and measure `content_bytes`;
- `findings_sha256` is the RFC 8785 digest of the findings projected to
  `code`, `validator`, `severity`, `category` and `message`, in order, and
  `findings_count` is their number.

A disagreement fails verification at that record, naming the digest. In a
content-stripped pack (§6.6) whose `removed_fields` include `raw_response`,
only the findings are checked. `compliance_record` on any other version or
kind, v1.20 on any other kind, a v1.20 record without the payload, or a
v1.20 record that also carries another kind's payload (`auth_session`,
`admin_action`, `mcp_event`, `coverage`), is invalid and fails verification.

**v1.21 `judgment.verdict`**: from `judgment_verdict`, after the kind
attestation: `verdict_id`, `judged_event_id`, `judged_upload_event_id`,
`judged_event_hash` (length-prefixed strings, §3), `judged_sequence_number`
(u64), `rule_id`, `judgment`, `pack_sha256`, `verdict`, `source`,
`reason_code` (length-prefixed strings), `enforceable` (one byte, `0x01` for
true or `0x00` for false), `uploaded_sha256`, `local_sha256`
(length-prefixed strings). 30 fields. Every field is required; a field that
is absent or of another type leaves the record with no defined preimage and
fails verification.

A verdict receipt records one judgment (`judgment`, `<id>@<version>`) of
one rule (`rule_id`) on one model request: its verdict (`PASS`, `FLAG` or
`INDETERMINATE`), what produced it (`source`), its reason code and whether
it may act (`enforceable`). It is sealed on the chain of the request it
judged, after it. It names that request three ways: `judged_event_id` (its
chain event id), `judged_event_hash` and `judged_sequence_number`.
`judged_upload_event_id` is the id under which the request's record is
uploaded to the control plane; it equals `judged_event_id` when nothing is
uploaded for the record.

Two parts of the receipt are stored beside the hash and bound by digests the
verifier recomputes:

- `judgment_verdict.uploaded_json`, the **uploaded form**: the receipt as the
  gateway uploads it (`judgment_verdict.v1`), stored as its RFC 8785 text.
  `uploaded_sha256` is the SHA-256 of those UTF-8 bytes as stored. It
  carries ids, digests, numbers and fixed vocabularies, and no text of the
  conversation. Its members `verdict_id`, `judged_event_id`, `rule_id`,
  `judgment`, `pack.sha256`, `verdict`, `source`, `reason_code` and
  `enforceable` must equal, in value and JSON type, the sealed
  `verdict_id`, `judged_upload_event_id`, `rule_id`, `judgment`,
  `pack_sha256`, `verdict`, `source`, `reason_code` and `enforceable`.
  `pack.version` is `null` exactly when `reason_code` is `pack_unavailable`
  (the rule's judgment pack was not loaded), and an unsigned integer on
  every other receipt.
- `raw_response`, the **local part**: an object with exactly the keys
  `schema` (`judgment_verdict_local.v1`), `reason_text`,
  `reason_text_withheld`, `spans` and `floor_unavailable`, or `null`.
  `local_sha256` is its RFC 8785 digest. It holds the judge's reason and the
  spans it quoted, and stays in the gateway's audit store. In a
  content-stripped pack (§6.6) whose `removed_fields` include
  `raw_response`, this check is left out.

The link: `judged_sequence_number` must be below the receipt's own
sequence. When the pack holds a record at that sequence, its `event_id`
must be `judged_event_id` (not compared for a hash-only stub) and its
`event_hash` must be `judged_event_hash`. A judged record outside the pack's
window is not a failure; the receipt's hash still binds the three values.

A disagreement fails verification at that receipt. `judgment_verdict` on any
other version or kind, v1.21 on any other kind, a v1.21 record without the
payload, or a v1.21 record that also carries another kind's payload
(`auth_session`, `admin_action`, `mcp_event`, `coverage`), is invalid and
fails verification. A receipt shows that a verdict was recorded and not
changed since. It does not show that the verdict was right.

**v1.22 `judgment.verdict`**: the v1.21 record and preimage, unchanged (the
same 30 fields; `schema_version` is not in the preimage). The stamp says the
receipt also records how the judge was given its input, and obliges the
checks below on top of every v1.21 check; the v1.21 refusals (another
kind, no payload, another kind's payload) apply to v1.22 alike. Because the stamp is outside the
hash, the uploaded form's own `schema` tells the two apart: a v1.21 record
whose uploaded form is `judgment_verdict.v2` fails verification.

The uploaded form is `judgment_verdict.v2`, a closed object. Any other key,
or a listed key missing, fails the receipt. Its keys (*code* is a string of
1 to 128 characters from `A-Za-z0-9_.:/@+-` starting with a letter or
digit; *hex* is 1 to 128 hex digits):

| Key | Value |
|---|---|
| `schema` | `"judgment_verdict.v2"` |
| `verdict_id`, `judged_event_id`, `rule_id` | code |
| `rule_sha256` | 64 lowercase hex: the SHA-256 of the rule as the gateway received it, in the canonical JSON of its governance bundle |
| `judgment` | `<id>@<version>`, a code; the version an unsigned 32-bit integer with no leading zero |
| `pack` | `{ "version": unsigned integer or null, "sha256": hex }`, closed |
| `verdict` | `PASS`, `FLAG` or `INDETERMINATE` |
| `source` | `judge`, `floor` or `none` |
| `reason_code` | one of `ok`, `clause_violated`, `floor_match`, `abstained`, `input_missing`, `budget_exceeded`, `backend_timeout`, `backend_unavailable`, `backend_error`, `malformed_answer`, `backlog_dropped`, `no_backend_configured`, `no_validated_backend`, `pack_unavailable`, `floor_unavailable`, `floor_triggered_unanswered`, `raw_input_not_permitted`; on v1.24 only, `pacing_limited` |
| `enforceable` | boolean |
| `questions` | a list of closed objects `{ "id": code, "clause_sha256": hex, "outcome": PASS, FLAG or INDETERMINATE, "p", "p_pass", "flag_at", "pass_at": number or null }` |
| `execution` | `gateway` or `pool` |
| `pool_verdict_id` | `null`, or `jv_` and 32 lowercase hex digits; always present, as below |
| `backend` | `null`, or the closed object `{ "id": code, "distribution": native, derived or null, "validated": boolean, "prompt_version": code, "prompt_sha256": hex, "validation_run": code or null, "validation_sha256": hex or null }` |
| `timing` | `after_delivery` or `before_delivery` |
| `rollout_stage` | `shadow`, `flag` or `enforce` |
| `action_taken` | `allow`, `warn`, `redact`, `mask_output`, `hold` or `block` |
| `stage` | `pre_request`, `post_response` or `tool_call`: where the judgment ran |
| `input_form` | `redacted` or `raw`: the form of every input of the judge call |
| `snapshot` | `forwarded_request`, `candidate_reply`, `candidate_reply_partial` (a streamed reply that was not seen whole) or `tool_arguments` |
| `raw_input_grant` | code; present only as below, otherwise absent (never `null`) |
| `latency_ms` | unsigned 32-bit integer |
| `evaluated_at` | RFC 3339 UTC time (`Z` or `+00:00`) |

Cross-field rules, each a failure when broken:

- `raw_input_grant` is present exactly when `input_form` is `raw` and
  `backend` is not `null`: a raw judgment that reached a backend names the
  organization's permission that covered that backend, and one that reached
  none names none.
- `pool_verdict_id` links a receipt to the shared decision pool's own record
  of the same verdict. It is `null` when `execution` is `gateway`. When
  `execution` is `pool` it is the pool's verdict id (`jv_` and 32 lowercase
  hex digits), or `null` only when the gateway settled the verdict itself
  because the pool issued none: an `INDETERMINATE` whose `source` is not
  `judge`, with `reason_code` `backend_timeout`, `backend_unavailable`,
  `backend_error`, `malformed_answer`, `raw_input_not_permitted`,
  `backlog_dropped`, `no_backend_configured`, `floor_unavailable` or
  `floor_triggered_unanswered`; or a `FLAG` from `source` `floor` with
  `reason_code` `floor_match`.
- `reason_code` `raw_input_not_permitted` (a raw judgment with no covering
  permission) has `input_form` `raw`, `backend` `null`, `verdict`
  `INDETERMINATE` and `source` `none`.
- Each stage judges its own snapshots: `forwarded_request` only with
  `stage` `pre_request`; `candidate_reply` and `candidate_reply_partial` only
  with `post_response`; `tool_arguments` exactly with `tool_call`.
- When the pack holds the judged record (and it is not a hash-only stub),
  `snapshot` `tool_arguments` judges an `mcp.tool_call` record and the other
  three an `llm_request` record, and `stage` `tool_call` judges an
  `mcp.tool_call` record.
- `pack.version` is `null` exactly when `reason_code` is `pack_unavailable`,
  as in v1.21.

The local part (`raw_response`) is `judgment_verdict_local.v2`, a closed
object: `schema` (`"judgment_verdict_local.v2"`), `reason_text` (string or
null), `reason_text_withheld` and `floor_unavailable` (booleans), `spans` (a
list of closed objects `{ "input": string, "start", "end": unsigned 32-bit
integers }`), `judged_input_sha256` and `floor_triggers`.
`judged_input_sha256` is 64 lowercase hex, the SHA-256 of the UTF-8 bytes of
the judged input block exactly as the backend received it, and is `null`
exactly when the uploaded form's `backend` is `null`. `floor_triggers` is a
list of closed objects `{ "rule_id", "term_id", "language": string }`, the
ids of the trigger-floor terms that fired; it never holds the matched text.
The local part is never uploaded. In a content-stripped pack (§6.6) whose
`removed_fields` include `raw_response`, its checks are left out.

What a v1.22 receipt does not show: `rule_sha256` names the rule as
delivered, but the pack does not hold the rule, so only its format is
checked; the verifier cannot tell whether a permission named by
`raw_input_grant` was live when the judge ran, or whether a reply marked
partial was in fact not seen whole, only that the receipt states these facts
consistently.

**v1.23 `control_probe.run`**: a new kind with a bucket of its own. From
`control_probe_run`, after the kind attestation: `run_id`, `started_at`,
`finished_at`, `bundle_sha256`, `policy_version`, `evidence_mode`
(length-prefixed strings, §3), `shadow_mode` (one byte, `0x01` for true or
`0x00` for false), `sets_sha256` (length-prefixed string), `passed`,
`failed`, `not_applicable` (u64), `results_sha256` (length-prefixed string).
28 fields. Every field is required; a field that is absent or of another
type leaves the record with no defined preimage and fails verification. v1.23
holds no other kind, and a `control_probe_run` payload on any other version
or kind fails.

A probe run records one scheduled run of synthetic negative tests through the
gateway's governance engine, with the policy in force: each case is a
synthetic input with the detection the rule is expected to reach, evaluated
against the one rule instance under test. The run names the policy bundle
(`bundle_sha256`, `policy_version`), the gateway's evidence mode
(`write_once` or `local_chain`), whether any case ran in shadow mode
(`shadow_mode`) and the counts of its case outcomes. It is not traffic: a
probe makes no upstream call and writes no request record.

Two parts are stored beside the hash and bound by digests the hash covers:

- `sets_json`, the probe sets the run used: the RFC 8785 serialization of
  the array of closed objects `{ "set_id": string, "version": unsigned
  integer, "sha256": 64 lowercase hex }`, sorted by `set_id`, `version`,
  `sha256`. Its SHA-256 is `sets_sha256`.
- `results_json`, the per-case results: the RFC 8785 serialization of the
  array of closed objects `{ "set_id", "case_id", "rule_instance": string,
  "configured_action": "block" | "redact" | "warn" | "flag" | "hold",
  "expected_detected", "actual_detected": boolean, "actual_decision":
  "block" | "redact" | "flag" | "hold" | "allow", "outcome": "pass" |
  "fail" | "not_applicable", "shadow": boolean }`, sorted by `set_id`,
  `case_id`, `rule_instance`. `set_id` and `case_id` are 3 to 64
  characters of lowercase letters, digits and hyphens, starting with a
  letter or digit; `rule_instance` is a non-empty string. Its SHA-256 is
  `results_sha256`.

When the record carries a stored part, the verifier checks that it hashes to
its digest, that it is the canonical form of the sorted array of closed
objects, that `passed`, `failed` and `not_applicable` are the counts of the
results' outcomes, and that `shadow_mode` is true exactly when some result
is in shadow. It also checks that the three digests are 64 lowercase hex and
that `evidence_mode` is `write_once` or `local_chain`. A record without a
stored part is not a failure: the verifier says the digest is bound but not
checked. The parts hold ids, digests, booleans and fixed vocabularies; no
input text of a case.

What a probe run does not show: that the gateway ran the cases it names, or
ran them against the bundle it names; only that the stated results were
recorded and have not changed since, and agree with the counts the hash
binds. A case in shadow mode shows what the policy would have done, not that
it blocked anything. A pass of the run says nothing of a rule no delivered
set covers.

**v1.24 `judgment.verdict`**: the v1.22 record, preimage, uploaded form and
local part, unchanged, with every v1.22 check. The stamp marks the receipt
of a verdict whose reason code is `pacing_limited`, the eighteenth code: a
judgment that left the gateway's after-delivery queue unanswered because the
gateway's own request pacing for the judge backend held it. A reader that
knows seventeen codes refuses the version instead of reading the new code as
tampering. The receipt has one shape: `verdict` `INDETERMINATE`, `source`
`none`, `execution` `gateway` and `backend` `null`. `timing` is the rule's
configured timing, so it can be either value. A `pacing_limited` receipt on
any other version, a v1.24 receipt with any other reason code, and a v1.24
stamp on any other kind fail verification.

What a v1.24 receipt does not show: that pacing was the cause, or that the
configured rate was the one in force; only that the gateway recorded the
judgment as left unanswered for that reason, and that the record has not
changed since.

MCP kinds are: `mcp.tool_call`, `mcp.policy_decision`, `mcp.tool_result`,
`mcp.tools_list.served`, `mcp.error`, `mcp.catalog_drift`. Any MCP hasher
called with a non-MCP kind is an error.

`*_sha256_jcs` values are hex SHA-256 digests over the JSON Canonicalization
Scheme (RFC 8785) serialization of the payload in question. For MCP records
the verifier checks that the digest string is what the record hashed; it does
not recompute the digest from a payload, because the payload is not part of
the record. For LLM records with a `content` block (v1.10, v1.11, v1.12,
v1.16, v1.18, v1.19) it also recomputes the stored-content digests (§4.4),
for v1.12, v1.14, v1.17, v1.18 and v1.19 records with an identity the
asserted-claims digest (§4.5), for v1.16, v1.18 and v1.19 records the
evaluation outcome digest, for v1.15 records the evidence-set digest (§4.3),
for v1.18 and v1.19 records the customer label digest (§4.6), for v1.20
records the stored-record, file-content and findings digests (§4.3), and for
v1.21, v1.22 and v1.24 records the digests of the uploaded form and the local
part, and for v1.23 records the digests of the probe sets and the case results
(§4.3).

### 4.4 LLM content attestation (v1.10, v1.11, v1.12, v1.16, v1.18, v1.19)

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
v1.12, v1.16, v1.18 or v1.19 record that carries a `content` block:

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

A v1.12, v1.16, v1.18 or v1.19 record with no `content` block was sealed with no
capture policy. Its prompt and response are stored but not bound, as before
v1.10, and are not checked.

In a content-stripped pack (§6.6) `messages`, `response_text` and
`tool_calls` are removed from every record. Checks 1, 2 and 4 are then not
made: the sealed digests are inside the hash, which the chain walk
recomputes, and that is all a stripped pack can show of them. Check 3 is
still made, because `findings` are kept.

JCS follows RFC 8785: object keys sorted by UTF-16 code units, no
whitespace, strings escaped as in RFC 8785 §3.2.2.2, numbers in ECMAScript
form (`1.0` → `1`, `1e-7` → `1e-7`, `1e21` → `1e+21`). A plain sorted-keys
JSON dump differs on numbers and must not be used.

### 4.5 Sealed identity (v1.12, v1.14, v1.16, v1.17, v1.18, v1.19)

A v1.12 record carries an `identity` block naming who called the proxy (a
v1.14, v1.16, v1.17, v1.18 or v1.19 record carries it too, when the proxy resolved
one):

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
saw. A verifier therefore checks, for every v1.12 record and every v1.14,
v1.17, v1.18 or v1.19 record that carries an identity, that
`asserted_digest` equals SHA-256(JCS(`asserted`)). A label rewritten after
sealing leaves the chain hash intact and fails this check. The labels are
claims a caller made, never evidence of who it was; only the hashed fields
record what the proxy verified. In a content-stripped pack (§6.6)
`identity.asserted` is removed and this check is not made; the digest stays
inside the hash. On a v1.16 record the identity is hashed but its
asserted-label digest is not re-derived by this release; a v1.16 label
rewritten after sealing is not caught until the record is checked by a
release that does.

### 4.6 Sealed customer (v1.18, v1.19)

A v1.18 record carries a `customer` block naming which of the proxy
operator's customers the call was made for. A v1.19 record carries one when
the proxy resolved a customer:

| Field | Hashed | Meaning |
|---|---|---|
| `source` | yes | How the customer was established: `credential`, from a credential the proxy verified; `asserted`, from a label the caller supplied; `none`, no customer |
| `label_sha256` | yes (optional string) | Hex SHA-256 over the UTF-8 bytes of the customer label; 64 lowercase hex characters |
| `credential_kid` | yes (optional string) | The key id of the credential that established the customer |
| `customer_id` | no, bound through `label_sha256` | The plain label, stored at the top level of the record beside the block |

The block's shape follows from `source`: `none` carries neither a digest
nor a kid; `asserted` carries a digest and no kid; `credential` carries a
digest and a non-blank kid. A block of any other shape, or a `source` not
listed, is invalid and fails verification.

A verifier checks, for every v1.18 or v1.19 record whose `source` is `asserted` and
which stores a non-empty `customer_id`, that `label_sha256` equals
SHA-256(UTF-8(`customer_id`)). A label rewritten after sealing leaves the
chain hash intact and fails this check. A missing `customer_id` is not a
problem: a pack produced for one customer carries other customers' records
without their label (as hash-only stubs, §6.6), and a content-stripped pack
removes `customer_id` from every record.

### 4.7 Data-reach block (v1.17, v1.18)

A `tool_call`-stage `mcp.policy_decision` may carry `mcp_event.data_reach`:
which declared data binding, if any, the tool call's arguments matched. Every
member is hashed (§3). The shape a verifier requires, and fails the record
without:

- `outcome` is one of `matched`, `no_match`, `error`;
- `binding_id` is `rb_` followed by 16 lowercase hex characters exactly when
  `outcome` is `matched`, and the string `unbound` otherwise;
- `access` is `read` or `write` exactly when `outcome` is `matched`, and
  absent otherwise;
- `schema_known` is a boolean;
- `arg_keys` is a list of at most 32 strings, each non-empty and at most 64
  characters, strictly ascending in UTF-8 byte order; it holds argument
  names, never values;
- `arg_keys_omitted` is an integer from 0 to 2³² − 1.

## 5. Reference values

The verifier's self-test pins one fixture hash per version. Two of them,
useful for a from-scratch implementation:

- The v1 fixture (`--self-test` assertion 1) hashes to
  `ba7a7f3d…e031` (full value in `verify-pack.py`, `FIXTURE_HASH`).
- A `Z`-suffixed timestamp and its `+00:00` form produce the same hash
  (assertion 2); feeding the `Z` form unnormalized does not.

## 6. Pack manifest

`manifest.json` (schema_version `"1.0"` through `"1.5"`) describes one
verification window of one chain:

```json
{
  "schema_version": "1.0" | "1.1" | "1.2" | "1.3" | "1.4" | "1.5",
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
  "claim": {"scope": "chain_to_head" | "interval", "from_sequence": 0, "to_sequence": 27},   … optional, §6.7 …
  "evidence_modes": [ … present when the pack holds evidence-mode seals, §6.8 … ],
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
  "anchoring": { … present on 1.1 and later, §6.1 … },
  "storage_layout": "per-record" | "segmented-v1",   … present on 1.2; on 1.3 and later when the chain is segmented, §6.2 …
  "control_plane": { … present on 1.3; on 1.4 and 1.5 when the pack carries that chain, §6.3 … },
  "decision_receipts": [ … present when the pack holds decision receipts, §6.4 … ],
  "evidence_class": "<label>",                        … present on 1.4; optional on 1.5, §6.5 …
  "content": "stripped",                              … present on 1.5 only, §6.6 …
  "removed_fields": [ … ],                            … present on 1.5 only, §6.6 …
  "stubs": [ … ],                                     … optional on 1.5 only, §6.6 …
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
      "previous_hash_match": true,
      "object": {"name": "<object name>", "index": 0}   … present with storage_layout, §6.2 …
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

### 6.1 Chain-head anchors (manifest 1.1 and later)

A chain shows order and integrity. It does not show time: `timestamp_utc`
comes from the proxy's clock, and a writer with access to the chain could
back-date a rewritten chain. A proxy that writes its chain to a write-once
store therefore anchors the chain head periodically with RFC 3161 timestamp
tokens from independent timestamp authorities (witnesses). The witness sees
only a 32-byte digest and a nonce, never a record.

**Statement.** An anchor statement is JCS (RFC 8785) JSON with exactly these
fields, `heads` sorted by chain name with no chain repeated:

```json
{"created_at":"2026-05-01T00:10:00.000Z","hash_alg":"sha-256","heads":[{"chain":"<chain name>","event_hash":"<hex>","seq":4}],"run_id":"<instance boot id>","v":"meilynx.anchor.v1"}
```

Each head is the last record the proxy had durably written to the store for
that chain, by sequence and `event_hash`. The imprint the witness signs is
`SHA-256("meilynx-anchor-v1\n" || statement bytes)` over the exact stored
bytes. A statement whose bytes are not the canonical form is invalid, so each
statement has exactly one imprint.

**Objects.** Next to the chain, under the same write-once retention:

| Object | Content |
|---|---|
| `anchors/{chain}/{seq:020d}.json` | The statement |
| `anchors/{chain}/{seq:020d}.{tsa_id}.tsr` | One `TimeStampResp` (RFC 3161) per witness, stored only after the proxy verified it |

`{seq}` is the head sequence the statement records for that chain. In an
exported pack they sit under `records/anchors/`. The verifier reads anchors
from the records directory offline, or from the bucket online. Anchors are
per-record in every layout: the verifier resolves an anchor's `{seq}` to its
record through the record objects of §1, so an anchor over a segmented chain
names the same sequence and `event_hash` it would over a per-record one.

**Token.** A token verifies when all of the following hold:

- `PKIStatus` is `granted`; the TSTInfo imprint equals the statement imprint
  under SHA-256, and a nonce is present.
- The signer certificate carries the `id-kp-timeStamping` extended key usage,
  marked critical, and the signed attributes are limited to contentType,
  messageDigest, signingTime, signingCertificateV2 and
  CMSAlgorithmProtection. ESSCertID v1 (SHA-1) is rejected.
- Digests are SHA-256, SHA-384 or SHA-512; signatures are RSA of at least
  2048 bits (PKCS#1 v1.5 or PSS with salt length equal to the hash length) or
  ECDSA on P-256 or P-384. SHA-1 and MD5 are rejected everywhere.
- The certificate path, built from intermediates carried in the token, ends
  at a trusted root that was valid at the token's `genTime`, and never
  follows a cross-certificate. Roots never come from the token.

**Roots.** Two public witnesses have roots pinned in `verify-pack.py`, each
with its SHA-256 fingerprint and trust window: `sigstore` (the Sigstore TSA
root from `sigstore/root-signing` `trusted_root.json`) and `globalsign-r45`
(GlobalSign Root CA - R6). A customer witness's roots are supplied with
`--tsa-root ID=FILE` (PEM, one or more certificates, each trusted within its
own validity period); the verifier then names that root and its fingerprint
in a NOTICE. No revocation check is made.

**Manifest section.** A 1.1 or 1.2 manifest carries `anchoring`:

```json
"anchoring": {
  "state": "anchored" | "partially_anchored" | "unanchored",
  "chains": [{
    "chain": "<chain name>",
    "reason": "anchored" | "disabled" | "misconfigured" | "no_anchors_found",
    "anchored_through_seq": 4 | null,
    "unanchored_tail": {"from_seq": 5, "to_seq": 9} | null,
    "anchors": [{
      "seq": 4,
      "statement": {"key": "anchors/<chain>/00000000000000000004.json", "sha256": "<hex>"},
      "tokens": {"<tsa_id>": {"gen_time": "<RFC 3339>", "sha256": "<hex>"}}
    }],
    "seals": [{"seq": 0, "event_hash": "<hex>", "action_type": "audit_anchoring_disabled" | "audit_anchoring_misconfigured"}]
  }]
}
```

Only anchors inside `[from_sequence, to_sequence]` are listed. An anchor at
sequence S covers every record from `from_sequence` through S, because each
record's hash commits to the one before it. Records after the last anchor are
the unanchored tail. A `seal` is an `admin_action` record the proxy wrote at
startup when anchoring was switched off or refused its configuration; it
explains an unanchored chain.

**What a verifier checks** (`verify-pack.py` does all of these):

| Finding | Verdict |
|---|---|
| Manifest 1.0, or 1.1 with `state: unanchored` and no anchors | Pass, with the status line `ANCHORS: none` |
| A listed anchor whose statement or token object is missing, or whose bytes differ from the manifest's SHA-256 | Fail (exit 1), naming the chain, the sequence and the reason |
| A statement that is not canonical, or does not name this chain at this sequence | Fail (exit 1) |
| The anchored `event_hash` differs from the record's recomputed hash, or from the hash the record stores | Fail (exit 1): the record changed after it was anchored |
| A token that does not verify, including a path that reaches no trusted root | Fail (exit 1), with the same reason code the proxy's verifier uses |
| A listed anchor at a sequence outside `[from_sequence, to_sequence]` | Fail (exit 1), whatever the claim (§6.7) |
| An anchor found in the records directory or bucket that the manifest does not list, at a sequence inside the pack | Verified like a listed one; a pass is reported as a NOTICE, a failure fails the pack |
| An anchor the manifest does not list, found next to the records at a sequence after the pack's last record | Judged only when the pack claims the whole chain up to its head (§6.7): a verified one is coverage not established (exit 4). Otherwise a NOTICE that it was not judged |
| The manifest's `state`, `reason`, `anchored_through_seq` or `unanchored_tail` disagree with the anchors that verified | Fail (exit 1) |
| A listed seal that is not the `admin_action` record it claims to be | Fail (exit 1) |
| A record whose `timestamp_utc` is more than five minutes after the `genTime` of the earliest anchor covering it | Pass, with a NOTICE naming the first such record; the token's `genTime` is the authoritative time |
| No trust root for a witness, an unparseable token, or a manifest `schema_version` this verifier does not know | Cannot evaluate (exit 2) |

The verifier prints one anchoring status line. A pass prints
`ANCHORS OK: verified through seq=<seq>, <verified>/<listed> witnesses`,
followed by `; seq=<from>..<to> not yet anchored` for an unanchored tail. A
pack with no anchors prints `ANCHORS: none`. A seal adds `anchoring turned
off at seq=<n>` or `anchoring misconfigured at seq=<n>` to the line, and a
manifest 1.0 pack prints `ANCHORS: none (manifest 1.0 predates anchoring)`.
An anchor shows that the covered records
existed no later than the token's `genTime` and are unchanged since. It does
not show that the chain is complete (§8).

### 6.2 Storage layout (manifest 1.2)

A 1.2 manifest is a 1.1 manifest, `anchoring` included, with two additions
that record where each record is stored. It is meant for a pack over a chain
stored in segment objects (§1); a pack over a per-record chain can stay on
1.1. A verifier reads either `storage_layout` value.

- `storage_layout`: `"per-record"` or `"segmented-v1"`. Absent, or any other
  value, is cannot evaluate (exit 2): the verifier does not know how to read
  the chain.
- `events[].object`: `{"name": "<object name>", "index": <n>}`. `name` is the
  object holding the record, relative to `prefix` (`{seq:020}.bin` or
  `{first:020}-{last:020}.seg`), and `index` is the record's 0-based position
  in it, so `index` equals `sequence − first`.

**What a verifier checks** (`verify-pack.py` does all of these), on top of
§1, §6 and §6.1:

| Finding | Verdict |
|---|---|
| An entry with no `object`, or one without `name` or `index` | Fail (exit 1) at that sequence |
| An `object` whose name is not a record object, or whose range and `index` do not hold the entry's sequence | Fail (exit 1) at that sequence |
| Reading from the bucket: no listed object of that name holds the sequence | Fail (exit 1) at that sequence |

Offline, the reference is checked against its own name and not against the
records directory, which may hold the same records as per-record files.

**Exported packs.** `verify-pack.py --export-records DIR` writes one
`{seq:020}.bin` file per record, byte-identical to a per-record object,
whatever the bucket's layout: it splits segments. An exported pack therefore
reads like a per-record pack, while its 1.2 manifest still names the segment
each record came from. `--export-records` works from `--bucket` and from a
`--records` directory.

Per-entry hashes are unchanged from 1.1, and a signed pack's signature covers
the 1.2 manifest's exact bytes as before (§7).

**Older verifiers.** A verifier from before this layout fails closed. Given a
1.2 manifest it is cannot evaluate (exit 2). Pointed at a segmented chain in
a bucket with a 1.1 manifest, it finds no `{seq}.bin` object and reports
every record missing (exit 1). It never passes such a chain.

On 1.3, 1.4 and 1.5, `storage_layout` and `events[].object` are present
exactly when the chain is segmented, and are read as on 1.2; a per-record
chain carries neither.

### 6.3 Control-plane chain (manifest 1.3)

A manifest with `schema_version` 1.3 carries a `control_plane` section
describing a second chain in the same bucket: the control plane's record of
the human actions a governance decision involved (a held call released,
denied or expired; a review disposition; a condition set accepted). A 1.4 or
1.5 manifest carries the section when the pack holds that chain; a 1.0, 1.1
or 1.2 manifest that carries one fails verification, as does a 1.3 manifest
without one.

```json
"control_plane": {
  "chain_family": "control-plane",
  "prefix": "control-plane/",
  "hash_algorithm": "SHA-256",
  "hash_version": "v1",
  "genesis_hash": "<hex>",
  "verified": true,
  "records_checked": 3,
  "events": [
    {"sequence": 0, "event_id": "…", "stored_event_hash": "<hex>", "recomputed_event_hash": "<hex>"}
  ]
}
```

Records are one JSON object each, at `control-plane/{seq:020d}.json` in the
bucket; in an exported pack they sit under `records/control-plane/`, where
`--export-records` writes them. Records carry `schema_version` `"v1"`, and
`event_hash` is SHA-256 over the sequence number (i64 little-endian), the
UTF-8 text of `previous_hash`, and the canonical JSON of the members
`actor_user_id`, `correlation_id`, `event_id`, `event_kind`, `occurred_at`,
`payload`, `project_id`, `schema_version` and `target_resource_id` (absent
members as `null`). Canonical JSON orders object members by UTF-16 code
units, has no whitespace, escapes only `"`, `\` and control characters
(`\b`, `\f`, `\n`, `\r`, `\t`, else `\u00xx` in lowercase hex), writes every
other character as UTF-8, and copies number tokens exactly as the stored
record spells them: a verifier must keep the record's number text rather
than re-format a parsed value. A record with a duplicate key, a `NaN` or
`Infinity` token, or one that is not an object, is unreadable. Sequence 0
links to the genesis hash of §2.

**What a verifier checks** (`verify-pack.py` does all of these):

| Finding | Verdict |
|---|---|
| `chain_family` is not `control-plane`, `prefix` is not `control-plane/`, `hash_version` is not `v1`, `genesis_hash` is not the §2 value, or `events[].sequence` is not `0, 1, …` in order | Fail (exit 1) |
| A record that cannot be read, parsed, or whose `schema_version` is not `v1` | Fail (exit 1) at that sequence; the walk continues |
| The record's `sequence_number` is not the entry's; its recomputed hash differs from its stored `event_hash` or from the entry's `recomputed_event_hash`; the entry's `event_id` is not the record's | Fail (exit 1) at that sequence |
| `previous_hash` is not the hash of the record before it (genesis for sequence 0) | Fail (exit 1): chain break |
| A record after one that failed, whose link could not be checked | Not verified: a `WARN` names it, and the chain's verdict is already Fail |

A pass prints `CONTROL-PLANE OK` with the record count. Each decision
receipt (§4.3) whose `cp_anchor_event_id` is the `event_id` of a verified
control-plane record must carry that record's `event_hash` as
`cp_anchor_event_hash`; a disagreement fails verification. A receipt naming
a record that failed is not checked (`WARN`), and one naming no record in
the pack prints `WARN receipt_anchor_outside_pack` and verifies.

### 6.4 Decision receipts index

A pack that holds decision receipts lists them in `decision_receipts`, on
any manifest version:

```json
"decision_receipts": [
  {"sequence": 7, "receipt_id": "…", "receipt_type": "…", "clock_status": "within"}
]
```

A verifier checks that each entry carries exactly those four keys, that no
sequence repeats, that each listed sequence is a `decision_receipt` record in
the pack whose sealed `receipt_id`, `receipt_type` and `clock_status` equal
the entry's, and that every decision receipt in the pack is listed. Any
disagreement fails verification. A manifest without the key, from a generator
that predates the index, is accepted; when the pack holds receipts, a NOTE
says they were checked as records only. A pass prints one `RECEIPT` line per
entry and `RECEIPTS INDEX OK`.

### 6.5 Evidence class (manifest 1.4)

A 1.4 manifest is a 1.3 manifest with a required `evidence_class` label
inside the manifest, covered by its signature when the pack is signed, saying what kind of evidence the pack holds; a 1.5
manifest carries it when it has one. The label must be one the verifier
reads:

| Label | Meaning |
|---|---|
| `sandbox-non-production` | Evidence sealed on a self-serve evaluation tenant, not production evidence. |
| `local-chain-not-write-once` | Records read from a gateway's own local hash chain. No write-once store confirmed them, and the pack is unsigned. |

The verifier prints the label and its meaning before the records and the
label on every verdict line. An unknown label, a 1.4 manifest without one,
or a label on a 1.0 to 1.3 manifest, is cannot evaluate (exit 2): a label is
never ignored.

**Local-chain packs.** A gateway with no write-once store keeps its chain
only in its own audit database. Its pack generator writes, for one chain,
`manifest.json` (1.4, `local-chain-not-write-once`, window A with no
signature, `bucket` set to `local-chain:<gateway id>`), the records under
`records/`, and the local chain-head anchors at or below the pack's last
record under `records/anchors/` (§6.1). The pack always starts at sequence 0
and runs to the head the generator read, and its manifest says so with a
`chain_to_head` claim (§6.7). A chain whose first records the gateway's
retention removed is not packed.

What such a pack can show: that each record's hash recomputes and links to
the record before it, and, where an anchor verifies, that the chain head at
that sequence existed no later than the token's `genTime`. What it cannot
show: who produced it (it is unsigned, so the manifest is only as
trustworthy as the way the reader received it); that the history is
complete (whoever controls the gateway's data volume can rewrite or remove
records before the pack is built, and a history rewritten before its first
anchor cannot be detected); anything about records after the last anchor
beyond their internal consistency. The one truncation a reader can detect is
a pack that stops before a head that a later anchor names, which §6.7
reports as coverage not established.

### 6.6 Content-stripped packs (manifest 1.5)

A 1.5 manifest describes a pack whose records carry no captured content and
no personal data, for a reader who is entitled to the evidence but not to
the content. Inside the signed bytes it says `content: "stripped"` and lists
`removed_fields`, which must be exactly this set (a dotted name is a member
of a nested object):

`customer_id`, `end_user_id`, `identity.asserted`, `messages`,
`raw_request`, `raw_response`, `response_text`, `tags_json`, `tool_calls`.

None of these fields is in any record version's preimage, so every record
still recomputes to its stored hash; a record that sealed its content is
checked against the digests it sealed (§4.4, §4.5, §4.6), not against the
removed content. A record that cannot be stripped and still verify, because
its hash or a sealed digest covers a personal identifier
(`auth_session.user_email`), ships as a **hash-only stub**: a JSON object
holding exactly `sequence_number`, `event_hash`, `previous_hash` and
`schema_version`, nothing of the body, listed in the manifest:

```json
"stubs": [
  {"sequence": 3, "reason": "sealed_personal_identifier", "field": "auth_session.user_email"}
]
```

`reason` is one of `sealed_personal_identifier`, `email_address` or
`unreadable_record`; `field` names the field that forced the stub. The list,
when present, is non-empty, in ascending sequence order with no repeat, and
names only sequences in `events[]`.

**What a verifier checks** (`verify-pack.py` does all of these):

| Finding | Verdict |
|---|---|
| `content` is not `stripped`, `removed_fields` is not exactly the set above, `stubs` is malformed or names an unknown reason, or any of the three keys appears on a 1.0 to 1.4 manifest | Cannot evaluate (exit 2) |
| The pack is read with `--bucket` | Cannot evaluate (exit 2): the bucket holds the full records, which are not what the manifest describes |
| A record (or stub) still carries a removed field, or a non-null `auth_session.user_email` | Cannot evaluate (exit 2) at that sequence, after the walk; a chain failure outranks it |
| A stub holds a member other than the four, lacks one, names another sequence, or its `event_hash` differs from the entry's `stored_event_hash` or `recomputed_event_hash` (on a signed pack the entry must carry `recomputed_event_hash`) | Fail (exit 1) at that sequence |
| A stub's `previous_hash` does not link to the record before it, or the record after it does not link to the stub's `event_hash` | Fail (exit 1): chain break |
| A stub whose `reason` is `unreadable_record` | Fail (exit 1): the stub stands for a record that does not parse, and nothing attests its hash |

A stub's hash is never recomputed; the chain is linked through it, and it
prints its own `STUB` line. The verdict line counts the stubs linked through
and carries `[content: stripped]`. A receipt evidence entry (§4.3) or a
chain-head anchor (§6.1) that cites a stub is checked on the stub's
`event_hash`. Read as a full pack, the same records fail their content
checks: the signed claim is what lets them verify.

### 6.7 Coverage claim

A manifest may carry `claim`, covered by the manifest's signature when the
pack is signed, saying what the pack holds:

```json
"claim": {"scope": "chain_to_head", "from_sequence": 0, "to_sequence": 27}
```

- `chain_to_head`: every record of the chain from sequence 0 up to the head
  the generator read. A local-chain pack (§6.5) carries this scope.
- `interval`: one window of a longer chain, which may go on on either side.
  A pack read from a write-once bucket carries this scope; the bucket is the
  record.

An explicit claim is an object with exactly these three keys, and both
bounds are non-negative integers. A manifest without `claim`, or with
`claim: null`, predates it and is read as `chain_to_head` when its evidence
class is `local-chain-not-write-once` and as `interval` otherwise; the
checks on an explicit claim's bounds in the table below are not applied to
such an inferred claim. The verifier prints one `CLAIM:` line, or `FAIL
claim:` with the reason when the claim contradicts the manifest.

| Finding | Verdict |
|---|---|
| An explicit claim whose bounds differ from `from_sequence` and `to_sequence` | Fail (exit 1) |
| An explicit `chain_to_head` claim with `from_sequence` other than 0 | Fail (exit 1) |
| A `local-chain-not-write-once` pack that claims `interval` | Fail (exit 1): relabelling such a pack as a window would stop a later anchor from being judged |
| An unknown scope, missing or extra keys, or a bound that is not a non-negative integer | Cannot evaluate (exit 2) |
| `chain_to_head`, and a verified anchor that the manifest does not list, found next to the records, names this chain at a sequence N after the pack's last record | Coverage not established (exit 4) |
| `interval`, and an unlisted anchor after the pack's last record | Not judged: `NOTICE: <n> anchor(s) outside this pack's window <from>..<to> were not judged` |

Anchors are read on manifest 1.1 and later (§6.1); a 1.0 manifest has
none. An anchor after a `chain_to_head` pack's last record is judged on its
statement and tokens only, because the record it names is not in the pack.
It is evidence of a later head only when at least one token verifies over a
canonical statement that names this chain at that sequence. When none
verifies and one has no trust root or cannot be parsed, the pack is cannot
evaluate (exit 2), because whether history is missing is not known. Any
other such anchor (no statement, a statement that does not name this chain
at that sequence, no token, a token that fails) is not evidence of a later
head and is reported as a NOTICE.

Coverage not established is neither a pass nor a tampering verdict. Every
record verified, but a timestamp authority saw the chain at sequence N and
the pack stops before N. The pack may have been built before that head, the
records after its last one may have been removed, or the anchor may name
another gateway's chain of the same name; nothing in the pack can say which.
The verifier prints

```
COVERAGE anchor seq=N: a verified anchor (…) names chain <chain> at seq=N, after this pack's last record seq=M; …
COVERAGE NOT ESTABLISHED through seq=N: …
INTEGRITY OK, COVERAGE NOT ESTABLISHED: all <count> events verified, … This is not a tampering verdict.
```

and exits 4. The remedy is a pack that runs through N. An anchor inside the
claim that names a different head is still a failure (exit 1, §6.1).

**`--require-through SEQ`.** The claim is in the manifest, which a local-chain
pack does not sign. A reader who knows from another source how far the chain
had reached (for example the head the gateway reported to its control plane)
passes it with `--require-through SEQ`. The option compares SEQ with the
manifest's `to_sequence`, whatever the manifest claims. A pack whose
`to_sequence` is before SEQ prints `COVERAGE NOT ESTABLISHED through
seq=SEQ: the pack's last record is seq=M, before the sequence you required
(--require-through)` and exits 4; one whose `to_sequence` is at or after SEQ
prints `COVERAGE: the pack reaches seq=M, at or after the required
seq=SEQ`. The option does not itself establish that the pack's records reach
`to_sequence`; that is the chain check's finding for the records the
manifest lists.

In this release the closing exit-4 line, `INTEGRITY OK, COVERAGE NOT
ESTABLISHED: … a verified anchor shows the chain went on past the head this
pack claims …`, mentions a verified anchor even when only `--require-through`
caused the result. In that case the `COVERAGE NOT ESTABLISHED through
seq=SEQ` line above it names the cause, and no anchor need have verified.

### 6.8 Evidence modes

A gateway resolves its evidence mode once at each start and seals it as an
`admin_action` record (v1.3) with `action_type` `evidence_mode_resolved` and
`metadata_json` holding `mode` (`write_once` or `local_chain`), `source`
(`configured` or `derived`, the latter when the mode was inferred from the
storage settings) and `write_once_confirmed`. The mode never changes while
the gateway runs, so a change of mode is visible only across a restart, as
two seals with different modes.

A manifest may carry `evidence_modes`, one entry per such seal among the
pack's records, in sequence order:

```json
"evidence_modes": [
  {"sequence": 1, "mode": "write_once", "source": "derived"},
  {"sequence": 4, "mode": "local_chain", "source": "configured"}
]
```

The verifier reads the seals from the records themselves. When the manifest
carries `evidence_modes`, each entry must hold exactly `sequence`, `mode`
and `source`, and the list must equal the seals found in the records, entry
for entry; otherwise the pack fails (exit 1) and the verifier prints `FAIL
evidence_modes: …` instead of the lines below. A manifest without the key
predates it, and the seals are read from the records alone. When the list is
absent or matches, the verifier prints one line per seal: `EVIDENCE MODE
seq=N: <mode> (<source>)`, or, in its place, `EVIDENCE MODE CHANGED at
seq=N: <old> -> <new> (<source>)` where the mode differs from the seal before
it. A pack with no seal prints `EVIDENCE MODE: no evidence-mode seal among
this pack's records`.

### 6.9 Witness files

A gateway with no write-once store holds its own record (§6.5): whoever
controls it can rewrite or remove records before a pack is built, and the
anchors inside the pack come from the same gateway. A gateway enrolled with
a control plane reports its chain heads there: on each heartbeat the head of
every chain (sequence and `event_hash`, with the head its evidence key
signed, §12), and, on an upload of their own, each anchor statement (§6.1)
with every timestamp token over it. The control plane verifies each token on
arrival and keeps all of it append-only. The organization's compliance
members download it as a **witness file**, and `--witness FILE` judges a
pack against it.

**Layout.** A ZIP archive, or the same tree as a directory:

| Member | Content |
|---|---|
| `witness-manifest.json` | The index below, as RFC 8785 bytes |
| `anchors/{chain}/{seq:020d}.json` | An anchor statement, the exact bytes the tokens are over |
| `anchors/{chain}/{seq:020d}.{tsa_id}.tsr` | One `TimeStampResp` per witness, each verified by the control plane on arrival |
| `head-signatures/{chain}/{head_sequence:020d}.json` | `{statement, signature}`: a chain head the gateway signed (§12), as it reported it |

**Manifest** (`meilynx.witness_manifest.v1`; the JSON schema and an example
are `fixtures/witness/witness-manifest.v1.schema.json` and
`fixtures/witness/witness-manifest.v1.example.json`):

```json
{
  "format": "meilynx.witness_manifest.v1",
  "generated_at": "2026-11-24T00:00:00Z",
  "org_id": "…", "project_id": "…", "proxy_id": "<gateway>",
  "chains": [{
    "chain": "<chain name>",
    "heads": [
      {"basis": "reported", "seq": 3, "event_hash": "<hex>", "observed_at": "…", "received_at": "…",
       "signed_head": {"path": "head-signatures/<chain>/00000000000000000003.json", "sha256": "<hex>"} | null},
      {"basis": "timestamp", "seq": 4, "event_hash": "<hex>", "received_at": "…",
       "statement": {"path": "anchors/<chain>/00000000000000000004.json", "sha256": "<hex>"},
       "tokens": {"<tsa_id>": {"path": "anchors/<chain>/00000000000000000004.<tsa_id>.tsr", "sha256": "<hex>",
                               "gen_time": "…"}}}
    ],
    "omitted_earlier_heads": 0
  }],
  "omitted_chains": 0,
  "contradictions": [{"kind": "fork" | "rewind" | "witness_conflict", "chain": "…", "seq": 4, "event_hash": "<hex>",
                      "earlier_seq": 6, "earlier_event_hash": "<hex>", "source": "heartbeat" | "witness",
                      "detected_at": "…"}],
  "signing": {"state": "signed" | "unsigned", "key_id": "<thumbprint>" | null,
              "reason": "attestation_key" | "no_attestation_key"},
  "disclosure": "<fixed text>",
  "signature": {"scheme": "meilynx.witness_manifest.v1", "alg": "ES256", "key_id": "<thumbprint>",
                "value": "<base64>"}
}
```

Times are UTC to the second. `chains` is sorted by name and `heads` by
sequence. `signature` is present exactly when `signing.state` is `signed`:
ECDSA P-256 with SHA-256 over `"meilynx.witness_manifest.v1" 0x00` followed
by the RFC 8785 bytes of the manifest without `signature`; `value` is the
64-byte `r || s` in standard base64 and `key_id` the RFC 7638 thumbprint of
the project's evidence attestation key (the key of §12's attestations).
`contradictions` lists what the control plane recorded as an integrity
finding: another hash at a sequence already reported (a fork), a lower
sequence after a higher one (a rewind), or another payload under a held
key. The heads on both sides are in `heads`, so a pack can match at most one
of them.

**Which heads count.** A `timestamp` head counts on the timestamp
authority's signature alone: at least one of its tokens verifies (§6.1, with
the roots of §6.1 and `--tsa-root`) over a canonical statement that names
this chain at this sequence with this `event_hash`, and whose `run_id` is
`<proxy_id>/<boot id>` for the file's gateway. A `reported` head, and a
timestamp head whose statement names no gateway, counts only when the
manifest's signature verifies under the attestation key the reader pins
(`--witness-key`, or `--attestation-key`). A file without a signature counts
only timestamp-backed heads; the verifier says so, and lists the others as
not counted. A head's `signed_head` is checked when the reader pins the
gateway's key (`--gateway-key`) or the pack carries attestations
(`--attestation-key`); it never makes a head count on its own.

**What a verifier checks** (`verify-pack.py --witness FILE` does all of these):

| Finding | Verdict |
|---|---|
| The file cannot be read, has no `witness-manifest.json`, or its manifest is outside the format | Cannot evaluate (exit 2) |
| The pack names no gateway (no `proxy_id`, no `local-chain:<gateway>` bucket label), or another gateway than the file | Cannot evaluate (exit 2) |
| A signature that does not verify under the pinned key, a key that is not pinned, or a `signing` member that disagrees with the signature | Fail (exit 1) |
| A listed object that is missing, does not match its digest or path, a statement that is not canonical or names another head, gateway or chain, a token that does not verify, a `gen_time` that is not the token's, or a signed head that names another gateway, chain or head | Fail (exit 1) |
| A counted head inside the pack whose record carries another `event_hash` | Fail (exit 1): the pack contradicts a witnessed head |
| A counted head after the pack's last record, whatever the pack claims | Coverage not established (exit 4) |
| No counted head for the pack's chain | Coverage not established (exit 4) |
| A head that does not count, a head before the pack's first record, another chain of the gateway, a recorded contradiction | NOTICE |
| A token whose witness has no trust root, or that cannot be parsed, on a head that does not otherwise count | Cannot evaluate (exit 2) |

A pass prints `WITNESS OK: chain <chain> matches <n> witnessed head(s)
inside the pack, witnessed through seq=<seq> (<basis>, <time>)`. A witnessed
head shows that the gateway reported that head, or that a timestamp
authority saw it, at that time; it does not show that the records behind it
were kept. A pack that passes is tamper-evident against the witnessed heads,
not proven complete: records written after the last witnessed head are
shown only to be consistent with each other.

### 6.10 Verification receipts

`--receipt FILE` writes what the run concluded as a content-free JSON
document, `meilynx.verification_receipt.v1`, in RFC 8785 bytes (schema and
example: `fixtures/witness/verification-receipt.v1.schema.json` and
`fixtures/witness/verification-receipt.v1.example.json`). It binds:

- the result: `exit_code` and its name (`pass`, `fail`, `cannot_evaluate`,
  `unsigned`, `coverage_not_established`);
- the verifier: `version` and the SHA-256 of the `verify-pack.py` that ran;
- the gateway: the witness file's `proxy_id` when it was bound to the pack,
  else the pack's own label;
- the pack: the SHA-256 of its `manifest.json` (which lists every record's
  hash), its id, evidence class, claim scope, record count and whether its
  signature verified;
- each chain: its sequence bounds, the `event_hash` it ends at, the
  `--require-through` value, the highest counted witnessed head, and whether
  coverage was established;
- the witness file: the SHA-256 of the file and of its manifest, its
  gateway, signature result and key, and the heads counted, matched, after
  the pack and not counted;
- the options that change the verdict: `--allow-unsigned`, the pinned
  attestation keys and the witnesses given roots.

`verified_at` is the clock of the host that ran the verifier, and nothing in
the receipt vouches for it. The receipt is unsigned: re-running the same
verifier on the same pack and witness file gives the same receipt apart from
`verified_at`. A receipt is written for every run that read the pack's
manifest (not for a usage error or an unreadable manifest or records
directory). Only exit 0 is a pass.

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
9. The certificate's subjectAltName holds the expected identity, and its
   Fulcio issuer extension (OID `1.3.6.1.4.1.57264.1.8`, falling back to
   `.1.1`) equals the expected issuer. For packs signed by the Meilynx
   signing workflow these are:
   - identity `https://github.com/Meilynx/meilynx-proxy/.github/workflows/integrity-pack-signed.yml@refs/heads/main`
   - OIDC issuer `https://token.actions.githubusercontent.com`

**Per-tenant signers.** A pack exported from a customer project is signed
instead by that project's own signer: a service account whose certificate
carries the issuer `https://accounts.google.com` and names the signer by an
email subjectAltName. Nothing in the pack can say whose signer it is, so the
reader supplies the exact email the evidence holder published for the
project with `--certificate-identity`. The verifier then:

- reads the issuer from the certificate; when it is `https://accounts.google.com`
  the signer is per-tenant, and the identity is matched against the
  certificate's email names only (a URI name never matches);
- refuses to evaluate a per-tenant pack checked without
  `--certificate-identity` (exit 2), even though the signature itself
  checks out;
- takes the expected issuer from `--certificate-oidc-issuer` when given;
  otherwise `https://accounts.google.com` when the supplied identity
  contains `@` and no `://`, and the workflow issuer above in every other
  case, including when no identity is supplied. The issuer is still compared
  exactly with the certificate's.

There is no pattern match on the identity: a per-tenant pack verifies only
against the one email the reader names, and the output says it is the
identity the reader supplied.

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
| 2 | Cannot evaluate: unsupported hash version, manifest version, storage layout, evidence class, content claim, signature method or bundle format; unusable trust anchors; a per-tenant signer checked without `--certificate-identity`; a content-stripped pack read with `--bucket` or still carrying a removed field. |
| 3 | Unsigned pack: records verified, authenticity not established. |
| 4 | Coverage not established: every record verified, but the pack claims the chain up to its head and a verified anchor names a later head (§6.7), or the pack stops before the sequence given with `--require-through`. `--allow-unsigned` does not turn it into 0. |

1 outranks 2, which outranks 4, which outranks 3. The codes are the same whether the records
are read from the bucket or from an exported record set. The export check
(§9) and the customer-conditions verdict (§10) each produce a code by the
same rule, and the highest-ranking code is the exit code.

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
  proxy was recorded. A chain whose objects stop before the last record its
  writer sealed (truncation, §1) verifies on the records present; the
  shortfall is not an integrity failure. The verifier reports it only when it
  has evidence of it: a pack that claims the whole chain up to its head and a
  verified anchor of a later head, or a pack that stops before the sequence a
  reader required (§6.7, exit 4). A local-chain pack (§6.5) comes from a
  store its operator can rewrite, so its records before the first anchor can
  have been rewritten without any check failing.
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
  `delegated_human` must agree with it. On v1.15 records the `evidence`
  list is stored but not hashed; `evidence_set_sha256` binds it (§4.3). On
  v1.16, v1.18 and v1.19 records the evaluation trace's timing is stored
  but not hashed; its outcomes are bound by `outcomes_sha256_jcs` (§4.3). On
  v1.18 and v1.19 records the plain `customer_id` is stored but not hashed;
  `label_sha256` binds it only when `source` is `asserted` (§4.6). On v1.20
  records the stored item, its file bytes and its findings are bound through
  `record_sha256`, `content_sha256` and `findings_sha256` (§4.3). On v1.21,
  v1.22 and v1.24 records the uploaded form and the local part are bound through
  `uploaded_sha256` and `local_sha256` (§4.3). On v1.23 records the probe
  sets and case results are bound through `sets_sha256` and
  `results_sha256` (§4.3). On LLM
  records before v1.19 `policy_version` and `model_executed` are stored but
  not hashed (v1.19 binds both, §4.3), and on every MCP record
  `mcp_event.finding_summary` is; the customer-conditions verdict (§10) says
  which of its findings rest on them.
- **Export copies.** An export of the chain to another format (§9) is a
  copy; the chain is the record. The verifier checks a copy against the
  pack, never the pack against a copy, and cannot recompute a record's hash
  from the copy.
- **Whether a detector missed something.** Under `redacted`, only spans a
  detector located are masked. The stored copy can still contain sensitive
  text no detector recognized.
- **Authorship of the chain.** A signed pack (§7) binds an identity to a
  window. A record signature (§11) binds each record to the proxy's chain
  signing key, not to a person or organisation, and whoever holds both that
  key and the records could sign a rewritten chain. An attestation (§12)
  binds that key to a gateway of a project, not to whoever held it.
- **Whether a verdict was right.** A verdict receipt (§4.3) shows which
  judgment gave which verdict on which record. It does not show that the
  verdict was correct, or that every request that should have been judged
  has a receipt.
- **When a record was written.** `timestamp_utc` is hashed, but it comes from
  the proxy's clock and nothing in the chain shows that clock was right. A
  chain-head anchor (§6.1) shows that a record existed no later than the
  witness's `genTime`, and the verifier flags a record clock that runs ahead
  of its anchor. A pack without anchors shows nothing about time, and the
  verifier prints `ANCHORS: none`. The same holds for a decision receipt's
  clock fields and a control-plane record's `occurred_at`: the sealed
  arithmetic is checked (§4.3), the clock behind it is not.

## 9. Export copies

A proxy may write its sealed records to a sink in OCSF form: gzip-compressed
NDJSON objects named by chain coordinates, each beside a `.manifest.json`
(RFC 8785 bytes) and, when the proxy holds an export signing key, a detached
`.manifest.sig`. The export is a copy of the chain, not the chain; content
fields are excluded from it by design, so a record's hash cannot be
recomputed from the export. `verify-pack.py --ocsf-export PATH` checks the
copy against the pack it is run with. `PATH` is one `.manifest.json`, a day's
`index.json` (whose `manifests` keys are resolved against the sink root that
holds it), or a directory searched for `*.manifest.json`; the object and the
signature are read beside each manifest.

An export manifest carries `mapping_version` (this verifier reads `"1"`),
`chain_id`, `first_sequence`, `last_sequence`, `record_count`,
`event_count`, `object` (the object's sink-relative key), `object_sha256`,
`signed` and `public_key_id`. Each line of the object is one event carrying
`meilynx.chain` (`chain_id`, `sequence_number`, `event_id`, `event_hash`,
`previous_hash`) and `meilynx.digests`, whose members are the digest fields
of §4.3 and §4.4 (`prompt_sha256_jcs`, `response_sha256`,
`stored_prompt_sha256_jcs`, `stored_response_sha256`, `findings_sha256_jcs`,
`tool_calls_sha256_jcs`, `stored_tool_calls_sha256_jcs` from `content`;
`payload_sha256_jcs`, `redacted_payload_sha256_jcs`,
`redaction_pre_sha256_jcs`, `redaction_post_sha256_jcs`, `mcp_bundle_sha256`
from `mcp_event`; `evidence_set_sha256` and `registry_digest` from
`decision_receipt`; `outcomes_sha256_jcs` from `evaluation_trace`;
`asserted_digest` from `identity`), each `null` when the record has none.

**What a verifier checks** (`verify-pack.py` does all of these):

| Finding | Verdict |
|---|---|
| `mapping_version` is not one the verifier reads | Cannot evaluate (exit 2) for that manifest, never a pass |
| `PATH` cannot be read or holds no manifest, or the `--ocsf-public-key` file is not a usable JWK | Cannot evaluate (exit 2) |
| `first_sequence` or `last_sequence` is not an integer; the object is missing beside its manifest; SHA-256 of the object differs from `object_sha256`; the object is not gzip NDJSON | Fail (exit 1), naming the object |
| The number of lines differs from `event_count`; the number of distinct sequences differs from `record_count`; the sequences do not span exactly `first_sequence`..`last_sequence` | Fail (exit 1), naming the object |
| A line that is not JSON, whose `chain_id` is not the manifest's, or whose `sequence_number` is outside the manifest's range | Fail (exit 1), naming the object and the line |
| An event on the pack's chain at a sequence the pack holds whose `event_id` or `event_hash` differs from the pack record's, whose `previous_hash` (when present) differs, or whose non-null digest is not the value the pack record holds in `content` or `mcp_event`, or names a digest the verifier does not know | Fail (exit 1), naming the object, the line and the field |
| An event on another chain, or at a sequence the pack does not hold | Pass, counted in one `WARN export_record_outside_pack`; not checked |
| Consecutive manifests of one chain that leave sequences uncovered, or overlap | Pass, with `WARN export_gap` or `WARN export_overlap` |
| A manifest that says it is `signed` and has no `.manifest.sig` | Signature fail (exit 1) |
| A signed manifest checked with `--ocsf-public-key JWK` (a P-256 EC JWK): the signature is 64 raw bytes `r ‖ s` in standard base64, verified as ECDSA P-256 over SHA-256 of the manifest's exact bytes | Pass when it verifies; signature fail (exit 1) when it does not |
| A signed manifest with no key given, or a manifest that is not signed | Unsigned (exit 3 without `--allow-unsigned`): the copy matches, authenticity not established |

The export's content and signature verdicts combine like a pack's (§7.3),
and the result ranks against the pack's code. An export is not checked
against a pack the verifier cannot evaluate.

## 10. Customer-conditions verdict

An evidence holder's control plane can accept a set of conditions another
party proposed, compile it into the holder's governance and MCP bundles as
rule instances `<family>@cust_<12 hex>` (the first 12 hex digits of the
relationship id), and seal the acceptance on its control-plane chain (§6.3)
as a record of `event_kind` `exchange.conditions_accepted` whose `payload`
carries `conditions_sha256` (the digest of the set the proposer holds),
`relationship_id`, and the compiled `compiled_governance_sha256` and
`compiled_mcp_sha256`. `verify-pack.py --conditions-sha256 HEX` adds one
verdict for that set, from the pack alone:

**The acceptance.** The last `exchange.conditions_accepted` record in the
pack's control-plane chain whose `payload.conditions_sha256` is `HEX`,
whether or not it verified; an earlier acceptance of the same digest is
never used in its place. Its `payload` must name a `relationship_id` that is a UUID, an
`occurred_at` that is a timestamp, and at least one 64-hex compiled bundle
digest; otherwise the verdict cannot be evaluated (a record supplied from
outside the pack that is not usable fails it). An acceptance that did not
verify in §6.3 fails the verdict. A pack that carries no control-plane
chain ("acceptance not in this pack"), or whose chain holds no acceptance
of the set ("this pack's control-plane chain holds no acceptance of the
set"), cannot evaluate the verdict (exit 2), unless the stored record
(`control-plane/{seq:020d}.json`) is given with `--conditions-acceptance
FILE`: its hash is then recomputed as in §6.3 and must equal its
`event_hash` (and, when the pack's chain holds a record with its
`event_id`, equal that record's), and the verdict says its link into the
holder's chain is not in the pack. Without an acceptance, only the records
that name a customer-condition instance are listed.

**The window.** The `llm_request` and MCP records of the pack whose
`timestamp_utc` is at or after the acceptance's `occurred_at` and, when a
later control-plane record released the set (`exchange.conditions_released`
of the same digest) or superseded it (an acceptance of another digest for
the same relationship), before that record's `occurred_at`. A hash-only stub
(§6.6) has no timestamp and is named apart, never placed in the window.

**Sealed under the set.** A record counts only by sealed evidence: an MCP
record whose hashed `mcp_event.mcp_bundle_sha256` equals
`compiled_mcp_sha256`, or an `llm_request` (v1.16, v1.18 or v1.19) whose
digest-bound `evaluation_trace.outcomes.rules[].rule_id` includes one ending
in `@cust_<12 hex>` for this relationship. Every other record in the window
is a `GAP` line with its sequence and hash. An `llm_request` whose
`policy_version` equals `compiled_governance_sha256` is counted in a
separate NOTE, never as sealed.

**Exceptions.** Each record in the window that names one of the set's
instances prints an `EXCEPTION` line saying what named it and whether a
sealed digest binds it: a `findings[].validator` (bound by
`content.findings_sha256_jcs` when the record carries one, else stored, not
hashed); the trace's `outcomes.deciding_rule_id` (bound by
`outcomes_sha256_jcs`); an `mcp_event.finding_summary[]` `rule_id` or
`detector` (stored, not hashed). A compiled MCP matrix row (`cust_<12
hex>.…`) is not an instance: a hold it raised that a person released is the
condition working.

The verdict line is `conditions: set <HEX> accepted at seq N; M of T records
in the window sealed under a governance version carrying it; E exceptions;
compiled by the holder's control plane`. The last clause is what the pack
cannot show: the compile runs in the holder's control plane, and the pack
carries bundle digests, not bundles. The verdict's code ranks against the
pack's as in §7.3; the verdict never changes the chain's own verdict.

## 11. Record signatures

A proxy configured with a chain signing key signs every record it seals, on
every chain and lane. The signature is Ed25519 (RFC 8032) over

```
"meilynx.audit.record_sig.v1" 0x00
|| u32 LE byte length of chain_id || chain_id (UTF-8)
|| u64 LE sequence_number
|| event_hash (64 lowercase hex characters, as ASCII)
```

and is stored on the record as `record_sig`, 128 lowercase hex characters.
`chain_id` is the chain the record belongs to, from its `source`: `proxy`
for `proxy` (or no `source`), `shadow` for `shadow_browser`, `coverage` for
`coverage`. A signed record with any other `source` fails verification. The
signature sits outside the preimage, so signing changes no record version.
Because `event_hash` commits to every earlier hash, a valid signature on a
record also vouches for the chain before it.

The proxy announces its key with an `admin_action` record whose
`action_type` is `chain_signing_started`, sealed when it starts with a key
configured. Its `metadata_json` carries `algorithm` (`ed25519`), `public_key` (the
32-byte key as 64 lowercase hex characters) and `public_key_fingerprint`
(`sha256:` followed by the hex SHA-256 of the raw key). A boundary whose key
is malformed, or whose fingerprint is not that key's, fails verification.
The proxy also publishes the key on its `/readyz` endpoint
(`chain_signing_public_key`).

A verifier walks the signatures with the hashes, in sequence order:

1. Records before the first signed record are the unsigned prefix: sealed
   before signing started, verified by hash only, and reported as such.
2. A record's signature is checked under the key the latest
   `chain_signing_started` boundary announced, else under the key the
   reader supplied. A signature that does not verify fails at that record:
   the record was edited and every hash after it recomputed without the key.
3. An unsigned record after a signed one fails: the chain was rewritten and
   its signatures stripped.
4. When the reader supplies the key (`--gateway-key`, alias
   `--chain-signing-key`), the newest
   signed record must verify under it. A chain re-signed under another key,
   even one that announces that key with a boundary of its own, fails there.
   Without a supplied key the verdict says the signatures were checked under
   the key the chain announces.
5. Signed records with neither a boundary in the pack nor a supplied key are
   counted as not checked.

The verdict prints one `SIGNATURES` line: `signed=true` when every record is
signed, `signed=partial` when an unsigned prefix comes first, and
`signed=false` when no record carries a signature. A pack whose records
carry no signature still verifies by hash. `record-signatures-v1` in
`VERIFIER_CAPABILITIES` declares this check.

The evidence-key seals of §12 change rules 3 and 4: after an
`evidence_key_signing_stopped` or `evidence_key_lost` seal, unsigned records
are accepted until the next `chain_signing_started`, and they are reported
as such.

## 12. Gateway evidence key

The key of §11 is the gateway's **evidence key**. Besides its records it
signs, with Ed25519, under domain-separated messages:

- **chain heads**, in `records/head-signatures/<head_sequence:020d>.json`:
  a `statement` (`format` `meilynx.evidence.chain_head.v1`, `proxy_id`,
  `chain_id`, `first_sequence`, `head_sequence`, `head_event_hash`,
  `hash_version`, `key_fingerprint`, `key_seq`, `signed_at`, and `org_id`
  and `project_id` when the gateway is enrolled) and a `signature`, 128
  lowercase hex characters, over `"meilynx.evidence.chain_head.v1" 0x00`
  followed by the statement's RFC 8785 bytes;
- **pack and OCSF export manifests**: a `signature` member with `scheme`
  `meilynx.evidence.v1`, `alg` `Ed25519`, `key_fingerprint`, `key_seq` and
  `value` (64 bytes, standard base64), over
  `"meilynx.evidence.manifest.v1" 0x00`, the kind (`evidence_pack` or
  `ocsf_export`), `0x00`, then the RFC 8785 bytes of the manifest without
  `signature`. An OCSF export manifest signed this way carries
  `mapping_version` `1+gateway-evidence-key-v1`.

**Attestation.** The control plane attests the key with the project's
P-256 attestation key. A pack carries every attestation in
`evidence-keys/attestations.json` (oldest first), each an envelope of a
`statement` (`format_version` `gateway_evidence_key_attestation.v1`,
`public_key_jwk`, `fingerprint`, `key_seq`, `reason`, `supersedes`,
`first_sequences`, `org_id`, `project_id`, `proxy_id`, `not_before`,
`issued_at`), its `sha256`, the `key_id` (RFC 7638 thumbprint) of the
attestation key and an ECDSA P-256 `signature` over SHA-256 of the
statement's RFC 8785 bytes. `reason` is `initial`, `rotation`,
`re_enrollment` or `acknowledged_loss`; an `acknowledged_loss` attestation
names the first sequence of each chain it covers in `first_sequences`.

**Pinning.** A reader pins one of two keys out of band:

- the project's attestation key (`--attestation-key`, a P-256 JWK). Every
  attestation must verify under it, and every record signature, signed head
  and manifest signature must verify under a key it attests, with the
  `key_seq` the attestation gives. The verdict prints `SIGNED BY GATEWAY
  <proxy> (key <fingerprint>, key_seq <n>), key attested by the project key
  you pinned`;
- the gateway's own key (`--gateway-key`), for a gateway with no control
  plane. The verdict says the key was pinned by the reader, not certified.

A manifest signed under `meilynx.evidence.v1` checked with neither is
cannot evaluate (exit 2).

**Key changes.** The gateway seals each change of key on its chain:
`evidence_key_rotated` (the last record the old key signs, with a rotation
statement the old key signed), `evidence_key_lost`,
`evidence_key_signing_stopped` (signing stops, for example while a new key
waits for the project's approval) and `evidence_key_rekeyed` (signed by the
new key after a loss). A key is credited from its
`chain_signing_started` boundary, after a rotation the previous key signed,
or, after an acknowledged loss, only from the sequence the attestation
names; the verdict then prints `KEY DISCONTINUITY at seq N` with the lost
and the new key. A key that took over from another with neither fails.
Records after a stop or a loss may be unsigned until the next boundary; a
record signed while its key was held back is reported as not attested and
never counted. A pack built while the key is lost or held back has an
unsigned manifest: it exits 3, or 0 with `--allow-unsigned`, and those
records never fail it.

**Signed heads and coverage.** A signed head inside the pack must name the
`event_hash` and `schema_version` of the pack's record at `head_sequence`
and the key in force there; otherwise the pack fails. A verified signed head
after the last record of a `chain_to_head` pack is coverage not established
(exit 4, §6.7), as an anchor is.

A signature shows which gateway key signed. It does not show who held the
key, or that no record is missing. `gateway-evidence-key-v1` in
`VERIFIER_CAPABILITIES` declares these checks.
