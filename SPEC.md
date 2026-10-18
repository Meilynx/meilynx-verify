# Meilynx audit chain format

This document describes the audit chain a Meilynx proxy writes, precisely
enough that a verifier can be written from it without reading Meilynx code.
`verify-pack.py` in this repository is one such verifier; its `--self-test`
pins the values below against fixture hashes.

Status: describes chain records with `schema_version` v1 through v1.18, the
per-record and segment storage layouts, the control-plane chain record
format `control-plane-v1`, pack manifest `schema_version` 1.0 through 1.5,
and OCSF export mapping version `1`, as read by `verify-pack.py` from
meilynx-proxy commit `4680d22` (2026-10-17).

## 1. Records

A chain is an ordered sequence of records. Each record is one JSON document
(UTF-8), stored in a write-once bucket under a chain prefix. The records are
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

A chain begins at sequence `0` on every proxy instance start and runs until
that instance stops. Different instances write different chains (distinct
prefixes); a chain never spans instances. Model-call and MCP records share
the request chain; coverage records (`coverage_computed`,
`coverage_key_inventory`) are written to a separate per-tenant coverage chain
with the same format and genesis.

Every record carries at least these fields:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Which preimage layout below applies (`"v1"`, `"v1.1"`, `"v1.2"`, … `"v1.18"`). Absent means `"v1"`. |
| `event_kind` | string | Record kind in serde form (`llm_request`, `admin_action`, `auth_session_started`, `mcp_tool_call`, `mcp_policy_decision`, `mcp_tool_result`, `mcp_tools_list_served`, `mcp_error`, `mcp_catalog_drift`, `coverage_computed`, `coverage_key_inventory`, `decision_receipt`). Absent means `llm_request`. |
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

Kind-specific payloads live under `admin_action`, `auth_session`,
`mcp_event`, `coverage`, `coverage_key_inventory`, `decision_receipt`,
`join_context`, `content`, `identity`, `evaluation_trace` and `customer`.
From v1.17 a policy decision on a tool call can also carry
`mcp_event.data_reach`. LLM records also carry `messages`,
`response_text`, `tool_calls`, `findings`, `policy_version`,
`raw_request`/`raw_response` and routing metadata, and a record can carry
the plain customer label in `customer_id`; **only the fields listed in the
preimage tables (§4) are covered by `event_hash`**. From v1.10 the content
of an LLM record is bound through digests (§4.4).

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
no separators, and no length prefixes except inside a name list (v1.17 and
later).

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
| bool | one byte: `0x01` for `true`, `0x00` for `false`. |
| name list | u32 count of names, then for each name a u32 byte length followed by the name's UTF-8 bytes. |
| data reach | `binding_id` (string), `access` (optional string), `outcome` (string), `schema_known` (bool), `arg_keys` (name list), `arg_keys_omitted` (u32). See §4.8. |
| sealed customer | `0x01` (the block's presence byte, always set in a v1.18 preimage), then `label_sha256` (optional string), `source` (string), `credential_kid` (optional string). See §4.9. |

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
keys; a `join_context` on a version other than v1.9, v1.10, v1.11, v1.12,
v1.14, v1.16, v1.17 and v1.18 is invalid and fails verification.

**v1.9 MCP kinds** — v1.7 fields, then the three `join_context` fields as
above. 38 fields.

**v1.10 `llm_request`** — the three `join_context` fields as in v1.9 (each
presence-tagged; a v1.10 record need not carry `join_context`, in which case
all three are fed as absent), then from `content`: `capture_policy`
(string), `prompt_sha256_jcs`, `response_sha256`,
`stored_prompt_sha256_jcs`, `stored_response_sha256`,
`findings_sha256_jcs` (all optional strings). 25 fields. A record carries
`content` only when the proxy's policy declared a capture policy; a
`content` payload on a version other than v1.10, v1.11, v1.12, v1.16 and
v1.18, or a v1.10 record without one, is invalid and fails verification.

**v1.11 `llm_request`**: the v1.10 fields, then from `content`:
`tool_calls_sha256_jcs` and `stored_tool_calls_sha256_jcs` (both optional
strings). 27 fields. A record is v1.11 exactly when the model's response made
at least one tool call; a record without tool calls stays v1.10. Tool-call
digests on a version other than v1.11, v1.12, v1.16 and v1.18, or a v1.11
record without `tool_calls_sha256_jcs`, are invalid and fail verification.

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

An `identity` block on a version other than v1.12, v1.14, v1.16, v1.17 and
v1.18, or a v1.12 record without one, is invalid and fails verification, as
is v1.12 on any kind other than `llm_request` and the MCP kinds. On an MCP record, a
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
record keeps its v1.12 (or earlier) bucket. A stage on a version other than
v1.14, v1.17 and v1.18, or a v1.14 record without one, is invalid and fails
verification, as is v1.14 on any kind other than the MCP kinds. A v1.14
record's identity, when present, is checked as in §4.5.

**v1.15 `decision.receipt`**: from `decision_receipt`, the 36 fields listed
in §4.6, in that order. 52 fields. A record is v1.15 exactly when it is a
`decision.receipt`. The payload on any other version or kind, v1.15 on any
other kind, or a v1.15 record without the payload, is invalid and fails
verification.

**v1.16 `llm_request`**: the v1.12 `llm_request` fields up to and including
the `content` presence byte and the eight `content` fields, then one
presence byte for the `identity` block: `0x00` if the record carries none,
else `0x01` followed by the sealed identity (§4.5). Then
`evaluation_trace.outcomes_sha256_jcs` (string). 36 entries counting both
presence bytes, when `content` and `identity` are present. A v1.16 record
carries an `evaluation_trace` (§4.7); its `join_context`, `content` and
`identity` are each optional. The proxy stamps v1.16 on an `llm_request`
record that carries an evaluation trace and no `customer` block (a record
with a `customer` block is v1.18). An `evaluation_trace` on a version other
than v1.16 and v1.18, or on any kind other than `llm_request`, is invalid
and fails verification, as is a v1.16 record without one and v1.16 on any
kind other than `llm_request`.

**v1.17 `mcp.policy_decision`**: the v1.14 MCP fields, byte for byte (the
`identity` presence byte and block, then `mcp_event.stage`), then the
`mcp_event.data_reach` block (§3, §4.8): `binding_id` (string), `access`
(optional string), `outcome` (string), `schema_known` (bool), `arg_keys`
(name list), `arg_keys_omitted` (u32). 52 entries counting the identity
presence byte, when `identity` is present. v1.17 is defined only for an
`mcp.policy_decision` record whose `mcp_event.stage` is `tool_call` and that
carries a `data_reach` block; v1.17 on any other kind, at any other stage,
or without the block is invalid and fails verification. A `data_reach`
block on a version other than v1.17 and v1.18, on any kind other than
`mcp.policy_decision`, or at any stage other than `tool_call` is invalid and
fails verification, as is a block that breaks a rule in §4.8. A v1.17
record's identity, when present, is checked as in §4.5.

**v1.18 `llm_request`**: the v1.16 `llm_request` fields up to and including
the `identity` presence byte and block, then one presence byte for the
`evaluation_trace`: `0x00` if the record carries none, else `0x01` followed
by `evaluation_trace.outcomes_sha256_jcs` (string). Then the sealed
customer block (§3, §4.9). 41 entries counting the four presence bytes
(`content`, `identity`, `evaluation_trace`, `customer`), when `content`,
`identity` and `evaluation_trace` are present. On v1.18, `join_context`,
`content`, `identity` and `evaluation_trace` are each optional.

**v1.18 MCP kinds**: the v1.14 MCP fields (the `identity` presence byte and
block, then `mcp_event.stage` as an optional string), then one presence
byte for `mcp_event.data_reach`: `0x00` if the record carries none, else
`0x01` followed by the six data-reach fields in their v1.17 order and
encoding. Then the sealed customer block. 57 entries counting the three
presence bytes (`identity`, `data_reach`, `customer`), when `identity` and
`data_reach` are present. v1.18 covers every MCP kind; unlike v1.14, a v1.18
MCP record need not carry a stage. A `data_reach` block is allowed only as
in v1.17: on an `mcp.policy_decision` whose stage is `tool_call`. No MCP
preimage reads `content`, so a v1.18 MCP record that carries a `content`
block is invalid and fails verification.

A record is v1.18 exactly when it carries a `customer` block, on either
lane: the proxy stamps v1.18 on such a record in place of v1.12, v1.14,
v1.16 or v1.17. A `customer` block on any other version, a v1.18 record
without one, v1.18 on any kind other than `llm_request` and the MCP kinds,
and a block that breaks a rule in §4.9 are invalid and fail verification.
A v1.18 record's identity, when present, is checked as in §4.5, its
evaluation trace, when present, as in §4.7, and its customer block as in
§4.9.

MCP kinds are: `mcp.tool_call`, `mcp.policy_decision`, `mcp.tool_result`,
`mcp.tools_list.served`, `mcp.error`, `mcp.catalog_drift`. Any MCP hasher
called with a non-MCP kind is an error.

`*_sha256_jcs` values are hex SHA-256 digests over the JSON Canonicalization
Scheme (RFC 8785) serialization of the payload in question. For MCP records
the verifier checks that the digest string is what the record hashed; it does
not recompute the digest from a payload, because the payload is not part of
the record. For `llm_request` records with a `content` block on v1.10, v1.11
and v1.12 it also recomputes the stored-content digests (§4.4); on v1.16 and v1.18
the `content` digests are hashed but not compared with the stored content.
It recomputes the asserted-claims digest (§4.5) for every v1.12 record and
every v1.14, v1.17 and v1.18 record that carries an identity, the
evaluation outcome digest (§4.7) for every v1.16 record and every v1.18
record that carries a trace, and the customer label digest (§4.9) for
every v1.18 record whose block's `source` is `asserted` and that stores a
`customer_id`.

### 4.4 LLM content attestation (v1.10, v1.11, v1.12, v1.16, v1.18)

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
v1.12, v1.16 and v1.18 `llm_request` record that carries a `content` block:

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

A v1.12, v1.16 or v1.18 record with no `content` block was sealed with no
capture policy. Its prompt and response are stored but not bound, as before
v1.10, and are not checked.

JCS follows RFC 8785: object keys sorted by UTF-16 code units, no
whitespace, strings escaped as in RFC 8785 §3.2.2.2, numbers in ECMAScript
form (`1.0` → `1`, `1e-7` → `1e-7`, `1e21` → `1e+21`). A plain sorted-keys
JSON dump differs on numbers and must not be used.

### 4.5 Sealed identity (v1.12, v1.14, v1.16, v1.17, v1.18)

A v1.12 record carries an `identity` block naming who called the proxy; a
v1.14, v1.16, v1.17 or v1.18 record carries it when the proxy resolved one:

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
v1.17 and v1.18 record that carries an identity, that `asserted_digest`
equals SHA-256(JCS(`asserted`)). A label rewritten after sealing leaves the
chain hash intact and fails this check. `verify-pack.py` does not run this
check on v1.16 records: their identity is hashed, but an `asserted` label
rewritten on a v1.16 record still verifies. The labels are claims a caller
made, never evidence of who it was; only the hashed fields record what the
proxy verified.

### 4.6 Decision receipts (v1.15)

After field 16, a v1.15 record feeds these fields of its `decision_receipt`
object:

| # | Field | Encoding |
|---|---|---|
| 17 | `receipt_id` | string |
| 18 | `receipt_type` | string |
| 19 | `receipt_type_version` | string |
| 20 | `registry_digest` | string |
| 21 | `source_kind` | string |
| 22 | `source_ref` | string |
| 23 | `subject_ref_sha256` | optional string |
| 24 | `evidence_set_sha256` | string |
| 25 | `policy_version` | optional string |
| 26 | `outcome` | string |
| 27 | `outcome_reason_code` | optional string |
| 28 | `outcome_reason_sha256` | optional string |
| 29 | `decider_user_id` | optional string |
| 30 | `decider_role` | optional string |
| 31 | `decider_identity_provenance` | optional string |
| 32 | `credential_status` | string |
| 33 | `credential_class` | optional string |
| 34 | `credential_registry` | optional string |
| 35 | `credential_verified_at` | optional i64 |
| 36 | `procedure_status` | string |
| 37 | `procedure_id` | optional string |
| 38 | `procedure_version` | optional string |
| 39 | `procedure_document_sha256` | optional string |
| 40 | `procedure_effective_at` | optional i64 |
| 41 | `clock_rule` | string |
| 42 | `clock_start_basis` | string |
| 43 | `clock_started_at` | i64, Unix seconds |
| 44 | `clock_deadline_at` | i64, Unix seconds |
| 45 | `clock_decided_at` | optional i64, Unix seconds |
| 46 | `clock_elapsed_seconds` | optional i64 |
| 47 | `clock_status` | string |
| 48 | `held_before_use` | optional bool: `0x00` if absent or null, else `0x01` then `0x01` (true) or `0x00` (false) |
| 49 | `supersedes_receipt_id` | optional string |
| 50 | `cp_anchor_event_id` | string |
| 51 | `cp_anchor_event_hash` | string |
| 52 | `issued_at` | i64, Unix seconds |

The object also stores `evidence`, a list of objects outside the preimage.
`evidence_set_sha256` binds it: the hex SHA-256 of the JCS form (§4.4) of
the list, with an absent list read as `[]`. Each entry names a chain record
by `chain_id`, `sequence_number`, `event_id` and `event_hash`; any other
member of an entry is covered by the digest only.

A verifier checks, for every v1.15 record:

1. `evidence_set_sha256` equals SHA-256(JCS(`evidence`)).
2. `outcome` is one of `approved`, `escalated`, `rejected`, `lapsed`, and
   the record's base `action` is `allow`, `hold`, `block` and `block`
   respectively.
3. When `outcome` is `lapsed`: `decider_user_id`, `clock_decided_at` and
   `clock_elapsed_seconds` are absent, and `clock_status` is `lapsed`.
4. Otherwise: `decider_user_id` and the three clock timestamps are present,
   `clock_elapsed_seconds` equals `clock_decided_at − clock_started_at`, and
   `clock_status` is `within` when `clock_decided_at ≤ clock_deadline_at`,
   else `breached`.
5. When `outcome` or `clock_status` is `lapsed`: `issued_at` and
   `clock_deadline_at` are present and `issued_at ≥ clock_deadline_at`.
6. When `credential_status` is `verified`: `credential_class`,
   `credential_registry` and `credential_verified_at` are present.
7. When `procedure_status` is `recorded`: `procedure_id` and
   `procedure_version` are present.

A record that fails any of these fails verification (exit 1), naming the
receipt and the field.

**Evidence in the pack.** The verifier also compares each `evidence` entry
with the pack. Records carry no chain id, so the pack's chain is read from
the manifest `prefix`: `audit/{chain}/` is `{chain}`, and the flat `audit/`
prefix matches an entry whose `chain_id` has the form
`chain_tnt_{proxy}_proxy`.

| Finding | Verdict |
|---|---|
| The entry names the pack's chain, and the pack holds a record at its `sequence_number` with the same `event_hash` and, when the entry has one, the same `event_id` | Pass |
| The entry names the pack's chain and the record at that sequence differs in `event_id` or `event_hash` | Fail (exit 1), naming the receipt, the entry and the field |
| The entry names no chain, or `proxy` or `shadow`, and the pack holds a record at its sequence with its `event_hash` | Checked as above |
| The cited record is a hash-only stub (§6.5) | Its `event_hash` is checked; a match prints a NOTE, a mismatch fails (exit 1) |
| The cited sequence is in the window but its record failed to read | Not checked; the record has already failed |
| Any other entry: another chain, or a record this pack does not hold | Pass, with `WARN receipt_evidence_outside_pack` naming the receipt, the entry and its coordinates |

`cp_anchor_event_id` and `cp_anchor_event_hash` name a record on the
control-plane chain. They are checked only when the pack carries that chain
(§6.3).

**Manifest index.** A manifest may carry `decision_receipts`, a list with
one entry per receipt record in the pack, each with exactly `sequence`,
`receipt_id`, `receipt_type` and `clock_status`. A pack that holds no
receipt carries no key.

| Finding | Verdict |
|---|---|
| No `decision_receipts` key, and the pack holds receipts | Pass, with a NOTE that the index is absent; the receipts are checked as records |
| Every receipt record listed once, each entry's fields equal to the sealed record's | Pass; one `RECEIPT seq=… type=… clock_status=… receipt_id=…` line per entry, then `RECEIPTS INDEX OK` |
| An entry with missing or extra fields, a non-integer `sequence`, or a sequence listed twice | Fail (exit 1) |
| An entry for a sequence that holds no receipt record, a field that differs from the sealed record, or a receipt record the index omits | Fail (exit 1) |

### 4.7 Evaluation trace (v1.16, v1.18)

A v1.16 `llm_request` record, and a v1.18 one that was evaluated, carries
an `evaluation_trace` object:

| Field | Hashed | Meaning |
|---|---|---|
| `outcomes_sha256_jcs` | yes | Hex SHA-256 over the JCS form (§4.4) of `outcomes` |
| `outcomes` | no, bound through `outcomes_sha256_jcs` | JSON object: the result of each rule evaluated on the request, the rule that decided, and how the response was delivered |
| `timing` | no, and not bound | Offsets and durations of the evaluation stages and rules, in microseconds |

The preimage holds only the digest. A verifier checks, for every v1.16
record and every v1.18 record that carries a trace, that `outcomes` is a
JSON object and that `outcomes_sha256_jcs` equals SHA-256(JCS(`outcomes`)).
It reads `outcomes` as an opaque object and does not check its members.

| Finding | Verdict |
|---|---|
| The digest matches the stored `outcomes` | Pass |
| The digest does not match | Fail (exit 1): `FAIL seq=<n>: evaluation outcomes do not match outcomes_sha256_jcs (the outcomes were changed after sealing)` |
| The trace has no `outcomes` object | Fail (exit 1) |
| A v1.16 record without `evaluation_trace` | Fail (exit 1) |
| An `evaluation_trace` on any other version or kind (§4.3) | Fail (exit 1) |
| A v1.18 record without `evaluation_trace` | Pass; there is nothing to check |
| `timing` changed after sealing | Not detected: `timing` is outside the hash and the digest |

### 4.8 Data reach (v1.17, v1.18)

A v1.17 record, and a v1.18 `mcp.policy_decision` at stage `tool_call` that
carries one, holds a `data_reach` object under `mcp_event`. It records
which declared data binding, if any, the tool call's arguments matched,
and the names (never the values) of the call's top-level arguments. Every
member is hashed, in this order:

| Field | Encoding | Rule |
|---|---|---|
| `binding_id` | string | `rb_` followed by 16 lowercase hex digits when `outcome` is `matched`; exactly `unbound` otherwise |
| `access` | optional string | `read` or `write`; present exactly when `outcome` is `matched` |
| `outcome` | string | `matched` (a binding matched), `no_match` (none did) or `error` (the bindings could not be evaluated) |
| `schema_known` | bool | A JSON boolean: whether the proxy held the tool's advertised input schema when it sealed the record |
| `arg_keys` | name list | Argument names present on the call and advertised by the tool: at most 32 names, each 1 to 64 characters (Unicode code points), strictly ascending by UTF-8 bytes, so no name repeats |
| `arg_keys_omitted` | u32 | A JSON integer from 0 to 4,294,967,295 (not a boolean): how many argument names were present but not sealed |

A name list feeds the count and then each name with its byte length, so two
names never hash like their concatenation.

| Finding | Verdict |
|---|---|
| A block that meets every rule above, on a record where §4.3 allows it | Pass |
| A block that breaks a rule above | Fail (exit 1) |
| A block on any other version, kind or stage (§4.3) | Fail (exit 1) |
| A v1.17 record without a block, or v1.17 on any other kind or stage | Fail (exit 1) |

### 4.9 Customer block (v1.18)

Every v1.18 record, on either lane, carries a top-level `customer` object.
All three members are in the preimage, in this order:

| Field | Hashed | Meaning |
|---|---|---|
| `label_sha256` | yes (optional string) | Lowercase hex SHA-256 over the UTF-8 bytes of the customer label; absent when `source` is `none` |
| `source` | yes | Where the label came from: `credential` (a credential the proxy verified bound the request to the label), `asserted` (the caller asserted the label) or `none` (no label) |
| `credential_kid` | yes (optional string) | Present exactly when `source` is `credential`: the key id of the credential that carried the label, or `iss:` followed by the issuer of a verified user token |

The record's top-level `customer_id`, when present, holds a label in the
clear. It is stored but not hashed. When `source` is `asserted`, it is
bound through `label_sha256`; under the other sources it is not compared.

A verifier checks, for every v1.18 record:

1. `source` is `credential`, `asserted` or `none`.
2. `label_sha256`, when present, is 64 lowercase hex characters.
3. Under `none`, neither `label_sha256` nor `credential_kid` is present.
4. Under `asserted`, `label_sha256` is present and `credential_kid` is not.
5. Under `credential`, `label_sha256` is present and `credential_kid` is a
   string that is not empty or all whitespace.
6. Under `asserted`, when the record stores a non-empty `customer_id`,
   `label_sha256` equals SHA-256(UTF-8 bytes of `customer_id`).

| Finding | Verdict |
|---|---|
| A block that meets checks 1 to 6 | Pass |
| A block that breaks one of checks 1 to 5 | Fail (exit 1) |
| `label_sha256` does not match the stored asserted label (check 6) | Fail (exit 1): `FAIL seq=<n>: customer.label_sha256 '<digest>' does not match the stored asserted label (recomputed '<digest>')`, followed by a note that the label was rewritten after sealing |
| Under `asserted`, no `customer_id` is stored (a content-stripped pack removes it) | Pass; there is nothing to compare |
| A v1.18 record without a `customer` block, a block on any other version, or v1.18 on any kind other than `llm_request` and the MCP kinds | Fail (exit 1) |

A label rewritten after sealing leaves the chain hash intact and fails
check 6.

## 5. Reference values

The verifier's self-test pins one fixture hash per version. Two of them,
useful for a from-scratch implementation:

- The v1 fixture (`--self-test` assertion 1) hashes to
  `ba7a7f3d…e031` (full value in `verify-pack.py`, `FIXTURE_HASH`).
- A `Z`-suffixed timestamp and its `+00:00` form produce the same hash
  (assertion 2); feeding the `Z` form unnormalized does not.
- The v1.15 decision receipt fixture (assertion 28a) hashes to
  `4e93ecd4…0682` (full value in `verify-pack.py`,
  `V1_15_DECISION_RECEIPT_FIXTURE_HASH`).
- `--self-test` assertions 32a to 32i verify a five-record content-stripped
  chain with one hash-only stub (§6.5), whose head hashes to `f6335bab…205a`.
  Assertions 33a to 33g exercise the
  condition-set verdict (§6.6) over a control-plane acceptance hashing to
  `d4a4d9c8…1ece` and a proxy chain whose head hashes to `f624f780…259d`.

## 6. Pack manifest

`manifest.json` (schema_version `"1.0"`, `"1.1"`, `"1.2"`, `"1.3"`, `"1.4"`
or `"1.5"`) describes one verification window of one chain, and, when it
carries a `control_plane` section, the control-plane chain stored in the same
bucket (§6.3). A manifest without `schema_version` reads as 1.0. Any other
value is cannot evaluate (exit 2).

```json
{
  "schema_version": "1.0" | "1.1" | "1.2" | "1.3" | "1.4" | "1.5",
  "pack_id": "<uuid>",
  "window": "A" | "B",
  "signing_deferred": true | false,
  "generated_at": "<RFC 3339>",
  "generator_version": "<string>",
  "substrate_name": "<string or null>",
  "evidence_class": "sandbox-non-production",   … required on 1.4, optional on 1.5, §6.4 …
  "content": "stripped",   … present on 1.5 only, §6.5 …
  "removed_fields": ["…"],   … present on 1.5 only, §6.5 …
  "stubs": [{"sequence": 3, "reason": "…", "field": "…"}],   … optional, on 1.5 only, §6.5 …
  "bucket": "<bucket name>",
  "prefix": "<chain prefix, ends with />",
  "storage_layout": "per-record" | "segmented-v1",   … required on 1.2, optional on 1.3 and later, §6.2 …
  "from_sequence": 0,
  "to_sequence": 27,
  "hash_algorithm": "SHA-256",
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
  "decision_receipts": [ … present when the pack holds decision receipts, §4.6 … ],
  "control_plane": { … required on 1.3, optional on 1.4 and 1.5, §6.3 … },
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
      "object": {"name": "<object name>", "index": 0}   … present on 1.2, and on 1.3 and later with storage_layout, §6.2 …
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
| Manifest 1.0, or 1.1 with `state: unanchored` and no anchors | Pass, with a prominent `UNANCHORED` notice |
| A listed anchor whose statement or token object is missing, or whose bytes differ from the manifest's SHA-256 | Fail (exit 1), naming the chain, the sequence and the reason |
| A statement that is not canonical, or does not name this chain at this sequence | Fail (exit 1) |
| The anchored `event_hash` differs from the record's recomputed hash, or from the hash the record stores | Fail (exit 1): the record changed after it was anchored |
| A token that does not verify, including a path that reaches no trusted root | Fail (exit 1), with the same reason code the proxy's verifier uses |
| An anchor found in the records directory or bucket that the manifest does not list | Verified like a listed one; a pass is reported as a NOTICE, a failure fails the pack |
| The manifest's `state`, `reason`, `anchored_through_seq` or `unanchored_tail` disagree with the anchors that verified | Fail (exit 1) |
| A listed seal that is not the `admin_action` record it claims to be | Fail (exit 1) |
| A record whose `timestamp_utc` is more than five minutes after the `genTime` of the earliest anchor covering it | Pass, with a `record clock ahead of anchor` notice; the token's `genTime` is the authoritative time |
| No trust root for a witness, an unparseable token, or a manifest `schema_version` this verifier does not know | Cannot evaluate (exit 2) |

A pass prints `ANCHORS OK: chain=<name> anchored_through=<seq>
witnesses=<verified>/<listed>`. An anchor shows that the covered records
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

### 6.3 Control-plane chain (manifest 1.3)

A 1.3 manifest carries, besides the chain it covers, the control-plane chain
of the same bucket: the control plane's record of human compliance actions.
It is a separate chain with its own record format and hash recipe
(`control-plane-v1`), and the same genesis as §2.

A 1.3 manifest is otherwise a 1.1 manifest, `anchoring` included.
`storage_layout` and each entry's `object` are as in 1.2 (§6.2) when the
covered chain is stored in segment objects, and absent when it is stored per
record. When `storage_layout` is present it is checked as in §6.2, and every
entry then needs its `object`; when it is absent, no entry is checked for
one. `storage_layout` describes the covered chain only: control-plane records
are always stored one per object.

**Objects.** Each control-plane record is one JSON object (UTF-8), stored in
the same bucket as the covered chain, under the fixed prefix
`control-plane/`:

```
control-plane/00000000000000000000.json
control-plane/00000000000000000001.json
…
```

The name is the record's sequence number, zero-padded to 20 digits, with a
`.json` suffix. The prefix does not depend on the manifest's `prefix`.
`verify-pack.py --bucket` reads these objects from the bucket it is given.
Offline, `--records DIR` reads them from `DIR/control-plane/{seq:020}.json`;
a `--records` path that is a single file holds no control-plane records, so
every listed record fails as unreadable. `--export-records DIR`, from `--bucket` or
from a `--records` directory, writes each control-plane record it reads to
`DIR/control-plane/{seq:020}.json`, byte-identical to the stored object; the
directory is created only when a control-plane record is read.

**Record.** A control-plane record (`schema_version` `"v1"`) carries:

| Field | Type | In the hash |
|---|---|---|
| `sequence_number` | integer | Fed directly (below) |
| `previous_hash` | string | Fed directly (below) |
| `actor_user_id` | string or null | Hashed |
| `correlation_id` | string or null | Hashed |
| `event_id` | string | Hashed |
| `event_kind` | string | Hashed |
| `occurred_at` | string | Hashed |
| `payload` | any JSON value, usually an object, or null | Hashed |
| `project_id` | string or null | Hashed |
| `schema_version` | string, `"v1"` | Hashed |
| `target_resource_id` | string or null | Hashed |
| `event_hash` | string | The result: lowercase hex SHA-256 |

Any other member is stored but not bound. `occurred_at` is hashed exactly as
stored, with no timestamp normalization (unlike §3). `event_kind` and
`payload` are hashed as stored; a verifier does not need to interpret them.

**Hash recipe (`control-plane-v1`).**

```
event_hash = hex(SHA-256( i64 LE sequence_number
                        || UTF-8 bytes of previous_hash
                        || UTF-8 bytes of canonical(H) ))
```

- `sequence_number` is fed as 8 bytes little-endian, two's complement. A
  value outside the signed 64-bit range has no preimage and fails
  verification.
- `previous_hash` is fed as the stored text (64 hex characters), not as the
  32 bytes it encodes.
- `H` is a JSON object with exactly the nine hashed members above
  (`actor_user_id`, `correlation_id`, `event_id`, `event_kind`,
  `occurred_at`, `payload`, `project_id`, `schema_version`,
  `target_resource_id`), each taken from the stored record. A member the
  record lacks is `null` in `H`, so absent and `null` hash the same.
- There are no separators and no length prefixes.

**Canonical JSON.** `canonical()` writes a value as follows:

- No whitespace anywhere.
- Object members are ordered by key, comparing keys as sequences of UTF-16
  code units. A key that starts with a character above U+FFFF (a surrogate
  pair, from 0xD800) therefore sorts before one that starts with a character
  from U+E000 to U+FFFF. This applies at every depth, `payload` included.
- Strings, keys included, escape only these characters: `"` as `\"`, `\` as
  `\\`, U+0008 as `\b`, U+000C as `\f`, U+000A as `\n`, U+000D as `\r`,
  U+0009 as `\t`, and every other character from U+0000 to U+001F as
  `\u00xx` with lowercase hex. Every other character, `/`, U+007F and
  non-ASCII included, is written as its UTF-8 bytes.
- `null`, `true` and `false` are written literally; arrays keep their order.
- **Numbers are copied verbatim** from the stored record: the number token
  exactly as it appears in the stored bytes (`1E-05`, `0.00001`, `42`,
  `9223372036854775807`). A verifier must not parse a number into a float or
  integer and re-format it: `1E-05` and `0.00001` are equal values with
  different tokens, and hash differently.

Only number tokens come from the stored bytes. Member order, whitespace and
string escapes are re-serialized by the rules above, so `verify-pack.py`
does not require the stored record itself to be canonical.

**Parsing.** A stored record is unreadable (a failure at its sequence) when
it is not UTF-8, is not JSON, is not a JSON object at the top level, has a
duplicate key in any object, or contains `NaN`, `Infinity` or `-Infinity`.
The hash cannot be recomputed (a failure at its sequence) when
`schema_version` is not `"v1"`, `sequence_number` is not a JSON integer token
(`-?[0-9]+`: `1.0` and `1e0` do not count), `previous_hash` is not a JSON
string, or a string holds an escaped unpaired surrogate that has no UTF-8
encoding.

**Linkage.** Record 0's `previous_hash` is the genesis hash,
`SHA-256("meilynx-genesis-v1")` (§2). Record n's `previous_hash` is record
n−1's `event_hash`. After a record that failed, the next record's
`previous_hash` may match any hash the pack attests for the failed one: its
stored `event_hash` (when it was readable), or its manifest entry's
`stored_event_hash` or `recomputed_event_hash`. When the pack attests none,
the link is not checked and the verifier prints a WARN; the pack has already
failed at the earlier record.

**Manifest section.**

```json
"control_plane": {
  "chain_family": "control-plane",
  "prefix": "control-plane/",
  "hash_algorithm": "SHA-256",
  "hash_version": "v1",
  "genesis_hash": "<hex>",
  "verified": true,
  "records_checked": 5,
  "first_sequence": 0,
  "last_sequence": 4,
  "break_at_sequence": null,
  "violation_kind": null,
  "events": [
    {
      "sequence": 0,
      "occurred_at": "…",
      "event_kind": "…",
      "event_id": "…",
      "project_id": "<uuid or null>",
      "stored_event_hash": "<hex>",
      "recomputed_event_hash": "<hex>",
      "hash_match": true,
      "previous_hash_match": true
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `chain_family` | Always `"control-plane"`. |
| `prefix` | Always `"control-plane/"`. |
| `hash_version` | The record `schema_version` the recipe reads: `"v1"`. |
| `genesis_hash` | Hex SHA-256 of `meilynx-genesis-v1`. |
| `events` | One entry per sequence from 0 to the last record listed, in order, with no gap. The chain is always listed from genesis, not as a window. |
| `events[].sequence` | The record's sequence number. |
| `events[].event_id` | The record's `event_id`; empty when the generator could not read the record. |
| `events[].stored_event_hash`, `events[].recomputed_event_hash` | The hash the record stores and the hash the generator recomputed. |
| `hash_algorithm`, `verified`, `records_checked`, `first_sequence`, `last_sequence`, `break_at_sequence`, `violation_kind`, `events[].occurred_at`, `events[].event_kind`, `events[].project_id`, `events[].hash_match`, `events[].previous_hash_match` | The generator's own summary. `violation_kind` is `missing_record`, `unreadable_record`, `sequence_mismatch`, `hash_mismatch` or `chain_break` for the first break, else `null`. `verify-pack.py` does not read these fields; it recomputes. |

The verifier reads exactly the sequences the section lists. A record written
after the last one listed is not part of the pack.

**What a verifier checks** (`verify-pack.py` does all of these), on top of
§1, §6, §6.1 and §6.2:

| Finding | Verdict |
|---|---|
| A 1.3 manifest with no `control_plane` section, or with `"control_plane": null` | Fail (exit 1): `FAIL control_plane: manifest 1.3 has no control_plane section` |
| A `control_plane` section on a 1.0, 1.1 or 1.2 manifest | Fail (exit 1) |
| A section that is not an object; `chain_family` other than `control-plane` or `prefix` other than `control-plane/`; `hash_version` other than `v1`; a `genesis_hash` that is not SHA-256 of `meilynx-genesis-v1`; `events` that is not a list, or whose `sequence` values are not 0, 1, 2, … in order | Fail (exit 1), `FAIL control_plane: <problem>`. No control-plane record is read and no receipt anchor is checked. |
| A section with an empty `events` list | Pass: `CONTROL-PLANE: the control-plane chain holds no records.` |
| A listed record that is missing or unreadable (see **Parsing**) | Fail (exit 1): `FAIL control-plane seq=<n>: record unreadable: <reason>` |
| A record whose hash cannot be recomputed (see **Parsing**), including a `schema_version` other than `v1` | Fail (exit 1) at that sequence |
| The record's `sequence_number` is not the entry's `sequence` | Fail (exit 1) at that sequence |
| The recomputed hash differs from the stored `event_hash` | Fail (exit 1): `hash mismatch` |
| The entry has a non-empty `recomputed_event_hash` that differs from the recomputed hash | Fail (exit 1) |
| The entry has a non-empty `event_id` that differs from the record's | Fail (exit 1) |
| The stored `previous_hash` does not link (see **Linkage**) | Fail (exit 1): `chain break` |
| A record after a failed one, when the pack attests no hash for the failed record | `WARN control-plane seq=<n>: … its chain link was not checked …`; the pack has already failed |
| Every listed record recomputes and links | Pass: one `PASS control-plane seq=<n> <event_kind> hash=<16 hex>... chain_ok` line per record, then `CONTROL-PLANE OK: <count> control-plane record(s) verified from genesis` |

All the problems with one record are reported on one `FAIL control-plane
seq=<n>:` line, separated by `; `. A failure at one record does not stop the
walk. Every control-plane finding is exit 1: an unknown control-plane
`hash_version` or record `schema_version` is a failure, not cannot evaluate.

**Decision-receipt anchors.** A v1.15 decision receipt carries
`cp_anchor_event_id` and `cp_anchor_event_hash`, both hashed in the
receipt's record: the `event_id` and `event_hash` of the control-plane record
the receipt is anchored to. When the manifest carries a well-formed
`control_plane` section, the verifier checks every record in the pack that
holds a `decision_receipt` object against the control-plane records it read,
matching `cp_anchor_event_id` to a record's `event_id`:

| Finding | Verdict |
|---|---|
| `cp_anchor_event_id` names a control-plane record in the pack that verified, and `cp_anchor_event_hash` equals its stored `event_hash` | Pass: `RECEIPT ANCHOR OK seq=<n> receipt=<receipt_id> control-plane seq=<m>` |
| `cp_anchor_event_id` names a control-plane record in the pack that verified, and `cp_anchor_event_hash` differs from its `event_hash` | Fail (exit 1): `FAIL receipt anchor: decision receipt <receipt_id>: cp_anchor_event_hash <16 hex>... is not the event_hash <16 hex>... of control-plane seq=<m> (<event_id>)` |
| `cp_anchor_event_id` names a control-plane record that failed above | `WARN seq=<n>: decision receipt <receipt_id> cites control-plane seq=<m>, which failed above, so its anchor was not checked.`; the pack has already failed |
| `cp_anchor_event_id` names no control-plane record in the pack (for example, an event after the last record the section lists), or is empty | `WARN receipt_anchor_outside_pack seq=<n> receipt=<receipt_id> cp_anchor_event_id=<id>: no record in this pack's control-plane chain has that event id.` The receipt still verifies as a record. |

`<n>` is the receipt record's sequence in the covered chain and `<m>` the
control-plane sequence. The `RECEIPT ANCHOR OK` lines are printed only when no
anchor fails. A manifest with no `control_plane` section (any 1.0, 1.1 or 1.2
manifest, and a 1.4 or 1.5 manifest without one) does not check receipt
anchors and prints nothing about them.

**Reference values.** `verify-pack.py --self-test` carries five
control-plane records that form one chain from genesis (assertions `cp1.0`
to `cp1.4`, full text in `verify-pack.py`). The first hashes to
`e8e8c864…24f4`. The third has `payload` keys that exercise the UTF-16 key
order and the string escapes; the fourth has number tokens such as `1E-05`,
`1E+20` and `9223372036854775807`. Assertion `cp3` rewrites `1E-05` to
`0.00001` in the fourth record and expects a hash mismatch there.

**Older verifiers.** A verifier that reads manifests up to 1.2 is cannot
evaluate (exit 2) on a 1.3 manifest. It never passes one without checking
the control-plane chain.

### 6.4 Evidence class (manifest 1.4)

A 1.4 manifest adds one required top-level field, `evidence_class`: a label
stating what kind of evidence the pack holds. Values:

| `evidence_class` | Meaning |
|---|---|
| `sandbox-non-production` | The records were sealed on a sandbox project, an evaluation tenant. They are not production evidence. |

The label is a member of `manifest.json`, so on a signed pack it is inside
the signed bytes (§7): changing it fails as `manifest bytes changed since
signing`. On an unsigned pack nothing authenticates it. The verifier does not
derive the label from the records; it reports what the manifest says.

A 1.4 manifest carries the 1.3 fields as in 1.3, each present only when the
pack has them: `storage_layout` and each entry's `object` when the covered
chain is segmented (§6.2), and `control_plane` when the pack carries the
control-plane chain (§6.3). Unlike 1.3, a 1.4 manifest without
`control_plane` (or with `"control_plane": null`) is valid, and then checks
no control-plane chain and no receipt anchor. `anchoring` is as in 1.1.

A 1.5 manifest carries `evidence_class` when the pack has one; it is
optional there and, when present, read as in 1.4.

**Output.** Before the records, the verifier prints
`EVIDENCE CLASS: <label> (<meaning>).` The final verdict line (`OK: …`,
`CHAIN OK, AUTHENTICITY NOT ESTABLISHED: …`, `FAIL: …` or
`CANNOT EVALUATE: …`) ends with ` [evidence class: <label>]`. A label is
never dropped from the output.

**What a verifier checks** (`verify-pack.py` does all of these), before
reading any record:

| Finding | Verdict |
|---|---|
| A 1.4 manifest whose `evidence_class` is a value this verifier reads | Read; printed as above |
| A 1.4 manifest with no `evidence_class`, or with `null` | Cannot evaluate (exit 2) |
| An `evidence_class` this verifier does not read, on 1.4 or 1.5 | Cannot evaluate (exit 2): `ERROR: manifest evidence_class '<label>' is not one this verifier reads (sandbox-non-production). Re-run with an updated verifier.` |
| An `evidence_class` member, of any value, on a 1.0, 1.1, 1.2 or 1.3 manifest | Cannot evaluate (exit 2): `ERROR: manifest <version> carries an evidence_class, which only 1.4 and 1.5 define` |

A verifier that reads manifests up to 1.3 is cannot evaluate (exit 2) on a
1.4 manifest, so a label is never silently ignored.

### 6.5 Content-stripped packs (manifest 1.5)

A content-stripped pack carries the chain's records with captured content and
personal identifiers removed. Each record keeps every field its hash covers,
so the chain still recomputes from genesis, and a record that sealed digests
of its content (§4.4, §4.5) is checked against those digests. A record that
cannot be stripped and still verify ships as a **hash-only stub**: its chain
coordinates and nothing of its body.

**Manifest.** A 1.5 manifest is a 1.4 manifest (`storage_layout` and
`control_plane` each present only when the pack has them) with three
additions, inside the bytes a signed pack signs:

```json
"schema_version": "1.5",
"content": "stripped",
"removed_fields": ["customer_id", "end_user_id", "identity.asserted", "messages",
                   "raw_request", "raw_response", "response_text", "tags_json", "tool_calls"],
"stubs": [{"sequence": 3, "reason": "sealed_personal_identifier", "field": "auth_session.user_email"}]
```

- `content`: `"stripped"`, the only value this format defines. Every 1.5
  manifest is content-stripped.
- `removed_fields`: the removed fields, as record paths (a dotted name is a
  member of a nested object). It must hold exactly the nine paths above, each
  once, in any order.
- `stubs`: optional. When present, a non-empty list of objects with exactly
  the members `sequence` (an integer that is the `sequence` of one of the
  manifest's `events`), `reason` and `field` (a non-empty string: the record
  path that forced the stub, or `record` for an unreadable record). Entries
  are in strictly increasing `sequence` order.

| `reason` | Printed as |
|---|---|
| `sealed_personal_identifier` | seals a personal identifier inside its hash |
| `email_address` | keeps an email address in a field its hash or a sealed digest covers |
| `unreadable_record` | does not parse |

`evidence_class` is optional on 1.5: when absent the pack carries no label,
and when present it is read exactly as on 1.4.

**Removed fields.** None of the nine is in the preimage of any record version
(§4), so removing them leaves every `event_hash` unchanged:

| Field | Hashed | What a full pack checks, and what a stripped pack checks instead |
|---|---|---|
| `messages` | no, bound through `stored_prompt_sha256_jcs` (v1.10 on) | The digest is inside the hash, which is recomputed; it is not re-derived |
| `response_text` | no, bound through `stored_response_sha256` (v1.10 on) | As `messages` |
| `tool_calls` | no, bound through `stored_tool_calls_sha256_jcs` (v1.11 on) | As `messages` |
| `identity.asserted` | no, bound through `asserted_digest` (§4.5) | `asserted_digest` is inside the hash; it is not re-derived. The `identity` block itself must still be present where its version requires it |
| `customer_id` | no | The stored label is absent, so it is not compared with a sealed label digest |
| `raw_request`, `raw_response`, `end_user_id`, `tags_json` | no, unbound | Nothing |

`findings` is kept. On a record whose `content` block carries
`findings_sha256_jcs`, a stripped pack is checked against it exactly as in
§4.4. Every other per-record check is unchanged.

**Withheld identifiers.** `auth_session.user_email` is in the preimage of a
v1.2 `auth.session_started` record (§4.3), so it cannot be removed without
breaking the hash. A record that holds it with a non-null value ships as a
hash-only stub with reason `sealed_personal_identifier`. A record that holds
an email address in another field its hash or a sealed digest covers ships as
a stub with reason `email_address`.

**Stubs.** A stub is a JSON object with at most the four members
`sequence_number`, `event_hash`, `previous_hash` and `schema_version`; the
first three are required. A verifier does not recompute a stub's hash (that
needs the body). It checks the stub against its coordinates: its
`sequence_number` is its own sequence, its `event_hash` equals the manifest
entry's `recomputed_event_hash` and `stored_event_hash` (each when present),
and its `previous_hash` links to the record before it (§2). On a signed pack
the stub's entry must carry `recomputed_event_hash`, as every entry must
(§7.1). The record after a stub links to the stub's `event_hash`. A record
shaped like a stub that `stubs` does not list is verified as a full record,
and fails.

**Other checks that cite a stub.** A decision receipt evidence entry that
cites a stub on this pack's chain is checked on its `event_hash` alone and,
when it matches, prints `NOTE seq=<n>: decision receipt <id> evidence[<i>]
(sequence=<s>) cites a hash-only stub`. A chain-head anchor (§6.1) whose head
is a stub, and a listed seal that is a stub, are compared with the stub's
`event_hash`, with a `NOTICE` saying so.

**Output.** Before the records, a stripped pack prints a line beginning
`CONTENT: stripped.` that names the removed fields and, when `stubs` is
present, `STUBS: <n> record(s) cannot be stripped and still verify, and ship
as hash-only stubs (sequence_number, event_hash, previous_hash,
schema_version; nothing of the body).` Each stub that passes prints:

```
STUB seq=<n> hash=<first 16 hex>... chain_ok: hash-only stub, <field> (<reason as printed>); body withheld, hash not recomputed
```

The final verdict line counts the stubs (`all <N> events verified, <k> of
them as hash-only stubs (linked, hash not recomputed)`), and every verdict
line ends with ` [content: stripped]`, or ` [content: stripped; <k> hash-only
stub]` (`stubs` for more than one) when the pack lists stubs. On a pack that
also carries `evidence_class`, its label comes first.

**Records source.** A stripped pack is verified from its own records
(`--records`). With `--bucket` the verifier would read the holder's full
records, which are not what the manifest describes, so it refuses and exits 2.

**What a verifier checks** (`verify-pack.py` does all of these):

| Finding | Verdict |
|---|---|
| A stripped chain whose records recompute and link, with every stub matching its signed entry and linking | Pass, with a `STUB` line for each stub and the stub count on the verdict |
| `content`, `removed_fields` or `stubs` on a manifest before 1.5 | Cannot evaluate (exit 2) |
| A 1.5 manifest whose `content` is not `stripped`, or whose `removed_fields` is not exactly the nine paths, each once | Cannot evaluate (exit 2) |
| A `stubs` list that is empty, has an entry with other members, a `sequence` not among the manifest's events or out of order or repeated, or a `reason` not in the table above | Cannot evaluate (exit 2) |
| A record (stub or not) that carries a removed field (present, even as `null`), or a non-null `auth_session.user_email` | Cannot evaluate (exit 2), with `CANNOT EVALUATE seq=<n>: the manifest says content stripped, and the record carries <path>`, when nothing else failed; a failure elsewhere still exits 1 |
| `findings` that do not match `findings_sha256_jcs` | Fail (exit 1) |
| A stub with members beyond the four, without `sequence_number`, `event_hash` or `previous_hash`, with another `sequence_number`, or with an `event_hash` that is not the manifest entry's | Fail (exit 1): `FAIL seq=<n>: hash-only stub (<field>): <reasons>` |
| A stub whose `previous_hash` does not link to the record before it | Fail (exit 1): `chain break` in the same line |
| A stub on a signed pack whose manifest entry has no `recomputed_event_hash` | Fail (exit 1) |
| A stub with reason `unreadable_record` | Fail (exit 1): nothing in the pack attests its hash |
| A stub after a record that failed, when nothing in the pack attests that record's hash | Pass on the stub's own checks, with `WARN seq=<n>: hash-only stub ... chain link ... was not checked` |
| Decision receipt evidence citing a stub, with the stub's `event_hash` | Pass, with the `NOTE` above (the stub's `event_id` is not in the pack) |
| Decision receipt evidence citing a stub, with another `event_hash` | Fail (exit 1) |
| A stripped pack given with `--bucket` | Cannot evaluate (exit 2) |

### 6.6 Condition-set verdict

`--conditions-sha256 HEX` adds one verdict over a condition set the evidence
holder accepted. `HEX` is the set's SHA-256 as 64 lowercase hex characters;
anything else is a usage error (exit 2). Without the flag nothing below is
printed.

**Acceptance.** The verdict starts from a control-plane record of
`event_kind` `exchange.conditions_accepted`. The verifier reads:

| Field | Use |
|---|---|
| `payload.conditions_sha256` | Equals `HEX` |
| `occurred_at` | RFC 3339; the window starts here |
| `payload.relationship_id` | A UUID. Its first 12 hex digits (dashes removed, lowercase) give the set's instance suffix `cust_<12 hex>`; a rule instance of the set has an id ending in `@cust_<12 hex>` |
| `payload.compiled_governance_sha256` | The compiled governance version, compared with a model request's `policy_version` |
| `payload.compiled_mcp_sha256` | The compiled MCP bundle, compared with an MCP record's `mcp_event.mcp_bundle_sha256` |

At least one of the two compiled digests must be 64 lowercase hex.

In the pack's control-plane chain, the acceptance is the last
`exchange.conditions_accepted` record whose `payload.conditions_sha256` is
`HEX`, and it must have verified. The window ends at the `occurred_at` of the
first later record that is either `exchange.conditions_released` with the
same `payload.conditions_sha256`, or `exchange.conditions_accepted` with
another `payload.conditions_sha256` and the same `payload.relationship_id`.

A pack whose manifest has no `control_plane` section does not carry the
acceptance. `--conditions-acceptance FILE` then supplies the stored record
(the bytes of `control-plane/<seq:020d>.json`); it requires
`--conditions-sha256`, and a file that does not parse as a control-plane
record is a usage error (exit 2). Its `event_hash` is recomputed under the
control-plane recipe (§6.3); its link into the chain is not in the pack, and the
verdict says so. A supplied acceptance has no window end. When the pack's
chain holds the acceptance, `--conditions-acceptance` is not used.

**Window.** The window is the records the chain walk read (stubs excluded) of
kind `llm_request` (`event_kind` absent or `llm_request`) or any `mcp_*`
kind, whose `timestamp_utc` is at or after the acceptance's `occurred_at` and
before the window end, compared at microsecond precision. T is the number of
records in the window. A record counts toward M only by sealed evidence:

| Record | Counts toward M when | Otherwise |
|---|---|---|
| MCP | `mcp_event.mcp_bundle_sha256` (hashed) equals `compiled_mcp_sha256` | GAP |
| Model request | It is v1.16 or v1.18 and an `evaluation_trace.outcomes.rules[].rule_id` (bound by `outcomes_sha256_jcs`) ends in `@cust_<12 hex>` | NOTE when `policy_version` (not hashed) equals `compiled_governance_sha256`, never counted; GAP otherwise |

**Exceptions.** In each window record, every item whose id ends in
`@cust_<12 hex>` is an exception. An id of the form `cust_<12 hex>.…`, with no
`@`, is not an instance and is not an exception. E is the number of distinct
records with at least one exception.

| Item | Printed binding |
|---|---|
| `findings[].validator` | `bound by content.findings_sha256_jcs` when the record's `content.findings_sha256_jcs` is present, else `stored, not hashed` |
| `evaluation_trace.outcomes.deciding_rule_id` (v1.16, v1.18) | `bound by evaluation_trace.outcomes_sha256_jcs` |
| `mcp_event.finding_summary[].rule_id` or `.detector` | `stored, not hashed` |

**Output.** After the pack's records:

```
CONDITIONS: set <HEX>
CONDITIONS: accepted at control-plane seq <N>, <occurred_at>: relationship <id>, instances cust_<12 hex>, compiled governance <16 hex>..., compiled MCP bundle <16 hex>...
GAP seq=<n> hash=<16 hex>...: sealed under governance|MCP bundle <16 hex or none>..., not the compiled <16 hex or none>...
NOTE: <k> model request(s) in the window (seq <list>) name the compiled governance version only in policy_version, which their hash does not cover; they are not counted as sealed.
EXCEPTION seq=<n> hash=<16 hex>...: <item> (<binding>)
conditions: set <HEX> accepted at seq <N>; <M> of <T> records in the window sealed under a governance version carrying it; <E> exceptions; compiled by the holder's control plane
```

The verdict line ends with the pack's verdict labels (§6.5). A content-stripped
pack with stubs also prints `NOTE: <k> hash-only stub(s) (seq <list>) carry no
timestamp, kind or findings, ...`; stubs are not placed in the window. The
verdict does not check that the compiled bundles implement the set: the pack
carries bundle digests, not bundles. The line's last clause says so.

With no acceptance, the verifier prints `CANNOT EVALUATE conditions: <why>.`,
an `INSTANCE seq=<n>: ...` line for each record in the pack that names any
`@cust_` instance, and:

```
conditions: set <HEX> <why>; <G> records in the pack not checked against a compiled version; <K> records name a customer-condition instance; compiled by the holder's control plane
```

`<why>` is `acceptance not in this pack` when the pack has no control-plane
chain, and `this pack's control-plane chain holds no acceptance of the set`
when it has one.

| Finding | Verdict |
|---|---|
| An acceptance that verified, read whatever M, T and E are | Pass: GAP, NOTE and EXCEPTION lines do not change the exit code |
| No acceptance in the pack and none supplied | Cannot evaluate (exit 2) |
| The pack's acceptance is in a control-plane chain that did not verify | Fail (exit 1): `FAIL conditions: the acceptance at control-plane seq=<N> did not verify` |
| The pack's acceptance lacks a UUID `relationship_id`, a timestamp `occurred_at` or both compiled digests | Cannot evaluate (exit 2), printed as `FAIL conditions: the acceptance ... is not usable: <reason>` |
| A supplied acceptance that cannot be recomputed, does not recompute to its `event_hash`, or differs from the record of the same `event_id` in the pack's chain | Fail (exit 1) |
| A supplied record that is not `exchange.conditions_accepted`, accepts another set, or lacks a field above | Fail (exit 1): `FAIL conditions: the acceptance ... is not usable: <reason>` |
| A pack whose records were not read (cannot evaluate before the walk) | Cannot evaluate (exit 2) |

The verdict's code combines with the pack's by the same precedence (1
outranks 2, which outranks 3).

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
9. The certificate's Fulcio issuer extension (OID `1.3.6.1.4.1.57264.1.8`,
   falling back to `.1.1`) equals the expected issuer exactly, and one of its
   subjectAltName values equals the expected identity exactly. Which
   subjectAltName values count depends on the certificate's issuer: for
   `https://accounts.google.com`, email (rfc822Name) values only, so a URI
   value holding the same text does not match; for any other issuer, URI and
   email values. Meilynx packs are signed by one of two signers:
   - **The Meilynx signing workflow**, the default when the reader passes no
     `--certificate-identity`:
     - identity `https://github.com/Meilynx/meilynx-proxy/.github/workflows/integrity-pack-signed.yml@refs/heads/main`
     - OIDC issuer `https://token.actions.githubusercontent.com`
   - **A per-tenant signer**: a pack exported for one project may instead be
     signed by that project's own signer, a Google service account:
     - identity `<name>@<project>.iam.gserviceaccount.com`, as an email
       subjectAltName
     - OIDC issuer `https://accounts.google.com`

   A per-tenant signer has no default and no pattern. The reader passes the
   exact email the evidence holder published for the project with
   `--certificate-identity`. When that value contains `@` and no `://`, and
   `--certificate-oidc-issuer` is not given, the expected issuer is
   `https://accounts.google.com`; otherwise it is the workflow's issuer, or
   the one given. A certificate whose issuer is `https://accounts.google.com`,
   checked without `--certificate-identity`, is cannot evaluate (exit 2) once
   checks 1 to 8 pass, never a pass: nothing in the pack can say which
   service account is the right one. The verifier prints the email the
   certificate names, for the reader to compare with the published one. A
   per-tenant certificate checked against any other identity, including the
   workflow identity passed explicitly, fails with `signer identity
   mismatch`; against any other issuer, with `OIDC issuer mismatch`.

   With a per-tenant identity the verifier prints
   `NOTE: expecting the per-tenant signer <identity> (--certificate-identity), issuer https://accounts.google.com. …`
   before the check, and on success
   `SIGNATURE OK: manifest.json is signed by <identity> (per-tenant signer, the identity you supplied)`.
   Without one, it prints
   `ERROR: this pack is signed by a per-tenant signer (<email>, issuer https://accounts.google.com). …`
   and exits 2.

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
| 2 | Cannot evaluate: unsupported hash version, signature method or bundle format, unusable trust anchors, or a pack signed by a per-tenant signer (§7.2 item 9) checked without `--certificate-identity`. |
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

For a pack signed by a per-tenant signer, pass the service-account email the
evidence holder published as `--certificate-identity` and
`https://accounts.google.com` as `--certificate-oidc-issuer`.

The signature attests who produced the manifest and that it has not changed
since; the chain hashes attest the records.

## 8. What the chain does not cover

- **Completeness.** The chain proves that the records it contains are intact
  and in order. It cannot show that an interaction which never reached the
  proxy was recorded. A chain whose objects stop before the last record its
  writer sealed (truncation, §1) verifies on the records present; the
  shortfall is not an integrity failure, and this verifier does not report
  it.
- **Unhashed fields.** For LLM records before v1.10, `messages`,
  `response_text`, `findings`, `raw_request`, `raw_response` and routing
  metadata are stored in the record but not in the preimage. From v1.10 the
  prompt, response and findings are bound through their digests (§4.4), and
  from v1.11 the response's tool calls too, on records sealed under a
  capture policy; `raw_request`, `raw_response` and routing metadata remain
  unbound. On v1.16 and v1.18 records those digests are hashed, but this
  verifier does not compare them with the stored content. For MCP records
  the payload is bound through its digest fields. On v1.12 records, and on
  v1.14, v1.17 and v1.18 records that carry an identity, the caller's
  asserted labels are bound through `asserted_digest` (§4.5); on v1.16
  records `asserted_digest` is hashed but this verifier does not recompute
  it. The principal chain's `on_behalf_of_attestation` marker is stored but
  not hashed; the hashed `delegated_human` must agree with it. On v1.15
  records the `evidence` list is stored but not hashed;
  `evidence_set_sha256` binds it (§4.6). On v1.16
  and v1.18 records `evaluation_trace.outcomes` is bound through
  `outcomes_sha256_jcs` (§4.7), and `evaluation_trace.timing` is stored but
  neither hashed nor bound. Every member of a `data_reach` block (v1.17,
  v1.18) is hashed (§4.8). `customer_id` is not hashed on any version; on a
  v1.18 record whose `customer.source` is `asserted` it is bound through
  `customer.label_sha256` (§4.9), and otherwise it is unbound.
- **Removed content.** A content-stripped pack (§6.5) shows that each record's
  sealed digests are intact, not the content they were sealed over. A
  hash-only stub's `event_hash` is taken from the signed manifest, not
  recomputed: the pack shows where that record sits in the chain, not what it
  held.
- **Whether a detector missed something.** Under `redacted`, only spans a
  detector located are masked. The stored copy can still contain sensitive
  text no detector recognized.
- **Authorship of the chain.** Only a signed pack (§7) binds an identity to
  a window.
- **When a record was written.** `timestamp_utc` is hashed, but it comes from
  the proxy's clock and nothing in the chain shows that clock was right. A
  chain-head anchor (§6.1) shows that a record existed no later than the
  witness's `genTime`, and the verifier flags a record clock that runs ahead
  of its anchor. A pack without anchors shows nothing about time, and says
  so with an `UNANCHORED` notice.
- **The rest of an OCSF export.** The export check (§9) binds an exported
  event's chain coordinates and digests to the pack record. The event's other
  fields are derived from the record and are not compared with it. A pack
  record with no exported event is not reported, and a missing range is
  reported only between two manifests of one chain (`export_gap`).

## 9. OCSF evidence export

A proxy can also write its sealed records to an object store as OCSF events.
The export is a copy of the chain, not the chain. A verifier checks it
against a pack (§6) whose records it has read, and every finding below is
relative to that pack. The verifier cannot recompute an event hash from the
export alone: an exported event does not carry the fields the preimage (§4)
needs. It checks the export against the pack.

`verify-pack.py` checks an export when given `--ocsf-export PATH` together
with the pack (`--manifest` and `--records` or `--bucket`), and checks the
manifest signatures when also given `--ocsf-public-key JWK`.

### 9.1 Objects

Each export object comes with a manifest and, when the proxy holds an export
signing key, a detached signature. They sit in one directory per chain and
UTC day, under the export root:

```
ocsf/v1/<proxy id>/<chain>/<yyyy>/<mm>/<dd>/<first:020>-<last:020>.ndjson.gz
ocsf/v1/<proxy id>/<chain>/<yyyy>/<mm>/<dd>/<first:020>-<last:020>.ndjson.gz.manifest.json
ocsf/v1/<proxy id>/<chain>/<yyyy>/<mm>/<dd>/<first:020>-<last:020>.ndjson.gz.manifest.sig
ocsf/v1/<proxy id>/<chain>/<yyyy>/<mm>/<dd>/index.json
```

| Object | Content |
|---|---|
| `{first:020}-{last:020}.ndjson.gz` | A gzip stream of NDJSON: one OCSF event per line, UTF-8, each line followed by a line feed. `first` and `last` are the first and last sequence numbers of the records it holds. A record can produce more than one event; each event carries that record's chain coordinates. |
| `<object>.manifest.json` | The manifest (§9.2), stored as its RFC 8785 (JCS) bytes |
| `<object>.manifest.sig` | The detached manifest signature (§9.4). Present only when the manifest says `signed: true`. |
| `index.json` | The manifests written that day: a JSON object whose `manifests` member lists their keys, relative to the export root (`ocsf/v1/...`). Its other members are not read. |

The verifier does not parse these names. It finds a manifest's object and
signature beside the manifest file: the object by the final path component of
the manifest's `object` field, and the signature by the manifest's file name
with `.manifest.json` replaced by `.manifest.sig`.

### 9.2 Manifest

```json
{
  "export_id": "<string>",
  "proxy_external_id": "<string>",
  "chain_id": "<chain name>",
  "first_sequence": 0,
  "last_sequence": 41,
  "record_count": 42,
  "event_count": 44,
  "object": "ocsf/v1/<proxy id>/<chain>/2026/10/11/00000000000000000000-00000000000000000041.ndjson.gz",
  "object_sha256": "<hex>",
  "ocsf_version": "1.5.0",
  "semconv_version": "<string>",
  "mapping_version": "1",
  "generated_at": "<RFC 3339>",
  "proxy_version": "<string>",
  "image_digest": "<string or null>",
  "chain_head": {"sequence": 41},
  "last_record": {"sequence": 41, "event_id": "<string>", "event_hash": "<hex or null>"},
  "anchor": null,
  "signed": true,
  "public_key_id": "<string or null>"
}
```

The verifier reads these fields:

| Field | Type | What the verifier does with it |
|---|---|---|
| `mapping_version` | string | Must be `"1"`. Any other value makes that manifest cannot evaluate; nothing else in it is checked. |
| `chain_id` | string | The chain name. Every event in the object must name it; it is matched against the pack's chain (§9.5). |
| `first_sequence`, `last_sequence` | integer | The sequence range the object holds. A value that is not an integer fails. |
| `record_count` | integer | Must equal the number of distinct sequence numbers in the object. |
| `event_count` | integer | Must equal the number of events (non-blank lines) in the object. |
| `object` | string | The object's key relative to the export root. The object is read beside the manifest, by this key's final path component. The verifier's output names a manifest by this value. |
| `object_sha256` | string | Lowercase hex SHA-256 of the object's bytes (the gzip stream). |
| `signed` | boolean | Whether a `.manifest.sig` must be present and is checked (§9.4). |
| `public_key_id` | string or null | Printed with the signature result. Not matched against the key. |

The other fields are stored and covered by the signature, but the verifier
does not check them.

### 9.3 Locating the export

`PATH` is one of:

- a file named `index.json`: each key in its `manifests` list is resolved
  against the index's directory and then each of its ancestors, and the
  first existing file is the manifest. A key that resolves nowhere is read as
  the file of the key's final path component in the index's directory.
- a directory: every file named `*.manifest.json` beneath it, at any depth.
- any other file: read as one manifest.

Manifests are checked in order of `chain_id`, then `first_sequence`.

### 9.4 Manifest signature

The signature file holds the standard base64 encoding (RFC 4648 §4) of 64
bytes: `r || s`, each a 32-byte big-endian integer. Whitespace around it is
ignored. It is an ECDSA P-256 signature over the SHA-256 of the manifest
file's exact bytes, as read: the verifier does not canonicalize them again.
A signature that is not valid base64, does not decode to 64 bytes, or has `r`
or `s` outside `[1, n − 1]` does not verify. High-`s` signatures are
accepted.

`--ocsf-public-key` names a file holding one JSON Web Key:

```json
{"kty": "EC", "crv": "P-256", "x": "<base64url>", "y": "<base64url>"}
```

`x` and `y` are the big-endian affine coordinates, base64url with or without
padding. The point must be on P-256. Other members are ignored. The one key
checks every manifest given.

| Finding | Verdict |
|---|---|
| `signed` is `true` and the signature verifies | Pass: `OK   <object>: manifest signature verified (key id <public_key_id>)` |
| `signed` is `true` and the signature does not verify under the given key | Fail (exit 1): `FAIL <object>: manifest signature does not verify under the given key` |
| `signed` is `true` and the `.manifest.sig` file is missing | Fail (exit 1): `FAIL <object>: manifest says it is signed but <file> is missing` |
| `signed` is `true` and no `--ocsf-public-key` was given | Unsigned (exit 3): `UNSIGNED-CHECK <object>: ...; authenticity not established` |
| `signed` is `false` or absent | Unsigned (exit 3): `UNSIGNED <object>: manifest carries no signature; authenticity not established` |

A `.manifest.sig` beside a manifest that says `signed: false` is not read.

### 9.5 Object and event checks

For each manifest with a supported `mapping_version` and integer
`first_sequence` and `last_sequence`, the verifier reads the object:

1. The object exists beside the manifest, and its SHA-256 equals
   `object_sha256`.
2. It decompresses as gzip and decodes as UTF-8. Its text is split on line
   feeds, and lines holding only whitespace are dropped. Each remaining line
   is one event; `line <n>` in the output counts these lines from 1.
3. The number of events equals `event_count`.

A failure at step 1 or 2 fails the manifest and skips its events.

Each event is a JSON object. The verifier reads two members of its `meilynx`
object, `chain` and `digests`:

1. `meilynx.chain.chain_id` equals the manifest's `chain_id`, and
   `meilynx.chain.sequence_number` is an integer within
   `[first_sequence, last_sequence]`. Otherwise the event fails. An event
   with no `meilynx.chain` fails here.
2. If the manifest's `chain_id` is not the pack's chain, or the pack does not
   hold the record at that sequence, the event is counted as outside the
   pack and not checked further.
3. Otherwise each of these must equal the pack record at that sequence:

| Exported event field | Pack record field |
|---|---|
| `meilynx.chain.event_id` | `event_id` |
| `meilynx.chain.event_hash` | `event_hash` |
| `meilynx.chain.previous_hash` (only when present and not null) | `previous_hash` |
| `meilynx.digests.prompt_sha256_jcs` | `content.prompt_sha256_jcs` |
| `meilynx.digests.response_sha256` | `content.response_sha256` |
| `meilynx.digests.stored_prompt_sha256_jcs` | `content.stored_prompt_sha256_jcs` |
| `meilynx.digests.stored_response_sha256` | `content.stored_response_sha256` |
| `meilynx.digests.findings_sha256_jcs` | `content.findings_sha256_jcs` |
| `meilynx.digests.tool_calls_sha256_jcs` | `content.tool_calls_sha256_jcs` |
| `meilynx.digests.stored_tool_calls_sha256_jcs` | `content.stored_tool_calls_sha256_jcs` |
| `meilynx.digests.payload_sha256_jcs` | `mcp_event.payload_sha256_jcs` |
| `meilynx.digests.redacted_payload_sha256_jcs` | `mcp_event.redacted_payload_sha256_jcs` |
| `meilynx.digests.redaction_pre_sha256_jcs` | `mcp_event.redaction_pre_sha256_jcs` |
| `meilynx.digests.redaction_post_sha256_jcs` | `mcp_event.redaction_post_sha256_jcs` |
| `meilynx.digests.mcp_bundle_sha256` | `mcp_event.mcp_bundle_sha256` |
| `meilynx.digests.evidence_set_sha256` | `decision_receipt.evidence_set_sha256` |
| `meilynx.digests.registry_digest` | `decision_receipt.registry_digest` |
| `meilynx.digests.outcomes_sha256_jcs` | `evaluation_trace.outcomes_sha256_jcs` |
| `meilynx.digests.asserted_digest` | `identity.asserted_digest` |

A digest whose value is null is skipped. A non-null digest under any other
name fails, as does one whose record has no such block or field. The
comparison is with the pack record's stored values; the pack's own check
(§2, §4) binds those to the record bytes.

After the events, the number of distinct sequence numbers among the events
that passed step 1 must equal `record_count`, and the lowest and highest
must equal `first_sequence` and `last_sequence`.

No other member of an event is checked: its OCSF class and activity fields,
its time, the remaining members of `meilynx.chain`, and everything else it
carries are not compared with the record.

**The pack's chain.** The pack's chain is the one its manifest `prefix`
names: `audit/<chain>/` is `<chain>`, and `audit/` is `legacy-flat`. The
pack holds a sequence when the manifest lists it and the verifier read and
parsed its record. A hash-only stub is not held for this check.

### 9.6 Gaps between manifests

Per `chain_id`, in the order of §9.3, each manifest's `first_sequence` is
compared with the highest `last_sequence` of the manifests before it:

- higher by more than 1: `WARN export_gap chain=<chain>: sequences <a>..<b>
  have no export manifest between the previous object and <object>`;
- equal or lower: `WARN export_overlap chain=<chain>: <object> starts at
  <first>, below the previous object's last sequence <last>`.

A manifest skipped for its `mapping_version` or a non-integer range takes no
part in this check. Nothing is reported before the first manifest given or
after the last, and the range is not compared with the pack's window.

### 9.7 Verdicts

| Finding | Verdict |
|---|---|
| Every event checked matches the pack, every object matches its manifest, and every manifest is signed and verifies | Pass |
| An event on another chain than the pack's, or on a sequence the pack does not hold | Pass, with one `WARN export_record_outside_pack: <n> exported event(s) ...` line counting them; those events are not checked |
| A gap between consecutive manifests of one chain | Pass, with `WARN export_gap chain=<chain>: sequences <a>..<b> ...` |
| A manifest that starts at or below the previous one's last sequence | Pass, with `WARN export_overlap chain=<chain>: ...` |
| `PATH` names no manifest (an empty directory, or an `index.json` with no `manifests`) | `WARN: no OCSF export manifest found`; nothing is checked, and the export counts as unsigned (exit 3) |
| A manifest unsigned, or signed with no `--ocsf-public-key` given | Unsigned (exit 3), after the checks above pass |
| A missing object, an `object_sha256` mismatch, or an object that is not gzip UTF-8 | Fail (exit 1): `FAIL <object>: ...` |
| An `event_count` or `record_count` mismatch, an object whose sequences span other than `first_sequence..last_sequence`, or a non-integer `first_sequence` or `last_sequence` | Fail (exit 1): `FAIL <object>: ...` |
| A line that is not JSON, names another chain than its manifest, or has a sequence outside the manifest's range | Fail (exit 1): `FAIL <object> line <n>: ...` |
| An event whose chain coordinates or a digest differ from the pack record, or that carries a digest the verifier does not know | Fail (exit 1): `FAIL <object> line <n> seq=<seq>: <field> ...`, one line per field |
| A manifest signature that does not verify, or a `.manifest.sig` missing where `signed` is `true` | Fail (exit 1) |
| A `mapping_version` other than `"1"` | Cannot evaluate (exit 2): `CANNOT EVALUATE <object>: ocsf mapping_version ...` |
| `PATH` missing, a listed manifest missing or not JSON, `index.json` whose `manifests` is not a list, or an unusable `--ocsf-public-key` | Cannot evaluate (exit 2): `ERROR: unusable --ocsf-export / --ocsf-public-key (...)` |
| The pack's records cannot be evaluated | Cannot evaluate (exit 2): the export is not checked |

The export's verdict follows the pack's rule (§7.3): 1 if a content or
signature check failed, else 2 if a manifest could not be evaluated, else 3
if a manifest is unsigned or its signature was not checked, else 0.
`--allow-unsigned` accepts an unsigned export as it accepts an unsigned pack.
The process exits with whichever of the pack's code and the export's code
ranks higher, 1 over 2 over 3 over 0. An export is still checked when the
pack's records fail, against the records as read.

The verifier prints `OCSF export: <n> event(s) checked against the pack
across <m> manifest(s).` and then one of:

- `FAIL: the OCSF export does not match the pack (see above).`
- `FAIL: an OCSF export manifest signature did not verify (see above).`
- `OCSF EXPORT OK, AUTHENTICITY NOT ESTABLISHED: the export matches the pack,
  but a manifest is unsigned or its key was not given.`
- `OK: the OCSF export matches the pack and its manifests are signed.`, or
  `OK: the OCSF export matches the pack.` when an unsigned export is accepted
  with `--allow-unsigned`.

An export that passes shows that each exported event names a record the pack
holds and carries that record's `event_id`, `event_hash` and digests. With a
verified signature, it also shows that each manifest and object is the one
the key's holder wrote.
