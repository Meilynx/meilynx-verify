# Changelog

## 0.9.1 (2026-10-20)

- `verify-pack.py` from meilynx-proxy `1e5eb4d`.
- Anchoring is reported as one status line next to the other results:
  `ANCHORS OK: verified through seq=N, a/b witnesses` (with `; seq=A..B not
  yet anchored` for an unanchored tail) or `ANCHORS: none`. A seal is named
  on the same line. The separate `UNANCHORED` notice, the seal notice and the
  note on what an anchor shows are no longer printed; SPEC §6.1 describes
  what an anchor shows.
- The record-clock notice reads `NOTICE: N record(s) carry a timestamp more
  than 5 min after the anchor covering them (first seq=…)`.
- Exit codes and verdicts are unchanged. A script that matched
  `ANCHORS OK: chain=… anchored_through=…` should match the new line.

## 0.9.0 (2026-10-19)

- `verify-pack.py` from meilynx-proxy `647bb71`.
- **Upgrade before verifying chains or packs written after this release.**
  A verifier older than 0.9.0 stops at the first `decision_receipt` record
  with `unknown schema_version 'v1.15'` (and likewise at the first v1.16,
  v1.17 or v1.18 record), and exits 2 on a 1.3, 1.4 or 1.5 manifest. It
  never reports such a chain as a pass.
- Chain v1.15 (SPEC §4.3): a new record kind, `decision_receipt`, sealed
  when a decision on a held call or a reviewed item is recorded. The v1.2
  prefix, the kind attestation `decision.receipt`, then 36 receipt fields in
  the order §4.3 lists (52 fields). The stored `evidence` list is outside the
  preimage and bound by `evidence_set_sha256`, which the verifier recomputes
  (RFC 8785). The verifier also checks the sealed clock arithmetic against
  the timestamps, that a lapse was issued no earlier than its deadline, the
  decider rule, the completeness of a `verified` credential and a `recorded`
  procedure, and that the base `action` is the outcome's projection.
  Each evidence entry that cites a record in the pack must carry that
  record's `event_id` and `event_hash`; one outside the pack is `WARN
  receipt_evidence_outside_pack`. The manifest's `decision_receipts` index
  (SPEC §6.4) must list every receipt in the pack, nothing else, field for
  field. `decision_receipt` on any other version, or v1.15 on any
  other kind, fails verification.
- Chain v1.16 (SPEC §4.3): an `llm_request` record the governance pipeline
  evaluated carries an `evaluation_trace`: which rules ran, what each
  decided, and how the response reached the caller. The preimage is the
  v1.12 layout with the identity block presence-tagged, then
  `outcomes_sha256_jcs`; the stored outcomes are bound by that digest, which
  the verifier recomputes (RFC 8785). Timing is stored but not hashed. A
  trace on any other version (v1.18 aside), or v1.16 without one, fails
  verification. A v1.16 record's stored prompt, response, findings
  and tool calls are re-derived from its content digests as on v1.12.
- Chain v1.17 (SPEC §4.3, §4.7): a `tool_call`-stage `mcp_policy_decision`
  that classified the call's arguments against declared data bindings
  carries `mcp_event.data_reach`. The preimage is the v1.14 layout, then the
  block's six members (binding id, access, outcome, schema flag, argument
  names with length prefixes, omitted count). The verifier requires the
  block's shape: a minted binding id and an access exactly when a binding
  matched, at most 32 argument names, each non-empty, at most 64 characters
  and strictly ascending in byte order. v1.17 on any other kind or stage, or
  a block elsewhere, fails verification.
- Chain v1.18 (SPEC §4.3, §4.6): a record sealed with a `customer` block,
  on both lanes. `llm_request`: the v1.16 layout with the trace
  presence-tagged, then the customer block; MCP kinds: the v1.14 layout with
  the data-reach block presence-tagged, then the customer block. The block
  is `source` (`credential`, `asserted`, `none`), `label_sha256` and
  `credential_kid`, whose shape follows from the source; on an asserted
  customer the verifier recomputes `label_sha256` from the stored
  `customer_id`. A block on any other version, or v1.18 without one, fails
  verification. A v1.18 `llm_request` keeps the content
  attestation and its stored content is re-derived; a content block on a
  v1.18 MCP record fails as unattested.
- Pack manifest 1.3 (SPEC §6.3): a `control_plane` section carrying the
  bucket's control-plane chain, one JSON object per record at
  `control-plane/<seq>.json` (`records/control-plane/` in an exported pack,
  which `--export-records` writes). Every record from sequence 0 is
  recomputed under the control-plane-v1 recipe (sequence, `previous_hash`
  text, canonical JSON of nine members with number tokens copied verbatim)
  and linked from the genesis hash. A decision receipt whose
  `cp_anchor_event_id` names a verified control-plane record must carry its
  `event_hash`; one naming no record in the pack is `WARN
  receipt_anchor_outside_pack`.
- Pack manifest 1.4 (SPEC §6.5): a required `evidence_class` label inside
  the signed bytes, printed before the records and on every verdict line.
  The one label this release reads is `sandbox-non-production`. An unknown
  or missing label, or one on an earlier manifest, exits 2.
- Pack manifest 1.5 (SPEC §6.6): a content-stripped pack. `content:
  stripped` and `removed_fields` (nine fields, none of them hashed) inside
  the signed bytes; records that cannot be stripped and still verify ship as
  hash-only stubs listed in `stubs`. Every record is verified from its
  sealed digests; the content checks skip the removed axes and keep the
  findings axis; the chain is linked through each stub without recomputing
  its hash, with a `STUB` line each and a count on the verdict. A stripped
  pack read with `--bucket`, or a record that still carries a removed field,
  exits 2; a stub whose hashes break the link, or that carries more than its
  four coordinates, exits 1.
- Per-tenant signatures (SPEC §7.2): a pack signed by a customer project's
  own signer (issuer `https://accounts.google.com`, named by an email
  subjectAltName) verifies only against the exact email passed with
  `--certificate-identity`; the issuer follows from an email identity unless
  `--certificate-oidc-issuer` is given. Such a pack checked without an
  identity exits 2, not 0. The Meilynx signing workflow stays the default.
- OCSF export check (SPEC §9): `--ocsf-export PATH`, with
  `--ocsf-public-key JWK`, checks an export of the chain against the pack:
  each object's SHA-256 against its manifest, each manifest's detached ECDSA
  P-256 signature, and every exported event's chain coordinates and digests
  against the pack record at that sequence. A mismatch fails naming the
  object, the line and the field; an event outside the pack is a WARN; a
  gap between manifests is `WARN export_gap`; an unsigned manifest, or one
  checked without a key, lands at exit 3; an unknown `mapping_version` is
  exit 2.
- Customer-conditions verdict (SPEC §10): `--conditions-sha256 HEX` reads
  the set's acceptance from the pack's control-plane chain (or from
  `--conditions-acceptance FILE`, whose hash is recomputed and whose link
  the verdict says is not in the pack), then counts the window's model and
  MCP records sealed under the compiled set by hashed evidence only, prints
  a `GAP` line for every other record, an `EXCEPTION` line for every record
  whose findings or decisions name one of the set's instances, and one
  verdict line. A pack without the acceptance exits 2.
- `VERIFIER_CAPABILITIES` declares `decision-receipts-v1`,
  `evaluation-trace-v1`, `data-reach-evidence-v1`, `control-plane-chain-v1`,
  `ocsf-export-v1`, `customer-scope-v1`, `per-tenant-signer-v1`,
  `evidence-class-v1`, `content-stripped-v1` and `customer-conditions-v1`,
  beside `chain-anchors-v1` and `segmented-records-v1`.
- Self-test: 20s-20y pin the per-tenant signer cases and a 1.4 manifest;
  cp1.0-cp1.4 the control-plane chain vectors; 28a-28n (with 28n2) the
  v1.15 fixtures, the fail-closed cases, the evidence cross-check and the
  receipts index; 29a-29d the v1.16 outcome digest and fixtures; 30a-30d
  the v1.17 fixtures and 27 rejected data-reach shapes; 31a-31e the v1.18
  fixtures on both lanes, a rewritten label and 10 rejected customer shapes;
  32a-32i the content-stripped pack, its stubs and the refusals; 33a-33g the
  customer-conditions verdict; 34a-34k the OCSF export check; 35a-35f the
  content re-derivation on v1.16 and v1.18 and the named failures for a
  trace without its digest, a content block without a capture policy and a
  control-plane sequence outside the signed 64-bit range.
- Known gap: a v1.16 record's asserted-label digest (`identity.asserted_digest`)
  is not re-derived by this release; v1.12, v1.14, v1.17 and v1.18 are. SPEC
  §4.5 says so. The next release closes it.

## 0.8.0 (2026-10-05)

- `verify-pack.py` from meilynx-proxy `b44e24c`.
- **Upgrade before verifying MCP chains written after this release.** A
  verifier older than 0.8.0 stops at the first `mcp_policy_decision` record
  with `unknown schema_version 'v1.14'`.
- Chain v1.14 (SPEC §4.3): every `mcp_policy_decision` record carries
  `mcp_event.stage`, the check the decision is (`access`, `limit`,
  `tool_call`, `tool_result`, `taint`, `adapter_fail_open`). The stage is
  hashed: the v1.12 MCP preimage with the identity block presence-tagged,
  then the stage. A stage on any other version, or v1.14 without one, fails
  verification. The asserted-label check (§4.5) runs on a v1.14 record that
  carries an identity.
- Action `hold` (SPEC §1): a tool call waiting on an approver is sealed
  `hold` instead of `block`. Released calls stay `allow`; denied calls and
  repeats of an approval already used stay `block`. The action is hashed as
  stored, so the preimage recipe is unchanged.
- Self-test 27a-d pins two v1.14 fixtures (a `tool_result`-stage allow
  carrying every earlier axis, and a bare held decision) and the fail-closed
  cases.

## 0.7.0 (2026-10-04)

- `verify-pack.py` from meilynx-proxy `ed2bc9f`.
- **Upgrade before verifying chains written after the segment rollout.** A
  verifier older than 0.7.0 reports a segmented chain as FAIL (missing
  records) in `--bucket` mode, and exits 2 on a 1.2 manifest.
- Segment objects (SPEC §1). A chain's records may be stored as
  `{first:020}-{last:020}.seg` objects, each holding the records `first`
  through `last` (at most 1,024), every record followed by one line feed and
  byte-identical to the `{seq:020}.bin` object it replaces. Record hashes are
  unchanged. The verifier parses every object name under a chain prefix into
  a range and reads the union, so a chain may mix both layouts.
- Verdicts: a record two objects hold with identical bytes is `WARN
  segment_overlap` and verifies; with different bytes it fails as
  `segment_fork`; a hole fails at the next record's `previous_hash` link; a
  chain whose objects stop early verifies on the records present; a segment
  whose body does not hold the records its name gives fails every one of
  them.
- Pack manifest `schema_version` 1.2 (SPEC §6.2): `storage_layout`
  (`per-record` or `segmented-v1`; absent or unknown exits 2) and a per-entry
  `object` reference (`name`, `index`) that must hold the entry's sequence
  and, in `--bucket` mode, be listed. Manifests 1.0 and 1.1 verify as before.
- `--bucket` finds each record through one name-bounded listing of the chain
  prefix, so it needs `storage.objects.list` as well as `storage.objects.get`
  (`roles/storage.objectViewer` holds both).
- `--records` reads a directory in either layout. `--export-records` splits
  segments into one `{seq:020}.bin` file per record, from `--bucket` or from a
  `--records` directory.
- `VERIFIER_CAPABILITIES` declares `segmented-records-v1`, so a release gate
  can tell from the file alone whether a verifier reads segment objects.
- Fixtures: `fixtures/segments/` holds six packs generated by
  `fixtures/gen-segment-fixtures.py` from the fully anchored pack (segmented,
  mixed, identical overlap, forked overlap, gap, truncation), each with the
  exit code and lines it must produce. `fixtures/run-segment-cases.py` runs
  them offline and against a stand-in bucket, checks the exports against the
  per-record objects byte for byte, and checks the committed fixtures match
  the generator.
- The `unknown-manifest-version` anchor fixture moves from 1.2, now a known
  version, to 2.0. Its verdict (exit 2) is unchanged.
- `--self-test` adds the segment assertions (26a to 26m).

## 0.6.0 (2026-10-03)

- `verify-pack.py` from meilynx-proxy `c831e20`. The verifier itself last
  changed in `78cb3a0`; `c831e20` is the commit from which the proxy also
  writes the manifest 1.1 packs this release reads.
- Chain-head anchors (SPEC §6.1). A proxy that writes to a write-once store
  periodically timestamps its chain heads with RFC 3161 tokens from two
  independent witnesses and stores the statement and tokens next to the
  chain. The verifier checks every anchor a pack lists or carries: the
  statement is canonical JSON naming this chain and sequence, the anchored
  `event_hash` equals the record's recomputed hash, and each token verifies
  against a pinned root (Sigstore TSA, GlobalSign Root CA - R6) or a root
  passed with `--tsa-root ID=FILE`. A record changed or replaced under an
  anchor fails with `the record changed after it was anchored`.
- Pack manifest `schema_version` 1.1, which adds the `anchoring` section.
  The verifier checks the manifest's coverage summary against the anchors it
  verified. Manifest 1.0 still verifies, with an `UNANCHORED` notice.
- Verdicts: an anchored pack prints `ANCHORS OK` with the anchored range and
  the witness count; a pack with no anchors passes with a prominent
  `UNANCHORED` notice; a listed anchor that is missing, differs from the
  manifest's digests or does not verify fails (exit 1); a witness with no
  trust root, an unparseable token or an unknown manifest version is cannot
  evaluate (exit 2).
- `--tsa-root ID=FILE`: PEM roots for a customer witness. A token verified
  through one is reported with that root's SHA-256 fingerprint.
- A record whose own clock is more than five minutes ahead of the anchor
  covering it is reported as a NOTICE. The token's genTime is the
  authoritative "existed by" time.
- `VERIFIER_CAPABILITIES` declares `chain-anchors-v1`. Meilynx gates
  production rollouts on it: a proxy build that writes anchors is not rolled
  until a public release declares the capability.
- Fixtures: `fixtures/anchors/` holds nine offline packs (fully, partially
  and un-anchored, tampered head, missing anchor, untrusted root, record
  clock ahead, manifest 1.0, unknown manifest version), each with the exit
  code and lines it must produce, plus 37 RFC 3161 token cases with the
  verdict the proxy's own verifier gave. `fixtures/run-anchor-cases.py` runs
  both sets and compares every token verdict with `openssl ts -verify`.
- `--self-test` adds the anchor assertions (25a to 25x).

## 0.5.0 (2026-10-03)

- `verify-pack.py` from meilynx-proxy `c1581f0`.
- Chain `schema_version` v1.12 (`llm_request` and the MCP kinds): the sealed
  caller identity. The record hashes the agent id, identification tier,
  credential kind and key id, the verified delegated user, and a digest of
  the labels the caller asserted (SPEC §4.3, §4.5). The verifier recomputes
  that digest from the stored labels, so a label rewritten after sealing
  fails. On an MCP record, the hashed delegated user must agree with the
  principal chain's attestation marker.
- The stored-content check (SPEC §4.4) runs on every v1.12 record that
  carries a content block, as on v1.10 and v1.11.
- Chain `schema_version` v1.13 (`coverage.key_inventory`): the provider-key
  inventory for one provider and day, sealed on the coverage chain with its
  per-key list hashed verbatim (SPEC §4.3).
- Releases up to 0.4.0 report an intact v1.12 or v1.13 record as a
  verification failure. Use this release for any pack that holds one.
- Fixtures: the request chain gains three v1.12 records (an agent's model
  call under a `full` capture policy, its MCP tool call on behalf of a
  verified user, and a project-key call with no capture policy), and a new
  coverage chain in `fixtures/coverage/` holds a v1.8 and a v1.13 record.
  `fixtures/generate.py --out DIR` now writes the same layout under `DIR`.
- `--self-test` adds v1.12 and v1.13 fixture hashes (24a to 24h, 16c, 16d).

## 0.4.0 (2026-09-28)

- `verify-pack.py` from meilynx-proxy `ce114ab`.
- Chain `schema_version` v1.11 (`llm_request` whose response made tool
  calls): the v1.10 fields plus `tool_calls_sha256_jcs` and
  `stored_tool_calls_sha256_jcs` (SPEC §4.3, §4.4). The stored-content check
  now also recomputes the stored tool-call digest from the record's own
  `tool_calls`.
- Failure reports name the record that failed. When a record fails, the next
  record's link is checked against the hashes the manifest commits for the
  failed record; if none are committed, the link is reported as not checked
  (`WARN`) rather than as a second failure.
- `--self-test` adds v1.11 fixture hashes and tool-call digest vectors.

## 0.3.0 (2026-09-26)

**Breaking:** an unsigned pack no longer exits `0`. Without `--allow-unsigned`
it exits `3` ("chain verified, authenticity not established"), offline and
online alike. Scripts that verify unsigned samples, including the fixture chain
in this repository, now pass `--allow-unsigned`. A signed pack stripped of its
signature and relabelled as unsigned therefore cannot read as a pass.

- `verify-pack.py` from meilynx-proxy `518e2d6`.
- Signed packs: the verifier checks the keyless cosign signature itself, with
  the standard library only and no network access:
  - the Sigstore bundle `manifest.json.sigstore.json` (v0.3, Rekor v1);
  - the Rekor signed entry timestamp, inclusion proof and checkpoint;
  - the Fulcio chain to embedded Sigstore public-good trust anchors;
  - the certificate's validity when the entry was logged;
  - the Meilynx signing identity and issuer.
  
  Details in SPEC §7.
- New options: `--certificate-identity`, `--certificate-oidc-issuer`,
  `--trusted-root`, `--allow-unsigned`.
- Exit codes: `0` verified, `1` failed with a reason, `2` cannot evaluate, `3`
  unsigned. When more than one applies, 1 outranks 2 and 2 outranks 3.
- A signed manifest must carry `recomputed_event_hash` on every entry.
- `--self-test` adds signature assertions 20a–20r: Wycheproof ECDSA vectors, a
  synthetic signed pack with one tampered variant per failure reason, the
  downgrade at the command line, and a real Sigstore public-good bundle.
- `fixtures/generate-signature-vectors.py` regenerates the embedded signature
  test vectors byte-identically. `fixtures/run-signature-cases.py` runs the
  command line against 30 signed and tampered packs; with `--cosign`, it
  compares every verdict with cosign's (a CI job does this).
- Certificate Transparency timestamps (SCTs) are not checked; see README.

## 0.2.0 (2026-09-25)

- `verify-pack.py` from meilynx-proxy `5e8a9cb`.
- Chain `schema_version` v1.10 (`llm_request` with content attestation): the v1.9 layout plus six `content` fields (SPEC §4.3, §4.4).
- Stored-content check: on every v1.10 record, the stored prompt, response and findings digests are recomputed from the record itself, so a record whose content was edited after sealing fails verification even though that content is outside the hash.
- RFC 8785 (JCS) canonical JSON in the standard library only, with ECMAScript number form.
- `--self-test` assertions 19a–19g: v1.10 fixture hashes, the production recompute path, fail-closed version guards, content digests paired with the proxy, offline tamper detection.
- SPEC §8 states what v1.10 still leaves unbound, and that `redacted` masks only what a detector located.

## 0.1.0 (2026-09-25)

First public release.

- `verify-pack.py` from meilynx-proxy `df7c422` (crate `meilynx-integrity-pack`).
- Offline verification from exported records (`--records DIR|file.jsonl|file.json`), standard library only.
- `--export-records DIR` on the online path.
- `--self-test` covers hash versions v1 through v1.9 against pinned fixture values, plus the offline path on a synthetic chain (clean, tampered, missing record).
- `SPEC.md`: record hash preimage per version, chain linkage, genesis, manifest and signature format.
- `fixtures/`: a three-record sample chain with its manifest.
