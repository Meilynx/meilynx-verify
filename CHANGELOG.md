# Changelog

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
