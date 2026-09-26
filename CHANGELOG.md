# Changelog

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
