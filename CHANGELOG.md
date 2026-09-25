# Changelog

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
