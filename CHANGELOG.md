# Changelog

## 0.1.0 (2026-09-25)

First public release.

- `verify-pack.py` from meilynx-proxy `df7c422` (crate `meilynx-integrity-pack`).
- Offline verification from exported records (`--records DIR|file.jsonl|file.json`), standard library only.
- `--export-records DIR` on the online path.
- `--self-test` covers hash versions v1 through v1.9 against pinned fixture values, plus the offline path on a synthetic chain (clean, tampered, missing record).
- `SPEC.md`: record hash preimage per version, chain linkage, genesis, manifest and signature format.
- `fixtures/`: a three-record sample chain with its manifest.
