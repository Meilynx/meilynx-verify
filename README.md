# meilynx-verify

Independent verifier for Meilynx audit chains.

Meilynx records every governed AI interaction in an append-only, SHA-256
hash-chained log. This repository holds the tool that lets **anyone** check
such a log without Meilynx in the loop: an examiner, an internal auditor, a
vendor-risk reviewer, or a customer's own engineer. It recomputes every
record's hash from the record's own bytes, confirms each record links to the
one before it back to a fixed genesis value, and reports the first place the
chain breaks if it does.

The verifier is a single Python file with no dependencies beyond the standard
library when run offline. The format it checks is documented in
[SPEC.md](SPEC.md) precisely enough to write a second verifier from scratch.

## Quick start

```bash
# 1. Confirm the verifier itself works (pinned fixture hashes + an offline tamper test)
python3 verify-pack.py --self-test

# 2. Verify the sample chain shipped with this repository
python3 verify-pack.py --records fixtures/records --manifest fixtures/manifest.json
```

Exit code `0` means every record verified and the chain is intact. Exit code
`1` names the first record that failed and why (hash mismatch, chain break,
missing record, unknown record kind).

Try it on a tampered copy:

```bash
cp -r fixtures/records /tmp/records
python3 - <<'EOF'
import json; p='/tmp/records/00000000000000000001.bin'
d=json.load(open(p)); d['input_tokens'] += 1; json.dump(d, open(p,'w'))
EOF
python3 verify-pack.py --records /tmp/records --manifest fixtures/manifest.json; echo "exit=$?"
```

The edited record fails its hash check, and the record after it fails its
chain check, because its stored `previous_hash` no longer matches what the
edited record now hashes to.

## What you need from the Meilynx deployment

A **pack** is what a Meilynx proxy's `integrity-pack` command produces:

| File | What it is |
|---|---|
| `manifest.json` | The window verified (`from_sequence`..`to_sequence`), the hash algorithm and version, the genesis hash, and one entry per record with the hash the generator recomputed |
| `records/<seq>.bin` | The chain records themselves, one JSON document per file, named by 20-digit zero-padded sequence number (the layout of the write-once bucket they came from) |
| `manifest.json.sig`, `manifest.json.bundle` | Present on a signed pack: a detached keyless-Sigstore signature over `manifest.json` and its Rekor transparency-log proof |

Records are exported alongside the manifest with
`verify-pack.py --bucket … --export-records DIR` by someone who has read
access to the bucket, or copied straight out of the bucket prefix. A reviewer
then runs the offline form above.

Online form, for a reviewer who has been granted read access to the bucket:

```bash
pip install google-cloud-storage && gcloud auth application-default login
python3 verify-pack.py --bucket <bucket> --manifest manifest.json
```

## What a passing verdict means, and what it does not

A pass proves that, for every record in the window:

- the record's hashed fields are byte-for-byte what they were when the record
  was written, and
- the records form one unbroken sequence from the genesis value, with no
  insertion, deletion or reordering.

It does **not** prove:

- that the window is complete, meaning that every AI interaction that
  happened was routed through the proxy and recorded. Completeness is a
  deployment property (routing enforcement), not a chain property.
- that fields outside the hash preimage are unchanged. Which fields are
  hashed is listed per record version in [SPEC.md](SPEC.md). For LLM-lane
  records the prompt and response text is stored in the record but is not in
  the preimage; for MCP-lane records a digest of the payload is.
- who wrote the record. A signed pack (`manifest.json.sig`) binds the
  manifest to the signing identity; the chain itself is not signed.

## Versions

The verifier understands chain records with `schema_version` v1 through
v1.9. A record of an unknown version or kind fails verification rather than
being skipped. Changes to the verifier are listed in
[CHANGELOG.md](CHANGELOG.md). The canonical source of this file is the
`meilynx-integrity-pack` crate in the proxy; releases here are byte-identical
copies tagged with the proxy commit they came from.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

Questions and findings: hello@meilynx.com
