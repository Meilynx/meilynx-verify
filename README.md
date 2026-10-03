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

# 2. Verify the sample chains shipped with this repository
#    (the samples are not signed, which --allow-unsigned acknowledges)
python3 verify-pack.py --records fixtures/records --manifest fixtures/manifest.json --allow-unsigned
python3 verify-pack.py --records fixtures/coverage/records --manifest fixtures/coverage/manifest.json --allow-unsigned
```

Exit codes, the same online and offline:

| Code | Meaning |
|---|---|
| `0` | Every record verified, and on a signed pack the signature too. An unsigned pack reaches `0` only with `--allow-unsigned`, and the output still says authenticity is not established. |
| `1` | Verification failed. The output names the first record that failed and why (hash mismatch, chain break, missing record, unknown record kind), or why the signature failed. |
| `2` | This verifier cannot evaluate the pack: an unsupported hash version, signature method or bundle format (use a newer release), or an unusable `--trusted-root`. |
| `3` | The records verified, but the pack is unsigned, so nothing shows who produced the manifest. |

When more than one applies, `1` outranks `2`, and `2` outranks `3`.

The sample chains carry no signature, so step 2 prints "AUTHENTICITY NOT
ESTABLISHED" and relies on `--allow-unsigned` for its `0`. Without the flag it
exits `3`. The first sample is a request chain (model calls and MCP tool
calls, including records that seal the caller's identity); the second is a
coverage chain.

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
| `manifest.json.sigstore.json` | Present on a signed pack: a Sigstore bundle holding a keyless cosign signature over `manifest.json`, the signing certificate, and the Rekor transparency-log proof |

Records are exported alongside the manifest with
`verify-pack.py --bucket … --export-records DIR` by someone who has read
access to the bucket, or copied straight out of the bucket prefix. A reviewer
then runs the offline form above.

Online form, for a reviewer who has been granted read access to the bucket:

```bash
pip install google-cloud-storage && gcloud auth application-default login
python3 verify-pack.py --bucket <bucket> --manifest manifest.json
```

## Signed packs

On a signed pack the verifier checks the signature before it checks the
records, with the Python standard library only and no network access. It
confirms all of the following:

- the signature verifies over the exact bytes of `manifest.json`;
- the Rekor transparency-log entry is authentic: its signed entry timestamp,
  its inclusion proof, and the signed checkpoint of the log;
- the logged entry is this signature, over this manifest, with this
  certificate;
- the certificate chains to a Sigstore Fulcio certificate authority that was
  trusted when the entry was logged, and was itself valid at that time;
- the certificate names the Meilynx signing identity:
  - identity `https://github.com/Meilynx/meilynx-proxy/.github/workflows/integrity-pack-signed.yml@refs/heads/main`
  - OIDC issuer `https://token.actions.githubusercontent.com`

A pack whose manifest says it is signed, and whose signature is missing or
fails any of these checks, exits `1` with the reason. A signed pack that has
had its signature removed and been relabelled as unsigned exits `3`, not `0`.

The trust anchors (the Fulcio certificates and the Rekor log key) are the
Sigstore public-good values, written out in `verify-pack.py` as
`SIGSTORE_PUBLIC_GOOD_TRUST_ROOT` with the `sigstore/root-signing` commit
they came from. To use anchors you fetched and checked yourself, pass
`--trusted-root trusted_root.json`. When Sigstore rotates a key, a pack signed
under the new key needs a release of this verifier that carries it, or
`--trusted-root`.

The verifier does not check the Certificate Transparency timestamps (SCTs)
embedded in the signing certificate. The Rekor entry it does check contains
that certificate. As an optional second opinion that also checks SCTs, cosign
runs the same assertion:

```bash
cosign verify-blob --bundle manifest.json.sigstore.json \
  --certificate-identity https://github.com/Meilynx/meilynx-proxy/.github/workflows/integrity-pack-signed.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  manifest.json
```

`fixtures/run-signature-cases.py` runs the verifier against a set of signed
and tampered test packs, and with `--cosign cosign` compares every verdict
with cosign's.

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
  records sealed under a capture policy (v1.10 and later), digests of the
  prompt, response, findings and tool calls are in the preimage and the
  verifier checks the stored content against them; without a capture policy
  that content is stored but not bound. For MCP-lane records a digest of the
  payload is in the preimage.
- who wrote the record. A signed pack (`manifest.json.sigstore.json`) binds
  the manifest to the signing identity, and the manifest binds each record's
  hash; the records themselves are not signed individually.

## Versions

The verifier understands chain records with `schema_version` v1 through
v1.13. A record of an unknown version or kind fails verification rather than
being skipped. Changes to the verifier are listed in
[CHANGELOG.md](CHANGELOG.md). The canonical source of this file is the
`meilynx-integrity-pack` crate in the proxy; releases here are byte-identical
copies tagged with the proxy commit they came from.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

Questions and findings: hello@meilynx.com
