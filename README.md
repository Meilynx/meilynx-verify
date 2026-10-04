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

# 3. Verify an anchored sample: a chain whose heads carry RFC 3161 timestamps
#    from two test witnesses, whose roots are passed with --tsa-root
python3 verify-pack.py --records fixtures/anchors/packs/fully-anchored/records \
  --manifest fixtures/anchors/packs/fully-anchored/manifest.json --allow-unsigned \
  --tsa-root test-rsa=fixtures/anchors/roots/rsa-root.pem \
  --tsa-root test-ec=fixtures/anchors/roots/ec-root.pem
```

Exit codes, the same online and offline:

| Code | Meaning |
|---|---|
| `0` | Every record verified, and on a signed pack the signature too. An unsigned pack reaches `0` only with `--allow-unsigned`, and the output still says authenticity is not established. |
| `1` | Verification failed. The output names the first record that failed and why (hash mismatch, chain break, missing record, unknown record kind, two stored copies of one record that differ), why the signature failed, or which chain-head anchor failed and why. |
| `2` | This verifier cannot evaluate the pack: an unsupported hash version, manifest version, storage layout, signature method or bundle format (use a newer release), an unusable `--trusted-root`, or an anchor from a witness with no trust root (pass `--tsa-root`). |
| `3` | The records verified, but the pack is unsigned, so nothing shows who produced the manifest. |

When more than one applies, `1` outranks `2`, and `2` outranks `3`.

The sample chains carry no signature, so step 2 prints "AUTHENTICITY NOT
ESTABLISHED" and relies on `--allow-unsigned` for its `0`. Without the flag it
exits `3`. The first sample is a request chain (model calls and MCP tool
calls, including records that seal the caller's identity); the second is a
coverage chain. The third, under `fixtures/anchors/`, is a chain whose heads
are anchored (see "Chain-head anchors" below); its output ends with
`ANCHORS OK`.

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
| `records/<seq>.bin` | The chain records themselves, one JSON document per file, named by 20-digit zero-padded sequence number. This is the per-record layout of the write-once bucket; a chain the bucket stores in segment objects is exported in the same form (see "Segment objects" below). |
| `manifest.json.sigstore.json` | Present on a signed pack: a Sigstore bundle holding a keyless cosign signature over `manifest.json`, the signing certificate, and the Rekor transparency-log proof |
| `records/anchors/<seq>.json` and `records/anchors/<seq>.<witness>.tsr` | Present on an anchored chain: the chain-head statement the proxy timestamped, and one RFC 3161 token per witness |

Records are exported alongside the manifest with
`verify-pack.py --bucket … --export-records DIR` by someone who has read
access to the bucket, or copied straight out of the bucket prefix. A reviewer
then runs the offline form above. `--export-records` also works with a
`--records` directory, which turns a copy of a segmented prefix into one file
per record.

Online form, for a reviewer who has been granted read access to the bucket
(`storage.objects.list` and `storage.objects.get`, which
`roles/storage.objectViewer` holds):

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

## Chain-head anchors

A hash chain shows order and integrity, not time. A proxy that writes its
chain to a write-once store therefore timestamps the chain head periodically
with RFC 3161 tokens from two independent timestamp authorities (Sigstore's
TSA and GlobalSign), and stores the signed statement and the tokens next to
the chain. The authority sees only a 32-byte digest and a nonce. The format is
in [SPEC.md](SPEC.md) §6.1.

On a pack whose manifest is version 1.1, the verifier checks every anchor the
manifest lists and every anchor it finds next to the records:

- the statement is canonical JSON and names this chain at this sequence;
- the anchored `event_hash` equals the hash recomputed from the record, so a
  record changed or replaced after it was anchored fails with
  `the record changed after it was anchored`;
- each token is a granted RFC 3161 response over the statement's digest,
  signed by a certificate with the time-stamping purpose that chains to a
  trusted root valid at the token's time; SHA-1 is refused everywhere;
- the manifest's coverage summary agrees with the anchors that verified.

A pass prints `ANCHORS OK` with the anchored sequence range and the number of
witnesses that verified. Records after the last anchor are reported as an
unanchored tail. A pack with no anchors still passes its chain check, and
prints a prominent `UNANCHORED` notice so nobody reads a chain check as
proof of time.

The roots of the two public witnesses are pinned in `verify-pack.py` with
their SHA-256 fingerprints and trust windows. A deployment that uses its own
timestamp authority passes that authority's root with
`--tsa-root <witness id>=<PEM file>`; the output then names the root and its
fingerprint, so a reviewer can check it against the authority's published
root. A witness with no root is exit `2`, not a pass.

An anchor shows that the covered records existed no later than the token's
time and are unchanged since. It does not show that the chain is complete,
and it does not vouch for the proxy's own clock: a record whose timestamp runs
more than five minutes ahead of its anchor is flagged, and the token's time
is the one to rely on.

`fixtures/run-anchor-cases.py` runs 37 token cases (valid and defective
tokens, including real Sigstore and GlobalSign tokens with altered
signatures, digests and certificates) and nine offline packs, checks that
every verdict matches the one the proxy's own verifier gave, and compares
each token verdict with `openssl ts -verify`.

## Segment objects

A chain's records are stored either one object per record,
`<seq:020>.bin`, or in segment objects, `<first:020>-<last:020>.seg`, each
holding up to 1,024 consecutive records separated by line feeds. Each record
inside a segment is byte-for-byte the per-record object it replaces, and its
hash is unchanged. The verifier reads both kinds under one chain prefix, in
any mix, from a bucket or from a records directory. The format is in
[SPEC.md](SPEC.md) §1, and the pack manifest that records each record's
segment (version 1.2) in §6.2.

- A record held by two objects with identical bytes prints
  `WARN seq=<n>: segment_overlap` and verifies once.
- A record held by two objects with different bytes fails with
  `segment_fork` (exit `1`).
- A missing range fails at the first record after it, which does not link to
  the record before the hole.
- A chain whose objects stop early verifies on the records present. That is
  a completeness question, not an integrity failure.

**Upgrade to 0.7.0 or later before verifying a chain written after the
segment rollout.** An older verifier reports a segmented chain as FAIL
(missing records) in `--bucket` mode, and exits `2` on a 1.2 manifest. It
never reports such a chain as a pass.

`fixtures/segments/` holds six packs built from the anchored sample: the
chain in segments, a mix of both layouts, an identical and a differing
overlap, a gap and a truncation, each with the exit code and lines it must
produce. `fixtures/run-segment-cases.py` runs each one offline and against a
stand-in bucket, and checks that the exported records are byte-identical to
the anchored sample's per-record objects.

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
- when a record was written, unless the chain is anchored. Without anchors
  the record's timestamp is the proxy's own clock. With anchors, the token's
  time bounds when the covered records existed.

## Versions

The verifier understands chain records with `schema_version` v1 through
v1.13, stored per record or in segment objects, and pack manifests 1.0, 1.1
and 1.2 (1.1 adds chain-head anchors, 1.2 the storage layout). A record of an
unknown version or kind fails verification rather than being skipped; a
manifest of an unknown version or storage layout is cannot evaluate (exit
`2`). Changes to the verifier are listed in
[CHANGELOG.md](CHANGELOG.md). The canonical source of this file is the
`meilynx-integrity-pack` crate in the proxy; releases here are byte-identical
copies tagged with the proxy commit they came from.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

Questions and findings: hello@meilynx.com
