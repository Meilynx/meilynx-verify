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

# 4. Verify a chain whose records carry Ed25519 signatures, pinned to the
#    key the proxy publishes on /readyz
python3 verify-pack.py --records fixtures/record-sigs/signed/records \
  --manifest fixtures/record-sigs/signed/manifest.json --allow-unsigned \
  --chain-signing-key d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

# 5. Verify a local-chain pack (a gateway with no write-once store), then the
#    same chain packed earlier and checked against a later anchor (exit 4)
python3 verify-pack.py --records fixtures/local-chain/clean/records \
  --manifest fixtures/local-chain/clean/manifest.json --allow-unsigned \
  --tsa-root test-rsa=fixtures/anchors/roots/rsa-root.pem \
  --tsa-root test-ec=fixtures/anchors/roots/ec-root.pem
python3 verify-pack.py --records fixtures/local-chain/earlier-pack/records \
  --manifest fixtures/local-chain/earlier-pack/manifest.json --allow-unsigned \
  --tsa-root test-rsa=fixtures/anchors/roots/rsa-root.pem \
  --tsa-root test-ec=fixtures/anchors/roots/ec-root.pem
```

Exit codes, the same online and offline:

| Code | Meaning |
|---|---|
| `0` | Every record verified, and on a signed pack the signature too. An unsigned pack reaches `0` only with `--allow-unsigned`, and the output still says authenticity is not established. |
| `1` | Verification failed. The output names the first record that failed and why (hash mismatch, chain break, missing record, unknown record kind, two stored copies of one record that differ), why the signature failed, or which chain-head anchor failed and why. |
| `2` | This verifier cannot evaluate the pack: an unsupported hash version, manifest version, storage layout, evidence class, content claim, signature method or bundle format (use a newer release), an unusable `--trusted-root`, an anchor from a witness with no trust root (pass `--tsa-root`), a pack signed by a per-tenant signer checked without `--certificate-identity`, or a content-stripped pack read with `--bucket` or still carrying a removed field. |
| `3` | The records verified, but the pack is unsigned, so nothing shows who produced the manifest. |
| `4` | Integrity passed, coverage not established. Every record verified, but the pack does not reach a sequence the chain is known to have reached: the pack claims the whole chain up to its head and a verified chain-head anchor names a later head, or the pack stops before the sequence you passed with `--require-through`. Not a pass, and not a tampering verdict (see "Local-chain evidence" below). |

When more than one applies, `1` outranks `2`, `2` outranks `4`, and `4`
outranks `3`. `--allow-unsigned` turns `3` into `0`; it never turns `4` into
`0`. A script that treats every non-zero exit as a failure needs no change;
one that treats only `1` as a failure should treat `4` as "ask for a pack
that runs further".

The sample chains carry no signature, so step 2 prints "AUTHENTICITY NOT
ESTABLISHED" and relies on `--allow-unsigned` for its `0`. Without the flag it
exits `3`. The first sample is a request chain (model calls and MCP tool
calls, including records that seal the caller's identity); the second is a
coverage chain. The third, under `fixtures/anchors/`, is a chain whose heads
are anchored (see "Chain-head anchors" below); its output includes an
`ANCHORS OK` line.

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
| `records/control-plane/<seq>.json` | Present on a pack whose manifest (1.3 and later) carries the control-plane chain: the control plane's own record of the human actions a decision involved, one JSON object per record, verified from its genesis and checked against each decision receipt in the pack that cites one of its records ([SPEC.md](SPEC.md) §6.3) |

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

A pack exported from a customer project is signed instead by that project's
own signer, a service account whose certificate names it by email with the
issuer `https://accounts.google.com`. Nothing in the pack can say whose
signer it is, so pass the exact email the evidence holder published for the
project with `--certificate-identity <email>`; the issuer follows. Without
it such a pack exits `2`, not `0`, even though the signature itself checks
out. There is no pattern match ([SPEC.md](SPEC.md) §7.2).

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

A pass prints `ANCHORS OK` with the sequence the anchors verify through and
the number of witnesses that verified. Records after the last anchor are
reported on the same line as not yet anchored. A pack with no anchors still
passes its chain check and prints `ANCHORS: none`. An anchor shows that the
covered records existed no later than the token's time and are unchanged
since (SPEC §6.1).

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

## Local-chain evidence

A gateway that runs with no write-once store keeps its audit chain only in
its own database. Its `meilynx-proxy evidence-pack` command writes, for one chain, a pack
with the same layout as above: `manifest.json`, `records/<seq>.bin`, the
gateway's chain-head anchors under `records/anchors/`, a copy of this
verifier and a README. The manifest is version 1.4 with evidence class
`local-chain-not-write-once` ([SPEC.md](SPEC.md) §6.5), and it states what
the pack holds: the whole chain from sequence 0 up to the head the gateway
read (`claim`, §6.7).

**What such a pack can show.** Each record's hash recomputes from its fields,
and each record names the hash of the record before it, so a record changed,
removed from the middle or reordered after the pack was built fails the
check. Where an anchor verifies, a timestamp authority signed the chain head
at that sequence: that head existed no later than the token's time, and the
records up to it have not changed since. A record changed after it was
anchored fails.

**What it cannot show.**

- **Who produced it.** The pack is unsigned. The manifest is only as
  trustworthy as the way you received it, and the verifier exits `3` unless
  you pass `--allow-unsigned`.
- **That the history is complete.** The records come from a database on a
  volume the gateway's operator controls. They are not write-once: no
  write-once store ever confirmed them, and whoever controls that volume can
  rewrite or remove records before a pack is built.
- **That records were not rewritten before they were anchored.** A record
  becomes tamper-evident only once a head that a timestamp authority signed
  covers it, and then only for a reader who holds that anchor. A history
  rewritten before its first anchor cannot be detected, and records after
  the last anchor are shown only to be consistent with each other. The
  anchors inside a pack come from the same gateway as the records; anchors
  you obtain separately, for example from the gateway's export sink, do not
  depend on the pack.

**How truncation shows up.** If you hold anchors from the gateway's export
sink, copy them into `records/anchors/` before you run the check. An anchor
that names a head after the pack's last record, and whose token verifies,
shows that the chain went on past what the pack holds. The verifier then
prints

```
COVERAGE anchor seq=4: a verified anchor (…) names chain … at seq=4, after this pack's last record seq=2; …
COVERAGE NOT ESTABLISHED through seq=4: every anchor this pack holds verified, but it claims chain … only up to its head at seq=2, …
INTEGRITY OK, COVERAGE NOT ESTABLISHED: all 3 events verified, … This is not a tampering verdict.
```

and exits `4`. Either the pack was built before that anchor, or records were
removed from its end, or the anchor belongs to another gateway's chain of
the same name; nothing in the pack can say which. Ask for a pack that runs
through the anchored sequence. The manifest's claim is unsigned, so the
verifier also refuses a local-chain pack whose claim was edited to a window
(exit `1`). If you know how far the chain had reached from another source,
for example the head the gateway reported to its control plane, pass
`--require-through <seq>`: a pack that stops before it exits `4` whatever its
manifest says.

The output of a clean local-chain pack carries these lines:

```
EVIDENCE CLASS: local-chain-not-write-once (records read from a gateway's own local hash chain; no write-once store confirmed them, so this pack cannot show that its history is complete).
CLAIM: the whole chain … from seq=0 up to its head at seq=4
ANCHORS OK: verified through seq=4, 2/2 witnesses
AUTHENTICITY NOT ESTABLISHED: this pack carries no signature (window A). …
OK: all 5 events verified. Authenticity not established (unsigned pack, accepted with --allow-unsigned). [evidence class: local-chain-not-write-once]
```

**Evidence modes.** A gateway seals its evidence mode (`write_once` or
`local_chain`) as a record at every start. The verifier prints each one,
`EVIDENCE MODE seq=1: write_once (derived)`, and every change,
`EVIDENCE MODE CHANGED at seq=4: write_once -> local_chain (configured)`.
A manifest that lists the modes (`evidence_modes`, [SPEC.md](SPEC.md) §6.8)
must list exactly the seals in the records, or the pack fails.

`fixtures/local-chain/` holds five packs: a clean local-chain pack, the same
chain packed at an earlier head and checked against the later anchor
(exit `4`), that pack with its claim edited (exit `1`), a chain with a
change of evidence mode, and the same chain with the change left out of the
manifest (exit `1`). `fixtures/run-local-chain-cases.py` runs each one with
its expected exit code and output lines; `fixtures/gen-local-chain-fixtures.py`
writes them and says where each record comes from.

## Further checks

Each of these runs with the chain check and ranks its verdict against it by
the same exit-code precedence.

- **Decision receipts and the control-plane chain** (no flag). A
  `decision_receipt` record's evidence digest, clock arithmetic and evidence
  entries are checked against the pack, the manifest's `decision_receipts`
  index against the receipts, and, on a manifest 1.3 or later pack that
  carries one, the control-plane chain from its genesis, with each receipt's
  anchor checked against it ([SPEC.md](SPEC.md) §4.3, §6.3, §6.4).
- **Evidence class and content-stripped packs** (no flag). A 1.4 manifest's
  `evidence_class` is printed on every verdict line; a 1.5 manifest's
  content-stripped pack is verified from its sealed digests, linked through
  its hash-only stubs, and refused if a record still carries a removed field
  ([SPEC.md](SPEC.md) §6.5, §6.6).
- `--ocsf-export PATH`, with `--ocsf-public-key JWK`: check an OCSF export
  of the chain (a `.manifest.json`, a day's `index.json`, or a directory)
  against the pack: each object's digest, each manifest's signature, and
  every exported event's chain coordinates and digests against the pack
  record at that sequence ([SPEC.md](SPEC.md) §9).
- `--conditions-sha256 HEX`, with `--conditions-acceptance FILE` for a pack
  that does not carry the control-plane chain: the customer-conditions
  verdict for the condition set whose digest you hold, counting the records
  in the window sealed under it, its gaps and its exceptions
  ([SPEC.md](SPEC.md) §10).
- **Compliance records** (no flag). A v1.20 `compliance_record` record, one
  item a proxy retrieved from a vendor's compliance API with the customer's
  own credential, binds the stored item, its file bytes and its findings
  through digests the verifier recomputes ([SPEC.md](SPEC.md) §4.3).
- **Record signatures** (no flag; `--chain-signing-key HEX` pins the key).
  Every record's `record_sig` is checked over its chain coordinates, and
  records sealed before signing started are reported as an unsigned prefix.
  Pass the key the proxy publishes on `/readyz` (`chain_signing_public_key`)
  and the newest signed record must verify under it, so a chain re-signed
  under another key fails ([SPEC.md](SPEC.md) §11).
  `fixtures/run-record-sig-cases.py` runs the verifier against chains the
  proxy's own writer sealed: intact, rewritten with the signatures kept, and
  rewritten with them removed.
- `--certificate-identity` and `--certificate-oidc-issuer`: the signer a
  signed pack must carry (see "Signed packs").
- `--tsa-root ID=FILE`: a customer witness's root for chain-head anchors
  (see "Chain-head anchors").
- `--require-through SEQ`: the sequence you expect the pack to reach, from a
  source other than the pack; a pack that stops before it exits `4` (see
  "Local-chain evidence").
- `--export-records DIR`: write every record read, including control-plane
  records and anchors, as per-record files for a reviewer without bucket
  access.

## What a passing verdict means, and what it does not

A pass proves that, for every record in the window:

- the record's hashed fields are byte-for-byte what they were when the record
  was written, and
- the records form one unbroken sequence from the genesis value, with no
  insertion, deletion or reordering.

It does **not** prove:

- that the window is complete, meaning that every AI interaction that
  happened was routed through the proxy and recorded. Completeness is a
  deployment property (routing enforcement), not a chain property. The
  verifier reports a shortfall only when it holds evidence of one (exit `4`,
  see "Local-chain evidence").
- for a local-chain pack, that the records were never rewritten before the
  pack was built. Its store is not write-once; anchors bound what could have
  changed (see "Local-chain evidence").
- that fields outside the hash preimage are unchanged. Which fields are
  hashed is listed per record version in [SPEC.md](SPEC.md). For LLM-lane
  records sealed under a capture policy (v1.10 and later), digests of the
  prompt, response, findings and tool calls are in the preimage and the
  verifier checks the stored content against them; without a capture policy
  that content is stored but not bound. For MCP-lane records a digest of the
  payload is in the preimage.
- who wrote the record. A signed pack (`manifest.json.sigstore.json`) binds
  the manifest to the signing identity, and the manifest binds each record's
  hash. A record signature (`record_sig`) binds each record to the proxy's
  chain signing key, not to a person or organisation.
- when a record was written, unless the chain is anchored. Without anchors
  the record's timestamp is the proxy's own clock. With anchors, the token's
  time bounds when the covered records existed.

## Versions

The verifier understands chain records with `schema_version` v1 through
v1.20, stored per record or in segment objects, and pack manifests 1.0
through 1.5 (1.1 adds chain-head anchors, 1.2 the storage layout, 1.3 the
control-plane chain, 1.4 the evidence class label, 1.5 the content-stripped
pack with its hash-only stubs). It declares the pack features it checks in
`VERIFIER_CAPABILITIES`: `chain-anchors-v1`, `segmented-records-v1`,
`decision-receipts-v1`, `evaluation-trace-v1`, `data-reach-evidence-v1`,
`control-plane-chain-v1`, `ocsf-export-v1`, `customer-scope-v1`,
`per-tenant-signer-v1`, `evidence-class-v1`, `content-stripped-v1`,
`customer-conditions-v1`, `record-signatures-v1`, `compliance-records-v1`,
`local-chain-evidence-v1`, `coverage-claim-v1` and `evidence-modes-v1`. A record of an unknown
version or kind fails verification rather than being skipped; a manifest of
an unknown version, storage layout, evidence class or content claim is
cannot evaluate (exit `2`). Changes to the verifier are listed in
[CHANGELOG.md](CHANGELOG.md). The canonical source of this file is the
`meilynx-integrity-pack` crate in the proxy; releases here are byte-identical
copies tagged with the proxy commit they came from.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

Questions and findings: hello@meilynx.com
