#!/usr/bin/env python3
"""Write the segment-object fixtures (MEI-2863, ADR-0081 D7) under
fixtures/segments/, from the per-record legacy pack
fixtures/anchors/packs/fully-anchored/.

    python3 fixtures/gen-segment-fixtures.py [OUT_DIR]

Every case stores the legacy chain's records, byte for byte, in the segment
layout of ADR-0081 D2 (`{first:020}-{last:020}.seg`: each record followed by
one 0x0A), with a manifest 1.2 (`storage_layout`, a per-entry `object`
reference) derived from the legacy manifest. Each case's expect.json holds
the exit code and lines verify-pack.py must print; fixtures/run-segment-cases.py
checks them in --records and --bucket mode and checks that this script still
writes exactly the committed bytes.

The cases, one per ADR-0081 D7 row:

  segmented          the whole chain in two segments                    exit 0
  mixed              per-record and segment objects in one chain        exit 0
  overlap-identical  seq 2 in two segments, byte-identical: WARN        exit 0
  overlap-forked     seq 2 in two segments, different bytes: FAIL       exit 1
  gap                seq 2 held by no object: FAIL at seq 3's link      exit 1
  truncated          finalized at 5, objects stop at 3: PASS on 0..3    exit 0

Deterministic: no clock, no randomness. Re-run it whenever the legacy pack
is regenerated (examples/gen_anchor_fixtures.rs).
"""
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LEGACY = HERE / "anchors" / "packs" / "fully-anchored"
TSA_ARGS = ["--tsa-root", "test-rsa=roots/rsa-root.der", "--tsa-root", "test-ec=roots/ec-root.der"]


def seg(first, last):
    return f"{first:020d}-{last:020d}.seg"


def rec(seq):
    return f"{seq:020d}.bin"


def span(name):
    m = re.fullmatch(r"(\d{20})\.bin", name)
    if m:
        return int(m.group(1)), int(m.group(1))
    m = re.fullmatch(r"(\d{20})-(\d{20})\.seg", name)
    return int(m.group(1)), int(m.group(2))


def unanchored(chain, lo, hi):
    """The anchoring section the generator writes for a chain with no anchors."""
    return {
        "chains": [{
            "anchored_through_seq": None,
            "anchors": [],
            "chain": chain,
            "reason": "no_anchors_found",
            "seals": [],
            "unanchored_tail": {"from_seq": lo, "to_seq": hi},
        }],
        "state": "unanchored",
    }


def fork(raw):
    """The same record with one hashed field changed: a second writer's copy."""
    changed, count = re.subn(rb'"input_tokens":(\d+)', lambda m: b'"input_tokens":%d' % (int(m.group(1)) + 1), raw)
    if count != 1:
        sys.exit(f"cannot fork the record: {count} input_tokens fields")
    return changed


CASES = [
    {
        "name": "segmented",
        "about": "The whole chain stored as two segment objects. Anchors at seq 2 and 4 resolve to "
                 "their records through the segments.",
        "objects": [seg(0, 1), seg(2, 4)],
        "anchored": True,
        "export_matches_legacy": True,
        "runs": [{"args": TSA_ARGS, "exit": 0,
                  "contains": ["PASS seq=4", "ANCHORS OK: chain=chain_tnt_fixture_run_a anchored_through=4",
                               "OK: all 5 events verified"],
                  "absent": ["WARN", "FAIL"]}],
    },
    {
        "name": "mixed",
        "about": "One chain in both layouts: per-record objects for seq 0 and 4, a segment for 1..3.",
        "objects": [rec(0), seg(1, 3), rec(4)],
        "anchored": True,
        "export_matches_legacy": True,
        "runs": [{"args": TSA_ARGS, "exit": 0,
                  "contains": ["OK: all 5 events verified", "ANCHORS OK"],
                  "absent": ["WARN", "FAIL"]}],
    },
    {
        "name": "overlap-identical",
        "about": "Seq 2 is held by two segments with byte-identical records (ADR-0081 D7): a WARN "
                 "segment_overlap, not a failure.",
        "objects": [seg(0, 2), seg(2, 4)],
        "anchored": True,
        "export_matches_legacy": True,
        "runs": [{"args": TSA_ARGS, "exit": 0,
                  "contains": [f"WARN seq=2: segment_overlap: {seg(0, 2)} and {seg(2, 4)} each hold this "
                               f"record, byte-identical", "OK: all 5 events verified"],
                  "absent": ["FAIL"]}],
    },
    {
        "name": "overlap-forked",
        "about": "Seq 2 is held by two segments with different bytes (ADR-0081 D7): a fork, FAIL.",
        "objects": [seg(0, 2), seg(2, 4)],
        "forked": (seg(2, 4), 2),
        "anchored": False,
        "verdict": {"verified": False, "break_at_sequence": 2},
        "runs": [{"args": [], "exit": 1,
                  "contains": [f"FAIL seq=2: record fetch error: segment_fork: {seg(0, 2)} and {seg(2, 4)} hold "
                               f"different bytes for seq=2", "PASS seq=3"],
                  "absent": ["FAIL seq=3", "FAIL seq=4"]}],
    },
    {
        "name": "gap",
        "about": "No object holds seq 2 and later objects exist (ADR-0081 D7). The manifest lists the "
                 "records present; seq 3 does not link to seq 1, so the chain fails there.",
        "objects": [seg(0, 1), seg(3, 4)],
        "events": [0, 1, 3, 4],
        "anchored": False,
        "verdict": {"verified": False, "break_at_sequence": 3},
        "runs": [{"args": [], "exit": 1,
                  "contains": ["FAIL seq=3: chain break", "PASS seq=4"],
                  "absent": ["FAIL seq=0", "FAIL seq=1", "FAIL seq=4"]}],
    },
    {
        "name": "truncated",
        "about": "The chain was finalized at final_next_sequence=5, but its objects stop at seq 3: the "
                 "segment holding seq 4 was never written (ADR-0081 D7). The records present verify; "
                 "the shortfall is a completeness verdict (the reconciler's finalized_mismatch), not an "
                 "integrity one.",
        "objects": [seg(0, 1), seg(2, 3)],
        "events": [0, 1, 2, 3],
        "anchored": False,
        "runs": [{"args": [], "exit": 0,
                  "contains": ["OK: all 4 events verified"],
                  "absent": ["WARN", "FAIL"]}],
    },
]


def dumps(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def write_case(case, out, legacy_manifest, legacy_records):
    case_dir = out / case["name"]
    records_dir = case_dir / "records"
    records_dir.mkdir(parents=True)
    chain = legacy_manifest["anchoring"]["chains"][0]["chain"]
    seqs = case.get("events", sorted(legacy_records))

    for name in case["objects"]:
        first, last = span(name)
        held = []
        for seq in range(first, last + 1):
            raw = legacy_records[seq]
            if case.get("forked") == (name, seq):
                raw = fork(raw)
            held.append(raw)
        body = held[0] if name.endswith(".bin") else b"".join(r + b"\n" for r in held)
        (records_dir / name).write_bytes(body)
    if case["anchored"]:
        shutil.copytree(LEGACY / "records" / "anchors", records_dir / "anchors")

    manifest = json.loads(json.dumps(legacy_manifest))
    manifest["schema_version"] = "1.2"
    manifest["storage_layout"] = "segmented-v1"
    manifest["events"] = [e for e in manifest["events"] if e["sequence"] in seqs]
    for entry in manifest["events"]:
        holder = next(n for n in case["objects"] if span(n)[0] <= entry["sequence"] <= span(n)[1])
        entry["object"] = {"name": holder, "index": entry["sequence"] - span(holder)[0]}
    lo, hi = min(seqs), max(seqs)
    manifest.update({"from_sequence": lo, "to_sequence": hi, "first_sequence": lo, "last_sequence": hi,
                     "records_checked": len(seqs)})
    manifest.update(case.get("verdict", {}))
    if not case["anchored"]:
        manifest["anchoring"] = unanchored(chain, lo, hi)
    (case_dir / "manifest.json").write_text(dumps(manifest), encoding="utf-8")

    expect = {"about": case["about"], "runs": case["runs"]}
    if case.get("export_matches_legacy"):
        expect["export_matches_legacy"] = True
    (case_dir / "expect.json").write_text(dumps(expect), encoding="utf-8")


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "segments"
    legacy_manifest = json.loads((LEGACY / "manifest.json").read_text(encoding="utf-8"))
    legacy_records = {}
    for path in sorted((LEGACY / "records").glob("*.bin")):
        raw = path.read_bytes()
        if b"\n" in raw:
            sys.exit(f"{path} holds a line feed: not a compact JSON record")
        legacy_records[int(path.stem)] = raw
    if sorted(legacy_records) != list(range(5)):
        sys.exit(f"the legacy pack must hold records 0..4, found {sorted(legacy_records)}")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for case in CASES:
        write_case(case, out, legacy_manifest, legacy_records)
    print(f"wrote {len(CASES)} segment fixture cases to {out}")


if __name__ == "__main__":
    main()
