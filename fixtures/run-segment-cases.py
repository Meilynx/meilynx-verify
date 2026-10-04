#!/usr/bin/env python3
"""Check verify-pack.py against the segment-object fixtures (MEI-2863,
ADR-0081 D6, D7, D9).

    python3 fixtures/run-segment-cases.py

1. The committed fixtures/segments/ are exactly what
   fixtures/gen-segment-fixtures.py writes from the legacy per-record pack,
   so they cannot drift from it.
2. Every case yields its expect.json verdict (exit code, lines printed and
   lines not printed) through the command line, twice: offline (--records)
   and against a bucket (--bucket), the bucket being a stand-in
   google.cloud.storage module put first on PYTHONPATH that serves the
   case's records. The bucket run also checks that the records are found
   with one name-bounded listing of the chain prefix.
3. Where a case says export_matches_legacy, --export-records (from the
   bucket and from the records directory) writes one <seq:020d>.bin per
   record, byte-identical to the legacy pack's per-record objects.
4. The legacy per-record pack itself still verifies through the same
   bucket path, unchanged.
"""
import filecmp
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE.parent / "verify-pack.py"
SEGMENTS = HERE / "segments"
ANCHORS = HERE / "anchors"
LEGACY = ANCHORS / "packs" / "fully-anchored"
BUCKET = "fixture-bucket"

FAKE_STORAGE = '''
"""Stand-in for google.cloud.storage: serves directories as GCS objects."""
import json
import os
from pathlib import Path


class NotFound(Exception):
    pass


def _objects():
    objects = {}
    for prefix, directory in json.loads(os.environ["FAKE_GCS_OBJECTS"]).items():
        d = Path(directory)
        if d.is_dir():
            for p in d.iterdir():
                if p.is_file():
                    objects[prefix + p.name] = p
    return objects


class _Named:
    def __init__(self, name):
        self.name = name


class _Blob:
    def __init__(self, name):
        self.name = name

    def download_as_bytes(self):
        path = _objects().get(self.name)
        if path is None:
            raise NotFound(f"404 {self.name}")
        return path.read_bytes()


class _Bucket:
    def blob(self, name):
        return _Blob(name)


class Client:
    def bucket(self, name):
        return _Bucket()

    def list_blobs(self, bucket_or_name, prefix=None, start_offset=None, end_offset=None):
        with open(os.environ["FAKE_GCS_LOG"], "a", encoding="utf-8") as log:
            log.write(json.dumps([prefix, start_offset, end_offset]) + "\\n")
        return [_Named(n) for n in sorted(_objects())
                if n.startswith(prefix or "")
                and (start_offset is None or n >= start_offset)
                and (end_offset is None or n < end_offset)]
'''


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def pem(der):
    import base64
    b64 = base64.b64encode(der).decode("ascii")
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(
        b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n-----END CERTIFICATE-----\n"


def resolve_args(args, work, label):
    out = []
    for arg in args:
        if "=roots/" in arg:
            tsa_id, rel = arg.split("=", 1)
            pem_path = work / f"{label}-{tsa_id}.pem"
            pem_path.write_text(pem((ANCHORS / rel).read_bytes()), encoding="ascii")
            arg = f"{tsa_id}={pem_path}"
        out.append(arg)
    return out


def fake_storage(work):
    pkg = work / "fakegcs" / "google" / "cloud"
    pkg.mkdir(parents=True, exist_ok=True)
    (work / "fakegcs" / "google" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "storage.py").write_text(FAKE_STORAGE, encoding="utf-8")
    return work / "fakegcs"


def run_verifier(case_dir, args, mode, work, export=None):
    """Exit code, output and the bucket listings of one verify-pack.py run."""
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    prefix = manifest["prefix"]
    chain = manifest["anchoring"]["chains"][0]["chain"]
    log = work / f"listings-{case_dir.name}-{mode}.jsonl"
    log.write_text("", encoding="utf-8")
    env = dict(os.environ)
    if mode == "bucket":
        source = ["--bucket", BUCKET]
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(fake_storage(work)), env.get("PYTHONPATH")]))
        env["FAKE_GCS_OBJECTS"] = json.dumps({prefix: str(case_dir / "records"),
                                              f"anchors/{chain}/": str(case_dir / "records" / "anchors")})
        env["FAKE_GCS_LOG"] = str(log)
    else:
        source = ["--records", str(case_dir / "records")]
    extra = ["--export-records", str(export)] if export else []
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), *source, "--manifest", str(case_dir / "manifest.json"),
         "--allow-unsigned", *args, *extra],
        capture_output=True, text=True, env=env,
    )
    listings = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    return proc.returncode, proc.stdout + proc.stderr, [entry for entry in listings if entry[0] == prefix]


def check_generator(work):
    fresh = work / "generated"
    proc = subprocess.run([sys.executable, str(HERE / "gen-segment-fixtures.py"), str(fresh)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        die(f"gen-segment-fixtures.py failed:\n{proc.stdout}{proc.stderr}")
    committed = sorted(p.relative_to(SEGMENTS) for p in SEGMENTS.rglob("*") if p.is_file())
    generated = sorted(p.relative_to(fresh) for p in fresh.rglob("*") if p.is_file())
    if committed != generated:
        die(f"fixtures/segments/ holds {committed}, the generator writes {generated}; "
            f"run python3 fixtures/gen-segment-fixtures.py")
    stale = [str(p) for p in committed if (SEGMENTS / p).read_bytes() != (fresh / p).read_bytes()]
    if stale:
        die(f"fixtures/segments/ differs from the generator's output in {stale}; "
            f"run python3 fixtures/gen-segment-fixtures.py")
    print(f"ok   fixtures/segments/ matches gen-segment-fixtures.py ({len(committed)} files)")


def check_export(export):
    legacy = sorted(p.name for p in (LEGACY / "records").glob("*.bin"))
    exported = sorted(p.name for p in export.glob("*.bin"))
    if exported != legacy:
        return f"exported {exported}, the legacy pack holds {legacy}"
    _, mismatch, errors = filecmp.cmpfiles(LEGACY / "records", export, legacy, shallow=False)
    if mismatch or errors:
        return f"exported files differ from the legacy per-record objects: {mismatch + errors}"
    return None


def main():
    failures = 0
    cases = sorted(p for p in SEGMENTS.iterdir() if p.is_dir())
    if len(cases) < 6:
        die(f"the segment case set shrank to {len(cases)}")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        check_generator(work)
        for case_dir in cases:
            expect = json.loads((case_dir / "expect.json").read_text(encoding="utf-8"))
            for index, run in enumerate(expect["runs"]):
                args = resolve_args(run["args"], work, f"{case_dir.name}-{index}")
                for mode in ("records", "bucket"):
                    export = None
                    if expect.get("export_matches_legacy"):
                        export = work / f"export-{case_dir.name}-{index}-{mode}"
                    code, output, listings = run_verifier(case_dir, args, mode, work, export)
                    problems = []
                    if code != run["exit"]:
                        problems.append(f"exit {code}, want {run['exit']}")
                    problems += [f"missing {line!r}" for line in run["contains"] if line not in output]
                    problems += [f"printed {line!r}" for line in run.get("absent", []) if line in output]
                    if mode == "bucket" and len(listings) != 1:
                        problems.append(f"{len(listings)} listings of the chain prefix, want 1: {listings}")
                    if export is not None:
                        problem = check_export(export)
                        if problem:
                            problems.append(problem)
                    label = f"{case_dir.name} run {index} --{mode}"
                    if problems:
                        print(f"FAIL {label}: {'; '.join(problems)}")
                        print("\n".join(f"    | {line}" for line in output.splitlines()))
                        failures += 1
                    else:
                        extra = ", export byte-identical to the legacy objects" if export else ""
                        print(f"ok   {label}: exit {code}{extra}")

        legacy_expect = json.loads((LEGACY / "expect.json").read_text(encoding="utf-8"))["runs"][0]
        args = resolve_args(legacy_expect["args"], work, "legacy")
        export = work / "export-legacy"
        code, output, listings = run_verifier(LEGACY, args, "bucket", work, export)
        problem = check_export(export)
        missing = [line for line in legacy_expect["contains"] if line not in output]
        if code != legacy_expect["exit"] or missing or problem or len(listings) != 1:
            print(f"FAIL legacy per-record pack --bucket: exit {code}, missing {missing}, export {problem}, "
                  f"listings {listings}")
            print("\n".join(f"    | {line}" for line in output.splitlines()))
            failures += 1
        else:
            print(f"ok   legacy per-record pack --bucket: exit {code}, export byte-identical, "
                  f"one listing {listings[0][1:]}")
    if failures:
        die(f"{failures} segment case run(s) failed")
    print("all segment cases passed")


if __name__ == "__main__":
    main()
