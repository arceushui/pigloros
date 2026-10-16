"""Temporary hosted-only #561 ABBA measurement; not a gate or baseline producer."""

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time


REVISIONS = {
    "baseline": "7c7bc93575e947171d340c9efd7b2a22fc9fed9c",
    "candidate": "77d78af043af93a1b1a5ee97df8fcb54ab893b1e",
}
CASES = {
    "manifest-cas": (0, 32, 128, 512),
    "acknowledgement-admission": (0, 8, 32, 63),
    "recovery-error-append": (0, 8, 24),
    "recovery-error-read": (1, 9, 25),
}
FIELDS = ["scenario", "cardinality", "sample", "elapsed_nanos"]
SAMPLE_COUNT = 100
ORDER = ["baseline", "candidate", "candidate", "baseline"] * 2


def measurements(source):
    """Require all fourteen cases and every predeclared raw sample."""
    reader = csv.DictReader(io.StringIO(source))
    if reader.fieldnames != FIELDS:
        raise ValueError("unexpected CSV header")
    expected = {(name, size, sample) for name, sizes in CASES.items()
                for size in sizes for sample in range(SAMPLE_COUNT)}
    values = {}
    for row in reader:
        if None in row or any(value is None for value in row.values()):
            raise ValueError("malformed CSV row")
        key = (row["scenario"], int(row["cardinality"]), int(row["sample"]))
        elapsed = int(row["elapsed_nanos"])
        if key not in expected or key in values or elapsed <= 0:
            raise ValueError("unexpected, duplicate, or invalid sample")
        values[key] = elapsed
    if values.keys() != expected:
        raise ValueError("incomplete benchmark sample set")
    return {f"{name}/{size}": sorted(values[name, size, sample]
            for sample in range(SAMPLE_COUNT))[SAMPLE_COUNT // 2]
            for name, sizes in CASES.items() for size in sizes}


def self_test():
    rows = [",".join(FIELDS)] + [f"{name},{size},{sample},{sample + 1}"
            for name, sizes in CASES.items() for size in sizes for sample in range(SAMPLE_COUNT)]
    assert len(measurements("\n".join(rows))) == 14
    assert set(measurements("\n".join(rows)).values()) == {51}
    for invalid in [rows[:-1], rows + [rows[1]], ["wrong"] + rows[1:],
                    rows[:1] + ["manifest-cas,0,0,0"] + rows[2:],
                    rows[:1] + ["manifest-cas,0,0,1,extra"] + rows[2:],
                    rows[:1] + ["manifest-cas,0,0"] + rows[2:],
                    rows[:1] + ["manifest-cas,999,0,1"] + rows[2:]]:
        try:
            measurements("\n".join(invalid))
        except ValueError:
            continue
        raise AssertionError("invalid diagnostic evidence accepted")
    print("diagnostic sample validation: positive control and 7 refusals passed")


def command(arguments, cwd=None):
    return subprocess.check_output(arguments, cwd=cwd, text=True).strip()


def run():
    # Hard stop before any build outside the explicitly scoped hosted workflow.
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != "arceushui/pigloros"
            or os.environ.get("GITHUB_REF") != "refs/heads/redmine/561-benchmark-diagnostic-0c05"):
        raise RuntimeError("this diagnostic may only build in its hosted branch workflow")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    artifacts = workspace / "artifacts"
    artifacts.mkdir(exist_ok=True)
    metadata = {name: os.environ.get(name) for name in (
        "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "ImageOS", "ImageVersion",
        "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUSTFLAGS", "PIGLOROS_BENCH_SAMPLES")}
    metadata.update(revisions=REVISIONS, order=ORDER, samples_per_case=SAMPLE_COUNT,
                    rustc=command(["rustc", "--version", "--verbose"]),
                    cargo=command(["cargo", "--version", "--verbose"]),
                    cpu=command(["lscpu"]), uname=command(["uname", "-a"]))
    (artifacts / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    binaries = {}
    sources = []
    for owner, revision in REVISIONS.items():
        checkout = workspace / owner
        if command(["git", "rev-parse", "HEAD"], cwd=checkout) != revision:
            raise RuntimeError("checkout identity mismatch")
        if command(["git", "status", "--porcelain"], cwd=checkout):
            raise RuntimeError("checkout is dirty before build")
        source = (checkout / "crates/pos-store/benches/memory_erasure.rs").read_bytes()
        sources.append(hashlib.sha256(source).hexdigest())
    if len(set(sources)) != 1:
        raise RuntimeError("benchmark source differs between revisions")
    metadata["benchmark_source_sha256"] = sources[0]
    for owner, revision in REVISIONS.items():
        checkout = workspace / owner
        environment = dict(os.environ, CARGO_TARGET_DIR=str(workspace / f"target-{owner}"))
        arguments = ["cargo", "bench", "--locked", "-p", "pos-store", "--bench",
                     "memory_erasure", "--no-run", "--message-format=json"]
        with (artifacts / f"build-{owner}.jsonl").open("w+") as output, (
                artifacts / f"build-{owner}.stderr").open("w") as errors:
            subprocess.run(arguments, cwd=checkout, env=environment,
                           stdout=output, stderr=errors, check=True, timeout=720)
            output.seek(0)
            messages = [json.loads(line) for line in output if line.strip()]
        candidates = [item["executable"] for item in messages
                      if item.get("reason") == "compiler-artifact" and item.get("executable")
                      and item.get("target", {}).get("name") == "memory_erasure"
                      and "bench" in item.get("target", {}).get("kind", [])]
        if len(candidates) != 1:
            raise RuntimeError("expected one benchmark executable")
        binary = Path(candidates[0]).resolve()
        if not binary.is_relative_to(workspace / f"target-{owner}"):
            raise RuntimeError("benchmark executable escaped its build directory")
        binaries[owner] = binary
        metadata[owner] = {"revision": revision, "binary_sha256":
                           hashlib.sha256(binary.read_bytes()).hexdigest()}
        if command(["git", "status", "--porcelain"], cwd=checkout):
            raise RuntimeError("build changed tracked or untracked source")
    # Pin measurements, not builds. Every child inherits this same CPU mask.
    # Two fixed ABBA blocks expose within-binary drift; no sample/run is dropped
    # and no observation controls whether another block is attempted.
    allowed_cpus = sorted(os.sched_getaffinity(0))
    selected_cpu = min(allowed_cpus)
    os.sched_setaffinity(0, {selected_cpu})
    metadata.update(allowed_cpus=allowed_cpus, measurement_cpu=selected_cpu)
    (artifacts / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    results = []
    for index, owner in enumerate(metadata["order"], 1):
        output_path = artifacts / f"{index}-{owner}.csv"
        environment = dict(os.environ, PIGLOROS_BENCH_OUTPUT=str(output_path),
                           PIGLOROS_BENCH_SAMPLES=str(SAMPLE_COUNT))
        if os.sched_getaffinity(0) != {selected_cpu}:
            raise RuntimeError("measurement CPU affinity changed")
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.monotonic()
        with (artifacts / f"{index}-{owner}.log").open("w") as log:
            subprocess.run([str(binaries[owner])], cwd=workspace / owner, env=environment,
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=90)
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        medians = measurements(output_path.read_text())
        result = {"order": index, "owner": owner, "revision": REVISIONS[owner],
                  "wall_seconds": time.monotonic() - started, "medians_ns": medians,
                  "user_cpu_seconds": after.ru_utime - before.ru_utime,
                  "system_cpu_seconds": after.ru_stime - before.ru_stime,
                  "voluntary_context_switches": after.ru_nvcsw - before.ru_nvcsw,
                  "involuntary_context_switches": after.ru_nivcsw - before.ru_nivcsw,
                  "csv_sha256": hashlib.sha256(output_path.read_bytes()).hexdigest()}
        results.append(result)
        print(json.dumps(result), flush=True)
        (artifacts / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Diagnostic complete. Measurements are not a performance clearance or trusted baseline.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif sys.argv[1:]:
        raise SystemExit("expected no arguments or --self-test")
    else:
        run()
