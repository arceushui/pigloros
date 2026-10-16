"""Hosted-only, test-source timing probe; never a gate or merge candidate."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


REVISION = "1b24e5f272c2962ed8091687ac29426e2b862356"
BRANCH = "refs/heads/redmine/561-benchmark-diagnostic-0c05"
FILES = {
    "imported_fork_replay_tests.rs": ("populate", "run_on_host"),
    "nested_imported_fork_replay_tests.rs": (
        "world", "populate", "invoke", "exercise", "run_cases",
    ),
}
TESTS = (
    "imported_fork_replay_tests::"
    "imported_mixed_and_empty_sources_reach_replay_and_replay_at_on_both_adapters",
    "nested_imported_fork_replay_tests::"
    "imported_nested_and_max_depth_histories_keep_exact_cuts_and_atomic_public_consumers",
)
HELPER = r'''
// Diagnostic branch only: inclusive wall timings, not production telemetry.
struct DiagnosticSpan(&'static str, std::time::Instant);
impl Drop for DiagnosticSpan {
    fn drop(&mut self) {
        eprintln!("[561-cost] {} {}", self.0, self.1.elapsed().as_nanos());
    }
}
'''


def instrument(source, filename, functions):
    """Insert only scoped timers; retain all existing test statements."""
    if "DiagnosticSpan" in source:
        raise ValueError("source already instrumented")
    for function in functions:
        matches = list(re.finditer(r"(?m)^fn " + function + r"[<(]", source))
        if len(matches) != 1:
            raise ValueError("expected exactly one diagnostic function")
        opening = source.index("{", matches[0].end()) + 1
        label = filename + "::" + function
        probe = ('\n    let _diagnostic_span = DiagnosticSpan("' + label
                 + '", std::time::Instant::now());')
        source = source[:opening] + probe + source[opening:]
    return source + HELPER


def measurements(log):
    result = {}
    for label, elapsed in re.findall(r"(?m)^\[561-cost\] (\S+) (\d+)$", log):
        entry = result.setdefault(label, {"calls": 0, "total_ns": 0, "max_ns": 0})
        entry["calls"] += 1
        entry["total_ns"] += int(elapsed)
        entry["max_ns"] = max(entry["max_ns"], int(elapsed))
    if not result:
        raise ValueError("missing timing probes")
    return result


def self_test():
    source = "fn populate<T>(x: T) -> Result<(), E> {\n    check(x)?;\n    Ok(())\n}\n"
    changed = instrument(source, "fixture.rs", ("populate",))
    assert changed.count("let _diagnostic_span") == 1
    assert "check(x)?;\n    Ok(())" in changed
    for invalid in (source + source, "", changed):
        try:
            instrument(invalid, "fixture.rs", ("populate",))
        except ValueError:
            continue
        raise AssertionError("ambiguous source accepted")
    assert measurements("[561-cost] fixture.rs::populate 10\n"
                        "[561-cost] fixture.rs::populate 20\n") == {
        "fixture.rs::populate": {"calls": 2, "total_ns": 30, "max_ns": 20},
    }
    try:
        measurements("no probes")
    except ValueError:
        pass
    else:
        raise AssertionError("missing probes accepted")
    print("timing instrumentation self-test passed")


def command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def run():
    # This guard precedes every filesystem mutation and compiler invocation.
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != "arceushui/pigloros"
            or os.environ.get("GITHUB_REF") != BRANCH):
        raise RuntimeError("diagnostic execution is restricted to its hosted branch")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    checkout = workspace / "candidate"
    if command(["git", "rev-parse", "HEAD"], checkout) != REVISION:
        raise RuntimeError("candidate revision mismatch")
    if command(["git", "status", "--porcelain"], checkout):
        raise RuntimeError("candidate was not clean before instrumentation")
    artifacts = workspace / "artifacts"
    artifacts.mkdir(exist_ok=True)
    metadata = {key: os.environ.get(key) for key in (
        "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "ImageOS", "ImageVersion",
        "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUSTFLAGS",
    )}
    metadata.update(candidate=REVISION, rustc=command(["rustc", "--version", "--verbose"]),
                    cpu=command(["lscpu"]), source_hashes={})
    for filename, functions in FILES.items():
        path = checkout / "crates/pos-time/src" / filename
        source = path.read_text()
        metadata["source_hashes"][filename] = hashlib.sha256(source.encode()).hexdigest()
        path.write_text(instrument(source, filename, functions))
    # Preserve the exact instrumentation diff, not just a prose description.
    (artifacts / "instrumentation.diff").write_text(command(["git", "diff"], checkout))
    (artifacts / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    environment = dict(os.environ, CARGO_TARGET_DIR=str(workspace / "target-test-cost"))
    started = time.monotonic()
    with (artifacts / "build.jsonl").open("w+") as output, (
            artifacts / "build.stderr").open("w") as errors:
        subprocess.run(["cargo", "test", "--locked", "--all-features", "-p", "pos-time",
                        "--lib", "--no-run", "--message-format=json"],
                       cwd=checkout, env=environment, stdout=output, stderr=errors,
                       check=True, timeout=900)
        output.seek(0)
        messages = [json.loads(line) for line in output if line.strip()]
    executables = [item["executable"] for item in messages
                   if item.get("reason") == "compiler-artifact" and item.get("executable")
                   and item.get("target", {}).get("name") == "pos_time"
                   and item.get("profile", {}).get("test")]
    if len(executables) != 1:
        raise RuntimeError("expected exactly one Time unit-test executable")
    binary = Path(executables[0]).resolve()
    if not binary.is_relative_to(workspace / "target-test-cost"):
        raise RuntimeError("executable escaped the diagnostic target directory")
    metadata.update(build_seconds=time.monotonic() - started,
                    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (artifacts / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    results = []
    for index, test in enumerate(TESTS):
        started = time.monotonic()
        log_path = artifacts / f"test-{index}.log"
        with log_path.open("w") as output:
            subprocess.run([str(binary), test, "--exact", "--include-ignored",
                            "--nocapture", "--test-threads=1"],
                           cwd=checkout, env=environment, stdout=output,
                           stderr=subprocess.STDOUT, check=True, timeout=480)
        log = log_path.read_text()
        if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in log:
            raise RuntimeError("the exact requested test did not execute successfully")
        measured = measurements(log)
        expected = FILES[tuple(FILES)[index]]
        if any(tuple(FILES)[index] + "::" + name not in measured for name in expected):
            raise RuntimeError("missing required function timing")
        if index == 0 and measured["imported_fork_replay_tests.rs::run_on_host"]["calls"] != 297:
            raise RuntimeError("ordinary matrix scenario count changed")
        result = {"test": test, "wall_seconds": time.monotonic() - started,
                  "inclusive_timings": measured,
                  "log_sha256": hashlib.sha256(log.encode()).hexdigest()}
        results.append(result)
        print(json.dumps(result), flush=True)
        (artifacts / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Diagnostic only: nested spans overlap; do not sum them or claim full CI clearance.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif sys.argv[1:]:
        raise SystemExit("expected no arguments or --self-test")
    else:
        run()
