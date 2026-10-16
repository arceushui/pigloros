"""Hosted-only diagnostic: unchanged Replay tests, one dependency optimization."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import time

from diagnose_561_benchmark import command


REVISION = "77d78af043af93a1b1a5ee97df8fcb54ab893b1e"
ORDER = ["baseline", "candidate", "candidate", "baseline"]
TESTS = [
    "imported_fork_replay_tests::"
    "imported_mixed_and_empty_sources_reach_replay_and_replay_at_on_both_adapters",
    "nested_imported_fork_replay_tests::"
    "imported_nested_and_max_depth_histories_keep_exact_cuts_and_atomic_public_consumers",
]


def validate_result(output, test):
    summaries = re.findall(r"^test result: .*?$", output, re.MULTILINE)
    if (len(summaries) != 1
            or not re.fullmatch(
                r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
                r"\d+ filtered out; finished in \d+\.\d+s", summaries[0])
            or output.splitlines().count(f"test {test} ... ok") != 1):
        raise ValueError("expected exactly one successful named test, no ignored tests")


def profile_multisets(messages, checkout):
    result = {}
    for item in messages:
        if item.get("reason") != "compiler-artifact":
            continue
        target = item["target"]
        package = item["package_id"].replace(str(checkout), "<checkout>")
        key = json.dumps([package, target["name"], target["kind"],
                          sorted(item["features"])])
        result.setdefault(key, []).append(item["profile"])
    return result


def validate_profile_multisets(baseline, candidate):
    if not baseline or baseline.keys() != candidate.keys():
        raise ValueError("compiler artifact inventories differ or are empty")
    changed = 0
    for key, before in baseline.items():
        after = candidate[key]
        package, name, kinds, _ = json.loads(key)
        if len({json.dumps(profile, sort_keys=True) for profile in before}) != 1:
            raise ValueError("ambiguous baseline group has mixed or absent profiles")
        expected = before
        if name == "curve25519_dalek" and kinds == ["lib"]:
            if (len(before) != 1 or "curve25519-dalek" not in package
                    or before[0]["opt_level"] != "0"
                    or not before[0]["debug_assertions"] or not before[0]["overflow_checks"]):
                raise ValueError("unexpected curve build inventory/profile")
            expected = [dict(before[0], opt_level="3")]
            changed += 1
        normalized = lambda entries: sorted(json.dumps(p, sort_keys=True) for p in entries)
        if normalized(after) != normalized(expected):
            raise ValueError("artifact multiplicity or profile changed unexpectedly")
    if changed != 1:
        raise ValueError("expected exactly one optimized curve library")


def profile_self_test():
    # Bounded parser fixture derived from the observed duplicate serde_json and
    # sha2 emissions. Opaque output names differ; identity/profile fields agree.
    registry = "registry+https://github.com/rust-lang/crates.io-index#"
    fixtures = [
        (registry + "curve25519-dalek@4.1.3", "curve25519_dalek", [], "curve"),
        (registry + "serde_json@1.0.151", "serde_json", ["default", "std"], "serde-one"),
        (registry + "serde_json@1.0.151", "serde_json", ["default", "std"], "serde-two"),
        (registry + "sha2@0.11.0", "sha2", ["alloc", "default", "oid"], "sha-one"),
        (registry + "sha2@0.11.0", "sha2", ["alloc", "default", "oid"], "sha-two"),
        ("path+file:///baseline#pos-time@0.1.0", "pos_time", [], "workspace"),
    ]
    messages = [
        {"reason": "compiler-artifact", "package_id": package,
         "target": {"name": name, "kind": ["lib"]}, "features": features,
         "filenames": [f"/baseline/target/debug/deps/{output}.rlib"],
         "profile": {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
                     "overflow_checks": True, "test": name == "pos_time"}}
        for package, name, features, output in fixtures
    ]
    messages.append({"reason": "build-finished", "success": True})
    baseline = profile_multisets(messages, Path("/baseline"))
    assert len(baseline) == 4 and sum(map(len, baseline.values())) == 6
    candidate_messages = copy.deepcopy(messages)
    for item in candidate_messages:
        if item["reason"] != "compiler-artifact":
            continue
        item["package_id"] = item["package_id"].replace("/baseline", "/candidate")
        item["filenames"] = [p.replace("/baseline", "/candidate") for p in item["filenames"]]
        if item["target"]["name"] == "curve25519_dalek":
            item["profile"]["opt_level"] = "3"
    candidate = profile_multisets(candidate_messages, Path("/candidate"))
    validate_profile_multisets(baseline, candidate)
    validate_profile_multisets(
        baseline, profile_multisets(reversed(candidate_messages), Path("/candidate")))
    curve = next(key for key in baseline if json.loads(key)[1] == "curve25519_dalek")
    other = next(key for key in baseline if json.loads(key)[1] == "pos_time")
    duplicates = [key for key, value in baseline.items() if len(value) == 2]
    assert {json.loads(key)[1] for key in duplicates} == {"serde_json", "sha2"}
    invalid = [(baseline, baseline), (baseline, {}),
               (baseline, {key: value for key, value in candidate.items() if key != curve})]
    for field in ["debug_assertions", "overflow_checks"]:
        bad = copy.deepcopy(candidate)
        bad[curve][0][field] = False
        invalid.append((baseline, bad))
    bad = copy.deepcopy(candidate)
    bad[other][0]["opt_level"] = "3"
    invalid.append((baseline, bad))
    bad = copy.deepcopy(candidate)
    changed_identity = json.loads(other)
    changed_identity[3] = ["unexpected-feature"]
    bad[json.dumps(changed_identity)] = bad.pop(other)
    invalid.append((baseline, bad))
    for key in duplicates:
        missing = copy.deepcopy(candidate)
        missing[key].pop()
        invalid.append((baseline, missing))
        extra = copy.deepcopy(candidate)
        extra[key].append(copy.deepcopy(extra[key][0]))
        invalid.append((baseline, extra))
        altered = copy.deepcopy(candidate)
        altered[key][0]["debug_assertions"] = False
        invalid.append((baseline, altered))
    extra = copy.deepcopy(candidate)
    extra[curve].append(copy.deepcopy(extra[curve][0]))
    invalid.append((baseline, extra))
    extra_base = copy.deepcopy(baseline)
    extra_base[curve].append(copy.deepcopy(extra_base[curve][0]))
    extra_candidate = copy.deepcopy(extra_base)
    for profile in extra_candidate[curve]:
        profile["opt_level"] = "3"
    invalid.append((extra_base, extra_candidate))
    for field, value in [("opt_level", "1"), ("debug_assertions", False),
                         ("overflow_checks", False)]:
        bad_base = copy.deepcopy(baseline)
        bad_base[curve][0][field] = value
        bad_candidate = copy.deepcopy(bad_base)
        bad_candidate[curve][0]["opt_level"] = "3"
        invalid.append((bad_base, bad_candidate))
    heterogeneous = copy.deepcopy(baseline)
    heterogeneous[duplicates[0]][0]["opt_level"] = "1"
    unchanged = copy.deepcopy(heterogeneous)
    unchanged[curve][0]["opt_level"] = "3"
    invalid.append((heterogeneous, unchanged))
    exchanged = copy.deepcopy(unchanged)
    exchanged[duplicates[0]].reverse()
    invalid.append((heterogeneous, exchanged))
    empty = copy.deepcopy(baseline)
    empty[duplicates[0]] = []
    invalid.append((empty, candidate))
    for before, after in invalid:
        try:
            validate_profile_multisets(before, after)
        except ValueError:
            continue
        raise AssertionError("invalid build profile evidence accepted")
    return 2, len(invalid)


def self_test():
    good = (f"test {TESTS[0]} ... ok\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "96 filtered out; finished in 1.23s\n")
    validate_result(good, TESTS[0])
    invalid = [good.replace("1 passed", "0 passed"), good.replace("0 ignored", "1 ignored"),
               good.replace(TESTS[0], "wrong"), good + good,
               good.replace("0 failed", "1 failed"), ""]
    for value in invalid:
        try:
            validate_result(value, TESTS[0])
        except ValueError:
            continue
        raise AssertionError("invalid test evidence accepted")
    positives, refusals = profile_self_test()
    print(f"test/profile evidence: {positives + 1} positive controls and "
          f"{refusals + len(invalid)} refusals passed")


def run():
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != "arceushui/pigloros"
            or os.environ.get("GITHUB_REF") != "refs/heads/redmine/561-benchmark-diagnostic-0c05"):
        raise RuntimeError("this diagnostic may only build in its hosted branch workflow")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    artifacts = workspace / "artifacts"
    artifacts.mkdir(exist_ok=True)
    metadata = {key: os.environ.get(key) for key in (
        "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "ImageOS", "ImageVersion",
        "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUSTFLAGS")}
    metadata.update(revision=REVISION, order=ORDER, tests=TESTS,
                    scope="pos-time lib all-features; not the workspace feature-unified binary",
                    rustc=command(["rustc", "--version", "--verbose"]),
                    cargo=command(["cargo", "--version", "--verbose"]), cpu=command(["lscpu"]))
    binaries, build_profiles = {}, {}
    for owner in ["baseline", "candidate"]:
        checkout = workspace / owner
        if (command(["git", "rev-parse", "HEAD"], cwd=checkout) != REVISION
                or command(["git", "status", "--porcelain"], cwd=checkout)):
            raise RuntimeError("checkout identity/cleanliness mismatch")
        target = workspace / f"target-{owner}"
        environment = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_TERM_COLOR="never")
        arguments = ["cargo", "test", "--locked", "-p", "pos-time", "--lib", "--all-features",
                     "--no-run", "--message-format=json"]
        if owner == "candidate":
            arguments += ["--config", "profile.test.package.curve25519-dalek.opt-level=3"]
        started = time.monotonic()
        with (artifacts / f"build-{owner}.jsonl").open("w+") as output, (
                artifacts / f"build-{owner}.stderr").open("w") as errors:
            subprocess.run(arguments, cwd=checkout, env=environment, stdout=output,
                           stderr=errors, check=True, timeout=900)
            build_seconds = time.monotonic() - started
            output.seek(0)
            messages = [json.loads(line) for line in output if line.strip()]
        build_profiles[owner] = profile_multisets(messages, checkout)
        candidates = [item["executable"] for item in messages
                      if item.get("reason") == "compiler-artifact" and item.get("executable")
                      and item["target"]["name"] == "pos_time"
                      and item["target"]["kind"] == ["lib"] and item["profile"]["test"]]
        if len(candidates) != 1:
            raise RuntimeError("expected one pos-time lib test executable")
        binary = Path(candidates[0]).resolve()
        if not binary.is_relative_to(target):
            raise RuntimeError("executable escaped its target directory")
        binaries[owner] = binary
        metadata[owner] = {"arguments": arguments, "build_seconds": build_seconds,
                           "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
        if command(["git", "status", "--porcelain"], cwd=checkout):
            raise RuntimeError("build modified source checkout")
        (artifacts / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    validate_profile_multisets(build_profiles["baseline"], build_profiles["candidate"])
    (artifacts / "profiles.json").write_text(json.dumps(build_profiles, indent=2) + "\n")
    allowed = sorted(os.sched_getaffinity(0))
    selected = min(allowed)
    os.sched_setaffinity(0, {selected})
    metadata.update(allowed_cpus=allowed, measurement_cpu=selected)
    (artifacts / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    results = []
    for test_index, test in enumerate(TESTS):
        for index, owner in enumerate(ORDER):
            if os.sched_getaffinity(0) != {selected}:
                raise RuntimeError("measurement affinity changed")
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            started = time.monotonic()
            log_path = artifacts / f"test-{test_index}-{index}-{owner}.log"
            with log_path.open("w+") as log:
                subprocess.run([str(binaries[owner]), test, "--exact", "--include-ignored",
                                "--test-threads=1", "--color=never"], cwd=workspace / owner,
                               stdout=log, stderr=subprocess.STDOUT, check=True, timeout=300)
                elapsed = time.monotonic() - started
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                log.seek(0)
                validate_result(log.read(), test)
            result = {"test": test, "order": index, "owner": owner, "wall_seconds": elapsed,
                      "user_cpu_seconds": after.ru_utime - before.ru_utime,
                      "system_cpu_seconds": after.ru_stime - before.ru_stime,
                      "log_sha256": hashlib.sha256(log_path.read_bytes()).hexdigest()}
            results.append(result)
            print(json.dumps(result), flush=True)
            (artifacts / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Diagnostic complete; no required gate, baseline, or performance clearance changed.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif sys.argv[1:]:
        raise SystemExit("expected no arguments or --self-test")
    else:
        run()
