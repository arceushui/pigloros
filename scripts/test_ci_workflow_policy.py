#!/usr/bin/env python3
"""Contract tests for CI change scope and the core Rust gate policy."""

from __future__ import annotations

import ast
import copy
import fnmatch
import hashlib
import os
import pathlib
import shlex
import subprocess
import tempfile
import tomllib
import unittest

import yaml

import test_check_owner_runtime_custody_policy as custody_policy_tests
import test_merge_owner_bridge_lcov as native_lcov_tests
import owner_bridge_windows_workflow_policy as native_policy
from check_owner_runtime_custody_policy import UniqueKeys
from check_asan_ci_policy import EXPECTED_SDK_HEADROOM_STEP


ROOT = pathlib.Path(__file__).resolve().parent.parent
FILTER_PATH = ROOT / ".github" / "rust-scope.yml"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
CODEQL_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "codeql.yml"
RUST_CACHE_ACTION = "Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16"
TRUSTED_MAIN_SAVE_IF = "${{ github.ref == 'refs/heads/main' }}"
# Workflows that run on main (push or schedule) own main-written caches. The
# pull-request-only mutation and sim1 proof-risk workflows keep PR-scoped keys.
MAIN_WRITER_WORKFLOW_PATHS = (
    CI_WORKFLOW_PATH,
    ROOT / ".github" / "workflows" / "fuzz.yml",
    ROOT / ".github" / "workflows" / "memory-store-benchmark.yml",
    ROOT / ".github" / "workflows" / "thread-sanitizer.yml",
)
TRUSTED_MAIN_DOCKER_CACHE_TO = (
    "${{ github.ref == 'refs/heads/main' && 'type=gha,mode=max' || '' }}"
)
CORE_CACHE_KEYS = {
    "feature-matrix": "feature-matrix",
    "test": "test",
    "test-shard": "test-nextest",
    "clippy": "clippy",
    "coverage": "coverage",
}
CORE_JOB_NAMES = ("fmt", "feature-matrix", "test", "test-shard", "clippy", "coverage")
CORE_GATE_JOB_NAMES = ("fmt", "feature-matrix", "test", "test-shards", "clippy", "coverage")
FEATURE_MATRIX_STEPS = (
    {
        "name": "cargo check (no default features)",
        "run": "cargo check --workspace --all-targets --no-default-features --locked",
    },
    {
        "name": "Plugin trust registry Memory vectors (no default features)",
        "run": "cargo test -p pos-store --no-default-features "
        "--test plugin_trust_registry_memory_public "
        "--test plugin_trust_registry_memory_policy_public "
        "--test plugin_trust_registry_memory_evaluation_public --locked\n",
    },
    {
        "name": "cargo check (all features, all targets)",
        "run": "cargo check --workspace --all-targets --all-features --locked",
    },
    {
        "name": "Prove reference evaluator implementation independence",
        "run": "bash scripts/check-reference-evaluator-independence.sh",
    },
    {
        "name": "Prove the conformance adapter dependency graph",
        "run": "bash scripts/check-adapter-graph.sh",
    },
)
WORKSPACE_DOCTEST_STEP = {
    "name": "cargo test doctests (all features, ignored included)",
    "run": "set -euo pipefail\n"
    "cargo test --workspace --all-features --locked --doc -- --include-ignored "
    "2>&1 | tee /tmp/cargo-doctest.log\n",
}
WORKSPACE_RUSTDOC_STEP = {
    "name": "cargo doc (warnings denied)",
    "env": {"CARGO_INCREMENTAL": "0", "RUSTDOCFLAGS": "-D warnings"},
    "run": "cargo doc --workspace --all-features --no-deps --locked",
}
RUSTDOC_JOB_IF = (
    "${{ !cancelled() && needs.ci_change_scope.result == 'success' && "
    "needs.cargo-crap.result == 'success' && "
    "(needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request') }}"
)
MAIN_PUSH_TRIGGER = {"branches": ["main"]}
PREFLIGHT_GATE_IF = "${{ always() }}"
REQUIRED_PREFLIGHT_NEEDS = ("ci_change_scope", "pinned-dependencies", "owner-bridge-windows")
PINNED_DEPENDENCIES_NEEDS = "ci_change_scope"
PINNED_DEPENDENCIES_IF = (
    "${{ needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request' }}"
)
CI_WORKFLOW_POLICY_TEST_STEP = {
    "name": "Test CI workflow policy",
    "run": "python scripts/test_ci_workflow_policy.py",
}
EXPECTED_EXCLUDES = {
    "!**/*.md",
    "!**/*.mdx",
    "!**/*.adoc",
    "!**/*.rst",
    "!.agents/**",
    "!docs/**",
}
CORE_JOB_NEEDS = ["ci_change_scope", "preflight-gate"]
CORE_JOB_IF = (
    "${{ !cancelled() && needs.preflight-gate.result == 'success' && "
    "(needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request') }}"
)


def assert_core_sdk_headroom(workflow: dict) -> None:
    """Protect the two workers observed exhausting disk during compilation."""
    for job_name in ("test-shard", "coverage"):
        steps = workflow["jobs"][job_name]["steps"]
        if (
            len(steps) < 2
            or steps[0].get("uses")
            != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
            or steps[1] != EXPECTED_SDK_HEADROOM_STEP
            or sum(
                step.get("name") == EXPECTED_SDK_HEADROOM_STEP["name"]
                for step in steps
            )
            != 1
        ):
            raise AssertionError(
                f"{job_name} must reclaim bounded SDK headroom immediately after checkout"
            )


def load_patterns() -> list[str]:
    with FILTER_PATH.open(encoding="utf-8") as stream:
        filters = yaml.load(stream, Loader=UniqueKeys)
    if not isinstance(filters, dict) or not isinstance(filters.get("rust"), list):
        raise AssertionError("rust-scope.yml must define a rust pattern list")
    patterns = filters["rust"]
    if not all(isinstance(pattern, str) for pattern in patterns):
        raise AssertionError("rust-scope.yml patterns must be strings")
    return patterns


def load_workflow(workflow_path: pathlib.Path) -> dict:
    with workflow_path.open(encoding="utf-8") as stream:
        workflow = yaml.load(stream, Loader=UniqueKeys)
    if not isinstance(workflow, dict):
        raise AssertionError(f"{workflow_path} must contain a mapping")
    return workflow


def workflow_triggers(workflow: dict) -> dict:
    """Return the top-level event mapping across PyYAML's YAML 1.1 key forms."""
    triggers = workflow.get("on")
    if triggers is None:
        triggers = workflow.get(True)
    if not isinstance(triggers, dict):
        raise AssertionError("ci.yml must define an event mapping")
    return triggers


def assert_core_jobs_run_on_main_push(workflow: dict) -> None:
    """Require the core Rust gates to remain reachable after a trusted main push."""
    for job_name in CORE_JOB_NAMES:
        job = workflow["jobs"].get(job_name)
        if not isinstance(job, dict):
            raise AssertionError(f"missing core Rust job: {job_name}")
        if job.get("needs") != CORE_JOB_NEEDS:
            raise AssertionError(f"{job_name} must wait for successful preflight")
        if job.get("if") != CORE_JOB_IF:
            raise AssertionError(f"{job_name} must remain reachable on a main push")


def assert_main_push_prerequisites(workflow: dict) -> None:
    """Keep the scope and preflight path available to every main push."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        raise AssertionError("ci.yml must define a jobs mapping")

    scope = jobs.get("ci_change_scope")
    if not isinstance(scope, dict):
        raise AssertionError("ci.yml must define ci_change_scope")
    if "needs" in scope:
        raise AssertionError("ci_change_scope must have no prerequisites")
    if "if" in scope:
        raise AssertionError("ci_change_scope must remain unconditional")

    pinned_dependencies = jobs.get("pinned-dependencies")
    if not isinstance(pinned_dependencies, dict):
        raise AssertionError("ci.yml must define pinned-dependencies")
    if pinned_dependencies.get("needs") != PINNED_DEPENDENCIES_NEEDS:
        raise AssertionError("pinned-dependencies must wait for ci_change_scope")
    if pinned_dependencies.get("if") != PINNED_DEPENDENCIES_IF:
        raise AssertionError(
            "pinned-dependencies must remain reachable on a main push"
        )
    pinned_steps = pinned_dependencies.get("steps")
    if (
        not isinstance(pinned_steps, list)
        or CI_WORKFLOW_POLICY_TEST_STEP not in pinned_steps
    ):
        raise AssertionError("pinned-dependencies must run the CI workflow policy test")

    preflight = jobs.get("preflight-gate")
    if not isinstance(preflight, dict):
        raise AssertionError("ci.yml must define preflight-gate")
    if preflight.get("if") != PREFLIGHT_GATE_IF:
        raise AssertionError("preflight-gate must remain reachable on a main push")
    preflight_needs = preflight.get("needs")
    if not isinstance(preflight_needs, list) or not set(REQUIRED_PREFLIGHT_NEEDS).issubset(
        preflight_needs
    ):
        raise AssertionError("preflight-gate must retain scope and policy dependencies")


def assert_core_rust_cache_contract(workflow: dict) -> None:
    """Require the trusted writer and PR restore paths for core Rust caches."""
    triggers = workflow_triggers(workflow)
    if "pull_request" not in triggers or triggers["pull_request"] is not None:
        raise AssertionError("ci.yml must retain an unfiltered pull_request trigger for cache restores")

    push = triggers.get("push")
    if push != MAIN_PUSH_TRIGGER:
        raise AssertionError("ci.yml must retain a main push trigger for trusted cache writers")

    assert_main_push_prerequisites(workflow)
    assert_core_jobs_run_on_main_push(workflow)
    for job_name, shared_key in CORE_CACHE_KEYS.items():
        steps = workflow["jobs"][job_name]["steps"]
        cache_steps = [
            step
            for step in steps
            if isinstance(step, dict)
            and isinstance(step.get("uses"), str)
            and step["uses"].startswith("Swatinem/rust-cache@")
        ]
        if len(cache_steps) != 1:
            raise AssertionError(f"{job_name} must contain exactly one Rust cache step")
        cache_step = cache_steps[0]
        if cache_step["uses"] != RUST_CACHE_ACTION:
            raise AssertionError(f"{job_name} must use the pinned Rust cache action")
        if cache_step.get("with") != {
            "shared-key": shared_key,
            "save-if": TRUSTED_MAIN_SAVE_IF,
        }:
            raise AssertionError(f"{job_name} cache must use the trusted-main policy")
        if "if" in cache_step:
            raise AssertionError(f"{job_name} cache must remain reachable on pull requests")


TEST_SHARDS_NEEDS = ["test-shard"]
TEST_SHARDS_IF = "${{ !cancelled() && needs.test-shard.result == 'success' }}"
TEST_SHARDS_CORE_CHECK = 'test "${TEST_SHARDS_RESULT}" = "${expected}"'
TEST_SHARD_COUNT = 3


def step_runs(job: dict) -> str:
    return "\n".join(str(step.get("run", "")) for step in job.get("steps", []))


def assert_test_shards_gate(workflow: dict) -> None:
    """Require the shard aggregate to run only on all-shard success and block core-gate."""
    jobs = workflow["jobs"]
    aggregate = jobs.get("test-shards")
    if not isinstance(aggregate, dict):
        raise AssertionError("ci.yml must define the test-shards aggregate")
    if aggregate.get("needs") != TEST_SHARDS_NEEDS:
        raise AssertionError("test-shards must wait for every test shard")
    if aggregate.get("if") != TEST_SHARDS_IF:
        raise AssertionError("test-shards must run only after every shard succeeded")
    shard = jobs.get("test-shard", {})
    strategy = shard.get("strategy", {})
    expected = list(range(1, TEST_SHARD_COUNT + 1))
    if strategy.get("matrix", {}).get("shard") != expected:
        raise AssertionError(f"test-shard matrix must be shards {expected}")
    if strategy.get("fail-fast") is not False:
        raise AssertionError("test-shard must not cancel sibling shards on failure")
    count = str(TEST_SHARD_COUNT)
    shard_runs = step_runs(shard)
    aggregate_runs = step_runs(aggregate)
    for fragment, runs in (
        (f'--partition "slice:${{SHARD}}/{count}"', shard_runs),
        (f"nextest partition: slice:%s/{count}", shard_runs),
        (f"for shard in {' '.join(map(str, expected))}; do", aggregate_runs),
        (f"slice:${{shard}}/{count}", aggregate_runs),
        (f"--partitioned={count}", aggregate_runs),
    ):
        if fragment not in runs:
            raise AssertionError(f"shard count must agree everywhere: missing {fragment}")
    core = jobs["core-gate"]
    if "test-shards" not in core.get("needs", []):
        raise AssertionError("core-gate must wait for test-shards")
    steps = core.get("steps", [])
    if not any(
        step.get("env", {}).get("TEST_SHARDS_RESULT") == "${{ needs.test-shards.result }}"
        and TEST_SHARDS_CORE_CHECK in step.get("run", "")
        for step in steps
    ):
        raise AssertionError("core-gate must require the test-shards result")


def assert_pull_requests_never_write_caches(workflow: dict) -> None:
    """Keep every cache write on main so pull requests cannot evict main's caches.

    The repository cache budget is shared; per-PR writes previously pushed it
    past the limit and evicted the trusted main caches every PR restores.
    """
    for job_name, job in workflow["jobs"].items():
        for step in job.get("steps", []):
            uses = step.get("uses", "") if isinstance(step, dict) else ""
            if uses.startswith("Swatinem/rust-cache@"):
                if step.get("with", {}).get("save-if") != TRUSTED_MAIN_SAVE_IF:
                    raise AssertionError(f"{job_name} Rust cache must save only from main")
            if uses.startswith("docker/build-push-action@"):
                cache_to = step.get("with", {}).get("cache-to")
                if cache_to is not None and cache_to != TRUSTED_MAIN_DOCKER_CACHE_TO:
                    raise AssertionError(f"{job_name} Docker cache must save only from main")


STANDARD_STAGE_RUNNER_CAP = 8
# Heavy jobs released by cargo-crap. Browser parity follows WASM packaging on
# the same budget, and standard-gate is the lightweight fan-in.
STANDARD_STAGE_JOBS = frozenset(
    {
        "rustdoc",
        "reference-evaluator-release",
        "materialize-conformance-bundles",
        "audit",
        "codeql",
        "docker-build",
        "world-client-wasm",
        "asan-build",
    }
)


def job_needs(job: dict) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def assert_standard_stage_runner_cap(workflow: dict) -> None:
    """Keep the normal stage within its documented concurrent-runner cap."""
    jobs = workflow["jobs"]
    started = {
        name
        for name, job in jobs.items()
        if name != "standard-gate" and "cargo-crap" in job_needs(job)
    }
    if started != STANDARD_STAGE_JOBS:
        raise AssertionError("standard stage must start exactly the counted jobs")
    if len(started) > STANDARD_STAGE_RUNNER_CAP:
        raise AssertionError("standard stage must start at most eight runners")
    for name in sorted(started):
        if "strategy" in jobs[name]:
            raise AssertionError(f"standard stage job {name} must use one runner")
    gate_needs = job_needs(jobs.get("standard-gate", {}))
    missing = sorted(started - set(gate_needs))
    if missing:
        raise AssertionError(f"standard-gate must wait for every standard-stage job: {missing}")


def assert_owner_windows_lane(workflow: dict, native: dict) -> None:
    """The Windows lane blocks core CI and reuses the completed ledger slot."""
    expected = {
        "name": "owner-bridge-windows",
        "needs": ["ci_change_scope", "ledger-windows"],
        "if": "${{ needs.ci_change_scope.outputs.rust == 'true' }}",
        "uses": "./.github/workflows/owner-bridge-windows.yml",
        "permissions": {"contents": "read"},
    }
    if workflow["jobs"].get("owner-bridge-windows") != expected:
        raise AssertionError("owner Windows lane must follow the completed ledger runner")
    gate = workflow["jobs"]["preflight-gate"]
    if "owner-bridge-windows" not in job_needs(gate):
        raise AssertionError("owner Windows lane must block preflight")
    step = gate["steps"][0]
    if step["env"].get("OWNER_WINDOWS_RESULT") != "${{ needs.owner-bridge-windows.result }}":
        raise AssertionError("preflight must use the actual owner Windows result")
    for result in ("success", "skipped"):
        if f'test "${{OWNER_WINDOWS_RESULT}}" = {result}' not in step["run"]:
            raise AssertionError("preflight must enforce the owner Windows scope result")
    try:
        native_policy.check(native)
    except native_policy.PolicyError as error:
        raise AssertionError(str(error)) from error


def excluded(path: str, patterns: list[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(path, pattern[1:])
        or fnmatch.fnmatchcase(path, pattern[1:].removeprefix("**/"))
        for pattern in patterns
        if pattern.startswith("!")
    )


def assert_parallel_validation_contract(workflow: dict) -> None:
    """Moving checks may change scheduling, never scope or failure semantics."""
    assert_core_jobs_run_on_main_push(workflow)
    jobs = workflow["jobs"]
    for owner, required in (
        ("feature-matrix", FEATURE_MATRIX_STEPS),
        ("test", (WORKSPACE_DOCTEST_STEP,)),
        ("rustdoc", (WORKSPACE_RUSTDOC_STEP,)),
    ):
        job = jobs[owner]
        if job.get("timeout-minutes") != 30 or "continue-on-error" in job:
            raise AssertionError(f"{owner} must keep its blocking 30-minute limit")
        for expected in required:
            occurrences = [
                (name, step)
                for name, candidate in jobs.items()
                for step in candidate.get("steps", [])
                if step.get("name") == expected["name"]
                or step.get("run") == expected["run"]
            ]
            if occurrences != [(owner, expected)]:
                raise AssertionError(f"{owner} must run the exact required step once")
    rustdoc = jobs["rustdoc"]
    if (rustdoc.get("needs") != ["ci_change_scope", "cargo-crap"]
            or rustdoc.get("if") != RUSTDOC_JOB_IF):
        raise AssertionError("rustdoc must retain its successful standard-stage prerequisites")
    if any(
        str(step.get("uses", "")).startswith("Swatinem/rust-cache@")
        for step in rustdoc["steps"]
    ):
        raise AssertionError("rustdoc must not restore the broken documentation target cache")
    gate = jobs["core-gate"]
    if gate.get("needs") != ["ci_change_scope", "preflight-gate", *CORE_GATE_JOB_NAMES]:
        raise AssertionError("core-gate must require every parallel core job")
    if gate.get("if") != "${{ always() }}" or "continue-on-error" in gate:
        raise AssertionError("core-gate must remain unconditional and blocking")
    step = gate["steps"][0]
    if "if" in step or "continue-on-error" in step:
        raise AssertionError("core-gate result check must remain blocking")
    for name in CORE_GATE_JOB_NAMES:
        variable = name.upper().replace("-", "_") + "_RESULT"
        if step["env"].get(variable) != "${{ needs." + name + ".result }}":
            raise AssertionError("core-gate must read every actual job result")
        if f'test "${{{variable}}}" = "${{expected}}"' not in step["run"]:
            raise AssertionError("core-gate must enforce every actual job result")


def rust_gate_required(paths: list[str], patterns: list[str]) -> bool:
    return any(not excluded(path, patterns) for path in paths)


def assert_codeql_preparation_contract(workflow: dict) -> None:
    """Prepare real missing inputs without narrowing the native analysis."""
    job = workflow["jobs"]["analyze"]
    steps = job["steps"]
    if job["timeout-minutes"] != 30 or len(steps) != 5:
        raise AssertionError("retain the analysis deadline and complete step inventory")
    if steps[3:] != [
        {"uses": "github/codeql-action/init@9b3254085494b55a0f7c4c2b3d2d52cc712ce370",
         "with": {"languages": "rust", "build-mode": "none"}},
        {"uses": "github/codeql-action/analyze@9b3254085494b55a0f7c4c2b3d2d52cc712ce370",
         "with": {"category": "/language:rust"}},
    ]:
        raise AssertionError("retain the unchanged full CodeQL initialization and analysis")
    # Exact reviewed-program snapshots, not a shell semantics oracle. Preserve
    # every byte, including heredoc data; update only with reviewed setup changes.
    required = (
        (5, "28c278b217fbafce26f3940be27c2dea987e012b986564110dbccb1ad7e21e0c"),
        (1, "8ff9e3fadf283e88daefd380c1de1bdcf915e9ee321bcc8dd9b850c9e6382978"),
    )
    for step, (deadline, digest) in zip(steps[1:3], required):
        if set(step) != {"name", "run", "timeout-minutes"} or step["timeout-minutes"] != deadline:
            raise AssertionError("source preparation must remain bounded, unconditional and blocking")
        if hashlib.sha256(step["run"].encode()).hexdigest() != digest:
            raise AssertionError("source preparation must retain its real inputs and refusal checks")


class CiWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.patterns = load_patterns()

    def test_filter_has_conservative_positive_default(self) -> None:
        self.assertEqual(self.patterns[0], "**")
        self.assertEqual(set(self.patterns[1:]), EXPECTED_EXCLUDES)

    def test_codeql_prepares_inputs_before_unchanged_analysis(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH.with_name("codeql.yml"))
        assert_codeql_preparation_contract(workflow)
        steps = workflow["jobs"]["analyze"]["steps"]
        installer = (ROOT / "plugins/community/examples/compatibility-prototype/install-tools.sh").read_text()
        for prefix in ("url=", "digest="):
            value = next(line[len(prefix):] for line in steps[1]["run"].splitlines()
                         if line.startswith(prefix))
            self.assertIn(value, installer)
        for step in steps[1:3]:
            subprocess.run(["bash", "-n"], input=step["run"], text=True, check=True)
        source = steps[2]["run"].split("python3 - <<'PY'\n")[1].split("\nPY\n")[0]
        tree = ast.parse(source)
        self.assertEqual(len(tree.body), 2)
        call = tree.body[1].value
        self.assertEqual(call.func.attr, "write_text")
        self.assertEqual(ast.literal_eval(call.func.value.args[0]), "scripts/asan/Cargo.toml")
        self.assertEqual(tomllib.loads(ast.literal_eval(call.args[0])), {
            "package": {"name": "pigloros-asan-extraction-canary", "version": "0.0.0", "edition": "2021"},
            "bin": [{"name": "intentional-leak", "path": "intentional-leak.rs"}],
            "workspace": {},
        })

    def test_codeql_preparation_refuses_missing_or_weakened_inputs(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH.with_name("codeql.yml"))
        for index in (1, 2):
            for key, value in (("if", "false"), ("continue-on-error", True), ("env", {})):
                changed = copy.deepcopy(workflow)
                changed["jobs"]["analyze"]["steps"][index][key] = value
                with self.assertRaises(AssertionError):
                    assert_codeql_preparation_contract(changed)
            changed = copy.deepcopy(workflow)
            del changed["jobs"]["analyze"]["steps"][index]
            with self.assertRaises(AssertionError):
                assert_codeql_preparation_contract(changed)
        for original, replacement in (("sha256sum --check --strict -", "true"),
                                      ("test ! -e scripts/asan/Cargo.toml", "true"),
                                      ("test -s", "test -e")):
            changed = copy.deepcopy(workflow)
            for step in changed["jobs"]["analyze"]["steps"][1:3]:
                step["run"] = step["run"].replace(original, replacement)
            with self.assertRaises(AssertionError):
                assert_codeql_preparation_contract(changed)
        changed = copy.deepcopy(workflow)
        changed["jobs"]["analyze"]["steps"][3]["with"]["config"] = "paths-ignore: [scripts]"
        with self.assertRaises(AssertionError):
            assert_codeql_preparation_contract(changed)
        changed = copy.deepcopy(workflow)
        changed["jobs"]["analyze"]["steps"][1]["run"] += "true || true\n"
        with self.assertRaises(AssertionError):
            assert_codeql_preparation_contract(changed)

    def test_codeql_preparation_refuses_non_executing_checksum_text(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH.with_name("codeql.yml"))
        run = workflow["jobs"]["analyze"]["steps"][1]["run"]
        checksum = next(line for line in run.splitlines()
                        if line.startswith("printf ") and "sha256sum --check" in line)
        quoted = "'" + checksum.replace("'", "'\\''") + "'"
        for replacement in ("# " + checksum, ": " + quoted, "echo " + quoted,
                            "if false; then\n" + checksum + "\nfi",
                            "unused_checksum() {\n" + checksum + "\n}"):
            changed = copy.deepcopy(workflow)
            changed["jobs"]["analyze"]["steps"][1]["run"] = run.replace(checksum, replacement)
            with self.assertRaises(AssertionError):
                assert_codeql_preparation_contract(changed)

    def test_codeql_generates_bindings_for_each_declared_rust_guest_owner(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH.with_name("codeql.yml"))
        run = workflow["jobs"]["analyze"]["steps"][1]["run"]
        # Execute the real owner-selection/generation section, not downloads.
        program = run.split('"$tools_dir/wit-bindgen" --version\n', 1)[1]
        program = program.rsplit('test -z "$(git diff --name-only HEAD)"', 1)[0]
        prototype = pathlib.Path("plugins/community/examples/compatibility-prototype")
        cases = (
            ("legacy", False, True),
            ("both", True, True),
            ("partial-probe", True, False),
            ("missing-required-source", False, False),
            ("preexisting-output", False, False),
            ("generator-failure", True, False),
            ("empty-output", True, False),
            ("dangling-probe", False, False),
            ("probe-is-file", False, False),
            ("linked-probe", False, False),
        )
        for case, has_probe, success in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                prefix="pigloros-codeql-owners-",
                dir="/dev/shm" if pathlib.Path("/dev/shm").is_dir() else None,
            ) as temporary:
                root = pathlib.Path(temporary)
                tools = root / "tools"
                tools.mkdir()
                generator = tools / "wit-bindgen"
                generator.write_text(
                    '#!/bin/sh\nset -eu\n'
                    'test "$#" -eq 6\n'
                    'test "$1" = rust\n'
                    'test "$2" = --world\n'
                    'test "$3" = community-plugin\n'
                    'test "$4" = --out-dir\n'
                    'test "$6" = plugins/community/wit\n'
                    'test -d "$6"\n'
                    'printf "%s\\n" "$5" >> "$PIGLOROS_CODEQL_OWNER_TRACE"\n'
                    'case "$PIGLOROS_CODEQL_STUB_MODE" in\n'
                    '  generator-failure) exit 37 ;;\n'
                    '  empty-output) : > "$5/community_plugin.rs" ;;\n'
                    '  *) printf "generated\\n" > "$5/community_plugin.rs" ;;\n'
                    'esac\n',
                    encoding="utf-8",
                )
                generator.chmod(0o755)
                (root / "plugins/community/wit").mkdir(parents=True)
                guests = ["rust-guest", "probe-guest"] if has_probe else ["rust-guest"]
                for guest in guests:
                    directory = root / prototype / guest
                    (directory / "src").mkdir(parents=True)
                    if case != "partial-probe" or guest != "probe-guest":
                        (directory / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
                    if case != "missing-required-source":
                        (directory / "src/lib.rs").write_text("// owner\n", encoding="utf-8")
                if case == "preexisting-output":
                    (root / prototype / "rust-guest/generated").mkdir()
                elif case == "dangling-probe":
                    (root / prototype / "probe-guest").symlink_to("absent-owner")
                elif case == "probe-is-file":
                    (root / prototype / "probe-guest").write_text("not a directory\n", encoding="utf-8")
                elif case == "linked-probe":
                    other = root / "separate-owner"
                    (other / "src").mkdir(parents=True)
                    (other / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
                    (other / "src/lib.rs").write_text("// owner\n", encoding="utf-8")
                    (root / prototype / "probe-guest").symlink_to(other, target_is_directory=True)
                trace = root / "owner-trace"
                result = subprocess.run(
                    ["bash", "-c", "set -euo pipefail\n"
                     + "tools_dir=" + shlex.quote(str(tools)) + "\n" + program],
                    cwd=root,
                    env=dict(os.environ, PIGLOROS_CODEQL_OWNER_TRACE=str(trace),
                             PIGLOROS_CODEQL_STUB_MODE=case),
                    capture_output=True, text=True, check=False, timeout=10,
                )
                self.assertEqual(result.returncode == 0, success, result.stderr)
                if success:
                    self.assertEqual(
                        trace.read_text(encoding="utf-8").splitlines(),
                        [str(prototype / guest / "generated") for guest in guests],
                    )
                    for guest in guests:
                        self.assertEqual(
                            (root / prototype / guest / "generated/community_plugin.rs")
                            .read_text(encoding="utf-8"), "generated\n",
                        )

    def test_scope_jobs_use_trusted_base_and_fail_closed(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        scope = workflow["jobs"]["ci_change_scope"]
        steps = scope["steps"]
        self.assertEqual(
            steps[0]["with"]["ref"],
            "${{ github.event.pull_request.base.sha }}",
        )
        filter_step = next(step for step in steps if step.get("id") == "scope")
        self.assertEqual(filter_step["with"]["filters"], ".github/rust-scope.yml")
        self.assertIn("hashFiles('.github/rust-scope.yml') != ''", filter_step["if"])
        self.assertIs(filter_step["continue-on-error"], True)
        fallback_step = next(step for step in steps if step.get("id") == "fallback")
        self.assertEqual(fallback_step["if"], "steps.scope.outcome == 'failure'")
        self.assertIn("printf 'rust=true\\n' >> \"$GITHUB_OUTPUT\"", fallback_step["run"])
        full_step = next(step for step in steps if step.get("id") == "full")
        self.assertIn("hashFiles('.github/rust-scope.yml') == ''", full_step["if"])
        self.assertEqual(
            scope["outputs"]["rust"],
            "${{ steps.fallback.outputs.rust || steps.scope.outputs.rust || "
            "steps.full.outputs.rust }}",
        )

    def test_codeql_runs_for_documentation_only_pull_requests(self) -> None:
        # The main ruleset's code_scanning rule needs an uploaded analysis for
        # every PR head, so a Rust-scope skip would leave docs-only PRs unmergeable.
        workflow = load_workflow(CI_WORKFLOW_PATH)
        jobs = workflow["jobs"]
        condition = " ".join(jobs["codeql"]["if"].split())
        self.assertIn("needs.cargo-crap.result == 'skipped'", condition)
        self.assertNotIn("outputs.rust == 'true'", condition)
        required = jobs["codeql-required"]
        self.assertEqual(required["name"], "CodeQL (Rust)")
        self.assertEqual(required["needs"], ["codeql"])
        self.assertIn('test "${CODEQL_RESULT}" = success', required["steps"][0]["run"])
        standard = jobs["standard-gate"]["steps"][0]["run"]
        self.assertIn('test "${CODEQL_RESULT}" = success', standard)
        self.assertNotIn('"${CODEQL_RESULT}"', standard.split("for result in")[1])
        codeql = load_workflow(CODEQL_WORKFLOW_PATH)
        self.assertEqual(list(codeql["jobs"]), ["analyze"])
        self.assertNotIn("if", codeql["jobs"]["analyze"])

    def test_documentation_only_paths_skip_rust_gate(self) -> None:
        paths = [
            "README.md",
            "guide/topic.mdx",
            "adr/decision.adoc",
            "notes/history.rst",
            ".agents/skills/example.md",
            "docs/reference.txt",
        ]
        self.assertFalse(rust_gate_required(paths, self.patterns))

    def test_unknown_and_build_inputs_require_rust_gate(self) -> None:
        paths = ("src/lib.rs", "Cargo.toml", "plugin.wit", ".github/workflows/ci.yml")
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(rust_gate_required([path], self.patterns))

    def test_deleted_and_renamed_rust_inputs_require_rust_gate(self) -> None:
        self.assertTrue(rust_gate_required(["old.rs"], self.patterns))
        self.assertTrue(rust_gate_required(["old.rs", "moved.md"], self.patterns))

    def test_ci_gate_distinguishes_scope_skips_from_unconditional_jobs(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        gate = workflow["jobs"]["ci-gate"]
        self.assertIn("ci_change_scope", gate["needs"])
        self.assertEqual(
            gate["steps"][0]["env"]["SCOPE_JOB_RESULT"],
            "${{ needs.ci_change_scope.result }}",
        )
        self.assertEqual(
            gate["steps"][0]["env"]["RUST_SCOPE_RESULT"],
            "${{ needs.ci_change_scope.outputs.rust }}",
        )
        run = gate["steps"][0]["run"]
        normalized_run = " ".join(run.replace("\\\n", " ").split())
        self.assertIn(
            "for result_name in PREFLIGHT_RESULT CORE_RESULT STANDARD_RESULT ASAN_RESULT",
            normalized_run,
        )
        self.assertIn('expected_mutation=skipped', run)
        self.assertIn('expected_mutation=success', run)
        self.assertIn('"${RUST_SCOPE_RESULT}" = true', run)
        self.assertIn('"${SCOPE_JOB_RESULT}" != "success"', run)

    def test_core_gates_run_after_successful_preflight_on_push(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        assert_core_jobs_run_on_main_push(workflow)

    def test_windows_owner_lane_is_blocking_and_sequenced_before_core(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        assert_owner_windows_lane(workflow, native)
        assert_standard_stage_runner_cap(workflow)

    def test_every_native_evidence_step_is_mandatory_and_ordered(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        assert_owner_windows_lane(workflow, native)
        steps = native["jobs"]["owner-bridge-windows"]["steps"]
        for index, _ in enumerate(steps):
            for action in ("remove", "skip", "ignore", "fabricate", "duplicate"):
                changed = copy.deepcopy(native)
                candidates = changed["jobs"]["owner-bridge-windows"]["steps"]
                if action == "remove": candidates.pop(index)
                elif action == "skip": candidates[index]["if"] = "false"
                elif action == "ignore": candidates[index]["continue-on-error"] = True
                elif action == "fabricate": candidates[index] = {"run": "echo fabricated > coverage.json"}
                else: candidates.insert(index, copy.deepcopy(candidates[index]))
                with self.subTest(index=index, action=action), self.assertRaises(AssertionError):
                    assert_owner_windows_lane(workflow, changed)
        changed = copy.deepcopy(native)
        changed["jobs"]["owner-bridge-windows"]["steps"].reverse()
        with self.assertRaises(AssertionError):
            assert_owner_windows_lane(workflow, changed)

    def test_native_graph_controls_types_and_producer_indirection_fail_closed(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        for mutate in (
            lambda w: w.update(permissions={"contents": "write"}),
            lambda w: w.update(env={"FAKE_COVERAGE": "1"}),
            lambda w: w[True].update(pull_request_target={}),
            lambda w: w["jobs"].update(fabricate={"runs-on": "ubuntu-latest"}),
            lambda w: w["jobs"]["owner-bridge-windows"].update(**{"timeout-minutes": 60.0}),
            lambda w: w["jobs"]["owner-bridge-windows"].update(**{"if": "false"}),
            lambda w: w["jobs"]["owner-bridge-windows"]["steps"][0]["with"].update(**{"persist-credentials": 0}),
        ):
            changed = copy.deepcopy(native); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(AssertionError):
                assert_owner_windows_lane(workflow, changed)
        native_policy.check_repository()
        original = native_policy.producer_sources()
        for name, source in original.items():
            for changed in ("", source + "\n# unreviewed producer\n", "print('fabricated')\n"):
                sources = dict(original, **{name: changed})
                with self.subTest(name=name), self.assertRaises(native_policy.PolicyError):
                    native_policy.check(native, sources)
        with self.assertRaises(native_policy.PolicyError):
            native_policy.check(native, {})

    def test_desktop_observer_cannot_change_native_evidence_or_control_processes(self) -> None:
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        coverage = native["jobs"]["owner-bridge-windows"]["steps"][8]
        for before, after in (
            ("--include-ignored", "--include-ignored --skip native"),
            (" --nocapture", ""),
            ("$nativeResult = $LASTEXITCODE", "$nativeResult = 0"),
            ("[System.IO.File]::WriteAllText($marker, 'stop')", "Write-Output 'not stopped'"),
        ):
            changed = copy.deepcopy(native)
            run = changed["jobs"]["owner-bridge-windows"]["steps"][8]["run"]
            self.assertEqual(run.count(before), 1)
            changed["jobs"]["owner-bridge-windows"]["steps"][8]["run"] = run.replace(before, after)
            with self.assertRaises(native_policy.PolicyError):
                native_policy.check(changed)
        self.assertIn("cargo llvm-cov", coverage["run"])
        sources = native_policy.producer_sources()
        name = "scripts/observe-owner-desktop.ps1"
        for payload in ("Stop-Process -Id 1", "Get-CimInstance Win32_Process | Select-Object CommandLine"):
            altered = dict(sources, **{name: sources[name] + "\n" + payload})
            with self.assertRaises(native_policy.PolicyError):
                native_policy.check(native, altered)

    def test_windows_owner_lane_rejects_missing_or_weakened_gates(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        for change in (
            lambda w: w["jobs"].pop("owner-bridge-windows"),
            lambda w: w["jobs"]["owner-bridge-windows"].update(needs=["ci_change_scope"]),
            lambda w: w["jobs"]["owner-bridge-windows"].update(**{"continue-on-error": True}),
            lambda w: w["jobs"]["preflight-gate"]["needs"].remove("owner-bridge-windows"),
            lambda w: w["jobs"]["preflight-gate"]["steps"][0]["env"].update(OWNER_WINDOWS_RESULT="success"),
            lambda w: w["jobs"]["preflight-gate"]["steps"][0].update(run="true"),
        ):
            mutated = copy.deepcopy(workflow)
            change(mutated)
            with self.assertRaises(AssertionError):
                assert_owner_windows_lane(mutated, native)

    def test_windows_owner_preflight_executes_fail_closed_for_every_result(self) -> None:
        gate = load_workflow(CI_WORKFLOW_PATH)["jobs"]["preflight-gate"]["steps"][0]
        base = dict(os.environ, **{name: "success" for name in gate["env"]})
        base.update(EVENT_NAME="pull_request", RUST_SCOPE="true")
        for scope, expected in (("true", "success"), ("false", "skipped")):
            env = dict(base, RUST_SCOPE=scope)
            for name in ("POLICY_RESULT", "PLUGIN_FIXTURES_RESULT", "NOTICES_RESULT"):
                env[name] = expected
            for result in ("success", "failure", "cancelled", "skipped", ""):
                with self.subTest(scope=scope, result=result):
                    actual = subprocess.run(
                        ["bash", "-c", gate["run"]],
                        env=dict(env, OWNER_WINDOWS_RESULT=result),
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(actual.returncode == 0, result == expected)

    def test_failed_native_diagnostics_cannot_qualify_or_weaken_measurement(self) -> None:
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        for name, field, before, after in (
            ("Export failed native coverage diagnostics", "if", "steps.coverage.outcome == 'failure'", "steps.coverage.outcome == 'success'"),
            ("Export failed native coverage diagnostics", "run", "cargo llvm-cov report -p", "cargo llvm-cov -p"),
            ("Export failed native coverage diagnostics", "run", "failed-measurement-diagnostic-only", "qualified"),
            ("Export failed native coverage diagnostics", "run", "Get-ChildItem -LiteralPath $profileDirectory", "Get-ChildItem -LiteralPath $metadata.target_directory"),
            ("Export failed native coverage diagnostics", "run", "Join-Path $metadata.target_directory 'llvm-cov-target'", "$metadata.target_directory"),
            ("Export failed native coverage diagnostics", "run", "CARGO_LLVM_COV_TARGET_DIR", "CARGO_TARGET_DIR"),
            ("Retain failed native coverage diagnostics", "name", "owner-windows-failed-diagnostic-", "owner-windows-lcov-"),
            ("Retain failed native coverage diagnostics", "path", "owner-windows-failed-diagnostic/", "owner-windows.lcov"),
        ):
            changed = copy.deepcopy(native)
            step = next(s for s in changed["jobs"]["owner-bridge-windows"]["steps"] if s.get("name") == name)
            target = step["with"] if field in ("name", "path") else step
            self.assertIn(before, target[field])
            target[field] = target[field].replace(before, after)
            with self.subTest(name=name, field=field), self.assertRaises(native_policy.PolicyError):
                native_policy.check(changed)
        steps = native["jobs"]["owner-bridge-windows"]["steps"]
        measurement = next(s for s in steps if s.get("id") == "coverage")
        self.assertNotIn("continue-on-error", measurement)
        report = next(s for s in steps if s.get("name") == "Export failed native coverage diagnostics")
        self.assertIn("profile unavailable", report["run"])
        self.assertIn("failure()", report["if"])
        self.assertNotIn("--fail-under", report["run"])

    def test_windows_single_native_run_keeps_fixtures_and_documentation_required(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        steps = native["jobs"]["owner-bridge-windows"]["steps"]
        self.assertFalse(any("--skip" in step.get("run", "") for step in steps))
        commands = [step.get("run", "") for step in steps]
        self.assertEqual(sum("cargo llvm-cov -p pos-owner-bridge-windows" in run for run in commands), 1)
        runtime_at = next(index for index, step in enumerate(steps) if step.get("id") == "runtime")
        native_tests_at = next(index for index, step in enumerate(steps) if step.get("id") == "coverage")
        self.assertLess(runtime_at, native_tests_at)
        for name, before, after in (
            (
                "Measure only shim source coverage",
                "--no-fail-fast",
                "",
            ),
            (
                "Measure only shim source coverage",
                "-- --include-ignored",
                "-- --include-ignored --skip tests::native_window_environment_and_buffers_lifecycle",
            ),
            (
                "Measure only shim source coverage",
                "cargo llvm-cov -p",
                "cargo llvm-cov report -p",
            ),
            (
                "Test portable bridge, owner executable and native docs",
                "-p pos-owner-bridge -p piglor-owner",
                "-p pos-owner-bridge",
            ),
            (
                "Test portable bridge, owner executable and native docs",
                "--doc -- --include-ignored",
                "--no-run -- --include-ignored",
            ),
        ):
            mutated = copy.deepcopy(native)
            step = next(s for s in mutated["jobs"]["owner-bridge-windows"]["steps"] if s.get("name") == name)
            self.assertIn(before, step["run"])
            step["run"] = step["run"].replace(before, after)
            with self.subTest(name=name, before=before), self.assertRaises(AssertionError):
                assert_owner_windows_lane(workflow, mutated)

    def test_windows_full_file_coverage_rejects_weakened_or_missing_scopes(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        name = "Enforce both full-file Windows coverage floors"
        for before, after in (
            ("--fail-under-lines 99", "--fail-under-lines 98"),
            ("--fail-under-regions 99", "--fail-under-regions 98"),
            ("--fail-under-lines 95", "--fail-under-lines 94"),
            ("--fail-under-regions 80", "--fail-under-regions 79"),
            ("--scope safe", "--scope ffi"),
            ("--list-report", "--scope all"),
            ("$ffiResult = $LASTEXITCODE", "$ffiResult = 0"),
        ):
            mutated = copy.deepcopy(native)
            step = next(s for s in mutated["jobs"]["owner-bridge-windows"]["steps"] if s.get("name") == name)
            step["run"] = step["run"].replace(before, after)
            with self.subTest(before=before), self.assertRaises(AssertionError):
                assert_owner_windows_lane(workflow, mutated)
        for replacement in (None, "${{ success() }}"):
            mutated = copy.deepcopy(native)
            steps = mutated["jobs"]["owner-bridge-windows"]["steps"]
            step = next(s for s in steps if s.get("name") == name)
            if replacement is None:
                steps.remove(step)
            else:
                step["if"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                assert_owner_windows_lane(workflow, mutated)

    def test_parallel_validation_preserves_every_required_command(self) -> None:
        assert_parallel_validation_contract(load_workflow(CI_WORKFLOW_PATH))

    def test_owner_bridge_coverage_scope_runs_with_fixtures_and_real_metadata(self) -> None:
        jobs = load_workflow(CI_WORKFLOW_PATH)["jobs"]
        expected = (
            ("pinned-dependencies", {
                "name": "Test Windows shim coverage exclusions",
                "run": "python scripts/test_owner_bridge_windows_cov_ignore.py",
            }),
            ("clippy", {
                "name": "Exercise Windows shim coverage exclusions with real metadata",
                "run": "set -euo pipefail\n"
                "cargo metadata --locked --no-deps --format-version 1 |\n"
                "  python scripts/owner_bridge_windows_cov_ignore.py > "
                '"${RUNNER_TEMP}/owner-bridge-windows-cov-ignore.txt"\n'
                'test -s "${RUNNER_TEMP}/owner-bridge-windows-cov-ignore.txt"\n',
            }),
        )
        for owner, step in expected:
            with self.subTest(job=owner):
                self.assertEqual(
                    [candidate for candidate in jobs[owner]["steps"]
                     if candidate.get("name") == step["name"]],
                    [step],
                )

    def test_native_width_counter_runs_on_the_actual_narrower_target(self) -> None:
        expected = {
            "name": "Exercise native-width canonical length arithmetic",
            "run": "cargo test -p pos-core --target i686-pc-windows-msvc --lib --locked "
            "canonical_length_tests -- --include-ignored",
        }
        steps = load_workflow(CI_WORKFLOW_PATH)["jobs"]["ledger-windows"]["steps"]
        self.assertEqual(
            [step for step in steps if step.get("name") == expected["name"]],
            [expected],
        )

    def test_parallel_validation_rejects_missing_or_weakened_commands(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for owner, required in (
            ("feature-matrix", FEATURE_MATRIX_STEPS),
            ("test", (WORKSPACE_DOCTEST_STEP,)),
            ("rustdoc", (WORKSPACE_RUSTDOC_STEP,)),
        ):
            for expected in required:
                for change in ("remove", "if", "continue-on-error", "run"):
                    with self.subTest(owner=owner, step=expected["name"], change=change):
                        mutated = copy.deepcopy(workflow)
                        steps = mutated["jobs"][owner]["steps"]
                        step = next(s for s in steps if s.get("name") == expected["name"])
                        if change == "remove":
                            steps.remove(step)
                        else:
                            step[change] = True if change == "continue-on-error" else "false"
                        with self.assertRaisesRegex(AssertionError, "exact required step"):
                            assert_parallel_validation_contract(mutated)

    def test_rustdoc_contract_rejects_broken_cache_and_weakened_job(self) -> None:
        changes = (
            (
                "steps",
                [{"uses": RUST_CACHE_ACTION}, WORKSPACE_RUSTDOC_STEP],
                "broken documentation target cache",
            ),
            ("needs", ["ci_change_scope"], "standard-stage prerequisites"),
            ("if", "${{ always() }}", "standard-stage prerequisites"),
            ("timeout-minutes", 60, "blocking 30-minute limit"),
            ("continue-on-error", True, "blocking 30-minute limit"),
        )
        for field, value, message in changes:
            with self.subTest(field=field):
                mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                mutated["jobs"]["rustdoc"][field] = value
                with self.assertRaisesRegex(AssertionError, message):
                    assert_parallel_validation_contract(mutated)

    def test_rustdoc_contract_rejects_weakened_environment(self) -> None:
        for variable, value in (("RUSTDOCFLAGS", ""), ("CARGO_INCREMENTAL", "1")):
            with self.subTest(variable=variable):
                mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                step = next(
                    step for step in mutated["jobs"]["rustdoc"]["steps"]
                    if step.get("name") == WORKSPACE_RUSTDOC_STEP["name"]
                )
                step["env"][variable] = value
                with self.assertRaisesRegex(AssertionError, "exact required step"):
                    assert_parallel_validation_contract(mutated)

    def test_parallel_validation_rejects_an_omitted_feature_result(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for change in ("needs", "env", "run"):
            with self.subTest(change=change):
                mutated = copy.deepcopy(workflow)
                gate = mutated["jobs"]["core-gate"]
                if change == "needs":
                    gate["needs"].remove("feature-matrix")
                elif change == "env":
                    gate["steps"][0]["env"]["FEATURE_MATRIX_RESULT"] = "success"
                else:
                    gate["steps"][0]["run"] = gate["steps"][0]["run"].replace(
                        'test "${FEATURE_MATRIX_RESULT}" = "${expected}"', "true"
                    )
                with self.assertRaisesRegex(AssertionError, "core-gate must"):
                    assert_parallel_validation_contract(mutated)

    def test_parallel_core_gate_executes_fail_closed_for_every_result(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        assert_parallel_validation_contract(workflow)
        # Execute only the inspected shell result checker, never Cargo commands.
        run = workflow["jobs"]["core-gate"]["steps"][0]["run"]
        results = {
            name.upper().replace("-", "_") + "_RESULT": "success"
            for name in CORE_GATE_JOB_NAMES
        }
        environment = dict(
            results, SCOPE_RESULT="success", PREFLIGHT_RESULT="success", RUST_SCOPE="true"
        )

        def verdict(env: dict[str, str]) -> int:
            return subprocess.run(
                ["/bin/bash", "-c", run], env=env, capture_output=True, check=False
            ).returncode

        self.assertEqual(verdict(environment), 0)
        for result in results:
            for state in ("failure", "cancelled", "skipped", ""):
                with self.subTest(result=result, state=state):
                    self.assertNotEqual(verdict(dict(environment, **{result: state})), 0)
        scoped = dict(environment, RUST_SCOPE="false")
        scoped.update(dict.fromkeys(results, "skipped"))
        self.assertEqual(verdict(scoped), 0)

    def test_core_workers_reclaim_sdk_headroom_before_cache_and_build(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        assert_core_sdk_headroom(workflow)
        program = workflow["jobs"]["test-shard"]["steps"][1]["run"]
        result = subprocess.run(
            ["bash", "-n"], input=program, text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_core_headroom_rejects_missing_duplicate_or_late_setup(self) -> None:
        for job_name in ("test-shard", "coverage"):
            for change in ("missing", "duplicate", "before-checkout", "after-cache"):
                with self.subTest(job=job_name, change=change):
                    workflow = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                    steps = workflow["jobs"][job_name]["steps"]
                    headroom = steps.pop(1)
                    if change == "duplicate":
                        steps[1:1] = [headroom, copy.deepcopy(headroom)]
                    elif change == "before-checkout":
                        steps.insert(0, headroom)
                    elif change == "after-cache":
                        steps.append(headroom)
                    with self.assertRaisesRegex(AssertionError, "SDK headroom"):
                        assert_core_sdk_headroom(workflow)

    def test_core_headroom_rejects_unsafe_cleanup_or_missing_receipts(self) -> None:
        edits = (
            ("/usr/share/dotnet/sdk", "/usr/share/dotnet"),
            ("/usr/local/lib/android/sdk", "/usr/local"),
            ("test ! -L", "true #"),
            ("readlink -e", "printf"),
            ("--one-file-system", ""),
            ("sudo du -sx -B1", "true #"),
            ("df -B1", "true #"),
            ("df -i", "true #"),
            ("set -euo pipefail", "set +e"),
        )
        for job_name in ("test-shard", "coverage"):
            for old, new in edits:
                with self.subTest(job=job_name, edit=old):
                    workflow = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                    steps = workflow["jobs"][job_name]["steps"]
                    # Mutate one consumer independently of the parsed YAML alias.
                    steps[1] = copy.deepcopy(steps[1])
                    self.assertIn(old, steps[1]["run"])
                    steps[1]["run"] = steps[1]["run"].replace(old, new)
                    with self.assertRaisesRegex(AssertionError, "SDK headroom"):
                        assert_core_sdk_headroom(workflow)

    def test_core_headroom_rejects_guard_bypasses_and_permissive_steps(self) -> None:
        for job_name in ("test-shard", "coverage"):
            for extra in (
                {"if": "${{ true }}"},
                {"if": "${{ runner.os == 'Linux' }}"},
                {"continue-on-error": True},
                {"shell": "bash {0} || true"},
                {"working-directory": "/tmp"},
            ):
                with self.subTest(job=job_name, extra=extra):
                    workflow = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                    steps = workflow["jobs"][job_name]["steps"]
                    steps[1] = copy.deepcopy(steps[1])
                    steps[1].update(extra)
                    with self.assertRaisesRegex(AssertionError, "SDK headroom"):
                        assert_core_sdk_headroom(workflow)

    def test_core_rust_caches_restore_on_prs_and_save_only_from_main(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        assert_core_rust_cache_contract(workflow)

    def test_core_cache_contract_rejects_missing_pull_request_trigger(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        del workflow_triggers(mutated)["pull_request"]
        with self.assertRaisesRegex(AssertionError, "pull_request"):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_filtered_pull_request_trigger(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        workflow_triggers(mutated)["pull_request"] = {"branches": ["release"]}
        with self.assertRaisesRegex(AssertionError, "unfiltered pull_request"):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_missing_main_push_trigger(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        workflow_triggers(mutated)["push"]["branches"] = ["release"]
        with self.assertRaisesRegex(AssertionError, "main push"):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_excluded_main_push_trigger(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        workflow_triggers(mutated)["push"]["branches"] = ["main", "!main"]
        with self.assertRaisesRegex(AssertionError, "main push"):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_path_filtered_main_push_trigger(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for field, patterns in (
            ("paths", ["crates/**"]),
            ("paths-ignore", ["**"]),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(workflow)
                workflow_triggers(mutated)["push"][field] = patterns
                with self.assertRaisesRegex(AssertionError, "main push"):
                    assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_unreachable_main_core_job(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        mutated["jobs"]["fmt"]["if"] = "${{ github.event_name == 'pull_request' }}"
        with self.assertRaisesRegex(AssertionError, "reachable on a main push"):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_unreachable_main_prerequisites(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for job_name, field, value, message in (
            (
                "ci_change_scope",
                "if",
                "${{ github.event_name == 'pull_request' }}",
                "ci_change_scope must remain unconditional",
            ),
            (
                "ci_change_scope",
                "needs",
                ["trunk-pr"],
                "ci_change_scope must have no prerequisites",
            ),
            (
                "pinned-dependencies",
                "if",
                "${{ github.event_name == 'pull_request' }}",
                "pinned-dependencies must remain reachable on a main push",
            ),
            (
                "pinned-dependencies",
                "needs",
                "trunk-pr",
                "pinned-dependencies must wait for ci_change_scope",
            ),
            (
                "preflight-gate",
                "if",
                "${{ github.event_name == 'pull_request' }}",
                "preflight-gate must remain reachable on a main push",
            ),
            (
                "preflight-gate",
                "needs",
                ["trunk-pr"],
                "preflight-gate must retain scope and policy dependencies",
            ),
        ):
            with self.subTest(job=job_name):
                mutated = copy.deepcopy(workflow)
                mutated["jobs"][job_name][field] = value
                with self.assertRaisesRegex(AssertionError, message):
                    assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_requires_pinned_preflight_dependency(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        mutated["jobs"]["preflight-gate"]["needs"].remove("pinned-dependencies")
        with self.assertRaisesRegex(
            AssertionError, "preflight-gate must retain scope and policy dependencies"
        ):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_requires_its_pinned_workflow_invocation(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        mutated["jobs"]["pinned-dependencies"]["steps"].remove(
            CI_WORKFLOW_POLICY_TEST_STEP
        )
        with self.assertRaisesRegex(
            AssertionError, "run the CI workflow policy test"
        ):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_conditional_pr_restore(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        cache_step = next(
            step
            for step in mutated["jobs"]["test"]["steps"]
            if str(step.get("uses", "")).startswith("Swatinem/rust-cache@")
        )
        cache_step["if"] = "${{ github.event_name == 'push' }}"
        with self.assertRaisesRegex(AssertionError, "reachable on pull requests"):
            assert_core_rust_cache_contract(mutated)

    def test_test_shards_gate_blocks_core_gate(self) -> None:
        assert_test_shards_gate(load_workflow(CI_WORKFLOW_PATH))

    def test_test_shards_gate_rejects_mutations(self) -> None:
        mutations = {
            "core-gate must wait for test-shards": lambda w: w["jobs"]["core-gate"][
                "needs"
            ].remove("test-shards"),
            "core-gate must require the test-shards result": lambda w: w["jobs"][
                "core-gate"
            ]["steps"][0].update(
                run=w["jobs"]["core-gate"]["steps"][0]["run"].replace(
                    TEST_SHARDS_CORE_CHECK, ""
                )
            ),
            "only after every shard succeeded": lambda w: w["jobs"]["test-shards"].update(
                {"if": "${{ always() }}"}
            ),
            "wait for every test shard": lambda w: w["jobs"]["test-shards"].update(
                needs=["test"]
            ),
            "must define the test-shards aggregate": lambda w: w["jobs"].pop("test-shards"),
            "matrix must be shards": lambda w: w["jobs"]["test-shard"]["strategy"].update(
                matrix={"shard": [1, 2]}
            ),
            "must not cancel sibling shards": lambda w: w["jobs"]["test-shard"][
                "strategy"
            ].update({"fail-fast": True}),
            "shard count must agree everywhere": lambda w: w["jobs"]["test-shards"][
                "steps"
            ][-1].update(
                run=w["jobs"]["test-shards"]["steps"][-1]["run"].replace(
                    "--partitioned=3", "--partitioned=2"
                )
            ),
        }
        for message, mutate in mutations.items():
            with self.subTest(message=message):
                mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                mutate(mutated)
                with self.assertRaisesRegex(AssertionError, message):
                    assert_test_shards_gate(mutated)

    def test_standard_stage_stays_within_runner_cap(self) -> None:
        assert_standard_stage_runner_cap(load_workflow(CI_WORKFLOW_PATH))

    def test_standard_stage_cap_rejects_mutations(self) -> None:
        mutations = {
            "start exactly the counted jobs": lambda w: w["jobs"].update(
                {
                    "ninth-heavy-job": {
                        "needs": ["ci_change_scope", "cargo-crap"],
                        "runs-on": "ubuntu-24.04",
                        "steps": [{"run": "true"}],
                    }
                }
            ),
            "must use one runner": lambda w: w["jobs"]["asan-build"].update(
                {"strategy": {"matrix": {"part": [1, 2]}}}
            ),
            "wait for every standard-stage job": lambda w: w["jobs"]["standard-gate"][
                "needs"
            ].remove("asan-build"),
        }
        for message, mutate in mutations.items():
            with self.subTest(message=message):
                mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                mutate(mutated)
                with self.assertRaisesRegex(AssertionError, message):
                    assert_standard_stage_runner_cap(mutated)

    def test_pull_requests_never_write_caches(self) -> None:
        for workflow_path in MAIN_WRITER_WORKFLOW_PATHS:
            with self.subTest(workflow=workflow_path.name):
                assert_pull_requests_never_write_caches(load_workflow(workflow_path))

    def test_cache_write_contract_rejects_pull_request_rust_cache_write(self) -> None:
        mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
        cache_step = next(
            step
            for step in mutated["jobs"]["clippy"]["steps"]
            if str(step.get("uses", "")).startswith("Swatinem/rust-cache@")
        )
        del cache_step["with"]["save-if"]
        with self.assertRaisesRegex(AssertionError, "clippy Rust cache must save only from main"):
            assert_pull_requests_never_write_caches(mutated)

    def test_cache_write_contract_rejects_pull_request_docker_cache_write(self) -> None:
        mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
        build_step = next(
            step
            for step in mutated["jobs"]["docker-build"]["steps"]
            if str(step.get("uses", "")).startswith("docker/build-push-action@")
        )
        build_step["with"]["cache-to"] = "type=gha,mode=max"
        with self.assertRaisesRegex(AssertionError, "docker-build Docker cache must save only from main"):
            assert_pull_requests_never_write_caches(mutated)

    def test_conformance_materialization_honors_rust_scope(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        materialization = workflow["jobs"]["materialize-conformance-bundles"]
        self.assertIn("ci_change_scope", materialization["needs"])
        self.assertEqual(
            materialization["if"],
            "${{ !cancelled() && needs.ci_change_scope.result == 'success' && "
            "needs.conformance-fixtures.result == 'success' && "
            "needs.cargo-crap.result == 'success' && "
            "(needs.ci_change_scope.outputs.rust == 'true' || "
            "github.event_name != 'pull_request') }}",
        )




# Accepted ADR-069's two-architecture static launcher evidence is a blocking
# contract. Keep the executable recipe, its graph and its fan-in explicit so
# changing the producer cannot silently turn acceptance evidence into a no-op.
STATIC_LAUNCHER_JOB = {'name': 'static-launcher',
 'needs': ['ci_change_scope', 'preflight-gate'],
 'if': "${{ !cancelled() && needs.preflight-gate.result == 'success' && "
       "(needs.ci_change_scope.outputs.rust == 'true' || github.event_name != "
       "'pull_request') }}",
 'runs-on': 'ubuntu-24.04',
 'timeout-minutes': 45,
 'env': {'RUSTFLAGS': '-D warnings -C target-feature=+crt-static -C '
                      'relocation-model=static',
         'CC_x86_64_unknown_linux_musl': 'musl-gcc',
         'CC_aarch64_unknown_linux_musl': 'aarch64-linux-gnu-gcc',
         'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER': 'musl-gcc',
         'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER': 'aarch64-linux-gnu-gcc'},
 'steps': [{'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
            'with': {'fetch-depth': 0, 'persist-credentials': False}},
           {'uses': 'dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8',
            'with': {'toolchain': '1.97.1',
                     'targets': 'x86_64-unknown-linux-musl,aarch64-unknown-linux-musl'}},
           {'uses': 'Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16',
            'with': {'shared-key': 'static-launcher',
                     'save-if': "${{ github.ref == 'refs/heads/main' }}"}},
           {'name': 'Install the musl and aarch64 cross toolchains',
            'run': 'set -euo pipefail\n'
                   'sudo apt-get update\n'
                   'sudo apt-get install --yes --no-install-recommends musl-tools '
                   'gcc-aarch64-linux-gnu libc6-dev-arm64-cross\n'},
           {'name': 'Build the provider binary as a static ELF for each architecture',
            'run': 'set -euo pipefail\n'
                   'for target in x86_64-unknown-linux-musl '
                   'aarch64-unknown-linux-musl; do\n'
                   '  cargo build --locked --release --package pos-sandboxd --bin '
                   'pos-sandboxd --target "${target}"\n'
                   'done\n'},
           {'name': 'Require no interpreter, no dynamic section and no shared '
                    'dependency',
            'run': 'set -euo pipefail\n'
                   'for target in x86_64-unknown-linux-musl '
                   'aarch64-unknown-linux-musl; do\n'
                   '  binary="target/${target}/release/pos-sandboxd"\n'
                   '  file "${binary}"\n'
                   '  file "${binary}" | grep -q \'statically linked\'\n'
                   '  if file "${binary}" | grep -qi \'interpreter\\|dynamically '
                   "linked'; then\n"
                   '    echo "${binary} names an interpreter or is dynamically linked" '
                   '>&2\n'
                   '    exit 1\n'
                   '  fi\n'
                   '  if readelf --program-headers --wide "${binary}" | grep -q '
                   "'INTERP'; then\n"
                   '    echo "${binary} has a PT_INTERP program header" >&2\n'
                   '    exit 1\n'
                   '  fi\n'
                   '  readelf --dynamic "${binary}" 2>&1 | grep -q \'There is no '
                   "dynamic section in this file'\n"
                   '  if readelf --section-headers --wide "${binary}" | grep -Eq '
                   "'\\.interp|\\.dynamic|\\.dynsym'; then\n"
                   '    echo "${binary} has dynamic-linking sections" >&2\n'
                   '    exit 1\n'
                   '  fi\n'
                   'done\n'},
           {'name': 'Run the x86_64 binary and require its launcher mode to refuse '
                    'invalid LPV1 input',
            'run': 'set -euo pipefail\n'
                   'binary=target/x86_64-unknown-linux-musl/release/pos-sandboxd\n'
                   'set +e\n'
                   '"${binary}" launch-barrier zz 2> launcher.err\n'
                   'status=$?\n'
                   'set -e\n'
                   'test "${status}" = 1\n'
                   "grep -q 'launch parameters are not a valid LPV1' launcher.err\n"}]}

STATIC_LAUNCHER_FAN_IN = {'name': 'standard-gate',
 'if': '${{ always() }}',
 'needs': ['ci_change_scope',
           'core-gate',
           'cargo-crap',
           'rustdoc',
           'reference-evaluator-release',
           'materialize-conformance-bundles',
           'audit',
           'codeql',
           'ledger-windows',
           'docker-build',
           'world-client-wasm',
           'world-client-browser-parity',
           'asan-build',
           'static-launcher'],
 'runs-on': 'ubuntu-24.04',
 'timeout-minutes': 5,
 'steps': [{'name': 'Require normal blocking checks',
            'env': {'RUST_SCOPE': '${{ needs.ci_change_scope.outputs.rust }}',
                    'CORE_RESULT': '${{ needs.core-gate.result }}',
                    'CARGO_CRAP_RESULT': '${{ needs.cargo-crap.result }}',
                    'RUSTDOC_RESULT': '${{ needs.rustdoc.result }}',
                    'REFERENCE_RESULT': '${{ needs.reference-evaluator-release.result '
                                        '}}',
                    'MATERIALIZE_RESULT': '${{ '
                                          'needs.materialize-conformance-bundles.result '
                                          '}}',
                    'DEPENDENCY_RESULT': '${{ needs.audit.result }}',
                    'CODEQL_RESULT': '${{ needs.codeql.result }}',
                    'LEDGER_WINDOWS_RESULT': '${{ needs.ledger-windows.result }}',
                    'DOCKER_RESULT': '${{ needs.docker-build.result }}',
                    'WASM_RESULT': '${{ needs.world-client-wasm.result }}',
                    'BROWSER_RESULT': '${{ needs.world-client-browser-parity.result }}',
                    'ASAN_BUILD_RESULT': '${{ needs.asan-build.result }}',
                    'STATIC_LAUNCHER_RESULT': '${{ needs.static-launcher.result }}'},
            'run': 'set -euo pipefail\n'
                   'test "${CORE_RESULT}" = success\n'
                   'test "${CODEQL_RESULT}" = success\n'
                   'expected=success\n'
                   'if [[ "${RUST_SCOPE}" = false ]]; then\n'
                   '  expected=skipped\n'
                   'fi\n'
                   'for result in \\\n'
                   '  "${CARGO_CRAP_RESULT}" "${RUSTDOC_RESULT}" "${REFERENCE_RESULT}" '
                   '\\\n'
                   '  "${MATERIALIZE_RESULT}" "${DEPENDENCY_RESULT}" \\\n'
                   '  "${LEDGER_WINDOWS_RESULT}" "${DOCKER_RESULT}" \\\n'
                   '  "${WASM_RESULT}" "${BROWSER_RESULT}" "${ASAN_BUILD_RESULT}" \\\n'
                   '  "${STATIC_LAUNCHER_RESULT}"; do\n'
                   '  test "${result}" = "${expected}"\n'
                   'done\n'}]}

STATIC_LAUNCHER_JOB_SET = ['asan',
 'asan-build',
 'asan-gate',
 'audit',
 'cargo-crap',
 'ci-gate',
 'ci_change_scope',
 'clippy',
 'codeql',
 'codeql-required',
 'conformance-fixtures',
 'conformance-non-linux',
 'core-gate',
 'coverage',
 'depgraph',
 'docker-build',
 'feature-matrix',
 'fmt',
 'ledger-windows',
 'materialize-conformance-bundles',
 'modules-structure',
 'mutation-checks',
 'mutation-required',
 'owner-bridge-windows',
 'pinned-dependencies',
 'plugin-component-fixtures',
 'preflight-gate',
 'reference-evaluator-release',
 'rustdoc',
 'standard-gate',
 'static-launcher',
 'test',
 'test-shard',
 'test-shards',
 'third-party-notices',
 'trunk-pr',
 'world-client-browser-parity',
 'world-client-wasm']


def assert_static_launcher_contract(workflow: dict) -> None:
    trigger_key = "on" if "on" in workflow else True
    if set(workflow) != {"name", trigger_key, "concurrency", "permissions", "env", "jobs"}:
        raise AssertionError("static-launcher requires the reviewed workflow root envelope")
    if workflow["name"] != "ci" or workflow["concurrency"] != {
        "group": "ci-${{ github.workflow }}-${{ github.event_name == 'push' && github.sha || github.ref }}",
        "cancel-in-progress": True,
    }:
        raise AssertionError("static-launcher requires the reviewed workflow controls")
    if set(workflow_triggers(workflow)) != {"push", "pull_request", "workflow_dispatch"}:
        raise AssertionError("static-launcher requires the reviewed workflow triggers")
    if workflow_triggers(workflow).get("push") != MAIN_PUSH_TRIGGER:
        raise AssertionError("static-launcher must execute on main pushes")
    if any(workflow_triggers(workflow)[trigger] is not None for trigger in ("pull_request", "workflow_dispatch")):
        raise AssertionError("static-launcher requires unfiltered pull-request and manual triggers")
    if workflow.get("permissions") != {"actions": "read", "contents": "read"}:
        raise AssertionError("static-launcher requires read-only workflow permissions")
    if workflow.get("env") != {"CARGO_TERM_COLOR": "always", "RUSTFLAGS": "-D warnings"}:
        raise AssertionError("static-launcher requires the reviewed workflow environment")
    jobs = workflow.get("jobs", {})
    if sorted(jobs) != STATIC_LAUNCHER_JOB_SET:
        raise AssertionError("static-launcher requires the reviewed complete job set")
    if jobs.get("static-launcher") != STATIC_LAUNCHER_JOB:
        raise AssertionError("static-launcher evidence producer differs from its reviewed contract")
    if jobs.get("standard-gate") != STATIC_LAUNCHER_FAN_IN:
        raise AssertionError("static-launcher evidence must block the reviewed fan-in")


class StaticLauncherPolicyTests(unittest.TestCase):
    def test_checked_in_static_launcher_contract(self) -> None:
        assert_static_launcher_contract(load_workflow(CI_WORKFLOW_PATH))

    def test_static_launcher_rejects_weakening(self) -> None:
        original = load_workflow(CI_WORKFLOW_PATH)
        cases = []

        def changed(label, mutate):
            workflow = copy.deepcopy(original)
            mutate(workflow)
            cases.append((label, workflow))

        changed("fabricated success", lambda w: w["jobs"]["static-launcher"].update(steps=[{"run": "true"}]))
        changed("skipped producer", lambda w: w["jobs"]["static-launcher"].update({"if": False}))
        changed("nonblocking producer", lambda w: w["jobs"]["static-launcher"].update({"continue-on-error": True}))
        changed("producer permission escalation", lambda w: w["jobs"]["static-launcher"].update(permissions={"contents": "write"}))
        changed("workflow permission escalation", lambda w: w.update(permissions="write-all"))
        changed("inherited no-op shell", lambda w: w.update(defaults={"run": {"shell": "true {0}"}}))
        changed("inherited working directory", lambda w: w.update(defaults={"run": {"working-directory": "/tmp"}}))
        changed("altered workflow name", lambda w: w.update(name="fabricated-ci"))
        changed("altered concurrency", lambda w: w["concurrency"].update(group="all-branches"))
        changed("disabled cancellation", lambda w: w["concurrency"].update({"cancel-in-progress": False}))
        changed("filtered pull request", lambda w: w["on" if "on" in w else True].update(pull_request={"types": ["opened"]}))
        changed("manual input injection", lambda w: w["on" if "on" in w else True].update(workflow_dispatch={"inputs": {"skip": {"default": True}}}))
        changed("detached trigger", lambda w: w["on" if "on" in w else True].pop("pull_request"))
        changed("injected environment", lambda w: w["env"].update(CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="true"))
        changed("injected job", lambda w: w["jobs"].update({"fabricate": {"runs-on": "ubuntu-24.04", "steps": [{"run": "true"}]}}))
        changed("reordered checks", lambda w: w["jobs"]["static-launcher"]["steps"].reverse())
        changed("missing architecture", lambda w: w["jobs"]["static-launcher"]["steps"][1]["with"].update(targets="x86_64-unknown-linux-musl"))
        changed("missing ELF inspection", lambda w: w["jobs"]["static-launcher"]["steps"].pop(5))
        changed("missing smoke check", lambda w: w["jobs"]["static-launcher"]["steps"].pop())
        changed("removed producer", lambda w: w["jobs"].pop("static-launcher"))
        changed("removed fan-in dependency", lambda w: w["jobs"]["standard-gate"]["needs"].remove("static-launcher"))
        changed("removed fan-in result", lambda w: w["jobs"]["standard-gate"]["steps"][0]["env"].pop("STATIC_LAUNCHER_RESULT"))
        changed("fabricated fan-in", lambda w: w["jobs"]["standard-gate"]["steps"][0].update(run="true"))
        for label, workflow in cases:
            with self.subTest(label=label), self.assertRaises(AssertionError):
                assert_static_launcher_contract(workflow)

    def test_failed_or_missing_launcher_result_cannot_pass_fan_in(self) -> None:
        gate = STATIC_LAUNCHER_FAN_IN["steps"][0]
        for result in ("failure", "cancelled", "skipped", "", "success"):
            with self.subTest(result=result):
                environment = {name: "success" for name in gate["env"]}
                environment["RUST_SCOPE"] = "true"
                environment["STATIC_LAUNCHER_RESULT"] = result
                completed = subprocess.run(["bash", "-c", gate["run"]], env=environment, capture_output=True, check=False)
                self.assertEqual(completed.returncode == 0, result == "success")


def load_tests(loader, tests, pattern):
    # The required central CI policy step also exercises the separately
    # triggered custody workflow, including its producer indirection.
    tests.addTests(loader.loadTestsFromModule(custody_policy_tests))
    tests.addTests(loader.loadTestsFromModule(native_lcov_tests))
    return tests


if __name__ == "__main__":
    unittest.main()
