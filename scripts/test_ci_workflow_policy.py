#!/usr/bin/env python3
"""Contract tests for CI change scope and the core Rust gate policy."""

from __future__ import annotations

import copy
import fnmatch
import pathlib
import subprocess
import unittest

import yaml


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
)
WORKSPACE_TEST_STEP = {
    "name": "cargo test (all features, no ignored skip)",
    "run": "set -euo pipefail\n"
    "cargo test --workspace --all-features --locked -- --include-ignored "
    "2>&1 | tee /tmp/cargo-test.log\n"
    "bash scripts/assert-no-ignored-in-test-summary.sh /tmp/cargo-test.log\n",
}
MAIN_PUSH_TRIGGER = {"branches": ["main"]}
PREFLIGHT_GATE_IF = "${{ always() }}"
REQUIRED_PREFLIGHT_NEEDS = ("ci_change_scope", "pinned-dependencies")
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


def load_patterns() -> list[str]:
    with FILTER_PATH.open(encoding="utf-8") as stream:
        filters = yaml.safe_load(stream)
    if not isinstance(filters, dict) or not isinstance(filters.get("rust"), list):
        raise AssertionError("rust-scope.yml must define a rust pattern list")
    patterns = filters["rust"]
    if not all(isinstance(pattern, str) for pattern in patterns):
        raise AssertionError("rust-scope.yml patterns must be strings")
    return patterns


def load_workflow(workflow_path: pathlib.Path) -> dict:
    with workflow_path.open(encoding="utf-8") as stream:
        workflow = yaml.safe_load(stream)
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
        ("test", (WORKSPACE_TEST_STEP,)),
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
    gate = jobs["core-gate"]
    if gate.get("needs") != ["ci_change_scope", "preflight-gate", *CORE_JOB_NAMES]:
        raise AssertionError("core-gate must require every parallel core job")
    if gate.get("if") != "${{ always() }}" or "continue-on-error" in gate:
        raise AssertionError("core-gate must remain unconditional and blocking")
    step = gate["steps"][0]
    if "if" in step or "continue-on-error" in step:
        raise AssertionError("core-gate result check must remain blocking")
    for name in CORE_JOB_NAMES:
        variable = name.upper().replace("-", "_") + "_RESULT"
        if step["env"].get(variable) != "${{ needs." + name + ".result }}":
            raise AssertionError("core-gate must read every actual job result")
        if f'test "${{{variable}}}" = "${{expected}}"' not in step["run"]:
            raise AssertionError("core-gate must enforce every actual job result")


def rust_gate_required(paths: list[str], patterns: list[str]) -> bool:
    return any(not excluded(path, patterns) for path in paths)


class CiWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.patterns = load_patterns()

    def test_filter_has_conservative_positive_default(self) -> None:
        self.assertEqual(self.patterns[0], "**")
        self.assertEqual(set(self.patterns[1:]), EXPECTED_EXCLUDES)

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

    def test_parallel_validation_preserves_every_required_command(self) -> None:
        assert_parallel_validation_contract(load_workflow(CI_WORKFLOW_PATH))

    def test_parallel_validation_rejects_missing_or_weakened_commands(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for owner, required in (
            ("feature-matrix", FEATURE_MATRIX_STEPS),
            ("test", (WORKSPACE_TEST_STEP,)),
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
            for name in CORE_JOB_NAMES
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

    def test_pull_requests_never_write_caches(self) -> None:
        for workflow_path in MAIN_WRITER_WORKFLOW_PATHS:
            with self.subTest(workflow=workflow_path.name):
                assert_pull_requests_never_write_caches(load_workflow(workflow_path))

    def test_cache_write_contract_rejects_pull_request_rust_cache_write(self) -> None:
        mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
        cache_step = next(
            step
            for step in mutated["jobs"]["rustdoc"]["steps"]
            if str(step.get("uses", "")).startswith("Swatinem/rust-cache@")
        )
        del cache_step["with"]["save-if"]
        with self.assertRaisesRegex(AssertionError, "rustdoc Rust cache must save only from main"):
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


if __name__ == "__main__":
    unittest.main()
