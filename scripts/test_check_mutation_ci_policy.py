#!/usr/bin/env python3
"""Adversarial tests for the mutation workflow toolchain policy checker."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import tempfile
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_mutation_ci_policy.py"
SPEC = importlib.util.spec_from_file_location("check_mutation_ci_policy", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def step_running(job: dict, fragment: str) -> dict:
    return next(step for step in job["steps"] if fragment in str(step.get("run", "")))


def toolchain_step(job: dict) -> dict:
    return next(
        step
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("dtolnay/rust-toolchain@")
    )


class MutationCiPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        path = ROOT / ".github/workflows/mutation.yml"
        self.workflow = yaml.safe_load(path.read_text(encoding="utf-8"))

    def check(self, workflow: dict) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory) / "mutation.yml"
            fixture.write_text(yaml.safe_dump(workflow, sort_keys=False), encoding="utf-8")
            CHECKER.check_workflow(fixture)

    def assert_rejected(self, mutate) -> None:
        workflow = copy.deepcopy(self.workflow)
        mutate(workflow["jobs"]["mutation"])
        with self.assertRaises(CHECKER.PolicyError):
            self.check(workflow)

    def test_repository_workflow_is_accepted(self) -> None:
        self.check(copy.deepcopy(self.workflow))

    def test_missing_mutation_job_is_rejected(self) -> None:
        workflow = copy.deepcopy(self.workflow)
        del workflow["jobs"]["mutation"]
        with self.assertRaises(CHECKER.PolicyError):
            self.check(workflow)

    def test_missing_toolchain_override_is_rejected(self) -> None:
        self.assert_rejected(lambda job: job["env"].pop("RUSTUP_TOOLCHAIN"))

    def test_override_different_from_installed_nightly_is_rejected(self) -> None:
        self.assert_rejected(lambda job: job["env"].update(RUSTUP_TOOLCHAIN="1.97.1"))

    def test_stable_toolchain_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            toolchain_step(job)["with"]["toolchain"] = "stable"
            job["env"]["RUSTUP_TOOLCHAIN"] = "stable"

        self.assert_rejected(mutate)

    def test_undated_nightly_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            toolchain_step(job)["with"]["toolchain"] = "nightly-latest"
            job["env"]["RUSTUP_TOOLCHAIN"] = "nightly-latest"

        self.assert_rejected(mutate)

    def test_empty_job_env_is_rejected(self) -> None:
        self.assert_rejected(lambda job: job.update(env=None))

    def test_empty_toolchain_inputs_are_rejected(self) -> None:
        self.assert_rejected(lambda job: toolchain_step(job).update({"with": None}))

    def test_step_level_toolchain_override_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            step_running(job, "cargo mutants")["env"] = {"RUSTUP_TOOLCHAIN": "stable"}

        self.assert_rejected(mutate)

    def test_plus_toolchain_mutants_invocation_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            run = step_running(job, "cargo mutants")
            run["run"] = run["run"].replace("cargo mutants", "cargo +stable mutants")

        self.assert_rejected(mutate)

    def test_second_toolchain_install_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            job["steps"].insert(0, copy.deepcopy(toolchain_step(job)))

        self.assert_rejected(mutate)

    def test_missing_active_toolchain_guard_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            job["steps"].remove(step_running(job, "rustup show active-toolchain"))

        self.assert_rejected(mutate)

    def test_guard_without_nightly_rustc_check_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            guard = step_running(job, "rustup show active-toolchain")
            guard["run"] = guard["run"].replace("rustc --version", "cargo --version")

        self.assert_rejected(mutate)

    def test_commented_out_guard_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            guard = step_running(job, "rustup show active-toolchain")
            guard["run"] = guard["run"].replace("[[ ", "# [[ ")

        self.assert_rejected(mutate)

    def test_non_fatal_guard_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            guard = step_running(job, "rustup show active-toolchain")
            guard["run"] = guard["run"].replace("-* ]]", "-* ]] || true")

        self.assert_rejected(mutate)

    def test_guard_without_errexit_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            guard = step_running(job, "rustup show active-toolchain")
            guard["run"] = guard["run"].replace("set -euo pipefail\n", "")

        self.assert_rejected(mutate)

    def test_guard_after_mutants_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            guard = step_running(job, "rustup show active-toolchain")
            job["steps"].remove(guard)
            job["steps"].append(guard)

        self.assert_rejected(mutate)

    def test_missing_mutants_run_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            job["steps"].remove(step_running(job, "cargo mutants"))

        self.assert_rejected(mutate)

    def test_changed_harness_arguments_are_rejected(self) -> None:
        def mutate(job: dict) -> None:
            run = step_running(job, "cargo mutants")
            run["run"] = run["run"].replace("-Zunstable-options", "--quiet")

        self.assert_rejected(mutate)

    def test_dropped_fail_fast_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            run = step_running(job, "cargo mutants")
            run["run"] = run["run"].replace("--fail-fast", "--quiet")

        self.assert_rejected(mutate)

    def test_commented_out_mutants_run_is_rejected(self) -> None:
        def mutate(job: dict) -> None:
            run = step_running(job, "cargo mutants")
            run["run"] = "# " + run["run"].replace("\n", "\n# ")

        self.assert_rejected(mutate)


if __name__ == "__main__":
    unittest.main()
