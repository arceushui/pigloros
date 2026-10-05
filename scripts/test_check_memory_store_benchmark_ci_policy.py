#!/usr/bin/env python3
"""Adversarial tests for the MemoryStore benchmark CI policy checker."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import tempfile
import unittest
from collections.abc import Callable
from typing import Any

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
BENCHMARK_WORKFLOW = ROOT / ".github" / "workflows" / "memory-store-benchmark.yml"
CHECKER_PATH = ROOT / "scripts" / "check_memory_store_benchmark_ci_policy.py"
SPEC = importlib.util.spec_from_file_location(
    "memory_store_benchmark_ci_policy", CHECKER_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class MemoryStoreBenchmarkCiPolicyTests(unittest.TestCase):
    """Mutate parsed Actions workflows to prove policy controls are executable."""

    def setUp(self) -> None:
        self.ci_workflow = CHECKER.load_workflow(CI_WORKFLOW)
        self.benchmark_workflow = CHECKER.load_workflow(BENCHMARK_WORKFLOW)

    def assert_rejected(
        self,
        mutate_ci: Callable[[dict[str, Any]], None] | None = None,
        mutate_benchmark: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        ci_workflow = copy.deepcopy(self.ci_workflow)
        benchmark_workflow = copy.deepcopy(self.benchmark_workflow)
        if mutate_ci is not None:
            mutate_ci(ci_workflow)
        if mutate_benchmark is not None:
            mutate_benchmark(benchmark_workflow)
        with tempfile.TemporaryDirectory() as directory:
            fixture_root = pathlib.Path(directory)
            ci_path = fixture_root / "ci.yml"
            benchmark_path = fixture_root / "memory-store-benchmark.yml"
            ci_path.write_text(
                yaml.safe_dump(ci_workflow, sort_keys=False), encoding="utf-8"
            )
            benchmark_path.write_text(
                yaml.safe_dump(benchmark_workflow, sort_keys=False), encoding="utf-8"
            )
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_workflows(ci_path, benchmark_path)

    @staticmethod
    def comparator_step(workflow: dict[str, Any], job: str) -> dict[str, Any]:
        return next(
            step
            for step in workflow["jobs"][job]["steps"]
            if step.get("name") == CHECKER.COMPARATOR_STEP_NAME
        )

    @staticmethod
    def named_benchmark_step(workflow: dict[str, Any], name: str) -> dict[str, Any]:
        return next(
            step
            for step in workflow["jobs"]["benchmark"]["steps"]
            if step.get("name") == name
        )

    def test_repository_workflows_pass(self) -> None:
        CHECKER.check_workflows(CI_WORKFLOW, BENCHMARK_WORKFLOW)

    def test_rejects_disabled_comparator_step(self) -> None:
        self.assert_rejected(
            mutate_ci=lambda workflow: self.comparator_step(workflow, "test").update(
                {"if": False}
            )
        )

    def test_rejects_non_failing_comparator_step(self) -> None:
        self.assert_rejected(
            mutate_ci=lambda workflow: self.comparator_step(workflow, "coverage").update(
                {"continue-on-error": True}
            )
        )

    def test_rejects_relocated_comparator_step(self) -> None:
        def relocate(workflow: dict[str, Any]) -> None:
            step = self.comparator_step(workflow, "test")
            workflow["jobs"]["test"]["steps"].remove(step)
            workflow["jobs"]["rustdoc"]["steps"].append(step)

        self.assert_rejected(mutate_ci=relocate)

    def test_rejects_commented_comparator_command(self) -> None:
        source = CI_WORKFLOW.read_text(encoding="utf-8")
        fixture_source = source.replace(
            "        run: python3 scripts/test_compare_memory_store_benchmarks.py",
            "        # run: python3 scripts/test_compare_memory_store_benchmarks.py",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            ci_path = pathlib.Path(directory) / "ci.yml"
            ci_path.write_text(fixture_source, encoding="utf-8")
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_workflows(ci_path, BENCHMARK_WORKFLOW)

    def test_rejects_widened_trusted_baseline_condition(self) -> None:
        def widen_trust(workflow: dict[str, Any]) -> None:
            step = self.named_benchmark_step(
                workflow, "Upload trusted main benchmark baseline"
            )
            step["if"] = (
                "${{ success() && (github.event_name == 'push' || "
                "github.event_name == 'schedule' || "
                "github.event_name == 'workflow_dispatch') }}"
            )

        self.assert_rejected(mutate_benchmark=widen_trust)

    def test_rejects_pr_checkout_manifest_sha_mismatch(self) -> None:
        def change_checkout_ref(workflow: dict[str, Any]) -> None:
            checkout = next(
                step
                for step in workflow["jobs"]["benchmark"]["steps"]
                if step.get("uses") == CHECKER.CHECKOUT_ACTION
            )
            checkout["with"]["ref"] = "${{ github.sha }}"

        self.assert_rejected(mutate_benchmark=change_checkout_ref)

    def test_rejects_manifest_sha_source_mismatch(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: workflow["jobs"]["benchmark"]["env"].update(
                {"HEAD_SHA": "${{ github.sha }}"}
            )
        )

    def test_rejects_non_failing_manifest_step(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: self.named_benchmark_step(
                workflow, CHECKER.WRITE_MANIFEST_STEP_NAME
            ).update({"continue-on-error": True})
        )

    def test_rejects_disabled_manifest_step(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: self.named_benchmark_step(
                workflow, CHECKER.WRITE_MANIFEST_STEP_NAME
            ).update({"if": False})
        )

    def test_rejects_commented_manifest_command(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: self.named_benchmark_step(
                workflow, CHECKER.WRITE_MANIFEST_STEP_NAME
            ).update({"run": "# manifest generation disabled\n"})
        )

    def test_rejects_manifest_head_sha_argument_drift(self) -> None:
        def replace_head_sha(workflow: dict[str, Any]) -> None:
            manifest = self.named_benchmark_step(
                workflow, CHECKER.WRITE_MANIFEST_STEP_NAME
            )
            manifest["run"] = manifest["run"].replace(
                '--head-sha "$HEAD_SHA"', '--head-sha "$GITHUB_SHA"'
            )

        self.assert_rejected(mutate_benchmark=replace_head_sha)

    def test_rejects_non_failing_comparison_step(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: self.named_benchmark_step(
                workflow, CHECKER.COMPARE_EVIDENCE_STEP_NAME
            ).update({"continue-on-error": True})
        )

    def test_rejects_disabled_comparison_step(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: self.named_benchmark_step(
                workflow, CHECKER.COMPARE_EVIDENCE_STEP_NAME
            ).update({"if": False})
        )

    def test_rejects_commented_comparison_command(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: self.named_benchmark_step(
                workflow, CHECKER.COMPARE_EVIDENCE_STEP_NAME
            ).update({"run": "# comparison disabled\n"})
        )

    def test_rejects_changed_comparison_command(self) -> None:
        def replace_comparison(workflow: dict[str, Any]) -> None:
            comparison = self.named_benchmark_step(
                workflow, CHECKER.COMPARE_EVIDENCE_STEP_NAME
            )
            comparison["run"] = "exit 0\n"

        self.assert_rejected(mutate_benchmark=replace_comparison)

    def test_rejects_widened_push_branch_scope(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: workflow["on"]["push"].update(
                {"branches": ["main", "feature"]}
            )
        )

    def test_rejects_narrowed_push_branch_scope(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: workflow["on"]["push"].update(
                {"branches": ["release"]}
            )
        )

    def test_rejects_changed_scheduled_execution(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: workflow["on"].update(
                {"schedule": [{"cron": "0 0 * * *"}]}
            )
        )

    def test_rejects_added_benchmark_event(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: workflow["on"].update(
                {"workflow_call": None}
            )
        )

    def test_rejects_removed_benchmark_event(self) -> None:
        def remove_schedule(workflow: dict[str, Any]) -> None:
            del workflow["on"]["schedule"]

        self.assert_rejected(mutate_benchmark=remove_schedule)

    def test_rejects_changed_benchmark_path_scope(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: workflow["on"]["pull_request"].update(
                {"paths": ["docs/**"]}
            )
        )

    def test_rejects_widened_benchmark_path_scope(self) -> None:
        def widen_paths(workflow: dict[str, Any]) -> None:
            workflow["on"]["pull_request"]["paths"].append("docs/**")

        self.assert_rejected(mutate_benchmark=widen_paths)

    def test_rejects_baseline_artifact_name_drift(self) -> None:
        self.assert_rejected(
            mutate_benchmark=lambda workflow: workflow["env"].update(
                {"BASELINE_ARTIFACT_NAME": "different-artifact"}
            )
        )


if __name__ == "__main__":
    unittest.main()
