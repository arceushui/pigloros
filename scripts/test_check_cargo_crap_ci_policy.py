#!/usr/bin/env python3
"""Adversarial tests for the cargo-crap GitHub Actions policy checker."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import tempfile
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_cargo_crap_ci_policy.py"
SPEC = importlib.util.spec_from_file_location("check_cargo_crap_ci_policy", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class CargoCrapCiPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        with (ROOT / ".github/workflows/ci.yml").open(encoding="utf-8") as stream:
            self.workflow = yaml.safe_load(stream)

    def assert_rejected(self, mutate) -> None:
        workflow = copy.deepcopy(self.workflow)
        mutate(workflow)
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory) / "ci.yml"
            fixture.write_text(yaml.safe_dump(workflow, sort_keys=False), encoding="utf-8")
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_workflow(fixture)

    def cargo_crap_step(self, workflow: dict, name: str) -> dict:
        return next(
            step
            for step in workflow["jobs"]["cargo-crap"]["steps"]
            if step.get("name") == name
        )

    def test_repository_workflow_passes(self) -> None:
        CHECKER.check_workflow(ROOT / ".github/workflows/ci.yml")

    def test_rejects_unpinned_cargo_crap(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(workflow, "Install cargo-crap")[
                "with"
            ].update({"tool": "cargo-crap"})
        )

    def test_rejects_optimistic_missing_coverage(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Analyze CRAP score changes"
            ).update(
                {
                    "run": self.cargo_crap_step(
                        workflow, "Analyze CRAP score changes"
                    )["run"].replace("--missing pessimistic", "--missing optimistic")
                }
            )
        )

    def test_rejects_missing_baseline(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Analyze CRAP score changes"
            ).update(
                {
                    "run": self.cargo_crap_step(
                        workflow, "Analyze CRAP score changes"
                    )["run"].replace(
                        '--baseline "${{ runner.temp }}/cargo-crap-baseline.json"',
                        "",
                    )
                }
            )
        )

    def test_rejects_required_arguments_hidden_in_a_comment(self) -> None:
        def replace_analysis(workflow: dict) -> None:
            step = self.cargo_crap_step(workflow, "Analyze CRAP score changes")
            original = step["run"]
            step["run"] = (
                "python -c 'import json; "
                'json.dump({\"version\":\"0.2.2\",\"entries\":[],\"removed\":[]}, '
                'open(\"${RUNNER_TEMP}/cargo-crap-report.json\",\"w\"))\'\n'
                f"# {original}"
            )

        self.assert_rejected(replace_analysis)

    def test_rejects_nonzero_regression_epsilon(self) -> None:
        def weaken_epsilon(workflow: dict) -> None:
            step = self.cargo_crap_step(workflow, "Analyze CRAP score changes")
            step["run"] = step["run"].replace("--epsilon 0 ", "--epsilon 0.01 ")

        self.assert_rejected(weaken_epsilon)

    def test_rejects_repository_configuration(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Reject repository cargo-crap configuration"
            ).update({"run": "true"})
        )

    def test_rejects_unpinned_bootstrap_base(self) -> None:
        def weaken_bootstrap(workflow: dict) -> None:
            step = self.cargo_crap_step(
                workflow, "Resolve trusted cargo-crap baseline"
            )
            step["run"] = step["run"].replace(
                'test "${BASE_SHA}" = "45bdac85b29d273573583f846ba7acd2b3a12573"',
                "true",
            )

        self.assert_rejected(weaken_bootstrap)

    def test_requires_bounded_baseline_retry(self) -> None:
        def remove_retry(workflow: dict) -> None:
            step = self.cargo_crap_step(
                workflow, "Resolve trusted cargo-crap baseline"
            )
            step["run"] = step["run"].replace(
                "for ((attempt = 1; attempt <= 30; attempt++)); do",
                "while true; do",
            )

        self.assert_rejected(remove_retry)

    def test_requires_scoped_coverage(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["coverage"].update(
                {"if": "${{ always() }}"}
            )
        )

    def test_requires_scoped_cargo_crap(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"].update(
                {"if": "${{ always() }}"}
            )
        )

    def test_requires_baseline_retry_delay(self) -> None:
        def remove_delay(workflow: dict) -> None:
            step = self.cargo_crap_step(
                workflow, "Resolve trusted cargo-crap baseline"
            )
            step["run"] = step["run"].replace("sleep 10", "sleep 1")

        self.assert_rejected(remove_delay)

    def test_requires_main_baseline_publication(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"]["steps"].pop()
        )

    def test_rejects_nonblocking_verdict(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Enforce cargo-crap policy"
            ).update({"continue-on-error": True})
        )

    def test_rejects_shallow_checkout(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"]["steps"][0].update(
                {"with": {"fetch-depth": 1}}
            )
        )

    def test_requires_visible_job_after_coverage(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"].update(
                {"needs": "test"}
            )
        )

    def test_requires_cargo_crap_in_aggregate_gate(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["ci-gate"]["needs"].remove(
                "cargo-crap"
            )
        )

    def test_requires_aggregate_verdict_to_read_cargo_crap(self) -> None:
        def remove_result(workflow: dict) -> None:
            step = workflow["jobs"]["ci-gate"]["steps"][0]
            step["env"].pop("CARGO_CRAP_RESULT")

        self.assert_rejected(remove_result)


if __name__ == "__main__":
    unittest.main()
