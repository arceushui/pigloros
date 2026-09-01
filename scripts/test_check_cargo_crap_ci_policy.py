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


if __name__ == "__main__":
    unittest.main()
