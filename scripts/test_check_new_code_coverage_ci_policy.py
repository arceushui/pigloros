#!/usr/bin/env python3
"""Adversarial tests for the blocking new-code coverage workflow policy."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_new_code_coverage_ci_policy.py"
BASE_RESOLVER = ROOT / "scripts" / "resolve-coverage-base.sh"
SPEC = importlib.util.spec_from_file_location("check_new_code_coverage_ci_policy", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class NewCodeCoverageCiPolicyTests(unittest.TestCase):
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

    @staticmethod
    def coverage_step(workflow: dict, name: str) -> dict:
        return next(
            step for step in workflow["jobs"]["coverage"]["steps"] if step.get("name") == name
        )

    def test_repository_workflow_passes(self) -> None:
        CHECKER.check_workflow(ROOT / ".github/workflows/ci.yml")

    def test_rejects_missing_changed_file_guard(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["coverage"]["steps"].remove(
                self.coverage_step(workflow, "Reject changed Rust files missing from coverage")
            )
        )

    def test_rejects_non_blocking_changed_file_guard(self) -> None:
        self.assert_rejected(
            lambda workflow: self.coverage_step(
                workflow, "Reject changed Rust files missing from coverage"
            ).update({"continue-on-error": True})
        )

    def test_rejects_changed_guard_command(self) -> None:
        self.assert_rejected(
            lambda workflow: self.coverage_step(
                workflow, "Reject changed Rust files missing from coverage"
            ).update({"run": "true"})
        )

    def test_rejects_missing_json_export(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["coverage"]["steps"].remove(
                self.coverage_step(workflow, "Export coverage details for new-code gate")
            )
        )

    def test_rejects_missing_covgate_step(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["coverage"]["steps"].remove(
                self.coverage_step(
                    workflow, "Enforce new Rust code coverage (lines ≥99%, regions ≥99%)"
                )
            )
        )

    def test_rejects_policy_job_outside_blocking_gate(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["ci-gate"]["needs"].remove(
                "new-code-coverage-policy"
            )
        )

    def test_resolves_diverged_base_like_covgate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = pathlib.Path(directory)
            self.run_git(repo, "init", "-q")
            self.run_git(repo, "config", "user.email", "coverage-test@example.invalid")
            self.run_git(repo, "config", "user.name", "coverage-test")
            source = repo / "src" / "lib.rs"
            shared = repo / "src" / "shared.rs"
            source.parent.mkdir()
            source.write_text("pub fn value() -> u8 { 1 }\n", encoding="utf-8")
            shared.write_text("pub fn shared() -> u8 { 1 }\n", encoding="utf-8")
            self.run_git(repo, "add", "src")
            self.run_git(repo, "commit", "-qm", "base")
            base = self.git_output(repo, "rev-parse", "HEAD")
            self.run_git(repo, "checkout", "-qb", "feature")
            source.write_text("pub fn value() -> u8 { 2 }\n", encoding="utf-8")
            self.run_git(repo, "add", "src/lib.rs")
            self.run_git(repo, "commit", "-qm", "feature")
            self.run_git(repo, "checkout", "-qb", "upstream", base)
            shared.write_text("pub fn shared() -> u8 { 2 }\n", encoding="utf-8")
            self.run_git(repo, "add", "src/shared.rs")
            self.run_git(repo, "commit", "-qm", "upstream")
            upstream = self.git_output(repo, "rev-parse", "HEAD")
            self.run_git(repo, "checkout", "-q", "feature")

            result = subprocess.run(
                [str(BASE_RESOLVER), upstream],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), base)

    @staticmethod
    def run_git(repo: pathlib.Path, *args: str) -> None:
        result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(result.stderr)

    @staticmethod
    def git_output(repo: pathlib.Path, *args: str) -> str:
        result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return result.stdout.strip()


if __name__ == "__main__":
    unittest.main()
