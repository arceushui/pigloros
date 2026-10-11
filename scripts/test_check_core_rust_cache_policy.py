#!/usr/bin/env python3
"""Adversarial tests for the core Rust cache workflow policy checker."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import tempfile
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_core_rust_cache_policy.py"
SPEC = importlib.util.spec_from_file_location("check_core_rust_cache_policy", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class CoreRustCachePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        with (ROOT / ".github" / "workflows" / "ci.yml").open(encoding="utf-8") as stream:
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
    def cache_step(workflow: dict, job_name: str) -> dict:
        return next(
            step
            for step in workflow["jobs"][job_name]["steps"]
            if step.get("uses") == CHECKER.RUST_CACHE_ACTION
        )

    def test_repository_workflow_passes(self) -> None:
        CHECKER.check_workflow()

    def test_core_cache_identities_are_distinct(self) -> None:
        self.assertEqual(
            {
                job_name: self.cache_step(self.workflow, job_name)["with"]["shared-key"]
                for job_name in CHECKER.CORE_CACHE_KEYS
            },
            CHECKER.CORE_CACHE_KEYS,
        )

    def test_rejects_pull_request_cache_writes(self) -> None:
        def remove_main_only_save_condition(workflow: dict) -> None:
            del self.cache_step(workflow, "test")["with"]["save-if"]

        self.assert_rejected(remove_main_only_save_condition)

    def test_rejects_non_main_cache_writer(self) -> None:
        def save_from_every_ref(workflow: dict) -> None:
            self.cache_step(workflow, "clippy")["with"]["save-if"] = "${{ true }}"

        self.assert_rejected(save_from_every_ref)

    def test_rejects_merged_coverage_and_test_cache_identity(self) -> None:
        def merge_incompatible_cache_identities(workflow: dict) -> None:
            self.cache_step(workflow, "coverage")["with"]["shared-key"] = "test"

        self.assert_rejected(merge_incompatible_cache_identities)


if __name__ == "__main__":
    unittest.main()
