#!/usr/bin/env python3
"""Contract tests for the documentation-only Rust scope filter."""

from __future__ import annotations

import fnmatch
import pathlib
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
FILTER_PATH = ROOT / ".github" / "rust-scope.yml"
WORKFLOW_PATHS = (
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "codeql.yml",
)
EXPECTED_EXCLUDES = {
    "!**/*.md",
    "!**/*.mdx",
    "!**/*.adoc",
    "!**/*.rst",
    "!.agents/**",
    "!docs/**",
}
EXPECTED_SCOPE_SCOPED_CI_RESULTS = (
    "FMT_RESULT",
    "RUSTDOC_RESULT",
    "TEST_RESULT",
    "CLIPPY_RESULT",
    "AUDIT_RESULT",
    "DENY_RESULT",
    "CARGO_SHEAR_RESULT",
    "GEIGER_RESULT",
    "ASAN_RESULT",
    "DOCKER_BUILD_RESULT",
    "WORLD_CLIENT_WASM_RESULT",
    "WORLD_CLIENT_BROWSER_PARITY_RESULT",
    "COVERAGE_RESULT",
    "CARGO_CRAP_RESULT",
)
EXPECTED_UNCONDITIONAL_CI_RESULTS = (
    "CONFORMANCE_FIXTURES_RESULT",
    "MATERIALIZE_CONFORMANCE_BUNDLES_RESULT",
    "CONFORMANCE_NON_LINUX_RESULT",
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


def excluded(path: str, patterns: list[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(path, pattern[1:])
        or fnmatch.fnmatchcase(path, pattern[1:].removeprefix("**/"))
        for pattern in patterns
        if pattern.startswith("!")
    )


def rust_gate_required(paths: list[str], patterns: list[str]) -> bool:
    return any(not excluded(path, patterns) for path in paths)


class RustScopePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.patterns = load_patterns()

    def test_filter_has_conservative_positive_default(self) -> None:
        self.assertEqual(self.patterns[0], "**")
        self.assertEqual(set(self.patterns[1:]), EXPECTED_EXCLUDES)

    def test_scope_jobs_use_trusted_base_and_fail_closed(self) -> None:
        for workflow_path in WORKFLOW_PATHS:
            with self.subTest(workflow=workflow_path.name):
                with workflow_path.open(encoding="utf-8") as stream:
                    workflow = yaml.safe_load(stream)
                scope_name = (
                    "ci_change_scope" if workflow_path.name == "ci.yml" else "codeql_change_scope"
                )
                scope = workflow["jobs"][scope_name]
                steps = scope["steps"]
                self.assertEqual(
                    steps[0]["with"]["ref"],
                    "${{ github.event.pull_request.base.sha }}",
                )
                filter_step = next(step for step in steps if step.get("id") == "scope")
                self.assertEqual(filter_step["with"]["filters"], ".github/rust-scope.yml")
                self.assertIn("hashFiles('.github/rust-scope.yml') != ''", filter_step["if"])
                full_step = next(step for step in steps if step.get("id") == "full")
                self.assertIn("hashFiles('.github/rust-scope.yml') == ''", full_step["if"])
                self.assertEqual(
                    scope["outputs"]["rust"],
                    "${{ steps.scope.outputs.rust || steps.full.outputs.rust }}",
                )

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
        workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
        with workflow_path.open(encoding="utf-8") as stream:
            workflow = yaml.safe_load(stream)
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
            "check_results true " + " ".join(EXPECTED_SCOPE_SCOPED_CI_RESULTS),
            normalized_run,
        )
        self.assertIn(
            "check_results false " + " ".join(EXPECTED_UNCONDITIONAL_CI_RESULTS),
            normalized_run,
        )
        self.assertIn('"${RUST_SCOPE_RESULT}" == "false"', run)
        self.assertIn('"${result}" == "skipped"', run)
        self.assertIn('"${SCOPE_JOB_RESULT}" != "success"', run)


if __name__ == "__main__":
    unittest.main()
