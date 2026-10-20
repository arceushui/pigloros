#!/usr/bin/env python3
"""Tests for .trunk/rust-test-policy.py test-code classification."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

POLICY = Path(__file__).resolve().parent.parent / ".trunk/rust-test-policy.py"


def run_policy(source: str) -> subprocess.CompletedProcess[str]:
    # The policy treats any path with a `tests` component as integration-test
    # code, so the probe file must live outside such a directory.
    with tempfile.TemporaryDirectory(dir="/tmp") as directory:
        path = Path(directory) / "src" / "lib.rs"
        path.parent.mkdir()
        assert "tests" not in path.parts, path
        path.write_text(source, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(POLICY), str(path)],
            capture_output=True,
            text=True,
            check=False,
        )


def gated_module(gate: str) -> str:
    return (
        "pub fn production() -> u8 {\n    1\n}\n\n"
        f"#[cfg({gate})]\n"
        "#[cfg_attr(coverage_nightly, coverage(off))]\n"
        "pub(crate) mod fixture;\n"
    )


class CoverageOffClassificationTest(unittest.TestCase):
    def assert_allowed(self, source: str) -> None:
        result = run_policy(source)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")

    def assert_rejected(self, source: str) -> None:
        result = run_policy(source)
        self.assertEqual(result.returncode, 1)
        self.assertIn("coverage-off-production", result.stdout)

    def test_cfg_test_module_is_test_code(self) -> None:
        self.assert_allowed(gated_module("test"))

    def test_test_support_fixture_module_is_test_code(self) -> None:
        self.assert_allowed(gated_module('any(test, feature = "test-support")'))

    def test_feature_gate_without_test_is_production(self) -> None:
        self.assert_rejected(gated_module('feature = "test-support"'))

    def test_other_feature_gate_is_production(self) -> None:
        self.assert_rejected(gated_module('any(test, feature = "installed-factory")'))

    def test_ungated_production_code_is_rejected(self) -> None:
        self.assert_rejected(
            "#[cfg_attr(coverage_nightly, coverage(off))]\n"
            "pub fn production() -> u8 {\n    1\n}\n"
        )


if __name__ == "__main__":
    unittest.main()
