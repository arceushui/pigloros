#!/usr/bin/env python3
"""Adversarial tests for the Plugin conformance evidence-status checker (R8-F5)."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_plugin_conformance_expected as checker  # noqa: E402

FIXTURES = HERE.parent / "fixtures/conformance"
LAYER = checker.LAYER


class CheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for part in ("expected", "inputs", "profiles", "matrix"):
            shutil.copytree(FIXTURES / part, self.root / part)

    def edit(self, relative: str, change) -> None:
        path = self.root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        change(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def record(self, change, family: str = "resource-exhaustion") -> None:
        self.edit(f"expected/{LAYER}/{family}.json", change)

    def test_the_checked_in_records_pass(self) -> None:
        self.assertEqual(checker.errors(self.root), [])

    def test_a_stale_digest_fails(self) -> None:
        self.record(lambda value: value.update(input_blake3_digest="0" * 64))
        self.assertEqual(len(checker.errors(self.root)), 1)

    def test_an_executed_record_fails(self) -> None:
        self.record(lambda value: value.update(status="executed", executed_at="now"))
        self.assertEqual(len(checker.errors(self.root)), 2)

    def test_a_result_fails(self) -> None:
        self.record(lambda value: value.update(execution_result="pass"))
        self.assertEqual(len(checker.errors(self.root)), 1)

    def test_an_extra_key_fails(self) -> None:
        self.record(lambda value: value.update(extra=1), "denied")
        self.assertEqual(len(checker.errors(self.root)), 1)

    def test_an_executed_matrix_case_fails(self) -> None:
        self.edit("matrix/execution-matrix.json", lambda m: m["cases"][0].update(executed=True))
        self.assertGreaterEqual(len(checker.errors(self.root)), 1)

    def test_a_plugin_matrix_row_fails(self) -> None:
        self.edit(
            "matrix/execution-matrix.json",
            lambda m: m["cases"][0].update(authority_fixture_id=LAYER),
        )
        self.assertEqual(len(checker.errors(self.root)), 1)

    def test_a_missing_profile_record_fails(self) -> None:
        self.edit(f"profiles/{LAYER}/profile.json", lambda p: p["fixtures"].pop())
        self.assertEqual(len(checker.errors(self.root)), 1)


if __name__ == "__main__":
    unittest.main()
