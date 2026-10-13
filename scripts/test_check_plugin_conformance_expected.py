#!/usr/bin/env python3
"""Adversarial tests for the Plugin conformance evidence-status checker (R8-F5)."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_plugin_conformance_expected as checker  # noqa: E402

FIXTURES = HERE.parent / "fixtures/conformance"
LAYER = checker.LAYER
MATRIX = "matrix/execution-matrix.json"
PROFILE = f"profiles/{LAYER}/profile.json"


class CheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for part in ("expected", "inputs", "profiles", "matrix"):
            shutil.copytree(FIXTURES / part, self.root / part)

    def edit(self, relative: str, change: Callable[[Any], object]) -> None:
        path = self.root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        change(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def record(self, change: Callable[[Any], object], family: str = "resource-exhaustion") -> None:
        self.edit(f"expected/{LAYER}/{family}.json", change)

    def assert_fault(self, text: str) -> None:
        found = checker.errors(self.root)
        self.assertTrue(any(text in fault for fault in found), f"{text!r} not in {found}")

    def test_the_checked_in_records_pass(self) -> None:
        self.assertEqual(checker.errors(self.root), [])

    def test_a_stale_digest_fails(self) -> None:
        self.record(lambda value: value.update(input_blake3_digest="0" * 64))
        self.assert_fault("resource-exhaustion: input_blake3_digest is not")

    def test_an_executed_record_fails(self) -> None:
        self.record(lambda value: value.update(status="executed", executed_at="now"))
        self.assert_fault("resource-exhaustion: status is not 'pending'")
        self.assert_fault("resource-exhaustion: executed_at is not None")

    def test_a_result_fails(self) -> None:
        self.record(lambda value: value.update(execution_result="pass"))
        self.assert_fault("resource-exhaustion: execution_result is not None")

    def test_an_extra_key_fails(self) -> None:
        self.record(lambda value: value.update(extra=1), "denied")
        self.assert_fault("denied: the record is not an object")

    def test_a_non_object_record_fails(self) -> None:
        (self.root / f"expected/{LAYER}/denied.json").write_text("[]", encoding="utf-8")
        self.assert_fault("denied: the record is not an object")

    def test_a_wrong_family_or_case_id_fails(self) -> None:
        self.record(lambda value: value.update(family="denied"))
        self.record(lambda value: value.update(case_id="plugin-conformance-denied"), "malformed")
        self.assert_fault("resource-exhaustion: family is not 'resource-exhaustion'")
        self.assert_fault("malformed: case_id is not 'plugin-conformance-malformed'")

    def test_an_executed_matrix_case_fails(self) -> None:
        self.edit(MATRIX, lambda m: m["cases"][0].update(executed=True))
        self.assert_fault("cases[0]: executed is not false")

    def test_a_digest_in_the_matrix_fails(self) -> None:
        self.edit(MATRIX, lambda m: m["cases"][1].update(expected_result_digest="ab" * 32))
        self.assert_fault("cases[1]: expected_result_digest is not null")

    def test_a_plugin_matrix_case_fails(self) -> None:
        self.edit(MATRIX, lambda m: m["cases"][0].update(authority_fixture_id=LAYER))
        self.assert_fault(f"cases[0]: a {LAYER} row")

    def test_a_plugin_matrix_row_fails(self) -> None:
        self.edit(MATRIX, lambda m: m["rows"][0].update(claim_layer=LAYER))
        self.assert_fault(f"rows[0]: a {LAYER} row")

    def test_an_executed_row_count_fails(self) -> None:
        self.edit(MATRIX, lambda m: m["rows"][2].update(executed_case_count=1))
        self.assert_fault("rows[2]: executed_case_count is not 0")

    def test_inconsistent_counts_fail(self) -> None:
        self.edit(MATRIX, lambda m: m.update(row_count=11, case_count=191))
        self.assert_fault("row_count is 11, the list has 12")
        self.assert_fault("case_count is 191, the list has 192")

    def test_a_malformed_matrix_is_reported(self) -> None:
        self.edit(MATRIX, lambda m: m["rows"].__setitem__(0, 5))
        self.assert_fault("rows[0]: not an object")

    def test_a_missing_profile_record_fails(self) -> None:
        self.edit(PROFILE, lambda p: p["fixtures"].pop())
        self.assert_fault("the profile binds")

    def test_a_foreign_profile_record_fails(self) -> None:
        self.edit(PROFILE, lambda p: p["fixtures"][0].update(expected="expected/other.json"))
        self.assert_fault("expected/other.json")

    def test_a_malformed_profile_is_reported(self) -> None:
        self.edit(PROFILE, lambda p: p.update(fixtures=7))
        self.assert_fault("the profile binds")


if __name__ == "__main__":
    unittest.main()
