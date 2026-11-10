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
        for part in ("expected", "inputs", "oracles", "profiles", "matrix"):
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

    def test_a_pending_record_fails(self) -> None:
        self.record(lambda value: value.update(status="pending", execution_result=None))
        self.assert_fault("resource-exhaustion: status is not 'executed'")
        self.assert_fault("resource-exhaustion: execution_result is not")

    def test_an_execution_time_fails(self) -> None:
        self.record(lambda value: value.update(executed_at="now"))
        self.assert_fault("resource-exhaustion: executed_at is not None")

    def test_a_result_other_than_both_passing_runs_fails(self) -> None:
        self.record(lambda value: value["execution_result"]["modes"].pop())
        self.record(lambda value: value["execution_result"]["modes"][0].update(outcome="fail"), "denied")
        self.record(lambda value: value["execution_result"].update(evidence="hosted"), "downgrade")
        self.assert_fault("resource-exhaustion: execution_result is not")
        self.assert_fault("denied: execution_result is not")
        self.assert_fault("downgrade: execution_result is not")

    def test_an_output_digest_that_is_not_the_oracle_fails(self) -> None:
        oracle = self.root / f"oracles/{LAYER}/positive.json"
        oracle.write_bytes(oracle.read_bytes() + b" ")
        self.assert_fault("positive: execution_result is not")

    def test_a_failure_code_that_is_not_the_oracle_fails(self) -> None:
        self.edit(f"oracles/{LAYER}/malformed.json", lambda o: o["oracle"].update(code_id="x"))
        self.assert_fault("malformed: execution_result is not")

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
        # cases[129] is NI-ARCHIVE-009-S-A, an Air-Gapped case no slice flips before N7.
        self.edit(MATRIX, lambda m: m["cases"][129].update(executed=True))
        self.assert_fault("cases[129]: executed is not false")

    def test_a_digest_in_the_matrix_fails(self) -> None:
        self.edit(MATRIX, lambda m: m["cases"][1].update(expected_result_digest="ab" * 32))
        self.assert_fault("cases[1]: expected_result_digest is not null")

    def test_a_plugin_matrix_case_fails(self) -> None:
        self.edit(MATRIX, lambda m: m["cases"][0].update(authority_fixture_id=LAYER))
        self.assert_fault(f"cases[0]: a {LAYER} row")

    def test_a_plugin_matrix_row_fails(self) -> None:
        self.edit(MATRIX, lambda m: m["rows"][0].update(claim_layer=LAYER))
        self.assert_fault(f"rows[0]: a {LAYER} row")

    def test_a_wrong_executed_row_count_fails(self) -> None:
        self.edit(MATRIX, lambda m: m["rows"][8].update(executed_case_count=1))
        self.assert_fault("rows[8]: executed_case_count is not its 12 cases")

    def test_an_unexecuted_total_fails(self) -> None:
        cases = json.loads((FIXTURES / MATRIX).read_text(encoding="utf-8"))["cases"]
        executed = sum(1 for case in cases if case["executed"] is True)
        self.edit(MATRIX, lambda m: m.update(executed_case_count=0))
        self.assert_fault(f"executed_case_count is not the {executed} executed cases")

    def test_an_executed_air_gapped_n1_case_fails(self) -> None:
        index = next(
            position
            for position, case in enumerate(json.loads((FIXTURES / MATRIX).read_text())["cases"])
            if case["case_id"] == "NI-PUBLIC-006-S-A"
        )
        self.edit(MATRIX, lambda m: m["cases"][index].update(executed=True))
        self.assert_fault(f"cases[{index}]: executed is not false")

    def case_index(self, case_id: str) -> int:
        cases = json.loads((FIXTURES / MATRIX).read_text(encoding="utf-8"))["cases"]
        return next(index for index, case in enumerate(cases) if case["case_id"] == case_id)

    def test_an_n1_authority_result_digest_fails(self) -> None:
        index = self.case_index("NI-EVAL-007-D-R")
        self.edit(MATRIX, lambda m: m["cases"][index].update(authority_result_digest="ab" * 32))
        self.assert_fault(f"cases[{index}]: authority_result_digest is not null")

    def test_an_executed_n1_case_without_a_hex_digest_fails(self) -> None:
        index = self.case_index("NI-EVAL-007-D-R")
        for digest in (None, "AB" * 32, "ab" * 31, 7):
            self.edit(MATRIX, lambda m, d=digest: m["cases"][index].update(expected_result_digest=d))
            self.assert_fault(f"cases[{index}]: expected_result_digest is not 64 lowercase hex")

    def test_an_open_n1_case_carrying_a_digest_fails(self) -> None:
        index = self.case_index("NI-PUBLIC-006-W-A")
        self.edit(MATRIX, lambda m: m["cases"][index].update(expected_result_digest="ab" * 32))
        self.assert_fault(f"cases[{index}]: expected_result_digest is not null")

    def test_an_unexecuted_n1_case_with_a_result_fails(self) -> None:
        index = self.case_index("NI-EVAL-007-S-L")
        self.edit(MATRIX, lambda m: m["cases"][index].update(executed=False))
        self.assert_fault(f"cases[{index}]: expected_result_digest is not null")
        self.assert_fault(f"cases[{index}]: expected_result is not null")

    def test_an_n1_row_count_disagreeing_with_its_cases_fails(self) -> None:
        self.edit(MATRIX, lambda m: m["rows"][5].update(executed_case_count=11))
        self.assert_fault("rows[5]: executed_case_count is not its 12 cases")

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
