#!/usr/bin/env python3
"""Adversarial tests for the cargo-crap delta report policy."""

from __future__ import annotations

import importlib.util
import math
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_cargo_crap_report.py"
SPEC = importlib.util.spec_from_file_location("check_cargo_crap_report", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def entry(*, status: str, crap: float) -> dict:
    if status == "new":
        baseline_crap = None
        delta = None
    elif status == "regressed":
        baseline_crap = crap - 1
        delta = 1.0
    elif status == "improved":
        baseline_crap = crap + 1
        delta = -1.0
    else:
        baseline_crap = crap
        delta = 0.0
    return {
        "file": "src/lib.rs",
        "function": "example",
        "line": 7,
        "cyclomatic": 2,
        "coverage": 100.0,
        "crap": crap,
        "baseline_crap": baseline_crap,
        "delta": delta,
        "status": status,
    }


def report(*entries: dict) -> dict:
    return {"version": "0.2.2", "entries": list(entries), "removed": []}


class CargoCrapReportTests(unittest.TestCase):
    def test_unchanged_legacy_score_above_ceiling_passes(self) -> None:
        self.assertEqual(CHECKER.policy_findings(report(entry(status="unchanged", crap=51))), [])

    def test_regression_below_absolute_ceiling_fails(self) -> None:
        findings = CHECKER.policy_findings(report(entry(status="regressed", crap=12)))
        self.assertEqual(len(findings), 1)

    def test_one_ulp_round_trip_noise_is_not_a_regression(self) -> None:
        current = math.nextafter(12.0, math.inf)
        value = entry(status="regressed", crap=current)
        value["baseline_crap"] = 12.0
        value["delta"] = current - 12.0
        self.assertEqual(CHECKER.policy_findings(report(value)), [])

    def test_two_ulp_increase_is_a_regression(self) -> None:
        current = math.nextafter(math.nextafter(12.0, math.inf), math.inf)
        value = entry(status="regressed", crap=current)
        value["baseline_crap"] = 12.0
        value["delta"] = current - 12.0
        self.assertEqual(len(CHECKER.policy_findings(report(value))), 1)

    def test_moved_function_score_increase_is_a_regression(self) -> None:
        value = entry(status="moved", crap=9.0)
        value["baseline_crap"] = 8.0
        value["delta"] = 1.0
        self.assertEqual(len(CHECKER.policy_findings(report(value))), 1)

    def test_status_cannot_hide_a_score_increase(self) -> None:
        value = entry(status="unchanged", crap=9.0)
        value["baseline_crap"] = 8.0
        value["delta"] = 1.0
        self.assertEqual(len(CHECKER.policy_findings(report(value))), 1)

    def test_new_function_above_ceiling_fails(self) -> None:
        findings = CHECKER.policy_findings(report(entry(status="new", crap=30.01)))
        self.assertEqual(len(findings), 1)

    def test_new_function_at_ceiling_passes(self) -> None:
        self.assertEqual(CHECKER.policy_findings(report(entry(status="new", crap=30))), [])

    def test_improved_moved_and_removed_functions_pass(self) -> None:
        value = report(entry(status="improved", crap=4), entry(status="moved", crap=7))
        value["removed"] = [{"file": "src/old.rs", "function": "old", "baseline_crap": 9}]
        self.assertEqual(CHECKER.policy_findings(value), [])

    def test_unknown_report_version_fails_closed(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.policy_findings({"version": "9.9.9", "entries": [], "removed": []})

    def test_empty_report_fails_closed(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.policy_findings(report())

    def test_unknown_status_fails_closed(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.policy_findings(report(entry(status="waived", crap=1)))

    def test_boolean_score_is_not_accepted_as_a_number(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.policy_findings(report(entry(status="new", crap=True)))


if __name__ == "__main__":
    unittest.main()
