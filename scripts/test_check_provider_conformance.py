#!/usr/bin/env python3
"""Tests for the provider conformance judge (#216)."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_provider_conformance.py"
MANIFEST_PATH = ROOT / "crates" / "pos-conformance" / "tests" / "vectors" / "provider-cases-v1.json"
SPEC = importlib.util.spec_from_file_location("check_provider_conformance", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

AGR1 = "ab" * 32
MANIFEST = CHECKER.load_manifest(MANIFEST_PATH)
CASES = {case["id"]: case for case in MANIFEST["cases"]}
SINGLE = [case for case in MANIFEST["cases"] if case["driver"] == "single-execute"]


def perfect(case: dict, *, code: int | None = None) -> list[str]:
    """The lines a conforming provider shows for a terminal case."""
    expect = case["expect"]
    events = [11, 12] + ([code] if code is not None else expect["codes"][:1])
    return [
        "execute\texecuted",
        f"outcome\t{expect['outcome']}",
        "events\t" + ",".join(str(event) for event in events),
        f"agr1\t{AGR1}",
    ]


class ManifestTests(unittest.TestCase):
    def test_the_vector_has_nineteen_cases_and_twelve_single_execute_cases(self) -> None:
        self.assertEqual(len(MANIFEST["cases"]), 19)
        self.assertEqual(len(SINGLE), 12)
        self.assertEqual(MANIFEST["overshoot"], 2)

    def test_an_unsupported_manifest_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.json"
            path.write_text(json.dumps({"version": 2, "cases": []}))
            with self.assertRaises(CHECKER.ConformanceError):
                CHECKER.load_manifest(path)


class JudgeTests(unittest.TestCase):
    def test_every_single_execute_case_passes_on_its_expected_outcome_with_cleanup(self) -> None:
        for case in SINGLE:
            verdict = CHECKER.judge_case(case, perfect(case), leaked_resources=0)
            self.assertEqual(verdict, {"id": case["id"], "status": "passed"}, case["id"])

    def test_without_cleanup_evidence_a_matching_case_is_unproven_not_passed(self) -> None:
        for case in SINGLE:
            verdict = CHECKER.judge_case(case, perfect(case))
            self.assertEqual(verdict["status"], "unproven", case["id"])

    def test_a_leak_fails_the_case(self) -> None:
        case = CASES["filesystem-escape"]
        verdict = CHECKER.judge_case(case, perfect(case), leaked_resources=1)
        self.assertEqual((verdict["status"], verdict["failure"]), ("failed", "resource_leak"))

    def test_a_different_outcome_fails_with_the_blocker_note(self) -> None:
        case = CASES["filesystem-escape"]
        lines = perfect(case)
        lines[1] = "outcome\tUnavailableAfterAdmission"
        verdict = CHECKER.judge_case(case, lines, leaked_resources=0)
        self.assertEqual((verdict["status"], verdict["failure"]), ("failed", "outcome"))
        self.assertEqual(verdict["note"], CHECKER.KNOWN_BLOCKER)
        self.assertIn("UnavailableAfterAdmission", verdict["shown"])
        bare = CHECKER.judge_case(case, lines, leaked_resources=0, blocker=None)
        self.assertNotIn("note", bare)

    def test_a_terminal_code_outside_the_expected_ones_fails(self) -> None:
        case = CASES["task-exhaustion"]
        for code in (4, 6, 8):
            verdict = CHECKER.judge_case(case, perfect(case, code=code), leaked_resources=0)
            self.assertEqual(verdict.get("failure"), "terminal_code", code)
        verdict = CHECKER.judge_case(case, perfect(case, code=5), leaked_resources=0)
        self.assertEqual(verdict["status"], "passed")

    def test_memory_exhaustion_accepts_either_of_its_two_codes(self) -> None:
        case = CASES["memory-exhaustion"]
        for code in (3, 4):
            verdict = CHECKER.judge_case(case, perfect(case, code=code), leaked_resources=0)
            self.assertEqual(verdict["status"], "passed", code)

    def test_a_missing_terminal_code_fails_when_one_is_expected(self) -> None:
        case = CASES["oversized-output"]
        lines = perfect(case)
        lines[2] = "events\t11,12"
        verdict = CHECKER.judge_case(case, lines, leaked_resources=0)
        self.assertEqual(verdict["failure"], "terminal_code")
        lines[2] = "events\t"
        verdict = CHECKER.judge_case(case, lines, leaked_resources=0)
        self.assertEqual(verdict["failure"], "terminal_code")

    def test_a_terminal_code_fails_when_none_is_expected(self) -> None:
        case = CASES["network-escape"]
        verdict = CHECKER.judge_case(case, perfect(case, code=8), leaked_resources=0)
        self.assertEqual(verdict["failure"], "terminal_code")

    def test_an_attempt_without_its_identity_fails(self) -> None:
        case = CASES["filesystem-escape"]
        for agr1 in ("", "ab", "AB" * 32):
            lines = perfect(case)[:-1] + ([f"agr1\t{agr1}"] if agr1 else [])
            verdict = CHECKER.judge_case(case, lines, leaked_resources=0)
            self.assertEqual(verdict["failure"], "attempt_identity", agr1)

    def test_an_exchange_that_did_not_execute_fails_the_case(self) -> None:
        case = CASES["filesystem-escape"]
        for lines, shown in (
            (["execute\trefused\tSandboxUnavailable"], "refused SandboxUnavailable"),
            (["execute\tfailed\tprovider execution failed before admission"], "failed"),
            (["execute\tunreportable"], "unreportable"),
            ([], "missing"),
        ):
            verdict = CHECKER.judge_case(case, lines, leaked_resources=0)
            self.assertEqual(verdict["failure"], "outcome")
            self.assertTrue(verdict["shown"].startswith(shown.split()[0]), verdict["shown"])

    def test_a_refusal_case_needs_one_of_its_codes(self) -> None:
        case = {
            "id": "synthetic",
            "driver": "single-execute",
            "expect": {"kind": "refused", "codes": ["TrustRevoked", "AuthorityMismatch"]},
        }
        ok = CHECKER.judge_case(case, ["execute\trefused\tTrustRevoked"], leaked_resources=0)
        self.assertEqual(ok["status"], "passed")
        wrong = CHECKER.judge_case(case, ["execute\trefused\tCleanupFailed"], leaked_resources=0)
        self.assertEqual(wrong["failure"], "refusal")
        executed = CHECKER.judge_case(case, perfect(CASES["filesystem-escape"]), leaked_resources=0)
        self.assertEqual(executed["failure"], "outcome")

    def test_every_case_that_is_not_single_execute_is_not_run_with_its_reason(self) -> None:
        others = [case for case in MANIFEST["cases"] if case["driver"] != "single-execute"]
        self.assertEqual(len(others), 7)
        for case in others:
            verdict = CHECKER.judge_case(case, perfect(CASES["filesystem-escape"]))
            self.assertEqual(verdict["status"], "not run", case["id"])
            self.assertEqual(verdict["reason"], CHECKER.NOT_RUN_REASONS[case["driver"]])
            self.assertIn("S4c", verdict["reason"])

    def test_a_single_execute_case_without_a_report_is_not_run(self) -> None:
        verdict = CHECKER.judge_case(CASES["filesystem-escape"], None)
        self.assertEqual(verdict["status"], "not run")
        self.assertIn("no report", verdict["reason"])


class ReportTests(unittest.TestCase):
    def test_events_and_terminal_codes(self) -> None:
        self.assertIsNone(CHECKER.terminal_code([]))
        self.assertIsNone(CHECKER.terminal_code([11, 12]))
        self.assertEqual(CHECKER.terminal_code([11, 12, 10]), 10)
        self.assertEqual(CHECKER.terminal_code([0]), 0)
        self.assertIsNone(CHECKER.terminal_code([10, 11]))

    def test_parse_report_reads_the_lines_it_judges_and_ignores_the_rest(self) -> None:
        report = CHECKER.parse_report(
            ["execute\texecuted", "outcome\tCompleted", "events\t11,12", "ready1\tpresent", f"agr1\t{AGR1}", ""]
        )
        self.assertEqual(report["kind"], "executed")
        self.assertEqual(report["events"], [11, 12])
        self.assertEqual(report["agr1"], AGR1)
        self.assertEqual(CHECKER.parse_report(["something"])["kind"], "missing")
        refused = CHECKER.parse_report(["execute\trefused\tundecodable"])
        self.assertEqual((refused["kind"], refused["detail"]), ("refused", "undecodable"))


class DirectoryTests(unittest.TestCase):
    def write_case(self, root: pathlib.Path, case: dict, lines: list[str], timings: str) -> None:
        directory = root / case["id"]
        directory.mkdir()
        (directory / "execute-report").write_text("\n".join(lines) + "\n")
        (directory / "timings").write_text(timings)

    def test_timings_are_parsed_and_malformed_ones_refused(self) -> None:
        self.assertEqual(
            CHECKER.parse_timings("stage\t1.5\nexecute\t70\n"), {"stage": 1.5, "execute": 70.0}
        )
        for text in ("stage\n", "stage\tfast\n", "\t1\n", "stage\t-1\n"):
            with self.assertRaises(CHECKER.ConformanceError, msg=text):
                CHECKER.parse_timings(text)

    def test_a_directory_is_judged_and_the_rest_listed_as_not_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            case = CASES["filesystem-escape"]
            self.write_case(root, case, perfect(case), "stage\t2\nexecute\t70.5\n")
            verdicts = CHECKER.judge_directory(MANIFEST, root)
            by_id = {verdict["id"]: verdict for verdict in verdicts}
            self.assertEqual(len(verdicts), 19)
            self.assertEqual(by_id["filesystem-escape"]["status"], "unproven")
            self.assertEqual(by_id["filesystem-escape"]["timings"], {"stage": 2.0, "execute": 70.5})
            self.assertEqual(by_id["task-exhaustion"]["status"], "not run")
            self.assertNotIn("timings", by_id["task-exhaustion"])
            self.assertEqual(by_id["cancel-while-running"]["status"], "not run")
            text = CHECKER.render(verdicts)
            self.assertIn("unproven  filesystem-escape 72.5s", text)
            self.assertIn("not run   cancel-while-running", text)

    def test_exit_status_fails_on_failed_and_unproven_and_optionally_on_not_run(self) -> None:
        passed = {"id": "a", "status": "passed"}
        for bad in ("failed", "unproven"):
            self.assertEqual(CHECKER.exit_status([passed, {"id": "b", "status": bad}], require_all=False), 1)
        not_run = {"id": "c", "status": "not run"}
        self.assertEqual(CHECKER.exit_status([passed, not_run], require_all=False), 0)
        self.assertEqual(CHECKER.exit_status([passed, not_run], require_all=True), 1)
        self.assertEqual(CHECKER.exit_status([passed], require_all=True), 0)

    def test_the_command_line_judges_a_directory_and_refuses_bad_usage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            case = CASES["filesystem-escape"]
            self.write_case(root, case, perfect(case), "stage\t1\n")
            self.assertEqual(CHECKER.main([str(MANIFEST_PATH), str(root)]), 1)
            self.assertEqual(CHECKER.main(["only-one"]), 2)
            self.assertEqual(CHECKER.main([str(MANIFEST_PATH), str(root), "--require-all"]), 1)


if __name__ == "__main__":
    unittest.main()
