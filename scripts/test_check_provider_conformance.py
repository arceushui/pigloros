#!/usr/bin/env python3
"""Tests for the provider conformance judge (#216)."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_provider_conformance.py"
VECTORS = ROOT / "crates" / "pos-conformance" / "tests" / "vectors"
MANIFEST_PATH = VECTORS / "provider-cases-v1.json"
SPEC = importlib.util.spec_from_file_location("check_provider_conformance", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

AGR1 = "ab" * 32
MANIFEST = CHECKER.load_manifest(MANIFEST_PATH)
CASES = {case["id"]: case for case in MANIFEST["cases"]}
SINGLE = [case for case in MANIFEST["cases"] if case["driver"] == "single-execute"]
OTHERS = [case for case in MANIFEST["cases"] if case["driver"] != "single-execute"]
CASE = CASES["filesystem-escape"]
CLEAN = ["clean"]
CLEAN_TEXT = "clean\n"
REFUSAL_CASE = {
    "id": "synthetic",
    "driver": "single-execute",
    "attempts": 1,
    "arguments": [],
    "expect": {"kind": "refused", "codes": ["TrustRevoked", "AuthorityMismatch"]},
}


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


def text(lines: list[str]) -> str:
    return "\n".join(lines) + "\n"


def pin_of(manifest: object) -> str:
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def run_main(arguments: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = CHECKER.main(arguments)
    return status, out.getvalue(), err.getvalue()


class TempTestCase(unittest.TestCase):
    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = pathlib.Path(holder.name) / "cases"
        self.root.mkdir()

    def write_case(
        self,
        case: dict,
        lines: list[str] | None = None,
        *,
        timings: str | None = None,
        leftovers: str | None = None,
    ) -> pathlib.Path:
        directory = self.root / case["id"]
        directory.mkdir(exist_ok=True)
        if lines is not None:
            (directory / "execute-report").write_text(text(lines))
        if timings is not None:
            (directory / "timings").write_text(timings)
        if leftovers is not None:
            (directory / "leftovers").write_bytes(leftovers.encode("ascii"))
        return directory

    def passing_directory(self) -> None:
        for case in SINGLE:
            self.write_case(case, perfect(case), timings="stage\t1\n", leftovers=CLEAN_TEXT)

    def write_manifest(self, manifest: object) -> pathlib.Path:
        path = self.root.parent / "manifest.json"
        path.write_text(json.dumps(manifest))
        return path


class ManifestTests(TempTestCase):
    def test_the_vector_has_nineteen_cases_and_twelve_single_execute_cases(self) -> None:
        self.assertEqual(len(MANIFEST["cases"]), 19)
        self.assertEqual(len(SINGLE), 12)
        self.assertEqual(len(OTHERS), 7)
        self.assertEqual(MANIFEST["overshoot"], 2)

    def mutated(self, change) -> dict:
        manifest = copy.deepcopy(MANIFEST)
        change(manifest)
        return manifest

    def test_a_malformed_manifest_is_refused_with_a_clear_error(self) -> None:
        def drop(key: str):
            return lambda m: m["cases"][0].pop(key)

        def expect(change):
            return lambda m: change(m["cases"][0]["expect"])

        broken = {
            "version 2": lambda m: m.update(version=2),
            "no cases": lambda m: m.update(cases=[]),
            "cases not a list": lambda m: m.update(cases={}),
            "duplicate id": lambda m: m["cases"][1].update(id=m["cases"][0]["id"]),
            "path id": lambda m: m["cases"][0].update(id="../escape"),
            "slash id": lambda m: m["cases"][0].update(id="a/b"),
            "unknown driver": lambda m: m["cases"][0].update(driver="mystery"),
            "two attempts": lambda m: m["cases"][0].update(attempts=2),
            "bool attempts": lambda m: m["cases"][0].update(attempts=True),
            "no id": drop("id"),
            "no driver": drop("driver"),
            "no expect": drop("expect"),
            "no attempts": drop("attempts"),
            "no arguments": drop("arguments"),
            "expect not object": lambda m: m["cases"][0].update(expect=[]),
            "unknown kind": expect(lambda e: e.update(kind="cancelled")),
            "codes missing": expect(lambda e: e.pop("codes")),
            "string code": expect(lambda e: e.update(codes=["5"])),
            "bool code": expect(lambda e: e.update(codes=[True])),
            "no outcome": expect(lambda e: e.pop("outcome")),
            "empty refusal": expect(lambda e: e.update(kind="refused", codes=[])),
            "case not object": lambda m: m["cases"].append(3),
        }
        for name, change in broken.items():
            with self.assertRaises(CHECKER.ConformanceError, msg=name):
                CHECKER.validate_manifest(self.mutated(change))
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.validate_manifest([])

    def test_a_manifest_file_that_cannot_be_read_is_refused(self) -> None:
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.load_manifest(self.root / "absent.json")
        path = self.root.parent / "bad.json"
        path.write_bytes(b"\xff")
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.load_manifest(path)
        path.write_text("{")
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.load_manifest(path)


class JudgeTests(unittest.TestCase):
    def test_every_single_execute_case_passes_on_its_expected_outcome_with_cleanup(self) -> None:
        for case in SINGLE:
            verdict = CHECKER.judge_case(case, perfect(case), CLEAN)
            self.assertEqual(verdict, {"id": case["id"], "status": "passed"}, case["id"])

    def test_a_full_guest_report_with_its_evidence_rows_passes(self) -> None:
        lines = perfect(CASE) + [
            "ready1\tpresent",
            "release1\tabsent",
            f"rqe1\t{AGR1}",
            f"koe1\t{AGR1}",
            f"tme1\t{AGR1}",
            f"raw\tagr1\t{AGR1}",
            f"raw\tspr1\t{AGR1}",
            f"raw\tspy1\t{AGR1}",
            f"raw\tsau1\t0\t{AGR1}",
            f"raw\tsau1\t1\t{AGR1}",
            f"output\t12\t{AGR1}",
        ]
        self.assertEqual(CHECKER.judge_case(CASE, lines, CLEAN)["status"], "passed")

    def test_without_cleanup_evidence_a_matching_case_is_unproven_not_passed(self) -> None:
        for case in SINGLE:
            verdict = CHECKER.judge_case(case, perfect(case))
            self.assertEqual(verdict["status"], "unproven", case["id"])
            self.assertIn("cleanup evidence", verdict["reason"])

    def test_every_leaked_resource_fails_the_case(self) -> None:
        verdict = CHECKER.judge_case(
            CASE, perfect(CASE), ["leak\tmount\t/run/pos/work", "leak\tcgroup\tpos.slice/x"]
        )
        self.assertEqual((verdict["status"], verdict["failure"]), ("failed", "resource_leak"))
        self.assertEqual(verdict["shown"], "mount: /run/pos/work; cgroup: pos.slice/x")
        for kind in CHECKER.LEAK_KINDS:
            leak = CHECKER.judge_case(CASE, perfect(CASE), [f"leak\t{kind}\tdetail"])
            self.assertEqual(leak["failure"], "resource_leak", kind)

    def test_malformed_cleanup_evidence_fails_the_case(self) -> None:
        for rows in (
            [],
            ["mount"],
            ["mount\tx"],
            ["leak\tmount"],
            ["leak\tmount\t"],
            ["leak\tsocket\tx"],
            ["leak\tmount\ta\tb"],
            ["clean", "clean"],
            ["clean", "leak\tunit\tx"],
            ["leak\tunit\tx", "clean"],
            ["CLEAN"],
        ):
            verdict = CHECKER.judge_case(CASE, perfect(CASE), rows)
            self.assertEqual(verdict["failure"], "malformed_evidence", rows)

    def test_a_different_outcome_fails_and_only_it_carries_the_blocker_note(self) -> None:
        lines = perfect(CASE)
        lines[1] = "outcome\tUnavailableAfterAdmission"
        verdict = CHECKER.judge_case(CASE, lines, CLEAN)
        self.assertEqual((verdict["status"], verdict["failure"]), ("failed", "outcome"))
        self.assertEqual(verdict["note"], CHECKER.KNOWN_BLOCKER)
        self.assertEqual(verdict["shown"], "executed UnavailableAfterAdmission events 11,12")
        other = CASES["task-exhaustion"]
        wrong_code = CHECKER.judge_case(other, perfect(other, code=4), CLEAN)
        self.assertEqual(wrong_code["failure"], "terminal_code")
        self.assertNotIn("note", wrong_code)

    def test_a_terminal_code_outside_the_expected_ones_fails(self) -> None:
        case = CASES["task-exhaustion"]
        for code in (4, 6, 8):
            verdict = CHECKER.judge_case(case, perfect(case, code=code), CLEAN)
            self.assertEqual(verdict.get("failure"), "terminal_code", code)
        self.assertEqual(CHECKER.judge_case(case, perfect(case, code=5), CLEAN)["status"], "passed")

    def test_memory_exhaustion_accepts_either_of_its_two_codes(self) -> None:
        case = CASES["memory-exhaustion"]
        for code in (3, 4):
            verdict = CHECKER.judge_case(case, perfect(case, code=code), CLEAN)
            self.assertEqual(verdict["status"], "passed", code)

    def test_a_missing_terminal_code_fails_when_one_is_expected(self) -> None:
        case = CASES["oversized-output"]
        for events in ("events\t11,12", "events\t"):
            lines = perfect(case)
            lines[2] = events
            verdict = CHECKER.judge_case(case, lines, CLEAN)
            self.assertEqual(verdict["failure"], "terminal_code", events)

    def test_a_terminal_code_fails_when_none_is_expected(self) -> None:
        case = CASES["network-escape"]
        verdict = CHECKER.judge_case(case, perfect(case, code=8), CLEAN)
        self.assertEqual(verdict["failure"], "terminal_code")

    def test_an_attempt_without_its_identity_fails(self) -> None:
        for agr1 in ("", "ab", "AB" * 32, "ab" * 33):
            lines = perfect(CASE)[:-1] + [f"agr1\t{agr1}"]
            verdict = CHECKER.judge_case(CASE, lines, CLEAN)
            self.assertEqual(verdict["failure"], "attempt_identity", agr1)
        verdict = CHECKER.judge_case(CASE, perfect(CASE)[:-1], CLEAN)
        self.assertEqual(verdict["failure"], "attempt_identity")

    def test_an_exchange_that_did_not_execute_fails_the_case(self) -> None:
        for lines, shown in (
            (["execute\trefused\tSandboxUnavailable"], "refused SandboxUnavailable"),
            (["execute\tfailed\tprovider execution failed"], "failed provider execution failed"),
            (["execute\tunreportable"], "unreportable"),
        ):
            verdict = CHECKER.judge_case(CASE, lines, CLEAN)
            self.assertEqual(verdict["failure"], "outcome")
            self.assertEqual(verdict["shown"], shown)

    def test_a_matching_refusal_is_unproven_for_want_of_a_request_identity(self) -> None:
        verdict = CHECKER.judge_case(REFUSAL_CASE, ["execute\trefused\tTrustRevoked"], CLEAN)
        self.assertEqual(verdict["status"], "unproven")
        self.assertIn("no request identity", verdict["reason"])
        wrong = CHECKER.judge_case(REFUSAL_CASE, ["execute\trefused\tCleanupFailed"], CLEAN)
        self.assertEqual(wrong["failure"], "refusal")
        executed = CHECKER.judge_case(REFUSAL_CASE, perfect(CASE), CLEAN)
        self.assertEqual(executed["failure"], "outcome")
        refused = ["execute\trefused\tTrustRevoked"]
        leaked = CHECKER.judge_case(REFUSAL_CASE, refused, ["leak\tunit\tx"])
        self.assertEqual(leaked["failure"], "resource_leak")

    def test_every_other_driver_is_not_run_with_its_reason_and_driver(self) -> None:
        for case in OTHERS:
            verdict = CHECKER.judge_case(case, perfect(CASE))
            self.assertEqual(verdict["status"], "not run", case["id"])
            self.assertEqual(verdict["driver"], case["driver"])
            self.assertEqual(verdict["reason"], CHECKER.NOT_RUN_REASONS[case["driver"]])
            self.assertIn("S4c", verdict["reason"])

    def test_a_single_execute_case_without_a_report_fails_with_no_evidence(self) -> None:
        verdict = CHECKER.judge_case(CASE, None)
        self.assertEqual((verdict["status"], verdict["failure"]), ("failed", "no_evidence"))
        self.assertNotIn("note", verdict)


class ReportTests(unittest.TestCase):
    def malformed(self, lines: list[str]) -> None:
        with self.assertRaises(CHECKER.EvidenceError, msg=lines):
            CHECKER.parse_report(lines)

    def test_terminal_codes(self) -> None:
        self.assertIsNone(CHECKER.terminal_code([]))
        self.assertIsNone(CHECKER.terminal_code([11, 12]))
        self.assertEqual(CHECKER.terminal_code([11, 12, 10]), 10)
        self.assertEqual(CHECKER.terminal_code([0]), 0)
        self.assertIsNone(CHECKER.terminal_code([10, 11]))

    def test_parse_report_reads_every_kind(self) -> None:
        report = CHECKER.parse_report(perfect(CASE) + ["ready1\tpresent"])
        self.assertEqual((report["kind"], report["outcome"]), ("executed", "Completed"))
        self.assertEqual((report["events"], report["agr1"]), ([11, 12], AGR1))
        refused = CHECKER.parse_report(["execute\trefused\tundecodable"])
        self.assertEqual((refused["kind"], refused["detail"]), ("refused", "undecodable"))
        self.assertEqual(CHECKER.parse_report(["execute\tunreportable"])["kind"], "unreportable")
        self.assertEqual(CHECKER.parse_report(["execute\tfailed\tx"])["detail"], "x")

    def test_a_malformed_report_is_refused_not_misread(self) -> None:
        good = perfect(CASE)
        for lines in (
            [],
            ["something"],
            ["execute"],
            ["execute\tmaybe"],
            ["execute\texecuted\textra"],
            ["execute\trefused"],
            ["execute\trefused\t"],
            ["execute\trefused\ta\tb"],
            ["execute\trefused\tX", "outcome\tCompleted"],
            ["execute\tunreportable\tx"],
            ["execute\tunreportable", "events\t1"],
            ["outcome\tCompleted"] + good,
            good + ["outcome\tCompleted"],
            good + ["events\t12"],
            good + [f"agr1\t{AGR1}"],
            good + ["mystery\t1"],
            good + ["ready1\tmaybe"],
            good + ["rqe1\tNOT"],
            good + ["raw\tagr1\tab"],
            good + ["raw\tsau1\tx\t" + AGR1],
            good + ["output\t-1\t" + AGR1],
            good + [f"raw\tagr1\t{AGR1}", f"raw\tagr1\t{AGR1}"],
            good[:1] + good[2:],
            good[:2] + good[3:],
            good + ["outcome\t"],
            good + ["outcome"],
            good + [""],
        ):
            self.malformed(lines)

    def test_events_are_digits_only(self) -> None:
        for value in ("-1", "1_0", " 5", "5 ", "1,,2", ",", "+1", "256", "1000", "٥", "a"):
            self.malformed(["execute\texecuted", "outcome\tCompleted", f"events\t{value}"])
        report = CHECKER.parse_report(["execute\texecuted", "outcome\tCompleted", "events\t0,255"])
        self.assertEqual(report["events"], [0, 255])
        padded = ["execute\texecuted", "outcome\tCompleted", "events\t005,0005,00000255"]
        self.assertEqual(CHECKER.parse_report(padded)["events"], [5, 5, 255])
        self.malformed(["execute\texecuted", "outcome\tCompleted", "events\t000000005"])

    def test_malformed_report_rows_become_a_case_failure_not_a_traceback(self) -> None:
        verdict = CHECKER.judge_case(CASE, ["execute\texecuted", "outcome\tCompleted"], CLEAN)
        self.assertEqual((verdict["status"], verdict["failure"]), ("failed", "malformed_evidence"))
        self.assertIn("events", verdict["shown"])
        events = perfect(CASE)
        events[2] = "events\t1_0"
        self.assertEqual(CHECKER.judge_case(CASE, events, CLEAN)["failure"], "malformed_evidence")


class FileTests(TempTestCase):
    def read(self, name: str) -> str | None:
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        return CHECKER.read_evidence(descriptor, name)

    def test_reading_is_strict_and_bounded(self) -> None:
        directory = self.root
        self.assertIsNone(self.read("timings"))
        (directory / "timings").write_bytes(b"stage\t1\n")
        self.assertEqual(self.read("timings"), "stage\t1\n")
        bad = {
            "non-ascii": b"stage\xc3\xa9\n",
            "control": b"stage\x00\n",
            "carriage return": b"stage\r\n",
            "oversized": b"a" * (CHECKER.MAX_EVIDENCE_BYTES + 1),
        }
        for name, data in bad.items():
            (directory / "timings").write_bytes(data)
            with self.assertRaises(CHECKER.EvidenceError, msg=name):
                self.read("timings")
        (directory / "timings").write_bytes(b"a" * CHECKER.MAX_EVIDENCE_BYTES)
        self.assertEqual(len(self.read("timings") or ""), 65536)

    def test_a_symlink_or_directory_is_not_evidence(self) -> None:
        (self.root / "target").write_text("stage\t1\n")
        os.symlink(self.root / "target", self.root / "timings")
        with self.assertRaises(CHECKER.EvidenceError):
            self.read("timings")
        (self.root / "leftovers").mkdir()
        with self.assertRaises(CHECKER.EvidenceError):
            self.read("leftovers")

    def test_diagnostic_files_need_only_to_be_plain_files(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        CHECKER.check_plain_file(descriptor, "execute-stderr")
        (self.root / "execute-stderr").write_bytes(b"\xff\x00" * 100000)
        CHECKER.check_plain_file(descriptor, "execute-stderr")
        (self.root / "execute-status").mkdir()
        with self.assertRaises(CHECKER.EvidenceError):
            CHECKER.check_plain_file(descriptor, "execute-status")
        with mock.patch.object(CHECKER.os, "stat", side_effect=PermissionError(13, "denied")):
            with self.assertRaises(CHECKER.EvidenceError):
                CHECKER.check_plain_file(descriptor, "execute-stderr")

    def test_lines_split_on_newline_only_with_no_blank_row(self) -> None:
        self.assertEqual(CHECKER.split_lines("", "f"), [])
        self.assertEqual(CHECKER.split_lines("a\nb\n", "f"), ["a", "b"])
        for bad in ("a", "a\n\n", "\n", "a\n\nb\n"):
            with self.assertRaises(CHECKER.EvidenceError, msg=repr(bad)):
                CHECKER.split_lines(bad, "f")

    def test_timings_are_parsed_and_malformed_ones_refused(self) -> None:
        self.assertEqual(
            CHECKER.parse_timings(["stage\t1.5", "execute\t70"]), {"stage": 1.5, "execute": 70.0}
        )
        for row in ("stage", "stage\tfast", "\t1", "stage\t-1", "stage\t1\t2", "stage\t1e3"):
            with self.assertRaises(CHECKER.EvidenceError, msg=row):
                CHECKER.parse_timings([row])
        with self.assertRaises(CHECKER.EvidenceError):
            CHECKER.parse_timings(["stage\t1", "stage\t2"])


class DirectoryTests(TempTestCase):
    def test_a_missing_cases_directory_is_unusable(self) -> None:
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.judge_directory(MANIFEST, self.root / "absent")
        (self.root / "file").write_text("x")
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.judge_directory(MANIFEST, self.root / "file")

    def test_an_empty_directory_fails_every_single_execute_case(self) -> None:
        verdicts = CHECKER.judge_directory(MANIFEST, self.root)
        self.assertEqual(len(verdicts), 19)
        for verdict in verdicts:
            if verdict["id"] in {case["id"] for case in SINGLE}:
                self.assertEqual(verdict["failure"], "no_evidence", verdict["id"])
            else:
                self.assertEqual(verdict["status"], "not run", verdict["id"])

    def test_an_unknown_or_not_single_execute_entry_is_unusable(self) -> None:
        for name in ("mystery", "cancel-while-running", "concurrent-attempts"):
            (self.root / name).mkdir()
            with self.assertRaises(CHECKER.ConformanceError, msg=name):
                CHECKER.judge_directory(MANIFEST, self.root)
            (self.root / name).rmdir()
        (self.root / "stray-file").write_text("x")
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.judge_directory(MANIFEST, self.root)

    def test_a_case_that_is_a_file_or_a_symlink_is_unusable(self) -> None:
        (self.root / "filesystem-escape").write_text("x")
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.judge_directory(MANIFEST, self.root)
        (self.root / "filesystem-escape").unlink()
        elsewhere = self.root.parent / "elsewhere"
        elsewhere.mkdir()
        os.symlink(elsewhere, self.root / "filesystem-escape")
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.judge_directory(MANIFEST, self.root)

    def test_a_symlinked_or_unknown_case_file_fails_the_case(self) -> None:
        directory = self.write_case(CASE)
        (self.root.parent / "real").write_text(text(perfect(CASE)))
        os.symlink(self.root.parent / "real", directory / "execute-report")
        verdict = self.judged("filesystem-escape")
        self.assertEqual(verdict["failure"], "malformed_evidence")
        self.assertIn("symbolic link", verdict["shown"])
        (directory / "execute-report").unlink()
        self.write_case(CASE, perfect(CASE))
        (directory / "extra").write_text("x")
        verdict = self.judged("filesystem-escape")
        self.assertEqual(verdict["failure"], "malformed_evidence")
        self.assertIn("extra", verdict["shown"])

    def judged(self, case_id: str) -> dict:
        verdicts = CHECKER.judge_directory(MANIFEST, self.root)
        return next(verdict for verdict in verdicts if verdict["id"] == case_id)

    def test_malformed_report_files_fail_their_case_only(self) -> None:
        good = text(perfect(CASE))
        for name, data in {
            "no newline": good[:-1],
            "blank row": good + "\n",
            "duplicate": good + "outcome\tCompleted\n",
            "empty": "",
        }.items():
            directory = self.write_case(CASE, perfect(CASE))
            (directory / "execute-report").write_text(data)
            verdict = self.judged("filesystem-escape")
            self.assertEqual(verdict["failure"], "malformed_evidence", name)
            self.assertEqual(self.judged("read-only-root-write")["failure"], "no_evidence")

    def test_non_ascii_and_oversized_files_fail_the_case(self) -> None:
        directory = self.write_case(CASE, perfect(CASE))
        (directory / "execute-report").write_bytes(b"execute\texecuted\xff\n")
        self.assertEqual(self.judged("filesystem-escape")["failure"], "malformed_evidence")
        (directory / "execute-report").write_bytes(b"x" * 70000)
        self.assertEqual(self.judged("filesystem-escape")["failure"], "malformed_evidence")
        (directory / "execute-report").write_text(text(perfect(CASE)))
        (directory / "execute-stderr").write_bytes(b"\xff" * 100000)
        self.write_case(CASE, timings="stage\t1\n", leftovers=CLEAN_TEXT)
        self.assertEqual(self.judged("filesystem-escape")["status"], "passed")
        (directory / "execute-stderr").unlink()
        os.symlink(self.root.parent, directory / "execute-stderr")
        self.assertEqual(self.judged("filesystem-escape")["failure"], "malformed_evidence")

    def test_a_directory_is_judged_and_the_rest_listed(self) -> None:
        self.write_case(CASE, perfect(CASE), timings="stage\t2\nexecute\t70.5\n")
        verdicts = CHECKER.judge_directory(MANIFEST, self.root)
        by_id = {verdict["id"]: verdict for verdict in verdicts}
        self.assertEqual(by_id["filesystem-escape"]["status"], "unproven")
        self.assertEqual(by_id["filesystem-escape"]["timings"], {"stage": 2.0, "execute": 70.5})
        self.assertEqual(by_id["task-exhaustion"]["failure"], "no_evidence")
        self.assertEqual(by_id["cancel-while-running"]["status"], "not run")
        rendered = CHECKER.render(verdicts)
        self.assertIn("unproven  filesystem-escape 72.5s", rendered)
        self.assertIn("not run   cancel-while-running", rendered)
        self.assertIn("failed    task-exhaustion no_evidence", rendered)

    def test_timings_errors_are_a_note_on_a_failed_case_and_a_failure_elsewhere(self) -> None:
        for timings in ("stage\nbad\n", "stage\t1\nstage\t2\n", "stage\t1"):
            self.write_case(CASE, perfect(CASE), timings=timings, leftovers=CLEAN_TEXT)
            verdict = self.judged("filesystem-escape")
            self.assertEqual(verdict["failure"], "malformed_evidence", timings)
            self.assertNotIn("timings", verdict)
        other = CASES["task-exhaustion"]
        self.write_case(other, perfect(other, code=4), timings="x\n", leftovers=CLEAN_TEXT)
        verdict = self.judged("task-exhaustion")
        self.assertEqual(verdict["failure"], "terminal_code")
        self.assertIn("malformed timings", verdict["note"])
        mismatch = perfect(CASE)
        mismatch[1] = "outcome\tCancelled"
        self.write_case(CASE, mismatch, timings="x\n", leftovers=CLEAN_TEXT)
        note = self.judged("filesystem-escape")["note"]
        self.assertIn(CHECKER.KNOWN_BLOCKER, note)
        self.assertIn("malformed timings", note)

class CommandLineTests(TempTestCase):
    ALL = "control,admission,concurrent"

    def run_cli(self, *extra: str) -> tuple[int, str, str]:
        return run_main([str(MANIFEST_PATH), str(self.root), *extra])

    def test_a_fully_passing_directory_exits_zero_when_the_other_drivers_are_allowed(self) -> None:
        self.passing_directory()
        status, out, _ = self.run_cli("--allow-not-run", self.ALL)
        self.assertEqual(status, 0, out)
        self.assertEqual(out.count("passed"), 12)
        self.assertEqual(out.count("not run"), 7)

    def test_not_run_cases_fail_the_exit_unless_their_driver_is_allowed(self) -> None:
        self.passing_directory()
        self.assertEqual(self.run_cli()[0], 1)
        self.assertEqual(self.run_cli("--allow-not-run", "control,admission")[0], 1)
        self.assertEqual(self.run_cli("--allow-not-run", "concurrent,control,admission")[0], 0)

    def test_a_leak_fails_the_exit(self) -> None:
        self.passing_directory()
        self.write_case(CASE, leftovers="leak\tunit\tpos-case.service\n")
        status, out, _ = self.run_cli("--allow-not-run", self.ALL)
        self.assertEqual(status, 1)
        self.assertIn("failed    filesystem-escape", out)
        self.assertIn("resource_leak (unit: pos-case.service)", out)

    def test_missing_cleanup_evidence_is_unproven_and_fails_the_exit(self) -> None:
        self.passing_directory()
        (self.root / "filesystem-escape" / "leftovers").unlink()
        status, out, _ = self.run_cli("--allow-not-run", self.ALL)
        self.assertEqual(status, 1)
        self.assertIn("unproven  filesystem-escape", out)

    def test_a_matching_refusal_is_unproven_and_fails_the_exit(self) -> None:
        manifest = {"version": 1, "cases": [REFUSAL_CASE]}
        path = self.write_manifest(manifest)
        self.write_case(REFUSAL_CASE, ["execute\trefused\tTrustRevoked"], leftovers=CLEAN_TEXT)
        with mock.patch.object(CHECKER, "PINNED_SHA256", pin_of(manifest)):
            status, out, _ = run_main([str(path), str(self.root)])
        self.assertEqual(status, 1)
        self.assertIn("unproven  synthetic", out)
        self.assertIn("no request identity", out)

    def test_unusable_input_exits_two_with_a_message(self) -> None:
        cases = (
            ["only-one"],
            [],
            [str(MANIFEST_PATH), str(self.root / "absent")],
            [str(self.root / "absent.json"), str(self.root)],
            [str(MANIFEST_PATH), str(self.root), "--allow-not-run", "single-execute"],
            [str(MANIFEST_PATH), str(self.root), "--allow-not-run", ""],
            [str(MANIFEST_PATH), str(self.root), "--allow-not-run", "control,mystery"],
            [str(MANIFEST_PATH), str(self.root), "--require-all"],
            [str(MANIFEST_PATH), str(self.root), "extra"],
        )
        for arguments in cases:
            self.assertEqual(run_main(arguments)[0], 2, arguments)
        (self.root / "mystery").mkdir()
        status, _, err = self.run_cli()
        self.assertEqual(status, 2)
        self.assertIn("mystery", err)
        self.assertNotIn("Traceback", err)

    def test_help_exits_zero(self) -> None:
        self.assertEqual(run_main(["--help"])[0], 0)


class PinTests(TempTestCase):
    def pinned_load(self, manifest: object) -> dict:
        path = self.write_manifest(manifest)
        return CHECKER.load_manifest(path)

    def test_the_committed_vector_matches_the_pin(self) -> None:
        self.assertEqual(pin_of(MANIFEST), CHECKER.PINNED_SHA256)

    def test_a_manifest_that_omits_adds_or_edits_a_case_is_refused(self) -> None:
        omitted = copy.deepcopy(MANIFEST)
        omitted["cases"].pop()
        added = copy.deepcopy(MANIFEST)
        added["cases"].append({**added["cases"][0], "id": "extra-case"})
        edited = copy.deepcopy(MANIFEST)
        edited["cases"][0]["expect"]["outcome"] = "Cancelled"
        redriven = copy.deepcopy(MANIFEST)
        redriven["cases"][0]["driver"] = "control"
        for name, manifest in (
            ("omitted", omitted),
            ("added", added),
            ("edited", edited),
            ("redriven", redriven),
        ):
            with self.assertRaises(CHECKER.ConformanceError, msg=name) as caught:
                self.pinned_load(manifest)
            self.assertIn("pinned", str(caught.exception), name)

    def test_a_control_only_manifest_judges_nothing_and_is_refused(self) -> None:
        control = [case for case in MANIFEST["cases"] if case["driver"] == "control"][:1]
        manifest = {"version": 1, "cases": control}
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.validate_manifest(manifest)
        path = self.write_manifest(manifest)
        status, _, err = run_main([str(path), str(self.root), "--allow-not-run", "control"])
        self.assertEqual(status, 2)
        self.assertIn("single-execute", err)

    def test_a_run_that_judges_no_single_execute_case_is_refused(self) -> None:
        manifest = {"version": 1, "cases": [OTHERS[0]]}
        with mock.patch.object(CHECKER, "PINNED_SHA256", pin_of(manifest)):
            with self.assertRaises(CHECKER.ConformanceError):
                self.pinned_load(manifest)

    def test_a_deep_or_oversized_manifest_is_refused_not_a_traceback(self) -> None:
        path = self.root.parent / "deep.json"
        path.write_text("[" * 200000 + "]" * 200000)
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.load_manifest(path)
        path.write_text('{"version": 1, "pad": "' + "a" * CHECKER.MAX_MANIFEST_BYTES + '"}')
        with self.assertRaises(CHECKER.ConformanceError):
            CHECKER.load_manifest(path)
        status, _, err = run_main([str(path), str(self.root)])
        self.assertEqual(status, 2)
        self.assertNotIn("Traceback", err)


class UnreadableTests(TempTestCase):
    def deny(self, path: pathlib.Path) -> None:
        path.chmod(0)
        self.addCleanup(path.chmod, 0o700)
        if os.access(path, os.R_OK):
            self.skipTest("the runner reads a mode 000 directory (root)")

    def test_an_unreadable_case_directory_fails_that_case(self) -> None:
        directory = self.write_case(CASE, perfect(CASE))
        self.deny(directory)
        verdicts = CHECKER.judge_directory(MANIFEST, self.root)
        verdict = next(v for v in verdicts if v["id"] == "filesystem-escape")
        self.assertEqual(verdict["failure"], "malformed_evidence")

    def test_an_unreadable_cases_directory_exits_two(self) -> None:
        self.write_case(CASE, perfect(CASE))
        self.deny(self.root)
        status, _, err = run_main([str(MANIFEST_PATH), str(self.root)])
        self.assertEqual(status, 2)
        self.assertNotIn("Traceback", err)

    def test_a_listing_that_fails_is_a_message_not_a_traceback(self) -> None:
        self.write_case(CASE, perfect(CASE))
        with mock.patch.object(CHECKER.os, "stat", side_effect=FileNotFoundError(2, "gone")):
            status, _, err = run_main([str(MANIFEST_PATH), str(self.root)])
        self.assertEqual(status, 2)
        self.assertIn("cannot read the cases directory", err)
        with mock.patch.object(CHECKER.os, "listdir", side_effect=PermissionError(13, "denied")):
            status, _, err = run_main([str(MANIFEST_PATH), str(self.root)])
        self.assertEqual(status, 2)

    def test_a_case_directory_that_vanishes_or_fails_to_list_fails_that_case(self) -> None:
        self.write_case(CASE, perfect(CASE))
        real = os.listdir
        calls = []

        def listing(argument):
            calls.append(argument)
            if len(calls) > 1:
                raise PermissionError(13, "denied")
            return real(argument)

        with mock.patch.object(CHECKER.os, "listdir", side_effect=listing):
            verdicts = CHECKER.judge_directory(MANIFEST, self.root)
        verdict = next(v for v in verdicts if v["id"] == "filesystem-escape")
        self.assertEqual(verdict["failure"], "malformed_evidence")
        self.assertIn("cannot be read", verdict["shown"])
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        self.assertEqual(CHECKER._read_case(descriptor, "task-exhaustion")["timings"], None)


class RepeatedOptionTests(TempTestCase):
    def test_a_repeated_allow_not_run_is_refused(self) -> None:
        arguments = [str(MANIFEST_PATH), str(self.root)]
        status, _, err = run_main(arguments + ["--allow-not-run", "control"] * 2)
        self.assertEqual(status, 2)
        self.assertIn("only once", err)
        self.passing_directory()
        status, _, _ = run_main(arguments + ["--allow-not-run", "control,admission,concurrent"])
        self.assertEqual(status, 0)


if __name__ == "__main__":
    unittest.main()
