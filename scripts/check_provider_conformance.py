#!/usr/bin/env python3
"""Judge the provider conformance cases that the QEMU guest ran (#216).

The guest records raw evidence only: for each case it ran, the lines of the
`execute` report, its timings and the resources it left behind. This checker
owns every judgement. It is table-driven from the committed case manifest
(crates/pos-conformance/tests/vectors/provider-cases-v1.json), which the
conformance suite states and a Rust test keeps equal to its code, so the
expected outcome of a case is never written down a second time here.

A case is judged exactly as the suite judges one attempt (pos-conformance
`evaluate`): the SPY1 outcome must equal the expected one; the terminal code,
the last operational event when it is one of the terminal codes 0 to 10, must
be one of the expected codes (and absent when none are expected); a refusal
needs one of the expected SPE1 codes; the attempt must name its identity (the
AGR1 digest); and no resource may remain. Nothing is softened: an outcome that
differs fails the case, a case that ran with no report fails as `no_evidence`,
evidence that is not exactly well formed fails as `malformed_evidence`, and a
case without cleanup evidence is `unproven`, not passed. A matching refusal is
also `unproven`: the execute report carries no request identity yet.

Usage: check_provider_conformance.py MANIFEST CASES_DIRECTORY
           [--allow-not-run DRIVER,...]

CASES_DIRECTORY must exist and holds one plain directory per single-execute
case, named by its id, with only these plain files:

- `execute-report`, the lines of the execute mode;
- `execute-stderr` and `execute-status`, the guest's own diagnostics (not
  judged);
- `timings`, lines `NAME<TAB>SECONDS`;
- `leftovers`, the cleanup evidence: one line `KIND<TAB>DETAIL` per leaked
  resource (KIND is mount, umount-failure, unit or cgroup), empty when nothing
  leaked. The part-2b collector writes it; absent means `unproven`.

Every case whose driver is not single-execute is listed as `not run` with its
reason, and a `not run` case fails the exit status unless its driver is named
by --allow-not-run. Exit status: 0 all passed, 1 a case failed, is unproven or
is not run, 2 the input is unusable.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any

TERMINAL_CODE_LIMIT = 10
MAX_EVIDENCE_BYTES = 64 * 1024
DIGEST = re.compile(r"^[0-9a-f]{64}$")
HEX = re.compile(r"^[0-9a-f]+$")
IDENTIFIER = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
SECONDS = re.compile(r"^[0-9]+(\.[0-9]+)?$")
LEAK_KINDS = ("mount", "umount-failure", "unit", "cgroup")
CASE_FILES = ("execute-report", "execute-stderr", "execute-status", "timings", "leftovers")

SINGLE_EXECUTE = "single-execute"
# The drivers this checker cannot judge today, with the slice that adds each.
NOT_RUN_REASONS = {
    "control": "the control exchange (cancel, revoke, broker crash) is not driven yet (S4c)",
    "admission": "the refusal before any attempt (revocation, feature) is not driven yet (S4c)",
    "concurrent": "the eight concurrent attempts are not driven yet (S4c)",
}
# Executing cases currently end at Cgroup(DeletionUnproven) until the cgroup
# deletion proof lands; an outcome mismatch carries this note.
KNOWN_BLOCKER = (
    "the cgroup deletion proof (#1569) is not merged: executing cases end DeletionUnproven"
)
SHOWN_LIMIT = 200


class ConformanceError(RuntimeError):
    """The manifest or the input directory is unusable."""


class EvidenceError(ConformanceError):
    """One piece of case evidence is not exactly well formed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceError(message)


def _validate_expect(case_id: str, expect: Any) -> None:
    _require(isinstance(expect, dict), f"case {case_id}: expect is not an object")
    codes = expect.get("codes")
    _require(isinstance(codes, list), f"case {case_id}: expect.codes is not a list")
    kind = expect.get("kind")
    if kind == "terminal":
        _require(isinstance(expect.get("outcome"), str), f"case {case_id}: no expected outcome")
        _require(
            all(type(code) is int for code in codes),
            f"case {case_id}: a terminal code is not an integer",
        )
    elif kind == "refused":
        _require(
            bool(codes) and all(isinstance(code, str) and code for code in codes),
            f"case {case_id}: a refusal code is not a name",
        )
    else:
        raise ConformanceError(f"case {case_id}: unknown expect kind {kind!r}")


def validate_manifest(manifest: Any) -> dict[str, Any]:
    _require(isinstance(manifest, dict), "the provider case manifest is not an object")
    _require(manifest.get("version") == 1, "unsupported provider case manifest")
    cases = manifest.get("cases")
    _require(isinstance(cases, list) and cases, "the provider case manifest has no cases")
    seen: set[str] = set()
    for case in cases:
        _require(isinstance(case, dict), "a manifest case is not an object")
        for key in ("id", "driver", "attempts", "arguments", "expect"):
            _require(key in case, f"manifest case {case.get('id')!r} lacks {key}")
        case_id = case["id"]
        _require(
            isinstance(case_id, str) and IDENTIFIER.match(case_id) is not None,
            f"manifest case id {case_id!r} is not a plain identifier",
        )
        _require(case_id not in seen, f"manifest case id {case_id} is not unique")
        seen.add(case_id)
        driver = case["driver"]
        _require(
            driver == SINGLE_EXECUTE or driver in NOT_RUN_REASONS,
            f"case {case_id}: unknown driver {driver!r}",
        )
        attempts = case["attempts"]
        _require(
            type(attempts) is int and attempts >= 1, f"case {case_id}: attempts is not a count"
        )
        _require(
            driver != SINGLE_EXECUTE or attempts == 1,
            f"case {case_id}: a single-execute case is one attempt",
        )
        _require(isinstance(case["arguments"], list), f"case {case_id}: arguments not a list")
        _validate_expect(case_id, case["expect"])
    return manifest


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, ValueError) as error:
        raise ConformanceError(f"cannot read the provider case manifest: {error}") from error
    return validate_manifest(manifest)


def read_evidence(case_directory: pathlib.Path, name: str) -> str | None:
    """The text of one evidence file, None when absent; strict and bounded."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(case_directory / name, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        reason = "a symbolic link" if error.errno == errno.ELOOP else error.strerror
        raise EvidenceError(f"{name} cannot be read: {reason}") from error
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise EvidenceError(f"{name} is not a plain file")
    with os.fdopen(descriptor, "rb") as handle:
        data = handle.read(MAX_EVIDENCE_BYTES + 1)
    if len(data) > MAX_EVIDENCE_BYTES:
        raise EvidenceError(f"{name} exceeds {MAX_EVIDENCE_BYTES} bytes")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{name} is not ASCII") from error
    if any(char not in "\n\t" and not " " <= char <= "~" for char in text):
        raise EvidenceError(f"{name} holds a control character")
    return text


def split_lines(text: str, name: str) -> list[str]:
    """The newline-terminated rows of a file; no blank row is allowed."""
    if not text:
        return []
    if not text.endswith("\n"):
        raise EvidenceError(f"{name} ends inside a row")
    rows = text[:-1].split("\n")
    if "" in rows:
        raise EvidenceError(f"{name} holds a blank row")
    return rows


def _parse_events(value: str) -> list[int]:
    if not value:
        return []
    events = []
    for part in value.split(","):
        if not (part.isascii() and part.isdigit() and len(part) <= 3 and int(part) <= 255):
            raise EvidenceError(f"events holds {part!r}, not an event code")
        events.append(int(part))
    return events


def _check_row(row: list[str]) -> tuple[Any, ...]:
    """The key of one evidence row of an executed report; unknown shapes are refused."""
    name, fields = row[0], row[1:]
    if name in ("ready1", "release1") and len(fields) == 1 and fields[0] in ("present", "absent"):
        return (name,)
    if name in ("rqe1", "koe1", "tme1") and len(fields) == 1 and HEX.match(fields[0]):
        return (name,)
    if name in ("outcome", "events", "agr1") and len(fields) == 1:
        return (name,)
    if name == "output" and len(fields) == 2 and fields[0].isascii() and fields[0].isdigit():
        return (name,) if DIGEST.match(fields[1]) else ()
    if name == "raw" and len(fields) == 2 and fields[0] in ("agr1", "spr1", "spy1"):
        return (name, fields[0]) if DIGEST.match(fields[1]) else ()
    if name == "raw" and len(fields) == 3 and fields[0] == "sau1":
        index = fields[1]
        digit = index.isascii() and index.isdigit()
        return (name, "sau1", index) if digit and DIGEST.match(fields[2]) else ()
    return ()


def parse_report(lines: list[str]) -> dict[str, Any]:
    """The facts of an execute report: its kind, outcome, events and AGR1."""
    rows = [line.split("\t") for line in lines]
    if not rows or len(rows[0]) < 2 or rows[0][0] != "execute":
        raise EvidenceError("the report does not begin with an execute row")
    kind, extra = rows[0][1], rows[0][2:]
    if kind in ("refused", "failed") and len(extra) == 1 and extra[0] and len(rows) == 1:
        return {"kind": kind, "detail": extra[0]}
    if kind == "unreportable" and not extra and len(rows) == 1:
        return {"kind": kind}
    if kind != "executed" or extra:
        raise EvidenceError(f"the execute row {rows[0]!r} is not a known report")
    report: dict[str, Any] = {"kind": kind}
    seen: set[tuple[Any, ...]] = set()
    for row in rows[1:]:
        key = _check_row(row)
        if not key:
            raise EvidenceError(f"unknown or malformed report row {row[0]!r}")
        if key in seen:
            raise EvidenceError(f"duplicate report row {row[0]!r}")
        seen.add(key)
        if row[0] == "outcome":
            report["outcome"] = row[1]
        elif row[0] == "events":
            report["events"] = _parse_events(row[1])
        elif row[0] == "agr1":
            report["agr1"] = row[1]
    for required in ("outcome", "events"):
        if required not in report:
            raise EvidenceError(f"the executed report has no {required} row")
    return report


def parse_leftovers(lines: list[str]) -> list[str]:
    """The leaked resources, each `KIND: DETAIL`; none when the file is empty."""
    leaked = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] not in LEAK_KINDS or not fields[1]:
            raise EvidenceError(f"malformed leftovers row {line!r}")
        leaked.append(f"{fields[0]}: {fields[1]}")
    return leaked


def terminal_code(events: list[int]) -> int | None:
    """The last event when it is a terminal code; lifecycle codes precede it."""
    if events and events[-1] <= TERMINAL_CODE_LIMIT:
        return events[-1]
    return None


def _outcome_failure(expected: dict[str, Any], report: dict[str, Any]) -> str | None:
    if expected["kind"] == "refused":
        if report["kind"] != "refused":
            return "outcome"
        return None if report["detail"] in expected["codes"] else "refusal"
    if report["kind"] != "executed" or report["outcome"] != expected["outcome"]:
        return "outcome"
    code = terminal_code(report["events"])
    allowed = expected["codes"]
    if code is None:
        return "terminal_code" if allowed else None
    return None if code in allowed else "terminal_code"


def _shown(report: dict[str, Any]) -> str:
    if report["kind"] == "executed":
        events = ",".join(str(code) for code in report["events"])
        return f"executed {report['outcome']} events {events}"
    return f"{report['kind']} {report.get('detail', '')}".strip()[:SHOWN_LIMIT]


def _failed(verdict: dict[str, Any], failure: str, shown: str) -> dict[str, Any]:
    failed = {**verdict, "status": "failed", "failure": failure, "shown": shown}
    if failure == "outcome":
        failed["note"] = KNOWN_BLOCKER
    return failed


def judge_case(
    case: dict[str, Any], lines: list[str] | None, leftovers: list[str] | None = None
) -> dict[str, Any]:
    """The verdict of one case: passed, failed, unproven or not run."""
    verdict: dict[str, Any] = {"id": case["id"]}
    if case["driver"] != SINGLE_EXECUTE:
        reason = NOT_RUN_REASONS[case["driver"]]
        return {**verdict, "status": "not run", "driver": case["driver"], "reason": reason}
    if lines is None:
        return _failed(verdict, "no_evidence", "the guest recorded no execute-report")
    try:
        report = parse_report(lines)
        leaked = None if leftovers is None else parse_leftovers(leftovers)
    except EvidenceError as error:
        return _failed(verdict, "malformed_evidence", str(error)[:SHOWN_LIMIT])
    expected = case["expect"]
    failure = _outcome_failure(expected, report)
    if failure is None and expected["kind"] == "terminal":
        if not DIGEST.match(report.get("agr1", "")):
            failure = "attempt_identity"
    if failure is not None:
        return _failed(verdict, failure, _shown(report))
    if leaked:
        return _failed(verdict, "resource_leak", "; ".join(leaked)[:SHOWN_LIMIT])
    if expected["kind"] == "refused":
        reason = "the report carries no request identity to bind the refusal to the request"
        return {**verdict, "status": "unproven", "reason": reason}
    if leaked is None:
        reason = "no cleanup evidence shows zero leaked resources"
        return {**verdict, "status": "unproven", "reason": reason}
    return {**verdict, "status": "passed"}


def parse_timings(lines: list[str]) -> dict[str, float]:
    timings: dict[str, float] = {}
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 2 or not fields[0] or not SECONDS.match(fields[1]):
            raise EvidenceError(f"malformed timings row {line!r}")
        if fields[0] in timings:
            raise EvidenceError(f"duplicate timings row {fields[0]!r}")
        timings[fields[0]] = float(fields[1])
    return timings


def _case_directories(manifest: dict[str, Any], directory: pathlib.Path) -> None:
    """Refuse a CASES_DIRECTORY that is not a plain tree of known single-execute cases."""
    try:
        listing = sorted(os.listdir(directory))
    except OSError as error:
        raise ConformanceError(f"cannot read the cases directory: {error.strerror}") from error
    known = {c["id"] for c in manifest["cases"] if c["driver"] == SINGLE_EXECUTE}
    for name in listing:
        if name not in known:
            raise ConformanceError(f"{name!r} is not a single-execute case id")
        if not stat.S_ISDIR(os.lstat(directory / name).st_mode):
            raise ConformanceError(f"{name!r} is not a plain directory")


def _read_case(case_directory: pathlib.Path) -> dict[str, list[str] | None]:
    """The rows of every evidence file of a case, None where a file is absent."""
    if case_directory.is_dir():
        extra = sorted(set(os.listdir(case_directory)) - set(CASE_FILES))
        if extra:
            raise EvidenceError(f"unexpected case file {extra[0]!r}")
    files: dict[str, list[str] | None] = {}
    for name in ("execute-report", "timings", "leftovers"):
        text = read_evidence(case_directory, name)
        files[name] = None if text is None else split_lines(text, name)
    for name in ("execute-stderr", "execute-status"):
        read_evidence(case_directory, name)
    return files


def judge_directory(manifest: dict[str, Any], directory: pathlib.Path) -> list[dict[str, Any]]:
    _require(directory.is_dir(), f"the cases directory {str(directory)!r} does not exist")
    _case_directories(manifest, directory)
    verdicts = []
    for case in manifest["cases"]:
        if case["driver"] != SINGLE_EXECUTE:
            verdicts.append(judge_case(case, None))
            continue
        try:
            files = _read_case(directory / case["id"])
        except EvidenceError as error:
            verdicts.append(_failed({"id": case["id"]}, "malformed_evidence", str(error)))
            continue
        verdict = judge_case(case, files["execute-report"], files["leftovers"])
        if files["timings"] is not None:
            try:
                verdict["timings"] = parse_timings(files["timings"])
            except EvidenceError as error:
                if verdict["status"] == "failed":
                    verdict["note"] = "; ".join(filter(None, [verdict.get("note"), str(error)]))
                else:
                    verdict = _failed({"id": case["id"]}, "malformed_evidence", str(error))
        verdicts.append(verdict)
    return verdicts


def render(verdicts: list[dict[str, Any]]) -> str:
    rows = []
    for verdict in verdicts:
        detail = verdict.get("reason") or verdict.get("failure", "")
        shown = f" ({verdict['shown']})" if "shown" in verdict else ""
        note = f" [{verdict['note']}]" if "note" in verdict else ""
        total = sum(verdict.get("timings", {}).values())
        timing = f" {total:.1f}s" if "timings" in verdict else ""
        rows.append(f"{verdict['status']:9} {verdict['id']}{timing} {detail}{shown}{note}".rstrip())
    return "\n".join(rows)


def exit_status(verdicts: list[dict[str, Any]], allow_not_run: frozenset[str]) -> int:
    for verdict in verdicts:
        if verdict["status"] in ("failed", "unproven"):
            return 1
        if verdict["status"] == "not run" and verdict["driver"] not in allow_not_run:
            return 1
    return 0


def _drivers(value: str) -> frozenset[str]:
    drivers = value.split(",")
    unknown = [driver for driver in drivers if driver not in NOT_RUN_REASONS]
    if unknown:
        allowed = ", ".join(sorted(NOT_RUN_REASONS))
        raise argparse.ArgumentTypeError(f"cannot allow {unknown[0]!r}; use {allowed}")
    return frozenset(drivers)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_provider_conformance.py",
        description="Judge the provider conformance cases that the guest ran.",
        allow_abbrev=False,
    )
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("cases_directory", type=pathlib.Path)
    parser.add_argument(
        "--allow-not-run",
        type=_drivers,
        default=frozenset(),
        metavar="DRIVER,...",
        help="drivers whose cases may stay `not run` without failing the exit status",
    )
    return parser


def main(arguments: list[str]) -> int:
    try:
        options = _parser().parse_args(arguments)
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else 2
    try:
        manifest = load_manifest(options.manifest)
        verdicts = judge_directory(manifest, options.cases_directory)
    except ConformanceError as error:
        print(f"check_provider_conformance: {error}", file=sys.stderr)
        return 2
    print(render(verdicts))
    return exit_status(verdicts, options.allow_not_run)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
