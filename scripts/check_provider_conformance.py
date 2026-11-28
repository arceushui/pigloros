#!/usr/bin/env python3
"""Judge the provider conformance cases that the QEMU guest ran (#216).

The guest records raw evidence only: for each case it ran, the lines of the
`execute` report and its timings. This checker owns every judgement. It is
table-driven from the committed case manifest
(crates/pos-conformance/tests/vectors/provider-cases-v1.json), which the
conformance suite states and a Rust test keeps equal to its code, so the
expected outcome of a case is never written down a second time here.

A case is judged exactly as the suite judges one attempt (pos-conformance
`evaluate`): the SPY1 outcome must equal the expected one; the terminal code,
the last operational event when it is one of the terminal codes 0 to 10, must
be one of the expected codes (and absent when none are expected); a refusal
needs one of the expected SPE1 codes; the attempt must name its identity (the
AGR1 digest); and no resource may remain. Nothing is softened: an outcome that
differs fails the case, and a case without cleanup evidence is `unproven`, not
passed.

Usage: check_provider_conformance.py MANIFEST CASES_DIRECTORY [--require-all]

CASES_DIRECTORY holds one directory per case that ran, named by its id, with
`execute-report` (the lines of the execute mode) and `timings` (lines
`NAME<TAB>SECONDS`). Every other case is listed as `not run` with its reason.
The exit status is 1 when any case failed or is unproven, and with
--require-all also when any case did not run.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

TERMINAL_CODE_LIMIT = 10
DIGEST = re.compile(r"^[0-9a-f]{64}$")

# The drivers this checker can judge today; every other driver is listed as
# not run, with the slice that adds it.
JUDGED_DRIVERS = ("single-execute",)
NOT_RUN_REASONS = {
    "control": "the control exchange (cancel, revoke, broker crash) is not driven yet (S4c)",
    "admission": "the refusal before any attempt (revocation, missing feature) is not driven yet (S4c)",
    "concurrent": "the eight concurrent attempts are not driven yet (S4c)",
}
# Executing cases currently end at Cgroup(DeletionUnproven) until the cgroup
# deletion proof lands; a failure carries this note and is still a failure.
KNOWN_BLOCKER = "the cgroup deletion proof (#1569) is not merged: executing cases end DeletionUnproven"


class ConformanceError(RuntimeError):
    """The manifest or the evidence is malformed."""


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text())
    if manifest.get("version") != 1 or not isinstance(manifest.get("cases"), list):
        raise ConformanceError("unsupported provider case manifest")
    return manifest


def parse_report(lines: list[str]) -> dict[str, Any]:
    """The facts of an execute report: its kind, outcome, events and AGR1."""
    rows = [line.split("\t") for line in lines if line]
    first = rows[0] if rows else []
    if len(first) < 2 or first[0] != "execute":
        return {"kind": "missing"}
    report: dict[str, Any] = {"kind": first[1], "detail": "\t".join(first[2:])}
    for row in rows[1:]:
        if len(row) == 2 and row[0] == "outcome":
            report["outcome"] = row[1]
        elif len(row) == 2 and row[0] == "events":
            report["events"] = [int(value) for value in row[1].split(",") if value]
        elif len(row) == 2 and row[0] == "agr1":
            report["agr1"] = row[1]
    return report


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
    if report["kind"] != "executed" or report.get("outcome") != expected["outcome"]:
        return "outcome"
    code = terminal_code(report.get("events", []))
    allowed = expected["codes"]
    if code is None:
        return "terminal_code" if allowed else None
    return None if code in allowed else "terminal_code"


def judge_case(
    case: dict[str, Any],
    lines: list[str] | None,
    *,
    leaked_resources: int | None = None,
    blocker: str | None = KNOWN_BLOCKER,
) -> dict[str, Any]:
    """The verdict of one case: passed, failed, unproven or not run."""
    verdict: dict[str, Any] = {"id": case["id"]}
    if case["driver"] not in JUDGED_DRIVERS:
        return {**verdict, "status": "not run", "reason": NOT_RUN_REASONS[case["driver"]]}
    if lines is None:
        return {**verdict, "status": "not run", "reason": "the guest recorded no report"}
    report = parse_report(lines)
    failure = _outcome_failure(case["expect"], report)
    if failure is None and case["expect"]["kind"] == "terminal":
        if not DIGEST.match(report.get("agr1", "")):
            failure = "attempt_identity"
    if failure is None and leaked_resources not in (None, 0):
        failure = "resource_leak"
    if failure is not None:
        failed = {**verdict, "status": "failed", "failure": failure, "shown": _shown(report)}
        return {**failed, "note": blocker} if blocker else failed
    if leaked_resources is None:
        return {**verdict, "status": "unproven", "reason": "no cleanup evidence shows zero leaked resources"}
    return {**verdict, "status": "passed"}


def _shown(report: dict[str, Any]) -> str:
    if report["kind"] == "executed":
        events = ",".join(str(code) for code in report.get("events", []))
        return f"executed {report.get('outcome')} events {events}"
    return f"{report['kind']} {report.get('detail', '')}".strip()


def parse_timings(text: str) -> dict[str, float]:
    timings: dict[str, float] = {}
    for line in text.splitlines():
        name, _, seconds = line.partition("\t")
        if not name or not re.fullmatch(r"[0-9]+(\.[0-9]+)?", seconds):
            raise ConformanceError(f"malformed timings line: {line!r}")
        timings[name] = float(seconds)
    return timings


def judge_directory(manifest: dict[str, Any], directory: pathlib.Path) -> list[dict[str, Any]]:
    verdicts = []
    for case in manifest["cases"]:
        report_file = directory / case["id"] / "execute-report"
        lines = report_file.read_text().splitlines() if report_file.is_file() else None
        verdict = judge_case(case, lines)
        timings_file = directory / case["id"] / "timings"
        if verdict["status"] != "not run" and timings_file.is_file():
            verdict["timings"] = parse_timings(timings_file.read_text())
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


def exit_status(verdicts: list[dict[str, Any]], *, require_all: bool) -> int:
    bad = {"failed", "unproven"} | ({"not run"} if require_all else set())
    return 1 if any(verdict["status"] in bad for verdict in verdicts) else 0


def main(arguments: list[str]) -> int:
    require_all = "--require-all" in arguments
    paths = [argument for argument in arguments if argument != "--require-all"]
    if len(paths) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    verdicts = judge_directory(load_manifest(pathlib.Path(paths[0])), pathlib.Path(paths[1]))
    print(render(verdicts))
    return exit_status(verdicts, require_all=require_all)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
