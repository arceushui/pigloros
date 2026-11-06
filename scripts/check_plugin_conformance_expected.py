#!/usr/bin/env python3
"""Check the evidence-status records of the Plugin conformance layer (ADR-061 r8, R8-F5).

Decision 11: every `expected/plugin-conformance/*.json` stays `pending` with a null result and a
null time, and binds the BLAKE3 digest of its payload (`inputs/plugin-conformance/<family>.json`).
The Local and Air-Gapped bundles are materialized from this one record per family, so their
digests are equal by construction; the profile must list exactly one `expected` path per family
and nothing else. The execution matrix holds no Plugin row, and no executed case outside the
G-PUB rows that ADR-062 Revision 8 slice N1 (#1229) flips; those cases are owned and checked by
`generate_non_interference_g_pub_fixtures.py`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import generate_pmf1_golden_vectors as golden  # noqa: E402

LAYER = "plugin-conformance"
# The rows whose verifier-accepted cases slice N1 flips (owner note
# ADR-062_R8_NonInterference_Executions); this checker does not own their execution fields.
NON_INTERFERENCE_EXECUTED_ROWS = ("NI-PUBLIC-006", "NI-EVAL-007")
HEX = "0123456789abcdef"
FAMILIES = (
    "positive",
    "denied",
    "malformed",
    "resource-exhaustion",
    "deletion-redaction",
    "downgrade",
    "independent-evaluation",
)
KEYS = {
    "claim_layer",
    "case_id",
    "family",
    "input_blake3_digest",
    "status",
    "execution_result",
    "executed_at",
}


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def as_dict(value: object) -> dict[str, object]:
    """`value` when it is an object, else an empty one (the callers report the fault)."""
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def record_errors(root: Path, family: str) -> list[str]:
    """The faults of the evidence-status record of `family`."""
    record = load(root / f"expected/{LAYER}/{family}.json")
    digest = golden.blake3((root / f"inputs/{LAYER}/{family}.json").read_bytes()).hex()
    wanted: dict[str, object] = {
        "claim_layer": LAYER,
        "case_id": f"{LAYER}-{family}",
        "family": family,
        "input_blake3_digest": digest,
        "status": "pending",
        "execution_result": None,
        "executed_at": None,
    }
    if not isinstance(record, dict) or set(record) != KEYS:
        return [f"{family}: the record is not an object with the keys {sorted(KEYS)}"]
    return [
        f"{family}: {key} is not {value!r}" for key, value in wanted.items() if record[key] != value
    ]


def profile_errors(root: Path) -> list[str]:
    """The profile binds one record per family, shared by both execution modes."""
    profile = as_dict(load(root / f"profiles/{LAYER}/profile.json"))
    entries = [as_dict(entry) for entry in as_list(profile.get("fixtures"))]
    bound = sorted(str(entry.get("expected")) for entry in entries)
    wanted = sorted(f"expected/{LAYER}/{family}.json" for family in FAMILIES)
    if bound == wanted:
        return []
    return [f"the profile binds {bound}, not one record per family {wanted}"]


def n1_case_errors(label: str, case: dict[str, object]) -> list[str]:
    """The faults of one case of a slice N1 row: only an L, R or F case may be executed, and then
    with a 64-hex expected result digest; every other case stays open."""
    faults = []
    if case.get("authority_result_digest") is not None:
        faults.append(f"{label}: authority_result_digest is not null")
    digest = case.get("expected_result_digest")
    if case.get("executed") is True and case.get("mode") in ("L", "R", "F"):
        if not (isinstance(digest, str) and len(digest) == 64 and all(c in HEX for c in digest)):
            faults.append(f"{label}: expected_result_digest is not 64 lowercase hex digits")
        return faults
    if case.get("executed") is not False:
        faults.append(f"{label}: executed is not false")
    for key in ("expected_result_digest", "expected_result"):
        if case.get(key) is not None:
            faults.append(f"{label}: {key} is not null")
    return faults


def row_errors(label: str, row: dict[str, object]) -> list[str]:
    """The faults of one matrix row or case: executed, digest-bearing or Plugin layer."""
    faults = []
    if LAYER in (row.get("claim_layer"), row.get("authority_fixture_id"), row.get("fixture_id")):
        faults.append(f"{label}: a {LAYER} row")
    if row.get("fixture_id") in NON_INTERFERENCE_EXECUTED_ROWS:
        # A slice N1 row's count is checked against its cases by `count_errors`.
        if "case_id" in row:
            faults.extend(n1_case_errors(label, row))
        elif row.get("authority_result_digest") is not None:
            faults.append(f"{label}: authority_result_digest is not null")
        return faults
    if row.get("executed") is not False and "executed" in row:
        faults.append(f"{label}: executed is not false")
    for key in ("expected_result_digest", "expected_result", "authority_result_digest"):
        if row.get(key) is not None:
            faults.append(f"{label}: {key} is not null")
    if row.get("executed_case_count", 0) != 0:
        faults.append(f"{label}: executed_case_count is not 0")
    return faults


def count_errors(matrix: dict[str, object]) -> list[str]:
    """`row_count`, `case_count` and `executed_case_count` agree with the lists."""
    rows, cases = as_list(matrix.get("rows")), as_list(matrix.get("cases"))
    faults = []
    for key, size in (("row_count", len(rows)), ("case_count", len(cases))):
        if matrix.get(key) != size:
            faults.append(f"{key} is {matrix.get(key)!r}, the list has {size}")
    executed = [case for case in cases if isinstance(case, dict) and case.get("executed") is True]
    if matrix.get("executed_case_count") != len(executed):
        faults.append(f"executed_case_count is not the {len(executed)} executed cases")
    for index, row in enumerate(rows):
        if isinstance(row, dict) and row.get("fixture_id") in NON_INTERFERENCE_EXECUTED_ROWS:
            count = sum(1 for case in executed if case.get("fixture_id") == row["fixture_id"])
            if row.get("executed_case_count") != count:
                faults.append(f"rows[{index}]: executed_case_count is not its {count} cases")
    return faults


def matrix_errors(root: Path) -> list[str]:
    """No Plugin conformance row, and no executed case or digest outside the slice N1 rows."""
    matrix = as_dict(load(root / "matrix/execution-matrix.json"))
    faults = count_errors(matrix)
    for kind in ("rows", "cases"):
        for index, entry in enumerate(as_list(matrix.get(kind))):
            if not isinstance(entry, dict):
                faults.append(f"{kind}[{index}]: not an object")
                continue
            faults.extend(row_errors(f"{kind}[{index}]", entry))
    return faults


def errors(root: Path) -> list[str]:
    found = profile_errors(root) + matrix_errors(root)
    for family in FAMILIES:
        found.extend(record_errors(root, family))
    return found


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "fixtures/conformance"
    found = errors(root)
    for fault in found:
        print(fault, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
