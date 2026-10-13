#!/usr/bin/env python3
"""Check the evidence-status records of the Plugin conformance layer (ADR-061 r8, R8-F5).

Decision 11: every `expected/plugin-conformance/*.json` stays `pending` with a null result and a
null time, and binds the BLAKE3 digest of its payload (`inputs/plugin-conformance/<family>.json`).
The Local and Air-Gapped bundles are materialized from this one record per family, so their
digests are equal by construction; the profile must list exactly one `expected` path per family
and nothing else. The execution matrix holds no executed case and no Plugin row.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import generate_pmf1_golden_vectors as golden  # noqa: E402

LAYER = "plugin-conformance"
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


def record_errors(root: Path, family: str) -> list[str]:
    """The faults of the evidence-status record of `family`."""
    record = load(root / f"expected/{LAYER}/{family}.json")
    digest = golden.blake3((root / f"inputs/{LAYER}/{family}.json").read_bytes()).hex()
    wanted = {
        "claim_layer": LAYER,
        "case_id": f"{LAYER}-{family}",
        "family": family,
        "input_blake3_digest": digest,
        "status": "pending",
        "execution_result": None,
        "executed_at": None,
    }
    if not isinstance(record, dict) or set(record) != KEYS:
        return [f"{family}: the record keys are not {sorted(KEYS)}"]
    return [
        f"{family}: {key} is not {value!r}" for key, value in wanted.items() if record[key] != value
    ]


def profile_errors(root: Path) -> list[str]:
    """The profile binds one record per family, shared by both execution modes."""
    profile = load(root / f"profiles/{LAYER}/profile.json")
    expected = sorted(entry["expected"] for entry in profile["fixtures"])
    wanted = sorted(f"expected/{LAYER}/{family}.json" for family in FAMILIES)
    return [] if expected == wanted else ["the profile does not bind one record per family"]


def matrix_errors(root: Path) -> list[str]:
    """No executed case, no digest and no Plugin conformance row in the execution matrix."""
    matrix = load(root / "matrix/execution-matrix.json")
    faults = []
    if matrix["executed_case_count"] != 0:
        faults.append("the matrix has executed cases")
    for case in matrix["cases"]:
        executed = case["executed"] or case["expected_result_digest"] is not None
        if executed or LAYER in json.dumps(case):
            faults.append(f"{case['case_id']}: an executed or Plugin conformance row")
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
