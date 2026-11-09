#!/usr/bin/env python3
"""Bind the checked-in non-interference evidence to the ADR-059 matrix (ADR-062 Revision 8
slices N1-N4 and N1b; owner notes `ADR-062_R8_NonInterference_Executions` and
`ADR-062_R8_NonInterference_Fork`, and ADR-127).

Every executed row declared in `scripts/non_interference_executed_rows.json` has one oracle
module that derives its expected NIA1 `result_digest` independently (Q3 (a)); the oracles are
listed in `ORACLES`. This script runs every oracle's self-test, then flips a matrix case to
`executed: true` only for a checked-in NIA1 the oracle's digest accepts (see
`non_interference_fixtures.py`), and rebinds the matrix digest, size and executed count in the
knowledge-non-interference profile and the publication review. `executed: true` never implies a
pass. The Rust test `apps/pos-experiment/tests/non_interference_evidence.rs` checks each NIA1's
signature with the pos-reference verifier.

Usage:
    python3 scripts/generate_non_interference_fixtures.py                   # write the bindings
    python3 scripts/generate_non_interference_fixtures.py --check           # self-test and verify
    python3 scripts/generate_non_interference_fixtures.py --print-expected  # every oracle digest
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate_non_interference_g_archive_fixtures as g_archive  # noqa: E402
import generate_non_interference_g_fork_fixtures as g_fork  # noqa: E402
import generate_non_interference_g_ops_fixtures as g_ops  # noqa: E402
import generate_non_interference_g_plug_fixtures as g_plug  # noqa: E402
import generate_non_interference_g_pub_fixtures as g_pub  # noqa: E402
import non_interference_fixtures as shared  # noqa: E402

ORACLES = (g_pub, g_plug, g_ops, g_fork, g_archive)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--print-expected", action="store_true")
    arguments = parser.parse_args()
    shared.self_test()
    for oracle in ORACLES:
        oracle.self_test()
    owners = shared.oracle_rows(ORACLES)
    if arguments.print_expected:
        for row, oracle in owners.items():
            for _, variant, _ in shared.VARIANTS:
                print(row, variant, oracle.expected_result_digest(row, variant).hex())
        return
    shared.check_executor()
    accepted = shared.accepted_executions(ORACLES)
    generated = shared.outputs(accepted)
    stale = [path for path, data in generated.items() if path.read_bytes() != data]
    if arguments.check:
        if stale:
            for path in stale:
                print(f"{path.relative_to(shared.ROOT)} is not reproducible", file=sys.stderr)
            raise SystemExit(1)
        print(f"verified {len(accepted)} non-interference NIA1 and their matrix bindings")
        return
    for path in stale:
        path.write_bytes(generated[path])
    print(f"wrote {len(stale)} file(s)")


if __name__ == "__main__":
    main()
