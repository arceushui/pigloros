#!/usr/bin/env python3
"""Adversarial tests for the prototype SPDX validator."""

from __future__ import annotations

import copy
import importlib.util
import pathlib


CHECKER_PATH = pathlib.Path(__file__).with_name("check_spdx_sbom.py")
SPEC = importlib.util.spec_from_file_location("check_spdx_sbom", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load SPDX checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


VALID = {
    "SPDXID": "SPDXRef-DOCUMENT",
    "creationInfo": {
        "created": "2026-09-21T00:00:00Z",
        "creators": ["Tool: test"],
    },
    "dataLicense": "CC0-1.0",
    "documentNamespace": "https://example.invalid/evidence/1",
    "files": [
        {
            "SPDXID": "SPDXRef-File-1",
            "checksums": [{"algorithm": "SHA256", "checksumValue": "0" * 64}],
            "copyrightText": "NOASSERTION",
            "fileName": "input.bin",
            "licenseConcluded": "NOASSERTION",
            "licenseInfoInFiles": ["NOASSERTION"],
        }
    ],
    "name": "test inventory",
    "spdxVersion": "SPDX-2.3",
}


def rejected(document: object) -> None:
    try:
        CHECKER.check(document)
    except CHECKER.SpdxError:
        return
    raise AssertionError("SPDX checker accepted an adversarial mutation")


def main() -> None:
    CHECKER.check(VALID)
    missing_created = copy.deepcopy(VALID)
    del missing_created["creationInfo"]["created"]
    rejected(missing_created)
    invalid_created = copy.deepcopy(VALID)
    invalid_created["creationInfo"]["created"] = "not-a-timestamp"
    rejected(invalid_created)
    duplicate = copy.deepcopy(VALID)
    duplicate["files"].append(copy.deepcopy(duplicate["files"][0]))
    rejected(duplicate)
    invalid_checksum = copy.deepcopy(VALID)
    invalid_checksum["files"][0]["checksums"][0]["checksumValue"] = "not-sha256"
    rejected(invalid_checksum)
    print("SPDX checker adversarial tests passed")


if __name__ == "__main__":
    main()
