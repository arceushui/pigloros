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
SOURCE_DATE_EPOCH = 1789948800
GITHUB_SHA = "a" * 40
GITHUB_RUN_ID = "12345"
GITHUB_RUN_ATTEMPT = "2"
ARCHITECTURE = "amd64"


VALID = {
    "SPDXID": "SPDXRef-DOCUMENT",
    "creationInfo": {
        "created": CHECKER.expected_created(SOURCE_DATE_EPOCH),
        "creators": [f"Tool: PiglorOS-ADR-084-evidence-workflow-{GITHUB_SHA}"],
    },
    "dataLicense": "CC0-1.0",
    "documentNamespace": (
        "https://github.com/arceushui/pigloros/adr084-evidence/"
        f"{GITHUB_RUN_ID}/{GITHUB_RUN_ATTEMPT}/{ARCHITECTURE}"
    ),
    "files": [
        {
            "SPDXID": "SPDXRef-File-1",
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": "0" * 40},
                {"algorithm": "SHA256", "checksumValue": "0" * 64},
            ],
            "copyrightText": "NOASSERTION",
            "fileName": "./input.bin",
            "licenseConcluded": "NOASSERTION",
            "licenseInfoInFiles": ["NOASSERTION"],
        }
    ],
    "name": "PiglorOS ADR-084 throwaway OCI fixture",
    "spdxVersion": "SPDX-2.3",
}


def rejected(document: object) -> None:
    try:
        CHECKER.check(
            document,
            SOURCE_DATE_EPOCH,
            GITHUB_SHA,
            GITHUB_RUN_ID,
            GITHUB_RUN_ATTEMPT,
            ARCHITECTURE,
        )
    except CHECKER.SpdxError:
        return
    raise AssertionError("SPDX checker accepted an adversarial mutation")


def main() -> None:
    CHECKER.check(
        VALID,
        SOURCE_DATE_EPOCH,
        GITHUB_SHA,
        GITHUB_RUN_ID,
        GITHUB_RUN_ATTEMPT,
        ARCHITECTURE,
    )
    extra_root = copy.deepcopy(VALID)
    extra_root["unexpected"] = True
    rejected(extra_root)
    missing_created = copy.deepcopy(VALID)
    del missing_created["creationInfo"]["created"]
    rejected(missing_created)
    invalid_created = copy.deepcopy(VALID)
    invalid_created["creationInfo"]["created"] = "not-a-timestamp"
    rejected(invalid_created)
    fractional_created = copy.deepcopy(VALID)
    fractional_created["creationInfo"]["created"] = "2026-09-21T00:00:00.000Z"
    rejected(fractional_created)
    mismatched_created = copy.deepcopy(VALID)
    mismatched_created["creationInfo"]["created"] = CHECKER.expected_created(
        SOURCE_DATE_EPOCH + 1
    )
    rejected(mismatched_created)
    unversioned_creator = copy.deepcopy(VALID)
    unversioned_creator["creationInfo"]["creators"] = ["Tool: test"]
    rejected(unversioned_creator)
    reused_namespace = copy.deepcopy(VALID)
    reused_namespace["documentNamespace"] = (
        "https://github.com/arceushui/pigloros/adr084-evidence/"
        f"{GITHUB_RUN_ID}/1/{ARCHITECTURE}"
    )
    rejected(reused_namespace)
    absolute_name = copy.deepcopy(VALID)
    absolute_name["files"][0]["fileName"] = "/input.bin"
    rejected(absolute_name)
    parent_name = copy.deepcopy(VALID)
    parent_name["files"][0]["fileName"] = "./../input.bin"
    rejected(parent_name)
    duplicate = copy.deepcopy(VALID)
    duplicate["files"].append(copy.deepcopy(duplicate["files"][0]))
    rejected(duplicate)
    invalid_spdxid = copy.deepcopy(VALID)
    invalid_spdxid["files"][0]["SPDXID"] = "invalid"
    rejected(invalid_spdxid)
    invalid_copyright = copy.deepcopy(VALID)
    invalid_copyright["files"][0]["copyrightText"] = ""
    rejected(invalid_copyright)
    invalid_concluded = copy.deepcopy(VALID)
    invalid_concluded["files"][0]["licenseConcluded"] = ""
    rejected(invalid_concluded)
    invalid_license = copy.deepcopy(VALID)
    invalid_license["files"][0]["licenseInfoInFiles"] = []
    rejected(invalid_license)
    invalid_checksum = copy.deepcopy(VALID)
    invalid_checksum["files"][0]["checksums"][1]["checksumValue"] = "not-sha256"
    rejected(invalid_checksum)
    missing_sha1 = copy.deepcopy(VALID)
    del missing_sha1["files"][0]["checksums"][0]
    rejected(missing_sha1)
    duplicate_sha256 = copy.deepcopy(VALID)
    duplicate_sha256["files"][0]["checksums"][0] = copy.deepcopy(
        duplicate_sha256["files"][0]["checksums"][1]
    )
    rejected(duplicate_sha256)
    print("SPDX checker adversarial tests passed")


if __name__ == "__main__":
    main()
