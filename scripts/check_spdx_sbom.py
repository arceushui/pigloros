#!/usr/bin/env python3
"""Validate the closed SPDX 2.3 subset emitted by the ADR-084 prototype."""

from __future__ import annotations

import datetime
import json
import pathlib
import re
import sys


SHA256 = re.compile(r"[0-9a-f]{64}")
FILE_KEYS = {
    "SPDXID",
    "checksums",
    "copyrightText",
    "fileName",
    "licenseConcluded",
    "licenseInfoInFiles",
}


class SpdxError(ValueError):
    """The emitted SPDX document is malformed or incomplete."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SpdxError(message)


def check(document: object) -> None:
    require(isinstance(document, dict), "document root must be an object")
    require(document.get("spdxVersion") == "SPDX-2.3", "wrong SPDX version")
    require(document.get("SPDXID") == "SPDXRef-DOCUMENT", "wrong document SPDXID")
    require(document.get("dataLicense") == "CC0-1.0", "wrong data license")
    require(isinstance(document.get("name"), str) and bool(document["name"]), "missing name")
    namespace = document.get("documentNamespace")
    require(
        isinstance(namespace, str) and namespace.startswith("https://"),
        "invalid document namespace",
    )
    creation = document.get("creationInfo")
    require(isinstance(creation, dict), "missing creationInfo")
    require(set(creation) == {"created", "creators"}, "invalid creationInfo keys")
    created = creation.get("created")
    require(isinstance(created, str) and created.endswith("Z"), "invalid creation time")
    try:
        parsed_created = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as error:
        raise SpdxError("invalid creation time") from error
    require(parsed_created.tzinfo is not None, "creation time lacks timezone")
    creators = creation.get("creators")
    require(
        isinstance(creators, list)
        and creators
        and all(isinstance(creator, str) and creator for creator in creators),
        "invalid creators",
    )
    files = document.get("files")
    require(isinstance(files, list) and files, "missing file inventory")
    names: set[str] = set()
    identifiers: set[str] = set()
    for entry in files:
        require(isinstance(entry, dict) and set(entry) == FILE_KEYS, "invalid file entry")
        name = entry["fileName"]
        identifier = entry["SPDXID"]
        require(isinstance(name, str) and name not in names, "duplicate or invalid file name")
        require(
            isinstance(identifier, str) and identifier not in identifiers,
            "duplicate or invalid file SPDXID",
        )
        names.add(name)
        identifiers.add(identifier)
        checksums = entry["checksums"]
        require(
            isinstance(checksums, list)
            and len(checksums) == 1
            and isinstance(checksums[0], dict)
            and checksums[0].get("algorithm") == "SHA256"
            and isinstance(checksums[0].get("checksumValue"), str)
            and SHA256.fullmatch(checksums[0]["checksumValue"]) is not None,
            "invalid SHA-256 checksum",
        )


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} SPDX_JSON")
    try:
        document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
        check(document)
    except (OSError, json.JSONDecodeError, SpdxError) as error:
        print(f"SPDX validation error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print("SPDX inventory OK")


if __name__ == "__main__":
    main()
