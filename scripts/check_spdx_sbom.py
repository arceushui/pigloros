#!/usr/bin/env python3
"""Validate the closed SPDX 2.3 document shape emitted by the prototype."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from datetime import UTC, datetime


SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
CREATED = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
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


def expected_created(source_date_epoch: int) -> str:
    return datetime.fromtimestamp(source_date_epoch, UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def check(document: object, source_date_epoch: int) -> None:
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
    require(
        isinstance(created, str) and CREATED.fullmatch(created) is not None,
        "invalid creation time",
    )
    try:
        datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise SpdxError("invalid creation time") from error
    require(
        created == expected_created(source_date_epoch),
        "creation time differs from source epoch",
    )
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
        require(
            isinstance(name, str)
            and name.startswith("./")
            and name != "./"
            and not pathlib.PurePosixPath(name).is_absolute()
            and ".." not in pathlib.PurePosixPath(name).parts
            and name not in names,
            "duplicate, absolute, or invalid file name",
        )
        require(
            isinstance(identifier, str) and identifier not in identifiers,
            "duplicate or invalid file SPDXID",
        )
        names.add(name)
        identifiers.add(identifier)
        checksums = entry["checksums"]
        require(
            isinstance(checksums, list)
            and len(checksums) == 2
            and all(
                isinstance(checksum, dict)
                and set(checksum) == {"algorithm", "checksumValue"}
                for checksum in checksums
            ),
            "invalid checksum inventory",
        )
        by_algorithm = {
            checksum["algorithm"]: checksum["checksumValue"] for checksum in checksums
        }
        require(
            set(by_algorithm) == {"SHA1", "SHA256"},
            "missing or duplicate checksum",
        )
        require(
            isinstance(by_algorithm["SHA1"], str)
            and SHA1.fullmatch(by_algorithm["SHA1"]) is not None,
            "invalid SHA-1 checksum",
        )
        require(
            isinstance(by_algorithm["SHA256"], str)
            and SHA256.fullmatch(by_algorithm["SHA256"]) is not None,
            "invalid SHA-256 checksum",
        )


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} SPDX_JSON SOURCE_DATE_EPOCH")
    try:
        source_date_epoch = int(sys.argv[2])
        require(source_date_epoch >= 0, "source epoch must be non-negative")
        document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
        check(document, source_date_epoch)
    except (OSError, ValueError) as error:
        print(f"SPDX validation error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print("SPDX document structure OK")


if __name__ == "__main__":
    main()
