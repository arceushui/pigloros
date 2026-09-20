#!/usr/bin/env python3
"""Independently validate and extract the exact revision-19 OCI ustar archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re


def octal(value: int, digits: int) -> bytes:
    encoded = f"{value:0{digits}o}".encode("ascii")
    if len(encoded) != digits:
        raise ValueError("ustar numeric field overflow")
    return encoded + b"\0"


def expected_header(name: str, size: int, directory: bool) -> bytes:
    encoded_name = name.encode("ascii")
    result = bytearray(512)
    result[0 : len(encoded_name)] = encoded_name
    result[100:108] = octal(0o755 if directory else 0o644, 7)
    result[108:116] = octal(0, 7)
    result[116:124] = octal(0, 7)
    result[124:136] = octal(size, 11)
    result[136:148] = octal(0, 11)
    result[148:156] = b"        "
    result[156] = ord("5" if directory else "0")
    result[257:263] = b"ustar\0"
    result[263:265] = b"00"
    result[329:337] = octal(0, 7)
    result[337:345] = octal(0, 7)
    checksum = sum(result)
    result[148:156] = f"{checksum:06o}".encode("ascii") + b"\0 "
    return bytes(result)


def parse_size(field: bytes) -> int:
    if not re.fullmatch(rb"[0-7]{11}\0", field):
        raise ValueError("noncanonical ustar size")
    return int(field[:-1], 8)


def canonical_json(content: bytes, name: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key in {name}")
            value[key] = item
        return value

    if content.startswith(b"\xef\xbb\xbf") or b"\0" in content:
        raise ValueError(f"invalid JSON encoding in {name}")
    value = json.loads(content.decode("utf-8"), object_pairs_hook=reject_duplicates)
    encoded = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    if encoded != content:
        raise ValueError(f"noncanonical JSON in {name}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("layout", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    arguments = parser.parse_args()

    archive = arguments.archive.read_bytes()
    if len(archive) % 512 or len(archive) > 1_073_741_824:
        raise ValueError("invalid OCI archive size")
    entries: list[tuple[str, bytes, bool]] = []
    offset = 0
    while offset < len(archive):
        header = archive[offset : offset + 512]
        if header == bytes(512):
            if archive[offset:] != bytes(1024):
                raise ValueError("archive does not end in exactly two zero blocks")
            offset = len(archive)
            break
        if b"\0" not in header[:100]:
            raise ValueError("unterminated ustar name")
        name = header[:100].split(b"\0", 1)[0].decode("ascii")
        size = parse_size(header[124:136])
        directory = header[156:157] == b"5"
        if header != expected_header(name, size, directory):
            raise ValueError(f"noncanonical ustar header for {name}")
        start = offset + 512
        end = start + size
        padded_end = start + ((size + 511) // 512) * 512
        if padded_end > len(archive) or archive[end:padded_end] != bytes(
            padded_end - end
        ):
            raise ValueError(f"invalid ustar payload padding for {name}")
        entries.append((name, archive[start:end], directory))
        offset = padded_end
    if offset != len(archive) or len(entries) < 6:
        raise ValueError("truncated OCI archive")

    names = [name for name, _, _ in entries]
    if names[:4] != ["blobs/", "blobs/sha256/", "oci-layout", "index.json"]:
        raise ValueError("OCI archive prefix order mismatch")
    if names[4:] != sorted(names[4:], key=str.encode) or len(set(names)) != len(
        names
    ):
        raise ValueError("OCI blob paths are not strictly sorted and unique")
    if any(content or not directory for _, content, directory in entries[:2]):
        raise ValueError("OCI directory entries are malformed")
    if any(directory for _, _, directory in entries[2:]):
        raise ValueError("OCI file entry uses a directory type")
    if any(
        not re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name)
        for name in names[4:]
    ):
        raise ValueError("OCI archive has an invalid blob path")

    files = {name: content for name, content, directory in entries if not directory}
    layout = canonical_json(files["oci-layout"], "oci-layout")
    index = canonical_json(files["index.json"], "index.json")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("unexpected oci-layout")
    if not isinstance(index, dict):
        raise ValueError("index is not an object")
    for name in names[4:]:
        content = files[name]
        if hashlib.sha256(content).hexdigest() != name.rsplit("/", 1)[1]:
            raise ValueError(f"blob path digest mismatch for {name}")
        if len(content) <= 1_048_576 and content.startswith((b"{", b"[")):
            canonical_json(content, name)

    arguments.layout.mkdir(parents=True)
    for name, content, directory in entries:
        path = arguments.layout / name
        if directory:
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    arguments.output.write_text(
        json.dumps(
            {
                "archive_sha256": hashlib.sha256(archive).hexdigest(),
                "entries": [
                    {
                        "name": name,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "size": len(content),
                        "type": "directory" if directory else "file",
                    }
                    for name, content, directory in entries
                ],
                "verdict": "passed",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
