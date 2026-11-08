#!/usr/bin/env python3
"""Verify an extracted Fixed Runtime against the ADR-110 retained manifest.

This is packaging evidence. Runtime activation independently verifies the same
compiled-in manifest; a successful packaging run does not authorize activation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

VERSION = "153.0.4234.48"
CAB_SHA256 = "11e8240cb0bc56dcd3e4498907203c251346f65107fe35a3a13e152c7d51c79e"
PER_START = (
    "msedgewebview2.exe",
    "msedge.dll",
    "msedge_elf.dll",
    "EBWebView/x64/EmbeddedBrowserWebView.dll",
)
MANIFEST = Path(__file__).resolve().parent.parent / "crates/pos-owner-bridge-windows/runtime-manifest.v1"


def parse_manifest(text: str) -> dict[str, tuple[int, str]]:
    """Reject ambiguous paths, aliases and malformed entries before filesystem IO."""
    entries = {}
    folded = set()
    for line in text.splitlines():
        digest, size, name = line.split("  ")
        path = PurePosixPath(name)
        if (
            not name or "\\" in name or ":" in name or path.is_absolute()
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or any(ord(char) < 32 for char in name)
            or any(part.endswith((" ", ".")) for part in path.parts)
            or name.casefold() in folded
            or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)
            or not size.isascii() or not size.isdecimal() or str(int(size)) != size
        ):
            raise ValueError("invalid runtime manifest entry")
        folded.add(name.casefold())
        entries[name] = (int(size), digest)
    if not entries:
        raise ValueError("empty runtime manifest")
    return entries


def verify_tree(root: Path, expected: dict[str, tuple[int, str]]) -> list[dict]:
    """Verify exact membership, regular files, sizes and all content digests."""
    if (root.is_symlink() or not root.is_dir()
            or getattr(root.lstat(), "st_file_attributes", 0) & 0x400):
        raise ValueError("runtime root must be an ordinary directory")
    files = {}
    for path in root.rglob("*"):
        if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("runtime must not contain links or junctions")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = path
        elif not path.is_dir():
            raise ValueError("runtime contains a non-regular entry")
    if files.keys() != expected.keys():
        raise ValueError("runtime file inventory differs from the retained manifest")
    result = []
    for name in sorted(expected):
        path = files[name]
        size, digest = expected[name]
        metadata = path.stat()
        if metadata.st_size != size:
            raise ValueError(f"runtime size mismatch: {name}")
        checksum = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                checksum.update(block)
        if checksum.hexdigest() != digest:
            raise ValueError(f"runtime digest mismatch: {name}")
        result.append({"path": name, "size": size, "sha256": digest,
                       "modified_filetime": metadata.st_mtime_ns // 100 + 116_444_736_000_000_000})
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    expected = parse_manifest(MANIFEST.read_text(encoding="utf-8"))
    if not all(name in expected for name in PER_START):
        raise ValueError("retained manifest lacks a per-start binary")
    files = verify_tree(args.root, expected)
    args.output.write_text(json.dumps({"version": 1, "runtime_version": VERSION,
                                      "cab_sha256": CAB_SHA256, "files": files},
                                     indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
