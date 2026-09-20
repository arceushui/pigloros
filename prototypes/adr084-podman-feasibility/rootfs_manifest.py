#!/usr/bin/env python3
"""Record the prototype's effective mounted rootfs without following symlinks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess


ROOTFS_FILE_DOMAIN = b"PiglorOS.OciRootfsFile.v1\0"


def regular_file_digests(path: pathlib.Path) -> tuple[int, str, str]:
    """Stream both raw SHA-256 and domain-separated BLAKE3 for one file."""
    sha256 = hashlib.sha256()
    length = 0
    process = subprocess.Popen(
        ["b3sum"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert process.stdin is not None
    process.stdin.write(ROOTFS_FILE_DOMAIN)
    with path.open("rb") as stream:
        while chunk := stream.read(65_536):
            length += len(chunk)
            sha256.update(chunk)
            process.stdin.write(chunk)
    process.stdin.close()
    assert process.stdout is not None
    assert process.stderr is not None
    output = process.stdout.read().decode("ascii")
    error = process.stderr.read().decode("utf-8", errors="replace")
    if process.wait() != 0:
        raise RuntimeError(f"b3sum failed for {path}: {error}")
    return length, sha256.hexdigest(), output.split()[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    entries: list[dict[str, object]] = []

    def append_entry(path: pathlib.Path) -> None:
        relative = path.relative_to(root)
        normalized = "/" if str(relative) == "." else "/" + relative.as_posix()
        metadata = path.lstat()
        item: dict[str, object] = {
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "path": normalized,
            "uid": metadata.st_uid,
        }
        if stat.S_ISDIR(metadata.st_mode):
            item.update(kind="directory", length=0)
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise ValueError(f"hard-linked rootfs file {normalized}")
            length, sha256, content_digest = regular_file_digests(path)
            item.update(
                kind="regular",
                length=length,
                sha256=sha256,
                content_digest=content_digest,
            )
        elif stat.S_ISLNK(metadata.st_mode):
            item.update(kind="symlink", length=0, target=os.readlink(path))
        else:
            raise ValueError(f"unsupported rootfs entry {normalized}")
        xattrs = os.listxattr(path, follow_symlinks=False)
        if xattrs:
            raise ValueError(f"unexpected xattrs on {normalized}: {xattrs}")
        entries.append(item)

    for directory, names, files in os.walk(root, followlinks=False):
        names.sort()
        files.sort()
        directory_path = pathlib.Path(directory)
        append_entry(directory_path)
        symlink_directories = [name for name in names if (directory_path / name).is_symlink()]
        names[:] = [name for name in names if name not in symlink_directories]
        for name in [*symlink_directories, *files]:
            append_entry(directory_path / name)
    entries.sort(key=lambda entry: str(entry["path"]).encode("utf-8"))
    if len({entry["path"] for entry in entries}) != len(entries):
        raise ValueError("duplicate rootfs paths")
    arguments.output.write_text(json.dumps({"entries": entries}, indent=2) + "\n")


if __name__ == "__main__":
    main()
