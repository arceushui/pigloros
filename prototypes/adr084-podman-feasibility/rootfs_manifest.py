#!/usr/bin/env python3
"""Record the prototype's effective mounted rootfs without following symlinks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat


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
            content = path.read_bytes()
            item.update(
                kind="regular",
                length=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
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
