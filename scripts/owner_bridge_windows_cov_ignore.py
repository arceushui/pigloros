#!/usr/bin/env python3
"""Generate ADR-110 section 15's shim-only coverage exclusion regex.

Read `cargo metadata --locked --no-deps --format-version 1` JSON on stdin.
Only stdout is the generated regex. No Cargo process is launched here.
The expression uses POSIX ERE syntax: cargo-llvm-cov passes it to llvm-cov.
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any


SHIM_NAME = "pos-owner-bridge-windows"
SHIM_DIRECTORY = "crates/pos-owner-bridge-windows"
SEPARATOR = r"[\\/]"
ERE_SPECIAL = frozenset(r"\.^$|?*+()[]{}")


class MetadataError(ValueError):
    """Metadata cannot safely describe the shim's coverage scope."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MetadataError(message)


def path_value(value: Any) -> str:
    require(isinstance(value, str) and bool(value), "paths must be nonempty strings")
    require(not any(c in value for c in "\0\r\n"), "paths contain unsupported control characters")
    return value


def member_directory(root: pathlib.PurePath, manifest: Any) -> pathlib.PurePath:
    path = type(root)(path_value(manifest))
    require(path.is_absolute(), "manifest paths must be absolute")
    require(path.name == "Cargo.toml", "member manifest must be Cargo.toml")
    require(".." not in path.parts, "manifest paths must not traverse parents")
    try:
        return path.parent.relative_to(root)
    except ValueError as error:
        raise MetadataError("workspace member is outside the workspace root") from error


def path_pattern(path: str) -> str:
    def escape(component: str) -> str:
        return "".join("\\" + c if c in ERE_SPECIAL else c for c in component)

    return SEPARATOR.join(escape(component) for component in path.split("/"))


def coverage_ignore_regex(metadata: Any) -> str:
    """Exclude all non-shim members without matching source nested in the shim.

    Package IDs are opaque. Unknown metadata fields and non-workspace packages
    do not affect the scope. Both absolute and workspace-relative report paths
    are supported, with either separator direction.
    """
    require(isinstance(metadata, dict), "metadata must be an object")
    require(type(metadata.get("version")) is int and metadata["version"] == 1,
            "metadata format version must be 1")
    root_value = path_value(metadata.get("workspace_root"))
    root = (pathlib.PureWindowsPath(root_value)
            if pathlib.PureWindowsPath(root_value).is_absolute()
            else pathlib.PurePosixPath(root_value))
    require(root.is_absolute() and ".." not in root.parts, "workspace root must be absolute")
    packages = metadata.get("packages")
    members = metadata.get("workspace_members")
    require(isinstance(packages, list), "packages must be an array")
    require(isinstance(members, list) and bool(members), "workspace members must be a nonempty array")
    require(all(isinstance(member, str) and member for member in members),
            "workspace member IDs must be nonempty strings")
    require(len(set(members)) == len(members), "duplicate workspace member IDs")
    by_id = {}
    for package in packages:
        require(isinstance(package, dict), "packages must contain objects")
        package_id = package.get("id")
        require(isinstance(package_id, str) and bool(package_id), "package IDs must be nonempty strings")
        require(package_id not in by_id, "duplicate package IDs")
        by_id[package_id] = package
    require(all(member in by_id for member in members), "workspace member is missing from packages")
    selected = [by_id[member] for member in members]
    require(all(isinstance(p.get("name"), str) and p["name"] for p in selected),
            "workspace package names must be nonempty strings")
    shims = [p for p in selected if p["name"] == SHIM_NAME]
    require(len(shims) == 1, "workspace must contain exactly one Windows shim")
    shim = member_directory(root, shims[0].get("manifest_path"))
    require(shim == type(root)(SHIM_DIRECTORY), "Windows shim moved from its approved directory")
    patterns = []
    for package in selected:
        directory = member_directory(root, package.get("manifest_path"))
        if package["id"] == shims[0]["id"]:
            continue
        require(not shim.is_relative_to(directory), "a member directory would exclude the Windows shim")
        patterns.append(path_pattern(directory.as_posix()) + SEPARATOR)
    if not patterns:
        # Coverage filenames are nonempty; an empty alternation would hide all.
        return "^$"
    root_pattern = path_pattern(root.as_posix().rstrip("/"))
    if isinstance(root, pathlib.PureWindowsPath) and len(root.drive) == 2:
        drive = root.drive[0]
        root_pattern = f"[{drive.lower()}{drive.upper()}]" + root_pattern[1:]
    # Anchor member directories at the workspace boundary. A shim source path
    # containing e.g. src/fixtures/crates/pos-core must never match that member.
    return "^(" + root_pattern + SEPARATOR + ")?(" + "|".join(sorted(set(patterns))) + ")"


def main() -> int:
    try:
        expression = coverage_ignore_regex(json.load(sys.stdin.buffer))
    except (MetadataError, json.JSONDecodeError, UnicodeDecodeError) as error:
        print(f"owner-bridge coverage metadata: {error}", file=sys.stderr)
        return 2
    # Cargo emits UTF-8; Windows redirected stdio may use a legacy code page.
    sys.stdout.buffer.write(expression.encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
