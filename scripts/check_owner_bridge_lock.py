#!/usr/bin/env python3
"""Check the accepted ADR-110 E16 rustix pin and Linux-only owner dependency.

Reads the committed manifests and lockfile without invoking Cargo.
The older rustix 0.38 transitive dependency is unrelated and remains allowed.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

VERSION = "1.1.5"
CHECKSUM = "891efababe418670775f199f0d233d84843c227a0949a883ce15b37c78d6629d"
SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
TARGET = 'cfg(target_os = "linux")'


def check(lock: dict, owner: dict, workspace: dict) -> list[str]:
    """Return violations of the selected dependency graph and features."""
    errors = []
    packages = lock.get("package", [])
    rustix = [p for p in packages if p.get("name") == "rustix"]
    selected = [p for p in rustix if p.get("version", "").startswith("1.")]
    if len(selected) != 1 or any(
        p.get(key) != value
        for p in selected
        for key, value in [("version", VERSION), ("source", SOURCE), ("checksum", CHECKSUM)]
    ):
        errors.append("expected exactly rustix 1.1.5 with the ADR-110 E16 source/checksum")
    consumers = [p for p in packages if p.get("name") == "pos-owner-bridge"]
    if len(consumers) != 1 or [
        dependency for dependency in consumers[0].get("dependencies", [])
        if dependency.split()[0] == "rustix"
    ] != ["rustix 1.1.5"]:
        errors.append("pos-owner-bridge must resolve the pinned rustix 1.1.5")
    expected = {"workspace": True, "features": ["process"]}
    targets = owner.get("target", {})
    actual = targets.get(TARGET, {}).get("dependencies", {}).get("rustix")
    if actual != expected:
        errors.append("owner rustix must inherit the workspace with only process on Linux")
    for target, table in [(None, owner), *targets.items()]:
        for kind in ["dependencies", "dev-dependencies", "build-dependencies"]:
            for name, dependency in table.get(kind, {}).items():
                is_rustix = name == "rustix" or (
                    isinstance(dependency, dict) and dependency.get("package") == "rustix"
                )
                if is_rustix and (target, kind, name) != (TARGET, "dependencies", "rustix"):
                    errors.append("owner rustix is allowed only as the named Linux normal dependency")
    expected_workspace = {
        "version": "1.1.4",
        "default-features": False,
        "features": ["fs", "std"],
    }
    if workspace.get("workspace", {}).get("dependencies", {}).get("rustix") != expected_workspace:
        errors.append("the shared rustix requirement/features must retain the accepted workspace entry")
    return errors


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    try:
        documents = [
            tomllib.loads((root / name).read_text(encoding="utf-8"))
            for name in ["Cargo.lock", "crates/pos-owner-bridge/Cargo.toml", "Cargo.toml"]
        ]
        errors = check(*documents)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print(f"owner-bridge lock check failed: {error}", file=sys.stderr)
        return 1
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("owner-bridge rustix pin and Linux-only features match ADR-110 E16")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
