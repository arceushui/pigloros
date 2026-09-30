#!/usr/bin/env python3
"""Keep `test-support` features out of deployable dependency graphs.

`test-support` features expose fixture registration and draft-policy bypasses.
They may be enabled only from `[dev-dependencies]` or forwarded by a feature
that is itself named `test-support`; normal and build dependencies, workspace
dependency defaults, and `default` features (directly or through any feature
reachable from `default`) must never enable one.
"""

from __future__ import annotations

import argparse
import tomllib
from pathlib import Path

FEATURE = "test-support"
DEPLOYABLE_SECTIONS = ("dependencies", "build-dependencies")


def manifests(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("Cargo.toml")
        if not {"target", ".git"}.intersection(path.relative_to(root).parts)
    )


def enables_test_support(spec: object) -> bool:
    return isinstance(spec, dict) and FEATURE in spec.get("features", [])


def default_closure(features: dict[str, list[str]]) -> set[str]:
    """Return every local feature reachable from `default`, including `default`."""
    reached: set[str] = set()
    pending = ["default"]
    while pending:
        feature = pending.pop()
        if feature in reached:
            continue
        reached.add(feature)
        pending.extend(
            member
            for member in features.get(feature, [])
            if "/" not in member and not member.startswith("dep:")
        )
    return reached


def violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in manifests(root):
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        name = path.relative_to(root)
        tables = [(section, manifest.get(section, {})) for section in DEPLOYABLE_SECTIONS]
        for target, target_tables in manifest.get("target", {}).items():
            tables.extend(
                (f"target.{target}.{section}", target_tables.get(section, {}))
                for section in DEPLOYABLE_SECTIONS
            )
        workspace = manifest.get("workspace", {})
        tables.append(("workspace.dependencies", workspace.get("dependencies", {})))
        for section, dependencies in tables:
            found.extend(
                f"{name}: [{section}] {dependency} enables {FEATURE}"
                for dependency, spec in dependencies.items()
                if enables_test_support(spec)
            )
        features = manifest.get("features", {})
        if FEATURE in default_closure(features):
            found.append(f"{name}: default feature enables {FEATURE}")
        for feature, members in features.items():
            forwards = [member for member in members if member.endswith(f"/{FEATURE}")]
            if forwards and feature != FEATURE:
                found.append(f"{name}: feature {feature} forwards {', '.join(forwards)}")
    return found


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    found = violations(root)
    if found:
        raise SystemExit("\n".join(found))
    print(f"{FEATURE} is enabled only by dev-dependencies or {FEATURE} features")


if __name__ == "__main__":
    main()
