#!/usr/bin/env python3
"""Keep the ADR-064 counterfactual adapter seal inside the storage adapters.

`pos_core::CounterfactualAdapterSealV1` mints counterfactual commit evidence
(generation receipts and committed Tick outcomes). Its constructor exists only
with `pos-core`'s `counterfactual-adapter` feature, so:

- only `crates/pos-store/Cargo.toml` may enable `counterfactual-adapter` in a
  deployable dependency table or forward it from a feature; every manifest may
  enable it from `[dev-dependencies]`;
- `pos-core`'s `default` feature must never reach `counterfactual-adapter`;
- outside `crates/pos-core/` and `crates/pos-store/`, only files under a
  `tests` directory may name `CounterfactualAdapterSealV1` in code (comments
  are ignored).
"""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

from check_test_support_features import default_closure
from check_trusted_clock_port_impls import strip_comments

FEATURE = "counterfactual-adapter"
SEAL = re.compile(r"\bCounterfactualAdapterSealV1\b")
ADAPTER_MANIFEST = "crates/pos-store/Cargo.toml"
SOURCE_PREFIXES = ("crates/pos-core/", "crates/pos-store/")
DEPLOYABLE_SECTIONS = ("dependencies", "build-dependencies")
SKIPPED_PARTS = {"target", ".git", ".trunk", "node_modules"}


def _kept(path: Path, root: Path) -> bool:
    return not SKIPPED_PARTS.intersection(path.relative_to(root).parts[:1])


def _deployable_tables(manifest: dict) -> list[tuple[str, dict]]:
    tables = [(section, manifest.get(section, {})) for section in DEPLOYABLE_SECTIONS]
    for target, target_tables in manifest.get("target", {}).items():
        tables.extend(
            (f"target.{target}.{section}", target_tables.get(section, {}))
            for section in DEPLOYABLE_SECTIONS
        )
    tables.append(("workspace.dependencies", manifest.get("workspace", {}).get("dependencies", {})))
    return tables


def manifest_violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("Cargo.toml")):
        if not _kept(path, root):
            continue
        name = path.relative_to(root).as_posix()
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        features = manifest.get("features", {})
        if FEATURE in default_closure(features):
            found.append(f"{name}: default feature enables {FEATURE}")
        if name == ADAPTER_MANIFEST:
            continue
        for section, dependencies in _deployable_tables(manifest):
            found.extend(
                f"{name}: [{section}] {dependency} enables {FEATURE}"
                for dependency, spec in dependencies.items()
                if isinstance(spec, dict) and FEATURE in spec.get("features", [])
            )
        for feature, members in features.items():
            if any(member.endswith(f"/{FEATURE}") for member in members):
                found.append(f"{name}: feature {feature} forwards {FEATURE}")
    return found


def source_violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        if not _kept(path, root):
            continue
        relative = path.relative_to(root)
        name = relative.as_posix()
        if name.startswith(SOURCE_PREFIXES) or "tests" in relative.parts[:-1]:
            continue
        code = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        if SEAL.search(code):
            found.append(f"{name}: names the counterfactual adapter seal outside the adapters")
    return found


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    found = manifest_violations(root) + source_violations(root)
    if found:
        raise SystemExit("\n".join(found))
    print(f"{FEATURE} and its seal stay inside the counterfactual storage adapters")


if __name__ == "__main__":
    main()
