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
  crate's top-level `tests` directory (a `tests` directory beside a
  `Cargo.toml`, not `src/tests/`) may name `CounterfactualAdapterSealV1` in
  code (comments are ignored);
- `crates/pos-store/src` never re-exports the seal (`pub use`, including a
  glob over `pos_core`) and no public fn there returns it;
- CI workflows, Dockerfiles and `.cargo/config*` never name the
  `counterfactual-adapter` feature, so no build flag can enable it outside
  the manifests above.
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
SEAL_REEXPORT = re.compile(
    r"\bpub\s+use\b[^;]*(?:\bCounterfactualAdapterSealV1\b|\bpos_core\s*::\s*\*)"
)
SEAL_RETURN = re.compile(
    r"\bpub\s+(?:(?:const|async|unsafe|extern\s+\"[^\"]*\")\s+)*fn\b[^{;]*?->[^{;]*"
    r"\bCounterfactualAdapterSealV1\b"
)
ADAPTER_SOURCES = "crates/pos-store/src/"
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


def _in_crate_tests(relative: Path, root: Path) -> bool:
    parts = relative.parts[:-1]
    return any(
        part == "tests" and (root.joinpath(*parts[:index]) / "Cargo.toml").is_file()
        for index, part in enumerate(parts)
    )


def _adapter_leaks(name: str, code: str) -> list[str]:
    found: list[str] = []
    if SEAL_REEXPORT.search(code):
        found.append(f"{name}: re-exports the counterfactual adapter seal")
    if SEAL_RETURN.search(code):
        found.append(f"{name}: returns the counterfactual adapter seal from a public fn")
    return found


def source_violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        if not _kept(path, root):
            continue
        relative = path.relative_to(root)
        name = relative.as_posix()
        code = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        if name.startswith(ADAPTER_SOURCES):
            found.extend(_adapter_leaks(name, code))
        if name.startswith(SOURCE_PREFIXES) or _in_crate_tests(relative, root):
            continue
        if SEAL.search(code):
            found.append(f"{name}: names the counterfactual adapter seal outside the adapters")
    return found


def _build_configs(root: Path) -> list[Path]:
    workflows = root / ".github/workflows"
    paths = [*workflows.glob("*.yml"), *workflows.glob("*.yaml")]
    paths.extend(
        path
        for pattern in ("Dockerfile*", "*.Dockerfile", "config*")
        for path in root.rglob(pattern)
        if path.is_file()
        and _kept(path, root)
        and (pattern != "config*" or path.parent.name == ".cargo")
    )
    return sorted(set(paths))


def config_violations(root: Path) -> list[str]:
    return [
        f"{path.relative_to(root).as_posix()}: enables {FEATURE} outside a manifest"
        for path in _build_configs(root)
        if FEATURE in path.read_text(encoding="utf-8", errors="replace")
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    found = manifest_violations(root) + source_violations(root) + config_violations(root)
    if found:
        raise SystemExit("\n".join(found))
    print(f"{FEATURE} and its seal stay inside the counterfactual storage adapters")


if __name__ == "__main__":
    main()
