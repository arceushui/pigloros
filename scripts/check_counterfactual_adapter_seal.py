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
- `crates/pos-store/src` never re-exports the seal: no `pub use` names it,
  globs over a `pos_core` path (any `pos_core` module may carry it),
  re-exports `pos_core::counterfactual_store`, or re-exports the `pos_core`
  crate itself (`pub use pos_core as alias`,
  `pub use pos_core::{self}`); no public fn there returns it; and no bare
  `pub` type, static, const, struct, enum or field line names it
  (`pub(crate)`/`pub(super)` items stay allowed);
- CI workflows, Dockerfiles and `.cargo/config*` never name the
  `counterfactual-adapter` feature, so no build flag can enable it outside
  the manifests above.

Stated limits: the check is textual. It does not cover `--all-features`
builds (which enable the feature by construction) nor build configuration
outside manifests, workflows, Dockerfiles and `.cargo/config*` (for example
a Makefile, justfile, `*.sh` script or composite action); those stay a
review responsibility.
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
PUBLIC_USE = re.compile(r"\bpub\s+use\s+([^;]*);")
CRATE_REEXPORT = re.compile(
    r"^(?:::)?pos_core(?:as\w+)?$|^(?:::)?pos_core::\{(?:.*,)?self(?:as\w+)?[,}]"
)
SEAL_MODULE = re.compile(
    r"\bcounterfactual_store(?:as\w+)?(?:[,}]|$)|\bcounterfactual_store::\{(?:.*,)?self\b"
)
PUBLIC_ITEM = re.compile(
    r"\bpub[ \t]+(?:type|static|struct|enum|"
    r"const\b(?![ \t]+(?:(?:async|unsafe|extern[ \t]+\"[^\"\n]*\")[ \t]+)*fn\b)|"
    r"(?:r#)?[A-Za-z_]\w*[ \t]*:(?!:))[^\n]*\bCounterfactualAdapterSealV1\b"
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


def _pos_core_leak(compact: str) -> bool:
    if not compact.startswith(("pos_core::", "::pos_core::")):
        return False
    return "*" in compact or SEAL_MODULE.search(compact) is not None


def _adapter_leaks(name: str, code: str) -> list[str]:
    found: list[str] = []
    for statement in PUBLIC_USE.findall(code):
        compact = re.sub(r"\s+", "", statement)
        if CRATE_REEXPORT.search(compact):
            found.append(f"{name}: re-exports the pos_core crate")
        elif SEAL.search(statement) or _pos_core_leak(compact):
            found.append(f"{name}: re-exports the counterfactual adapter seal")
    if PUBLIC_ITEM.search(code):
        found.append(f"{name}: exposes the counterfactual adapter seal from a public item")
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
