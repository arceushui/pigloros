#!/usr/bin/env python3
"""Keep the ADR-129 A5.9 authority trust-root seal inside the trusted composition roots (#1374).

`pos_core::AuthorityTrustRootSealV1` builds the `AuthenticatedPrincipalResultV1` and
`AuthorityRegistrySnapshotV1` values the authority evaluator trusts, and the metadata authority
installed by `pos_store::community::CommunityMetadataAuthorityV1::new`. Its constructor exists
only with `pos-core`'s `authority-trust-root` feature, so:

- only `apps/piglor-gateway`, `apps/pos-experiment` and `apps/pos-plugin-conformance-adapter`
  (the trusted composition roots) and `crates/pos-store` (the community owner, #560) may enable
  `authority-trust-root` in a deployable dependency table or forward it from a feature; every
  manifest may enable it from `[dev-dependencies]`;
- no feature named `local-admission-host`, nor any feature it reaches, forwards it, in any
  manifest: the local scheduled-admission host takes the seal from its caller and never mints it;
- outside `crates/pos-core/`, non-test code calls `for_composition_root` only at the pinned mint
  sites, exactly once each: `apps/piglor-gateway/src/local_principal.rs`,
  `apps/pos-experiment/src/lib.rs`, `apps/pos-plugin-conformance-adapter/src/main.rs` and
  `crates/pos-store/src/community/attestation.rs` (the community owner's per-request snapshot and
  verified authentication result, ADR-129 R6.2(5)). Crates
  that depend on an allowed crate compile the minter too (Cargo features are global) but cannot
  call it. Test code is exempt: a crate's top-level `tests` directory, an inline
  `#[cfg(test)] mod name { .. }`, and the file of a module declared `#[cfg(test)] mod name;`
  with all of its descendant modules. Any other guard (`cfg(all(test, ..))`, `#[path]`) is not
  recognised, so such a mint is rejected;
- in non-test `crates/pos-core/src` code, the seal derives only `Debug`, has exactly one inherent
  impl (in `authority.rs`) whose only fn is `for_composition_root`, has no trait impl, and is
  never constructed by a literal, so no second constructor can bypass the doctests;
- no `default` feature closure reaches `authority-trust-root` or a feature that forwards it, and
  no `pos-core` feature forwards it;
- outside `crates/pos-core/` and the crates' top-level `tests` directories, no source re-exports
  the seal: no `pub use` names it, globs over a `pos_core` path, re-exports
  `pos_core::authority`, or re-exports the `pos_core` crate itself; no public fn, and no fn in a
  `pub trait`, returns it; no `pub enum` body names it; no type alias of any visibility names
  it; and no bare `pub` static, const, struct or field line names it
  (`pub(crate)`/`pub(super)` items other than aliases stay allowed);
- CI workflows, Dockerfiles and `.cargo/config*` never name the `authority-trust-root` feature,
  so no build flag can enable it outside the manifests above.

The source rule applies to the allowed crates too: they mint the seal for their own use and pass
it only by reference.

Stated limits: the check is textual. It does not cover `--all-features` builds (which enable the
feature by construction) nor build configuration outside manifests, workflows, Dockerfiles and
`.cargo/config*`; those stay a review responsibility.
"""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

from check_counterfactual_adapter_seal import (
    CRATE_REEXPORT,
    PUBLIC_USE,
    _build_configs,
    _deployable_tables,
    _in_crate_tests,
    _kept,
)
from check_test_support_features import default_closure
from check_trusted_clock_port_impls import strip_comments

FEATURE = "authority-trust-root"
SEAL_NAME = "AuthorityTrustRootSealV1"
SEAL = re.compile(rf"\b{SEAL_NAME}\b")
SEAL_MODULE = re.compile(r"\bauthority(?:as\w+)?(?:[,}]|$)|\bauthority::\{(?:.*,)?self\b")
PUBLIC_ITEM = re.compile(
    r"\bpub[ \t]+(?:type|static|struct|enum|"
    r"const\b(?![ \t]+(?:(?:async|unsafe|extern[ \t]+\"[^\"\n]*\")[ \t]+)*fn\b)|"
    rf"(?:r#)?[A-Za-z_]\w*[ \t]*:(?!:))[^\n]*\b{SEAL_NAME}\b"
)
SEAL_RETURN = re.compile(
    r"\bpub\s+(?:(?:const|async|unsafe|extern\s+\"[^\"]*\")\s+)*fn\b[^{;]*?->[^{;]*"
    rf"\b{SEAL_NAME}\b"
)
PUBLIC_BODY = re.compile(r"\bpub\s+(trait|enum)\b[^{;]*\{")
BODY_RETURN = re.compile(rf"\bfn\b[^{{;]*?->[^{{;]*\b{SEAL_NAME}\b")
ALIAS = re.compile(rf"\btype\s+\w+(?:<[^>]*>)?\s*=[^;]*\b{SEAL_NAME}\b")
ENABLING_MANIFESTS = (
    "apps/piglor-gateway/Cargo.toml",
    "apps/pos-experiment/Cargo.toml",
    "apps/pos-plugin-conformance-adapter/Cargo.toml",
    "crates/pos-store/Cargo.toml",
)
ADMISSION_FEATURE = "local-admission-host"
CORE_SOURCES = "crates/pos-core/"
CORE_SEAL_SOURCE = "crates/pos-core/src/authority.rs"
MINT = re.compile(r"\bfor_composition_root\b")
MINT_SITES = {
    "apps/piglor-gateway/src/local_principal.rs": 1,
    "apps/pos-experiment/src/lib.rs": 1,
    "apps/pos-plugin-conformance-adapter/src/main.rs": 1,
    "crates/pos-store/src/community/attestation.rs": 1,
}
TEST_ATTRIBUTES = r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*"
INLINE_TEST_MODULE = re.compile(TEST_ATTRIBUTES + r"\{")
OUTLINE_TEST_MODULE = re.compile(TEST_ATTRIBUTES + ";")
OUTLINE_MODULE = re.compile(r"(?:^|[;}\]\s])(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;")
SEAL_PATH = rf"(?:(?:\w+)?::)*{SEAL_NAME}\b"
SEAL_IMPL = re.compile(rf"\bimpl\b(?:\s*<[^>]*>)?\s*[\w:<>, ]+?\s+for\s+{SEAL_PATH}")
SEAL_INHERENT = re.compile(rf"\bimpl\s+{SEAL_PATH}\s*\{{")
SEAL_DERIVE = re.compile(rf"#\[derive\(([^)]*)\)\]\s*pub\s+struct\s+{SEAL_NAME}\b")
SEAL_LITERAL = re.compile(rf"(?<!struct )\b{SEAL_NAME}\s*\(\s*\(\s*\)\s*\)")
FN_NAME = re.compile(r"\bfn\s+(\w+)")


def _forwards(members: list[str]) -> bool:
    return any(member == FEATURE or member.endswith(f"/{FEATURE}") for member in members)


def _closure(features: dict[str, list[str]], start: str) -> set[str]:
    """Return every local feature reachable from `start`, including `start`."""
    return default_closure({**features, "default": [start]}) - {"default"} | {start}


def _default_violations(name: str, features: dict[str, list[str]]) -> list[str]:
    reached = default_closure(features)
    if any(_forwards(features.get(feature, [])) for feature in reached):
        return [f"{name}: default feature enables {FEATURE}"]
    return []


def _forwarding_allowed(name: str, feature: str) -> bool:
    return name in ENABLING_MANIFESTS and feature != ADMISSION_FEATURE


def manifest_violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("Cargo.toml")):
        if not _kept(path, root):
            continue
        name = path.relative_to(root).as_posix()
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        features = manifest.get("features", {})
        found.extend(_default_violations(name, features))
        found.extend(
            f"{name}: feature {feature} forwards {FEATURE}"
            for feature, members in features.items()
            if _forwards(members) and not _forwarding_allowed(name, feature)
        )
        if ADMISSION_FEATURE in features:
            found.extend(
                f"{name}: feature {ADMISSION_FEATURE} reaches {FEATURE} through {feature}"
                for feature in sorted(_closure(features, ADMISSION_FEATURE) - {ADMISSION_FEATURE})
                if _forwards(features.get(feature, []))
            )
        if name in ENABLING_MANIFESTS:
            continue
        for section, dependencies in _deployable_tables(manifest):
            found.extend(
                f"{name}: [{section}] {dependency} enables {FEATURE}"
                for dependency, spec in dependencies.items()
                if isinstance(spec, dict) and FEATURE in spec.get("features", [])
            )
    return found


def _pos_core_leak(compact: str) -> bool:
    if not compact.startswith(("pos_core::", "::pos_core::")):
        return False
    return "*" in compact or SEAL_MODULE.search(compact) is not None


def _public_bodies(code: str, keyword: str) -> list[str]:
    """Return the brace-balanced bodies of every `pub trait` or `pub enum` in `code`."""
    bodies: list[str] = []
    for match in PUBLIC_BODY.finditer(code):
        if match.group(1) != keyword:
            continue
        depth = 1
        index = match.end()
        while index < len(code) and depth:
            depth += {"{": 1, "}": -1}.get(code[index], 0)
            index += 1
        bodies.append(code[match.end() : index])
    return bodies


def _leaks(name: str, code: str) -> list[str]:
    found: list[str] = []
    for statement in PUBLIC_USE.findall(code):
        compact = re.sub(r"\s+", "", statement)
        if CRATE_REEXPORT.search(compact):
            found.append(f"{name}: re-exports the pos_core crate")
        elif SEAL.search(statement) or _pos_core_leak(compact):
            found.append(f"{name}: re-exports the authority trust-root seal")
    enum_leak = any(SEAL.search(body) for body in _public_bodies(code, "enum"))
    if PUBLIC_ITEM.search(code) or enum_leak or ALIAS.search(code):
        found.append(f"{name}: exposes the authority trust-root seal from a public item")
    trait_leak = any(BODY_RETURN.search(body) for body in _public_bodies(code, "trait"))
    if SEAL_RETURN.search(code) or trait_leak:
        found.append(f"{name}: returns the authority trust-root seal from a public fn")
    return found


def _block_end(code: str, start: int) -> int:
    depth = 1
    index = start
    while index < len(code) and depth:
        depth += {"{": 1, "}": -1}.get(code[index], 0)
        index += 1
    return index


def _test_spans(code: str) -> list[tuple[int, int]]:
    """Return the spans of every inline `#[cfg(test)] mod name { ... }` in `code`."""
    return [
        (match.start(), _block_end(code, match.end()))
        for match in INLINE_TEST_MODULE.finditer(code)
    ]


def _module_files(path: Path, module: str) -> list[Path]:
    owns_directory = path.name in ("lib.rs", "main.rs", "mod.rs")
    directory = path.parent if owns_directory else path.with_suffix("")
    return [directory / f"{module}.rs", directory / module / "mod.rs"]


def _test_files(codes: dict[Path, str]) -> set[Path]:
    """Return the files of modules declared `#[cfg(test)] mod name;`, and their descendants."""
    pending = [
        candidate
        for path, code in codes.items()
        for match in OUTLINE_TEST_MODULE.finditer(code)
        for candidate in _module_files(path, match.group(1))
        if candidate in codes
    ]
    found: set[Path] = set()
    while pending:
        path = pending.pop()
        if path in found:
            continue
        found.add(path)
        pending.extend(
            candidate
            for match in OUTLINE_MODULE.finditer(codes[path])
            for candidate in _module_files(path, match.group(1))
            if candidate in codes
        )
    return found


def _without_tests(code: str) -> str:
    """Return `code` with every inline `#[cfg(test)]` module removed."""
    kept: list[str] = []
    position = 0
    for start, end in _test_spans(code):
        if start >= position:
            kept.append(code[position:start])
            position = end
    kept.append(code[position:])
    return "".join(kept)


def _mint_violations(name: str, mints: int) -> list[str]:
    expected = MINT_SITES.get(name, 0)
    if mints == expected:
        return []
    if not expected:
        return [f"{name}: mints the authority trust-root seal outside its pinned mint sites"]
    return [f"{name}: mints the authority trust-root seal {mints} times, expected {expected}"]


def _core_seal_violations(name: str, code: str) -> list[str]:
    code = _without_tests(code)
    found: list[str] = []
    if SEAL_IMPL.search(code):
        found.append(f"{name}: implements a trait for the authority trust-root seal")
    inherent = [
        FN_NAME.findall(code[match.end() : _block_end(code, match.end())])
        for match in SEAL_INHERENT.finditer(code)
    ]
    if name == CORE_SEAL_SOURCE and inherent != [["for_composition_root"]]:
        found.append(f"{name}: the seal's only constructor must be for_composition_root")
    elif name != CORE_SEAL_SOURCE and inherent:
        found.append(f"{name}: adds an inherent impl to the authority trust-root seal")
    derives = [match.group(1).replace(" ", "") for match in SEAL_DERIVE.finditer(code)]
    if name == CORE_SEAL_SOURCE and derives != ["Debug"]:
        found.append(f"{name}: the seal may derive only Debug")
    if SEAL_LITERAL.search(code):
        found.append(f"{name}: constructs the seal outside for_composition_root")
    return found


def source_violations(root: Path) -> list[str]:
    codes = {
        path: strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        for path in sorted(root.rglob("*.rs"))
        if _kept(path, root)
    }
    tests = _test_files(codes)
    found: list[str] = []
    for path, code in codes.items():
        relative = path.relative_to(root)
        name = relative.as_posix()
        test_only = path in tests or _in_crate_tests(relative, root)
        if name.startswith(CORE_SOURCES):
            if not test_only:
                found.extend(_core_seal_violations(name, code))
            continue
        if not test_only:
            found.extend(_mint_violations(name, len(MINT.findall(_without_tests(code)))))
        if not _in_crate_tests(relative, root):
            found.extend(_leaks(name, code))
    found.extend(
        f"{name}: pinned mint site is missing"
        for name in MINT_SITES
        if root / name not in codes
    )
    return found


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
    found = [
        *manifest_violations(root),
        *source_violations(root),
        *config_violations(root),
    ]
    if found:
        raise SystemExit("\n".join(found))
    print(f"{FEATURE} and its seal stay inside the trusted composition roots")


if __name__ == "__main__":
    main()
