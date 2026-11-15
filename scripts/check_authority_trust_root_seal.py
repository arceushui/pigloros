#!/usr/bin/env python3
"""Keep the ADR-129 A5.9 authority trust-root seal inside the trusted composition roots (#1374).

`pos_core::AuthorityTrustRootSealV1` builds the `AuthenticatedPrincipalResultV1` and
`AuthorityRegistrySnapshotV1` values the authority evaluator trusts, and the metadata authority
installed by `pos_store::community::CommunityMetadataAuthorityV1::new`. Its constructor exists
only with `pos-core`'s `authority-trust-root` feature, so:

- only `apps/piglor-gateway`, `crates/pos-store` and `apps/pos-experiment` may enable
  `authority-trust-root` in a deployable dependency table or forward it from a feature;
  `crates/pos-runtime` may forward it only from its `local-admission-host` feature; every
  manifest may enable it from `[dev-dependencies]`;
- `local-admission-host` therefore carries the seal minter to every crate that enables it.
  `scripts/check_fixture_instant_confinement.py` (rule 5) confines its deployable enablers to
  `apps/pos-experiment` and `apps/pos-plugin-conformance-adapter`, plus features named
  `test-support` (which `scripts/check_test_support_features.py` keeps out of deployable graphs).
  This checker pins that list: it fails if the other checker's list changes, so widening it is
  also a change to this seal's boundary. The adapter compiles the minter through `pos-runtime`
  and never calls it; the source rules below apply to it;
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
from check_fixture_instant_confinement import ADMISSION_MANIFESTS
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
TRAIT_RETURN = re.compile(
    rf"\bpub\s+trait\b[^{{]*\{{[^}}]*?\bfn\b[^{{;]*?->[^{{;]*\b{SEAL_NAME}\b"
)
ENUM_BODY = re.compile(rf"\bpub\s+enum\b[^{{]*\{{[^}}]*\b{SEAL_NAME}\b")
ALIAS = re.compile(rf"\btype\s+\w+(?:<[^>]*>)?\s*=[^;]*\b{SEAL_NAME}\b")
ADMISSION_HOLDERS = (
    "apps/pos-experiment/Cargo.toml",
    "apps/pos-plugin-conformance-adapter/Cargo.toml",
)
ENABLING_MANIFESTS = (
    "apps/piglor-gateway/Cargo.toml",
    "crates/pos-store/Cargo.toml",
    "apps/pos-experiment/Cargo.toml",
)
FORWARDING_FEATURES = {"crates/pos-runtime/Cargo.toml": "local-admission-host"}
CORE_SOURCES = "crates/pos-core/"


def _forwards(members: list[str]) -> bool:
    return any(member == FEATURE or member.endswith(f"/{FEATURE}") for member in members)


def _default_violations(name: str, features: dict[str, list[str]]) -> list[str]:
    reached = default_closure(features)
    if any(_forwards(features.get(feature, [])) for feature in reached):
        return [f"{name}: default feature enables {FEATURE}"]
    return []


def _forwarding_allowed(name: str, feature: str) -> bool:
    return name in ENABLING_MANIFESTS or FORWARDING_FEATURES.get(name) == feature


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


def _leaks(name: str, code: str) -> list[str]:
    found: list[str] = []
    for statement in PUBLIC_USE.findall(code):
        compact = re.sub(r"\s+", "", statement)
        if CRATE_REEXPORT.search(compact):
            found.append(f"{name}: re-exports the pos_core crate")
        elif SEAL.search(statement) or _pos_core_leak(compact):
            found.append(f"{name}: re-exports the authority trust-root seal")
    if PUBLIC_ITEM.search(code) or ENUM_BODY.search(code) or ALIAS.search(code):
        found.append(f"{name}: exposes the authority trust-root seal from a public item")
    if SEAL_RETURN.search(code) or TRAIT_RETURN.search(code):
        found.append(f"{name}: returns the authority trust-root seal from a public fn")
    return found


def source_violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        if not _kept(path, root):
            continue
        relative = path.relative_to(root)
        name = relative.as_posix()
        if name.startswith(CORE_SOURCES) or _in_crate_tests(relative, root):
            continue
        code = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        found.extend(_leaks(name, code))
    return found


def holder_violations(admission_manifests: tuple[str, ...]) -> list[str]:
    if tuple(sorted(admission_manifests)) == tuple(sorted(ADMISSION_HOLDERS)):
        return []
    return [
        "scripts/check_fixture_instant_confinement.py: local-admission-host enablers "
        f"{sorted(admission_manifests)} differ from the seal's pinned holders "
        f"{sorted(ADMISSION_HOLDERS)}"
    ]


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
        *holder_violations(ADMISSION_MANIFESTS),
        *manifest_violations(root),
        *source_violations(root),
        *config_violations(root),
    ]
    if found:
        raise SystemExit("\n".join(found))
    print(f"{FEATURE} and its seal stay inside the trusted composition roots")


if __name__ == "__main__":
    main()
