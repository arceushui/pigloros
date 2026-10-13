#!/usr/bin/env python3
"""Confine the fixture evaluation instant and the local admission host (ADR-061 revision 8).

ADR-061 revision 8 decision 4 lists both policies as confinement rules (1) to (5) of this one
script, so the script keeps the fixture-instant name the ADR gives it.

`pos_core::trusted_clock::FixtureWallSourceV1` returns one fixture-supplied instant to the
Plugin trust paths (`PluginTrustWallSourceV1`). It and `FixtureEvaluationInstantV1` exist only
with `pos-core`'s non-default `fixture-instant` feature. Because CI builds with `--all-features`
the types are compiled everywhere in CI, so this checker is the control. It requires:

1. `fixture-instant` is enabled only in `[dependencies]` of
   `apps/pos-plugin-conformance-adapter`, and a feature forwards it (`crate/fixture-instant`,
   `crate?/fixture-instant`) only when the forwarding feature has the same name. Rule 1 is what
   confines the enablers: a same-name forwarding feature is accepted only in the adapter
   manifest, because forwarding enables the feature in the dependency.
2. `fixture-instant` is not reachable from a `default` feature closure, and no `default` feature
   forwards it.
3. `FixtureWallSourceV1` and `FixtureEvaluationInstantV1` occur (comments ignored) in no `.rs`
   file outside `crates/pos-core/src/trusted_clock.rs`, `crates/pos-core/tests/` and the adapter
   crate (`src` and `tests`). `crates/pos-core/src/lib.rs` re-exports neither type, by name or by
   a glob over `trusted_clock`: callers write `pos_core::trusted_clock::...`.
4. No other manifest depends on the adapter, except `apps/pos-plugin-worker` as a
   `[dev-dependencies]` entry (the worker tests reach the fixture instant only through the
   adapter library and name neither type).
5. `local-admission-host` is enabled only by `apps/pos-experiment`, the adapter and a feature
   named `test-support` that forwards it.

Rules 1 and 3 have a real subject since the adapter exists (S2, #615); rule 4 stays vacuous on the
real tree until the worker dev-dependency of S3b1 (#617). The companion test script exercises all
of them with synthetic manifests and sources. The adapter is not named in
`[workspace.dependencies]` (S2 decided: path dependencies only), so such an entry is rejected like
any other dependent. Rule 5 accepts any
feature named `test-support` that forwards `local-admission-host`, in any crate (the pinned
behaviour of `pos-runtime`'s own `test-support`), and only that.

Stated limits: the check is textual. It does not look at build configuration outside manifests
(workflows, Dockerfiles, `.cargo/config*`, shell scripts); the only release build selects the one
package `piglor-gateway`, whose graph never reaches the adapter.
"""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

from check_test_support_features import default_closure
from check_trusted_clock_port_impls import SKIPPED_PARTS, strip_comments

FIXTURE_FEATURE = "fixture-instant"
ADMISSION_FEATURE = "local-admission-host"
ADAPTER_NAME = "pos-plugin-conformance-adapter"
ADAPTER_DIR = f"apps/{ADAPTER_NAME}"
ADAPTER_MANIFEST = f"{ADAPTER_DIR}/Cargo.toml"
WORKER_MANIFEST = "apps/pos-plugin-worker/Cargo.toml"
ADMISSION_MANIFESTS = ("apps/pos-experiment/Cargo.toml", ADAPTER_MANIFEST)
ALLOWED_SOURCES = (
    "crates/pos-core/src/trusted_clock.rs",
    "crates/pos-core/tests/",
    f"{ADAPTER_DIR}/src/",
    f"{ADAPTER_DIR}/tests/",
)
CORE_LIB = "crates/pos-core/src/lib.rs"
FIXTURE_TYPES = re.compile(r"\b(?:FixtureWallSourceV1|FixtureEvaluationInstantV1)\b")
GLOB_REEXPORT = re.compile(
    r"\bpub\s+use\s+(?:(?:crate|self)\s*::\s*)?trusted_clock\s*::\s*(?:\*|\{[^;]*\*)"
)
SECTIONS = ("dependencies", "build-dependencies", "dev-dependencies")


def _kept(path: Path, root: Path) -> bool:
    return not SKIPPED_PARTS.intersection(path.relative_to(root).parts[:1])


def _tables(manifest: dict) -> list[tuple[str, str, dict]]:
    """Every dependency table as (label, section, table)."""
    tables = [(section, section, manifest.get(section, {})) for section in SECTIONS]
    for target, target_tables in manifest.get("target", {}).items():
        tables.extend(
            (f"target.{target}.{section}", section, target_tables.get(section, {}))
            for section in SECTIONS
        )
    workspace = manifest.get("workspace", {}).get("dependencies", {})
    tables.append(("workspace.dependencies", "workspace.dependencies", workspace))
    return tables


def _enables(spec: object, feature: str) -> bool:
    return isinstance(spec, dict) and feature in spec.get("features", [])


def _forwards(member: str, feature: str) -> bool:
    return member.endswith(f"/{feature}")


def _manifests(root: Path) -> list[tuple[str, dict]]:
    return [
        (path.relative_to(root).as_posix(), tomllib.loads(path.read_text(encoding="utf-8")))
        for path in sorted(root.rglob("Cargo.toml"))
        if _kept(path, root)
    ]


def _fixture_enablers(name: str, manifest: dict) -> list[str]:
    found: list[str] = []
    for label, _, dependencies in _tables(manifest):
        allowed = name == ADAPTER_MANIFEST and label == "dependencies"
        found.extend(
            f"{name}: [{label}] {dependency} enables {FIXTURE_FEATURE}"
            for dependency, spec in dependencies.items()
            if _enables(spec, FIXTURE_FEATURE) and not allowed
        )
    return found


def _fixture_forwards(name: str, manifest: dict) -> list[str]:
    return [
        f"{name}: feature {feature} forwards {FIXTURE_FEATURE}"
        for feature, members in manifest.get("features", {}).items()
        if not (feature == FIXTURE_FEATURE and name == ADAPTER_MANIFEST)
        and any(_forwards(m, FIXTURE_FEATURE) for m in members)
    ]


def _default_reach(name: str, manifest: dict) -> list[str]:
    features = manifest.get("features", {})
    reached = default_closure(features)
    found = []
    if FIXTURE_FEATURE in reached:
        found.append(f"{name}: default feature enables {FIXTURE_FEATURE}")
    if any(_forwards(m, FIXTURE_FEATURE) for f in reached for m in features.get(f, [])):
        found.append(f"{name}: default feature forwards {FIXTURE_FEATURE}")
    return found


def _names_adapter(dependency: str, spec: object) -> bool:
    if dependency == ADAPTER_NAME:
        return True
    if not isinstance(spec, dict):
        return False
    return spec.get("package") == ADAPTER_NAME or ADAPTER_NAME in str(spec.get("path", ""))


def _adapter_dependents(name: str, manifest: dict) -> list[str]:
    found: list[str] = []
    for label, section, dependencies in _tables(manifest):
        allowed = name == WORKER_MANIFEST and section == "dev-dependencies"
        found.extend(
            f"{name}: [{label}] {dependency} depends on the conformance adapter"
            for dependency, spec in dependencies.items()
            if _names_adapter(dependency, spec) and not allowed
        )
    return found


def _admission_enablers(name: str, manifest: dict) -> list[str]:
    if name in ADMISSION_MANIFESTS:
        return []
    found = [
        f"{name}: [{label}] {dependency} enables {ADMISSION_FEATURE}"
        for label, _, dependencies in _tables(manifest)
        for dependency, spec in dependencies.items()
        if _enables(spec, ADMISSION_FEATURE)
    ]
    found.extend(
        f"{name}: feature {feature} forwards {ADMISSION_FEATURE}"
        for feature, members in manifest.get("features", {}).items()
        if feature not in ("test-support", ADMISSION_FEATURE)
        and any(m == ADMISSION_FEATURE or _forwards(m, ADMISSION_FEATURE) for m in members)
    )
    return found


def manifest_violations(root: Path) -> list[str]:
    found: list[str] = []
    for name, manifest in _manifests(root):
        if name != ADAPTER_MANIFEST:
            found.extend(_adapter_dependents(name, manifest))
        found.extend(_fixture_enablers(name, manifest))
        found.extend(_fixture_forwards(name, manifest))
        found.extend(_default_reach(name, manifest))
        found.extend(_admission_enablers(name, manifest))
    return found


def _source_violations(name: str, code: str) -> list[str]:
    found: list[str] = []
    if FIXTURE_TYPES.search(code) and not name.startswith(ALLOWED_SOURCES):
        found.append(f"{name}: names the fixture evaluation instant types outside their owners")
    if name == CORE_LIB and GLOB_REEXPORT.search(code):
        found.append(f"{name}: glob re-exports trusted_clock")
    return found


def source_violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        if _kept(path, root):
            code = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
            found.extend(_source_violations(path.relative_to(root).as_posix(), code))
    return found


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    found = manifest_violations(root) + source_violations(root)
    if found:
        raise SystemExit("\n".join(found))
    print(f"{FIXTURE_FEATURE} and its types stay inside the Plugin-conformance adapter")


if __name__ == "__main__":
    main()
