#!/usr/bin/env python3
"""Adversarial tests for the authority trust-root seal policy checker (#1374)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_authority_trust_root_seal.py"
sys.path.insert(0, str(CHECKER.parent))
SPEC = importlib.util.spec_from_file_location("check_authority_trust_root_seal", CHECKER)
assert SPEC is not None and SPEC.loader is not None
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
ADMISSION_HOLDERS = POLICY.ADMISSION_HOLDERS
holder_violations = POLICY.holder_violations

ENABLING = 'pos-core = { path = "../pos-core", features = ["authority-trust-root"] }\n'
DEV_ONLY = "[dev-dependencies]\n" + ENABLING
MINT = "AuthorityTrustRootSealV1::for_composition_root();\n"
SEAL_USE = "let seal = pos_core::AuthorityTrustRootSealV1::for_composition_root();\n"

ALLOWED_MANIFESTS = {
    "apps/piglor-gateway/Cargo.toml": "[dependencies]\n" + ENABLING,
    "crates/pos-store/Cargo.toml": '[features]\nowner = ["pos-core/authority-trust-root"]\n'
    + "[target.'cfg(unix)'.dependencies]\n"
    + ENABLING,
    "apps/pos-experiment/Cargo.toml": "[features]\n"
    + 'test-support = ["pos-core?/authority-trust-root"]\n'
    + "[build-dependencies]\n"
    + ENABLING,
    "crates/pos-runtime/Cargo.toml": "[features]\n"
    + 'local-admission-host = ["pos-core/authority-trust-root"]\n'
    + DEV_ONLY,
    "crates/pos-state/Cargo.toml": DEV_ONLY,
    "crates/pos-core/Cargo.toml": "[features]\nauthority-trust-root = []\n",
}

DEPENDENCY = "enables authority-trust-root"
REEXPORT = "re-exports the authority trust-root seal"
CRATE = "re-exports the pos_core crate"
ITEM = "exposes the authority trust-root seal from a public item"
RETURNS = "returns the authority trust-root seal from a public fn"
CONFIG = "enables authority-trust-root outside a manifest"
DEFAULT = "default feature enables authority-trust-root"
FEATURES_FLAG = "cargo test -p pos-state --features pos-core/authority-trust-root\n"

REJECTED_MANIFESTS = {
    "dependency": ("apps/fixture/Cargo.toml", "[dependencies]\n" + ENABLING, DEPENDENCY),
    "build dependency": (
        "apps/fixture/Cargo.toml",
        "[build-dependencies]\n" + ENABLING,
        DEPENDENCY,
    ),
    "target dependency": (
        "apps/fixture/Cargo.toml",
        "[target.'cfg(unix)'.dependencies]\n" + ENABLING,
        DEPENDENCY,
    ),
    "runtime dependency": (
        "crates/pos-runtime/Cargo.toml",
        "[dependencies]\n" + ENABLING,
        DEPENDENCY,
    ),
    "workspace dependency": (
        "Cargo.toml",
        "[workspace.dependencies]\n"
        + 'pos-core = { path = "crates/pos-core", features = ["authority-trust-root"] }\n',
        DEPENDENCY,
    ),
    "forwarding feature": (
        "apps/fixture/Cargo.toml",
        '[features]\nroots = ["pos-core/authority-trust-root"]\n',
        "feature roots forwards authority-trust-root",
    ),
    "same-name forwarding feature": (
        "apps/fixture/Cargo.toml",
        '[features]\nauthority-trust-root = ["pos-core/authority-trust-root"]\n',
        "feature authority-trust-root forwards authority-trust-root",
    ),
    "runtime forwarding from another feature": (
        "crates/pos-runtime/Cargo.toml",
        '[features]\ntest-support = ["pos-core/authority-trust-root"]\n',
        "feature test-support forwards authority-trust-root",
    ),
    "core forwarding feature": (
        "crates/pos-core/Cargo.toml",
        '[features]\ntest-support = ["authority-trust-root"]\nauthority-trust-root = []\n',
        "feature test-support forwards authority-trust-root",
    ),
    "core default feature": (
        "crates/pos-core/Cargo.toml",
        '[features]\ndefault = ["authority-trust-root"]\nauthority-trust-root = []\n',
        DEFAULT,
    ),
    "allowed crate default feature": (
        "crates/pos-store/Cargo.toml",
        '[features]\ndefault = ["owner"]\nowner = ["pos-core/authority-trust-root"]\n',
        DEFAULT,
    ),
    "runtime default feature": (
        "crates/pos-runtime/Cargo.toml",
        '[features]\ndefault = ["local-admission-host"]\n'
        + 'local-admission-host = ["pos-core/authority-trust-root"]\n',
        DEFAULT,
    ),
}

ALLOWED_SOURCES = {
    "apps/piglor-gateway/src/local_principal.rs": "const SEAL: AuthorityTrustRootSealV1 = " + MINT,
    "crates/pos-store/src/community/owner.rs": "pub(crate) fn seal() "
    + "-> AuthorityTrustRootSealV1 {\n"
    + "pub fn install(seal: &AuthorityTrustRootSealV1) -> u8 {\n"
    + "pub trait Installer {\n    fn install(&self, seal: &AuthorityTrustRootSealV1) -> u8;\n}\n",
    "crates/pos-store/src/lib.rs": "pub use pos_core::{CoreError, Seq};\n"
    + "use pos_core::AuthorityTrustRootSealV1;\n"
    + "pub(crate) use pos_core as core_api;\n"
    + "pub use pos_core::authority_persistence::AuthorityViewV1;\n"
    + "pub(super) const SEAL: AuthorityTrustRootSealV1 = "
    + MINT,
    "crates/pos-state/src/lib.rs": SEAL_USE + "// pub use pos_core::AuthorityTrustRootSealV1;\n",
    "crates/pos-core/src/authority.rs": "pub struct AuthorityTrustRootSealV1(());\n"
    + "pub const fn for_composition_root() -> AuthorityTrustRootSealV1 {\n",
    "crates/pos-core/src/lib.rs": "pub use authority::AuthorityTrustRootSealV1;\n",
    "crates/pos-state/tests/support/mod.rs": "pub fn seal() "
    + "-> pos_core::AuthorityTrustRootSealV1 {\n"
    + "pub use pos_core::AuthorityTrustRootSealV1;\n",
}

CRATE_MANIFEST = {"crates/pos-state/Cargo.toml": DEV_ONLY}

REJECTED_SOURCES = {
    "re-export": (
        "crates/pos-state/src/lib.rs",
        "pub use pos_core::{\n    CoreError,\n    AuthorityTrustRootSealV1 as Seal,\n};\n",
        REEXPORT,
    ),
    "allowed crate re-export": (
        "crates/pos-store/src/lib.rs",
        "pub use pos_core::AuthorityTrustRootSealV1;\n",
        REEXPORT,
    ),
    "glob re-export": ("crates/pos-state/src/lib.rs", "pub use pos_core::*;\n", REEXPORT),
    "module glob re-export": (
        "crates/pos-state/src/lib.rs",
        "pub use pos_core::authority::*;\n",
        REEXPORT,
    ),
    "nested glob re-export": (
        "crates/pos-state/src/lib.rs",
        "pub use pos_core::{\n    Seq,\n    authority::*,\n};\n",
        REEXPORT,
    ),
    "module re-export": (
        "crates/pos-state/src/lib.rs",
        "pub use pos_core::authority as auth;\n",
        REEXPORT,
    ),
    "module self re-export": (
        "crates/pos-state/src/lib.rs",
        "pub use pos_core::authority::{self, AuthorityViewV1};\n",
        REEXPORT,
    ),
    "renamed crate re-export": ("crates/pos-state/src/lib.rs", "pub use pos_core as api;\n", CRATE),
    "crate re-export": ("crates/pos-state/src/lib.rs", "pub use ::pos_core;\n", CRATE),
    "self re-export": (
        "crates/pos-state/src/lib.rs",
        "pub use pos_core::{self as api, Seq};\n",
        CRATE,
    ),
    "src/tests directory": (
        "crates/pos-state/src/tests/mod.rs",
        "pub use pos_core::AuthorityTrustRootSealV1;\n",
        REEXPORT,
    ),
    "tests directory outside a crate": (
        "tools/tests/seal.rs",
        "pub use pos_core::AuthorityTrustRootSealV1;\n",
        REEXPORT,
    ),
    "public type alias": (
        "crates/pos-state/src/lib.rs",
        "pub type Seal = pos_core::AuthorityTrustRootSealV1;\n",
        ITEM,
    ),
    "public static": (
        "apps/piglor-gateway/src/lib.rs",
        "pub static SEAL: AuthorityTrustRootSealV1 = " + MINT,
        ITEM,
    ),
    "public const": (
        "crates/pos-store/src/lib.rs",
        "pub const SEAL: AuthorityTrustRootSealV1 = " + MINT,
        ITEM,
    ),
    "public tuple struct": (
        "crates/pos-state/src/lib.rs",
        "pub struct Holder(pub AuthorityTrustRootSealV1);\n",
        ITEM,
    ),
    "public enum": (
        "crates/pos-state/src/lib.rs",
        "pub enum Minted { Seal(AuthorityTrustRootSealV1) }\n",
        ITEM,
    ),
    "public enum variant line": (
        "crates/pos-state/src/lib.rs",
        "pub enum Minted {\n    Empty,\n    Seal(AuthorityTrustRootSealV1),\n}\n",
        ITEM,
    ),
    "public enum after a struct-like variant": (
        "crates/pos-state/src/lib.rs",
        "pub enum Minted { Empty { x: u8 }, Seal(AuthorityTrustRootSealV1) }\n",
        ITEM,
    ),
    "public trait method after a default body": (
        "crates/pos-state/src/lib.rs",
        "pub trait Minter {\n    fn a(&self) { }\n"
        + "    fn seal(&self) -> AuthorityTrustRootSealV1;\n}\n",
        RETURNS,
    ),
    "private type alias": (
        "crates/pos-store/src/lib.rs",
        "type Root = pos_core::AuthorityTrustRootSealV1;\npub fn root() -> Root {\n",
        ITEM,
    ),
    "crate type alias": (
        "crates/pos-state/src/lib.rs",
        "pub(crate) type Root<'a> = &'a AuthorityTrustRootSealV1;\n",
        ITEM,
    ),
    "public trait method": (
        "crates/pos-state/src/lib.rs",
        "pub trait Minter {\n    fn seal(&self) -> AuthorityTrustRootSealV1;\n}\n",
        RETURNS,
    ),
    "public field": (
        "apps/pos-experiment/src/lib.rs",
        "pub(crate) struct Holder {\n    pub seal: AuthorityTrustRootSealV1,\n}\n",
        ITEM,
    ),
    "public fn": (
        "crates/pos-runtime/src/scheduled_admission_host/local.rs",
        "pub const fn seal() -> pos_core::AuthorityTrustRootSealV1 {\n",
        RETURNS,
    ),
    "workflow": (".github/workflows/ci.yml", "run: " + FEATURES_FLAG, CONFIG),
    "Dockerfile": ("docker/Dockerfile", "RUN " + FEATURES_FLAG, CONFIG),
    "cargo config": (
        ".cargo/config.toml",
        '[alias]\nt = "test --features pos-core/authority-trust-root"\n',
        CONFIG,
    ),
}


def invoke(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def with_files(files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        ignored = {
            "target/debug/Cargo.toml": "[dependencies]\n" + ENABLING,
            "target/debug/build.rs": "pub use pos_core::AuthorityTrustRootSealV1;\n",
        }
        for relative, text in {**ignored, **files}.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return invoke(root)


def expect_rejected(case: str, result: subprocess.CompletedProcess[str], reason: str) -> None:
    if result.returncode == 0:
        raise SystemExit(f"checker accepted {case}")
    if reason not in result.stderr:
        raise SystemExit(f"checker rejected {case} without {reason!r}:\n{result.stderr}")


def main() -> None:
    repository = invoke(ROOT)
    if repository.returncode != 0:
        raise SystemExit(f"repository violates policy:\n{repository.stderr}")
    allowed = with_files({**ALLOWED_MANIFESTS, **ALLOWED_SOURCES})
    if allowed.returncode != 0:
        raise SystemExit(f"checker rejected an allowed use:\n{allowed.stderr}")
    for case, (relative, text, reason) in REJECTED_MANIFESTS.items():
        result = with_files({relative: text})
        expect_rejected(f"a {case} enabling the trust-root feature", result, reason)
    for case, (relative, text, reason) in REJECTED_SOURCES.items():
        result = with_files({**CRATE_MANIFEST, relative: text})
        expect_rejected(f"the seal in a {case}", result, reason)
    if holder_violations(tuple(reversed(ADMISSION_HOLDERS))):
        raise SystemExit("checker rejected the pinned local-admission-host holders")
    for widened in (
        (*ADMISSION_HOLDERS, "apps/fixture/Cargo.toml"),
        ADMISSION_HOLDERS[:1],
    ):
        if not holder_violations(widened):
            raise SystemExit(f"checker accepted local-admission-host holders {widened}")


if __name__ == "__main__":
    main()
