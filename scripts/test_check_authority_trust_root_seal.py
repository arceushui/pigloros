#!/usr/bin/env python3
"""Adversarial tests for the authority trust-root seal policy checker (#1374)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_authority_trust_root_seal.py"

ENABLING = 'pos-core = { path = "../pos-core", features = ["authority-trust-root"] }\n'
DEV_ONLY = "[dev-dependencies]\n" + ENABLING
MINT = "AuthorityTrustRootSealV1::for_composition_root();\n"
SEAL_USE = "let seal = pos_core::AuthorityTrustRootSealV1::for_composition_root();\n"

ALLOWED_MANIFESTS = {
    "apps/piglor-gateway/Cargo.toml": '[features]\nowner = ["pos-core/authority-trust-root"]\n'
    + "[target.'cfg(unix)'.dependencies]\n"
    + ENABLING,
    "crates/pos-store/Cargo.toml": DEV_ONLY,
    "apps/pos-experiment/Cargo.toml": "[features]\n"
    + 'test-support = ["pos-core?/authority-trust-root"]\n'
    + "[build-dependencies]\n"
    + ENABLING,
    "crates/pos-runtime/Cargo.toml": "[features]\nlocal-admission-host = []\n" + DEV_ONLY,
    "apps/pos-plugin-conformance-adapter/Cargo.toml": "[dependencies]\n" + ENABLING,
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
PINNED = "mints the authority trust-root seal outside its pinned mint sites"
NON_LITERAL = "pulls in a file by a non-literal path"
MINT_SITE_FILES = (
    "apps/piglor-gateway/src/local_principal.rs",
    "apps/pos-experiment/src/lib.rs",
    "apps/pos-plugin-conformance-adapter/src/main.rs",
)
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
    "runtime local admission host forwarding": (
        "crates/pos-runtime/Cargo.toml",
        '[features]\nlocal-admission-host = ["pos-core/authority-trust-root"]\n',
        "feature local-admission-host forwards authority-trust-root",
    ),
    "allowed crate local admission host forwarding": (
        "apps/pos-experiment/Cargo.toml",
        '[features]\nlocal-admission-host = ["pos-core?/authority-trust-root"]\n',
        "feature local-admission-host forwards authority-trust-root",
    ),
    "adapter forwarding from local admission host": (
        "apps/pos-plugin-conformance-adapter/Cargo.toml",
        '[features]\nlocal-admission-host = ["pos-runtime/local-admission-host", '
        + '"pos-core/authority-trust-root"]\n',
        "feature local-admission-host forwards authority-trust-root",
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
    "store dependency": (
        "crates/pos-store/Cargo.toml",
        "[dependencies]\n" + ENABLING,
        DEPENDENCY,
    ),
    "store target dependency": (
        "crates/pos-store/Cargo.toml",
        "[target.'cfg(target_os = \"linux\")'.dependencies]\n" + ENABLING,
        DEPENDENCY,
    ),
    "store forwarding feature": (
        "crates/pos-store/Cargo.toml",
        '[features]\nowner = ["pos-core/authority-trust-root"]\n',
        "feature owner forwards authority-trust-root",
    ),
    "store default feature": (
        "crates/pos-store/Cargo.toml",
        '[features]\ndefault = ["owner"]\nowner = ["pos-core/authority-trust-root"]\n',
        DEFAULT,
    ),
    "indirect local admission host forwarding": (
        "apps/pos-experiment/Cargo.toml",
        '[features]\nlocal-admission-host = ["roots"]\nroots = ["pos-core/authority-trust-root"]\n',
        "feature local-admission-host reaches authority-trust-root through roots",
    ),
    "allowed crate default feature": (
        "apps/piglor-gateway/Cargo.toml",
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

CORE_SEAL = (
    "#[derive(Debug)]\n#[must_use]\npub struct AuthorityTrustRootSealV1(());\n"
    + "impl AuthorityTrustRootSealV1 {\n"
    + "    pub const fn for_composition_root() -> Self {\n        Self(())\n    }\n}\n"
)
TEST_MODULE = "#[cfg(test)]\n#[cfg_attr(coverage_nightly, coverage(off))]\nmod tests {\n"

ALLOWED_SOURCES = {
    "apps/piglor-gateway/src/local_principal.rs": "static SEAL: AuthorityTrustRootSealV1 = "
    + MINT
    + TEST_MODULE
    + "    fn helper() {\n        "
    + SEAL_USE
    + "    }\n}\n",
    "apps/piglor-gateway/src/lib.rs": "#[cfg(test)]\n#[cfg_attr(coverage_nightly, coverage(off))]\n"
    + "mod e2e;\nmod local_principal;\n",
    "apps/piglor-gateway/src/e2e.rs": "mod child;\n" + SEAL_USE,
    "apps/piglor-gateway/src/e2e/child.rs": SEAL_USE,
    "apps/pos-experiment/src/lib.rs": "use pos_core::AuthorityTrustRootSealV1;\n"
    + "static AUTHORITY_TRUST_ROOT: AuthorityTrustRootSealV1 = "
    + MINT,
    "apps/pos-plugin-conformance-adapter/src/main.rs": "static ROOT: AuthorityTrustRootSealV1 = "
    + MINT,
    "apps/pos-plugin-conformance-adapter/src/runner/tests.rs": SEAL_USE,
    "apps/pos-plugin-conformance-adapter/src/generated.rs": "include!(concat!("
    + 'env!("OUT_DIR"), "/g.rs"));\n'
    + 'const SCHEMA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/s.bin"));\n',
    "apps/pos-plugin-conformance-adapter/build.rs": "fn main() {\n"
    + '    println!("cargo:rerun-if-changed=x");\n}\n',
    "apps/pos-plugin-conformance-adapter/src/runner.rs": "#[cfg(test)]\nmod tests;\n"
    + "pub fn open(seal: &'static AuthorityTrustRootSealV1) {}\n",
    "crates/pos-store/src/community/attestation.rs": "pub(super) fn snapshot("
    + "seal: &AuthorityTrustRootSealV1) {}\n",
    "crates/pos-store/src/community/owner.rs": "pub(crate) fn seal() "
    + "-> AuthorityTrustRootSealV1 {\n"
    + "pub fn install(seal: &AuthorityTrustRootSealV1) -> u8 {\n"
    + "pub trait Installer {\n    fn install(&self, seal: &AuthorityTrustRootSealV1) -> u8;\n}\n",
    "crates/pos-store/src/lib.rs": "pub use pos_core::{CoreError, Seq};\n"
    + "use pos_core::AuthorityTrustRootSealV1;\n"
    + "pub(crate) use pos_core as core_api;\n"
    + "pub use pos_core::authority_persistence::AuthorityViewV1;\n",
    "crates/pos-state/src/lib.rs": TEST_MODULE
    + '    const CLOSE: &str = "}";\n'
    + '    include!("generated.rs",);\n'
    + "    "
    + SEAL_USE
    + "}\n// pub use pos_core::AuthorityTrustRootSealV1;\n// "
    + SEAL_USE
    + "/* outer /* inner */ still a comment: "
    + SEAL_USE
    + " */\n",
    "crates/pos-core/src/authority.rs": CORE_SEAL
    + TEST_MODULE
    + "    impl Clone for super::AuthorityTrustRootSealV1 {}\n}\n",
    "crates/pos-core/src/lib.rs": "pub use authority::AuthorityTrustRootSealV1;\n",
    "crates/pos-core/tests/authority_public.rs": "fn forge() -> AuthorityTrustRootSealV1 {\n"
    + "    AuthorityTrustRootSealV1(())\n}\n",
    "crates/pos-state/tests/support/mod.rs": "pub fn seal() "
    + "-> pos_core::AuthorityTrustRootSealV1 {\n"
    + "pub use pos_core::AuthorityTrustRootSealV1;\n"
    + SEAL_USE,
}


CRATE_MANIFEST = {"crates/pos-state/Cargo.toml": DEV_ONLY}

TEST_ONLY_E2E = {
    "apps/piglor-gateway/src/lib.rs": "#[cfg(test)]\nmod e2e;\n",
    "apps/piglor-gateway/src/e2e.rs": SEAL_USE,
}
REJECTED_LAYOUTS = {
    "a test-only file pulled into non-test code by include!": {
        **TEST_ONLY_E2E,
        "apps/piglor-gateway/src/http.rs": 'include!("e2e.rs");\n',
    },
    "a test-only file pulled into non-test code by #[path]": {
        **TEST_ONLY_E2E,
        "apps/piglor-gateway/src/http.rs": '#[path = "e2e.rs"]\nmod real;\n',
    },
    "a test-only file pulled in transitively": {
        **TEST_ONLY_E2E,
        "apps/piglor-gateway/src/lib.rs": "#[cfg(test)]\nmod e2e;\n#[cfg(test)]\nmod mid;\n",
        "apps/piglor-gateway/src/mid.rs": 'include!("e2e.rs");\n',
        "apps/piglor-gateway/src/http.rs": 'include!("mid.rs");\n',
    },
}
REJECTED_REFERENCES = {
    "a tests-directory file included from src": (
        {
            "apps/piglor-gateway/tests/support/seal.rs": SEAL_USE,
            "apps/piglor-gateway/src/http.rs": 'include!("../tests/support/seal.rs");\n',
        },
        "apps/piglor-gateway/tests/support/seal.rs: " + PINNED,
    ),
    "a file outside the repository included from src": (
        {"apps/piglor-gateway/src/http.rs": 'include!("/etc/passwd");\n'},
        "apps/piglor-gateway/src/http.rs: includes /etc/passwd",
    ),
    "an include hidden after a brace in a test-module literal": (
        {
            "apps/piglor-gateway/src/seal.in": SEAL_USE,
            "apps/piglor-gateway/src/http.rs": TEST_MODULE
            + '    const OPEN: &str = "{";\n}\n'
            + 'include!("seal.in");\n',
        },
        "apps/piglor-gateway/src/seal.in: " + PINNED,
    ),
    "a crate-directory include": (
        {
            "apps/piglor-gateway/Cargo.toml": "[package]\nname = \"gateway\"\n",
            "apps/piglor-gateway/tests/support/seal.rs": SEAL_USE,
            "apps/piglor-gateway/src/http.rs": 'include!(concat!(env!("CARGO_MANIFEST_DIR"), '
            + '"/tests/support/seal.rs"));\n',
        },
        "apps/piglor-gateway/tests/support/seal.rs: " + PINNED,
    ),
    "a file pulled into a build script": (
        {
            "apps/piglor-gateway/build.rs": '#[path = "src/emit.rs"]\nmod emit;\nfn main() {}\n',
            "apps/piglor-gateway/src/emit.rs": 'const S: &str = "AuthorityTrustRootSealV1";\n',
        },
        "apps/piglor-gateway/src/emit.rs: build code names the seal",
    ),
    "a non-Rust file included from src": (
        {
            "apps/piglor-gateway/src/seal.in": SEAL_USE,
            "apps/piglor-gateway/src/http.rs": 'include!("seal.in");\n',
        },
        "apps/piglor-gateway/src/seal.in: " + PINNED,
    ),
}

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
    "second adapter mint": (
        "apps/pos-plugin-conformance-adapter/src/main.rs",
        "static ROOT: AuthorityTrustRootSealV1 = " + MINT + SEAL_USE,
        "mints the authority trust-root seal 2 times, expected 1",
    ),
    "adapter library mint": ("apps/pos-plugin-conformance-adapter/src/lib.rs", SEAL_USE, PINNED),
    "runtime source mint": (
        "crates/pos-runtime/src/scheduled_admission_host/local.rs",
        SEAL_USE,
        PINNED,
    ),
    "non-enabling crate mint": ("plugins/agent/src/provider_driver.rs", SEAL_USE, PINNED),
    "store mint at the former owner site": (
        "crates/pos-store/src/community/attestation.rs",
        "static OWNER_SEAL: AuthorityTrustRootSealV1 = " + MINT,
        PINNED,
    ),
    "store mint outside its pinned site": (
        "crates/pos-store/src/community/lifecycle_authority.rs",
        SEAL_USE,
        PINNED,
    ),
    "unpinned enabling crate mint": ("apps/piglor-gateway/src/http.rs", SEAL_USE, PINNED),
    "mint in a test-named module without cfg(test)": (
        "crates/pos-state/src/lib.rs",
        "mod tests {\n    " + SEAL_USE + "}\n",
        PINNED,
    ),
    "mint in a cfg(all(test, ..)) module": (
        "crates/pos-state/src/lib.rs",
        "#[cfg(all(test, unix))]\nmod tests {\n    " + SEAL_USE + "}\n",
        PINNED,
    ),
    "mint in a module declared without cfg(test)": (
        "crates/pos-state/src/tests.rs",
        SEAL_USE,
        PINNED,
    ),
    "trait impl on the seal": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL + "impl Default for AuthorityTrustRootSealV1 {\n",
        "implements a trait for the authority trust-root seal",
    ),
    "generic From impl on the seal": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL + "impl<T> From<T> for crate::AuthorityTrustRootSealV1 {\n",
        "implements a trait for the authority trust-root seal",
    ),
    "second core constructor": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL.replace(
            "    pub const fn",
            "    pub fn forge() -> Self {\n        Self(())\n    }\n    pub const fn",
        ),
        "the seal's only constructor must be for_composition_root",
    ),
    "second inherent impl": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL + "impl AuthorityTrustRootSealV1 {\n    fn forge() {}\n}\n",
        "the seal's only constructor must be for_composition_root",
    ),
    "missing core constructor": (
        "crates/pos-core/src/authority.rs",
        "#[derive(Debug)]\npub struct AuthorityTrustRootSealV1(());\n",
        "the seal's only constructor must be for_composition_root",
    ),
    "cloneable seal": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL.replace("derive(Debug)", "derive(Clone, Debug)"),
        "the seal may derive only Debug",
    ),
    "inherent impl elsewhere in core": (
        "crates/pos-core/src/store.rs",
        "impl AuthorityTrustRootSealV1 {\n    pub const fn forge() {}\n}\n",
        "adds an inherent impl to the authority trust-root seal",
    ),
    "literal elsewhere in core": (
        "crates/pos-core/src/store.rs",
        "fn forge() -> crate::AuthorityTrustRootSealV1 {\n"
        + "    crate::AuthorityTrustRootSealV1(())\n}\n",
        "constructs the seal outside for_composition_root",
    ),
    "From<()> impl on the seal": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL + "impl From<()> for AuthorityTrustRootSealV1 {\n",
        "implements a trait for the authority trust-root seal",
    ),
    "Deserialize impl on the seal": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL + "impl<'de> serde::Deserialize<'de> for AuthorityTrustRootSealV1 {\n",
        "implements a trait for the authority trust-root seal",
    ),
    "split derive": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL.replace("#[derive(Debug)]", "#[derive(Clone)]\n#[derive(Debug)]"),
        "the seal may derive only Debug",
    ),
    "conditional derive": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL.replace("#[must_use]", "#[cfg_attr(feature = \"x\", derive(Clone))]"),
        "the seal may derive only Debug",
    ),
    "alias in core": (
        "crates/pos-core/src/store.rs",
        "type S = crate::AuthorityTrustRootSealV1;\n",
        "aliases the authority trust-root seal",
    ),
    "Self literal outside the seal impl": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL + "impl Other {\n    fn forge() -> Self {\n        Self(())\n    }\n}\n",
        "constructs the seal outside for_composition_root",
    ),
    "field-zero literal in core": (
        "crates/pos-core/src/store.rs",
        "fn forge() -> crate::AuthorityTrustRootSealV1 {\n"
        + "    crate::AuthorityTrustRootSealV1 { 0: () }\n}\n",
        "constructs the seal outside for_composition_root",
    ),
    "mint inside core": (
        "crates/pos-core/src/store.rs",
        "fn root() {\n"
        + "    let _seal = crate::AuthorityTrustRootSealV1::for_composition_root();\n}\n",
        "mints the authority trust-root seal inside pos-core",
    ),
    "mint after a test module with braces in literals": (
        "crates/pos-state/src/lib.rs",
        TEST_MODULE
        + "    const B: char = '{';\n"
        + "    const S: &str = \"{{\";\n"
        + "    const R: &str = r#\"{\"#;\n}\n"
        + SEAL_USE,
        PINNED,
    ),
    "conditional Debug derive": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL.replace("#[derive(Debug)]", "#[cfg_attr(feature = \"x\", derive(Debug))]"),
        "the seal may derive only Debug",
    ),
    "missing seal struct": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL.replace("pub struct AuthorityTrustRootSealV1(());\n", ""),
        "the seal may derive only Debug",
    ),
    "core alias with an inherent impl": (
        "crates/pos-core/src/authority.rs",
        CORE_SEAL + "type S = AuthorityTrustRootSealV1;\nimpl S {\n    pub fn forge() -> S {\n",
        "aliases the authority trust-root seal",
    ),
    "pinned mint in a fn": (
        "apps/piglor-gateway/src/local_principal.rs",
        "fn seal() -> AuthorityTrustRootSealV1 {\n    " + MINT + "}\n",
        "mints the authority trust-root seal other than as a static initializer",
    ),
    "pinned mint as a const": (
        "apps/pos-experiment/src/lib.rs",
        "const ROOT: AuthorityTrustRootSealV1 = " + MINT,
        "mints the authority trust-root seal other than as a static initializer",
    ),
    "pinned mint inside a macro": (
        "apps/pos-plugin-conformance-adapter/src/main.rs",
        "macro_rules! mint {\n    () => {\n        "
        + MINT
        + "    };\n}\n",
        "expands the authority trust-root seal mint from a macro",
    ),
    "use rename in core": (
        "crates/pos-core/src/store.rs",
        "use crate::AuthorityTrustRootSealV1 as Root;\n",
        "aliases the authority trust-root seal",
    ),
    "include with an env path": (
        "apps/piglor-gateway/src/http.rs",
        'include!(concat!(env!("SEAL_DIR"), "/seal.rs"));\n',
        NON_LITERAL,
    ),
    "include with a trailing comma": (
        "apps/piglor-gateway/src/http.rs",
        'include!("seal.rs",);\n',
        NON_LITERAL,
    ),
    "include with brackets": (
        "apps/piglor-gateway/src/http.rs",
        'include!["seal.rs"];\n',
        NON_LITERAL,
    ),
    "spaced include": ("apps/piglor-gateway/src/http.rs", 'include ! ("seal.rs");\n', NON_LITERAL),
    "cfg_attr path": (
        "apps/piglor-gateway/src/http.rs",
        '#[cfg_attr(not(test), path = "seal.rs")]\nmod real;\n',
        NON_LITERAL,
    ),
    "build script naming the seal in a literal": (
        "apps/piglor-gateway/build.rs",
        'fn main() {\n    println!("{}", "AuthorityTrustRootSealV1::for_composition_root()");\n}\n',
        "apps/piglor-gateway/build.rs: build code names the seal",
    ),
    "mint after a C string holding //": (
        "crates/pos-state/src/lib.rs",
        'let _ = c"//"; ' + SEAL_USE,
        PINNED,
    ),
    "mint after a raw C string holding //": (
        "crates/pos-state/src/lib.rs",
        'let _ = cr#"a"//"#; ' + SEAL_USE,
        PINNED,
    ),
    "mint after a raw byte string holding //": (
        "crates/pos-state/src/lib.rs",
        'let _ = br#"a"//"#; ' + SEAL_USE,
        PINNED,
    ),
    "mint after a nested block comment": (
        "crates/pos-state/src/lib.rs",
        "/* outer /* inner */ outer */\n" + SEAL_USE,
        PINNED,
    ),
    "mint after a test module with a continued string": (
        "crates/pos-state/src/lib.rs",
        TEST_MODULE + '    const S: &str = "a\\\n        {";\n}\n' + SEAL_USE,
        PINNED,
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
    for missing in MINT_SITE_FILES:
        result = with_files(
            {
                path: text
                for path, text in {**ALLOWED_MANIFESTS, **ALLOWED_SOURCES}.items()
                if path != missing
            }
        )
        expect_rejected(
            f"an allowed layout without {missing}", result, "pinned mint site is missing"
        )
    for case, (relative, text, reason) in REJECTED_MANIFESTS.items():
        result = with_files({relative: text})
        expect_rejected(f"a {case} enabling the trust-root feature", result, reason)
    for case, (relative, text, reason) in REJECTED_SOURCES.items():
        result = with_files({**CRATE_MANIFEST, relative: text})
        expect_rejected(f"the seal in a {case}", result, reason)
    for case, files in REJECTED_LAYOUTS.items():
        result = with_files({**CRATE_MANIFEST, **files})
        expect_rejected(case, result, "apps/piglor-gateway/src/e2e.rs: " + PINNED)
    for case, (files, reason) in REJECTED_REFERENCES.items():
        expect_rejected(case, with_files({**CRATE_MANIFEST, **files}), reason)


if __name__ == "__main__":
    main()
