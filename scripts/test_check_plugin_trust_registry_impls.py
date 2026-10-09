#!/usr/bin/env python3
"""Adversarial tests for the Plugin trust policy registry checker (ADR-103 revisions 4 and 5)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_plugin_trust_registry_impls.py"

GATE = '#![cfg(any(test, feature = "test-support"))]\n'
LINUX = '#[cfg(target_os = "linux")]\n'
IMPL = "impl PluginTrustPolicyRegistryV1 for Forged {}\n"
GENERIC_IMPL = "impl<'a> PluginTrustPolicyRegistryV1\n    for Forged<'a> {}\n"
IMPORT = "use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1;\n"
GLOB = "use pos_store::plugin_trust_registry::*;\n"
CALLS = "fn f(s: &mut S) { s.admit(a); s.rollback(a); s.provision(a); s.advance_policy(a); }\n"
ANCHOR = "fn f() { PluginTrustPolicyAnchorV1::new(a, b, c, d, e); }\n"
UTC = "fn f(s: &mut S) { TrustedUtcSecondV1::from_source(s); }\n"
INSTALLER_FILE = "crates/pos-plugin-publisher/src/install.rs"
INSTALLER_SIBLING = "crates/pos-plugin-publisher/src/other.rs"
TEST_WORLD_FILE = "crates/pos-plugin-publisher/tests/support/world.rs"
INSTALLER_BODY = (
    IMPORT + "fn f(s: &mut S, w: &mut W) { TrustedUtcSecondV1::from_source(w); s.admit(a); }\n"
)
REGISTRY_FILE = "crates/pos-store/src/plugin_trust_registry/types.rs"
ADAPTER_FILE = "crates/pos-store/src/memory/plugin_trust_registry.rs"
SQLITE_ADAPTER_FILE = "crates/pos-store/src/sqlite/plugin_trust_registry.rs"
SQLITE_SIBLING_FILE = "crates/pos-store/src/sqlite/plugin_trust_registry_rows.rs"
SQLITE_SCHEMA_FILE = "crates/pos-store/src/sqlite/plugin_trust_registry_schema.rs"


def registry(text: str) -> dict[str, str]:
    return {REGISTRY_FILE: text}


ALLOWED = {
    "crates/pos-store/src/lib.rs": LINUX + "pub mod plugin_trust_registry;\n",
    "crates/pos-store/src/memory.rs": (
        LINUX
        + "mod plugin_trust_registry;\n"
        + LINUX
        + "#[doc(hidden)]\n"
        + "plugin_trust: plugin_trust_registry::State,\n"
        + "#[cfg(test)]\nmod tests { use crate::plugin_trust_registry::X; }\n"
    ),
    "crates/pos-store/src/plugin_trust_registry/mod.rs": (
        IMPL
        + "pub struct ActiveReleaseV1 { pub name: u8, pub(crate) signature: u8 }\n"
        + "pub(crate) fn signature_check() {}\n"
        + "fn is_live() {}\n"
        + 'pub const NOTE: &str = "signature is_live";\n'
        + "pub enum PluginTrustPolicyRegistryErrorV1 {\n"
        + '    #[error("a, b")]\n    MissingState,\n    Bridge(#[from] Inner),\n}\n'
        + "pub use types::{ActiveReleaseV1, CurrentReleaseEvaluationV1, RetainedPolicyStateV1};\n"
        # ADR-103 revision 5 (EU1): the type, its accessors, and the two variants pass the lint;
        # the trait method carries no `pub`, so the name lint does not see it.
        + "pub struct CurrentReleaseEvaluationV1 { pub(crate) scope: u8 }\n"
        + "impl CurrentReleaseEvaluationV1 {\n"
        + "    pub fn scope(&self) -> u8 { 1 }\n"
        + "    pub const fn pmf1_digest(&self) -> u8 { 2 }\n"
        + "    pub const fn ptr1_floor(&self) -> u8 { 3 }\n}\n"
        + "pub enum Revision5Error { PolicyNotAdvanced, ReleaseNotActive }\n"
        + "impl PluginTrustPolicyRegistryV1 for Other {\n"
        + "    fn evaluate_current_release(&self) {}\n}\n"
        + "/// Never claims `signature` validity or is_live authority.\n"
    ),
    ADAPTER_FILE: (
        "impl PluginTrustPolicyRegistryV1 for MemoryStore {\n"
        "    fn admit(&mut self) { self.admit_with_faults(); }\n"
        "    fn rollback(&mut self) { self.rollback_with_faults(); }\n}\n"
        "#[cfg(test)]\nmod tests {\n    fn t(s: &mut S) { s.admit(a); s.rollback(a); }\n}\n"
    ),
    "crates/pos-store/src/sqlite.rs": (
        LINUX + "mod plugin_trust_registry;\n" + LINUX + "mod plugin_trust_registry_rows;\n"
    ),
    SQLITE_ADAPTER_FILE: (
        "impl PluginTrustPolicyRegistryV1 for SqliteStore {\n"
        "    fn admit(&mut self) { self.admit_in_transaction(); }\n"
        "    fn rollback(&mut self) { self.rollback_in_transaction(); }\n}\n"
        "#[cfg(test)]\n#[path = \"plugin_trust_registry_tests.rs\"]\nmod tests;\n"
    ),
    SQLITE_SIBLING_FILE: "pub(super) fn insert_ledger() {}\n",
    SQLITE_SCHEMA_FILE: "pub(super) fn validate() {}\n",
    "crates/pos-store/src/sqlite/plugin_trust_registry_tests.rs": (
        GATE + IMPORT + "fn t(s: &mut S) { s.admit(a); s.rollback(a); s.provision(a); }\n"
    ),
    "crates/pos-store/tests/registry_public.rs": IMPORT + CALLS + ANCHOR + UTC,
    "crates/pos-runtime/src/host.rs": IMPL + IMPORT + ANCHOR + UTC + CALLS.replace(
        "s.admit(a); s.rollback(a); ", ""
    ),
    "crates/pos-core/src/registry_fixture.rs": GATE + IMPL + IMPORT + CALLS + ANCHOR + UTC,
    "crates/pos-conformance/tests/bridge_public.rs": ANCHOR + IMPORT + CALLS,
    "crates/pos-state/src/docs.rs": "// impl PluginTrustPolicyRegistryV1 for Forged {}\n",
    "crates/pos-state/src/block.rs": "/* store.admit(a); AdmittedPluginReleaseReceiptV1 { } */\n",
    "crates/pos-state/src/path_unaware.rs": "fn f(s: &mut S) { Other::admit(s, a); Other::rollback(s, a); }\n",
    "crates/pos-state/src/path_test_only.rs": IMPORT + "#[cfg(test)]\nmod tests { fn t(s: &mut S) { MemoryStore::admit(s, a); } }\n",
    "crates/pos-state/src/uses.rs": "fn f(_: &mut dyn PluginTrustPolicyRegistryV1) {}\n",
    "crates/pos-state/src/imports.rs": IMPORT,
    # The read-only method has no call-site rule: any file that names the port may call it.
    "crates/pos-state/src/evaluates.rs": (
        IMPORT + "fn f(s: &S) { s.evaluate_current_release(a, b); }\n"
    ),
    "crates/pos-state/src/unaware.rs": "fn f(x: &mut X) { x.admit(a); x.rollback(a); x.provision(a); }\n",
    "crates/pos-state/src/defines.rs": (
        "struct ActiveReleaseV1 { a: u8 }\nimpl ActiveReleaseV1 { }\n"
        "enum PluginRollbackReceiptV1 { }\nfn f() -> RollbackFactsV1 { x }\n"
        "fn g(&self) -> &ActiveReleaseV1 { &self.a }\n"
    ),
    "crates/pos-state/src/test_only.rs": IMPORT + "#[cfg(test)]\nmod tests {\n" + CALLS + "}\n",
    "crates/pos-state/src/gated_item.rs": (
        IMPORT + '#[cfg(any(test, feature = "test-support"))]\nfn f(s: &mut S) { s.admit(a); }\n'
    ),
    "target/debug/build/generated.rs": IMPL + IMPORT + CALLS,
    INSTALLER_FILE: INSTALLER_BODY,
    "crates/pos-plugin-publisher/tests/installer_public.rs": IMPORT + CALLS,
    # The shared signed-release test world (#579): gated fixture files under `tests/support`,
    # included into the library by `#[path]` under the `test-support` feature.
    TEST_WORLD_FILE: GATE + IMPL + IMPORT + CALLS + ANCHOR + UTC,
    "crates/pos-plugin-publisher/tests/support/mod.rs": GATE + "pub mod world;\n",
}

REJECTED = {
    "crates/pos-state/src/forged.rs": IMPL,
    "crates/pos-state/src/sqlite/plugin_trust_registry.rs": IMPL,
    "crates/pos-store/src/sqlite/plugin_trust_registry_calls.rs": (
        IMPORT + "fn f(s: &mut S) { s.admit(a); }\n"
    ),
    "crates/pos-time/src/forged.rs": GENERIC_IMPL,
    "crates/pos-core/src/ungated.rs": '#[cfg(feature = "test-support")]\n' + IMPL,
    "crates/x/src/target/forged.rs": IMPL,
    "crates/pos-state/src/alias_port.rs": (
        "use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1 as R;\n"
    ),
    "crates/pos-state/src/alias_utc.rs": "use pos_store::plugin_trust_registry::{TrustedUtcSecondV1 as U};\n",
    "crates/pos-state/src/alias_anchor.rs": "use pos_conformance::PluginTrustPolicyAnchorV1 as A;\n",
    "crates/pos-state/src/utc.rs": UTC,
    "crates/pos-conformance/tests/utc.rs": UTC,
    "crates/pos-state/src/receipt.rs": "fn f() -> R { AdmittedPluginReleaseReceiptV1 { a: 1 } }\n",
    "crates/pos-state/src/rollback_receipt.rs": "fn f() { let _ = PluginRollbackReceiptV1 { a: 1 }; }\n",
    "crates/pos-state/src/ledger.rs": "fn f() { let _ = PluginTrustLedgerRowV1 { a: 1 }; }\n",
    "crates/pos-state/src/evaluation.rs": (
        "fn f() { let _ = CurrentReleaseEvaluationV1 { a: 1 }; }\n"
    ),
    "crates/pos-plugin-publisher/tests/support/ungated_evaluation.rs": (
        "fn f() { let _ = CurrentReleaseEvaluationV1 { a: 1 }; }\n"
    ),
    "crates/pos-state/src/anchor.rs": ANCHOR,
    "crates/pos-state/src/provision.rs": IMPORT + "fn f(s: &mut S) { s.provision(a, b); }\n",
    "crates/pos-state/src/advance.rs": IMPORT + "fn f(s: &mut S) { s.advance_policy(a); }\n",
    "crates/pos-state/src/ufcs_provision.rs": (
        "fn f() { PluginTrustPolicyRegistryV1::provision(s, a, b); }\n"
    ),
    "crates/pos-state/src/admit.rs": IMPORT + "fn f(s: &mut S) { s.admit(a, b); }\n",
    "crates/pos-state/src/rollback.rs": IMPORT + "fn f(s: &mut S) { s.\n    rollback(a); }\n",
    "crates/pos-state/src/path_admit.rs": IMPORT + "fn f(s: &mut S) { MemoryStore::admit(s, a); }\n",
    "crates/pos-state/src/path_rollback.rs": IMPORT + "fn f(s: &mut S) { MemoryStore::rollback(s, a); }\n",
    "crates/pos-state/src/qualified_admit.rs": (
        IMPORT + "fn f(s: &mut S) { <S as PluginTrustPolicyRegistryV1>::admit(s, a); }\n"
    ),
    "crates/pos-state/src/path_provision.rs": IMPORT + "fn f(s: &mut S) { MemoryStore::provision(s, a); }\n",
    "crates/pos-state/src/ufcs.rs": "fn f() { PluginTrustPolicyRegistryV1::admit(s, a); }\n",
    "crates/pos-state/src/glob.rs": GLOB + "fn f(s: &mut S) { s.admit(a); }\n",
    "crates/pos-store/src/composition.rs": (
        LINUX + IMPORT + LINUX + "fn f(s: &mut S) { s.admit(a); }\n"
    ),
    "crates/pos-runtime/src/composition.rs": IMPORT + "fn f(s: &mut S) { s.rollback(a); }\n",
    "crates/pos-state/src/feature_gated.rs": (
        IMPORT + '#[cfg(feature = "test-support")]\nfn f(s: &mut S) { s.admit(a); }\n'
    ),
    "crates/pos-state/src/gate_in_comment.rs": "// " + GATE + IMPL,
    "crates/pos-state/src/gate_in_string.rs": 'const S: &str = "\n' + GATE.replace('"', '\\"') + '";\n' + IMPL,
    "crates/pos-state/src/gate_after_item.rs": "fn f() {}\n" + GATE + IMPL,
    "crates/pos-state/src/after_test_item.rs": (
        IMPORT + "#[cfg(test)]\nfn t() {}\nfn f(s: &mut S) { s.admit(a); }\n"
    ),
    "crates/pos-state/src/string_opener.rs": 'const S: &str = "/*"; ' + IMPL.rstrip("\n") + " // */\n",
    "crates/pos-store/src/lib_without_cfg.rs": "pub mod plugin_trust_registry;\n",
    "crates/pos-store/src/lib_wrong_cfg.rs": (
        '#[cfg(feature = "sqlite")]\npub mod plugin_trust_registry;\n'
    ),
    "crates/pos-store/src/sqlite.rs": (
        LINUX + "mod a;\nfn f() {}\nstruct S {\n    state: plugin_trust_registry::State,\n}\n"
    ),
    INSTALLER_SIBLING: INSTALLER_BODY,
    "crates/pos-plugin-publisher/src/install_copy.rs": IMPORT + "fn f(s: &mut S) { s.admit(a); }\n",
    "crates/pos-plugin-publisher/src/utc.rs": UTC,
    # A sibling of the world fixture without the fixture gate is not a fixture.
    "crates/pos-plugin-publisher/tests/support/ungated_impl.rs": IMPL,
    "crates/pos-plugin-publisher/tests/support/ungated_utc.rs": UTC,
    "crates/pos-plugin-publisher/tests/support/ungated_receipt.rs": (
        "fn f() { let _ = PluginRollbackReceiptV1 { a: 1 }; }\n"
    ),
    "crates/pos-plugin-publisher/tests/support/feature_only.rs": (
        '#![cfg(feature = "test-support")]\n' + IMPL
    ),
    "crates/pos-store/src/blank_gap.rs": (
        LINUX + "const X: u8 = 1;\npub mod plugin_trust_registry;\n"
    ),
}

FORBIDDEN_NAMES = {
    "fn_signature": "pub fn signature_valid() {}\n",
    "fn_verified": "pub fn verified_signature_token() {}\n",
    "fn_admitted": "impl R { pub fn is_admitted(&self) -> bool { true } }\n",
    "fn_live": "impl R { pub const fn is_live(&self) -> bool { true } }\n",
    "fn_from_receipt": "pub fn authorize_from_receipt() {}\n",
    "struct_camel": "pub struct VerifiedSignatureV1;\n",
    "struct_live": "pub struct LiveAuthority;\n",
    "enum_name": "pub enum SignatureKind { A }\n",
    "enum_variant": "pub enum K { A, LiveAuthority }\n",
    "enum_variant_attr": 'pub enum K {\n    #[error("a, b")]\n    IsAdmitted(u8),\n}\n',
    "enum_variant_struct": "pub enum K { A { x: u8 }, VerifiedSignature { y: u8 } }\n",
    "field": "pub struct S { pub signature: u8 }\n",
    "evaluation_is_live_release": "impl R { pub fn is_live_release(&self) -> bool { true } }\n",
    "evaluation_live_authority_of": "pub fn live_authority_of() {}\n",
    "evaluation_signature_accessor": (
        "impl CurrentReleaseEvaluationV1 { pub fn signature_ok(&self) -> bool { true } }\n"
    ),
    "evaluation_snake_signature": "impl R { pub fn release_signature(&self) -> u8 { 0 } }\n",
    "constant": "pub const IS_LIVE: bool = false;\n",
    "static_item": "pub static SIGNATURE_OK: bool = false;\n",
    "type_alias": "pub type SignatureResult = u8;\n",
    "module": "pub mod signature;\n",
    "reexport": "pub use other::authorize_from_receipt;\n",
    "reexport_list": "pub use other::{A, SignatureToken};\n",
}


# The installer file is rejected, not exempted, for everything except `admit` and
# the one trusted-time construction.
INSTALLER_REJECTED = {
    "rollback": IMPORT + "fn f(s: &mut S) { s.rollback(a); }\n",
    "provision": IMPORT + "fn f(s: &mut S) { s.provision(a, b); }\n",
    "advance": IMPORT + "fn f(s: &mut S) { s.advance_policy(a); }\n",
    "anchor": ANCHOR,
    "impl": IMPL,
    "receipt": "fn f() { let _ = AdmittedPluginReleaseReceiptV1 { a: 1 }; }\n",
    "path_rollback": IMPORT + "fn f(s: &mut S) { MemoryStore::rollback(s, a); }\n",
}


def run(files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )


def main() -> None:
    accepted = run(ALLOWED)
    if accepted.returncode != 0:
        raise SystemExit(f"allowed layout was rejected:\n{accepted.stderr}")
    for relative, text in REJECTED.items():
        result = run({**ALLOWED, relative: text})
        if result.returncode == 0 or relative not in result.stderr:
            raise SystemExit(f"{relative} was not rejected")
    for label, text in INSTALLER_REJECTED.items():
        result = run({**ALLOWED, INSTALLER_FILE: INSTALLER_BODY + text})
        if result.returncode == 0 or INSTALLER_FILE not in result.stderr:
            raise SystemExit(f"installer {label} was not rejected")
    for label, text in FORBIDDEN_NAMES.items():
        for relative in (
            REGISTRY_FILE,
            ADAPTER_FILE,
            SQLITE_ADAPTER_FILE,
            SQLITE_SIBLING_FILE,
            SQLITE_SCHEMA_FILE,
        ):
            result = run({**ALLOWED, relative: text})
            if result.returncode == 0 or relative not in result.stderr:
                raise SystemExit(f"{label} in {relative} was not rejected")
    print("Plugin trust registry checker rejects every forged use")


if __name__ == "__main__":
    main()
