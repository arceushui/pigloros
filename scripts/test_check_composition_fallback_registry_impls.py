#!/usr/bin/env python3
"""Adversarial tests for the ADR-119 composition fallback registry checker (slice #663)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_composition_fallback_registry_impls.py"

GATE = '#![cfg(any(test, feature = "test-support"))]\n'
LINUX = '#[cfg(target_os = "linux")]\n'
IMPL = "impl CompositionFallbackRegistryV1 for Forged {}\n"
GENERIC_IMPL = "impl<'a> CompositionFallbackRegistryV1\n    for Forged<'a> {}\n"
IMPORT = "use pos_store::composition_fallback_registry::CompositionFallbackRegistryV1;\n"
GLOB = "use pos_store::composition_fallback_registry::*;\n"
CALLS = "fn f(s: &mut S) { s.declare(a); s.activate(a); s.provision_fallback_registry(); }\n"
LITERALS = "fn f() -> R { FallbackLedgerRowV1 { a: 1 } }\n"
LOGIC = "use pos_store::composition_fallback_registry::logic::plan_declare;\n"
MEMORY_ADAPTER = "crates/pos-store/src/memory/composition_fallback_registry.rs"
SQLITE_ADAPTER = "crates/pos-store/src/sqlite/composition_fallback_registry.rs"
REGISTRY_FILE = "crates/pos-store/src/composition_fallback_registry/types.rs"

ALLOWED = {
    "crates/pos-store/src/lib.rs": "pub mod composition_fallback_registry;\n",
    "crates/pos-store/src/memory.rs": (
        "mod composition_fallback_registry;\n"
        "/// The registry state.\n"
        "composition_fallback: composition_fallback_registry::State,\n"
        + LINUX
        + "plugin_trust: plugin_trust_registry::State,\n"
    ),
    "crates/pos-store/src/sqlite.rs": (
        "mod composition_fallback_registry;\nmod composition_fallback_registry_rows;\n"
    ),
    REGISTRY_FILE: (
        "pub struct FallbackLedgerRowV1 { pub(crate) row_seq: u64 }\n"
        "impl FallbackLedgerRowV1 { pub const fn row_seq(&self) -> u64 { self.row_seq } }\n"
    ),
    "crates/pos-store/src/composition_fallback_registry/logic.rs": (
        "fn f() -> FallbackLedgerRowV1 { FallbackLedgerRowV1 { row_seq: 1 } }\n"
    ),
    MEMORY_ADAPTER: IMPL + LOGIC + CALLS + LITERALS,
    SQLITE_ADAPTER: IMPL + LOGIC + CALLS + LITERALS,
    "crates/pos-store/src/sqlite/composition_fallback_registry_tests.rs": GATE + IMPORT + CALLS,
    "crates/pos-store/tests/composition_fallback_public.rs": IMPORT + CALLS,
    "crates/pos-store/tests/support/composition_fallback_fixtures.rs": IMPORT + CALLS,
    "crates/pos-runtime/src/fallback.rs": IMPORT + CALLS,
    "crates/pos-plugin-supervisor/src/boundary.rs": GLOB + CALLS,
    "crates/pos-runtime/tests/fallback_public.rs": IMPORT + CALLS,
    "crates/pos-state/src/docs.rs": "// impl CompositionFallbackRegistryV1 for Forged {}\n" + "/* s.declare(a); */\n",
    "crates/pos-state/src/unaware.rs": "fn f(x: &mut X) { x.declare(a); x.activate(a); }\n",
    "crates/pos-state/src/reads.rs": IMPORT + "fn f(s: &S) { s.registry_row(a, b); s.fallback_ledger(a, b); }\n",
    "crates/pos-state/src/types.rs": (
        "fn f(r: &FallbackLedgerRowV1) -> &FallbackRegistryRowV1 { r.row() }\n"
        "struct FallbackEntryStateV1 { a: u8 }\nimpl FallbackEntryStateV1 { }\n"
    ),
    "crates/pos-state/src/test_only.rs": IMPORT + "#[cfg(test)]\nmod tests {\n" + CALLS + "}\n",
    "crates/pos-state/src/gated.rs": GATE + IMPORT + CALLS,
    "target/debug/build/generated.rs": IMPL + IMPORT + CALLS + LOGIC,
}

REJECTED = {
    "crates/pos-state/src/forged.rs": IMPL,
    "crates/pos-time/src/forged.rs": GENERIC_IMPL,
    "crates/pos-runtime/src/forged.rs": IMPL,
    "crates/pos-store/tests/forged.rs": IMPL,
    "crates/pos-state/src/alias.rs": (
        "use pos_store::composition_fallback_registry::CompositionFallbackRegistryV1 as R;\n"
    ),
    "crates/pos-state/src/ledger.rs": LITERALS,
    "crates/pos-runtime/src/receipt.rs": "fn f() { let _ = FallbackCommitReceiptV1 { a: 1 }; }\n",
    "crates/pos-state/src/row.rs": "fn f() { let _ = FallbackRegistryRowV1 { a: 1 }; }\n",
    "crates/pos-state/src/state.rs": "fn f() { let _ = FallbackRegistryStateV1 { a: 1 }; }\n",
    "crates/pos-state/src/entry.rs": "fn f() { let _ = FallbackEntryStateV1 { a: 1 }; }\n",
    "crates/pos-state/src/event.rs": "fn f() { let _ = FallbackEventIdentityV1 { a: 1 }; }\n",
    "crates/pos-runtime/src/logic.rs": LOGIC,
    "crates/pos-runtime/src/logic_group.rs": (
        "use pos_store::composition_fallback_registry::{logic::plan_activate, X};\n"
    ),
    "crates/pos-state/src/declare.rs": IMPORT + "fn f(s: &mut S) { s.declare(a); }\n",
    "crates/pos-state/src/activate.rs": IMPORT + "fn f(s: &mut S) { s.\n    activate(a); }\n",
    "crates/pos-state/src/provision.rs": IMPORT + "fn f(s: &mut S) { s.provision_fallback_registry(); }\n",
    "crates/pos-state/src/path.rs": IMPORT + "fn f(s: &mut S) { MemoryStore::declare(s, a); }\n",
    "crates/pos-state/src/qualified.rs": (
        IMPORT + "fn f(s: &mut S) { <S as CompositionFallbackRegistryV1>::activate(s, a); }\n"
    ),
    "crates/pos-state/src/glob.rs": GLOB + "fn f(s: &mut S) { s.activate(a); }\n",
    "crates/pos-state/src/feature_gated.rs": (
        IMPORT + '#[cfg(feature = "test-support")]\nfn f(s: &mut S) { s.declare(a); }\n'
    ),
    "crates/pos-state/src/gate_after_item.rs": "fn f() {}\n" + GATE + IMPORT + CALLS,
    "crates/pos-state/src/after_test_item.rs": (
        IMPORT + "#[cfg(test)]\nfn t() {}\nfn f(s: &mut S) { s.declare(a); }\n"
    ),
    "crates/pos-store/src/lib.rs": LINUX + "pub mod composition_fallback_registry;\n",
    "crates/pos-store/src/memory.rs": (
        '#[cfg(not(target_os = "windows"))]\nmod composition_fallback_registry;\n'
    ),
    "crates/pos-store/src/sqlite.rs": (
        LINUX + "#[doc(hidden)]\nmod composition_fallback_registry_rows;\n"
    ),
    REGISTRY_FILE: LINUX + "pub struct FallbackLedgerRowV1 { pub(crate) row_seq: u64 }\n",
    MEMORY_ADAPTER: LINUX + IMPL,
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
            raise SystemExit(f"{relative} was not rejected:\n{result.stderr}")
    print("composition fallback registry checker rejects every forged use")


if __name__ == "__main__":
    main()
