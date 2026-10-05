#!/usr/bin/env python3
"""Adversarial tests for the counterfactual adapter seal policy checker."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_counterfactual_adapter_seal.py"

ENABLING = 'pos-core = { path = "../pos-core", features = ["counterfactual-adapter"] }\n'
DEV_ONLY = "[dev-dependencies]\n" + ENABLING
MINT = "CounterfactualAdapterSealV1::for_adapter();\n"
SEAL_USE = "let seal = pos_core::CounterfactualAdapterSealV1::for_adapter();\n"

ALLOWED_MANIFESTS = {
    "crates/pos-store/Cargo.toml": "[dependencies]\n" + ENABLING,
    "crates/pos-runtime/Cargo.toml": DEV_ONLY,
    "crates/pos-core/Cargo.toml": '[features]\ncounterfactual-adapter = []\n',
}

DEPENDENCY = "enables counterfactual-adapter"
OUTSIDE = "names the counterfactual adapter seal outside the adapters"
REEXPORT = "re-exports the counterfactual adapter seal"
CRATE = "re-exports the pos_core crate"
ITEM = "exposes the counterfactual adapter seal from a public item"
RETURNS = "returns the counterfactual adapter seal from a public fn"
CONFIG = "enables counterfactual-adapter outside a manifest"
FEATURES_FLAG = "cargo test -p pos-runtime --features pos-core/counterfactual-adapter\n"

REJECTED_MANIFESTS = {
    "dependency": ("[dependencies]\n" + ENABLING, DEPENDENCY),
    "build dependency": ("[build-dependencies]\n" + ENABLING, DEPENDENCY),
    "target dependency": ("[target.'cfg(unix)'.dependencies]\n" + ENABLING, DEPENDENCY),
    "workspace dependency": (
        "[workspace.dependencies]\n"
        + 'pos-core = { path = "crates/pos-core", features = ["counterfactual-adapter"] }\n',
        DEPENDENCY,
    ),
    "forwarding feature": (
        '[features]\nadapters = ["pos-core/counterfactual-adapter"]\n',
        "feature adapters forwards counterfactual-adapter",
    ),
    "default feature": (
        '[features]\ndefault = ["seal"]\nseal = ["counterfactual-adapter"]\n'
        + "counterfactual-adapter = []\n",
        "default feature enables counterfactual-adapter",
    ),
}

ALLOWED_SOURCES = {
    "crates/pos-store/src/memory.rs": SEAL_USE,
    "crates/pos-store/src/sqlite.rs": "pub(crate) fn seal() -> CounterfactualAdapterSealV1 {\n",
    "crates/pos-store/src/lib.rs": "pub use pos_core::{CoreError, Seq};\n"
    + "use pos_core::CounterfactualAdapterSealV1;\n",
    "crates/pos-store/src/counterfactual_adapter.rs": "use pos_core::counterfactual_store::*;\n"
    + "pub(crate) type Seal = CounterfactualAdapterSealV1;\n"
    + "pub(super) const SEAL: CounterfactualAdapterSealV1 = " + MINT
    + "pub(crate) use pos_core as core_api;\n"
    + "pub use crate::counterfactual_store;\n"
    + "pub use pos_core::store::{CounterfactualStoreErrorV1, Seq};\n"
    + "pub const fn mint(seal: CounterfactualAdapterSealV1) -> u8 {\n",
    "crates/pos-core/src/counterfactual_store.rs": SEAL_USE,
    "crates/pos-runtime/tests/coordinator.rs": SEAL_USE,
    "crates/pos-runtime/tests/support/mod.rs": SEAL_USE,
    "crates/pos-runtime/src/coordinator.rs": "// CounterfactualAdapterSealV1 is adapter-only.\n",
}

CRATE_MANIFEST = {"crates/pos-runtime/Cargo.toml": DEV_ONLY}

REJECTED_SOURCES = {
    "runtime source": ("crates/pos-runtime/src/coordinator.rs", SEAL_USE, OUTSIDE),
    "tests-named file": ("crates/pos-runtime/src/tests.rs", SEAL_USE, OUTSIDE),
    "src/tests directory": ("crates/pos-runtime/src/tests/mod.rs", SEAL_USE, OUTSIDE),
    "tests directory outside a crate": ("tools/tests/seal.rs", SEAL_USE, OUTSIDE),
    "nested crate": ("apps/fixture/crates/pos-store/src/lib.rs", SEAL_USE, OUTSIDE),
    "re-export": (
        "crates/pos-store/src/lib.rs",
        "pub use pos_core::{\n    CoreError,\n    CounterfactualAdapterSealV1 as Seal,\n};\n",
        REEXPORT,
    ),
    "glob re-export": ("crates/pos-store/src/lib.rs", "pub use pos_core::*;\n", REEXPORT),
    "module glob re-export": (
        "crates/pos-store/src/lib.rs",
        "pub use pos_core::counterfactual_store::*;\n",
        REEXPORT,
    ),
    "nested glob re-export": (
        "crates/pos-store/src/lib.rs",
        "pub use pos_core::{\n    Seq,\n    counterfactual_store::*,\n};\n",
        REEXPORT,
    ),
    "module re-export": (
        "crates/pos-store/src/lib.rs",
        "pub use pos_core::counterfactual_store as cf;\n",
        REEXPORT,
    ),
    "renamed crate re-export": ("crates/pos-store/src/lib.rs", "pub use pos_core as api;\n", CRATE),
    "crate re-export": ("crates/pos-store/src/lib.rs", "pub use ::pos_core;\n", CRATE),
    "self re-export": (
        "crates/pos-store/src/lib.rs",
        "pub use pos_core::{self as api, Seq};\n",
        CRATE,
    ),
    "public type alias": (
        "crates/pos-store/src/lib.rs",
        "pub type Seal = pos_core::CounterfactualAdapterSealV1;\n",
        ITEM,
    ),
    "public static": (
        "crates/pos-store/src/lib.rs",
        "pub static SEAL: CounterfactualAdapterSealV1 = " + MINT,
        ITEM,
    ),
    "public const": (
        "crates/pos-store/src/lib.rs",
        "pub const SEAL: CounterfactualAdapterSealV1 = " + MINT,
        ITEM,
    ),
    "public tuple struct": (
        "crates/pos-store/src/lib.rs",
        "pub struct Holder(pub CounterfactualAdapterSealV1);\n",
        ITEM,
    ),
    "public enum": (
        "crates/pos-store/src/lib.rs",
        "pub enum Minted { Seal(CounterfactualAdapterSealV1) }\n",
        ITEM,
    ),
    "public field": (
        "crates/pos-store/src/lib.rs",
        "pub(crate) struct Holder {\n    pub seal: CounterfactualAdapterSealV1,\n}\n",
        ITEM,
    ),
    "public fn": (
        "crates/pos-store/src/memory.rs",
        "pub const fn seal() -> pos_core::CounterfactualAdapterSealV1 {\n",
        RETURNS,
    ),
    "workflow": (".github/workflows/ci.yml", "run: " + FEATURES_FLAG, CONFIG),
    "Dockerfile": ("docker/Dockerfile", "RUN " + FEATURES_FLAG, CONFIG),
    "cargo config": (
        ".cargo/config.toml",
        '[alias]\nt = "test --features pos-core/counterfactual-adapter"\n',
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
            "target/debug/Cargo.toml": REJECTED_MANIFESTS["dependency"][0],
            "target/debug/build.rs": SEAL_USE,
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
    for case, (text, reason) in REJECTED_MANIFESTS.items():
        result = with_files({"apps/fixture/Cargo.toml": text})
        expect_rejected(f"a {case} enabling the adapter feature", result, reason)
    for case, (relative, text, reason) in REJECTED_SOURCES.items():
        result = with_files({**CRATE_MANIFEST, relative: text})
        expect_rejected(f"the seal in a {case}", result, reason)


if __name__ == "__main__":
    main()
