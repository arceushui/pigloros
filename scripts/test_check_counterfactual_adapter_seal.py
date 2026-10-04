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
SEAL_USE = "let seal = pos_core::CounterfactualAdapterSealV1::for_adapter();\n"

ALLOWED_MANIFESTS = {
    "crates/pos-store/Cargo.toml": "[dependencies]\n" + ENABLING,
    "crates/pos-runtime/Cargo.toml": DEV_ONLY,
    "crates/pos-core/Cargo.toml": '[features]\ncounterfactual-adapter = []\n',
}

REJECTED_MANIFESTS = {
    "dependency": "[dependencies]\n" + ENABLING,
    "build dependency": "[build-dependencies]\n" + ENABLING,
    "target dependency": "[target.'cfg(unix)'.dependencies]\n" + ENABLING,
    "workspace dependency": "[workspace.dependencies]\n"
    + 'pos-core = { path = "crates/pos-core", features = ["counterfactual-adapter"] }\n',
    "forwarding feature": '[features]\nadapters = ["pos-core/counterfactual-adapter"]\n',
    "default feature": '[features]\ndefault = ["seal"]\nseal = ["counterfactual-adapter"]\n'
    + "counterfactual-adapter = []\n",
}

ALLOWED_SOURCES = {
    "crates/pos-store/src/memory.rs": SEAL_USE,
    "crates/pos-core/src/counterfactual_store.rs": SEAL_USE,
    "crates/pos-runtime/tests/coordinator.rs": SEAL_USE,
    "crates/pos-runtime/src/coordinator.rs": "// CounterfactualAdapterSealV1 is adapter-only.\n",
}

REJECTED_SOURCES = {
    "runtime source": ("crates/pos-runtime/src/coordinator.rs", SEAL_USE),
    "tests-named file": ("crates/pos-runtime/src/tests.rs", SEAL_USE),
    "nested crate": ("apps/fixture/crates/pos-store/src/lib.rs", SEAL_USE),
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
            "target/debug/Cargo.toml": REJECTED_MANIFESTS["dependency"],
            "target/debug/build.rs": SEAL_USE,
        }
        for relative, text in {**ignored, **files}.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return invoke(root)


def main() -> None:
    repository = invoke(ROOT)
    if repository.returncode != 0:
        raise SystemExit(f"repository violates policy:\n{repository.stderr}")
    allowed = with_files({**ALLOWED_MANIFESTS, **ALLOWED_SOURCES})
    if allowed.returncode != 0:
        raise SystemExit(f"checker rejected an allowed use:\n{allowed.stderr}")
    for case, text in REJECTED_MANIFESTS.items():
        if with_files({"apps/fixture/Cargo.toml": text}).returncode == 0:
            raise SystemExit(f"checker accepted {case} enabling the adapter feature")
    for case, (relative, text) in REJECTED_SOURCES.items():
        if with_files({relative: text}).returncode == 0:
            raise SystemExit(f"checker accepted the seal in a {case}")


if __name__ == "__main__":
    main()
