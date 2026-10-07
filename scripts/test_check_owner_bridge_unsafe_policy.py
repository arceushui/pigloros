#!/usr/bin/env python3
"""Adversarial tests for the ADR-110 Windows unsafe-boundary checker."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_owner_bridge_unsafe_policy.py"
SPEC = importlib.util.spec_from_file_location("owner_bridge_unsafe_policy", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load owner-bridge unsafe-policy checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

SHIM = "crates/pos-owner-bridge-windows"

ROOT_MANIFEST = '''
[workspace]
members = ["crates/safe", "crates/pos-owner-bridge-windows"]

[workspace.lints.rust]
unsafe_code = "forbid"
warnings = { level = "deny", priority = -2 }
future_incompatible = { level = "deny", priority = -1 }
rust_2024_compatibility = { level = "deny", priority = -1 }
unexpected_cfgs = { level = "warn", check-cfg = ["cfg(coverage_nightly)", "cfg(coverage)"] }
unreachable_pub = "warn"

[workspace.lints.clippy]
all = "deny"
pedantic = "deny"
nursery = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
unreachable = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
exit = "deny"
mem_forget = "deny"
let_underscore_must_use = "deny"
'''

SHIM_MANIFEST = '''
[package]
name = "pos-owner-bridge-windows"
version = "0.1.0"

[lints.rust]
unsafe_code = "allow"
warnings = { level = "deny", priority = -2 }
future_incompatible = { level = "deny", priority = -1 }
rust_2024_compatibility = { level = "deny", priority = -1 }
unexpected_cfgs = { level = "warn", check-cfg = ["cfg(coverage_nightly)", "cfg(coverage)"] }
unreachable_pub = "warn"
unsafe_op_in_unsafe_fn = "deny"

[lints.clippy]
all = "deny"
pedantic = "deny"
nursery = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
unreachable = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
exit = "deny"
mem_forget = "deny"
let_underscore_must_use = "deny"
undocumented_unsafe_blocks = "deny"
multiple_unsafe_ops_per_block = "deny"
'''

SAFE_MANIFEST = '''
[package]
name = "safe"
version = "0.1.0"

[lints]
workspace = true
'''

SAFE_LIB = "#![forbid(unsafe_code)]\npub fn safe() {}\n"
SHIM_LIB = "#![cfg(windows)]\n#![forbid(unsafe_code)]\n"
EMPTY_INVENTORY = "# No FFI unsafe block has been added yet.\n"


def write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def fixture(extra: dict[str, str] | None = None) -> list[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        files = {
            "Cargo.toml": ROOT_MANIFEST,
            "crates/safe/Cargo.toml": SAFE_MANIFEST,
            "crates/safe/src/lib.rs": SAFE_LIB,
            f"{SHIM}/Cargo.toml": SHIM_MANIFEST,
            f"{SHIM}/src/lib.rs": SHIM_LIB,
            f"{SHIM}/unsafe-inventory.toml": EMPTY_INVENTORY,
        }
        for relative, content in {**files, **(extra or {})}.items():
            write(root, relative, content)
        return CHECKER.violations(root)


def require_rejected(name: str, extra: dict[str, str], needle: str) -> None:
    found = fixture(extra)
    if not any(needle in violation for violation in found):
        raise SystemExit(f"{name} was not rejected: {found}")


def main() -> None:
    if found := fixture():
        raise SystemExit(f"accepted fixture was rejected: {found}")
    require_rejected(
        "safe crate unsafe operation",
        {"crates/safe/src/lib.rs": "pub fn forged() { unsafe {} }\n"},
        "unsafe is reserved",
    )
    require_rejected(
        "safe crate unsafe lint override",
        {"crates/safe/Cargo.toml": SAFE_MANIFEST + "\n[lints.rust]\nunsafe_code = \"allow\"\n"},
        "non-shim crate configures unsafe_code",
    )
    require_rejected(
        "missing safe-module forbid",
        {f"{SHIM}/src/host.rs": "#![cfg(windows)]\npub fn host() {}\n"},
        "non-ffi module must forbid unsafe_code",
    )
    require_rejected(
        "ffi block missing inventory",
        {
            f"{SHIM}/src/ffi/ops.rs": (
                "#![cfg(windows)]\npub fn call() {\n// SAFETY: fixture.\nunsafe {}\n}\n"
            )
        },
        "missing record",
    )
    require_rejected(
        "ffi block missing safety comment",
        {
            f"{SHIM}/src/ffi/ops.rs": "#![cfg(windows)]\npub fn call() {\nunsafe {}\n}\n",
            f"{SHIM}/unsafe-inventory.toml": (
                "[[block]]\nfile = \"src/ffi/ops.rs\"\nline = 3\nfunction = \"call\"\n"
                "operation = \"fixture\"\ninvariant = \"fixture\"\nhosted_test = \"ffi_fixture\"\n"
            ),
            f"{SHIM}/tests/ffi.rs": "fn ffi_fixture() {}\n",
        },
        "lacks // SAFETY:",
    )
    allowed = fixture(
        {
            f"{SHIM}/src/ffi/ops.rs": (
                "#![cfg(windows)]\npub fn call() {\n// SAFETY: fixture.\nunsafe {}\n}\n"
            ),
            f"{SHIM}/unsafe-inventory.toml": (
                "[[block]]\nfile = \"src/ffi/ops.rs\"\nline = 4\nfunction = \"call\"\n"
                "operation = \"fixture\"\ninvariant = \"fixture\"\nhosted_test = \"ffi_fixture\"\n"
            ),
            f"{SHIM}/tests/ffi.rs": "fn ffi_fixture() {}\n",
        }
    )
    if allowed:
        raise SystemExit(f"fully inventoried FFI fixture was rejected: {allowed}")
    require_rejected(
        "stale inventory record",
        {
            f"{SHIM}/unsafe-inventory.toml": (
                "[[block]]\nfile = \"src/ffi/ops.rs\"\nline = 4\nfunction = \"call\"\n"
                "operation = \"fixture\"\ninvariant = \"fixture\"\nhosted_test = \"ffi_fixture\"\n"
            )
        },
        "stale record",
    )
    require_rejected(
        "unsafe function declaration",
        {f"{SHIM}/src/ffi/ops.rs": "#![cfg(windows)]\npub unsafe fn call() {}\n"},
        "unsafe must be an explicit block",
    )
    print("owner-bridge unsafe-policy checker rejects every forged boundary")


if __name__ == "__main__":
    main()
