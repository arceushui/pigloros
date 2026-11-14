#!/usr/bin/env python3
"""Check ADR-110 native Windows family pins and the E16 Linux owner dependency.

Reads the committed manifests and lockfile without invoking Cargo.
The older rustix 0.38 transitive dependency is unrelated and remains allowed.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

VERSION = "1.1.6"
CHECKSUM = "e5e76742e5294153d4dde1207dbec5bdd81eef6fabdc0d2118babadabfd858aa"
SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
TARGET = 'cfg(target_os = "linux")'


def check(lock: dict, owner: dict, workspace: dict) -> list[str]:
    """Return violations of the selected dependency graph and features."""
    errors = []
    packages = lock.get("package", [])
    rustix = [p for p in packages if p.get("name") == "rustix"]
    selected = [p for p in rustix if p.get("version", "").startswith("1.")]
    if len(selected) != 1 or any(
        p.get(key) != value
        for p in selected
        for key, value in [("version", VERSION), ("source", SOURCE), ("checksum", CHECKSUM)]
    ):
        errors.append("expected exactly rustix 1.1.6 with the ADR-110 E16 source/checksum")
    consumers = [p for p in packages if p.get("name") == "pos-owner-bridge"]
    if len(consumers) != 1 or [
        dependency for dependency in consumers[0].get("dependencies", [])
        if dependency.split()[0] == "rustix"
    ] != ["rustix 1.1.6"]:
        errors.append("pos-owner-bridge must resolve the pinned rustix 1.1.6")
    expected = {"workspace": True, "features": ["process"]}
    targets = owner.get("target", {})
    actual = targets.get(TARGET, {}).get("dependencies", {}).get("rustix")
    if actual != expected:
        errors.append("owner rustix must inherit the workspace with only process on Linux")
    for target, table in [(None, owner), *targets.items()]:
        for kind in ["dependencies", "dev-dependencies", "build-dependencies"]:
            for name, dependency in table.get(kind, {}).items():
                is_rustix = name == "rustix" or (
                    isinstance(dependency, dict) and dependency.get("package") == "rustix"
                )
                if is_rustix and (target, kind, name) != (TARGET, "dependencies", "rustix"):
                    errors.append("owner rustix is allowed only as the named Linux normal dependency")
    expected_workspace = {
        "version": "1.1.4",
        "default-features": False,
        "features": ["fs", "std"],
    }
    if workspace.get("workspace", {}).get("dependencies", {}).get("rustix") != expected_workspace:
        errors.append("the shared rustix requirement/features must retain the accepted workspace entry")
    return errors


WINDOWS_TARGET = "cfg(windows)"
WINDOWS_PINS = {
    "windows": ("0.62.2", "527fadee13e0c05939a6a05d5bd6eec6cd2e3dbd648b9f8e447c6518133d8580"),
    "windows-core": ("0.62.2", "b8e83a14d34d0623b51dce9581199302a221863196a1dde71a7663a4c2be9deb"),
    "windows-implement": ("0.60.2", "053e2e040ab57b9dc951b72c264860db7eb3b0200ba345b4e4c3b14f67855ddf"),
    "windows-interface": ("0.59.3", "3f316c4a2570ba26bbec722032c4099d8c8bc095efccdc15688708623367e358"),
}
WEBVIEW_PINS = {
    "webview2-com": ("0.39.1", "3f89fca7a704cee10dcb3654c1dbb8941d1783132f1917358af75bec37a7d7e6"),
    "webview2-com-sys": ("0.39.1", "b3a07132775117d6065853d9d1178157b8c90e228de47129d6bce2c7edebedfb"),
    "webview2-com-macros": ("0.8.1", "67a921c1b6914c367b2b823cd4cde6f96beec77d30a939c8199bb377cf9b9b54"),
}
COMPANIONS = (WINDOWS_PINS.keys() | WEBVIEW_PINS.keys()) - {"windows", "webview2-com"}


def check_windows(lock: dict, shim: dict, workspace: dict) -> list[str]:
    """Enforce consumed pins; unused WebView crates must not be introduced early."""
    errors = []
    packages = lock.get("package", [])
    shared = workspace.get("workspace", {}).get("dependencies", {})
    target_deps = shim.get("target", {}).get(WINDOWS_TARGET, {}).get("dependencies", {})
    if shared.get("windows") != {
        "version": "=0.62.2", "default-features": False, "features": ["std"]
    }:
        errors.append("windows must retain the accepted exact workspace pin and std-only shared features")
    windows = target_deps.get("windows")
    if not isinstance(windows, dict) or windows.get("workspace") is not True or set(windows) != {"workspace", "features"}:
        errors.append("shim windows must inherit the named Windows-only normal dependency")
    webview = target_deps.get("webview2-com")
    enabled = webview is not None
    if enabled and (webview != {"workspace": True} or shared.get("webview2-com") != "=0.39.1"):
        errors.append("webview2-com must inherit exactly =0.39.1 without features or companion pins")
    if not enabled and "webview2-com" in shared:
        errors.append("do not declare an unused webview2-com workspace pin before its shim consumer")
    selected = WINDOWS_PINS | (WEBVIEW_PINS if enabled else {})
    for name, (version, checksum) in selected.items():
        actual = [p for p in packages if p.get("name") == name]
        if len(actual) != 1 or any(
            p.get(key) != expected for p in actual
            for key, expected in [("version", version), ("checksum", checksum), ("source", SOURCE)]
        ):
            errors.append(f"expected exactly {name} {version} with its ADR-110 source/checksum")
    if not enabled and any(p.get("name") in WEBVIEW_PINS for p in packages):
        errors.append("unconsumed WebView crates must not be added to the lockfile")
    for package in packages:
        name = package.get("name", "")
        if name in {"openssl", "openssl-sys", "openssl-src", "tauri", "wry"} or name.startswith("webauthn-rs"):
            errors.append(f"ADR-110 prohibits dependency {name}")
    for name, dependency in shared.items():
        actual = dependency.get("package", name) if isinstance(dependency, dict) else name
        if actual in COMPANIONS:
            errors.append(f"{actual} is a transitive companion, never a direct workspace pin")
    for target, table in [(None, shim), *shim.get("target", {}).items()]:
        for kind in ["dependencies", "dev-dependencies", "build-dependencies"]:
            for name, dependency in table.get(kind, {}).items():
                actual = dependency.get("package", name) if isinstance(dependency, dict) else name
                if actual in COMPANIONS:
                    errors.append(f"shim must not directly depend on companion {actual}")
                if actual in {"windows", "webview2-com"} and (target, kind, name) != (WINDOWS_TARGET, "dependencies", actual):
                    errors.append(f"shim {actual} is allowed only as the named Windows normal dependency")
    consumers = [p for p in packages if p.get("name") == "pos-owner-bridge-windows"]
    if len(consumers) != 1:
        errors.append("the Windows shim must have exactly one lockfile entry")
    else:
        direct = [d.split()[0] for d in consumers[0].get("dependencies", [])]
        for name, expected in [("windows", True), ("webview2-com", enabled)]:
            if direct.count(name) != int(expected):
                errors.append(f"shim lockfile resolution for {name} disagrees with its consumed manifest")
        if set(direct) & COMPANIONS:
            errors.append("shim lockfile must not resolve a direct companion edge")
    return errors


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    try:
        documents = [
            tomllib.loads((root / name).read_text(encoding="utf-8"))
            for name in ["Cargo.lock", "crates/pos-owner-bridge/Cargo.toml", "Cargo.toml", "crates/pos-owner-bridge-windows/Cargo.toml"]
        ]
        errors = check(*documents[:3]) + check_windows(documents[0], documents[3], documents[2])
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print(f"owner-bridge lock check failed: {error}", file=sys.stderr)
        return 1
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("owner-bridge native Windows family and E16 Linux dependency pins match ADR-110")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
