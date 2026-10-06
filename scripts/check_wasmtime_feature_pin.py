#!/usr/bin/env python3
"""Fail unless Wasmtime resolves to the ADR-061 revision 4 pin and features.

ADR-061 revision 4 decision 2 pins Wasmtime with an exact `=` version and
`default-features = false`, enabling `component-model` and `cranelift` plus
only what Cargo needs them to imply. `runtime` is the feature that lets a
Component be instantiated and called, and `cranelift` implies `std`.

The check reads `cargo metadata --format-version 1` JSON (stdin or a path) and
requires that:
- exactly one Wasmtime package resolves, at the pinned version, from crates.io;
- only `pos-plugin-host` depends on it, with the exact requirement, default
  features off and exactly the requested features;
- the resolved feature set is exactly the recorded one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CRATE = "wasmtime"
HOST_PACKAGE = "pos-plugin-host"
VERSION = "49.0.2"
REQUIREMENT = "=49.0.2"
SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
REQUESTED_FEATURES = ["component-model", "cranelift", "runtime"]
RESOLVED_FEATURES = ["component-model", "cranelift", "runtime", "std"]


def check(metadata: dict) -> list[str]:
    """Return every violation of the pin found in `metadata`."""
    errors: list[str] = []
    packages = metadata.get("packages", [])
    pinned = [package for package in packages if package.get("name") == CRATE]
    if len(pinned) != 1:
        return [f"expected exactly one {CRATE} package, found {len(pinned)}"]
    package = pinned[0]
    if package.get("version") != VERSION:
        errors.append(f"{CRATE} resolved to {package.get('version')}, not {VERSION}")
    if package.get("source") != SOURCE:
        errors.append(f"{CRATE} comes from {package.get('source')}, not crates.io")

    dependents = sorted(
        candidate.get("name", "")
        for candidate in packages
        if any(dep.get("name") == CRATE for dep in candidate.get("dependencies", []))
    )
    if dependents != [HOST_PACKAGE]:
        errors.append(f"only {HOST_PACKAGE} may depend on {CRATE}, found {dependents}")
    for candidate in packages:
        if candidate.get("name") != HOST_PACKAGE:
            continue
        for dep in candidate.get("dependencies", []):
            if dep.get("name") != CRATE:
                continue
            if dep.get("req") != REQUIREMENT:
                errors.append(f"requirement {dep.get('req')} is not {REQUIREMENT}")
            if dep.get("uses_default_features") is not False:
                errors.append("default features must be disabled")
            if sorted(dep.get("features", [])) != REQUESTED_FEATURES:
                errors.append(f"requested features {dep.get('features')} changed")

    nodes = [
        node
        for node in metadata.get("resolve", {}).get("nodes", [])
        if node.get("id") == package.get("id")
    ]
    if len(nodes) != 1:
        errors.append(f"{CRATE} has {len(nodes)} resolve nodes, expected 1")
    elif sorted(nodes[0].get("features", [])) != RESOLVED_FEATURES:
        errors.append(
            f"resolved features {sorted(nodes[0].get('features', []))} "
            f"are not {RESOLVED_FEATURES}"
        )
    return errors


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print("usage: check_wasmtime_feature_pin.py [METADATA_JSON]", file=sys.stderr)
        return 2
    text = Path(argv[1]).read_text(encoding="utf-8") if len(argv) == 2 else sys.stdin.read()
    errors = check(json.loads(text))
    for error in errors:
        print(f"wasmtime pin: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"{CRATE} {VERSION} resolves with exactly {RESOLVED_FEATURES}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
