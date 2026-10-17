#!/usr/bin/env python3
"""Restrict the ADR-119 composition fallback registry to the trusted host (slice #663).

`CompositionFallbackRegistryV1` is a trusted-host port: a registry that retains untruthful
rows, or a caller-made receipt, could switch the implementation a composition runs.
`composition.fallback.declare` and `composition.fallback.activate` are host-native grants that
are never given to a Plugin (ADR-119 section 4.3). This checker enforces, on the
comment-stripped source of every `.rs` file outside the top-level build and tooling directories:

1. Implementations of the port, and struct-literal constructions of its row, state, entry,
   Event-identity, ledger, and receipt types, are allowed only in `crates/pos-store/src/`.
   Renaming the port with `use ... as` elsewhere is rejected too.
2. The adapter-independent decision module (`composition_fallback_registry::logic`) is named
   only under `crates/pos-store/`.
3. Non-test call sites of `declare`, `activate`, and `provision_fallback_registry` are allowed
   only in `crates/pos-store/`, `crates/pos-runtime/` (the runtime `declare`, slice 4), and
   `crates/pos-plugin-supervisor/` (the composition boundary transaction, slice 6). Files under
   a `tests` directory, `test-support` fixture files gated by the leading inner attribute
   `#![cfg(any(test, feature = "test-support"))]`, and `#[cfg(test)]` items are tests. A file
   can call a method of the port only after naming the trait or glob importing its module, so
   method names are checked only in such files.
4. The port is not Linux-only (ADR-119 section 4.3): no reference to the registry modules from a
   `pos-store` source file sits under a `cfg` attribute that names `target_os`, and the registry
   modules themselves name no `target_os`.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from check_plugin_trust_registry_impls import strip_test_items
from check_trusted_clock_port_impls import FIXTURE_GATE, SKIPPED_PARTS, strip_comments

PORT = "CompositionFallbackRegistryV1"
STORE_SOURCE = "crates/pos-store/src/"
STORE_CRATE = "crates/pos-store/"
CALLER_PREFIXES = (STORE_CRATE, "crates/pos-runtime/", "crates/pos-plugin-supervisor/")
OPAQUE_TYPES = (
    "FallbackRegistryRowV1",
    "FallbackRegistryStateV1",
    "FallbackEntryStateV1",
    "FallbackEventIdentityV1",
    "FallbackLedgerRowV1",
    "FallbackCommitReceiptV1",
)
REGISTRY_MODULE = re.compile(
    r"^crates/pos-store/src/"
    r"(?:composition_fallback_registry/.+|(?:memory|sqlite)/composition_fallback_registry[^/]*\.rs)$"
)
REGISTRY_REFERENCE = re.compile(r"\bcomposition_fallback_registry")
TARGET_OS = re.compile(r"\btarget_os\b")
TARGET_OS_ATTRIBUTE = re.compile(r"^\s*#\[cfg(?:_attr)?\(.*\btarget_os\b.*\)\]\s*$")
IMPL = re.compile(
    r"\bimpl\b(?:\s*<[^{;]*?>)?[^{;]*?\b" + PORT + r"\b(?:\s*<[^{;]*?>)?\s+for\b",
    re.DOTALL,
)
ALIAS = re.compile(r"\buse\b[^;]*?\b" + PORT + r"\s+as\b", re.DOTALL)
LITERAL = re.compile(r"\b(" + "|".join(OPAQUE_TYPES) + r")\s*\{")
LITERAL_PREFIX = re.compile(r"(?:->\s*&?|\b(?:struct|enum|impl|for|trait|type|dyn))\s*$")
LOGIC = re.compile(r"\bcomposition_fallback_registry\s*::\s*(?:\{[^}]*\blogic\b|logic\b)")
# A method call, a path call (`MemoryStore::declare(..)`), or a qualified call
# (`<S as CompositionFallbackRegistryV1>::activate(..)`).
CALL = re.compile(r"(?:\.|::)\s*(?:declare|activate|provision_fallback_registry)\s*\(")
AWARE = re.compile(r"\b" + PORT + r"\b|\bcomposition_fallback_registry\s*::\s*\*")


def has_target_os_gate(lines: list[str], number: int) -> bool:
    """Return whether the attribute lines directly above `lines[number]` name `target_os`."""
    above = number - 1
    while above >= 0:
        if TARGET_OS_ATTRIBUTE.match(lines[above]):
            return True
        if lines[above].strip() and not lines[above].lstrip().startswith("#["):
            return False
        above -= 1
    return False


def platform_findings(relative: str, code: str) -> list[str]:
    """Rule 4: the registry is never confined to one target OS."""
    if REGISTRY_MODULE.match(relative):
        return [f"{relative}: registry module names target_os"] if TARGET_OS.search(code) else []
    if not relative.startswith(STORE_SOURCE):
        return []
    lines = code.splitlines()
    return [
        f"{relative}:{number + 1}: registry item is under a target_os cfg"
        for number, line in enumerate(lines)
        if REGISTRY_REFERENCE.search(line) and has_target_os_gate(lines, number)
    ]


def construction_findings(relative: str, code: str) -> list[str]:
    """Rule 1: implementations, aliases, and struct literals outside the adapters."""
    found: list[str] = []
    if IMPL.search(code):
        found.append(f"{relative}: composition fallback registry implemented outside pos-store")
    if ALIAS.search(code):
        found.append(f"{relative}: composition fallback registry port aliased outside pos-store")
    for match in LITERAL.finditer(code):
        if LITERAL_PREFIX.search(code[: match.start()]) is None:
            found.append(f"{relative}: {match.group(1)} constructed outside pos-store")
            break
    return found


def file_findings(relative: str, code: str) -> list[str]:
    """Return every rule violation of one comment-stripped source file."""
    gated = FIXTURE_GATE.match(code) is not None
    is_test = gated or "tests" in Path(relative).parts
    live = strip_test_items(code)
    found = platform_findings(relative, code)
    if not relative.startswith(STORE_SOURCE):
        found.extend(construction_findings(relative, code))
    if not relative.startswith(STORE_CRATE) and LOGIC.search(code):
        found.append(f"{relative}: registry decision module named outside pos-store")
    aware = AWARE.search(live) is not None
    caller = relative.startswith(CALLER_PREFIXES)
    if not is_test and not caller and aware and CALL.search(live):
        found.append(f"{relative}: registry write called outside the trusted host")
    return found


def violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        relative_path = path.relative_to(root)
        if relative_path.parts[0] in SKIPPED_PARTS:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        found.extend(file_findings(relative_path.as_posix(), strip_comments(text)))
    return found


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    found = violations(root)
    if found:
        raise SystemExit("\n".join(found))
    print("the composition fallback registry is confined to the trusted host")


if __name__ == "__main__":
    main()
