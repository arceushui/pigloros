#!/usr/bin/env python3
"""Restrict the ADR-103 revision 4 Plugin trust policy registry to the trusted composition.

`PluginTrustPolicyRegistryV1` is a trusted-host port: a registry that retains
untruthful state, a forged trusted UTC second, or a caller-made receipt can
mint Plugin admission authority. This checker enforces, on the comment-stripped
source of every `.rs` file outside the top-level build and tooling directories:

1. Implementations of the port, constructions of `TrustedUtcSecondV1`, and
   struct-literal constructions of the retained, receipt, and ledger types are
   allowed only in `crates/pos-store`, `crates/pos-runtime`, or a
   `test-support` fixture file whose module is gated by the leading inner
   attribute `#![cfg(any(test, feature = "test-support"))]`. Renaming a guarded
   name with `use ... as` elsewhere is rejected too.
2. Non-test call sites of `PluginTrustPolicyAnchorV1::new`, `provision`, and
   `advance_policy` follow the same allow-list. Files under a `tests`
   directory, gated fixture files, and `#[cfg(test)]` items are tests.
3. `admit` and `rollback` may be called only from tests and `test-support`
   fixtures (decision 1), with one exception: the signed installer module
   `crates/pos-plugin-publisher/src/install.rs` (#573) is the only non-test
   call site of `admit`, and the only non-test file that may construct
   `TrustedUtcSecondV1` outside the trusted host, because it verifies the
   PMF1 release signature before it calls `admit`. It may not call
   `rollback`, `provision`, or `advance_policy`, nor implement the port. Any
   other call site, including one inside `pos-store`, is rejected. A file can
   call a method of the port only after naming the trait or glob importing
   its module, so method names are checked only in such files.
4. Every public item of the registry modules (functions, types, constants,
   fields, enum variants, and re-exports) is linted against the forbidden-name
   list: no name may contain `signature`, `verified_signature`, `is_admitted`,
   `is_live`, `live_authority`, or `authorize_from_receipt`, because no
   registry type claims signature validity or live authority.
5. Every reference to the registry modules from another `pos-store` file sits
   under a `cfg` attribute that names `target_os = "linux"`: non-Linux builds
   expose no admission surface.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from check_trusted_clock_port_impls import (
    FIXTURE_GATE,
    SKIPPED_PARTS,
    _literal_end,
    strip_comments,
)

PORT = "PluginTrustPolicyRegistryV1"
ALLOWED_PREFIXES = ("crates/pos-store/", "crates/pos-runtime/")
INSTALLER_FILE = "crates/pos-plugin-publisher/src/install.rs"
GUARDED_NAMES = (PORT, "TrustedUtcSecondV1", "PluginTrustPolicyAnchorV1")
RECEIPT_TYPES = (
    "AdmittedPluginReleaseReceiptV1",
    "PluginRollbackReceiptV1",
    "RetainedReleaseDecisionV1",
    "RetainedPolicyStateV1",
    "ActiveReleaseV1",
    "PluginTrustLedgerRowV1",
    "ActivationEventIdentityV1",
    "RollbackFactsV1",
)
FORBIDDEN_TERMS = (
    "signature",
    "verified_signature",
    "is_admitted",
    "is_live",
    "live_authority",
    "authorize_from_receipt",
)
REGISTRY_MODULE = re.compile(
    r"^crates/pos-store/src/"
    r"(?:plugin_trust_registry/.+|(?:memory|sqlite)/plugin_trust_registry[^/]*\.rs)$"
)
REGISTRY_REFERENCE = re.compile(r"\bplugin_trust_registry\b")
LINUX_ATTRIBUTE = re.compile(r'^\s*#\[cfg\(.*target_os\s*=\s*"linux".*\)\]\s*$')
TEST_ATTRIBUTE = re.compile(
    r'#\[cfg\((?:test|any\(\s*test\s*,\s*feature\s*=\s*"test-support"\s*\))\)\]'
)
IMPL = re.compile(
    r"\bimpl\b(?:\s*<[^{;]*?>)?[^{;]*?\b" + PORT + r"\b(?:\s*<[^{;]*?>)?\s+for\b",
    re.DOTALL,
)
ALIAS = re.compile(r"\buse\b[^;]*?\b(?:" + "|".join(GUARDED_NAMES) + r")\s+as\b", re.DOTALL)
UTC_CONSTRUCTION = re.compile(r"\bTrustedUtcSecondV1\s*::\s*from_source\b")
RECEIPT_LITERAL = re.compile(r"\b(" + "|".join(RECEIPT_TYPES) + r")\s*\{")
LITERAL_PREFIX = re.compile(r"(?:->\s*&?|\b(?:struct|enum|impl|for|trait|type|dyn))\s*$")
ANCHOR_CALL = re.compile(r"\bPluginTrustPolicyAnchorV1\s*::\s*new\s*\(")
# A method call, a path call (`MemoryStore::admit(..)`), or a qualified call
# (`<S as PluginTrustPolicyRegistryV1>::admit(..)`).
SETUP_CALL = re.compile(r"(?:\.|::)\s*(?:provision|advance_policy)\s*\(")
ADMISSION_CALL = re.compile(r"(?:\.|::)\s*(?:admit|rollback)\s*\(")
ROLLBACK_CALL = re.compile(r"(?:\.|::)\s*rollback\s*\(")
REGISTRY_AWARE = re.compile(r"\b" + PORT + r"\b|\bplugin_trust_registry\s*::\s*\*")
PUBLIC_ITEM = re.compile(
    r"\bpub\s+(?:const\s+)?(?:unsafe\s+)?(?:async\s+)?"
    r"(?:fn|struct|enum|trait|type|const|static|mod)\s+(\w+)"
)
PUBLIC_FIELD = re.compile(
    r"\bpub\s+(?!(?:fn|struct|enum|trait|type|const|static|mod|use|unsafe|async|extern)\b)"
    r"([A-Za-z_]\w*)\s*:"
)
PUBLIC_USE = re.compile(r"\bpub\s+use\b([^;]*);")
PUBLIC_ENUM = re.compile(r"\bpub\s+enum\s+\w+[^{;]*\{")
OPENERS = {"(": ")", "[": "]", "{": "}"}


def _advance(code: str, index: int) -> int:
    """Return the index after the character, string, or char literal at `index`."""
    end = _literal_end(code, index)
    return end if end != index else index + 1


def _balanced_end(code: str, index: int) -> int:
    """Return the index after the bracket group opened at `code[index]`."""
    depth = 0
    while index < len(code):
        if code[index] in OPENERS:
            depth += 1
        elif code[index] in OPENERS.values():
            depth -= 1
            if depth == 0:
                return index + 1
        index = _advance(code, index)
    return len(code)


def _item_end(code: str, index: int) -> int:
    """Return the index after the item whose attributes end at `index`."""
    while index < len(code) and code[index] not in "{;":
        index = _advance(code, index)
    if index >= len(code):
        return len(code)
    return index + 1 if code[index] == ";" else _balanced_end(code, index)


def strip_test_items(code: str) -> str:
    """Remove items gated by `#[cfg(test)]` or the `test-support` gate."""
    kept: list[str] = []
    index = 0
    while True:
        match = TEST_ATTRIBUTE.search(code, index)
        if match is None:
            kept.append(code[index:])
            return "".join(kept)
        kept.append(code[index : match.start()])
        index = _item_end(code, match.end())


def top_level_chunks(body: str) -> list[str]:
    """Split an enum body on its depth-0 commas, ignoring literals and groups."""
    chunks: list[str] = []
    start = 0
    index = 0
    while index < len(body):
        if body[index] in OPENERS:
            index = _balanced_end(body, index)
        elif body[index] == ",":
            chunks.append(body[start:index])
            start = index = index + 1
        else:
            index = _advance(body, index)
    chunks.append(body[start:])
    return chunks


def variant_name(chunk: str) -> str | None:
    """Return the variant identifier of one enum chunk, after its attributes."""
    index = 0
    while index < len(chunk):
        if chunk.startswith("#", index):
            index = _balanced_end(chunk, chunk.index("[", index))
        elif chunk[index].isspace():
            index += 1
        else:
            match = re.match(r"\w+", chunk[index:])
            return match.group(0) if match else None
    return None


def public_names(code: str) -> list[str]:
    """Return the names of every public item, field, enum variant, and re-export."""
    names = PUBLIC_ITEM.findall(code) + PUBLIC_FIELD.findall(code)
    for use in PUBLIC_USE.findall(code):
        names.extend(re.findall(r"\w+", use))
    for match in PUBLIC_ENUM.finditer(code):
        body = code[match.end() : _balanced_end(code, match.end() - 1) - 1]
        names.extend(
            name for name in map(variant_name, top_level_chunks(body)) if name is not None
        )
    return names


def snake_case(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def forbidden_name_findings(relative: str, code: str) -> list[str]:
    found: list[str] = []
    for name in public_names(code):
        spellings = {name.lower(), snake_case(name)}
        for term in FORBIDDEN_TERMS:
            if any(term in spelling for spelling in spellings):
                found.append(f"{relative}: public name `{name}` contains forbidden term `{term}`")
                break
    return found


def has_linux_gate(lines: list[str], number: int) -> bool:
    """Return whether the attribute lines directly above `lines[number]` name Linux."""
    above = number - 1
    while above >= 0:
        if LINUX_ATTRIBUTE.match(lines[above]):
            return True
        if lines[above].strip() and not lines[above].lstrip().startswith("#["):
            return False
        above -= 1
    return False


def linux_gate_findings(relative: str, code: str) -> list[str]:
    """Require a `target_os = "linux"` cfg attribute above every registry reference."""
    lines = code.splitlines()
    return [
        f'{relative}:{number + 1}: registry item is not under cfg(target_os = "linux")'
        for number, line in enumerate(lines)
        if REGISTRY_REFERENCE.search(line) and not has_linux_gate(lines, number)
    ]


def construction_findings(relative: str, code: str, installer: bool) -> list[str]:
    found: list[str] = []
    if not installer and UTC_CONSTRUCTION.search(code):
        found.append(f"{relative}: TrustedUtcSecondV1 constructed outside the trusted host")
    for match in RECEIPT_LITERAL.finditer(code):
        if LITERAL_PREFIX.search(code[: match.start()]) is None:
            found.append(f"{relative}: {match.group(1)} constructed outside the trusted host")
            break
    return found


def file_findings(relative: str, code: str) -> list[str]:
    """Return every rule violation of one comment-stripped source file."""
    gated = FIXTURE_GATE.match(code) is not None
    trusted = relative.startswith(ALLOWED_PREFIXES) or gated
    is_test = gated or "tests" in Path(relative).parts
    live = strip_test_items(code)
    aware = REGISTRY_AWARE.search(live) is not None
    installer = relative == INSTALLER_FILE
    found: list[str] = []
    if REGISTRY_MODULE.match(relative):
        found.extend(forbidden_name_findings(relative, live))
    elif relative.startswith("crates/pos-store/src/"):
        found.extend(linux_gate_findings(relative, live))
    if not trusted:
        if IMPL.search(code):
            found.append(f"{relative}: Plugin trust registry implemented outside the trusted host")
        if ALIAS.search(code):
            found.append(f"{relative}: Plugin trust registry name aliased outside the trusted host")
        found.extend(construction_findings(relative, code, installer))
        if not is_test and (ANCHOR_CALL.search(live) or (aware and SETUP_CALL.search(live))):
            found.append(f"{relative}: registry anchor or setup call outside the trusted host")
    call = ROLLBACK_CALL if installer else ADMISSION_CALL
    if not is_test and aware and call.search(live):
        found.append(f"{relative}: admit or rollback called outside tests and the installer")
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
    print("the Plugin trust registry is confined to the trusted composition")


if __name__ == "__main__":
    main()
