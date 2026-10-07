#!/usr/bin/env python3
"""Enforce the ADR-110 Windows owner-bridge unsafe boundary.

Only ``pos-owner-bridge-windows`` may opt out of the workspace's
``unsafe_code = \"forbid\"`` lint. Its manifest copies the workspace lint
tables exactly except for the four ADR-approved entries, and only its
``src/ffi`` modules may contain explicit unsafe blocks. Each such block needs
an adjacent ``// SAFETY:`` explanation and a matching record in
``unsafe-inventory.toml`` that names a hosted test function.

This is deliberately source-based. The Windows shim compiles to nothing on
Linux, so a Linux-only compiler or geiger run cannot audit its FFI boundary.
"""

from __future__ import annotations

import argparse
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


SHIM = "crates/pos-owner-bridge-windows"
INVENTORY = "unsafe-inventory.toml"
REQUIRED_BLOCK_FIELDS = ("file", "line", "function", "operation", "invariant", "hosted_test")
UNSAFE_TOKEN = re.compile(r"\bunsafe\b")
UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
RAW_STRING = re.compile(r"(?:br|rb|r)(?P<hashes>#+)?\"")
IDENTIFIER = re.compile(r"[A-Za-z0-9_]")


@dataclass(frozen=True)
class UnsafeBlock:
    """One explicit source-level unsafe block."""

    file: str
    line: int
    offset: int


def _blank(text: str) -> str:
    """Keep line positions while hiding non-code text."""
    return "".join("\n" if character == "\n" else " " for character in text)


def _block_comment_end(text: str, start: int) -> int:
    depth = 0
    index = start
    while index < len(text):
        if text.startswith("/*", index):
            depth += 1
            index += 2
        elif text.startswith("*/", index):
            depth -= 1
            index += 2
            if depth == 0:
                return index
        else:
            index += 1
    return len(text)


def _quoted_end(text: str, start: int, quote: str) -> int:
    index = start + 1
    while index < len(text):
        if text[index] == "\\\\":
            index += 2
        elif text[index] == quote:
            return index + 1
        else:
            index += 1
    return len(text)


def _raw_string_end(text: str, start: int) -> int | None:
    if start and IDENTIFIER.fullmatch(text[start - 1]):
        return None
    match = RAW_STRING.match(text, start)
    if match is None:
        return None
    closing = '"' + (match.group("hashes") or "")
    end = text.find(closing, match.end())
    return len(text) if end < 0 else end + len(closing)


def _char_end(text: str, start: int) -> int | None:
    """Return a simple character-literal end, leaving lifetimes as code."""
    if start + 2 >= len(text):
        return None
    if text[start + 1] == "\\\\":
        return _quoted_end(text, start, "'")
    return start + 3 if text[start + 2] == "'" else None


def code_only(text: str) -> str:
    """Mask comments and literals while preserving source offsets and lines."""
    pieces: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            pieces.append(_blank(text[index:end]))
            index = end
            continue
        if text.startswith("/*", index):
            end = _block_comment_end(text, index)
            pieces.append(_blank(text[index:end]))
            index = end
            continue
        raw_end = _raw_string_end(text, index)
        if raw_end is not None:
            pieces.append(_blank(text[index:raw_end]))
            index = raw_end
            continue
        if text.startswith('b"', index):
            end = _quoted_end(text, index + 1, '"')
            pieces.append(_blank(text[index:end]))
            index = end
            continue
        if text[index] == '"':
            end = _quoted_end(text, index, '"')
            pieces.append(_blank(text[index:end]))
            index = end
            continue
        char_end = _char_end(text, index) if text[index] == "'" else None
        if char_end is not None:
            pieces.append(_blank(text[index:char_end]))
            index = char_end
            continue
        pieces.append(text[index])
        index += 1
    return "".join(pieces)


def _toml(path: Path) -> dict[str, object]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _workspace_members(root_manifest: dict[str, object]) -> tuple[str, ...]:
    workspace = root_manifest.get("workspace")
    if not isinstance(workspace, dict):
        return ()
    members = workspace.get("members")
    if not isinstance(members, list) or not all(isinstance(member, str) for member in members):
        return ()
    return tuple(members)


def _member_manifests(root: Path, members: Iterable[str]) -> Iterable[tuple[str, Path]]:
    for member in members:
        manifest = root / member / "Cargo.toml"
        if manifest.is_file():
            yield member, manifest


def _contains_unsafe_code_lint(value: object) -> bool:
    if isinstance(value, dict):
        return any(key == "unsafe_code" or _contains_unsafe_code_lint(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_unsafe_code_lint(item) for item in value)
    return False


def _rust_files(directory: Path) -> Iterable[Path]:
    if not directory.is_dir():
        return ()
    return (path for path in sorted(directory.rglob("*.rs")) if "target" not in path.parts)


def _expected_shim_lints(root_manifest: dict[str, object]) -> tuple[dict[str, object], dict[str, object]] | None:
    workspace = root_manifest.get("workspace")
    if not isinstance(workspace, dict):
        return None
    lints = workspace.get("lints")
    if not isinstance(lints, dict):
        return None
    rust = lints.get("rust")
    clippy = lints.get("clippy")
    if not isinstance(rust, dict) or not isinstance(clippy, dict):
        return None
    expected_rust = dict(rust)
    expected_rust["unsafe_code"] = "allow"
    expected_rust["unsafe_op_in_unsafe_fn"] = "deny"
    expected_clippy = dict(clippy)
    expected_clippy["undocumented_unsafe_blocks"] = "deny"
    expected_clippy["multiple_unsafe_ops_per_block"] = "deny"
    return expected_rust, expected_clippy


def _has_windows_cfg(text: str) -> bool:
    return bool(re.match(r"\s*#!\[cfg\(windows\)\]", text))


def _has_forbid_unsafe(text: str) -> bool:
    return bool(re.match(r"\s*(?:#!\[[^\]]*\]\s*)*#!\[forbid\(unsafe_code\)\]", text))


def _unsafe_blocks(relative: str, source: str, code: str) -> tuple[UnsafeBlock, ...]:
    return tuple(
        UnsafeBlock(relative, code.count("\n", 0, match.start()) + 1, match.start())
        for match in UNSAFE_BLOCK.finditer(code)
    )


def _has_safety_comment(source: str, block: UnsafeBlock) -> bool:
    lines = source[: block.offset].splitlines()
    return bool(lines and lines[-1].lstrip().startswith("// SAFETY:"))


def _hosted_test_exists(crate: Path, name: str) -> bool:
    expression = re.compile(rf"\b(?:async\s+)?fn\s+{re.escape(name)}\b")
    return any(
        expression.search(code_only(path.read_text(encoding="utf-8", errors="replace")))
        for path in _rust_files(crate / "tests")
    )


def _inventory_blocks(crate: Path, found: list[str]) -> tuple[dict[tuple[str, int], dict[str, object]], ...]:
    path = crate / INVENTORY
    if not path.is_file():
        found.append(f"{SHIM}/{INVENTORY}: missing unsafe inventory")
        return ()
    data = _toml(path)
    blocks = data.get("block", [])
    if not isinstance(blocks, list):
        found.append(f"{SHIM}/{INVENTORY}: block must be an array")
        return ()
    parsed: list[dict[tuple[str, int], dict[str, object]]] = []
    for index, entry in enumerate(blocks, start=1):
        if not isinstance(entry, dict):
            found.append(f"{SHIM}/{INVENTORY}: block {index} is not a table")
            continue
        missing = [field for field in REQUIRED_BLOCK_FIELDS if field not in entry]
        if missing:
            found.append(
                f"{SHIM}/{INVENTORY}: block {index} is missing {', '.join(missing)}"
            )
            continue
        file = entry["file"]
        line = entry["line"]
        strings = tuple(entry[field] for field in REQUIRED_BLOCK_FIELDS if field not in {"file", "line"})
        if (
            not isinstance(file, str)
            or not isinstance(line, int)
            or line < 1
            or not all(isinstance(value, str) and value for value in strings)
        ):
            found.append(f"{SHIM}/{INVENTORY}: block {index} has an invalid field")
            continue
        pure = PurePosixPath(file)
        if pure.is_absolute() or ".." in pure.parts or not file.startswith("src/ffi/") or not file.endswith(".rs"):
            found.append(f"{SHIM}/{INVENTORY}: block {index} has an invalid ffi file path")
            continue
        key = (file, line)
        record = {str(field): value for field, value in entry.items()}
        parsed.append({key: record})
    return tuple(parsed)


def violations(root: Path) -> list[str]:
    """Return every source-policy violation beneath ``root``."""
    found: list[str] = []
    root_manifest_path = root / "Cargo.toml"
    if not root_manifest_path.is_file():
        return ["Cargo.toml: missing workspace manifest"]
    root_manifest = _toml(root_manifest_path)
    members = _workspace_members(root_manifest)
    if SHIM not in members:
        found.append(f"Cargo.toml: workspace must contain {SHIM}")
        return found
    shim = root / SHIM
    shim_manifest_path = shim / "Cargo.toml"
    if not shim_manifest_path.is_file():
        return [f"{SHIM}/Cargo.toml: missing shim manifest"]

    expected = _expected_shim_lints(root_manifest)
    shim_manifest = _toml(shim_manifest_path)
    shim_lints = shim_manifest.get("lints")
    if expected is None or not isinstance(shim_lints, dict):
        found.append(f"{SHIM}/Cargo.toml: cannot verify shim lint tables")
    else:
        actual_rust = shim_lints.get("rust")
        actual_clippy = shim_lints.get("clippy")
        if actual_rust != expected[0]:
            found.append(f"{SHIM}/Cargo.toml: rust lint table differs from ADR-110 policy")
        if actual_clippy != expected[1]:
            found.append(f"{SHIM}/Cargo.toml: clippy lint table differs from ADR-110 policy")

    for member, manifest_path in _member_manifests(root, members):
        if member == SHIM:
            continue
        if _contains_unsafe_code_lint(_toml(manifest_path).get("lints", {})):
            found.append(f"{member}/Cargo.toml: non-shim crate configures unsafe_code")
        for source in _rust_files(manifest_path.parent):
            code = code_only(source.read_text(encoding="utf-8", errors="replace"))
            if UNSAFE_TOKEN.search(code):
                found.append(
                    f"{source.relative_to(root).as_posix()}: unsafe is reserved for {SHIM}/src/ffi"
                )

    actual_blocks: dict[tuple[str, int], UnsafeBlock] = {}
    for source in _rust_files(shim / "src"):
        relative = source.relative_to(shim).as_posix()
        source_text = source.read_text(encoding="utf-8", errors="replace")
        code = code_only(source_text)
        if not _has_windows_cfg(source_text):
            found.append(f"{SHIM}/{relative}: must start with #![cfg(windows)]")
        is_ffi = relative.startswith("src/ffi/")
        if not is_ffi and not _has_forbid_unsafe(source_text):
            found.append(f"{SHIM}/{relative}: non-ffi module must forbid unsafe_code")
        blocks = _unsafe_blocks(relative, source_text, code)
        block_offsets = {block.offset for block in blocks}
        for match in UNSAFE_TOKEN.finditer(code):
            if match.start() not in block_offsets:
                found.append(f"{SHIM}/{relative}: unsafe must be an explicit block in src/ffi")
        if not is_ffi and blocks:
            found.append(f"{SHIM}/{relative}: unsafe blocks belong only in src/ffi")
        for block in blocks:
            if not _has_safety_comment(source_text, block):
                found.append(f"{SHIM}/{relative}:{block.line}: unsafe block lacks // SAFETY:")
            actual_blocks[(block.file, block.line)] = block

    records: dict[tuple[str, int], dict[str, object]] = {}
    for parsed in _inventory_blocks(shim, found):
        for key, record in parsed.items():
            if key in records:
                found.append(f"{SHIM}/{INVENTORY}: duplicate record for {key[0]}:{key[1]}")
            records[key] = record
    for key in sorted(actual_blocks):
        if key not in records:
            found.append(f"{SHIM}/{INVENTORY}: missing record for {key[0]}:{key[1]}")
    for key, record in sorted(records.items()):
        if key not in actual_blocks:
            found.append(f"{SHIM}/{INVENTORY}: stale record for {key[0]}:{key[1]}")
            continue
        hosted_test = record["hosted_test"]
        if isinstance(hosted_test, str) and not _hosted_test_exists(shim, hosted_test):
            found.append(
                f"{SHIM}/{INVENTORY}: hosted test {hosted_test} for {key[0]}:{key[1]} does not exist"
            )
    return found


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    found = violations(root)
    if found:
        raise SystemExit("\n".join(found))
    print("owner-bridge Windows unsafe policy holds")


if __name__ == "__main__":
    main()
