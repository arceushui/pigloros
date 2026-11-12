#!/usr/bin/env python3
"""Enforce the ADR-110 Windows owner-bridge unsafe boundary.

The Windows shim ``crates/pos-owner-bridge-windows`` is the only crate allowed
to opt out of the workspace ``unsafe_code = "forbid"`` lint. The checker is
source-based and target-independent: the shim compiles to nothing on Linux, so
a Linux compiler run cannot audit its FFI boundary.

Policy, enforced over every ``.rs`` file under every workspace member (except
``<member>/target``):

* ADR110 section5.2 API families for script injection, DevTools, extensions,
  WebMessages and frame-interface posting are forbidden in the shim, including
  imports/aliases and newer method variants. The SDK's unbounded async pump
  helper is forbidden; native opening must preserve the selected phase bounds.
* Allowed unsafe form: only an explicit ``unsafe { }`` block, only inside
  ``crates/pos-owner-bridge-windows/src/ffi/*.rs``. Each block needs a
  ``// SAFETY:`` comment (immediately above the block or above the statement it
  belongs to) and an inventory record naming its enclosing function, operation,
  invariant and a hosted ``#[test]``.
* ``unsafe fn``, ``unsafe impl``, ``unsafe trait``, ``unsafe extern`` and every
  other ``unsafe`` token that is not a block are rejected everywhere.
* ``#[no_mangle]``, ``#[export_name]``, ``#[link_section]`` (including their
  ``#[unsafe(...)]`` forms) and ``extern "ABI" fn`` definitions are rejected
  everywhere, because they create FFI surface in edition 2021 without the
  ``unsafe`` token.
* ``#[path]``, ``include!``, ``include_str!`` and ``include_bytes!`` can pull
  files from outside the scanned tree. They are rejected in the shim. In other
  members, ``#[path]`` and ``include!`` must name a ``.rs`` file inside a
  scanned member (``concat!(env!("CARGO_MANIFEST_DIR"), "...")`` is resolved
  against the member; ``concat!(env!("OUT_DIR"), "...")`` names build-script
  output and is allowed); the data forms are allowed there.
* Symlinks (file or directory) under a scanned member are rejected, because
  neither the walk nor rustc's module resolution would agree on where they
  lead. Include and ``#[path]`` targets are resolved physically.
* The bare words ``no_mangle``, ``export_name`` and ``link_section`` and
  ``extern <abi> fn`` (also with a macro ``$abi``) are rejected anywhere in
  code, so macro-spelled forms cannot evade the attribute checks.
* Any path dependency (``dependencies``, ``dev-dependencies``,
  ``build-dependencies``, ``target.*`` tables, ``workspace.dependencies``,
  ``[patch.*]`` and ``[replace]``) must name a scanned member: dependency
  crates do not inherit the workspace ``forbid``, so unscanned unsafe in one
  would compile for Windows.
* In non-shim members, cargo target paths (``lib.path``, ``bin|test|bench|example[].path`` and
  ``package.build``) must name a ``.rs`` file inside the crate directory.
* ``include``, ``include_str`` and ``include_bytes`` may not be imported
  (``use``) or named as a path segment without ``!``: an alias would hide the
  include target. A local identifier of that name is fine.
* Hosted tests are accepted in exactly three places: a top-level
  ``tests/<name>.rs`` integration test (its own crate root); an inline
  ``#[cfg(test)] mod tests { }`` (or ``cfg(all(test, windows))``) in the crate
  root ``src/lib.rs`` / ``src/main.rs``; or ``src/tests.rs`` /
  ``src/tests/mod.rs`` named by a file-scope ``#[cfg(test)] mod tests;`` in the
  crate root. No other ``mod name;`` file is followed, so a test elsewhere is
  not counted. The ``#[test]`` must be at file scope or inside live inline
  ``mod`` blocks (never inside a ``fn``, ``impl``, ``trait`` or other block),
  must carry no ``ignore``, and the file may carry no inner cfg other than
  ``cfg(test)``, ``cfg(windows)`` and ``cfg(all(test, windows))`` (a ``cfg_attr``
  that adds a cfg is dead; so is any other cfg on the test or an enclosing mod).
* A ``#[cfg(test)] mod tests`` in ``src/lib.rs`` must itself carry
  ``#[forbid(unsafe_code)]`` like every other non-ffi file-scope ``mod``.
* In the shim, ``macro_rules!``/``macro`` definitions, raw identifiers
  (``r#cfg`` resolves to the builtin) and macro invocations whose arguments
  contain ``mod``, ``fn``, ``impl``, ``trait`` or an attribute are rejected,
  because they can hide never-compiled tests or modules from the scan.
* The shim manifest is checked against a key allowlist: ``[package]`` keeps
  descriptive keys only (no ``autobins``, ``autolib``, ``autotests``,
  ``autoexamples``, ``autobenches``, ``build``, ``default-run`` ...), ``[lib]``
  only ``name`` and ``crate-type``, and ``[[bin]]``, ``[[test]]``, ``[[bench]]``
  and ``[[example]]`` only ``name``. ``test``, ``harness``, ``path``,
  ``required-features``, ``doctest`` and every other key are rejected, so a
  target ``name`` always maps to the auto-discovered file and the default
  harness runs it. Dotted and inline table forms are normalized by the parser.
* ``global_asm!``/``naked_asm!`` (even aliased), ``asm!`` outside an inventoried
  unsafe block of ``src/ffi``, and ``#[link(...)]`` are rejected.
* Every non-shim manifest must set ``[lints] workspace = true``.
* The root ``[workspace.lints.rust] unsafe_code`` must be ``forbid``, and no
  non-shim manifest may configure ``unsafe_code`` (or ``unsafe-code``).
* One unsafe block per line: the inventory is keyed by file and line, so a
  second block on the same line is rejected rather than undercounted. A SAFETY
  comment above a multi-line statement serves every block inside it, but each
  block still needs its own inventory record on its own line.
* ``include!(concat!(env!("OUT_DIR"), "<relative path>"))`` is allowed in
  non-shim members: it names build-script output that no source scan can see.
  That is a deliberate trade-off; the workspace ``forbid(unsafe_code)`` lint
  still compiles over generated code on Linux. The literal part must be
  relative with no ``..`` component.
* Sources are read with ``utf-8-sig`` so a byte-order mark, which rustc
  accepts, does not defeat the leading-attribute checks.
* The shim manifest repeats the workspace lint tables except for the four
  ADR-approved entries. Other members configure no ``unsafe_code`` lint.
* A shim ``build.rs`` is rejected outright, and the ffi module must be
  ``src/ffi/mod.rs`` (``src/ffi.rs`` is rejected) so that ``src/ffi/`` holds
  every unsafe file.
* Every shim source file (all of ``src``, ``tests``, ``examples``, ``benches``)
  starts with ``#![cfg(windows)]``. Every shim file outside ``src/ffi`` starts
  with ``#![forbid(unsafe_code)]``, except the crate root ``src/lib.rs``: an
  inner forbid at the crate root is crate-wide and cannot be relaxed in
  ``ffi``. The root therefore must not contain it, and instead every non-ffi
  file-scope ``mod`` declaration in ``src/lib.rs`` carries ``#[forbid(unsafe_code)]``.
* Workspace members must be listed explicitly; globs and missing member
  manifests are errors, never silently skipped.

A mod nested inside an inline ``mod`` in ``src/lib.rs`` inherits that mod's
forbid and needs none of its own. The test function named by the inventory must
carry ``#[test]``.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


SHIM = "crates/pos-owner-bridge-windows"
INVENTORY = "unsafe-inventory.toml"
REQUIRED_BLOCK_FIELDS = ("file", "line", "function", "operation", "invariant", "hosted_test")
# ADR110 section5.2 prohibits these API families even inside an inventoried
# FFI block. Scan identifiers after masking comments/data, so aliases/imports
# and method variants cannot introduce host injection, messages or frame posts.
FORBIDDEN_WEBVIEW_API = re.compile(
    r"(?<!\w)(?:ExecuteScript\w*|AddScriptToExecuteOnDocumentCreated\w*|"
    r"CallDevToolsProtocolMethod\w*|GetDevToolsProtocolEventReceiver\w*|"
    r"AddBrowserExtension\w*|\w*WebMessageReceived\w*|PostWebMessage\w*|"
    r"ICoreWebView2Frame(?:[0-9]+)?|wait_for_async_operation)(?!\w)"
)
UNSAFE_TOKEN = re.compile(r"(?<!\w)unsafe(?!\w)")
UNSAFE_BLOCK = re.compile(r"(?<!\w)unsafe\s*\{")
UNSAFE_KIND = re.compile(r"unsafe\s*(\w+|\()")
ATTRIBUTE_START = re.compile(r"#\s*(!?)\s*\[")
BANNED_WORD = re.compile(r"(?<!\w)(no_mangle|export_name|link_section)(?!\w)")
# ``unsafe_code`` must be a bare element of ``forbid(...)``: ``foo::unsafe_code`` is another lint.
FORBIDS_UNSAFE = re.compile(r"(?<!\w)forbid\((?:[^()]*,)?unsafe_code(?=[,)])")
GLOBAL_ASM_WORD = re.compile(r"(?<!\w)(global_asm|naked_asm)(?!\w)")
ASM_MACRO = re.compile(r"(?<!\w)asm\s*!")
LINK_ATTRIBUTE = re.compile(r"(?<!\w)link\s*(?:\(|\Z)")
INLINE_MOD_HEADER = re.compile(r"\s*(?:pub\s*(?:\([^)]*\)\s*)?)?mod\s+(?P<name>\w+)\s*")
DEPENDENCY_TABLES = frozenset(
    {"dependencies", "dev-dependencies", "build-dependencies", "dev_dependencies", "build_dependencies", "replace"}
)
LIVE_TEST_CFGS = ("cfg(test)", "cfg(windows)", "cfg(all(test,windows))", "cfg(all(windows,test))")
USE_STATEMENT = re.compile(r"(?<!\w)use\s[^;]*;")
INCLUDE_WORD = re.compile(r"(?<!\w)(include(?:_str|_bytes)?)(?!\w)(?!\s*!)")
MOD_FILE_DECLARATION = re.compile(r"(?<!\w)(?P<visibility>pub\s*(?:\([^)]*\)\s*)?)?mod\s+(?P<name>\w+)\s*;")
MACRO_INVOCATION = re.compile(r"(?<!\w)(\w+)\s*!\s*(?=[(\[{])")
MACRO_HIDES_ITEMS = re.compile(r"(?<!\w)(?:mod|fn|impl|trait|macro_rules|macro)(?!\w)|#\s*!?\s*\[")
MACRO_DEFINITION = re.compile(r"(?<!\w)(macro_rules|macro)(?!\w)")
TEST_MOD_CFGS = ("cfg(test)", "cfg(all(test,windows))", "cfg(all(windows,test))")
PATH_ATTRIBUTE = re.compile(r"(?<!\w)path\s*=")
PATH_LITERAL = re.compile(r'path\s*=\s*"([^"\\]*)"')
INCLUDE_MACRO = re.compile(r"(?<!\w)(include(?:_str|_bytes)?)\s*!")
INCLUDE_LITERAL = re.compile(r'\s*[(\[{]\s*"([^"\\]*)"\s*[)\]}]')
GENERATED_INCLUDE = re.compile(
    r'\s*[(\[{]\s*concat!\s*\(\s*env!\s*\(\s*"(OUT_DIR|CARGO_MANIFEST_DIR)"\s*\)\s*,\s*"([^"\\]*)"\s*,?\s*\)\s*[)\]}]'
)
EXTERN_FN = re.compile(r"(?<!\w)extern\s+(?:\$\w+\s+)?fn\s+[\w$]")
MOD_DECLARATION = re.compile(r"(?<!\w)(?P<visibility>pub\s*(?:\([^)]*\)\s*)?)?mod\s+(?P<name>\w+)\s*[;{]")
FUNCTION = re.compile(r"(?<!\w)fn\s+(\w+)")
FUNCTION_MODIFIERS = re.compile(r"(?:(?:pub(?:\s*\([^)]*\))?|async|const)\s+)*\Z")
RAW_PREFIXES = ("r", "br", "cr")
STRING_PREFIXES = ("b", "c")
WORD_RUN = re.compile(r"\w+")
CODE_SYMBOLS = re.compile(r"""[^\w/"']+""")
MISSING = object()


@dataclass(frozen=True)
class Scan:
    """Masked source plus the standalone ``//`` comments by 0-based line."""

    code: str
    code_lines: tuple[str, ...]
    comments: dict[int, str]
    raw_identifiers: tuple[int, ...] = ()
    source: str = ""


@dataclass(frozen=True)
class Attribute:
    """One ``#[...]`` or ``#![...]`` attribute in masked code."""

    start: int
    end: int
    inner: bool
    content: str


@dataclass(frozen=True)
class UnsafeBlock:
    """One explicit unsafe block in ``src/ffi`` and the functions enclosing it."""

    file: str
    line: int
    functions: tuple[str, ...]


@dataclass(frozen=True)
class ShimScan:
    """What the shim pass learned, for the inventory comparison."""

    blocks: dict[tuple[str, int], UnsafeBlock]
    scans: dict[str, tuple[Scan, tuple[Attribute, ...]]]


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


def _quoted_end(text: str, start: int) -> int:
    """Return the end of the escaped string literal opened at ``text[start]``."""
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
        elif text[index] == '"':
            return index + 1
        else:
            index += 1
    return len(text)


def _char_end(text: str, start: int) -> int | None:
    """Return the end of the character literal at ``text[start]``, or None.

    ``None`` means the quote opens a lifetime or label, which stays code.
    """
    following = start + 1
    if following >= len(text):
        return None
    if text[following] == "\\":
        index = following + 2
        while index < len(text) and text[index] not in "'\n":
            index += 1
        return index + 1 if index < len(text) and text[index] == "'" else None
    if text[following] != "'" and following + 1 < len(text) and text[following + 1] == "'":
        return following + 2
    return None


def _raw_string_end(text: str, quote: int, hashes: int) -> int:
    closing = '"' + "#" * hashes
    end = text.find(closing, quote + 1)
    return len(text) if end < 0 else end + len(closing)


def scan(text: str) -> Scan:
    """Tokenize Rust source, masking comments, literals and raw identifiers.

    Offsets and line breaks are preserved. Strings, raw strings, byte and C
    strings, character literals, comments (nested block comments included) and
    doc comments become spaces. A raw identifier such as ``r#unsafe`` becomes
    underscores so it is neither a keyword nor lost. Lifetimes stay code.
    """
    pieces: list[str] = []
    raw_identifiers: list[int] = []
    comments: dict[int, str] = {}
    length = len(text)
    index = 0
    line = 0
    line_start = 0

    def emit(end: int, mode: str) -> None:
        nonlocal index, line, line_start
        segment = text[index:end]
        if mode == "keep":
            pieces.append(segment)
        elif mode == "ident":
            raw_identifiers.append(index)
            pieces.append("_" * len(segment))
        else:
            pieces.append(_blank(segment))
        newlines = segment.count("\n")
        if newlines:
            line += newlines
            line_start = index + segment.rfind("\n") + 1
        index = end

    while index < length:
        character = text[index]
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end < 0 else end
            if not text[line_start:index].strip():
                comments[line] = text[index + 2 : end].strip()
            emit(end, "blank")
        elif text.startswith("/*", index):
            emit(_block_comment_end(text, index), "blank")
        elif word_match := WORD_RUN.match(text, index):
            end = word_match.end()
            word = text[index:end]
            after = text[end : end + 1]
            if word in RAW_PREFIXES and after in ('"', "#"):
                quote = end
                while quote < length and text[quote] == "#":
                    quote += 1
                if quote < length and text[quote] == '"':
                    emit(_raw_string_end(text, quote, quote - end), "blank")
                    continue
                if word == "r" and quote == end + 1:
                    if identifier := WORD_RUN.match(text, quote):
                        emit(identifier.end(), "ident")
                        continue
            if word in STRING_PREFIXES and after == '"':
                emit(_quoted_end(text, end), "blank")
            elif word == "b" and after == "'" and _char_end(text, end) is not None:
                emit(_char_end(text, end) or end, "blank")
            else:
                emit(end, "keep")
        elif character == '"':
            emit(_quoted_end(text, index), "blank")
        elif character == "'":
            char_end = _char_end(text, index)
            if char_end is None:
                emit(index + 1, "keep")
            else:
                emit(char_end, "blank")
        elif symbols := CODE_SYMBOLS.match(text, index):
            emit(symbols.end(), "keep")
        else:
            emit(index + 1, "keep")
    code = "".join(pieces)
    return Scan(code, tuple(code.split("\n")), comments, tuple(raw_identifiers), text)


def _line_of(code: str, offset: int) -> int:
    return code.count("\n", 0, offset) + 1


def _attributes(code: str) -> tuple[Attribute, ...]:
    attributes: list[Attribute] = []
    position = 0
    for match in ATTRIBUTE_START.finditer(code):
        if match.start() < position:
            continue
        depth = 1
        index = match.end()
        while index < len(code) and depth:
            if code[index] == "[":
                depth += 1
            elif code[index] == "]":
                depth -= 1
            index += 1
        if depth:
            continue
        attributes.append(Attribute(match.start(), index, bool(match.group(1)), code[match.end() : index - 1]))
        position = index
    return tuple(attributes)


def _normalized(content: str) -> str:
    return re.sub(r"\s+", "", content)


def _leading_inner_attributes(code: str, attributes: Iterable[Attribute]) -> tuple[str, ...]:
    """Return the normalized inner attributes that open the file."""
    leading: list[str] = []
    position = 0
    for attribute in attributes:
        if not attribute.inner or code[position : attribute.start].strip():
            break
        leading.append(_normalized(attribute.content))
        position = attribute.end
    return tuple(leading)


def _outer_attributes_before(code: str, attributes: Iterable[Attribute], start: int) -> tuple[str, ...]:
    """Return the normalized outer attributes directly attached to an item."""
    candidates = tuple(attributes)
    attached: list[str] = []
    while True:
        for attribute in candidates:
            if not attribute.inner and attribute.end <= start and not code[attribute.end : start].strip():
                attached.append(_normalized(attribute.content))
                start = attribute.start
                break
        else:
            return tuple(attached)


def _matching_brace(code: str, start: int) -> int:
    depth = 0
    for index in range(start, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(code)


def _function_spans(code: str) -> tuple[tuple[str, int, int], ...]:
    """Return ``(name, body_start, body_end)`` for every ``fn`` with a body."""
    spans: list[tuple[str, int, int]] = []
    for match in FUNCTION.finditer(code):
        depth = 0
        index = match.end()
        while index < len(code):
            character = code[index]
            if character in "([":
                depth += 1
            elif character in ")]":
                depth -= 1
            elif depth <= 0 and character == ";":
                break
            elif depth <= 0 and character == "{":
                spans.append((match.group(1), index, _matching_brace(code, index)))
                break
            index += 1
    return tuple(spans)


def _toml(root: Path, path: Path, found: list[str]) -> dict[str, object] | None:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError) as error:
        found.append(f"{path.relative_to(root).as_posix()}: malformed TOML: {error}")
        return None


def _workspace_members(root_manifest: dict[str, object]) -> tuple[str, ...]:
    workspace = root_manifest.get("workspace")
    if not isinstance(workspace, dict):
        return ()
    members = workspace.get("members")
    if not isinstance(members, list) or not all(isinstance(member, str) for member in members):
        return ()
    return tuple(members)


def _contains_unsafe_code_lint(value: object) -> bool:
    if isinstance(value, dict):
        return any(key.replace("-", "_") == "unsafe_code" or _contains_unsafe_code_lint(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_unsafe_code_lint(item) for item in value)
    return False


def _walk(directory: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Return ``(rust files, symlinks)`` under a crate without following links.

    Only ``<crate>/target`` is skipped.
    """
    files: list[Path] = []
    links: list[Path] = []
    if not directory.is_dir():
        return (), ()
    for current, dirnames, filenames in os.walk(directory, followlinks=False):
        here = Path(current)
        if here == directory:
            dirnames[:] = [name for name in dirnames if name != "target"]
        dirnames.sort()
        links.extend(here / name for name in dirnames + filenames if (here / name).is_symlink())
        files.extend(here / name for name in sorted(filenames) if name.lower().endswith(".rs") and (here / name).is_file())
    return tuple(sorted(files)), tuple(sorted(links))


def _path_dependencies(value: object, parent: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        tables = list(value.values()) if parent == "patch" else [value]
        for table in tables if parent in {"patch", *DEPENDENCY_TABLES} else []:
            if isinstance(table, dict):
                found.extend(
                    item["path"] for item in table.values() if isinstance(item, dict) and isinstance(item.get("path"), str)
                )
        for key, item in value.items():
            found.extend(_path_dependencies(item, key))
    return found


def _plain_relative(literal: str) -> bool:
    stripped = literal.lstrip("/")
    return bool(stripped) and "\\" not in literal and ".." not in PurePosixPath(stripped).parts


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


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


def _table_differences(actual: object, expected: dict[str, object]) -> list[str] | None:
    if not isinstance(actual, dict):
        return None
    return sorted(
        key for key in set(actual) | set(expected) if actual.get(key, MISSING) != expected.get(key, MISSING)
    )


PACKAGE_KEYS = frozenset(
    {
        "name", "version", "edition", "rust-version", "license", "license-file", "publish",
        "description", "authors", "repository", "homepage", "documentation", "readme", "keywords", "categories",
    }
)
TOP_LEVEL_KEYS = frozenset(
    {"package", "lints", "lib", "bin", "test", "bench", "example", "features",
     "dependencies", "dev-dependencies", "build-dependencies", "target"}
)
LIB_KEYS = frozenset({"name", "crate-type"})
TARGET_KEYS = frozenset({"name"})


def _check_shim_manifest_keys(manifest: dict[str, object], found: list[str]) -> None:
    """Allow only manifest keys that leave cargo's target discovery untouched.

    ``test``, ``harness``, ``path``, ``required-features``, ``doctest``, every
    ``package.auto*`` switch and any other key could stop cargo from compiling
    or running a file the checker believes is a hosted test, so everything not
    listed is rejected. TOML parsing normalizes dotted and inline forms.
    """
    label = f"{SHIM}/Cargo.toml"
    for key in sorted(set(manifest) - TOP_LEVEL_KEYS):
        found.append(f"{label}: top-level key {key} is not allowed in the shim manifest")
    package = manifest.get("package")
    if isinstance(package, dict):
        for key in sorted(set(package) - PACKAGE_KEYS):
            found.append(f"{label}: package.{key} is not allowed in the shim manifest")
    library = manifest.get("lib")
    if isinstance(library, dict):
        for key in sorted(set(library) - LIB_KEYS):
            found.append(f"{label}: lib.{key} is not allowed in the shim manifest")
    elif library is not None:
        found.append(f"{label}: lib must be a table")
    for kind in ("bin", "test", "bench", "example"):
        items = manifest.get(kind)
        if items is None:
            continue
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            found.append(f"{label}: {kind} must be an array of tables")
            continue
        for item in items:
            for key in sorted(set(item) - TARGET_KEYS):
                found.append(f"{label}: {kind}.{key} is not allowed in the shim manifest")


def _check_shim_lints(root_manifest: dict[str, object], shim_manifest: dict[str, object], found: list[str]) -> None:
    expected = _expected_shim_lints(root_manifest)
    if expected is None:
        found.append(
            f"{SHIM}/Cargo.toml: cannot verify shim lint tables without root "
            "[workspace.lints.rust] and [workspace.lints.clippy]"
        )
        return
    lints = shim_manifest.get("lints")
    if not isinstance(lints, dict):
        found.append(f"{SHIM}/Cargo.toml: [lints] is missing or not a table")
        return
    extra = sorted(set(lints) - {"rust", "clippy"})
    if extra:
        found.append(f"{SHIM}/Cargo.toml: [lints] must hold only the rust and clippy tables, found {', '.join(extra)}")
    for name, table in (("rust", expected[0]), ("clippy", expected[1])):
        differences = _table_differences(lints.get(name), table)
        if differences is None:
            found.append(f"{SHIM}/Cargo.toml: [lints.{name}] is missing or not a table")
        elif differences:
            found.append(f"{SHIM}/Cargo.toml: [lints.{name}] differs from ADR-110 policy in {', '.join(differences)}")


def _check_root_lints(root_manifest: dict[str, object], found: list[str]) -> None:
    workspace = root_manifest.get("workspace")
    lints = workspace.get("lints") if isinstance(workspace, dict) else None
    rust = lints.get("rust") if isinstance(lints, dict) else None
    if isinstance(rust, dict):
        value = rust.get("unsafe_code")
        level = value.get("level") if isinstance(value, dict) else value
        if level != "forbid":
            found.append('Cargo.toml: [workspace.lints.rust] unsafe_code must be "forbid"')


def _check_path_dependencies(
    root: Path,
    directory: Path,
    manifest: dict[str, object],
    scanned_dirs: tuple[Path, ...],
    found: list[str],
) -> None:
    """Flag path dependencies (all tables, patch and replace) on anything but a scanned member.

    Dependency crates do not inherit the workspace ``forbid``, so unscanned unsafe
    in one would be compiled for Windows.
    """
    label = (directory / "Cargo.toml").relative_to(root).as_posix()
    for relative in _path_dependencies(manifest):
        if (directory / relative).resolve() not in scanned_dirs:
            found.append(f"{label}: path dependency {relative} must name a listed workspace member")


def _target_paths(manifest: dict[str, object]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    library = manifest.get("lib")
    if isinstance(library, dict) and isinstance(library.get("path"), str):
        found.append(("lib.path", library["path"]))
    for key in ("bin", "test", "bench", "example"):
        items = manifest.get(key)
        if isinstance(items, list):
            found.extend(
                (f"{key}.path", item["path"]) for item in items if isinstance(item, dict) and isinstance(item.get("path"), str)
            )
    package = manifest.get("package")
    if isinstance(package, dict) and isinstance(package.get("build"), str):
        found.append(("package.build", package["build"]))
    return found


def _check_target_paths(root: Path, directory: Path, manifest: dict[str, object], found: list[str]) -> None:
    """Cargo target paths must name a ``.rs`` file inside the crate's own directory."""
    label = (directory / "Cargo.toml").relative_to(root).as_posix()
    for key, relative in _target_paths(manifest):
        if not _scanned_rust_file((directory / relative).resolve(), (directory,)):
            found.append(f"{label}: {key} {relative} must name a .rs file inside the crate directory")


def _scanned_rust_file(target: Path, scanned_dirs: tuple[Path, ...]) -> bool:
    if target.suffix != ".rs" or not target.is_file():
        return False
    return any(
        target.is_relative_to(directory) and target.relative_to(directory).parts[:1] != ("target",)
        for directory in scanned_dirs
    )


def _check_surface(
    label: str,
    path: Path,
    crate_dir: Path,
    text: str,
    scanned: Scan,
    attributes: tuple[Attribute, ...],
    scanned_dirs: tuple[Path, ...],
    strict_includes: bool,
    found: list[str],
    asm_spans: tuple[tuple[int, int], ...] = (),
) -> None:
    """Reject attributes, macros and definitions that create unaudited surface.

    ``asm!`` is only accepted inside ``asm_spans`` (the inventoried unsafe
    blocks of ``src/ffi``); ``global_asm`` and ``naked_asm`` never are.
    """
    code = scanned.code

    def at(offset: int) -> str:
        return f"{label}:{_line_of(code, offset)}"

    def inclusion(offset: int, kind: str, literal: str | None, base: Path, *, data: bool) -> None:
        if strict_includes:
            found.append(f"{at(offset)}: {kind} is forbidden in the shim: it can pull in files outside the scanned tree")
        elif not data:
            target = None if literal is None else (base / literal).resolve()
            if target is None or not _scanned_rust_file(target, scanned_dirs):
                found.append(f"{at(offset)}: {kind} must name a .rs file inside a scanned workspace member")

    for match in BANNED_WORD.finditer(code):
        found.append(f"{at(match.start())}: {match.group(1)} creates FFI surface and is forbidden")
    for match in GLOBAL_ASM_WORD.finditer(code):
        found.append(f"{at(match.start())}: {match.group(1)} creates FFI surface without an unsafe block and is forbidden")
    for match in ASM_MACRO.finditer(code):
        if not any(begin <= match.start() < end for begin, end in asm_spans):
            found.append(f"{at(match.start())}: asm! is only allowed inside an unsafe block in src/ffi")
    for attribute in attributes:
        if LINK_ATTRIBUTE.search(attribute.content):
            found.append(f"{at(attribute.start)}: #[link] creates FFI surface and is forbidden")
        if PATH_ATTRIBUTE.search(attribute.content):
            literal = PATH_LITERAL.search(text[attribute.start : attribute.end])
            inclusion(attribute.start, "#[path]", literal.group(1) if literal else None, path.parent, data=False)
    for match in INCLUDE_MACRO.finditer(code):
        name = match.group(1)
        data = name != "include"
        literal = INCLUDE_LITERAL.match(text, match.end())
        if literal:
            inclusion(match.start(), f"{name}!", literal.group(1), path.parent, data=data)
            continue
        generated = GENERATED_INCLUDE.match(text, match.end())
        if generated and generated.group(1) == "CARGO_MANIFEST_DIR":
            inclusion(match.start(), f"{name}!", generated.group(2).lstrip("/"), crate_dir, data=data)
        elif generated and not strict_includes and _plain_relative(generated.group(2)):
            continue
        else:
            inclusion(match.start(), f"{name}!", None, crate_dir, data=data)
    use_spans = [use.span() for use in USE_STATEMENT.finditer(code)]
    for match in INCLUDE_WORD.finditer(code):
        imported = any(begin <= match.start() < end for begin, end in use_spans)
        if not imported and not code[: match.start()].rstrip().endswith("::"):
            continue
        found.append(
            f"{at(match.start())}: {match.group(1)} must only be used as the {match.group(1)}! macro; "
            "an import or alias would hide the include target"
        )
    for match in EXTERN_FN.finditer(code):
        found.append(f"{at(match.start())}: extern fn definition creates FFI surface and is forbidden")


def _has_safety_comment(scanned: Scan, line: int, column: int) -> bool:
    """Accept a ``// SAFETY:`` comment above the block or its statement start."""
    # A comment above a multi-line statement serves every block inside it;
    # each block still needs its own inventory record.
    anchor = line
    if not scanned.code_lines[line][:column].strip():
        while anchor > 0:
            previous = scanned.code_lines[anchor - 1].strip()
            if previous and not previous.endswith((";", "{", "}")):
                anchor -= 1
            else:
                break
    texts: list[str] = []
    index = anchor - 1
    while index >= 0 and index in scanned.comments:
        texts.append(scanned.comments[index])
        index -= 1
    texts.reverse()
    for position, text in enumerate(texts):
        if text.startswith("SAFETY:"):
            return bool(" ".join(texts[position:])[len("SAFETY:") :].strip())
    return False


def _is_live_test(attached: tuple[str, ...]) -> bool:
    """A ``#[test]`` that is neither ignored nor cfg'd out or ignored conditionally."""
    if "test" not in attached:
        return False
    for item in attached:
        if item.startswith("ignore"):
            return False
        if item.startswith("cfg(") and item not in LIVE_TEST_CFGS:
            return False
        if item.startswith("cfg_attr(") and ("ignore" in item or "cfg(" in item):
            return False
    return True


def _dead_cfg(content: str) -> bool:
    """Return whether a normalized attribute is a cfg that could compile the item out."""
    return (content.startswith("cfg(") and content not in LIVE_TEST_CFGS) or (
        content.startswith("cfg_attr(") and "cfg(" in content
    )


def _file_is_live(attributes: Iterable[Attribute]) -> bool:
    """Reject any inner cfg other than the live ones, wherever it sits in the file."""
    return not any(attribute.inner and _dead_cfg(_normalized(attribute.content)) for attribute in attributes)


def _enclosing_mods(
    code: str, attributes: tuple[Attribute, ...], offset: int
) -> tuple[tuple[str, tuple[str, ...]], ...] | None:
    """Return ``(name, normalized outer attributes)`` of the inline mods enclosing ``offset``.

    ``()`` means file scope; None means the position is inside a ``fn``, ``impl``,
    ``trait`` or any other block, or behind a dead cfg, so a ``#[test]`` there
    may never be compiled. Macros that could hide items are banned in the shim,
    so tracking braces is complete.
    """
    stack: list[tuple[int, int]] = []
    boundary = 0
    for index in range(offset):
        character = code[index]
        if character == "{":
            stack.append((boundary, index))
            boundary = index + 1
        elif character == "}":
            if stack:
                stack.pop()
            boundary = index + 1
        elif character == ";":
            boundary = index + 1
    names: list[tuple[str, tuple[str, ...]]] = []
    for begin, end in stack:
        header = code[begin:end]
        outer: list[str] = []
        for attribute in attributes:
            if begin <= attribute.start and attribute.end <= end:
                if not attribute.inner:
                    outer.append(_normalized(attribute.content))
                    if _dead_cfg(outer[-1]):
                        return None
                header = header[: attribute.start - begin] + _blank(code[attribute.start : attribute.end]) + header[attribute.end - begin :]
        header_match = INLINE_MOD_HEADER.fullmatch(header)
        if not header_match:
            return None
        names.append((header_match.group("name"), tuple(outer)))
    return tuple(names)


def _declares_test_module(scans: dict[str, tuple[Scan, tuple[Attribute, ...]]], root: str) -> list[str]:
    """Return the sibling files a ``#[cfg(test)] mod tests;`` at file scope of ``root`` names."""
    if root not in scans:
        return []
    scanned, attributes = scans[root]
    files: list[str] = []
    for match in MOD_FILE_DECLARATION.finditer(scanned.code):
        if match.group("name") != "tests":
            continue
        start = match.start("visibility") if match.group("visibility") else match.start()
        attached = _outer_attributes_before(scanned.code, attributes, start)
        if (
            _enclosing_mods(scanned.code, attributes, start) == ()
            and any(item in TEST_MOD_CFGS for item in attached)
            and not any(_dead_cfg(item) for item in attached)
        ):
            files.extend(("src/tests.rs", "src/tests/mod.rs"))
    return files


def _hosted_test_exists(scans: dict[str, tuple[Scan, tuple[Attribute, ...]]], name: str) -> bool:
    """Return whether a live ``#[test]`` named ``name`` sits in an accepted hosted-test place.

    Accepted: a top-level ``tests/<file>.rs`` integration test (its own crate
    root); an inline ``#[cfg(test)] mod tests { }`` in the crate root
    ``src/lib.rs`` or ``src/main.rs``; or the file ``src/tests.rs`` /
    ``src/tests/mod.rs`` named by a ``#[cfg(test)] mod tests;`` at file scope of
    the crate root. The test must not be inside a ``fn``, ``impl``, ``trait`` or
    dead-cfg block, and the file may carry no dead inner cfg. No other ``mod``
    file is followed.
    """
    expression = re.compile(rf"(?<!\w)fn\s+{re.escape(name)}(?!\w)")
    test_files = {file for root in ("src/lib.rs", "src/main.rs") for file in _declares_test_module(scans, root)}
    for relative, (scanned, attributes) in scans.items():
        integration = PurePosixPath(relative).parent.as_posix() == "tests"
        root = relative in ("src/lib.rs", "src/main.rs")
        if not (integration or root or relative in test_files) or not _file_is_live(attributes):
            continue
        for match in expression.finditer(scanned.code):
            modifiers = FUNCTION_MODIFIERS.search(scanned.code[: match.start()])
            start = modifiers.start() if modifiers else match.start()
            attached = _outer_attributes_before(scanned.code, attributes, start)
            mods = _enclosing_mods(scanned.code, attributes, start)
            if mods is None or not _is_live_test(attached):
                continue
            if root and not (mods and mods[0][0] == "tests" and any(item in TEST_MOD_CFGS for item in mods[0][1])):
                continue
            return True
    return False


def _group_end(code: str, start: int) -> int:
    depth = 0
    for index in range(start, len(code)):
        if code[index] in "([{":
            depth += 1
        elif code[index] in ")]}":
            depth -= 1
            if depth == 0:
                return index + 1
    return len(code)


def _check_shim_macros(label: str, scanned: Scan, found: list[str]) -> None:
    """Ban raw identifiers, macro definitions and macros that could hide items or tests.

    ``r#cfg`` resolves to the builtin attribute, a declarative macro can swallow
    ``mod x;`` or ``#[test] fn`` without ever compiling it, and a lexical scan
    cannot follow either, so the shim may not use them.
    """
    code = scanned.code
    for offset in scanned.raw_identifiers:
        found.append(f"{label}:{_line_of(code, offset)}: raw identifiers are forbidden in the shim")
    for match in MACRO_DEFINITION.finditer(code):
        found.append(f"{label}:{_line_of(code, match.start())}: {match.group(1)} definitions are forbidden in the shim")
    for match in MACRO_INVOCATION.finditer(code):
        if MACRO_HIDES_ITEMS.search(code, match.end(), _group_end(code, match.end())):
            found.append(
                f"{label}:{_line_of(code, match.start())}: macro {match.group(1)}! with items or attributes "
                "in its arguments is forbidden in the shim: it can hide never-compiled tests or modules"
            )


def _reviewed_fault_code(code: str) -> bool:
    """Accept only the reviewed test-only fixed process-fault implementation."""
    normalized = re.sub(r"\s+", "", code).encode()
    return hashlib.sha256(normalized).hexdigest() == "31d6ce4b86a3f3316828599a0bb6e72bd81fdf073c8d6f969c8026dc56c09eb7"


def _check_shim_sources(shim: Path, scanned_dirs: tuple[Path, ...], found: list[str]) -> ShimScan:
    blocks: dict[tuple[str, int], UnsafeBlock] = {}
    scans: dict[str, tuple[Scan, tuple[Attribute, ...]]] = {}
    for source in _walk(shim)[0]:
        relative = source.relative_to(shim).as_posix()
        label = f"{SHIM}/{relative}"
        if source.suffix != ".rs":
            found.append(f"{label}: Rust source suffix must be canonical .rs")
        if relative == "build.rs":
            found.append(f"{label}: build scripts are forbidden in the shim")
            continue
        if relative == "src/ffi.rs":
            found.append(f"{label}: the ffi module must be src/ffi/mod.rs, not src/ffi.rs")
        text = _read(source)
        scanned = scan(text)
        code = scanned.code
        for api in FORBIDDEN_WEBVIEW_API.finditer(code):
            found.append(
                f"{label}:{_line_of(code, api.start())}: forbidden owner WebView API {api.group()}"
            )
        attributes = _attributes(code)
        scans[relative] = (scanned, attributes)
        is_ffi = relative.startswith("src/ffi/")
        asm_spans = (
            tuple((match.start(), _matching_brace(code, match.end() - 1)) for match in UNSAFE_BLOCK.finditer(code))
            if is_ffi
            else ()
        )
        _check_surface(label, source, shim, text, scanned, attributes, scanned_dirs, True, found, asm_spans)
        _check_shim_macros(label, scanned, found)
        leading = _leading_inner_attributes(code, attributes)
        if relative == "src/ffi/events/control_fixture.rs" and "cfg(test)" not in leading:
            found.append(f"{label}: ADR-131 control observations require file-scope cfg(test)")
        for declaration in MOD_DECLARATION.finditer(code):
            if declaration.group("name") == "control_fixture":
                guards = _outer_attributes_before(code, attributes, declaration.start())
                if declaration.group("visibility") or "cfg(test)" not in guards:
                    found.append(f"{label}: ADR-131 control_fixture must be a private cfg(test) module")
        # The termination authority is confined to one test-only reviewed file.
        # Hashing masked, whitespace-free source makes any semantic change to
        # that narrow primitive require an explicit policy review and update.
        fault_file = "src/ffi/process_fault.rs"
        if relative == fault_file:
            if "cfg(test)" not in leading:
                found.append(f"{label}: process fault helper requires file-scope cfg(test)")
            if not _reviewed_fault_code(code):
                found.append(f"{label}: process fault implementation differs from the reviewed fixed authority")
        else:
            for authority in re.finditer(r"(?<!\w)(?:TerminateProcess|PROCESS_TERMINATE|GetProcessInfos|GetExitCodeProcess)(?!\w)", code):
                found.append(f"{label}:{_line_of(code, authority.start())}: process fault authority belongs only in the test helper")
        process_open = list(re.finditer(r"(?<!\w)OpenProcess\s*\(", code))
        if relative == "src/ffi/process.rs":
            expected_open = re.compile(r"OpenProcess\s*\(\s*PROCESS_QUERY_LIMITED_INFORMATION\s*,\s*false\s*,\s*pid\s*\)")
            if len(process_open) != 1 or len(re.findall(r"(?<!\w)OpenProcess(?!\w)", code)) != 2 or not expected_open.search(code):
                found.append(f"{label}: product process probe must use its fixed query-only OpenProcess")
        elif relative != fault_file and process_open:
            found.append(f"{label}: OpenProcess is confined to the fixed probe and fault helper")
        if re.search(r"(?<!\w)(?:NtTerminateProcess|ZwTerminateProcess|LoadLibrary\w*)(?!\w)", code):
            found.append(f"{label}: indirect process termination authority is forbidden")
        if re.search(r"(?<!\w)GetProcAddress(?!\w)", code):
            # The one pre-existing dynamic lookup resolves only DefWindowProcW.
            lookup = re.compile(r'GetProcAddress\s*\(\s*module\s*,\s*PCSTR\s*\(\s*c"DefWindowProcW"\.as_ptr\(\)\.cast\(\)\s*\)\s*\)')
            calls = list(re.finditer(r"(?<!\w)GetProcAddress\s*\(", code))
            # Masking preserves offsets: bind the required literal to the real
            # code call, so an approved expression in a comment cannot stand in
            # for a different symbol at the executable call site.
            if relative != "src/ffi/window.rs" or len(calls) != 1 or len(re.findall(r"(?<!\w)GetProcAddress(?!\w)", code)) != 2 or not lookup.match(text, calls[0].start()):
                found.append(f"{label}: dynamic lookup must remain the fixed DefWindowProcW lookup")
        if relative == "src/ffi/mod.rs":
            for declaration in MOD_DECLARATION.finditer(code):
                if declaration.group("name") == "process_fault":
                    guards = _outer_attributes_before(code, attributes, declaration.start())
                    if declaration.group("visibility") or "cfg(test)" not in guards:
                        found.append(f"{label}: process_fault must be a private cfg(test) module")
        if relative != "src/ffi/events/control_fixture.rs":
            for readback in re.finditer(r"(?:\.|::)\s*(Handled|State|Cancel|ProcessFailedKind)\s*\(", code):
                found.append(f"{label}:{_line_of(code, readback.start())}: ADR-131 control readback belongs only in control_fixture")
        if "cfg(windows)" not in leading:
            found.append(f"{label}: must start with #![cfg(windows)]")
        if relative == "src/lib.rs":
            if any(FORBIDS_UNSAFE.search(_normalized(a.content)) for a in attributes if a.inner):
                found.append(
                    f"{label}: crate root must not hold a crate-wide #![forbid(unsafe_code)]; "
                    "forbid each non-ffi mod instead"
                )
            for match in MOD_DECLARATION.finditer(code):
                if match.group("name") == "ffi":
                    continue
                start = match.start("visibility") if match.group("visibility") else match.start()
                if _enclosing_mods(code, attributes, start):
                    # Nested in an inline mod that itself must carry the forbid, which it inherits.
                    continue
                if not any(FORBIDS_UNSAFE.match(item) for item in _outer_attributes_before(code, attributes, start)):
                    found.append(
                        f"{label}:{_line_of(code, match.start())}: mod {match.group('name')} "
                        "must carry #[forbid(unsafe_code)]"
                    )
        elif not is_ffi and not any(FORBIDS_UNSAFE.match(item) for item in leading):
            found.append(f"{label}: non-ffi module must forbid unsafe_code")
        block_starts = {match.start() for match in UNSAFE_BLOCK.finditer(code)}
        spans = _function_spans(code)
        for token in UNSAFE_TOKEN.finditer(code):
            line = _line_of(code, token.start())
            if token.start() not in block_starts:
                kind_match = UNSAFE_KIND.match(code, token.start())
                kind = kind_match.group(1) if kind_match else "construct"
                kind = "attribute" if kind == "(" else kind
                found.append(
                    f"{label}:{line}: unsafe {kind} is forbidden; only explicit unsafe blocks in src/ffi are allowed"
                )
            elif not is_ffi:
                found.append(f"{label}:{line}: unsafe blocks belong only in src/ffi")
            elif (relative, line) in blocks:
                found.append(
                    f"{label}:{line}: more than one unsafe block on a line; "
                    "put each block on its own line so the inventory counts match"
                )
            else:
                column = token.start() - (code.rfind("\n", 0, token.start()) + 1)
                if not _has_safety_comment(scanned, line - 1, column):
                    found.append(f"{label}:{line}: unsafe block lacks // SAFETY:")
                functions = tuple(name for name, begin, end in spans if begin < token.start() < end)
                blocks[(relative, line)] = UnsafeBlock(relative, line, functions)
    if "src/ffi/process_fault.rs" in scans:
        _check_fault_authority(shim.parent.parent, scans, found)
    return ShimScan(blocks, scans)


def _check_fault_assets(root: Path, found: list[str]) -> None:
    catalogue = root / "crates/pos-owner-bridge/src/listener/fixtures.rs"
    responses = root / "crates/pos-owner-bridge/src/listener/fixture_assets.rs"
    try:
        catalogue_code = scan(catalogue.read_text()).code
        response_text = responses.read_text()
    except OSError:
        catalogue_code, response_text = "", ""
    if hashlib.sha256(re.sub(r"\s+", "", catalogue_code).encode()).hexdigest() != "064e4f1625847db44246768eaa33e3b147a3641340511aab602898abcbf53520":
        found.append(f"{catalogue.relative_to(root).as_posix()}: process fault catalogue differs from reviewed sealed response selection")
    response_code = scan(response_text).code
    for variant, constant, filename, digest in (
        ("DelayedDelivery", "DELAYED_DELIVERY", "delayed_delivery", "1bf521a4a1ff47ccf652d1ec9859c717b169412fde00e4ab3e743e9f8f31e653"),
        ("Pending", "PENDING", "pending", "592560cb9ec82f5a93945c0b04ec6ed38b5bf78215eca0dad8eb9730c2918479"),
        ("SuccessfulGetReleaseDelay", "SUCCESSFUL_GET_RELEASE_DELAY", "successful_get_release_delay", "1d09cd8be58999eaec6b3d602873c0ec52c01db407a82faac424cde1a48076e1"),
        ("SuccessfulGetWritingDelay", "SUCCESSFUL_GET_WRITING_DELAY", "successful_get_writing_delay", "835d8dcc1fb948e541e4c05bed41ef528adbf6dbc9c48ef09e5f07a5a8f35b65"),
        ("WithheldDelivery", "WITHHELD_DELIVERY", "withheld_delivery", "cd8dfa06a751630390ab12db964bb347862671a8b75fa31a214e8cd814ea841a"),
    ):
        asset = root / f"crates/pos-owner-bridge/assets/qualification/{filename}.html"
        try:
            asset_digest = hashlib.sha256(asset.read_bytes()).hexdigest()
        except OSError:
            asset_digest = ""
        if asset_digest != digest:
            found.append(f"{asset.relative_to(root).as_posix()}: process fault topology requires the reviewed no-frame asset")
        if not re.search(rf"Self\s*::\s*{variant}\s*=>\s*&\s*fixture_assets\s*::\s*{constant}(?!\w)", catalogue_code):
            found.append(f"{catalogue.relative_to(root).as_posix()}: process fault must select the sealed {variant} response")
        declarations = list(re.finditer(rf"(?<!\w)const\s+{constant}\s*:", response_code))
        binding = re.compile(rf'const\s+{constant}\s*:\s*Response\s*=\s*Response\s*\{{\s*body\s*:\s*include_bytes!\(\s*"\.\./\.\./assets/qualification/{filename}\.html"\s*\)')
        if len(declarations) != 1 or not binding.match(response_text, declarations[0].start()):
            found.append(f"{responses.relative_to(root).as_posix()}: {variant} response must embed the reviewed asset")


def _check_fault_authority(root: Path, scans: dict[str, tuple[Scan, tuple[Attribute, ...]]], found: list[str]) -> None:
    # The fault helper delegates identity/path observation to this shared
    # query-only implementation. Bind its callees as well as the fault caller.
    shared = scans.get("src/ffi/process.rs")
    shared_code = shared[0].code if shared else ""
    if hashlib.sha256(re.sub(r"\s+", "", shared_code).encode()).hexdigest() != "7c6a97e8cd00e8cdcdae58abc3809187cd2f0314605e9e924cf744ce3a2f0c15":
        found.append(f"{SHIM}/src/ffi/process.rs: shared process identity differs from the reviewed read-only observer")
    _check_fault_assets(root, found)
    callbacks = scans.get("src/ffi/events/control_fixture.rs")
    callback_code = callbacks[0].code if callbacks else ""
    if hashlib.sha256(re.sub(r"\s+", "", callback_code).encode()).hexdigest() != "201ffd540b2feeaa1250015fe7bca54ecbae9a6877aed41af315fa888be7dc9a":
        found.append(f"{SHIM}/src/ffi/events/control_fixture.rs: process failure observations differ from reviewed typed callbacks")
    ffi_parent = scans.get("src/ffi/mod.rs")
    ffi_code = ffi_parent[0].code if ffi_parent else ""
    declarations = [match for match in MOD_DECLARATION.finditer(ffi_code) if match.group("name") == "process_fault"]
    if len(declarations) != 1:
        found.append(f"{SHIM}/src/ffi/mod.rs: process fault helper must have exactly one private cfg(test) declaration")
    test_parent = scans.get("src/adapter/native_tests.rs")
    test_code = test_parent[0].code if test_parent else ""
    if len([match for match in MOD_DECLARATION.finditer(test_code) if match.group("name") == "process_fault"]) != 1:
        found.append(f"{SHIM}/src/adapter/native_tests.rs: process fault fixture declaration is missing or ambiguous")
    root_item = scans.get("src/lib.rs")
    root_code = root_item[0].code if root_item else ""
    failure_type = root_code.find("pub(crate) enum NativeProcessFailure")
    opening = root_code.find("{", failure_type) if failure_type >= 0 else -1
    body = root_code[failure_type:_matching_brace(root_code, opening) + 1] if opening >= 0 else ""
    if hashlib.sha256(re.sub(r"\s+", "", body).encode()).hexdigest() != "17da8bd84053875a19b3507ac07b8692b2a1938eccc4c73928584c53ee48095b":
        found.append(f"{SHIM}/src/lib.rs: native failure classifications differ from reviewed variants")
    if failure_type < 0 or not root_item or "cfg(test)" not in _outer_attributes_before(root_code, root_item[1], failure_type):
        found.append(f"{SHIM}/src/lib.rs: native failure classifications require cfg(test)")
    wrappers = list(re.finditer(r"(?<!\w)fn\s+native_verified_owned_process_faults_retire\s*\(", root_code))
    if len(wrappers) != 1:
        found.append(f"{SHIM}/src/lib.rs: process fault hosted test is missing or ambiguous")
    else:
        opening = root_code.find("{", wrappers[0].end())
        body = root_code[opening:_matching_brace(root_code, opening) + 1] if opening >= 0 else ""
        if re.sub(r"\s+", "", body) != "{crate::Native::native_verified_owned_process_faults_retire()}":
            found.append(f"{SHIM}/src/lib.rs: process fault hosted test must call the real fixture")
    retirement = scans.get("src/adapter/native_tests/retirement.rs")
    retirement_code = retirement[0].code if retirement else ""
    if hashlib.sha256(re.sub(r"\s+", "", retirement_code).encode()).hexdigest() != "eb6e478e963eb5c7d03378be4106380321fd851cb6238c080e3e0395f8e784aa":
        found.append(f"{SHIM}/src/adapter/native_tests/retirement.rs: shared retirement differs from reviewed code")
    if len([match for match in MOD_DECLARATION.finditer(test_code) if match.group("name") == "retirement"]) != 1:
        found.append(f"{SHIM}/src/adapter/native_tests.rs: shared retirement declaration is missing or ambiguous")
    type_start = root_code.find("pub(crate) enum ProcessFaultTarget")
    type_end = root_code.find("pub(crate) trait NativeOperations", type_start) if type_start >= 0 else -1
    types = root_code[type_start:type_end] if type_end >= 0 else ""
    if hashlib.sha256(re.sub(r"\s+", "", types).encode()).hexdigest() != "5a419834c90ee24dda3a73acdaff32a397274394602d56e415d973f8a945868d":
        found.append(f"{SHIM}/src/lib.rs: process fault capability types differ from reviewed test-only code")
    elif "cfg(test)" not in _outer_attributes_before(root_code, root_item[1], type_start):
        found.append(f"{SHIM}/src/lib.rs: process fault capability types require cfg(test)")
    # The seal is created only by the declared sealed-asset native fixture;
    # these fixed boundaries prevent bypassing lifecycle/identity checks.
    specifications = (
        ("src/adapter/surface/diagnostics.rs", "quarantined_fault_state", "ab2738e15f12084ff78850a991e3a4bf09edac95d07c4063e63e4fa1f60c15c1"),
        ("src/adapter/surface/diagnostics.rs", "inject_quarantined_fault", "02303635aa711fc81e6e8843cc54cf0d75c1fd7b888d61a28358f9d9ee52131b"),
        ("src/adapter/surface/tests.rs", "quarantined_fault_refuses_missing_state_and_unheld_keeper", "d5b57fd8657c020b01bf6437598fc3cd03f1b75850308b5b5a50a928483b93f7"),
        ('src/adapter/surface/mod.rs', 'pre_environment_retention', '1cb427754f0a7c3675063890f5fac1eeea50f342ff3988bfe2f6532c65e5bc6d'),
        ('src/adapter/surface/mod.rs', 'early_renderer_presence', '1f0f23a60d23aa258a7c4b2ddf7079540d4f841ee87719c1474d7ad1759b0f6f'),
        ('src/adapter/surface/mod.rs', 'pre_environment_completion', '3566802f65e63c69f642d7b4b5a070e0b802945847e0a24d8a0637b08f8a3fd7'),
        ('src/ffi/session.rs', 'early_renderer_presence', '98d418a783a187e248b5843d15de972346d8efb5907253b6287fe3bb310b00b7'),
        ('src/ffi/session.rs', 'environment_creation_completion', '67cc92ce1948741f3ff340e49e8ea613ff06dca426ab11fad87ec168837fd9b9'),
        ('src/ffi/creation.rs', 'environment_succeeded', 'f74a4b5856d90f5c1d9f12fddd61c5c160fdd1bd35121507c3f6f5126cf4ae24'),
        ('src/lib.rs', 'early_renderer_presence', 'ce782283a5686cc23a94ade4be891c7b67587d5c412271dc3fb6c670d906a415'),
        ('src/lib.rs', 'environment_creation_completion', '518311d3b890a07c23d1739324d01c59d531ab29ba00025651466be8c0fd5f9c'),
        ('src/adapter/surface/mod.rs', 'before_record_fault_state', '49205841cf6005a43cd32dc1175026713fd3792d8f86b4e93718f35ee8614466'),
        ('src/adapter/surface/mod.rs', 'before_record_owners_retained', '502ed68d263fce4656e16380d091e1efd621ed8d740508dfd42f37ff759427e3'),
        ('src/adapter/surface/mod.rs', 'inject_before_record_fault', 'bd47d1b628ba6dd12d0286ddf101e8bb8f7c3b181f68ee3d019f1205c49f227f'),
        ('src/adapter/surface/mod.rs', 'inject_posted_consuming_fault', '8d2a7e8a867ac336094f4bfdc45194220735cd8e709c28d12d7e07c7422e4427'),
        ('src/adapter/surface/mod.rs', 'posted_ready_fault_state', '338bbaa04356e3f9d6e235d859e1427608723276a67ba1a17da3ea1abc0e143a'),
        ('src/adapter/surface/mod.rs', 'inject_posted_ready_fault', '43214afa0e0beb3daf39dc3ad67d4b3dc3a985f5299362e169cac58c141e1820'),
        ('src/adapter/surface/mod.rs', 'posted_retry_fault_state', '32f6a4721488f17a6d9629b3112ca4cf8de196df49ab8eea7d9fe8a150fed8c0'),
        ('src/adapter/surface/mod.rs', 'inject_posted_retry_fault', '0ce323d34f99595ccb3bf45db32abff3a0d1fb636a7f20be5864941a32505926'),
        ('src/adapter/surface/mod.rs', 'posted_writing_fault_state', '5be6d3f63972546114c8ce0fb27c34bd28f63434ee4c702b6649a23f0b502a16'),
        ('src/adapter/surface/mod.rs', 'inject_posted_writing_fault', 'a6c54d48ab66301c9c77e8e3282ff609dd28143ae27b625bf5ba66b60746c33d'),
        ('src/lib.rs', 'pending_opening_owners_retained', '41a133b45f8a9ca9bb050a8836d59fe0aed4c3bcfb52774daf7c0dd179c95713'),
        ('src/lib.rs', 'pending_opening_browser_candidate', '468186693170c9279a597590155e5ae3ef6ce261a96a02141dcb7fa9f69b5aa0'),
        ('src/ffi/session.rs', 'require_owned_browser', '4f80646795b6f0177dbf716e84ecbd7244754fea8ef3c9c161b4e0a36da620ed'),
        ('src/ffi/session.rs', 'retain_exit_browser', 'f205af1bb5c6e71842df1355510f0faf45ff6edd4259dccfb3a848d31667b066'),
        ('src/ffi/session.rs', 'pending_candidate_checked', '6d8bae2221f1b989881f3bab2fb5ec48e4564fa2be60cf3b8018dd1ab68179b5'),
        ('src/ffi/session.rs', 'pending_opening_owners_retained', '6ba3a7de9b084a2df4b09c8cf7dbc9740941cee9fd482e880691aa9c760127d7'),
        ('src/ffi/session.rs', 'pending_opening_browser_candidate', '58455c75194b1170db3b836b6fcdfa88568a788c792cbd94885ea5b650fb3c66'),
        ('src/adapter/surface/mod.rs', 'prepare_pending_opening_browser', '9ac7b4b60533b37509faafe6c44e780d6ba39a4c72891f5b3225224bf85f7754'),
        ('src/adapter/surface/mod.rs', 'pending_opening_owners_retained', '8953566b940f807ca8fc90295b23c15dd8a12777b4c9365543acfbff10aa869f'),
        ('src/adapter/surface/mod.rs', 'pending_opening_completion', 'afb594852028158432b1193ab7b648cc2c1f481540d0053164baa664e05bd1ee'),
        ('src/adapter/surface/mod.rs', 'inject_pending_opening_browser', 'ddc7aaefd114c22d4b18fa5fdc7ab1cf0d9b0f6b3b52315ac2185aa2dd394588'),
        ('src/adapter/surface/mod.rs', 'posted_empty_fault_state', '10559b7e88c8b25629c3d18b8498b69bd74523fee31aaae735e577fd21dc42fc'),
        ('src/adapter/surface/mod.rs', 'inject_posted_empty_fault', 'd3bcfb4dc6cba0703788cd1eb68cdd2bbf487ef7f1a84edfbf883bd0e1fb30b2'),
        ('src/adapter/surface/mod.rs', 'navigating_fault_ready', '170f33d3143a5c334f9bfedeaaa3fb1920f4d8811baa46dd2ad2abf7ad4226aa'),
        ('src/adapter/surface/mod.rs', 'navigating_fault_state', 'd6de42b2ce32c2d27068bfbb0652433e1d61aa517009d6b6a2d3909fc38e7b76'),
        ('src/adapter/surface/mod.rs', 'navigating_fault_owners_retained', 'abcc8f41aef3b7577e9900b4279f36a5c89485a4b193850e7227fc83ee6e7ea1'),
        ('src/adapter/surface/mod.rs', 'inject_navigating_fault', 'b7791d7cf75b7d40c5f41511903a92734bc5b2058596d2ba21209cadd40d61e0'),
        ('src/lib.rs', 'preload_fault_owners_retained', 'da2364753998997805c42fd95372b5675dc6623e00a3fdd36b208f65f2193e12'),
        ('src/ffi/session.rs', 'preload_fault_owners_retained', 'dd2db1b06d35a3a2b71399e52e861c2736c60c16555972199721b48edaacfad6'),
        ('src/adapter/surface/mod.rs', 'awaiting_load_fault_ready', '9c02146d3c7413eadec419859cb15ff50021afc4c68e0b93a00a332cc6064d6b'),
        ('src/adapter/surface/mod.rs', 'awaiting_load_fault_state', 'fafcc4256742a7180c886b0166eab7eed95f994f5407cc0c763c72adbdc5d6dc'),
        ('src/adapter/surface/mod.rs', 'awaiting_load_fault_owners_retained', 'fe4c7bf1d40e90f372500ce3700d5955844d2ca432167590d31feee3df60bf66'),
        ('src/adapter/surface/mod.rs', 'inject_awaiting_load_fault', '45efb89f8c5c2b93a9d2c4a27f5d97e597334c65a6fe9d2356e6913bf89278c8'),
        ("src/ffi/session.rs", "exit_fault_owners_retained", "21eb731d926c21f1098162ac9b9b3a0f9eef03ed0a5a923c915b3debb885f4d1"),
        ("src/adapter/surface/mod.rs", "releasing_fault_state", "13227b1d97e85f6b4e67a55fbddd45ed434d2a2fdeccfc95cb00b757e23e4010"),
        ("src/adapter/surface/mod.rs", "inject_releasing_fault", "b595eec3a4611cfd5adc730043826329a78216878a1eff8d5c4539ae1fbc7abd"),
        ("src/adapter/surface/mod.rs", "inject_view_fault", "46e4f6c4a8743a011753cee29d8b18067e16f5c179946c347fd13c3dabdd1f47"),
        ("src/adapter/surface/mod.rs", "exit_fault_phase_reached", "3507e06bb9ab7006e1d3303184163c8f5466f34b560b8165f50f4ec8cf23d0dc"),
        ("src/adapter/surface/mod.rs", "exit_fault_owners_retained", "0a3dbd358ff75e0d028d4f1e89f4867ef569cbbf074b8db0cdc9997306adaaad"),
        ("src/lib.rs", "recordless_controller_completion", "75e1e78404b4635cb121edd0d07834a5ffba8e7d05d018bc6b77d6c0192dcc2e"),
        ("src/lib.rs", "recordless_browser_candidate", "1ef7801db227ee0844983f1b22157a12d799d0d664c2e2d790120450a4039227"),
        ("src/lib.rs", "recordless_fault_owners_retained", "bc729d07de51de2ede38fdb6ffe64f9fb60168b194d33797c6eeb8289c564e06"),
        ("src/lib.rs", "exit_fault_owners_retained", "f7329128e67ce78852f1473ec3bf99ba958bb7a47b918bb4b36de536b5f2894a"),
        ("src/lib.rs", "inject_process_fault", "294b987cde982e756d951216a786fbf47cddcb352b67d16b5fb3e343644662ed"),
        ("src/ffi/session.rs", "fault_owners_retained", "eccda5bd1bc5847953133394e934a30276c539d09fa2842f0e3ad42722556f69"),
        ("src/adapter/surface/mod.rs", "fault_owners_retained", "f5b290213a5da3871f225e3abbba1e1f61c7ae0b021766b7d9a3f63f05b14b9f"),
        ("src/ffi/session.rs", "inject_process_fault", "e455365f08d79a80fdd9cc69c3a3e41e90f3a6d34b236e46b98fa5a7eee45ab1"),
        ("src/ffi/creation.rs", "succeeded", "abd90b783da539c962504dcb63f9a6f467fcbf0bf213e251f9b94c309a1f35f8"),
        ("src/ffi/session.rs", "recordless_controller_completion", "29b41776eba0afe06f194a40aa7d1fed581daa6b3c50e61394d884b8b203c3b1"),
        ("src/ffi/session.rs", "recordless_browser_candidate", "f9b8af0278a6b4f1ffe01a4c6483c9d204f574345270b49183a9f25a087052d7"),
        ("src/ffi/session.rs", "recordless_fault_owners_retained", "bf88e96c51f36f95a92be37186e2ecaede1d38a651ede1b969708b48956cc853"),
        ("src/adapter/surface/mod.rs", "recordless_opening_ready", "d5a07f5c6c28b374ad9f31ce3f5a061ce2f408d30a9bc2fc9d94543e0189a35b"),
        ("src/adapter/surface/mod.rs", "recordless_controller_completion", "28f286ba6e16abf3c08ebb0a1963b40b235b9f99ef8156e2d7710bd7cddc4138"),
        ("src/adapter/surface/mod.rs", "prepare_recordless_browser", "affa81267bf22aedb7928e98f4cfaa505c20f86f2464d3f8a2e1907a42c2a228"),
        ("src/adapter/surface/mod.rs", "inject_recordless_browser", "5511b49b260de834605d7df5b09ae676a81c252e8f23afebc643f475de4b4f73"),
        ("src/adapter/surface/mod.rs", "recordless_fault_event", "cdd869c7f6fdb57285a2b11bf88ea524706e4a2721a3ed76641b2ab3c2bad75a"),
        ("src/adapter/surface/mod.rs", "recordless_fault_owners_retained", "b4a262133309e1950953a8aecb3a15780bb2c2aa5d23d03934f576f8a8fd0093"),
        ("src/adapter/surface/mod.rs", "posted_fault_state", "7b58fa51f4ecc3d9c39f0721dd9c0b6e6afdbcafbad2198e42e565f8a6a5bf3b"),
        ("src/adapter/surface/mod.rs", "posted_fault_snapshot", "1134fc3bcaabdfee43ef2b50662f0c8f86c2a97cca0d278c5a9e2e33b578724a"),
        ("src/adapter/surface/mod.rs", "posted_fault_event", "9997eb9c0ff65871d2253e99fbe0cde02f599225d18c07e2dfc4c25e1c71d36f"),
        ("src/adapter/surface/mod.rs", "inject_posted_fault", "b0c851aca731b5aa318fa1dcc33f0f426cbad6a9ec6d61a2cf17d60ddc299050"),
    )
    for relative, name, digest in specifications:
        item = scans.get(relative)
        code = item[0].code if item else ""
        matches = list(re.finditer(rf"(?<!\w)fn\s+{name}\s*\(", code))
        if len(matches) != 1:
            found.append(f"{SHIM}/{relative}: process fault authority function {name} is missing or ambiguous")
            continue
        match = matches[0]
        opening = code.find("{", match.end())
        body = code[match.start():_matching_brace(code, opening) + 1] if opening >= 0 else ""
        if hashlib.sha256(re.sub(r"\s+", "", body).encode()).hexdigest() != digest:
            found.append(f"{SHIM}/{relative}: process fault authority function {name} differs from reviewed code")
        if "cfg(test)" not in _outer_attributes_before(code, item[1], match.start()):
            # A visibility modifier can occur between the attribute and fn.
            modifiers = FUNCTION_MODIFIERS.search(code[:match.start()])
            start = modifiers.start() if modifiers else match.start()
            if "cfg(test)" not in _outer_attributes_before(code, item[1], start):
                found.append(f"{SHIM}/{relative}: process fault authority function {name} requires cfg(test)")
    # Actual callback invocation markers and their bounded private recorder are
    # evidence only when both SDK call sites and the test caller are reviewed.
    callback_begin = root_code.find("#[cfg(test)]", root_code.find("struct Native;"))
    callback_end = root_code.find("#[forbid(unsafe_code)]", callback_begin)
    callback_block = root_code[callback_begin:callback_end] if callback_begin >= 0 and callback_end >= 0 else ""
    if hashlib.sha256(re.sub(r"\s+", "", callback_block).encode()).hexdigest() != "671b74e45e73bea3a430fb1c093e4fae333c98f2bed44b18a7867877228563e6":
        found.append(f"{SHIM}/src/lib.rs: callback ordering recorder differs from reviewed test-only code")
    for relative, digest in (("src/ffi/creation.rs", "a280e1ec7cb83ce6ab11082454e0162ed5d92035d538cc4ee72cc2cb8d6702fe"), ("src/ffi/environment.rs", "3fcf212e5718bca6a7262b768a7c711e05b76d6a34c1f446beb1acc2e9158bf9")):
        item = scans.get(relative)
        body = item[0].code if item else ""
        if hashlib.sha256(re.sub(r"\s+", "", body).encode()).hexdigest() != digest:
            found.append(f"{SHIM}/{relative}: callback invocation differs from reviewed SDK path")
    for relative, (scanned, _) in scans.items():
        for reference in re.finditer(r"(?<!\w)(?:NativeCallbackMoment|CALLBACK_ORDER|record_callback|callback_order|arm_callback_order|disarm_callback_order|NativeCreationMoment|CreationCallback|CREATION_ORDER|creation_moment|creation_order|arm_creation_order|disarm_creation_order)(?!\w)", scanned.code):
            allowed = relative in ("src/ffi/creation.rs", "src/ffi/environment.rs", "src/adapter/native_tests/process_fault.rs")
            allowed |= (
                relative == "src/adapter/native_tests/process_fault/model_tests/pending_opening_tests.rs"
                and reference.group() in ("NativeCallbackMoment", "callback_order")
            )
            allowed |= relative == "src/lib.rs" and callback_begin <= reference.start() < callback_end
            if not allowed:
                found.append(f"{SHIM}/{relative}: callback evidence references belong only in reviewed paths")
    fixture_root_item = scans.get("src/adapter/native_tests.rs")
    fixture_root_code = fixture_root_item[0].code if fixture_root_item else ""
    root_impls = list(re.finditer(r"(?<!\w)impl\s+FixtureRoot\s*\{", fixture_root_code))
    root_start = root_impls[0].start() if len(root_impls) == 1 else -1
    root_open = fixture_root_code.find("{", root_start) if root_start >= 0 else -1
    root_end = _matching_brace(fixture_root_code, root_open) if root_open >= 0 else -1
    root_body = fixture_root_code[root_start:root_end + 1] if root_end >= 0 else ""
    if hashlib.sha256(re.sub(r"\s+", "", root_body).encode()).hexdigest() != "30b62a1903eada0a14b9721b26c2a52d7ae138e6e70db52025230aca0e5dab78":
        found.append(f"{SHIM}/src/adapter/native_tests.rs: fixture root differs from reviewed private temporary directory")
    root_format = list(re.finditer(r"(?<!\w)format!\s*\(", root_body))
    expected_root = re.compile(r'format!\s*\(\s*"piglor-native-\{\}-\{\}-\{\}"')
    if (len(root_format) != 1 or not fixture_root_item or
            not expected_root.match(fixture_root_item[0].source, root_start + root_format[0].start())):
        found.append(f"{SHIM}/src/adapter/native_tests.rs: fixture root must use its fixed temporary name")
    obstruction_path = "src/adapter/native_tests/process_fault/obstruction.rs"
    obstruction = scans.get(obstruction_path)
    obstruction_code = obstruction[0].code if obstruction else ""
    if hashlib.sha256(re.sub(r"\s+", "", obstruction_code).encode()).hexdigest() != "37f4ba14dd9bf47d5b81a9cc4baeac1ed9a38d6f05b52f2b98fa25a46028de06":
        found.append(f"{SHIM}/{obstruction_path}: owned UDF obstruction differs from reviewed fixed fixture")
    join_calls = list(re.finditer(r"(?<!\w)folder\s*\.\s*join\s*\(", obstruction_code))
    fixed_join = re.compile(r'folder\s*\.\s*join\s*\(\s*"EBWebView"\s*\)')
    if (len(join_calls) != 1 or not obstruction or
            not fixed_join.match(obstruction[0].source, join_calls[0].start())):
        found.append(f"{SHIM}/{obstruction_path}: UDF obstruction must use its fixed EBWebView child")
    fixture = scans.get("src/adapter/native_tests/process_fault.rs")
    fixture_code = fixture[0].code if fixture else ""
    constructor = list(re.finditer(r"(?<!\w)fn\s+new_obstructed\s*\(", fixture_code))
    opening = fixture_code.find("{", constructor[0].end()) if len(constructor) == 1 else -1
    ending = _matching_brace(fixture_code, opening) if opening >= 0 else -1
    root_calls = [match for match in re.finditer(r"(?<!\w)let\s+root\s*=\s*root\s*\.\s*join\s*\(", fixture_code)
                  if opening < match.start() < ending]
    fixed_root = re.compile(r'let\s+root\s*=\s*root\s*\.\s*join\s*\(\s*"environment-obstruction"\s*\)')
    if (len(root_calls) != 1 or not fixture or not fixed_root.match(fixture[0].source, root_calls[0].start())):
        found.append(f"{SHIM}/src/adapter/native_tests/process_fault.rs: UDF obstruction root must use its fixed fixture child")
    declarations = [match for match in MOD_DECLARATION.finditer(fixture_code) if match.group("name") == "obstruction"]
    if len(declarations) != 1 or declarations[0].group("visibility"):
        found.append(f"{SHIM}/src/adapter/native_tests/process_fault.rs: obstruction module must be unique and private")
    for relative, (scanned, _) in scans.items():
        for reference in re.finditer(r"(?<!\w)(?:ObstructionFactory|ObstructionSession)(?!\w)", scanned.code):
            if relative not in (
                obstruction_path,
                "src/adapter/native_tests/process_fault.rs",
                "src/adapter/native_tests/process_fault/obstruction/tests.rs",
            ):
                found.append(f"{SHIM}/{relative}: UDF obstruction capability belongs only in the sealed test fixture")
    surface_item = scans.get("src/adapter/surface/mod.rs")
    surface_text = surface_item[0].code if surface_item else ""
    enum_start = surface_text.find("pub(in crate::adapter) enum PreEnvironmentRetention")
    enum_open = surface_text.find("{", enum_start) if enum_start >= 0 else -1
    enum_body = surface_text[enum_start:_matching_brace(surface_text, enum_open) + 1] if enum_open >= 0 else ""
    if (hashlib.sha256(re.sub(r"\s+", "", enum_body).encode()).hexdigest() != "9c39e796aa826523970cae61c061a219c7b0fb4a3f3ded23b586954bed10d395" or not surface_item or
            "cfg(test)" not in _outer_attributes_before(surface_text, surface_item[1], enum_start)):
        found.append(f"{SHIM}/src/adapter/surface/mod.rs: pre-environment retention type must be reviewed and test-only")
    for relative, name, digest in (('src/adapter/surface/mod.rs', 'open', 'bc942d2b6005fe1aca77e76d3841df05e48bd99373b9481e782097cb84747439'), ('src/ffi/session.rs', 'window', 'b25f4191690ca7a0aed740988fa01e94b213cc219a584c9111056ce155d1b79f'), ('src/ffi/window.rs', 'snapshot', 'a7ee6e1a5515f4cf82fd01e16a70cc5cf818c6fdf5016f4afcf3e554fd415727'),):
        item = scans.get(relative)
        source = item[0].code if item else ""
        matches = list(re.finditer(rf"(?<!\w)fn\s+{name}\s*\(", source))
        opening = source.find("{", matches[0].end()) if len(matches) == 1 else -1
        body = source[matches[0].start():_matching_brace(source, opening) + 1] if opening >= 0 else ""
        if hashlib.sha256(re.sub(r"\s+", "", body).encode()).hexdigest() != digest:
            found.append(f"{SHIM}/{relative}: competing-admission observation {name} differs from reviewed code")
    _check_fault_capabilities(scans, found)
    surface = scans.get("src/adapter/surface/mod.rs")
    surface_code = surface[0].code if surface else ""
    recordless_fields = list(re.finditer(r"(?<!\w)recordless_fault\s*:", surface_code))
    if len(recordless_fields) != 2 or not surface or any(
        "cfg(test)" not in _outer_attributes_before(surface_code, surface[1], field.start())
        for field in recordless_fields
    ):
        found.append(f"{SHIM}/src/adapter/surface/mod.rs: recordless fixture identity and initialization require cfg(test)")
    _check_zero_witness(scans, found)
    relative = "src/adapter/native_tests/process_fault.rs"
    item = scans.get(relative)
    code = item[0].code if item else ""
    if hashlib.sha256(re.sub(r"\s+", "", code).encode()).hexdigest() != "0886cec2a7bdbdaab921005f628a0060e1d1cade855f954be4fb0d4dae448969":
        found.append(f"{SHIM}/{relative}: process fault fixture differs from reviewed sealed caller")


def _check_fault_capabilities(scans: dict[str, tuple[Scan, tuple[Attribute, ...]]], found: list[str]) -> None:
    root = scans.get("src/lib.rs")
    code = root[0].code if root else ""
    begin = code.find("pub(crate) enum ProcessFaultTarget")
    end = code.find("pub(crate) trait NativeOperations", begin) if begin >= 0 else -1
    for marker in ("struct FaultSeal", "impl FaultSeal", "struct FaultAuthority", "impl FaultAuthority"):
        start = code.find(marker)
        if start < 0 or not root or "cfg(test)" not in _outer_attributes_before(code, root[1], start):
            found.append(f"{SHIM}/src/lib.rs: {marker} requires its private cfg(test) declaration")
    for relative, (scanned, _) in scans.items():
        source = scanned.code
        for reference in re.finditer(r"(?<!\w)model_main_renderer_exit(?!\w)", source):
            allowed = (
                relative == "src/ffi/events/control_fixture.rs"
                and re.search(r"\bfn\s+$", source[max(0, reference.start() - 16):reference.start()]) is not None
            ) or (
                relative == "src/adapter/native_tests/process_fault/model_tests.rs"
                and any(name == "modeled_early_renderer_observer_enforces_deadline" and start < reference.start() < stop
                        for name, start, stop in _function_spans(source))
            )
            if not allowed or re.search(r"(?<!\w)model_main_renderer_exit\s+as\s", source):
                found.append(f"{SHIM}/{relative}: modeled renderer observation belongs only in its reviewed model")
        retained_paths = {
            "src/lib.rs", "src/ffi/process_fault.rs", "src/ffi/session.rs",
            "src/adapter/surface/exit_boundary.rs", "src/adapter/surface/tests/native.rs",
        }
        if relative not in retained_paths and re.search(r"(?<!\w)RetainedExitHandle(?!\w)", source):
            found.append(f"{SHIM}/{relative}: retained-exit capability belongs only in reviewed paths")
        if re.search(r"(?<!\w)RetainedExitHandle\s+as\s", source):
            found.append(f"{SHIM}/{relative}: retained-exit capability may not be aliased")
        # A named struct can also be constructed through a type alias. Confine
        # every reference to these types to already hash-bound source regions,
        # so imports, aliases, generic aliases and extra implementations cannot
        # introduce an unreviewed route around the literal constructor checks.
        regions = [(begin, end)] if relative == "src/lib.rs" else []
        reviewed_functions = {
            "src/lib.rs": ("inject_process_fault", "retain_exit_browser"),
            "src/ffi/session.rs": ("inject_process_fault", "retain_exit_browser"),
            "src/adapter/surface/tests/native.rs": ("retain_exit_browser", "terminate", "inject_process_fault"),
            "src/adapter/surface/exit_boundary.rs": ("acquire_exit_handle", "consume_exit_capture"),
            "src/adapter/surface/diagnostics.rs": ("inject_quarantined_fault",),
            "src/adapter/surface/tests.rs": ("quarantined_fault_refuses_missing_state_and_unheld_keeper",),
            "src/adapter/surface/mod.rs": (
                "inject_posted_fault", "inject_recordless_browser", "inject_releasing_fault",
                "inject_view_fault", "inject_awaiting_load_fault", "inject_navigating_fault", "inject_posted_empty_fault", "inject_pending_opening_browser", "inject_posted_writing_fault", "inject_posted_ready_fault", "inject_posted_retry_fault", "inject_posted_consuming_fault", "inject_before_record_fault",
            ),
        }.get(relative, ())
        for reviewed_function in reviewed_functions:
            for function in re.finditer(rf"(?<!\w)fn\s+{reviewed_function}\s*\(", source):
                opening = source.find("{", function.end())
                if opening >= 0:
                    regions.append((function.start(), _matching_brace(source, opening) + 1))
        if relative in ("src/ffi/process_fault.rs", "src/adapter/native_tests/process_fault.rs",
                        "src/adapter/native_tests/process_fault/quarantined.rs",
                        "src/adapter/surface/tests/fault_admission.rs"):
            regions.append((0, len(source)))
        for reference in re.finditer(r"(?<!\w)(?:FaultSeal|FaultAuthority)(?!\w)", source):
            if not any(start <= reference.start() < stop for start, stop in regions):
                found.append(f"{SHIM}/{relative}: fault capability references belong only in reviewed authority paths")
        if re.search(r"(?<!\w)(?:FaultSeal|FaultAuthority)\s+as\s", source):
            found.append(f"{SHIM}/{relative}: fault capabilities may not be aliased")
        for implementation in re.finditer(r"\bimpl\b[^{;]*\b(?:FaultSeal|FaultAuthority)\b[^{;]*\{", source):
            if relative != "src/lib.rs" or not begin <= implementation.start() < end:
                found.append(f"{SHIM}/{relative}: fault capability implementations belong only in the reviewed root types")
        for match in re.finditer(r"(?<!\w)FaultSeal\s*[(\{]", source):
            root_declaration = relative == "src/lib.rs" and begin <= match.start() < end
            sealed_fixture = relative in (
                "src/adapter/native_tests/process_fault.rs",
                "src/adapter/native_tests/process_fault/quarantined.rs",
            )
            # The complete model-only admission fixture is source-bound below.
            negative_fixture = (
                relative == "src/adapter/surface/tests/fault_admission.rs"
                or relative == "src/adapter/surface/tests.rs" and any(
                    name == "quarantined_fault_refuses_missing_state_and_unheld_keeper"
                    and start < match.start() < stop
                    for name, start, stop in _function_spans(source)
                )
            )
            if not root_declaration and not sealed_fixture and not negative_fixture:
                found.append(f"{SHIM}/{relative}: FaultSeal construction belongs only in the sealed fixture")
        for match in re.finditer(r"(?<!\w)FaultAuthority\s*\{", source):
            root_declaration = relative == "src/lib.rs" and begin <= match.start() < end
            surface_construction = relative == "src/adapter/surface/mod.rs" and any(
                name in ("inject_view_fault", "inject_recordless_browser", "inject_awaiting_load_fault", "inject_navigating_fault", "inject_pending_opening_browser", "inject_before_record_fault") and start < match.start() < stop
                for name, start, stop in _function_spans(source)
            )
            exit_construction = relative == "src/adapter/surface/exit_boundary.rs" and any(
                name in ("acquire_exit_handle", "consume_exit_capture") and start < match.start() < stop
                for name, start, stop in _function_spans(source)
            )
            quarantined_construction = relative == "src/adapter/surface/diagnostics.rs" and any(
                name == "inject_quarantined_fault" and start < match.start() < stop
                for name, start, stop in _function_spans(source)
            )
            if not root_declaration and not surface_construction and not quarantined_construction and not exit_construction:
                found.append(f"{SHIM}/{relative}: FaultAuthority construction belongs only in the validated Surface path")


def _check_zero_witness(scans: dict[str, tuple[Scan, tuple[Attribute, ...]]], found: list[str]) -> None:
    relative = "src/ffi/buffers.rs"
    item = scans.get(relative)
    code = item[0].code if item else ""
    if hashlib.sha256(re.sub(r"\s+", "", code).encode()).hexdigest() != "b8c453561d2bef99821a2ef593ea9a3717d13dcc2618b3087bdd2f82ba1c7f37":
        found.append(f"{SHIM}/{relative}: live mapping witness differs from the reviewed atomic readback")
    for pattern in (r"mod\s+zero_witness", r"let\s+witness\s*=\s*zero_witness::before", r"zero_witness::after\s*\("):
        matches = list(re.finditer(pattern, code))
        if len(matches) != 1 or not item or "cfg(test)" not in _outer_attributes_before(code, item[1], matches[0].start()):
            found.append(f"{SHIM}/{relative}: live mapping witness module and both call sites require cfg(test)")
    root = scans.get("src/lib.rs")
    root_code = root[0].code if root else ""
    start = root_code.find("pub(crate) struct NativeZeroObservation")
    if start < 0 or not root or "cfg(test)" not in _outer_attributes_before(root_code, root[1], start):
        found.append(f"{SHIM}/src/lib.rs: native zero observations require cfg(test)")
    opening = root_code.find("{", start) if start >= 0 else -1
    body = root_code[start:_matching_brace(root_code, opening) + 1] if opening >= 0 else ""
    if hashlib.sha256(re.sub(r"\s+", "", body).encode()).hexdigest() != "e73ff178509c2658db05d26e183da64f05a0a1f7b57187e80b7b73f7fa838871":
        found.append(f"{SHIM}/src/lib.rs: native zero observation fields differ from the reviewed booleans")


def _check_member_sources(root: Path, directory: Path, scanned_dirs: tuple[Path, ...], found: list[str]) -> None:
    for source in _walk(directory)[0]:
        label = source.relative_to(root).as_posix()
        text = _read(source)
        scanned = scan(text)
        _check_surface(label, source, directory, text, scanned, _attributes(scanned.code), scanned_dirs, False, found)
        for token in UNSAFE_TOKEN.finditer(scanned.code):
            found.append(f"{label}:{_line_of(scanned.code, token.start())}: unsafe is reserved for {SHIM}/src/ffi")


def _inventory_blocks(shim: Path, root: Path, found: list[str]) -> list[tuple[tuple[str, int], dict[str, object]]]:
    path = shim / INVENTORY
    label = f"{SHIM}/{INVENTORY}"
    if not path.is_file():
        found.append(f"{label}: missing unsafe inventory")
        return []
    data = _toml(root, path, found)
    if data is None:
        return []
    blocks = data.get("block", [])
    if not isinstance(blocks, list):
        found.append(f"{label}: block must be an array")
        return []
    parsed: list[tuple[tuple[str, int], dict[str, object]]] = []
    for index, entry in enumerate(blocks, start=1):
        if not isinstance(entry, dict):
            found.append(f"{label}: block {index} is not a table")
            continue
        missing = [field for field in REQUIRED_BLOCK_FIELDS if field not in entry]
        if missing:
            found.append(f"{label}: block {index} is missing {', '.join(missing)}")
            continue
        file = entry["file"]
        line = entry["line"]
        strings = tuple(entry[field] for field in REQUIRED_BLOCK_FIELDS if field not in {"file", "line"})
        if (
            not isinstance(file, str)
            or not isinstance(line, int)
            or isinstance(line, bool)
            or line < 1
            or not all(isinstance(value, str) and value for value in strings)
        ):
            found.append(f"{label}: block {index} has an invalid field")
            continue
        pure = PurePosixPath(file)
        if (
            pure.is_absolute()
            or ".." in pure.parts
            or "\\" in file
            or not file.startswith("src/ffi/")
            or not file.endswith(".rs")
        ):
            found.append(f"{label}: block {index} has an invalid ffi file path")
            continue
        parsed.append(((file, line), {str(field): value for field, value in entry.items()}))
    return parsed


def _check_inventory(shim: Path, root: Path, shim_scan: ShimScan, found: list[str]) -> None:
    label = f"{SHIM}/{INVENTORY}"
    records: dict[tuple[str, int], dict[str, object]] = {}
    for key, record in _inventory_blocks(shim, root, found):
        if key in records:
            found.append(f"{label}: duplicate record for {key[0]}:{key[1]}")
        records[key] = record
    for key in sorted(shim_scan.blocks):
        if key not in records:
            found.append(f"{label}: missing record for {key[0]}:{key[1]}")
    for key, record in sorted(records.items()):
        block = shim_scan.blocks.get(key)
        if block is None:
            found.append(f"{label}: stale record for {key[0]}:{key[1]}")
            continue
        function = str(record["function"])
        if function.rsplit("::", 1)[-1] not in block.functions:
            enclosing = ", ".join(block.functions) or "no fn"
            found.append(
                f"{label}: function {function} for {key[0]}:{key[1]} does not enclose the block "
                f"(enclosed by {enclosing})"
            )
        hosted_test = str(record["hosted_test"])
        if not _hosted_test_exists(shim_scan.scans, hosted_test):
            found.append(
                f"{label}: hosted test {hosted_test} for {key[0]}:{key[1]} "
                "is not a live #[test] function under tests/ or src/"
            )


def _check_owned_parent_boundary(sources: dict[str, str], found: list[str]) -> None:
    """Bind the private parent/child fixture and its only test-support plan call."""
    prefix = "crates/pos-owner-bridge-windows/src/"
    lib = prefix + "lib.rs"
    # Pin complete source text, including literals, attributes and enclosing
    # module scopes. Function-body-only hashes cannot detect a removed #[test]
    # or a disabled enclosing cfg. _read normalizes platform line endings.
    complete_sources = {
        lib: "0d395f5c6d154bcd9023f195e7891c9c464936b6e50a4167853853caf3196b63",
        prefix + "ffi/mod.rs": "e0d5c4aa2ad33f5d68df91fded5e57c6ce7f9e3d908aef88ff8b275810eec68c",
        prefix + "adapter/native_tests.rs": "1514271d14a58ab895a46b71e60daf5a5a54bb751f305c99531aab20caacb8d5",
        "crates/pos-owner-bridge/src/ceremony/plan.rs": "bb0cbe0ced177ac33833c89cffaa68f2e30ddd4af0e07e875c67283b6e9cb3e6",
    }
    for path, digest in complete_sources.items():
        if hashlib.sha256(sources.get(path, "").replace("\r\n", "\n").encode()).hexdigest() != digest:
            found.append(f"{path}: owned-parent source and hosted-test scope differ from reviewed code")
    helper = prefix + "ffi/fixture_parent.rs"
    expected = "c1c027e0bfe94959430e05a5827c7251d5aa6ccb0cb1fe124116d236fb0f2a1d"
    if hashlib.sha256(sources.get(helper, "").encode()).hexdigest() != expected:
        found.append(f"{helper}: owned-parent fixture differs from reviewed test-only code")
    module = sources.get(prefix + "ffi/mod.rs", "")
    if len(re.findall(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*mod\s+fixture_parent\s*;", module)) != 1:
        found.append(f"{prefix}ffi/mod.rs: owned-parent module must be cfg(test)")
    plan = "crates/pos-owner-bridge/src/ceremony/plan.rs"
    if not re.search(r"#\s*\[\s*cfg\s*\(\s*feature\s*=\s*\"test-support\"\s*\)\s*\]\s*impl\s+CeremonyPlan\s*\{", sources.get(plan, "")):
        found.append(f"{plan}: owned-parent plan builder must be test-support only")
    if not re.search(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*#\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]\s*mod\s+tests\s*\{", sources.get(lib, "")):
        found.append(f"{lib}: native host fixture must remain in the test module")
    specs = (
        (plan, "with_test_owner_window", "df7788308f2149191a92004d4d57598c85c4036d2dc60cb106d1bccba6367606"),
        (lib, "native_host_fixture_child", "00c2d4140ff13359ffdcb7c81f100b6452ff07538e1c6e9ad08c5a8daf011c75"),
        (lib, "native_host_opens_fresh_environments_and_retires_before_reuse", "59cbe1ca5074bdb5088a7c318424844127288858c7318f4341bb0b08db449ce7"),
        (prefix + "adapter/native_tests.rs", "native_host_lifecycle", "ad257a26fd236b84eaf1fd2100af8c43bd16b723c40177dcc61414342779ba7a"),
    )
    for path, name, digest in specs:
        raw = sources.get(path, "")
        spans = [(start, end) for found_name, start, end in _function_spans(scan(raw).code) if found_name == name]
        if len(spans) != 1 or hashlib.sha256(re.sub(r"\s+", "", raw[spans[0][0]:spans[0][1]]).encode()).hexdigest() != digest:
            found.append(f"{path}: owned-parent function {name} differs from reviewed code")
    uses = {
        "fixture_parent": {prefix + "ffi/mod.rs", helper},
        "OwnedParent": {helper},
        "child_owner": {helper},
        "with_test_owner_window": {plan, prefix + "adapter/native_tests.rs", "crates/pos-owner-bridge/tests/protocol/opening.rs"},
        "native_host_parent_fixture": {helper, lib},
        "native_host_lifecycle": {helper, prefix + "adapter/native_tests.rs"},
    }
    for path, raw in sources.items():
        code = scan(raw).code
        for name, allowed in uses.items():
            if path not in allowed and re.search(rf"(?<!\w){name}(?!\w)", code):
                found.append(f"{path}: owned-parent capability {name} outside reviewed fixture")


# Exact source/asset custody for test-only qualification observations
# and the accepted External URI profile.
# Full text binds attributes, literal URI, handler/denial observations and scope.
EXTERNAL_FIXTURE_SOURCES = {
    'crates/pos-owner-bridge-windows/src/adapter/native_tests/process_fault.rs': '70134cb12338bdb5f15b6c2858096f602c58b7395feefa54f09ba92ea704def8',
    'crates/pos-owner-bridge-windows/src/adapter/native_tests/process_fault/model_tests.rs': '683d6dca23ae30b4b11d7eaec43558f93336af93ea746936bb2469fabaa58314',
    'crates/pos-owner-bridge-windows/src/adapter/native_tests/process_fault/model_tests/pending_opening_tests.rs': 'c3c9c42aa293d2c472439368c758c5c6ee9491b4301aff1f009ef05420ba9790',
    'crates/pos-owner-bridge-windows/src/adapter/native_tests/process_fault/port_tests.rs': '1fc463501f4590c17e1e6f50bea051cabe5cdfa3e90e1585c6d70275718b78a5',
    'crates/pos-owner-bridge-windows/src/adapter/surface/tests/pending_creation.rs': 'd7f8754a41ff1f90d47de9934b629f01792dc1a5330c197ba2f5b59916b762c2',
    'crates/pos-owner-bridge-windows/src/adapter/surface/tests/exit_boundary_tests.rs': 'e8fe541efe44f7eda4565a6086fbdcf1900889af1299abc3bed72e9112b5ba92',
    'crates/pos-owner-bridge-windows/src/adapter/host.rs': '4b36b2618d257d2769eacea9acd3b264d0f4a68f060842520dc357f036d2e84a',
    'crates/pos-owner-bridge-windows/src/adapter/host/tests.rs': 'f987aa8a99b0e5d55e476f1b8db2e4665942dd934997269b54639f7e63030236',
    'crates/pos-owner-bridge-windows/src/adapter/surface/tests/native.rs': '9570125bc1ae53bd8ca100db668b1ca7d4718c5145dbe88f7bb9f7836f678662',
    'crates/pos-owner-bridge-windows/src/adapter/surface/tests/fault_admission.rs': 'd46cb485049f2d2828503f38a13b2e97a38d43e5ec0d43b8e1422f2e9912394e',
    'crates/pos-owner-bridge-windows/src/adapter/native_tests/process_fault/obstruction/tests.rs': 'f8b4ec091ca43d5652f3852b08ab5c1642ce1f8f269001ae886f202b7770b210',
    'crates/pos-owner-bridge-windows/src/adapter/native_tests/readiness.rs': '0da3ddc90381e0f6c0015d6f71677ec7ab3030c3cd560e0723baf3bbaab21788',
    'crates/pos-owner-bridge-windows/src/ffi/window.rs': '75ab4125d3d73408247b96d86724aaf1afa9e1163ff67efe3f962c4c779e61dc',
    'crates/pos-owner-bridge-windows/src/adapter/native_tests/session.rs': '78e5cbddbe3984c769f518f980c06f7c01802a0baaaf418eeb1302b4dadc7850',
    'crates/pos-owner-bridge-windows/src/adapter/native_tests/process_fault/quarantined.rs': '250b1334b5d681c9da45c3265d12eb46737411415b79aa380dc86d16ad40c49e',
    'crates/pos-owner-bridge-windows/src/adapter/surface/diagnostics.rs': '93b9252dd497dde9d16dd85eccffa8cef508d637046e5d352e23666de9370b15',
    'crates/pos-owner-bridge-windows/src/adapter/surface/exit_boundary.rs': '0669c03257c31be00fa41c224b3031eeaeccaab4936cbbb7eec4006ad5742fd8',
    'crates/pos-owner-bridge-windows/src/adapter/surface/tests.rs': 'bd6ce6cae654ee04b191e8486c0b173a6c7eb41b1e2dfc29d91f3e4f14d99cca',
    'crates/pos-owner-bridge-windows/src/adapter/surface/tests/fault_states.rs': 'd1a3d6d9e2b4e961aedc060b0c82bd7072c74e9b2cd3cfe794dfee86b2056cc3',
    'crates/pos-owner-bridge-windows/src/adapter/surface/controller_qualification.rs': '682b4398d10aadf642285a49f570d23d18162b3813c809b5f9f7c4cb2a0d99b5',
    'crates/pos-owner-bridge-windows/src/ffi/process_fault.rs': '06c9c91606a4500a0ade936cb0b3292c14853128671c88df6e1781e7bbc61fe0',
    'crates/pos-owner-bridge-windows/src/ffi/process_fault/candidate_tests.rs': '29ea47f5ebe24db94d0d8104b2bb13e8338743c7411db543f00cd350d2fd22df',
    'crates/pos-owner-bridge-windows/src/adapter/surface/mod.rs': '95c472ff1aa10f08e2788921da6524d9a4e16e8164d853e0ad46c238ba07bf58',
    'crates/pos-owner-bridge-windows/src/ffi/events/controls.rs': '8c53ef70d3d845bebd2a1d84976765e4a37beafb44ba3a0eb5359b2725c91d29',
    'crates/pos-owner-bridge-windows/src/ffi/events/mod.rs': 'cf9f1cb7a28dea1bce36c1c939bd0f901177e3f84dc0b020d450c43d2b4359e7',
    'crates/pos-owner-bridge-windows/src/ffi/events/denial.rs': '71f6f8d17899bb398948fada325cb478cd7e71e532c38ac305f83dc686a0ddf9',
    'crates/pos-owner-bridge-windows/src/ffi/session.rs': 'cbf00676ab0b7589051f9a6db3502ab240c8e0177e9cd0efb3f916dfcbdcaf6e',
    'crates/pos-owner-bridge-windows/src/lib.rs': '0d395f5c6d154bcd9023f195e7891c9c464936b6e50a4167853853caf3196b63',
    'crates/pos-owner-bridge-windows/src/adapter/native_tests/controls.rs': 'fed180557f6f13b8b30a4b6815cf8eb823ddef6a53f7e6055397159af3c68379',
    'crates/pos-owner-bridge-windows/src/adapter/native_tests.rs': '1514271d14a58ab895a46b71e60daf5a5a54bb751f305c99531aab20caacb8d5',
    'crates/pos-owner-bridge-windows/src/adapter/events.rs': 'dc38f06f41d825b8487ddb33e5f637d6931bae05927e2091125ca1b034d6a718',
    'crates/pos-owner-bridge-windows/src/ffi/events/navigation.rs': '63f7dd99a0acd42cf9d7397b87dcadac042bbda0d9f3b59a393562d3424cff98',
    'crates/pos-owner-bridge-windows/src/ffi/events/resource.rs': '45a67ad7beb6d2fd518428e95f3b83f951ef26b8eace0b31cae52ef940c8315c',
    'crates/pos-owner-bridge-windows/src/ffi/events/control_fixture.rs': '7bccb277d733e1d1f1b57f2c678259ba511183e61f98be366ea7d6adaf91caa3',
    'crates/pos-owner-bridge-windows/src/ffi/events/control_denial.rs': '3fee8a9ea7609019c88fce323b9e5ecd8cadc372e69c14d477d1c4c66d235157',
    'scripts/owner_bridge_assets.py': '8be7cf5afd2c9fd534989a02bb0766f9faf3994c018264efbbaa33fa74a40cb5',
    'crates/pos-owner-bridge/assets/qualification/external.html': '45c476fa75fd4ac257c62148a1b288eb7f13ab411d371d8b8842eec48a9e96b4',
    'crates/pos-owner-bridge/assets/qualification/manifest.json': '4d37c95ce8fd82b2bc183cffdee8ee11a164f4c534e12a09b87a35780e193811',
    'crates/pos-owner-bridge/src/listener/fixture_assets.rs': '7891ff7491e638fb11ecdb54f04b8270cf5a24c5c80b46971402d0064c971c3d',
    'crates/pos-owner-bridge/src/listener/fixtures.rs': '2487177ab012dad956a79396d87714e4a7aaacbf897d44e8cbc801bb893cb998',
}


def _check_external_fixture(sources: dict[str, str], found: list[str]) -> None:
    for path, expected in EXTERNAL_FIXTURE_SOURCES.items():
        digest = hashlib.sha256(sources.get(path, "").replace("\r\n", "\n").encode()).hexdigest()
        if digest != expected:
            found.append(f"{path}: External URI qualification differs from reviewed source")
    controls = "crates/pos-owner-bridge-windows/src/adapter/native_tests/controls.rs"
    parent_loss_sources = {
        f"{SHIM}/src/lib.rs",
        f"{SHIM}/src/ffi/session.rs",
        f"{SHIM}/src/ffi/window.rs",
        f"{SHIM}/src/adapter/surface/controller_qualification.rs",
        f"{SHIM}/src/adapter/native_tests/process_fault.rs",
    }
    for path, source in sources.items():
        if not path.endswith(".rs"):
            continue
        code = scan(source).code
        if path != controls and re.search(r"\b(?:ExternalAllowance|EXTERNAL_URI)\b", code):
            found.append(f"{path}: External allowance capability outside private fixture")
        parent_references = list(re.finditer(
            r"\b(?:ControllerParentLossSeal|lose_controller_parent|"
            r"lose_pending_controller_parent|lost_controller_parent_retention)\b", code
        ))
        pending_model = f"{SHIM}/src/adapter/surface/tests/pending_creation.rs"
        if path == pending_model:
            spans = [(start, end) for name, start, end in _function_spans(code)
                     if name == "modeled_controller_qualification_retains_pending_owners_on_refusal"]
            if (len(spans) != 1 or len(parent_references) != 2
                    or any(ref.group() != "lose_pending_controller_parent"
                           or not spans[0][0] <= ref.start() < spans[0][1]
                           for ref in parent_references)):
                found.append(f"{path}: controller parent loss capability outside sealed test fixture")
        elif path not in parent_loss_sources and parent_references:
            found.append(f"{path}: controller parent loss capability outside sealed test fixture")


def violations(root: Path, *, component_fixture: bool = False) -> list[str]:
    """Return every source-policy violation beneath ``root``, sorted."""
    root = root.resolve()
    found: list[str] = []
    root_manifest_path = root / "Cargo.toml"
    if not root_manifest_path.is_file():
        return ["Cargo.toml: missing workspace manifest"]
    root_manifest = _toml(root, root_manifest_path, found)
    if root_manifest is None:
        return found
    members = _workspace_members(root_manifest)
    if SHIM not in members:
        return [f"Cargo.toml: workspace must contain {SHIM}"]

    directories: dict[str, Path] = {}
    for member in members:
        if any(character in member for character in "*?["):
            found.append(f"Cargo.toml: glob workspace member {member} cannot be audited; list members explicitly")
            continue
        directory = (root / member).resolve()
        if (root / member).is_symlink():
            found.append(f"Cargo.toml: workspace member {member} is a symlink")
        elif directory != Path(os.path.normpath(root / member)):
            found.append(f"Cargo.toml: workspace member {member} traverses a symlink")
        elif not directory.is_relative_to(root):
            found.append(f"Cargo.toml: workspace member {member} is outside the repository")
        elif not (directory / "Cargo.toml").is_file():
            found.append(f"{member}/Cargo.toml: workspace member manifest is missing")
        else:
            directories[member] = directory
    scanned_dirs = tuple(directories.values())
    _check_root_lints(root_manifest, found)
    _check_path_dependencies(root, root, root_manifest, scanned_dirs, found)
    for directory in scanned_dirs:
        for link in _walk(directory)[1]:
            found.append(f"{link.relative_to(root).as_posix()}: symlinks are forbidden under a scanned workspace member")

    shim = directories.get(SHIM)
    if shim is not None:
        shim_manifest = _toml(root, shim / "Cargo.toml", found)
        if shim_manifest is not None:
            _check_shim_lints(root_manifest, shim_manifest, found)
            _check_path_dependencies(root, shim, shim_manifest, scanned_dirs, found)
            _check_shim_manifest_keys(shim_manifest, found)
        _check_inventory(shim, root, _check_shim_sources(shim, scanned_dirs, found), found)

    for member, directory in directories.items():
        if member == SHIM:
            continue
        manifest = _toml(root, directory / "Cargo.toml", found)
        if manifest is not None:
            _check_path_dependencies(root, directory, manifest, scanned_dirs, found)
            _check_target_paths(root, directory, manifest, found)
        if manifest is not None:
            lints = manifest.get("lints")
            if not isinstance(lints, dict) or lints.get("workspace") is not True:
                found.append(f"{member}/Cargo.toml: non-shim crate must set [lints] workspace = true")
            if _contains_unsafe_code_lint(manifest.get("lints", {})):
                found.append(f"{member}/Cargo.toml: non-shim crate configures unsafe_code")
        _check_member_sources(root, directory, scanned_dirs, found)
    owned_sources = {
        source.relative_to(root).as_posix(): _read(source)
        for directory in scanned_dirs
        for source in _walk(directory)[0]
        if source.suffix == ".rs"
    }
    if not component_fixture:
        _check_owned_parent_boundary(owned_sources, found)
        external_sources = dict(owned_sources)
        for path in EXTERNAL_FIXTURE_SOURCES:
            source = root / path
            external_sources[path] = _read(source) if source.is_file() else ""
        _check_external_fixture(external_sources, found)
    return sorted(set(found))


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
