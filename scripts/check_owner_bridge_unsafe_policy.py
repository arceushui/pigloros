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
MISSING = object()


@dataclass(frozen=True)
class Scan:
    """Masked source plus the standalone ``//`` comments by 0-based line."""

    code: str
    code_lines: tuple[str, ...]
    comments: dict[int, str]
    raw_identifiers: tuple[int, ...] = ()


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


def _is_word(character: str) -> bool:
    return character.isalnum() or character == "_"


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
        elif _is_word(character):
            end = index + 1
            while end < length and _is_word(text[end]):
                end += 1
            word = text[index:end]
            after = text[end : end + 1]
            if word in RAW_PREFIXES and after in ('"', "#"):
                quote = end
                while quote < length and text[quote] == "#":
                    quote += 1
                if quote < length and text[quote] == '"':
                    emit(_raw_string_end(text, quote, quote - end), "blank")
                    continue
                if word == "r" and quote == end + 1 and quote < length and _is_word(text[quote]):
                    identifier_end = quote
                    while identifier_end < length and _is_word(text[identifier_end]):
                        identifier_end += 1
                    emit(identifier_end, "ident")
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
        else:
            emit(index + 1, "keep")
    code = "".join(pieces)
    return Scan(code, tuple(code.split("\n")), comments, tuple(raw_identifiers))


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


# ADR-132's exclusive creator is a deliberately narrow native capability.
# Compare its executable tokens, not comments or an operation-name inventory.
LEDGER_CREATOR_BODY = r'''
{
 let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
 if path[..path.len() - 1].contains(&0) { return Err(()); }
 let sid = super::directory::current_sid()?;
 let text: Vec<u16> = format!("O:{sid}D:P(A;;FA;;;{sid})").encode_utf16().chain([0]).collect();
 let mut output = PSECURITY_DESCRIPTOR::default();
 unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(text.as_ptr()), SDDL_REVISION_1, &raw mut output, None,) }.map_err(|_| ())?;
 let security = LocalMemory(HLOCAL(output.0));
 let attributes = SECURITY_ATTRIBUTES {
  nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| ())?,
  lpSecurityDescriptor: security.0 .0,
  bInheritHandle: false.into(),
 };
 let handle = unsafe { CreateFileW(PCWSTR(path.as_ptr()), (GENERIC_READ | GENERIC_WRITE).0,
  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, Some(&raw const attributes), CREATE_NEW,
  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, None,) }.map_err(|_| ())?;
 let owned = unsafe { OwnedHandle::from_raw_handle(handle.0) };
 Ok(File::from(owned))
}
'''

LEDGER_OPEN_BODY = r'''
{
 let path = guard.test_directory.join("PiglorOS");
 require_dos_path(&path)?;
 match fs::symlink_metadata(&path) {
  Ok(_) => crate::verify_private_directory(&path).map_err(|_| ())?,
  Err(error) if error.kind() == io::ErrorKind::NotFound => {
   crate::create_private_directory(&path).map_err(|_| ())?;
  }
  Err(_) => return Err(()),
 }
 crate::Native::cleanup_path_ntfs(&path)?;
 let directory = open_directory(&path)?;
 let volume = crate::Native::cleanup_file_volume(&directory)?;
 let store = Self { _guard: guard, directory, path, volume, };
 store.admit_directory()?;
 store.remove_stale_temporary()?;
 Ok(store)
}
'''

LEDGER_GUARD_ACQUIRE_BODY = r'''
{
 if !test_directory.is_absolute() || !test_directory.is_dir() { return Err(unavailable()); }
 crate::SubjectMutex::acquire().map(|mutex| Self { mutex, test_directory: test_directory.to_owned(), }).map_err(|()| unavailable())
}
'''

LEDGER_ADMISSION_BODIES = {
    "admit_directory": r'''{ crate::verify_private_directory(&self.path).map_err(|_| ())?;
      if crate::Native::cleanup_file_volume(&self.directory)? != self.volume { return Err(()); }
      let reopened = open_directory(&self.path)?;
      if crate::Native::file_identity(&self.directory)? != crate::Native::file_identity(&reopened)? { return Err(()); }
      Ok(()) }''',
    "validate_file": r'''{ let metadata = file.metadata().map_err(|_| ())?;
      if !metadata.is_file() || metadata.file_attributes() & REPARSE_POINT != 0 { return Err(()); }
      crate::Native::require_private_file(file)?;
      if crate::Native::file_link_count(file)? != 1 || crate::Native::cleanup_file_volume(file)? != self.volume { return Err(()); }
      Self::same_name(file, path) }''',
    "same_name": r'''{ let reopened = open_file(path)?;
      if crate::Native::file_identity(file)? != crate::Native::file_identity(&reopened)? { return Err(()); }
      Ok(()) }''',
    "open_existing": r'''{ let path = self.path.join(name); let file = open_file(&path)?;
      self.validate_file(&file, &path)?; Ok(file) }''',
    "open_directory": r'''{ OpenOptions::new().read(true).share_mode(SHARE_ALL)
      .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0).open(path).map_err(|_| ()) }''',
    "open_file": r'''{ OpenOptions::new().read(true).write(true).share_mode(SHARE_ALL)
      .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_WRITE_THROUGH.0).open(path).map_err(|_| ()) }''',
    "read_bounded": r'''{ let mut bytes = Vec::new(); file.take((LIMIT + 1) as u64).read_to_end(&mut bytes).map_err(|_| ())?;
      if bytes.len() > LIMIT { return Err(()); } Ok(bytes) }''',
    "require_dos_path": r'''{ let mut components = path.components();
      if !matches!(components.next(), Some(Component::Prefix(prefix))
       if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
       || components.next() != Some(Component::RootDir)
       || components.any(|component| !matches!(component, Component::Normal(_))) { return Err(()); }
      Ok(()) }''',
}


def _literal_at(code: str, text: str, anchor: str, literal: str) -> bool:
    matches = list(re.finditer(anchor, code))
    return len(matches) == 1 and bool(re.match(r"\s*" + re.escape(literal), text[matches[0].end() :]))


def _check_ledger_origin(relative: str, label: str, text: str, code: str, spans: tuple[tuple[str, int, int], ...], found: list[str]) -> None:
    if relative == "src/adapter/ledger_storage.rs" and "create_private_ledger_file" in code:
        openings = [(begin, end) for name, begin, end in spans if name == "open"]
        impls = []
        for item in re.finditer(r"\bimpl\s*<\s*'guard\s*>\s*WindowsNonceLedger\s*<\s*'guard\s*>\s*\{", code):
            opening = item.end() - 1
            impls.append((opening, _matching_brace(code, opening)))
        if len(openings) != 1 or not any(begin < openings[0][0] < end for begin, end in impls) or _normalized(code[openings[0][0] : openings[0][1] + 1]) != _normalized(scan(LEDGER_OPEN_BODY).code):
            found.append(f"{label}: ADR-132 ledger directory must derive from the held guard and be admitted")
        elif not _literal_at(code[openings[0][0] : openings[0][1]], text[openings[0][0] : openings[0][1]], r"\bjoin\s*\(", '"PiglorOS"'):
            found.append(f"{label}: ADR-132 ledger directory must use the fixed leaf")
        if not _literal_at(code, text, r"\bconst\s+TEMPORARY\s*:\s*&\s*str\s*=", '"subject-nonce-ledger.v1.tmp"'):
            found.append(f"{label}: ADR-132 staging name must remain fixed")
        if not _literal_at(code, text, r"\bconst\s+LEDGER\s*:\s*&\s*str\s*=", '"subject-nonce-ledger.v1"'):
            found.append(f"{label}: ADR-132 primary ledger name must remain fixed")
        for name, expected in LEDGER_ADMISSION_BODIES.items():
            matches = [(begin, end) for candidate, begin, end in spans if candidate == name]
            if len(matches) != 1 or _normalized(code[matches[0][0] : matches[0][1] + 1]) != _normalized(scan(expected).code):
                found.append(f"{label}: ADR-132 ledger admission helper {name} changed")
        compact = _normalized(code)
        if any(item not in compact for item in ("constSHARE_ALL:u32=7;", "constREPARSE_POINT:u32=0x400;", "constLIMIT:usize=1_048_576;")):
            found.append(f"{label}: ADR-132 ledger admission constants changed")
    if relative == "src/adapter/nonce_ledger.rs":
        acquire = [(begin, end) for name, begin, end in spans if name == "acquire"]
        guard = _normalized("pub struct WindowsSubjectEncryptorLock { mutex: crate::SubjectMutex, pub(super) test_directory: PathBuf, }")
        if guard not in _normalized(code) or len(acquire) != 1 or _normalized(code[acquire[0][0] : acquire[0][1] + 1]) != _normalized(scan(LEDGER_GUARD_ACQUIRE_BODY).code):
            found.append(f"{label}: ADR-132 ledger guard must acquire and retain the subject mutex")


def _check_ledger_creator(label: str, text: str, code: str, spans: tuple[tuple[str, int, int], ...], found: list[str]) -> None:
    creators = [(begin, end) for name, begin, end in spans if name == "create_private_ledger_file"]
    if len(creators) != 1:
        found.append(f"{label}: ADR-132 requires exactly one ledger creator")
        return
    begin, end = creators[0]
    function = next((item for item in FUNCTION.finditer(code) if item.group(1) == "create_private_ledger_file" and item.start() < begin), None)
    start = code.rfind("\n", 0, function.start()) + 1 if function else begin
    signature = "pub(crate)fncreate_private_ledger_file(path:&Path)->Result<File,()>"
    if function is None or _normalized(code[start:begin]) != signature:
        found.append(f"{label}: ADR-132 ledger creator signature and visibility changed")
    actual = code[begin : end + 1]
    if _normalized(actual) != _normalized(scan(LEDGER_CREATOR_BODY).code):
        found.append(f"{label}: ADR-132 ledger creator executable body differs from the authorized boundary")
    format_call = re.search(r"\bformat\s*!\s*\(", actual)
    if format_call is None or not re.match(r'\s*"O:\{sid\}D:P\(A;;FA;;;\{sid\}\)"\s*\)', text[begin + format_call.end() : end]):
        found.append(f"{label}: ADR-132 ledger creator must use the exact current-SID owner and DACL")
    imports = (
        "use std::os::windows::io::{FromRawHandle, OwnedHandle};",
        "use windows::core::PCWSTR;",
        "use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HLOCAL};",
        "use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,};",
        "use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};",
        "use windows::Win32::Storage::FileSystem::{CreateFileW, MoveFileExW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,};",
        "use super::directory::LocalMemory;",
    )
    compact = _normalized(code)
    if any(_normalized(item) not in compact for item in imports):
        found.append(f"{label}: ADR-132 creator must use the pinned SDK and shared allocation owner")


def _test_only_regions(code: str, attributes: tuple[Attribute, ...], header: str) -> tuple[tuple[int, int], ...]:
    regions = []
    for match in re.finditer(header, code):
        start = code.rfind("\n", 0, match.start()) + 1
        if "cfg(test)" in _outer_attributes_before(code, attributes, start):
            opening = match.end() - 1
            regions.append((opening, _matching_brace(code, opening)))
    return tuple(regions)


def _check_ledger_creator_calls(relative: str, label: str, code: str, attributes: tuple[Attribute, ...], spans: tuple[tuple[str, int, int], ...], found: list[str]) -> None:
    fixture_regions: tuple[tuple[int, int], ...] = ()
    if relative == "src/adapter/ledger_storage.rs":
        fixture_regions = _test_only_regions(code, attributes, r"\bmod\s+native_tests\s*\{")
    elif relative == "src/adapter/store_file_identity.rs":
        fixture_regions = _test_only_regions(code, attributes, r"\bimpl\s+crate\s*::\s*Native\s*\{")
    ledger_impls = []
    for item in re.finditer(r"\bimpl\s*<\s*'guard\s*>\s*WindowsNonceLedger\s*<\s*'guard\s*>\s*\{", code):
        opening = item.end() - 1
        start = code.rfind("\n", 0, item.start()) + 1
        guards = _outer_attributes_before(code, attributes, start)
        if code[:item.start()].count("{") == code[:item.start()].count("}") and not any(
            guard.startswith(("cfg(", "cfg_attr(")) for guard in guards
        ):
            ledger_impls.append((opening, _matching_brace(code, opening)))
    replacements = [(begin, end) for name, begin, end in spans if name == "replace_observing"]
    declarations = [item for item in FUNCTION.finditer(code) if item.group(1) == "replace_observing"]
    active_replacement = None
    if len(ledger_impls) == len(replacements) == len(declarations) == 1:
        impl_begin, impl_end = ledger_impls[0]
        begin, end = replacements[0]
        declaration = declarations[0]
        start = code.rfind("\n", 0, declaration.start()) + 1
        guards = _outer_attributes_before(code, attributes, start)
        prefix = code[impl_begin + 1 : declaration.start()]
        if (impl_begin < declaration.start() < begin < end < impl_end
                and prefix.count("{") == prefix.count("}")
                and not any(guard.startswith(("cfg(", "cfg_attr(")) for guard in guards)):
            active_replacement = (begin, end)
    production_calls = 0
    for occurrence in re.finditer(r"\bcreate_private_ledger_file\b", code):
        before = code[max(0, occurrence.start() - 100) : occurrence.start()]
        after = code[occurrence.end() :]
        if re.search(r"\bfn\s*$", before):
            if relative != "src/ffi/ledger_storage.rs":
                found.append(f"{label}: ADR-132 ledger creator declaration is restricted")
            continue
        is_call = bool(re.match(r"\s*\(", after)) and bool(re.search(r"(?:crate\s*::\s*Native|Self)\s*::\s*$", before))
        fixture = any(begin < occurrence.start() < end for begin, end in fixture_regions)
        production = (relative == "src/adapter/ledger_storage.rs" and active_replacement is not None
                      and active_replacement[0] < occurrence.start() < active_replacement[1])
        if not is_call or not (fixture or production):
            found.append(f"{label}:{_line_of(code, occurrence.start())}: ADR-132 ledger creator caller is not an admitted staging or cfg(test) fixture")
        if production:
            production_calls += 1
    if relative == "src/adapter/ledger_storage.rs" and active_replacement is None:
        found.append(f"{label}: ADR-132 requires one active ledger replacement method")
    elif relative == "src/adapter/ledger_storage.rs" and active_replacement is not None:
        compact = _normalized(code[active_replacement[0] : active_replacement[1] + 1])
        required = _normalized('''{ if bytes.len() > LIMIT { return Err(()); }
            self.admit_directory()?;
            let previous = self.open_existing(LEDGER)?;
            let temporary_path = self.path.join(TEMPORARY);
            let mut temporary = crate::Native::create_private_ledger_file(&temporary_path)?;
            self.validate_file(&temporary, &temporary_path)?;''')
        owner = _normalized("pub struct WindowsNonceLedger<'guard> { _guard: &'guard WindowsSubjectEncryptorLock, directory: File, path: PathBuf, volume: u32, }")
        if production_calls != 1 or not compact.startswith(required) or owner not in _normalized(code):
            found.append(f"{label}: ADR-132 creator must use the held-guard admitted staging path")


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
        if relative == "src/ffi/ledger_storage.rs" and any(name == "create_private_ledger_file" for name, _, _ in spans):
            _check_ledger_creator(label, text, code, spans, found)
        _check_ledger_origin(relative, label, text, code, spans, found)
        _check_ledger_creator_calls(relative, label, code, attributes, spans, found)
        imports = tuple((item.start(), item.end()) for item in USE_STATEMENT.finditer(code))
        for reference in re.finditer(r"\bCreateFileW\b", code):
            imported = any(begin < reference.start() < end for begin, end in imports)
            inside_creator = any(
                name == "create_private_ledger_file" and begin < reference.start() < end
                for name, begin, end in spans
            )
            if relative != "src/ffi/ledger_storage.rs" or not (imported or inside_creator):
                found.append(f"{label}:{_line_of(code, reference.start())}: ADR-132 CreateFileW reference is outside the creator")
        for create in re.finditer(r"\bCreateFileW\s*\(", code):
            inside_creator = any(
                name == "create_private_ledger_file" and begin < create.start() < end
                for name, begin, end in spans
            )
            if relative != "src/ffi/ledger_storage.rs" or not inside_creator:
                found.append(f"{label}:{_line_of(code, create.start())}: ADR-132 CreateFileW is restricted to the ledger creator")
        for alias in re.finditer(r"\bCreateFileW\s+as\s+", code):
            found.append(f"{label}:{_line_of(code, alias.start())}: ADR-132 CreateFileW aliases are forbidden")
        for query in re.finditer(r"\bGetHandleInformation\s*\(", code):
            inside_witness = any(
                name == "fixture_handle_not_inheritable" and begin < query.start() < end
                for name, begin, end in spans
            )
            if relative != "src/ffi/ledger_storage.rs" or not inside_witness:
                found.append(f"{label}:{_line_of(code, query.start())}: ADR-132 handle query belongs only in the fixture witness")
        for alias in re.finditer(r"\bGetHandleInformation\s+as\s+", code):
            found.append(f"{label}:{_line_of(code, alias.start())}: ADR-132 handle query aliases are forbidden")
        for function in FUNCTION.finditer(code):
            if function.group(1) == "fixture_handle_not_inheritable":
                start = code.rfind("\n", 0, function.start()) + 1
                if relative != "src/ffi/ledger_storage.rs" or "cfg(test)" not in _outer_attributes_before(code, attributes, start):
                    found.append(f"{label}:{_line_of(code, function.start())}: ADR-132 handle witness requires cfg(test)")
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
    return ShimScan(blocks, scans)


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


def violations(root: Path) -> list[str]:
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
