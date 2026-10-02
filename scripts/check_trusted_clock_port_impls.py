#!/usr/bin/env python3
"""Restrict ADR-112 trusted-host port implementations.

`TrustedClockStorePortV1` and `ReleaseGuardPortV1` are trusted-host
interfaces: an implementation that reports rows or lock state untruthfully
can obtain a real handoff token. Implementations may live only in
`crates/pos-store`, `crates/pos-runtime`, or a `test-support` fixture file
whose module is gated by the inner attribute
`#![cfg(any(test, feature = "test-support"))]`.

Renaming a port with `use ... as` outside those paths is rejected too, so an
alias cannot hide an implementation from the `impl` pattern. Only top-level
build and tooling directories are skipped; a nested directory named `target`
inside a crate is still scanned.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

PORTS = ("TrustedClockStorePortV1", "ReleaseGuardPortV1")
ALLOWED_PREFIXES = ("crates/pos-store/", "crates/pos-runtime/")
FIXTURE_GATE = re.compile(
    r'^#!\[cfg\(any\(test,\s*feature\s*=\s*"test-support"\)\)\]\s*$', re.MULTILINE
)
IMPL = re.compile(
    r"\bimpl\b(?:\s*<[^{;]*?>)?[^{;]*?\b(?:" + "|".join(PORTS) + r")\b(?:\s*<[^{;]*?>)?\s+for\b",
    re.DOTALL,
)
ALIAS = re.compile(r"\buse\b[^;]*?\b(?:" + "|".join(PORTS) + r")\s+as\b", re.DOTALL)
RAW_STRING = re.compile(r'b?r(#*)"')
SKIPPED_PARTS = {"target", ".git", ".trunk", "node_modules"}


def _identifier_char(text: str, index: int) -> bool:
    return index >= 0 and (text[index].isalnum() or text[index] == "_")


def _block_comment_end(text: str, index: int) -> int:
    """Return the index after the (nested) block comment opened at `index`."""
    depth = 0
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
    return index


def _quoted_end(text: str, index: int, quote: str) -> int:
    """Return the index after the escaped literal whose opening quote is at `index`."""
    index += 1
    while index < len(text) and text[index] != quote:
        index += 2 if text[index] == "\\" else 1
    return index + 1


def _char_literal_end(text: str, index: int) -> int:
    """Return the end of a char literal at `index`, or `index` for a lifetime."""
    if text.startswith("\\", index + 1):
        return _quoted_end(text, index, "'")
    if index + 2 < len(text) and text[index + 2] == "'":
        return index + 3
    return index


def _literal_end(text: str, index: int) -> int:
    """Return the end of a string, raw string or char literal at `index`, or `index`."""
    if text[index] in "br" and _identifier_char(text, index - 1):
        return index
    raw = RAW_STRING.match(text, index)
    if raw:
        closing = '"' + raw.group(1)
        end = text.find(closing, raw.end())
        return len(text) if end < 0 else end + len(closing)
    start = index + 1 if text.startswith(("b\"", "b'"), index) else index
    if text.startswith('"', start):
        return _quoted_end(text, start, '"')
    if text.startswith("'", start):
        end = _char_literal_end(text, start)
        return index if end == start else end
    return index


def strip_comments(text: str) -> str:
    """Remove comments so documentation cannot trigger or hide a finding.

    String, raw string and char literals are copied verbatim, so a comment
    opener inside a literal cannot swallow the code that follows it.
    """
    kept: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            kept.append(" ")
            continue
        if text.startswith("/*", index):
            index = _block_comment_end(text, index)
            kept.append(" ")
            continue
        end = _literal_end(text, index)
        if end == index:
            end = index + 1
        kept.append(text[index:end])
        index = end
    return "".join(kept)


def allowed(relative: str, text: str) -> bool:
    if relative.startswith(ALLOWED_PREFIXES):
        return True
    return FIXTURE_GATE.search(text) is not None


def violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        relative_parts = path.relative_to(root).parts
        if relative_parts[0] in SKIPPED_PARTS:
            continue
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        code = strip_comments(text)
        if allowed(relative, text):
            continue
        if IMPL.search(code):
            found.append(f"{relative}: trusted-clock port implemented outside the trusted host")
        if ALIAS.search(code):
            found.append(f"{relative}: trusted-clock port aliased outside the trusted host")
    return found


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    found = violations(root)
    if found:
        raise SystemExit("\n".join(found))
    print("trusted-clock ports are implemented only by the trusted host")


if __name__ == "__main__":
    main()
