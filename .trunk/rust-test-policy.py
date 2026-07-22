#!/usr/bin/env python3
"""Trunk custom linter: no #[ignore]; coverage(off) only on test code.

Prints Trunk regex diagnostics:
  path:line:col: [error] message (code)

Ignores matches inside line comments, block comments, and string/char literals.
Also bans #[cfg_attr(..., ignore)] forms.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Real attribute forms only (applied after comment/string masking).
IGNORE_ATTR = re.compile(
    r"#\[\s*ignore(?:\s*\([^)]*\))?\s*\]"
    r"|#\[\s*cfg_attr\s*\([^)]*\bignore\b[^)]*\)\s*\]"
)
DOC_IGNORE = re.compile(r"```(?:rust,)?ignore\b")
COV_OFF = re.compile(r"coverage\s*\(\s*off\s*\)")
TEST_ATTR = re.compile(r"#\[\s*(?:tokio::)?test(?:\s*\([^)]*\))?\s*\]")
CFG_TEST = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]")
MOD_START = re.compile(r"\bmod\s+[A-Za-z_][A-Za-z0-9_]*")


def emit(path: str, line: int, code: str, message: str) -> None:
    print(f"{path}:{line}:1: [error] {message} ({code})")


def mask_non_code(text: str) -> str:
    """Replace comments and string/char literals with spaces (preserve newlines)."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        # Line comment
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # Block comment
        if text.startswith("/*", i):
            out.append("  ")
            i += 2
            while i < n and not text.startswith("*/", i):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append("  ")
                i += 2
            continue
        # Raw string r#"..."# / r##"..."##
        if text[i] == "r" and i + 1 < n and (text[i + 1] == '"' or text[i + 1] == "#"):
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                closing = '"' + ("#" * hashes)
                out.extend(" " for _ in range(j + 1 - i))
                i = j + 1
                while i < n and not text.startswith(closing, i):
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
                if i < n:
                    out.extend(" " for _ in range(len(closing)))
                    i += len(closing)
                continue
        # Normal string
        if text[i] == '"':
            out.append(" ")
            i += 1
            while i < n:
                if text[i] == "\\":
                    out.append("  ")
                    i += 2
                    continue
                if text[i] == '"':
                    out.append(" ")
                    i += 1
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        # Char literal
        if text[i] == "'":
            out.append(" ")
            i += 1
            if i < n and text[i] == "\\":
                out.append("  ")
                i += 2
            elif i < n:
                out.append(" ")
                i += 1
            if i < n and text[i] == "'":
                out.append(" ")
                i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def check(path: Path) -> int:
    text = path.read_text(errors="ignore")
    masked = mask_non_code(text)
    lines = text.splitlines()
    masked_lines = masked.splitlines()
    # Pad if trailing newline differences
    while len(masked_lines) < len(lines):
        masked_lines.append("")

    depth = 0
    test_body_starts: list[int] = []
    findings = 0

    for i, line in enumerate(lines):
        stripped = line.strip()
        masked_stripped = masked_lines[i].strip() if i < len(masked_lines) else ""
        window_back = "\n".join(lines[max(0, i - 6) : i + 1])
        opens = stripped.count("{")
        closes = stripped.count("}")

        entering = False
        if opens > 0 and CFG_TEST.search(window_back):
            if MOD_START.search(stripped) or stripped.startswith("impl ") or " impl " in stripped:
                entering = True
        if entering:
            test_body_starts.append(depth + 1)

        depth += opens - closes
        while test_body_starts and depth < test_body_starts[-1]:
            test_body_starts.pop()

        # Doc fences (//! / ///): masked // comments hide ```ignore; check raw doc lines.
        doc_line = stripped.startswith("//!") or stripped.startswith("///")
        if doc_line:
            # Strip the doc marker then look for fence
            body = re.sub(r"^//[/!]\s?", "", stripped)
            if DOC_IGNORE.search(body):
                emit(
                    str(path),
                    i + 1,
                    "forbidden-doc-ignore",
                    "```ignore doctest fence is forbidden — use ```text or a real doctest "
                    "(CI runs --include-ignored)",
                )
                findings += 1
        elif DOC_IGNORE.search(masked_stripped):
            emit(
                str(path),
                i + 1,
                "forbidden-doc-ignore",
                "```ignore doctest fence is forbidden — use ```text or a real doctest "
                "(CI runs --include-ignored)",
            )
            findings += 1

        if IGNORE_ATTR.search(masked_stripped):
            emit(
                str(path),
                i + 1,
                "forbidden-ignore",
                "#[ignore] / #[cfg_attr(..., ignore)] is forbidden — every test must run in CI",
            )
            findings += 1

        if not COV_OFF.search(masked_stripped):
            continue

        allowed = bool(test_body_starts)
        ahead = "\n".join(lines[i : min(len(lines), i + 10)])
        if TEST_ATTR.search(ahead):
            allowed = True
        around = "\n".join(lines[max(0, i - 6) : min(len(lines), i + 4)])
        if CFG_TEST.search(around) and (
            MOD_START.search(around) or re.search(r"\bimpl\b", around)
        ):
            allowed = True

        if not allowed:
            emit(
                str(path),
                i + 1,
                "coverage-off-production",
                "coverage(off) is only allowed on #[test]/#[tokio::test] or #[cfg(test)] code",
            )
            findings += 1

    return 1 if findings else 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: rust-test-policy.py <file.rs>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.is_file():
        return 0
    return check(path)


if __name__ == "__main__":
    raise SystemExit(main())
