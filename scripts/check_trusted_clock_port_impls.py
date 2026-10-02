#!/usr/bin/env python3
"""Restrict ADR-112 trusted-host port implementations.

`TrustedClockStorePortV1` and `ReleaseGuardPortV1` are trusted-host
interfaces: an implementation that reports rows or lock state untruthfully
can obtain a real handoff token. Implementations may live only in
`crates/pos-store`, `crates/pos-runtime`, or a `test-support` fixture file
whose module is gated by the inner attribute
`#![cfg(any(test, feature = "test-support"))]`.
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
LINE_COMMENT = re.compile(r"//[^\n]*")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
SKIPPED_PARTS = {"target", ".git", ".trunk", "node_modules"}


def strip_comments(text: str) -> str:
    """Remove comments so documentation cannot trigger or hide a finding."""
    return LINE_COMMENT.sub("", BLOCK_COMMENT.sub("", text))


def allowed(relative: str, text: str) -> bool:
    if relative.startswith(ALLOWED_PREFIXES):
        return True
    return FIXTURE_GATE.search(text) is not None


def violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        relative_parts = path.relative_to(root).parts
        if SKIPPED_PARTS.intersection(relative_parts):
            continue
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        code = strip_comments(text)
        if IMPL.search(code) and not allowed(relative, text):
            found.append(f"{relative}: trusted-clock port implemented outside the trusted host")
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
