#!/usr/bin/env python3
"""Enforce ADR-110 E15's source boundary before subject-encryption activation.

The inventory contains the activation type currently implemented. Extend it
when another activation constructor lands; pure codecs and role enums are not
activation types. References to these types stay in file-gated fixtures, so a
function pointer, inferred return type or struct literal cannot hide a builder.
Existing protocol-test fakes are exempt from the non-fake
port rule. The feature-graph checker separately excludes test-support from
deployable graphs. This source check does not establish activation approval.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from check_owner_bridge_unsafe_policy import _group_end, scan
from check_trusted_clock_port_impls import FIXTURE_GATE, SKIPPED_PARTS, strip_comments

TYPES = ("SubjectEncryptorLock",)
PORTS = ("EnrollmentPort", "UnlockPort")
NAMES = "|".join((*TYPES, *PORTS))
TYPE_NAMES = "|".join(TYPES)
ALIAS = re.compile(r"\buse\b[^;]*\b(?:" + NAMES + r")\s+as\b", re.DOTALL)
TYPE_ALIAS = re.compile(r"\btype\s+\w+[^;=]*=[^;]*\b(?:" + NAMES + r")\b", re.DOTALL)
ACTIVATION_REFERENCE = re.compile(r"\b(?:" + TYPE_NAMES + r")\b")
PORT_IMPL = re.compile(
    r"\b(?:" + "|".join(PORTS) + r")\s+for\s+([^;{]+)",
    re.DOTALL,
)
REFERENCE = re.compile(r"\b(?:" + NAMES + r")\b")
PORT_REFERENCE = re.compile(r"\b(?:" + "|".join(PORTS) + r")\b")
MACRO = re.compile(r"\b\w+\s*!\s*([({\[])")
TEST_ITEM = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:#\[[^\]]*\]\s*)*")
FAKES = {
    "crates/pos-owner-bridge/tests/protocol/main.rs": {"FakeEnrollment", "FakeUnlock"},
}


def without_test_items(code: str) -> str:
    """Mask explicitly cfg(test) items, preserving source offsets."""
    if re.match(r"\A\s*(?:#!\[[^\]]*\]\s*)*?#!\[\s*cfg\(\s*test\s*\)\s*\]", code):
        return ""
    result = list(code)
    for match in TEST_ITEM.finditer(code):
        end = match.end()
        while end < len(code) and code[end] not in "{;":
            end += 1
        if end < len(code) and code[end] == "{":
            depth = 1
            end += 1
            while end < len(code) and depth:
                depth += (code[end] == "{") - (code[end] == "}")
                end += 1
        else:
            end += 1
        result[match.start():end] = " " * (end - match.start())
    return "".join(result)


def check_source(relative: str, text: str) -> list[str]:
    """Check real tokens and the actual file-leading gate, not quoted examples."""
    scanned = scan(text)
    code = scanned.code
    errors = []
    if ALIAS.search(code) or TYPE_ALIAS.search(code):
        errors.append("activation type or owner port is hidden by an alias")
    for offset in scanned.raw_identifiers:
        identifier = re.match(r"r#(\w+)", text[offset:])
        if identifier and identifier[1] in (*TYPES, *PORTS):
            errors.append("raw identifier hides an activation type or owner port")
    gated = FIXTURE_GATE.match(strip_comments(text)) is not None
    nonfake = any(
        match[1].strip() not in FAKES.get(relative, set()) for match in PORT_IMPL.finditer(code)
    )
    hidden_port = any(
        PORT_REFERENCE.search(code[match.end():_group_end(code, match.start(1))])
        for match in MACRO.finditer(code)
    )
    if not gated and (ACTIVATION_REFERENCE.search(code) or nonfake or hidden_port):
        errors.append("activation constructor or non-fake owner port lacks the E15 file gate")
    if relative.startswith("apps/") and REFERENCE.search(without_test_items(code)):
        errors.append("deployable app names the activation surface outside cfg(test)")
    return [f"{relative}: {error}" for error in errors]


def violations(root: Path) -> list[str]:
    errors = []
    for path in sorted(root.rglob("*.rs")):
        relative = path.relative_to(root)
        if relative.parts[0] in SKIPPED_PARTS:
            continue
        errors.extend(check_source(relative.as_posix(), path.read_text(encoding="utf-8")))
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    errors = violations(parser.parse_args().root.resolve())
    if errors:
        raise SystemExit("\n".join(errors))
    print("subject-encryption activation remains confined to test support")


if __name__ == "__main__":
    main()
