#!/usr/bin/env python3
"""Contract tests for the documentation-only Rust scope filter."""

from __future__ import annotations

import fnmatch
import pathlib
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
FILTER_PATH = ROOT / ".github" / "rust-scope.yml"
EXPECTED_EXCLUDES = {
    "!**/*.md",
    "!**/*.mdx",
    "!**/*.adoc",
    "!**/*.rst",
    "!.agents/**",
    "!.cursor/**",
    "!docs/**",
}


def load_patterns() -> list[str]:
    with FILTER_PATH.open(encoding="utf-8") as stream:
        filters = yaml.safe_load(stream)
    if not isinstance(filters, dict) or not isinstance(filters.get("rust"), list):
        raise AssertionError("rust-scope.yml must define a rust pattern list")
    patterns = filters["rust"]
    if not all(isinstance(pattern, str) for pattern in patterns):
        raise AssertionError("rust-scope.yml patterns must be strings")
    return patterns


def excluded(path: str, patterns: list[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(path, pattern[1:])
        or fnmatch.fnmatchcase(path, pattern[1:].removeprefix("**/"))
        for pattern in patterns
        if pattern.startswith("!")
    )


def rust_gate_required(paths: list[str], patterns: list[str]) -> bool:
    return any(not excluded(path, patterns) for path in paths)


class RustScopePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.patterns = load_patterns()

    def test_filter_has_conservative_positive_default(self) -> None:
        self.assertEqual(self.patterns[0], "**")
        self.assertEqual(set(self.patterns[1:]), EXPECTED_EXCLUDES)

    def test_documentation_only_paths_skip_rust_gate(self) -> None:
        paths = [
            "README.md",
            "guide/topic.mdx",
            "adr/decision.adoc",
            "notes/history.rst",
            ".agents/skills/example.md",
            ".cursor/rules/example.txt",
            "docs/reference.txt",
        ]
        self.assertFalse(rust_gate_required(paths, self.patterns))

    def test_unknown_and_build_inputs_require_rust_gate(self) -> None:
        paths = ("src/lib.rs", "Cargo.toml", "plugin.wit", ".github/workflows/ci.yml")
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(rust_gate_required([path], self.patterns))

    def test_deleted_and_renamed_rust_inputs_require_rust_gate(self) -> None:
        self.assertTrue(rust_gate_required(["old.rs"], self.patterns))
        self.assertTrue(rust_gate_required(["old.rs", "moved.md"], self.patterns))


if __name__ == "__main__":
    unittest.main()
