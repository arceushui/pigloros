#!/usr/bin/env python3
"""Adversarial tests for the owner-bridge vector and listener-asset checker.

Each test copies the checker, the packaged page, its manifest and the Rust asset constants into
a temporary tree, tampers with exactly one of them, and requires `owner_bridge_vectors.py
--check` to fail. The untouched copy must pass, so a failure is never an artefact of the copy.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = "scripts/owner_bridge_vectors.py"
BRIDGE = "crates/pos-owner-bridge"
COPIED = (
    CHECKER,
    f"{BRIDGE}/assets/owner.html",
    f"{BRIDGE}/assets/manifest.v1",
    f"{BRIDGE}/src/listener/assets.rs",
)
ASSETS_RS = f"{BRIDGE}/src/listener/assets.rs"
PAGE = f"{BRIDGE}/assets/owner.html"
MANIFEST = f"{BRIDGE}/assets/manifest.v1"


def flip_first_byte(name: str) -> Callable[[str], str]:
    """Change the first byte of the Rust byte-array constant `name`."""

    def transform(source: str) -> str:
        pattern = re.compile(rf"(const {name}: \[u8; 32\] = \[\s*0x)([0-9a-f]{{2}})")
        match = pattern.search(source)
        if match is None:
            raise AssertionError(f"{name} not found")
        flipped = f"{int(match.group(2), 16) ^ 1:02x}"
        return source[: match.start(2)] + flipped + source[match.end(2) :]

    return transform


def replace_once(old: str, new: str) -> Callable[[str], str]:
    """Replace the single occurrence of `old`, failing if the text is not there exactly once."""

    def transform(source: str) -> str:
        if source.count(old) != 1:
            raise AssertionError(f"{old!r} occurs {source.count(old)} times")
        return source.replace(old, new)

    return transform


def replace_first(old: str, new: str) -> Callable[[str], str]:
    """Replace the first occurrence of `old`."""

    def transform(source: str) -> str:
        if old not in source:
            raise AssertionError(f"{old!r} not found")
        return source.replace(old, new, 1)

    return transform


class OwnerBridgeVectorChecker(unittest.TestCase):
    """The checker accepts the real tree and rejects every single tampering."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tree = Path(directory.name)
        for relative in COPIED:
            target = self.tree / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / relative, target)

    def edit(self, relative: str, transform: Callable[[str], str]) -> None:
        path = self.tree / relative
        path.write_text(transform(path.read_text(encoding="utf-8")), encoding="utf-8")

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(self.tree / CHECKER), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_rejected(self, expected: str | None = None) -> None:
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        if expected is not None:
            self.assertIn(expected, result.stderr)

    def test_the_untampered_tree_passes(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ALL MATCH", result.stdout)

    def test_a_wrong_document_digest_is_rejected(self) -> None:
        self.edit(ASSETS_RS, flip_first_byte("OWNER_HTML_SHA256"))
        self.assert_rejected("OWNER_HTML_SHA256")

    def test_a_wrong_response_digest_is_rejected(self) -> None:
        self.edit(ASSETS_RS, flip_first_byte("OWNER_RESPONSE_SHA256"))
        self.assert_rejected("OWNER_RESPONSE_SHA256")

    def test_a_wrong_content_length_is_rejected(self) -> None:
        self.edit(ASSETS_RS, replace_first("Content-Length: ", "Content-Length: 1"))
        self.assert_rejected("OWNER_RESPONSE_HEAD")

    def test_an_edited_script_block_is_rejected(self) -> None:
        self.edit(PAGE, replace_once("<script>", "<script> "))
        self.assert_rejected()

    def test_an_edited_style_block_is_rejected(self) -> None:
        self.edit(PAGE, replace_once("<style>", "<style> "))
        self.assert_rejected()

    def test_a_changed_page_with_an_unchanged_manifest_is_rejected(self) -> None:
        self.edit(PAGE, lambda text: text + "\n")
        self.assert_rejected()

    def test_a_missing_manifest_entry_is_rejected(self) -> None:
        self.edit(MANIFEST, lambda text: "")
        self.assert_rejected()

    def test_a_manifest_with_a_wrong_digest_is_rejected(self) -> None:
        self.edit(MANIFEST, lambda text: "0" * 64 + text[64:])
        self.assert_rejected()

    def test_a_manifest_with_a_wrong_content_type_is_rejected(self) -> None:
        self.edit(MANIFEST, replace_once("text/html", "text/plain"))
        self.assert_rejected()

    def test_a_missing_security_header_is_rejected(self) -> None:
        self.edit(ASSETS_RS, replace_first('"X-Content-Type-Options: nosniff\\r\\n",', ""))
        self.assert_rejected()

    def test_a_weakened_content_security_policy_is_rejected(self) -> None:
        self.edit(ASSETS_RS, replace_first("default-src 'none'", "default-src 'self'"))
        self.assert_rejected()

    def test_a_changed_permissions_policy_is_rejected(self) -> None:
        self.edit(ASSETS_RS, replace_first("camera=()", "camera=(self)"))
        self.assert_rejected()

    def test_a_changed_fixed_error_response_is_rejected(self) -> None:
        self.edit(ASSETS_RS, replace_first("404 Not Found", "404 Not Founds"))
        self.assert_rejected("NOT_FOUND_RESPONSE")

    def test_a_wrong_script_hash_constant_is_rejected(self) -> None:
        self.edit(
            ASSETS_RS,
            lambda text: re.sub(
                r'(CSP_SCRIPT_SHA256: &str = ")(.)',
                lambda match: match.group(1) + ("B" if match.group(2) == "A" else "A"),
                text,
                count=1,
            ),
        )
        self.assert_rejected("CSP_SCRIPT_SHA256")

    def test_a_missing_constant_is_rejected(self) -> None:
        self.edit(ASSETS_RS, replace_once("OWNER_RESPONSE_SHA256", "OWNER_RESPONSE_HASH"))
        self.assert_rejected()

    def test_a_wrong_vector_hex_is_rejected(self) -> None:
        self.edit(CHECKER, replace_once('"request_header": "5057', '"request_header": "5157'))
        self.assert_rejected("request_header")

    def test_a_wrong_asset_shaped_prf_vector_is_rejected(self) -> None:
        self.edit(
            CHECKER,
            replace_once('"222324483031323334353637f6f6f6"', '"222324483031323334353637f6f6f7"'),
        )
        self.assert_rejected("assertion_reply_without_prf")

    def test_a_vector_that_lost_an_item_is_rejected(self) -> None:
        self.edit(
            CHECKER,
            replace_once('"222324483031323334353637f6f6f6"', '"222324483031323334353637f6f6"'),
        )
        self.assert_rejected()

    def test_a_dropped_vector_is_rejected(self) -> None:
        self.edit(
            CHECKER,
            lambda text: re.sub(
                r'    "cleanup_record": \(\n.*?\n    \),\n', "", text, count=1, flags=re.DOTALL
            ),
        )
        self.assert_rejected()


if __name__ == "__main__":
    unittest.main()
