#!/usr/bin/env python3
"""Public runtime-manifest and extracted-tree security contracts (no downloads)."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from owner_bridge_runtime import MANIFEST, PER_START, parse_manifest, verify_tree


def row(name, content=b"runtime"):
    return f"{hashlib.sha256(content).hexdigest()}  {len(content)}  {name}"


class RuntimeManifestTests(unittest.TestCase):
    def test_retained_inventory_matches_the_accepted_cab_evidence(self):
        entries = parse_manifest(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(len(entries), 257)
        self.assertEqual(sum(size for size, _ in entries.values()), 699_773_121)
        self.assertTrue(all(name in entries for name in PER_START))

    def test_ambiguous_paths_and_encodings_are_refused(self):
        for name in ["", "/x", "../x", "a/../x", "./x", "a//x", "C:/x",
                     "x\\y", "x:stream", "x\t", "x.", "x ", "a./x", "a /x"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                parse_manifest(row(name))
        for text in ["", "\n", row("x").replace("  7  ", "  07  "),
                     row("x").replace("  7  ", "  -7  "),
                     row("x").replace("  7  ", "  ７  "),
                     row("x").replace("  7  ", "  +7  "),
                     "g" * 64 + "  1  x", "A" * 64 + "  1  x", "0  1  x"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_manifest(text)

    def test_duplicate_and_case_alias_entries_are_refused(self):
        for name in ["engine.dll", "ENGINE.DLL"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                parse_manifest(row("engine.dll") + "\n" + row(name))

    def test_full_tree_checks_exact_membership_size_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "engine").mkdir()
            (root / "engine/a.dll").write_bytes(b"runtime")
            (root / "browser.exe").write_bytes(b"browser")
            expected = parse_manifest(row("engine/a.dll") + "\n" + row("browser.exe", b"browser"))
            result = verify_tree(root, expected)
            self.assertEqual([entry["path"] for entry in result], ["browser.exe", "engine/a.dll"])
            self.assertEqual(result[0]["size"], 7)
            self.assertEqual(result[0]["sha256"], hashlib.sha256(b"browser").hexdigest())
            self.assertEqual(result[0]["modified_filetime"],
                             (root / "browser.exe").stat().st_mtime_ns // 100 + 116_444_736_000_000_000)
            for content, message in [(b"bad", "size mismatch"), (b"changed", "digest mismatch")]:
                (root / "browser.exe").write_bytes(content)
                with self.assertRaisesRegex(ValueError, message):
                    verify_tree(root, expected)
            (root / "browser.exe").write_bytes(b"browser")
            (root / "extra").write_bytes(b"extra")
            with self.assertRaisesRegex(ValueError, "inventory differs"):
                verify_tree(root, expected)
            (root / "extra").unlink()
            (root / "browser.exe").unlink()
            with self.assertRaisesRegex(ValueError, "inventory differs"):
                verify_tree(root, expected)
            with self.assertRaisesRegex(ValueError, "ordinary directory"):
                verify_tree(root / "missing", expected)

    def test_links_cannot_redirect_runtime_members_or_the_root(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "runtime"
            root.mkdir()
            (base / "outside").write_bytes(b"runtime")
            (root / "engine.dll").symlink_to(base / "outside")
            expected = parse_manifest(row("engine.dll"))
            with self.assertRaisesRegex(ValueError, "links or junctions"):
                verify_tree(root, expected)
            (base / "alias").symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "ordinary directory"):
                verify_tree(base / "alias", expected)


if __name__ == "__main__":
    unittest.main()
