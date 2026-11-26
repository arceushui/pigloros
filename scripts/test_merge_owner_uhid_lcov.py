#!/usr/bin/env python3
"""U-tier coverage fixtures: counts are added, and every false join is refused."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import merge_owner_uhid_lcov as policy
from merge_owner_bridge_lcov import CoverageError

CHECKOUT = "b" * 40
HIDRAW = "crates/pos-owner-ctap/src/hidraw.rs"
TTY = "crates/pos-owner-ctap/src/tty.rs"
OTHER = "crates/pos-core/src/lib.rs"
SCRIPT = pathlib.Path(__file__).resolve().parent / "merge_owner_uhid_lcov.py"


def record(path, counts, summary=True):
    lines = [f"SF:{path}", *(f"DA:{line},{hits}" for line, hits in counts)]
    if summary:
        lines += [f"LF:{len(counts)}", f"LH:{sum(1 for _, hits in counts if hits)}"]
    return "\n".join([*lines, "end_of_record"]) + "\n"


def receipt(uhid, root, checkout=CHECKOUT):
    return {"version": 1, "checkout": checkout, "workspace_root": str(root),
            "lcov_sha256": hashlib.sha256(uhid).hexdigest()}


class OwnerUhidLcovTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name).resolve()
        for name in (HIDRAW, TTY, OTHER):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n")
        self.linux = (record(self.root / OTHER, ((1, 2),)) + record(self.root / HIDRAW, ((1, 0), (2, 5), (3, 0)))
                      + record(self.root / TTY, ((7, 1),))).encode()
        self.uhid = (record(self.root / HIDRAW, ((1, 4), (2, 1), (9, 3)))).encode()

    def merge(self, uhid=None, linux=None, metadata=None, workspace=None):
        uhid = self.uhid if uhid is None else uhid
        return policy.merge(self.linux if linux is None else linux, uhid,
                            receipt(uhid, self.root) if metadata is None else metadata,
                            self.root if workspace is None else workspace, CHECKOUT)

    def test_counts_are_added_and_other_records_are_untouched(self):
        merged, summary = self.merge()
        self.assertIn("DA:1,4\nDA:2,6\nDA:3,0\nLF:3\nLH:2\n", merged)
        self.assertIn(f"SF:{self.root / OTHER}\nDA:1,2\nLF:1\nLH:1\n", merged)
        self.assertIn(f"SF:{self.root / TTY}\nDA:7,1\nLF:1\nLH:1\n", merged)
        self.assertEqual(summary, {"sources": 1, "lines_added": 2, "lines_unmatched": 1})

    def test_a_record_without_a_summary_is_rewritten_without_one(self):
        linux = record(self.root / HIDRAW, ((1, 0),), summary=False).encode()
        merged, _ = self.merge(linux=linux)
        self.assertEqual(merged, f"SF:{self.root / HIDRAW}\nDA:1,4\nend_of_record\n")

    def test_a_checksum_field_survives(self):
        linux = f"SF:{self.root / HIDRAW}\nDA:1,0,abc\nend_of_record\n".encode()
        merged, _ = self.merge(linux=linux)
        self.assertIn("DA:1,4,abc", merged)

    def test_relative_sources_bind_to_the_checkout(self):
        uhid = record(HIDRAW, ((1, 4),)).encode()
        merged, _ = self.merge(uhid=uhid)
        self.assertIn("DA:1,4\nDA:2,5", merged)

    def test_sources_outside_the_crate_source_tree_are_ignored(self):
        uhid = (record(self.root / HIDRAW, ((1, 1),)) + record(self.root / OTHER, ((1, 100),))
                + record("/elsewhere/" + HIDRAW, ((1, 100),))
                + record(self.root / "crates/pos-owner-ctap/src/notes.txt", ((1, 100),))).encode()
        merged, summary = self.merge(uhid=uhid)
        self.assertIn(f"SF:{self.root / OTHER}\nDA:1,2\n", merged)
        self.assertEqual(summary["sources"], 1)

    def test_an_empty_observation_set_is_refused(self):
        with self.assertRaises(CoverageError):
            self.merge(uhid=record(self.root / OTHER, ((1, 1),)).encode())

    def test_a_source_missing_from_the_linux_lcov_is_refused(self):
        with self.assertRaises(CoverageError):
            self.merge(linux=record(self.root / OTHER, ((1, 2),)).encode())

    def test_a_source_missing_from_the_tree_is_refused(self):
        (self.root / HIDRAW).unlink()
        with self.assertRaises(CoverageError):
            self.merge()

    def test_duplicates_are_refused(self):
        with self.assertRaises(CoverageError):
            self.merge(uhid=self.uhid + self.uhid)
        with self.assertRaises(CoverageError):
            self.merge(linux=self.linux + record(self.root / HIDRAW, ((1, 0),)).encode())

    def test_the_receipt_must_match_the_checkout_and_the_digest(self):
        good = receipt(self.uhid, self.root)
        for bad in (dict(good, checkout="c" * 40), dict(good, lcov_sha256="0" * 64), dict(good, version=2),
                    dict(good, workspace_root="relative/path"), dict(good, extra=1),
                    {key: value for key, value in good.items() if key != "version"}):
            with self.subTest(bad=bad), self.assertRaises(CoverageError):
                self.merge(metadata=bad)

    def test_a_malformed_checkout_is_refused(self):
        with self.assertRaises(CoverageError):
            policy.merge(self.linux, self.uhid, receipt(self.uhid, self.root, "x"), self.root, "x")

    def run_cli(self, *extra, checkout=CHECKOUT):
        linux, uhid, metadata, output = (self.root / name for name in ("linux.lcov", "uhid.lcov", "receipt.json", "out.lcov"))
        linux.write_bytes(self.linux)
        uhid.write_bytes(self.uhid)
        metadata.write_text(json.dumps(receipt(self.uhid, self.root)))
        arguments = [sys.executable, str(SCRIPT), "--linux", str(linux), "--uhid", str(uhid), "--receipt", str(metadata),
                     "--workspace", str(self.root), "--checkout", checkout, "--output", str(output), *extra]
        return subprocess.run(arguments, capture_output=True, text=True, check=False), output

    def test_the_command_line_writes_a_fresh_merged_file(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                        "--allow-empty", "-m", "x"], check=True)
        head = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
        linux, uhid, metadata, output = (self.root / name for name in ("linux.lcov", "uhid.lcov", "receipt.json", "out.lcov"))
        linux.write_bytes(self.linux)
        uhid.write_bytes(self.uhid)
        metadata.write_text(json.dumps(receipt(self.uhid, self.root, head)))
        arguments = [sys.executable, str(SCRIPT), "--linux", str(linux), "--uhid", str(uhid), "--receipt", str(metadata),
                     "--workspace", str(self.root), "--checkout", head, "--output", str(output)]
        done = subprocess.run(arguments, capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("DA:2,6", output.read_text())
        again = subprocess.run(arguments, capture_output=True, text=True, check=False)
        self.assertEqual(again.returncode, 1)
        self.assertIn("fresh", again.stderr)

    def test_the_command_line_refuses_the_wrong_checkout(self):
        done, output = self.run_cli()
        self.assertEqual(done.returncode, 1)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
