#!/usr/bin/env python3
"""Coverage transport fixtures: preserve observations and reject false joins."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import merge_owner_bridge_lcov as policy


CHECKOUT = "a" * 40
ROOT = pathlib.Path(__file__).resolve().parent.parent


def record(path, counts=((1, 7), (2, 0))):
    return "SF:" + str(path) + "\n" + "\n".join(f"DA:{line},{hits}" for line, hits in counts) + "\nend_of_record\n"


def receipt(native, root="C:/work/repo", checkout=CHECKOUT):
    return {"version": 1, "checkout": checkout, "workspace_root": root,
            "target_directory": root + "/target", "cargo_home": "C:/users/runner/.cargo",
            "rustup_home": "C:/users/runner/.rustup", "lcov_sha256": hashlib.sha256(native).hexdigest()}


class OwnerBridgeLcovTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name).resolve()
        self.paths = ["crates/pos-core/src/lib.rs", "crates/pos-owner-bridge-windows/src/lib.rs",
                      "crates/pos-owner-bridge-windows/src/ffi/ops.rs",
                      "crates/pos-owner-bridge-windows/src/adapter/runtime/tests.rs"]
        for name in self.paths:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("fixture\n")
        self.linux = record(self.root / self.paths[0], ((1, 3), (2, 0))).encode()
        self.native = (record("C:/work/repo/" + self.paths[1]) + record("C:/work/repo/" + self.paths[2])
                       + record("C:/work/repo/" + self.paths[3])).encode()

    def merge(self, native=None, metadata=None, linux=None):
        native = self.native if native is None else native
        return policy.merge(self.linux if linux is None else linux, native,
                            receipt(native) if metadata is None else metadata, self.root, CHECKOUT)

    def test_actual_counts_and_uncovered_lines_survive_the_join(self):
        merged, summary = self.merge()
        self.assertTrue(merged.startswith(self.linux.decode()))
        self.assertEqual(merged.count("DA:1,7"), 3)
        self.assertEqual(merged.count("DA:2,0"), 4)
        self.assertEqual(summary, {"native_sources": 3, "native_lines": {"safe": 4, "ffi": 2}, "omitted_non_src_records": 0})
        self.assertIn("SF:" + str(self.root / self.paths[3]), merged)
        self.assertNotIn("C:/work/repo", merged)

    def test_drive_case_unc_and_slash_normalization_bind_to_the_same_sources(self):
        for root in ("C:/work/repo", "//server/share/repo"):
            for separator in ("/", "\\"):
                native = (record(root + "/" + self.paths[1]) + record(root + "/" + self.paths[2])).replace("/", separator).encode()
                metadata = receipt(native, root=root)
                if root.startswith("C:"): metadata["workspace_root"] = root.replace("C:", "c:")
                merged, summary = self.merge(native=native, metadata=metadata)
                self.assertIn("SF:" + str(self.root / self.paths[2]), merged)
                self.assertEqual(summary["native_sources"], 2)

    def test_checkout_digest_version_and_receipt_fields_are_mandatory(self):
        for change in ({"checkout": "b" * 40}, {"lcov_sha256": "0" * 64}, {"version": True},
                       {"version": 2}, {"unexpected": 1}, {"workspace_root": "relative"},
                       {"cargo_home": "C:/work/../repo"}, {"rustup_home": None}):
            metadata = dict(receipt(self.native), **change)
            with self.subTest(change=change), self.assertRaises(policy.CoverageError):
                self.merge(metadata=metadata)
        for missing in policy.RECEIPT_KEYS:
            metadata = receipt(self.native); del metadata[missing]
            with self.subTest(missing=missing), self.assertRaises(policy.CoverageError):
                self.merge(metadata=metadata)

    def test_sources_must_exist_in_the_exact_checkout_without_parent_or_alias_escape(self):
        for name in ("D:/foreign/file.rs", "C:/work/repo/crates/other/src/lib.rs",
                     "C:/work/repo/crates/pos-owner-bridge-windows/src/missing.rs",
                     "C:/work/repo/crates/pos-owner-bridge-windows/src/../lib.rs",
                     "relative/lib.rs", "C:/work/repo/crates/pos-owner-bridge-windows/src/data.json",
                     "C:/work/repo/rustc/" + "8b" * 20 + "/src/lib.rs", "C:/work/repo/rustc/8b/library/core.rs"):
            native = self.native + record(name).encode()
            with self.subTest(name=name), self.assertRaises(policy.CoverageError): self.merge(native=native)
        outside = self.root.parent / (self.root.name + "-outside.rs")
        outside.write_text("external\n"); self.addCleanup(outside.unlink)
        link = self.root / "crates/pos-owner-bridge-windows/src/alias.rs"; link.symlink_to(outside)
        with self.assertRaises(policy.CoverageError):
            self.merge(native=self.native + record("C:/work/repo/crates/pos-owner-bridge-windows/src/alias.rs").encode())

    def test_known_non_src_records_are_counted_without_replacing_package_coverage(self):
        ignored = ["C:/work/repo/crates/pos-owner-bridge-windows/tests/integration.rs",
                   "C:/work/repo/target/build/generated.rs", "C:/users/runner/.cargo/registry/dependency.rs",
                   "C:/users/runner/.rustup/toolchains/std.rs", "/rustc/012345abcdef/library/core.rs",
                   "C:\\work\\repo\\rustc\\" + "8b" * 20 + "\\library\\std\\src\\thread.rs"]
        native = self.native + "".join(record(name) for name in ignored).encode()
        merged, summary = self.merge(native=native)
        self.assertEqual(summary["omitted_non_src_records"], len(ignored))
        self.assertEqual(summary["native_sources"], 3)
        self.assertTrue(merged.startswith(self.linux.decode()))
        self.assertNotIn("dependency.rs", merged)

    def test_duplicate_overlapping_and_empty_native_scopes_fail_closed(self):
        for native in (self.native + self.native, record("C:/work/repo/" + self.paths[1]).encode(),
                       record("C:/work/repo/" + self.paths[2]).encode(), b""):
            with self.subTest(native=native[:80]), self.assertRaises(policy.CoverageError): self.merge(native=native)
        for linux in (self.linux + self.linux,
                      record(self.root / self.paths[1]).encode(), record("/outside/lib.rs").encode()):
            with self.subTest(linux=linux[:80]), self.assertRaises(policy.CoverageError): self.merge(linux=linux)

    def test_malformed_or_ambiguous_lcov_is_not_made_into_coverage(self):
        bad = [b"\xff", b"SF:x\0.rs\nend_of_record\n", b"DA:1,2\n", b"end_of_record\n",
               b"SF:x.rs\n", b"SF:x.rs\nSF:y.rs\nend_of_record\n",
               b"SF:x.rs\nDA:1,2\nDA:1,3\nend_of_record\n"]
        for counter in ["0,1", "-1,1", "1,-1", "1,nan", "1,1,extra,bad", "4294967296,1", "1,18446744073709551616"]:
            bad.append(("SF:x.rs\nDA:" + counter + "\nend_of_record\n").encode())
        for data in bad:
            with self.subTest(data=data), self.assertRaises(policy.CoverageError): policy.records(data)

    def test_public_cli_checks_consumer_commit_and_preserves_inputs_on_failure(self):
        commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        native = (record("C:/work/repo/crates/pos-owner-bridge-windows/src/lib.rs") +
                  record("C:/work/repo/crates/pos-owner-bridge-windows/src/ffi/mod.rs")).encode()
        linux = record(ROOT / "crates/pos-core/src/lib.rs").encode()
        paths = {"linux": linux, "native": native, "receipt": json.dumps(receipt(native, checkout=commit)).encode()}
        command = [sys.executable, str(pathlib.Path(policy.__file__))]
        for name, content in paths.items():
            path = self.root / name; path.write_bytes(content); command += ["--" + name, str(path)]
        output = self.root / "output.lcov"
        command += ["--workspace", str(ROOT), "--output", str(output), "--checkout", commit]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.read_bytes().startswith(linux))
        retained = output.read_bytes()
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(output.read_bytes(), retained)
        output.unlink(); command[-1] = "0" * 40
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(output.exists())
        self.assertEqual((self.root / "native").read_bytes(), native)


if __name__ == "__main__":
    unittest.main()
