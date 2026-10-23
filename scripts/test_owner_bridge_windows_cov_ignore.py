#!/usr/bin/env python3
"""Public CLI and path-matching tests for ADR-110's coverage exclusion tool."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import unittest


SCRIPT = pathlib.Path(__file__).with_name("owner_bridge_windows_cov_ignore.py")
SPEC = importlib.util.spec_from_file_location("owner_bridge_windows_cov_ignore", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


def metadata(root: str = "/work/repo") -> dict:
    members = [
        ("opaque shim ID", "pos-owner-bridge-windows", "crates/pos-owner-bridge-windows"),
        ("opaque core ID", "pos-core", "crates/pos-core"),
        ("opaque bridge ID", "pos-owner-bridge", "crates/pos-owner-bridge"),
        ("opaque application ID", "gateway", "apps/piglor-gateway"),
    ]
    return {
        "version": 1,
        "workspace_root": root,
        "workspace_members": [member[0] for member in members],
        "packages": [
            {"id": identity, "name": name, "manifest_path": f"{root}/{directory}/Cargo.toml"}
            for identity, name, directory in members
        ],
    }


def run_cli(value: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT)], input=value, encoding="utf-8",
                          capture_output=True, check=False)


class CoverageIsolationTests(unittest.TestCase):
    def assert_scope(self, value: dict) -> None:
        expression = TOOL.coverage_ignore_regex(value)
        root = value["workspace_root"].replace("\\", "/").rstrip("/")
        for package in value["packages"]:
            if package["id"] not in value["workspace_members"]:
                continue
            directory = package["manifest_path"].replace("\\", "/").rsplit("/", 1)[0]
            relative = directory[len(root) + 1:]
            for path in [f"{directory}/src/lib.rs", f"{relative}/src/lib.rs"]:
                for separator in ["/", "\\"]:
                    with self.subTest(package=package["name"], path=path, separator=separator):
                        matched = re.search(expression, path.replace("/", separator)) is not None
                        self.assertEqual(matched, package["name"] != "pos-owner-bridge-windows")

    def test_posix_metadata_excludes_every_other_workspace_member(self) -> None:
        self.assert_scope(metadata())

    def test_windows_metadata_accepts_native_and_normalized_slashes(self) -> None:
        value = metadata(r"C:\work\repo")
        for package in value["packages"]:
            package["manifest_path"] = package["manifest_path"].replace("/", "\\")
        self.assert_scope(value)
        expression = TOOL.coverage_ignore_regex(value)
        self.assertIsNotNone(re.search(expression, r"c:\work\repo\crates\pos-core\src\lib.rs"))

    def test_unc_metadata_uses_the_same_member_boundaries(self) -> None:
        self.assert_scope(metadata("//server/share/repo"))

    def test_added_members_are_included_without_an_allowlist(self) -> None:
        value = metadata()
        value["packages"].append({"id": "new opaque ID", "name": "new-package",
                                  "manifest_path": "/work/repo/new/location/Cargo.toml"})
        value["workspace_members"].append("new opaque ID")
        self.assert_scope(value)

    def test_metacharacters_in_root_and_member_are_literal(self) -> None:
        value = metadata("/work/repo+[stable].(1)")
        value["packages"][1]["manifest_path"] = (
            value["workspace_root"] + "/crates/core+[1].(test)/Cargo.toml")
        self.assert_scope(value)
        expression = TOOL.coverage_ignore_regex(value)
        self.assertIsNone(re.search(expression, "/work/repoxstable1/crates/pos-core/src/lib.rs"))
        self.assertIsNone(re.search(expression, "crates/core111xtest/src/lib.rs"))

    def test_directory_prefixes_and_shim_nested_names_never_match(self) -> None:
        expression = TOOL.coverage_ignore_regex(metadata())
        for path in [
            "crates/pos-core-extra/src/lib.rs",
            "other/crates/pos-core/src/lib.rs",
            "/different/work/repo/crates/pos-core/src/lib.rs",
            "crates/pos-owner-bridge-windows/src/fixtures/crates/pos-core/src/lib.rs",
            "/work/repo/crates/pos-owner-bridge-windows/src/fixtures/apps/piglor-gateway/src/lib.rs",
        ]:
            with self.subTest(path=path):
                self.assertIsNone(re.search(expression, path))

    def test_package_and_member_order_do_not_change_output(self) -> None:
        value = metadata()
        expected = TOOL.coverage_ignore_regex(value)
        value["packages"].reverse()
        value["workspace_members"].reverse()
        self.assertEqual(TOOL.coverage_ignore_regex(value), expected)

    def test_non_workspace_dependencies_and_future_fields_are_ignored(self) -> None:
        value = metadata()
        value["packages"].append({"id": "dependency ID", "name": "pos-owner-bridge-windows",
                                  "manifest_path": "/registry/dependency/Cargo.toml"})
        value["future_field"] = {"value": True}
        self.assertEqual(TOOL.coverage_ignore_regex(value), TOOL.coverage_ignore_regex(metadata()))

    def test_shim_only_workspace_does_not_emit_an_empty_matching_alternation(self) -> None:
        value = metadata()
        value["packages"] = value["packages"][:1]
        value["workspace_members"] = value["workspace_members"][:1]
        self.assert_scope(value)

    def test_cli_emits_only_the_regex_and_one_newline(self) -> None:
        value = metadata()
        result = run_cli(json.dumps(value))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, TOOL.coverage_ignore_regex(value) + "\n")

    def test_expression_also_matches_with_a_posix_extended_regex_engine(self) -> None:
        # LLVM consumes POSIX ERE, so Python-only regex extensions are invalid.
        expression = TOOL.coverage_ignore_regex(metadata(r"C:\work\repo"))
        paths = [
            r"C:\work\repo\crates\pos-core\src\lib.rs",
            "apps/piglor-gateway/src/lib.rs",
            r"C:\work\repo\crates\pos-owner-bridge-windows\src\lib.rs",
            "crates/pos-owner-bridge-windows/src/fixtures/crates/pos-core/src/lib.rs",
            "crates/pos-core-extra/src/lib.rs",
        ]
        result = subprocess.run(["grep", "-E", expression], input="\n".join(paths) + "\n",
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), paths[:2])

    def test_cli_uses_utf8_bytes_even_with_ascii_stdio(self) -> None:
        value = metadata("/work/路徑/repo")
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps(value, ensure_ascii=False).encode("utf-8"),
            env={**os.environ, "PYTHONIOENCODING": "ascii"},
            capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, TOOL.coverage_ignore_regex(value).encode("utf-8") + b"\n")

    def test_cli_rejects_invalid_utf8_without_a_traceback(self) -> None:
        result = subprocess.run([sys.executable, str(SCRIPT)], input=b"\xff",
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"Traceback", result.stderr)

    def test_cli_rejects_invalid_json_without_output_or_traceback(self) -> None:
        result = run_cli("not JSON")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("owner-bridge coverage metadata:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_invalid_metadata_fails_closed_at_the_cli(self) -> None:
        variants = []
        for key, invalid in [("version", 2), ("version", True), ("workspace_root", "relative"),
                             ("workspace_root", "/work/../repo"), ("workspace_root", "/work/\nrepo"),
                             ("workspace_members", []), ("workspace_members", [True]),
                             ("workspace_members", "not an array"), ("packages", {})]:
            value = metadata()
            value[key] = invalid
            variants.append(value)
        value = metadata()
        value["packages"] = value["packages"][1:]
        variants.append(value)
        value = metadata()
        value["workspace_members"].append("missing ID")
        variants.append(value)
        value = metadata()
        value["workspace_members"].append(value["workspace_members"][0])
        variants.append(value)
        value = metadata()
        value["packages"].append(copy.deepcopy(value["packages"][0]))
        variants.append(value)
        value = metadata()
        value["packages"][1]["name"] = "pos-owner-bridge-windows"
        variants.append(value)
        for manifest in ["relative/Cargo.toml", "/elsewhere/Cargo.toml", "/work/repo/../other/Cargo.toml",
                         "/work/repo/Cargo.toml", "/work/repo/member/not-a-manifest", None]:
            value = metadata()
            value["packages"][1]["manifest_path"] = manifest
            variants.append(value)
        value = metadata()
        value["packages"][0]["manifest_path"] = "/work/repo/moved-shim/Cargo.toml"
        variants.append(value)
        variants.extend([None, [], {"version": 1}])
        for index, value in enumerate(variants):
            with self.subTest(case=index):
                result = run_cli(json.dumps(value))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
