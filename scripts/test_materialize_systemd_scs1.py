#!/usr/bin/env python3
"""Executable regeneration and adversarial policy tests for production SCS1."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/materialize-systemd-scs1.py"
VECTORS = ROOT / "crates/pos-conformance/vectors/systemd-provider-v260.2"
PINNED_REVISION = "f1d0952a125b96b7ab2f1ff29a87448ade8ac29b"
WRONG_PARENT = "03def5c285a32c5c0def2edc5ff6a407d9cc5fb0"
PINNED_SYSTEMD_SHA256 = "4242ae8aead8d2f0d9094449dfe039486edf0c0d8b32ba4cffc7991820590751"
PINNED_ARCHIVE_SHA256 = "501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be"
SPEC = importlib.util.spec_from_file_location("systemd_scs1", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
MATERIALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALIZER)


class MaterializerPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Required inputs fail closed: no skipped reproduction tests.
        cls.systemd = Path(os.environ["SYSTEMD_SCS1_SYSTEMD_SOURCE"])
        cls.archive = Path(os.environ["SYSTEMD_SCS1_LIBSECCOMP_ARCHIVE"])

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def invoke(self, output: Path, *, systemd=None, archive=None, check=False):
        command = [
            sys.executable, str(SCRIPT),
            "--systemd-source", str(systemd or self.systemd),
            "--libseccomp-archive", str(archive or self.archive),
            "--output", str(output),
        ]
        if check:
            command.append("--check")
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def assert_rejected(self, result, message: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)

    def clone_systemd(self) -> Path:
        destination = self.directory / "systemd"
        subprocess.run(
            ["git", "clone", "--quiet", "--shared", "--no-checkout", str(self.systemd), str(destination)],
            check=True,
        )
        subprocess.run(["git", "-C", str(destination), "checkout", "--quiet", "--detach", PINNED_REVISION], check=True)
        return destination

    def test_pins_and_complete_outputs_reproduce_twice(self) -> None:
        self.assertEqual(MATERIALIZER.SYSTEMD_REVISION, PINNED_REVISION)
        self.assertEqual(MATERIALIZER.SYSTEMD_SECCOMP_SHA256, PINNED_SYSTEMD_SHA256)
        self.assertEqual(MATERIALIZER.LIBSECCOMP_SOURCE_SHA256, PINNED_ARCHIVE_SHA256)
        self.assertEqual(MATERIALIZER.SYSTEMD_VERSION, "260.2")
        self.assertEqual(MATERIALIZER.LIBSECCOMP_VERSION, "2.6.1")
        self.assertEqual(MATERIALIZER.LIBSECCOMP_SYSCALLS_SHA256, "ab64e55719254d44bc279d967845568ab9940e81ed7800e9d1066f664a9f5231")
        self.assertEqual(MATERIALIZER.ARCHITECTURES, {"x86_64": 0, "aarch64": 1})
        expected = {path.name: path.read_bytes() for path in VECTORS.iterdir() if path.name != "README.md"}
        for ordinal in range(2):
            output = self.directory / str(ordinal)
            result = self.invoke(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            actual = {path.name: path.read_bytes() for path in output.iterdir()}
            self.assertEqual(actual, expected)
        result = self.invoke(VECTORS, check=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_revision_with_identical_syscall_source_is_rejected(self) -> None:
        systemd = self.clone_systemd()
        subprocess.run(["git", "-C", str(systemd), "checkout", "--quiet", "--detach", WRONG_PARENT], check=True)
        self.assertEqual(hashlib.sha256((systemd / "src/shared/seccomp-util.c").read_bytes()).hexdigest(), PINNED_SYSTEMD_SHA256)
        output = self.directory / "output"
        self.assert_rejected(self.invoke(output, systemd=systemd), "systemd revision is not pinned")
        self.assertFalse(output.exists())

    def test_modified_pinned_systemd_source_is_rejected(self) -> None:
        systemd = self.clone_systemd()
        (systemd / "src/shared/seccomp-util.c").write_text("wrong source", encoding="utf-8")
        self.assert_rejected(self.invoke(self.directory / "output", systemd=systemd), "systemd seccomp-util.c is not the pinned source")

    def test_wrong_libseccomp_archive_is_rejected(self) -> None:
        archive = self.directory / "libseccomp.tar.gz"
        archive.write_bytes(self.archive.read_bytes() + b"modified")
        self.assert_rejected(self.invoke(self.directory / "output", archive=archive), "libseccomp source archive is not the pinned source")

    def test_check_rejects_every_output_and_provenance_mutation(self) -> None:
        original_manifest = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
        for section in ("systemd", "libseccomp"):
            for field in original_manifest[section]:
                with self.subTest(section=section, field=field):
                    output = self.directory / "check"
                    shutil.copytree(VECTORS, output, dirs_exist_ok=True)
                    manifest = json.loads(json.dumps(original_manifest))
                    manifest[section][field] = "wrong"
                    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    self.assert_rejected(self.invoke(output, check=True), "manifest.json")
        for index, record in enumerate(original_manifest["records"]):
            for field in record:
                with self.subTest(record=index, field=field):
                    output = self.directory / "check"
                    shutil.copytree(VECTORS, output, dirs_exist_ok=True)
                    manifest = json.loads(json.dumps(original_manifest))
                    manifest["records"][index][field] = "wrong"
                    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    self.assert_rejected(self.invoke(output, check=True), "manifest.json")
        for record in original_manifest["records"]:
            with self.subTest(file=record["file"]):
                output = self.directory / "check"
                shutil.copytree(VECTORS, output, dirs_exist_ok=True)
                (output / record["file"]).write_bytes(b"wrong bytes")
                self.assert_rejected(self.invoke(output, check=True), record["file"])

    def test_systemd_group_parser_and_recursive_expansion(self) -> None:
        source = '.name = "@system-service",\n.value = "@child\\0" "socket\\0"\n},\n.name = "@child",\n.value = "poll\\0"\n},'
        groups = MATERIALIZER.parse_systemd_groups(source)
        self.assertEqual(MATERIALIZER.expand_group("@system-service", groups), ["poll", "socket"])
        with self.assertRaisesRegex(ValueError, "no @system-service"):
            MATERIALIZER.parse_systemd_groups("wrong source")
        with self.assertRaisesRegex(ValueError, "unknown systemd"):
            MATERIALIZER.expand_group("@system-service", {"@system-service": ("@missing",)})
        with self.assertRaisesRegex(ValueError, "recursive systemd"):
            MATERIALIZER.expand_group("@system-service", {"@system-service": ("@child",), "@child": ("@system-service",)})

    def test_csv_rejects_malformed_header_rows_and_duplicates(self) -> None:
        for source, message in [
            ("", "no expected header"),
            ("#syscall,x86_64\nsocket,1", "architecture columns"),
            ("#syscall,x86_64,aarch64,x86_64\nsocket,1,1,1", "architecture columns"),
            ("#syscall,x86_64,aarch64\nsocket,1", "malformed row"),
            ("#syscall,x86_64,aarch64\nsocket,1,1\nsocket,1,1", "duplicate syscall"),
        ]:
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, message):
                MATERIALIZER.parse_libseccomp_interface(source)

    def test_target_filtering_architecture_and_required_syscalls(self) -> None:
        required = {"execveat", "getsockopt", "poll", "recvmsg", "sendto", "socket"}
        names = required | {"name000"}
        interface = {name: {"x86_64": "1", "aarch64": "1"} for name in names}
        interface["undefined"] = {"x86_64": "KV_UNDEF", "aarch64": ""}
        interface["pseudo"] = {"x86_64": "PNR", "aarch64": "PNR"}
        interface["invalid"] = {"x86_64": "not-a-number", "aarch64": "-1"}
        interface["access"] = {"x86_64": "21", "aarch64": "PNR"}
        interface["poll"] = {"x86_64": "7", "aarch64": "PNR"}
        for architecture in ("x86_64", "aarch64"):
            expected = names | {"access"} if architecture == "x86_64" else names
            self.assertEqual(MATERIALIZER.target_names(names | {"undefined", "unknown", "pseudo", "invalid", "access"}, interface, architecture), sorted(expected))
        with self.assertRaisesRegex(ValueError, "unsupported architecture"):
            MATERIALIZER.target_names(names, interface, "riscv64")
        with self.assertRaisesRegex(ValueError, "omits required syscalls: socket"):
            MATERIALIZER.target_names(names - {"socket"}, interface, "x86_64")
        interface["poll"]["x86_64"] = "PNR"
        with self.assertRaisesRegex(ValueError, "omits required syscalls: poll"):
            MATERIALIZER.target_names(names, interface, "x86_64")
        interface["poll"]["x86_64"] = "7"
        interface["sendto"]["aarch64"] = "PNR"
        with self.assertRaisesRegex(ValueError, "omits required syscalls: sendto"):
            MATERIALIZER.target_names(names, interface, "aarch64")
        interface["sendto"]["aarch64"] = "206"
        interface["@retained"] = {"x86_64": "1"}
        with self.assertRaisesRegex(ValueError, "retained a systemd syscall group"):
            MATERIALIZER.target_names((names - {"name000"}) | {"@retained"}, interface, "x86_64")

    def test_pinned_target_names_have_no_non_required_pseudo_syscalls(self) -> None:
        systemd_source = (self.systemd / "src/shared/seccomp-util.c").read_text(encoding="utf-8")
        expanded = set(MATERIALIZER.expand_group("@system-service", MATERIALIZER.parse_systemd_groups(systemd_source)))
        with tarfile.open(self.archive, "r:gz") as archive:
            with archive.extractfile("libseccomp-2.6.1/src/syscalls.csv") as source:
                interface = MATERIALIZER.parse_libseccomp_interface(source.read().decode("utf-8"))
        expected_counts = {"x86_64": 315, "aarch64": 275}
        self.assertEqual(MATERIALIZER.EXPECTED_MATERIALIZED_NAMES, expected_counts)
        for architecture, count in expected_counts.items():
            names = MATERIALIZER.target_names(expanded, interface, architecture)
            self.assertEqual(len(names), count)
            pseudo = {name for name in names if interface[name][architecture] == "PNR"}
            self.assertEqual(pseudo, {"poll"} if architecture == "aarch64" else set())
            # Independently classify the entire pinned expansion, not just a
            # few invalid-name examples. The explicit poll rule is D-Bus-only.
            native = set()
            for name in expanded & interface.keys():
                try:
                    number = int(interface[name][architecture])
                except ValueError:
                    continue
                if number >= 0:
                    native.add(name)
            if architecture == "aarch64":
                native.add("poll")
            self.assertEqual(set(names), native)


if __name__ == "__main__":
    unittest.main()
