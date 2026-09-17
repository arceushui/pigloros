"""Public read-only inspection boundaries, including fail-closed negative cases."""

import errno
import json
import unittest
from unittest.mock import patch

from native_profiling_host_preflight import inspect_kvm, main, prerequisite_failures


class KvmInspectionTests(unittest.TestCase):
    def test_success_closes_descriptor_and_uses_only_version_ioctl(self):
        with patch("native_profiling_host_preflight.os.open", return_value=17) as opened:
            with patch("native_profiling_host_preflight.fcntl.ioctl", return_value=12) as ioctl:
                with patch("native_profiling_host_preflight.os.close") as closed:
                    self.assertEqual(inspect_kvm(), {"api_version": 12, "errno": None})
        opened.assert_called_once()
        ioctl.assert_called_once_with(17, 0xAE00, 0)
        closed.assert_called_once_with(17)

    def test_open_failure_does_not_close_an_unowned_descriptor(self):
        for code in (errno.ENOENT, errno.EACCES):
            with self.subTest(errno=code):
                with patch("native_profiling_host_preflight.os.open", side_effect=OSError(code, "denied")):
                    with patch("native_profiling_host_preflight.os.close") as closed:
                        self.assertEqual(inspect_kvm(), {"api_version": None, "errno": code})
                closed.assert_not_called()

    def test_ioctl_failure_still_closes_descriptor(self):
        with patch("native_profiling_host_preflight.os.open", return_value=17):
            with patch("native_profiling_host_preflight.fcntl.ioctl", side_effect=OSError(errno.ENOTTY, "unsupported")):
                with patch("native_profiling_host_preflight.os.close") as closed:
                    self.assertEqual(inspect_kvm(), {"api_version": None, "errno": errno.ENOTTY})
        closed.assert_called_once_with(17)

    def test_both_native_classes_require_unprivileged_api_12(self):
        for arch in ("aarch64", "x86_64"):
            with self.subTest(arch=arch):
                self.assertEqual(prerequisite_failures(arch, arch, 1001, {"api_version": 12}), [])
        self.assertEqual(prerequisite_failures("aarch64", "x86_64", 0, {"api_version": None}), [
            "native-architecture-mismatch",
            "host-inspection-must-be-unprivileged",
            "usable-kvm-api-12-not-established",
        ])
        self.assertEqual(prerequisite_failures("x86_64", "x86_64", 1001, {"api_version": 11}), [
            "usable-kvm-api-12-not-established",
        ])

    def test_entry_point_binds_sources_but_never_authorizes_activation(self):
        for version, expected_status in ((12, False), (None, True)):
            with self.subTest(version=version):
                with patch("sys.argv", ["preflight", "--expected-arch", "x86_64", "--source-sha", "a" * 40]):
                    with patch("native_profiling_host_preflight.platform.machine", return_value="x86_64"):
                        with patch("native_profiling_host_preflight.os.geteuid", return_value=1001):
                            with patch("native_profiling_host_preflight.inspect_kvm", return_value={"api_version": version}):
                                with patch("builtins.print") as printed:
                                    self.assertEqual(main(), expected_status)
                report = json.loads(printed.call_args.args[0])
                self.assertFalse(report["privileged_activation_authorized"])
                self.assertFalse(report["vm_created"])
                self.assertEqual(report["source_sha"], "a" * 40)
                self.assertEqual(len(report["source_file_sha256"]), 4)
                self.assertEqual(report["kvm_prerequisite_pass"], not expected_status)

    def test_entry_point_rejects_abbreviated_source_identity(self):
        with patch("sys.argv", ["preflight", "--expected-arch", "x86_64", "--source-sha", "abc"]):
            with patch("sys.stderr"):
                with self.assertRaises(SystemExit) as error:
                    main()
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
