#!/usr/bin/env python3
"""Tests of the ADR-135 §4 test shape helpers (#1422): `air_gapped_seccomp_exec.py` and
`air-gapped-namespace.sh`."""

from __future__ import annotations

import errno
import platform
import struct
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import air_gapped_seccomp_exec as helper  # noqa: E402

HELPER = HERE / "air_gapped_seccomp_exec.py"
NAMESPACE = HERE / "air-gapped-namespace.sh"
DENY = helper.SECCOMP_RET_ERRNO | errno.EAFNOSUPPORT


def run_filter(code: bytes, nr: int, arch: int, arg0: int) -> int:
    """An independent classic-BPF interpreter over `struct seccomp_data` (little-endian)."""
    data = struct.pack("<iIQ6Q", nr, arch, 0, arg0, 0, 0, 0, 0, 0)
    program = [struct.unpack("=HBBI", code[index:index + 8]) for index in range(0, len(code), 8)]
    accumulator, pc = 0, 0
    while True:
        op, jt, jf, k = program[pc]
        if op == helper.BPF_LD_W_ABS:
            accumulator = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif op == helper.BPF_JEQ_K:
            pc += 1 + (jt if accumulator == k else jf)
        elif op == helper.BPF_JGE_K:
            pc += 1 + (jt if accumulator >= k else jf)
        elif op == helper.BPF_RET_K:
            return k
        else:
            raise AssertionError(f"unknown opcode {op:#x}")


class SeccompFilterTest(unittest.TestCase):
    def test_the_filter_allows_exactly_the_three_families_on_every_architecture(self) -> None:
        for machine, (arch, socket_nr) in helper.ARCHITECTURES.items():
            code = helper.program(machine)
            self.assertEqual(len(code), 8 * len(helper.instructions(machine)))
            for family in range(0, 64):
                expected = (
                    helper.SECCOMP_RET_ALLOW if family in (1, 2, 10) else DENY
                )
                self.assertEqual(run_filter(code, socket_nr, arch, family), expected,
                                 (machine, family))
            # A family is the low word of args[0]: AF_INET plus a high word is still AF_INET.
            self.assertEqual(run_filter(code, socket_nr, arch, (1 << 32) | 2),
                             helper.SECCOMP_RET_ALLOW)
            # Every other system call is allowed whatever its first argument.
            for nr in (0, 1, socket_nr - 1, socket_nr + 1, 335):
                self.assertEqual(run_filter(code, nr, arch, 17), helper.SECCOMP_RET_ALLOW)
            # A foreign architecture and an x32 call fail closed.
            self.assertEqual(run_filter(code, socket_nr, arch ^ 1, 2), DENY)
            self.assertEqual(run_filter(code, helper.X32_SYSCALL_BIT, arch, 0), DENY)
            self.assertEqual(run_filter(code, helper.X32_SYSCALL_BIT - 1, arch, 0),
                             helper.SECCOMP_RET_ALLOW)

    def test_the_architectures_are_the_kernel_constants(self) -> None:
        self.assertEqual(helper.ARCHITECTURES, {
            "x86_64": (0xC000003E, 41),
            "aarch64": (0xC00000B7, 198),
        })
        self.assertEqual(helper.ALLOWED_FAMILIES, (1, 2, 10))
        self.assertEqual(helper.OFFSET_ARG0, 16)


@unittest.skipUnless(platform.machine() in helper.ARCHITECTURES, "unsupported architecture")
class SeccompExecTest(unittest.TestCase):
    def run_helper(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(HELPER), *arguments],
                              capture_output=True, text=True, check=False, timeout=60)

    def test_the_program_runs_under_the_filter_with_no_new_privs(self) -> None:
        result = self.run_helper("/bin/cat", "/proc/self/status")
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = dict(line.split(":\t", 1) for line in result.stdout.splitlines() if ":\t" in line)
        self.assertEqual(fields["Seccomp"].strip(), "2")
        self.assertEqual(fields["NoNewPrivs"].strip(), "1")

    def test_only_unix_and_inet_sockets_can_be_created(self) -> None:
        probe = (
            "import socket\n"
            "for family, kind in ((1, 1), (2, 1), (10, 2), (16, 3), (17, 3), (40, 1)):\n"
            "    try:\n"
            "        socket.socket(family, kind).close()\n"
            "        print(family, 0)\n"
            "    except OSError as error:\n"
            "        print(family, error.errno)\n"
        )
        result = self.run_helper(sys.executable, "-I", "-c", probe)
        self.assertEqual(result.returncode, 0, result.stderr)
        outcome = dict(line.split() for line in result.stdout.splitlines())
        self.assertEqual(outcome, {
            "1": "0", "2": "0", "10": "0",
            "16": str(errno.EAFNOSUPPORT), "17": str(errno.EAFNOSUPPORT),
            "40": str(errno.EAFNOSUPPORT),
        })


class UsageTest(unittest.TestCase):
    def test_a_missing_program_is_a_usage_error(self) -> None:
        self.assertEqual(helper.main(["air_gapped_seccomp_exec.py"]), 2)
        result = subprocess.run([str(NAMESPACE)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_a_program_that_cannot_be_executed_is_a_clean_error(self) -> None:
        with mock.patch.object(helper, "install"), \
                mock.patch.object(helper.platform, "machine", return_value="x86_64"), \
                mock.patch("sys.stderr") as stderr:
            self.assertEqual(helper.main(["helper", "/nonexistent/program"]), 127)
        self.assertIn("cannot execute /nonexistent/program",
                      "".join(call.args[0] for call in stderr.write.call_args_list))

    def test_an_unknown_architecture_installs_nothing(self) -> None:
        with mock.patch.object(helper.platform, "machine", return_value="riscv64"), \
                mock.patch.object(helper, "install") as install, \
                mock.patch.object(helper.os, "execv") as execv:
            self.assertEqual(helper.main(["helper", "/bin/true"]), 2)
        install.assert_not_called()
        execv.assert_not_called()

    def test_a_refused_prctl_is_an_error(self) -> None:
        library = mock.Mock()
        library.prctl.return_value = -1
        with mock.patch.object(helper.ctypes, "CDLL", return_value=library):
            with self.assertRaisesRegex(OSError, "prctl\\(38\\) failed"):
                helper.install("x86_64")


if __name__ == "__main__":
    unittest.main()
