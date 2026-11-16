#!/usr/bin/env python3
"""Install the ADR-135 §4 test seccomp address-family filter, then execute a program.

Test-only helper of `scripts/air-gapped-namespace.sh` (#1422; owner decision 2026-11-16 on
#1400: a Python helper through ctypes, no unsafe Rust and no new crate). It sets
`no_new_privs` and installs a classic-BPF seccomp filter under which `socket(2)` creates only
`AF_UNIX`, `AF_INET` and `AF_INET6` sockets; every other family, `AF_PACKET`, `AF_NETLINK` and
`AF_VSOCK` included, fails with `EAFNOSUPPORT`. A system call of another audit architecture, or an
x32 system call on x86_64, fails the same way. `/proc/self/status` then reports `Seccomp: 2`, so
the program runs with the real filter that ADR-135 §4 item 3 asks for. It is never used by
the Gateway.

Usage: air_gapped_seccomp_exec.py PROGRAM [ARGUMENT...]
"""

from __future__ import annotations

import ctypes
import os
import platform
import struct
import sys

# Classic BPF opcodes (linux/filter.h).
BPF_LD_W_ABS = 0x20
BPF_JEQ_K = 0x15
BPF_JGE_K = 0x35
BPF_RET_K = 0x06
# seccomp(2) actions and prctl(2) options.
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
EAFNOSUPPORT = 97
# Offsets in struct seccomp_data: nr, arch, then the low word of args[0] (little-endian).
OFFSET_NR = 0
OFFSET_ARCH = 4
OFFSET_ARG0 = 16
X32_SYSCALL_BIT = 0x40000000
# AF_UNIX, AF_INET, AF_INET6.
ALLOWED_FAMILIES = (1, 2, 10)
# machine -> (AUDIT_ARCH_*, socket system call number).
ARCHITECTURES = {
    "x86_64": (0xC000003E, 41),
    "aarch64": (0xC00000B7, 198),
}


def instructions(machine: str) -> list[tuple[int, int, int, int]]:
    """The filter for `machine` as `(code, jt, jf, k)` instructions; jumps are relative."""
    arch, socket_nr = ARCHITECTURES[machine]
    deny = SECCOMP_RET_ERRNO | EAFNOSUPPORT
    return [
        (BPF_LD_W_ABS, 0, 0, OFFSET_ARCH),  # 0
        (BPF_JEQ_K, 1, 0, arch),  # 1: native -> 3, else -> 2
        (BPF_RET_K, 0, 0, deny),  # 2
        (BPF_LD_W_ABS, 0, 0, OFFSET_NR),  # 3
        (BPF_JGE_K, 5, 0, X32_SYSCALL_BIT),  # 4: x32 -> 10
        (BPF_JEQ_K, 0, 5, socket_nr),  # 5: socket -> 6, else -> 11
        (BPF_LD_W_ABS, 0, 0, OFFSET_ARG0),  # 6
        (BPF_JEQ_K, 3, 0, ALLOWED_FAMILIES[0]),  # 7: -> 11
        (BPF_JEQ_K, 2, 0, ALLOWED_FAMILIES[1]),  # 8: -> 11
        (BPF_JEQ_K, 1, 0, ALLOWED_FAMILIES[2]),  # 9: -> 11
        (BPF_RET_K, 0, 0, deny),  # 10
        (BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),  # 11
    ]


def program(machine: str) -> bytes:
    """The `struct sock_filter` array of the filter for `machine`."""
    return b"".join(struct.pack("=HBBI", *instruction) for instruction in instructions(machine))


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def install(machine: str) -> None:
    """Set `no_new_privs` and install the filter in this process."""
    code = program(machine)
    buffer = ctypes.create_string_buffer(code, len(code))
    fprog = SockFprog(len(code) // 8, ctypes.cast(buffer, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    for arguments in (
        (PR_SET_NO_NEW_PRIVS, ctypes.c_ulong(1), ctypes.c_ulong(0), ctypes.c_ulong(0)),
        (PR_SET_SECCOMP, ctypes.c_ulong(SECCOMP_MODE_FILTER), ctypes.byref(fprog),
         ctypes.c_ulong(0)),
    ):
        if libc.prctl(ctypes.c_int(arguments[0]), *arguments[1:], ctypes.c_ulong(0)) != 0:
            raise OSError(ctypes.get_errno(), f"prctl({arguments[0]}) failed")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: air_gapped_seccomp_exec.py PROGRAM [ARGUMENT...]", file=sys.stderr)
        return 2
    machine = platform.machine()
    if machine not in ARCHITECTURES:
        print(f"no seccomp filter for the {machine} architecture", file=sys.stderr)
        return 2
    install(machine)
    os.execv(argv[1], argv[1:])
    return 1  # pragma: no cover - execv does not return


if __name__ == "__main__":
    sys.exit(main(sys.argv))
