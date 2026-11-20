#!/usr/bin/env python3
"""ADR-110 E20 UG1: hosted uhid feasibility for the Linux owner U-tier.

Run as root (through `sudo`) on the hosted runner. It creates one virtual
FIDO HID device through `/dev/uhid` and finds its hidraw node by the sysfs
`report_descriptor`, whose usage page must be 0xF1D0. It then hands the node
to the invoking user (`SUDO_UID`), the way the U-tier setup will, opens it
as that user, and destroys the device. Each step prints one evidence line;
any failure exits non-zero. Redmine #1474.
"""

from __future__ import annotations

import os
import select
import struct
import sys
import time
from pathlib import Path

UHID_DESTROY = 1
UHID_CREATE2 = 11
BUS_USB = 0x03
EVENT_SIZE = 4 + 128 + 64 + 64 + 2 + 2 + 4 * 4 + 4096
FIDO_USAGE_PAGE = 0xF1D0
NAME = b"pigloros-ug1-virtual-fido"

# The FIDO Alliance CTAPHID report descriptor: one 64-byte input and one
# 64-byte output report on usage page 0xF1D0, usage 0x01.
FIDO_REPORT_DESCRIPTOR = bytes.fromhex(
    "06d0f1"  # Usage Page (FIDO Alliance)
    "0901"  # Usage (CTAPHID)
    "a101"  # Collection (Application)
    "0920"  # Usage (Input Report Data)
    "150026ff00750895408102"  # Logical 0..255, 8 bits x 64, Input
    "0921"  # Usage (Output Report Data)
    "150026ff00750895409102"  # Logical 0..255, 8 bits x 64, Output
    "c0"  # End Collection
)


def create2_event(descriptor: bytes, name: bytes = NAME) -> bytes:
    """Encode a `struct uhid_event` carrying `UHID_CREATE2`."""
    if len(descriptor) > 4096 or len(name) >= 128:
        raise ValueError("descriptor or name too long")
    event = struct.pack(
        "<I128s64s64sHHIIII",
        UHID_CREATE2,
        name,
        b"",
        b"",
        len(descriptor),
        BUS_USB,
        0x1209,  # pid.codes test vendor
        0x0001,
        0,
        0,
    )
    return event + descriptor.ljust(4096, b"\0")


def destroy_event() -> bytes:
    return struct.pack("<I", UHID_DESTROY).ljust(EVENT_SIZE, b"\0")


def usage_pages(descriptor: bytes) -> list[int]:
    """Every Usage Page (global item tag 0) value in a short-item descriptor."""
    pages: list[int] = []
    index = 0
    while index < len(descriptor):
        prefix = descriptor[index]
        if prefix == 0xFE:  # long item: size byte, tag byte, data
            if index + 1 >= len(descriptor):
                raise ValueError("truncated long item")
            index += 3 + descriptor[index + 1]
            continue
        size = (0, 1, 2, 4)[prefix & 0x03]
        data = descriptor[index + 1 : index + 1 + size]
        if len(data) != size:
            raise ValueError("truncated short item")
        if prefix & 0xFC == 0x04:
            pages.append(int.from_bytes(data, "little"))
        index += 1 + size
    return pages


def is_fido_descriptor(descriptor: bytes) -> bool:
    try:
        return FIDO_USAGE_PAGE in usage_pages(descriptor)
    except ValueError:
        return False


def find_fido_hidraw(sysfs: Path, before: set[str]) -> str | None:
    for entry in sorted(sysfs.glob("hidraw*")):
        if entry.name in before:
            continue
        descriptor = entry / "device" / "report_descriptor"
        try:
            if is_fido_descriptor(descriptor.read_bytes()):
                return entry.name
        except OSError:
            continue
    return None


def open_as(uid: int, gid: int, node: str) -> int:
    """Fork, drop to `uid`/`gid`, open `node` read-write; return the exit code."""
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            descriptor = os.open(node, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
            os.close(descriptor)
            os._exit(0)
        except OSError as error:
            print(f"UG1 open as uid {uid} failed: {error}", file=sys.stderr)
            os._exit(1)
    return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])


def main() -> int:
    if os.geteuid() != 0:
        print("UG1 must run as root through sudo", file=sys.stderr)
        return 2
    uid = int(os.environ["SUDO_UID"])
    gid = int(os.environ["SUDO_GID"])
    sysfs = Path("/sys/class/hidraw")
    print(f"UG1 kernel {os.uname().release}")
    before = {entry.name for entry in sysfs.glob("hidraw*")} if sysfs.exists() else set()
    uhid = os.open("/dev/uhid", os.O_RDWR | os.O_CLOEXEC)
    try:
        os.write(uhid, create2_event(FIDO_REPORT_DESCRIPTOR))
        print("UG1 uhid CREATE2 accepted")
        deadline = time.monotonic() + 10
        node = None
        while node is None and time.monotonic() < deadline:
            # Drain START/OPEN events so the kernel never blocks on us.
            if select.select([uhid], [], [], 0.2)[0]:
                os.read(uhid, EVENT_SIZE)
            node = find_fido_hidraw(sysfs, before)
        if node is None:
            print("UG1 no hidraw node with usage page 0xF1D0 appeared", file=sys.stderr)
            return 1
        print(f"UG1 {node} report_descriptor has usage page 0xF1D0")
        path = f"/dev/{node}"
        deadline = time.monotonic() + 10
        while not os.path.exists(path) and time.monotonic() < deadline:
            time.sleep(0.1)
        os.chown(path, uid, gid)
        os.chmod(path, 0o600)
        print(f"UG1 {path} handed to uid {uid} with mode 0600")
        code = open_as(uid, gid, path)
        if code != 0:
            return 1
        print(f"UG1 uid {uid} opened {path} read-write")
        return 0
    finally:
        os.write(uhid, destroy_event())
        os.close(uhid)


if __name__ == "__main__":
    sys.exit(main())
