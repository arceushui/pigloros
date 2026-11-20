#!/usr/bin/env python3
"""ADR-110 E20 UG1: hosted uhid feasibility for the Linux owner U-tier.

Run as root (through `sudo`) on the hosted runner, after `modprobe uhid`. It
creates one virtual FIDO HID device through `/dev/uhid` and finds its hidraw
node by the sysfs `report_descriptor`, whose usage page must be 0xF1D0. After
`udevadm settle` it records the node's default owner, mode and ACL and
whether the invoking user (`SUDO_UID`) can read the descriptor and open the
node. It then hands the node to that user, the way the CI-only U-tier setup
will, and opens it again. Closing `/dev/uhid` destroys the device. Each step
prints one evidence line; any failure exits non-zero. Redmine #1474.
"""

from __future__ import annotations

import errno
import os
import select
import struct
import subprocess
import sys
import time
from pathlib import Path

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


def usage_pages(descriptor: bytes) -> list[int]:
    """Every Usage Page (global item tag 0) value in a short-item descriptor."""
    pages: list[int] = []
    index = 0
    while index < len(descriptor):
        prefix = descriptor[index]
        if prefix == 0xFE:  # long item: size byte, tag byte, data
            if index + 2 >= len(descriptor) or index + 3 + descriptor[index + 1] > len(
                descriptor
            ):
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


def open_as(uid: int, gid: int, path: str, flags: int) -> int:
    """Fork, drop to `uid`/`gid` and open `path` with `flags`.

    Returns 0 when the open succeeds, the errno when it fails with an
    `OSError`, and 255 for any other failure. Root drops every supplementary
    group, so the result is what `uid`/`gid` alone may open.
    """
    # Flush first so the child does not repeat the parent's buffered lines.
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        code = 255
        try:
            try:
                if os.geteuid() == 0:
                    os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
                os.close(os.open(path, flags | os.O_NONBLOCK | os.O_CLOEXEC))
                code = 0
            except OSError as error:
                # `OSError.errno` may be None; keep the 255 failure sentinel.
                code = error.errno or 255
        finally:
            # Any other exception still ends here: the child never returns
            # into main.
            os._exit(code)
    return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])


def outcome(code: int) -> str:
    if code == 0:
        return "opened"
    if code in (errno.EACCES, errno.EPERM):
        return f"refused ({errno.errorcode[code]})"
    return f"failed (code {code})"


def run_tool(arguments: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(arguments, capture_output=True, text=True, check=False)
    except OSError as error:
        print(f"UG1 {arguments[0]} unavailable: {error}")
        return None


def show_access(path: str) -> None:
    """Print the node's owner, mode and ACL as evidence."""
    metadata = os.stat(path)
    mode = metadata.st_mode & 0o7777
    print(f"UG1 {path} uid {metadata.st_uid} gid {metadata.st_gid} mode {mode:04o}")
    acl = run_tool(["getfacl", "-p", path])
    if acl is not None:
        for line in (acl.stdout or acl.stderr).splitlines():
            print(f"UG1 acl {line}")


def main() -> int:
    if os.geteuid() != 0:
        print("UG1 must run as root through sudo", file=sys.stderr)
        return 2
    if "SUDO_UID" not in os.environ or "SUDO_GID" not in os.environ:
        print("UG1 must run through sudo so SUDO_UID and SUDO_GID name the runner", file=sys.stderr)
        return 2
    uid = int(os.environ["SUDO_UID"])
    gid = int(os.environ["SUDO_GID"])
    sysfs = Path("/sys/class/hidraw")
    print(f"UG1 kernel {os.uname().release}")
    before = {entry.name for entry in sysfs.glob("hidraw*")} if sysfs.exists() else set()
    try:
        uhid = os.open("/dev/uhid", os.O_RDWR | os.O_CLOEXEC)
    except OSError as error:
        print(f"UG1 /dev/uhid unavailable: {error}", file=sys.stderr)
        return 1
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
        # Let udev finish its rules for the new node before reading or
        # changing its access.
        settle = run_tool(["udevadm", "settle", "--timeout=10"])
        if settle is not None:
            print(f"UG1 udevadm settle rc={settle.returncode}")
        if not os.path.exists(path):
            print(f"UG1 {path} did not appear", file=sys.stderr)
            return 1
        descriptor = f"{sysfs}/{node}/device/report_descriptor"
        read = outcome(open_as(uid, gid, descriptor, os.O_RDONLY))
        print(f"UG1 uid {uid} {read} {descriptor} for reading")
        show_access(path)
        default = outcome(open_as(uid, gid, path, os.O_RDWR))
        print(f"UG1 uid {uid} {default} {path} read-write with the default access")
        os.chown(path, uid, gid)
        os.chmod(path, 0o600)
        show_access(path)
        handed = open_as(uid, gid, path, os.O_RDWR)
        print(f"UG1 uid {uid} {outcome(handed)} {path} read-write after the sudo hand-over")
        return 0 if handed == 0 and read == "opened" else 1
    finally:
        # Closing /dev/uhid destroys the device; an explicit DESTROY could
        # fail after a refused CREATE2 and hide the real error.
        os.close(uhid)


if __name__ == "__main__":
    sys.exit(main())
