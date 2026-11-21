#!/usr/bin/env python3
"""Unit tests for the UG1 uhid feasibility script (Redmine #1474)."""

from __future__ import annotations

import contextlib
import errno
import io
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import owner_uhid_feasibility as ug1  # noqa: E402


class EventEncoding(unittest.TestCase):
    def test_create2_matches_the_kernel_layout(self) -> None:
        event = ug1.create2_event(ug1.FIDO_REPORT_DESCRIPTOR)
        self.assertEqual(len(event), ug1.EVENT_SIZE)
        (kind,) = struct.unpack_from("<I", event, 0)
        self.assertEqual(kind, ug1.UHID_CREATE2)
        self.assertEqual(event[4 : 4 + len(ug1.NAME)], ug1.NAME)
        rd_size, bus, vendor = struct.unpack_from("<HHI", event, 4 + 128 + 64 + 64)
        self.assertEqual(rd_size, len(ug1.FIDO_REPORT_DESCRIPTOR))
        self.assertEqual(bus, ug1.BUS_USB)
        self.assertEqual(vendor, 0x1209)
        data = event[4 + 128 + 64 + 64 + 2 + 2 + 16 :]
        self.assertEqual(data[: rd_size], ug1.FIDO_REPORT_DESCRIPTOR)
        self.assertEqual(set(data[rd_size:]), {0})

    def test_create2_refuses_oversized_input(self) -> None:
        with self.assertRaises(ValueError):
            ug1.create2_event(bytes(4097))
        with self.assertRaises(ValueError):
            ug1.create2_event(b"", bytes(128))


class DescriptorParsing(unittest.TestCase):
    def test_the_fido_descriptor_is_recognised(self) -> None:
        self.assertEqual(ug1.usage_pages(ug1.FIDO_REPORT_DESCRIPTOR), [0xF1D0])
        self.assertTrue(ug1.is_fido_descriptor(ug1.FIDO_REPORT_DESCRIPTOR))

    def test_other_and_malformed_descriptors_are_not(self) -> None:
        keyboard = bytes.fromhex("05010906a101c0")
        self.assertEqual(ug1.usage_pages(keyboard), [0x01])
        self.assertFalse(ug1.is_fido_descriptor(keyboard))
        self.assertFalse(ug1.is_fido_descriptor(bytes.fromhex("06d0")))
        self.assertFalse(ug1.is_fido_descriptor(bytes.fromhex("fe")))

    def test_long_items_are_skipped(self) -> None:
        long_item = bytes.fromhex("fe0201aabb")
        self.assertEqual(ug1.usage_pages(long_item + bytes.fromhex("06d0f1")), [0xF1D0])
        for truncated in ("fe02", "fe0201", "fe0201aa"):
            with self.assertRaises(ValueError):
                ug1.usage_pages(bytes.fromhex(truncated))

    def test_find_skips_existing_unreadable_and_other_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            sysfs = Path(root)
            for name, descriptor in [
                ("hidraw0", ug1.FIDO_REPORT_DESCRIPTOR),
                ("hidraw1", bytes.fromhex("05010906a101c0")),
                ("hidraw3", ug1.FIDO_REPORT_DESCRIPTOR),
            ]:
                (sysfs / name / "device").mkdir(parents=True)
                (sysfs / name / "device" / "report_descriptor").write_bytes(descriptor)
            (sysfs / "hidraw2" / "device").mkdir(parents=True)
            self.assertEqual(ug1.find_fido_hidraw(sysfs, {"hidraw0"}), "hidraw3")
            self.assertIsNone(ug1.find_fido_hidraw(sysfs, {"hidraw0", "hidraw3"}))


class OpenAs(unittest.TestCase):
    def test_reports_success_permission_and_other_errors(self) -> None:
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as root:
            readable = Path(root) / "readable"
            readable.write_bytes(b"x")
            self.assertEqual(ug1.open_as(uid, gid, str(readable), os.O_RDONLY), 0)
            locked = Path(root) / "locked"
            locked.write_bytes(b"x")
            locked.chmod(0)
            if uid != 0:
                code = ug1.open_as(uid, gid, str(locked), os.O_RDONLY)
                self.assertEqual(code, errno.EACCES)
                self.assertEqual(ug1.outcome(code), "refused (EACCES)")
            missing = ug1.open_as(uid, gid, str(Path(root) / "missing"), os.O_RDONLY)
            self.assertEqual(missing, errno.ENOENT)
            self.assertEqual(ug1.outcome(missing), f"failed (code {errno.ENOENT})")
        self.assertEqual(ug1.outcome(0), "opened")
        self.assertEqual(ug1.outcome(errno.EPERM), "refused (EPERM)")

    def test_a_missing_tool_is_reported_not_raised(self) -> None:
        self.assertIsNone(ug1.run_tool(["/nonexistent/ug1-tool"]))
        self.assertEqual(ug1.run_tool([sys.executable, "-c", "pass"]).returncode, 0)


class Main(unittest.TestCase):
    @unittest.skipIf(os.geteuid() == 0, "the refusal is for non-root callers")
    def test_a_non_root_run_is_refused_before_touching_uhid(self) -> None:
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            self.assertEqual(ug1.main(), 2)
        self.assertEqual(captured.getvalue(), "UG1 must run as root through sudo\n")


if __name__ == "__main__":
    unittest.main()
