#!/usr/bin/env python3
"""Tests for the #444 evidence producer's QEMU observation and cleanup logic.

The shell helpers run from the sourced scripts/qemu-closure-evidence.sh with
a passthrough `sudo` stub, against real child processes of this test. The
QMP helper runs against a fake QMP server on a Unix socket.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

import qemu_qmp_query_kvm as qmp


ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "qemu-closure-evidence.sh"
QEMU = "/nix/store/0123456789abcdfghijklmnpqrsvwxya-qemu-host-cpu-only-10.2.4"


class Shell:
    """Run producer functions in bash, with `sudo` passing straight through."""

    def __init__(self, directory: pathlib.Path):
        self.bin = directory / "bin"
        self.bin.mkdir()
        (self.bin / "sudo").write_text('#!/bin/sh\nexec "$@"\n')
        (self.bin / "sudo").chmod(0o755)

    def run(self, script: str) -> subprocess.CompletedProcess:
        environment = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}")
        return subprocess.run(["bash", "-c", f'source "{SCRIPT}"\n{script}'], env=environment,
                              capture_output=True, text=True, check=False)

    def out(self, script: str) -> str:
        result = self.run(script)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result.stdout


def start_time(pid: int) -> str:
    return pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


class ProducerShellTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = pathlib.Path(directory.name)
        self.shell = Shell(self.base)

    def child(self, *command: str) -> subprocess.Popen:
        process = subprocess.Popen(list(command or ("sleep", "60")))
        self.addCleanup(lambda: (process.poll() is None and process.kill(), process.wait()))
        return process

    def zombie(self) -> subprocess.Popen:
        process = subprocess.Popen(["true"])
        deadline = time.monotonic() + 10
        while self.state(process.pid) != "Z":
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.addCleanup(process.wait)
        return process

    @staticmethod
    def state(pid: int) -> str:
        try:
            return pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except OSError:
            return ""

    def test_only_the_recorded_emulator_images_match(self):
        for exe, expected in (
            (f"{QEMU}/bin/qemu-system-x86_64", True),
            (f"{QEMU}/bin/.qemu-system-x86_64-wrapped", True),
            (f"{QEMU}/bin/qemu-system-aarch64", False),
            (f"{QEMU}/bin/.qemu-system-aarch64-wrapped", False),
            (f"{QEMU}/bin/qemu-system-x86_64-wrapped", False),
            (f"{QEMU}/bin/.qemu-system-x86_64", False),
            (f"{QEMU}/libexec/qemu-system-x86_64", False),
            ("/nix/store/0123456789abcdfghijklmnpqrsvwxyb-qemu/bin/qemu-system-x86_64", False),
            (f"{QEMU}/bin/qemu-system-x86_64.evil", False),
            ("", False),
        ):
            with self.subTest(exe=exe):
                result = self.shell.run(f'is_qemu_image "{exe}" "{QEMU}" x86_64')
                self.assertEqual(result.returncode == 0, expected, result.stderr)

    def test_process_stat_reads_state_and_start_time(self):
        process = self.child()
        state, start = self.shell.out(f"process_stat {process.pid}").split()
        self.assertIn(state, ("S", "R"))
        self.assertEqual(start, start_time(process.pid))
        process.kill()
        process.wait()
        self.assertEqual(self.shell.out(f"process_stat {process.pid}"), "")

    def test_stop_qemu_kills_a_running_process_and_accepts_exited_ones(self):
        running = self.child()
        self.shell.out(f"stop_qemu {running.pid} {start_time(running.pid)}")
        self.assertIn(self.state(running.pid), ("Z", ""))
        zombie = self.zombie()
        self.shell.out(f"stop_qemu {zombie.pid} 1")
        self.assertEqual(self.state(zombie.pid), "Z")
        # A recycled PID (other start time) is never killed.
        other = self.child()
        self.shell.out(f"stop_qemu {other.pid} 1")
        self.assertIn(self.state(other.pid), ("S", "R"))

    def test_cleanup_record_names_running_zombie_and_recycled_processes(self):
        (self.base / "out" / "host").mkdir(parents=True)
        present = self.base / "work"
        present.mkdir()
        running, zombie = self.child(), self.zombie()
        cases = [
            (running.pid, start_time(running.pid), present, "unobserved-or-running", "present"),
            (zombie.pid, start_time(zombie.pid), self.base / "gone", "exited", "removed"),
            (running.pid, "1", self.base / "gone", "exited", "removed"),
            ("", "", self.base / "gone", "unobserved-or-running", "removed"),
        ]
        for pid, start, work, process, directory in cases:
            with self.subTest(pid=pid, start=start):
                self.shell.out(f'write_cleanup_record "{pid}" "{start}" "{work}" "{self.base}/out"')
                self.assertEqual((self.base / "out/host/vm-cleanup").read_text(),
                                 f"qemu-process\t{process}\nwork-directory\t{directory}\n")

    def test_failed_proc_reads_report_without_exiting(self):
        (self.base / "out" / "host").mkdir(parents=True)
        process = self.child()
        process.kill()
        process.wait()
        result = self.shell.run(f'record_qemu {process.pid} "{self.base}/out" || echo reported-failure')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "reported-failure")
        live = self.child()
        self.shell.out(f'record_qemu {live.pid} "{self.base}/out"')
        argv = (self.base / "out/host/qemu-argv").read_bytes().split(b"\0")
        self.assertEqual(argv[:2], [b"sleep", b"60"])

    def finish(self, qemu_pid: str, start: str, observe_failed: int) -> tuple[subprocess.CompletedProcess, pathlib.Path]:
        out, work = self.base / f"out{self.id()}{qemu_pid}{observe_failed}", self.base / "w"
        (out / "host").mkdir(parents=True)
        (out / "host/serial-console.log").write_text("Power down\n")
        (work / "xchg/guest").mkdir(parents=True, exist_ok=True)
        (work / "xchg/guest/status").write_text("complete\n")
        result = self.shell.run(
            f'true & finish_boot $! "{qemu_pid}" "{start}" {observe_failed} "{work}" "{out}"')
        return result, out

    def test_finish_boot_always_cleans_up_and_fails_only_at_the_end(self):
        zombie = self.zombie()
        for observe_failed, code in ((0, 0), (1, 1)):
            with self.subTest(observe_failed=observe_failed):
                result, out = self.finish(str(zombie.pid), start_time(zombie.pid), observe_failed)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse((self.base / "w").exists())
                self.assertEqual((out / "guest/status").read_text(), "complete\n")
                self.assertEqual((out / "host/vm-exit-status").read_text(), "0\n")
                self.assertEqual((out / "host/vm-cleanup").read_text(),
                                 "qemu-process\texited\nwork-directory\tremoved\n")
        # A QEMU that is still running is stopped before the record is written.
        running = self.child()
        result, out = self.finish(str(running.pid), start_time(running.pid), 0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.state(running.pid), ("Z", ""))
        self.assertEqual((out / "host/vm-cleanup").read_text(),
                         "qemu-process\texited\nwork-directory\tremoved\n")
        # No observed QEMU always fails, after the same cleanup.
        result, out = self.finish("", "", 0)
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.base / "w").exists())
        self.assertIn("unobserved-or-running", (out / "host/vm-cleanup").read_text())

    def test_producer_and_checker_hash_the_same_inputs(self):
        import check_qemu_closure_evidence as checker
        listed = self.shell.out('printf "%s\\n" "${provenance_files[@]}"').split()
        self.assertEqual(tuple(listed), checker.PROVENANCE_FILES)


class FakeQmp:
    """A one-connection QMP server that sends scripted replies."""

    def __init__(self, path: pathlib.Path, replies: list[str], greeting: str | None = None):
        self.path, self.replies, self.received = path, replies, []
        self.greeting = greeting if greeting is not None else json.dumps({"QMP": {"version": {}}})
        self.server = socket.socket(socket.AF_UNIX)
        self.server.bind(str(path))
        self.server.listen(1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        connection, _ = self.server.accept()
        with connection, connection.makefile("rw") as stream:
            stream.write(self.greeting + "\n")
            stream.flush()
            for reply in self.replies:
                line = stream.readline()
                if not line:
                    return
                self.received.append(json.loads(line)["execute"])
                stream.write(reply + "\n")
                stream.flush()

    def close(self):
        self.thread.join(5)
        self.server.close()


class QmpTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.socket = pathlib.Path(directory.name) / "qmp.sock"

    def run_main(self, pid: int | str = os.getpid()) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = qmp.main([str(self.socket), str(pid)])
        return code, out.getvalue(), err.getvalue()

    def test_reports_query_kvm_after_capabilities_and_skips_events(self):
        server = FakeQmp(self.socket, [
            json.dumps({"event": "RESUME"}) + "\n" + json.dumps({"return": {}}),
            json.dumps({"return": {"enabled": False, "present": True}}),
        ])
        code, out, err = self.run_main()
        server.close()
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), {"return": {"enabled": False, "present": True}})
        self.assertEqual(server.received, ["qmp_capabilities", "query-kvm"])

    def test_refused_capabilities_missing_greeting_and_garbage_fail(self):
        cases = [
            ([json.dumps({"error": {"class": "CommandNotFound"}}), json.dumps({"return": {}})], None),
            ([json.dumps({"return": {}})], None),
            ([json.dumps({"return": {}}), "[1, 2]"], None),
            ([json.dumps({"return": {}}), "not json"], None),
            ([json.dumps({"return": {}}), json.dumps({"return": {}})], json.dumps({"hello": 1})),
        ]
        for replies, greeting in cases:
            with self.subTest(replies=replies, greeting=greeting):
                self.socket.unlink(missing_ok=True)
                server = FakeQmp(self.socket, replies, greeting)
                code, _, err = self.run_main()
                server.close()
                self.assertEqual(code, 1, err)

    def test_retries_while_qemu_runs_and_stops_once_it_exits(self):
        start = time.monotonic()
        with self.assertRaisesRegex(qmp.QmpError, "never accepted"):
            qmp.connect(str(self.socket), os.getpid(), attempts=3, interval=0.01)
        exited = subprocess.Popen(["true"])
        exited.wait()
        with self.assertRaisesRegex(qmp.QmpError, "exited before"):
            qmp.connect(str(self.socket), exited.pid, attempts=1000, interval=0.5)
        self.assertLess(time.monotonic() - start, 5)

        def late_server():
            time.sleep(0.3)
            FakeQmp(self.socket, [json.dumps({"return": {}}),
                                  json.dumps({"return": {"enabled": False, "present": True}})])
        threading.Thread(target=late_server, daemon=True).start()
        code, out, err = self.run_main()
        self.assertEqual(code, 0, err)
        self.assertFalse(json.loads(out)["return"]["enabled"])

    def test_zombie_qemu_counts_as_exited(self):
        zombie = subprocess.Popen(["true"])
        deadline = time.monotonic() + 10
        while qmp.running(zombie.pid):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.addCleanup(zombie.wait)
        self.assertFalse(qmp.running(zombie.pid))
        self.assertTrue(qmp.running(os.getpid()))

    def test_bad_arguments_are_refused(self):
        for argv in ([], [str(self.socket)], [str(self.socket), "pid"]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()):
                self.assertEqual(qmp.main(argv), 2)


if __name__ == "__main__":
    unittest.main()
