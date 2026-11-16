#!/usr/bin/env python3
"""Tests for the #444 evidence producer's QEMU observation and cleanup logic.

The shell helpers run from the sourced scripts/qemu-closure-evidence.sh with
a passthrough `sudo` stub, against real child processes of this test. The
QMP helper runs against a fake QMP server on a Unix socket. The Nix settings
check runs from the sourced scripts/install-pinned-nix.sh against a stub
`nix`, and the guest's process recording from the sourced collector.
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
INSTALL_NIX = ROOT / "scripts" / "install-pinned-nix.sh"
COLLECTOR = ROOT / "deploy" / "nixos" / "qemu-evidence" / "collect-evidence.sh"
NIX_SETTINGS = {
    "substituters": "https://cache.nixos.org",
    "trusted-public-keys": "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
    "require-sigs": "true",
    "sandbox": "true",
}
QEMU = "/nix/store/0123456789abcdfghijklmnpqrsvwxya-qemu-host-cpu-only-10.2.4"


class Shell:
    """Run producer functions in bash, with `sudo` passing straight through."""

    def __init__(self, directory: pathlib.Path):
        self.bin = directory / "bin"
        self.bin.mkdir()
        (self.bin / "sudo").write_text('#!/bin/sh\nexec "$@"\n')
        (self.bin / "sudo").chmod(0o755)

    def stub(self, name: str, body: str) -> None:
        (self.bin / name).write_text(f"#!/bin/bash\n{body}\n")
        (self.bin / name).chmod(0o755)

    def run(self, script: str, source: pathlib.Path = SCRIPT) -> subprocess.CompletedProcess:
        environment = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}")
        # writeShellApplication runs the collector with the same options.
        prelude = "set -o errexit -o nounset -o pipefail\n" if source == COLLECTOR else ""
        return subprocess.run(["bash", "-c", f'{prelude}source "{source}"\n{script}'], env=environment,
                              capture_output=True, text=True, check=False)

    def out(self, script: str, source: pathlib.Path = SCRIPT) -> str:
        result = self.run(script, source)
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
        # A record that cannot be kept fails the step, after the same cleanup.
        out = self.base / "blocked"
        (out / "host").mkdir(parents=True)
        (out / "host/serial-console.log").write_text("")
        (out / "guest").write_text("a file where the guest record goes")
        (self.base / "w/xchg/guest").mkdir(parents=True)
        result = self.shell.run(f'true & finish_boot $! "{zombie.pid}" "{start_time(zombie.pid)}" 0 "{self.base}/w" "{out}"')
        self.assertEqual(result.returncode, 1)
        self.assertIn("record failed 1", result.stderr)
        self.assertFalse((self.base / "w").exists())
        self.assertEqual((out / "host/vm-cleanup").read_text(), "qemu-process\texited\nwork-directory\tremoved\n")
        # No observed QEMU always fails, after the same cleanup.
        result, out = self.finish("", "", 0)
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.base / "w").exists())
        self.assertIn("unobserved-or-running", (out / "host/vm-cleanup").read_text())

    def nix_stub(self, settings: dict[str, str]) -> pathlib.Path:
        cases = "".join(f"  {name}) printf '%s\\n' '{value}' ;;\n" for name, value in settings.items())
        nix = self.base / "nix"
        nix.write_text(f'#!/bin/bash\n[[ $1 == config && $2 == show ]] || exit 2\n'
                       f'case "$3" in\n{cases}  *) exit 1 ;;\nesac\n')
        nix.chmod(0o755)
        return nix

    def test_nix_settings_must_equal_the_pinned_trust_settings(self):
        result = self.shell.run(f'check_nix_settings "{self.nix_stub(NIX_SETTINGS)}"', INSTALL_NIX)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "".join(f"{name} = {value}\n" for name, value in NIX_SETTINGS.items()))
        for name, value in (("substituters", "https://cache.nixos.org https://evil.example"),
                            ("trusted-public-keys", "evil-1:AAAA"),
                            ("require-sigs", "false"), ("sandbox", "relaxed"), ("sandbox", "")):
            with self.subTest(name=name, value=value):
                result = self.shell.run(
                    f'check_nix_settings "{self.nix_stub({**NIX_SETTINGS, name: value})}"', INSTALL_NIX)
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"effective {name} is", result.stderr)
        # A setting Nix cannot show fails too.
        settings = dict(NIX_SETTINGS)
        del settings["sandbox"]
        result = self.shell.run(f'check_nix_settings "{self.nix_stub(settings)}"', INSTALL_NIX)
        self.assertNotEqual(result.returncode, 0)

    def record(self, pid: int) -> subprocess.CompletedProcess:
        work = self.base / "guest"
        (work / "processes").mkdir(parents=True, exist_ok=True)
        return self.shell.run(f'cd "{work}"\nrecord_process {pid}', COLLECTOR)

    def test_collector_records_a_running_process(self):
        process = self.child()
        result = self.record(process.pid)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.base / "guest/processes" / str(process.pid)
        self.assertEqual({path.name for path in record.iterdir()}, {"exe", "environ", "namespaces"})
        self.assertEqual((record / "exe").read_text(), f"{os.readlink(f'/proc/{process.pid}/exe')}\n")
        self.assertEqual((record / "environ").read_bytes(),
                         pathlib.Path(f"/proc/{process.pid}/environ").read_bytes())
        self.assertEqual((record / "namespaces").read_text(), "".join(
            f"{ns}\t{os.readlink(f'/proc/{process.pid}/ns/{ns}')}\n" for ns in ("pid", "user", "mnt")))

    def test_collector_skips_a_process_that_exits_during_the_scan(self):
        gone = self.child()
        gone.kill()
        gone.wait()
        for pid in (gone.pid, self.zombie().pid):
            with self.subTest(pid=pid):
                result = self.record(pid)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.base / "guest/processes" / str(pid)).exists())
        # A process that exits while it is read: the reads fail, then its
        # /proc entry is gone.
        exiting = self.child()
        self.shell.stub("readlink", f"kill -KILL {exiting.pid}; while [[ -e /proc/{exiting.pid} ]]; "
                                    f"do sleep 0.01; done; exit 1")
        threading.Thread(target=exiting.wait, daemon=True).start()
        result = self.record(exiting.pid)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.base / "guest/processes" / str(exiting.pid)).exists())

    def test_collector_keeps_a_process_whose_zombie_leader_has_live_threads(self):
        # The leader calls pthread_exit while another thread sleeps: the leader
        # shows state Z, but the process still runs.
        process = self.child(sys.executable, "-c", (
            "import ctypes, threading, time\n"
            "threading.Thread(target=time.sleep, args=(60,)).start()\n"
            "ctypes.CDLL(None).pthread_exit(None)\n"))
        deadline = time.monotonic() + 10
        while self.state(process.pid) != "Z":
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.assertEqual(self.shell.out(f"start_time {process.pid}", COLLECTOR), f"{start_time(process.pid)}\n")
        # It is recorded, or its failed reads fail the collection: never skipped.
        result = self.record(process.pid)
        recorded = (self.base / "guest/processes" / str(process.pid)).exists()
        self.assertTrue((result.returncode == 0 and recorded) or (
            result.returncode == 1 and f"cannot read running process {process.pid}" in result.stderr),
            result.stderr)
        # Once every thread has exited, it is gone.
        process.kill()
        deadline = time.monotonic() + 10
        while len(list(pathlib.Path(f"/proc/{process.pid}/task").glob("*"))) > 1:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.assertEqual(self.shell.out(f"start_time {process.pid}", COLLECTOR), "")

    def test_collector_skips_a_reused_pid(self):
        process = self.child()
        # The second stat read shows another start time: the PID was reused.
        counter = self.base / "stat-reads"
        self.shell.stub("cat", f'if [[ $1 == /proc/*/stat ]] && [[ -e "{counter}" ]]; then\n'
                               "  /bin/cat \"$1\" | awk '{ $22 = 1; print }'\n"
                               f'else\n  [[ $1 == /proc/*/stat ]] && touch "{counter}"\n  exec /bin/cat "$@"\nfi')
        result = self.record(process.pid)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(counter.exists())
        self.assertFalse((self.base / "guest/processes" / str(process.pid)).exists())

    def test_collector_fails_on_any_other_read_failure(self):
        process = self.child()
        self.shell.stub("readlink", "printf 'readlink: Permission denied\\n' >&2; exit 1")
        result = self.record(process.pid)
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"cannot read running process {process.pid}", result.stderr)
        # So does a /proc entry whose stat cannot be read.
        self.shell.stub("cat", "exit 1")
        result = self.record(process.pid)
        self.assertEqual(result.returncode, 1)

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

    def run_main(self, pid: int = os.getpid()) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = qmp.main([str(self.socket), str(pid), start_time(pid)])
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
            qmp.connect(str(self.socket), os.getpid(), start_time(os.getpid()), attempts=3, interval=0.01)
        exited = subprocess.Popen(["true"])
        exited.wait()
        with self.assertRaisesRegex(qmp.QmpError, "exited before"):
            qmp.connect(str(self.socket), exited.pid, "1", attempts=1000, interval=0.5)
        # A live process with another start time is a recycled PID, not QEMU.
        with self.assertRaisesRegex(qmp.QmpError, "exited before"):
            qmp.connect(str(self.socket), os.getpid(), "1", attempts=1000, interval=0.5)
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
        zombie_start = start_time(zombie.pid)
        while qmp.running(zombie.pid, zombie_start):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.addCleanup(zombie.wait)
        self.assertFalse(qmp.running(zombie.pid, zombie_start))
        self.assertTrue(qmp.running(os.getpid(), start_time(os.getpid())))

    def test_bad_arguments_are_refused(self):
        for argv in ([], [str(self.socket)], [str(self.socket), "1"], [str(self.socket), "pid", "1"],
                     [str(self.socket), "1", "start"]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()):
                self.assertEqual(qmp.main(argv), 2)


if __name__ == "__main__":
    unittest.main()
