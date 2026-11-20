#!/usr/bin/env python3
"""Tests for the #444 evidence producer's QEMU observation and cleanup logic.

The shell helpers run from the sourced scripts/qemu-closure-evidence.sh with
a passthrough `sudo` stub, against real child processes of this test. The
QMP helper runs against a fake QMP server on a Unix socket. The Nix settings
check runs from the sourced scripts/install-pinned-nix.sh against a stub
`nix`, and the guest's process recording from the sourced collector.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import signal
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
KERNEL_CACHE = ROOT / "scripts" / "qemu-kernel-cache.sh"
KERNEL_SIGNING_PUBLIC_KEY = "piglor-qemu-kernel-1:62KZ76u3AzKRSSsmRDqEanDdgOu7j81BXH5VINsQj9c="
COLLECTOR = ROOT / "deploy" / "nixos" / "qemu-evidence" / "collect-evidence.sh"
NIX_SETTINGS = {
    "substituters": "https://cache.nixos.org",
    "trusted-public-keys": "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= "
                           + KERNEL_SIGNING_PUBLIC_KEY,
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
                            ("trusted-public-keys", NIX_SETTINGS["trusted-public-keys"] + " evil-1:AAAA"),
                            ("trusted-public-keys", "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="),
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

    def test_readback_records_digests_or_the_whole_read_error(self):
        import check_qemu_closure_evidence as checker
        root = self.base / "root"
        (root / "usr/share/pigloros").mkdir(parents=True)
        expected = checker.readback_bytes()
        (root / "usr/share/pigloros/readback").write_bytes(expected)
        self.assertEqual(self.shell.out(f'readback "{root}"', COLLECTOR), (
            f"file\t0\t{hashlib.sha256(expected).hexdigest()}\n"
            f"block-0\t0\t{hashlib.sha256(expected[:4096]).hexdigest()}\n"))
        # A failed read keeps its whole message, with tabs and newlines flattened.
        self.shell.stub("sha256sum", "/bin/cat >/dev/null\n"
                                     "printf 'sha256sum: -: Input/output error\\n\\textra\\n' >&2; exit 1")
        lines = self.shell.out(f'readback "{root}"', COLLECTOR).splitlines()
        self.assertEqual(lines[0], "file\t1\tsha256sum: -: Input/output error  extra")
        self.assertTrue(lines[1].startswith("block-0\t1\t"), lines)

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


class KernelCacheTests(unittest.TestCase):
    """scripts/qemu-kernel-cache.sh against a `nix` stub that logs each call."""

    DRV = "/nix/store/0123456789abcdfghijklmnpqrsvwxya-linux-6.12.117.drv"
    OUT = "/nix/store/0123456789abcdfghijklmnpqrsvwxyb-linux-6.12.117"
    DEV = "/nix/store/0123456789abcdfghijklmnpqrsvwxyc-linux-6.12.117-dev"
    MODULES = "/nix/store/0123456789abcdfghijklmnpqrsvwxye-linux-6.12.117-modules"
    OUTPUTS = (OUT, DEV, MODULES)
    APPLY = ('kernel: builtins.concatStringsSep "\\n" (map (output: (builtins.getAttr output kernel).outPath)'
             ' kernel.outputs) + "\\n"')
    SECRET = "piglor-qemu-kernel-1:c2VjcmV0LWtleS1ieXRlcw=="
    PUBLIC = KERNEL_SIGNING_PUBLIC_KEY
    NIXOS = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    THROWAWAY_SECRET = "qemu-kernel-cache-selftest:dGhyb3dhd2F5LXNlY3JldA=="
    THROWAWAY_PUBLIC = "qemu-kernel-cache-selftest:dGhyb3dhd2F5LXB1YmxpYw=="
    SAMPLE = "/nix/store/0123456789abcdfghijklmnpqrsvwxyd-qemu-kernel-cache-selftest-1"
    REFUSED = "error: cannot add path because it lacks a signature by a trusted key"
    UNTRUSTED = "path is untrusted"

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = pathlib.Path(directory.name)
        self.log = self.base / "nix.log"
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.cache = self.base / "cache"
        self.stub_nix()

    def stub_nix(self, drv: str = DRV, outputs: tuple[str, ...] = OUTPUTS, trusted: str | None = None,
                 public: str | None = None, copy_status: int = 0, verify_status: int = 0,
                 verify_message: str = UNTRUSTED, copy_sleep: int = 0, import_status: int = 0,
                 import_message: str = REFUSED, sample_ca: str = "null") -> None:
        # Each call logs its arguments on one line, and whether it inherited
        # the signing secret. `key convert-secret-to-public` logs what it read
        # on stdin; `copy --to` logs the signing key file's mode and content,
        # read while the copy runs; `store verify` logs a NIX_CONFIG override
        # and passes with one, otherwise it exits with verify_status.
        self.log.unlink(missing_ok=True)
        (self.base / "key-path").unlink(missing_ok=True)
        trusted = f"{self.NIXOS} {self.PUBLIC}" if trusted is None else trusted
        public = self.PUBLIC if public is None else public
        quoted = " ".join(f"'{output}'" for output in outputs)
        listing = f"printf '%s\\n' {quoted}" if outputs else ":"
        (self.bin / "nix").write_text(f"""#!/bin/bash
line="$*"
printf '%s\\n' "${{line//$'\\n'/ }}" >>"{self.log}"
if [[ -n ${{QEMU_KERNEL_CACHE_SIGNING_KEY:-}} ]]; then
  printf 'inherited-secret\\n' >>"{self.log}"
fi
case "$1 $2" in
eval*)
  case "$*" in
  *--apply*) {listing} ;;
  *.drvPath) printf '%s' '{drv}' ;;
  esac ;;
"build --impure") printf '%s\\n' '{self.SAMPLE}' ;;
"path-info --json") printf '{{"%s":{{"ca":%s}}}}\\n' '{self.SAMPLE}' '{sample_ca}' ;;
"key convert-secret-to-public")
  secret="$(cat)"
  printf 'stdin %s\\n' "$secret" >>"{self.log}"
  if [[ $secret == '{self.THROWAWAY_SECRET}' ]]; then
    printf '%s\\n' '{self.THROWAWAY_PUBLIC}'
  else
    printf '%s\\n' '{public}'
  fi ;;
"key generate-secret") printf '%s\\n' '{self.THROWAWAY_SECRET}' ;;
"config show") printf '%s\\n' '{trusted}' ;;
"store delete") ;;
"store verify")
  if [[ -n ${{NIX_CONFIG:-}} ]]; then
    printf 'NIX_CONFIG=%s\\n' "$NIX_CONFIG" >>"{self.log}"
    exit 0
  fi
  if (({verify_status} != 0)); then
    printf '%s\\n' '{verify_message}' >&2
  fi
  exit {verify_status} ;;
"copy --from")
  if (({import_status} != 0)); then
    printf '%s\\n' '{import_message}' >&2
  fi
  exit {import_status} ;;
copy*)
  for arg in "$@"; do
    if [[ $arg == file://*secret-key=* ]]; then
      key="${{arg##*secret-key=}}"
      printf '%s\\n' "$key" >"{self.base}/key-path"
      printf 'key-mode %s\\nkey-content %s\\n' "$(stat -c %a "$key")" "$(cat "$key")" >>"{self.log}"
      sleep {copy_sleep}
    fi
  done
  exit {copy_status} ;;
esac
""")
        (self.bin / "nix").chmod(0o755)

    def environment(self, secret: str | None) -> dict[str, str]:
        environment = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}")
        environment.pop("QEMU_KERNEL_CACHE_SIGNING_KEY", None)
        if secret is not None:
            environment["QEMU_KERNEL_CACHE_SIGNING_KEY"] = secret
        return environment

    def run_cache(self, *args: str, secret: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(KERNEL_CACHE), *args], env=self.environment(secret),
                              capture_output=True, text=True, check=False)

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def kernel(self, architecture: str) -> str:
        return (f"{ROOT}/deploy/nixos#nixosConfigurations.qemu-evidence-{architecture}"
                ".config.boot.kernelPackages.kernel")

    def path_evals(self, architecture: str) -> list[str]:
        kernel = self.kernel(architecture)
        return [f"eval --raw --no-update-lock-file {kernel} --apply {self.APPLY}"]

    def verify_call(self) -> str:
        return f"store verify --recursive --store file://{self.cache} --sigs-needed 1 {' '.join(self.OUTPUTS)}"

    def key_path(self) -> pathlib.Path:
        return pathlib.Path((self.base / "key-path").read_text().strip())

    def test_key_names_the_kernel_derivation(self):
        result = self.run_cache("key", "aarch64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "key=qemu-kernel-piglor-qemu-kernel-1-aarch64-0123456789abcdfghijklmnpqrsvwxya\n")
        self.assertEqual(self.calls(), [f"eval --raw --no-update-lock-file {self.kernel('aarch64')}.drvPath"])

    def test_key_refuses_an_unexpected_derivation_or_architecture(self):
        self.stub_nix(drv="/nix/store/short-linux.drv")
        result = self.run_cache("key", "x86_64")
        self.assertEqual(result.returncode, 1)
        self.assertIn("unexpected kernel derivation path", result.stderr)
        for args in (("key", "riscv64"), ("key",), ("build", "x86_64", "extra"),
                     ("verify", "x86_64"), ("import", "riscv64", "dir"), ("sign", "x86_64"),
                     ("selftest",), ("selftest", "dir", "extra")):
            with self.subTest(args=args):
                self.assertEqual(self.run_cache(*args).returncode, 2)

    def test_build_builds_every_output_without_the_signing_key(self):
        result = self.run_cache("build", "x86_64")
        self.assertEqual(result.returncode, 0, result.stderr)
        kernel = self.kernel("x86_64")
        self.assertEqual(self.calls(), [f"build --no-update-lock-file --no-link --print-build-logs {kernel}^*"])

    def test_export_signs_the_built_paths_with_a_private_temporary_key_file_then_verifies(self):
        result = self.run_cache("export", "x86_64", str(self.cache), secret=self.SECRET)
        self.assertEqual(result.returncode, 0, result.stderr)
        key_path = self.key_path()
        self.assertEqual(self.calls(), [
            "key convert-secret-to-public",
            f"stdin {self.SECRET}",
            "config show trusted-public-keys",
            *self.path_evals("x86_64"),
            f"copy --to file://{self.cache}?compression=zstd&secret-key={key_path} {' '.join(self.OUTPUTS)}",
            "key-mode 600",
            f"key-content {self.SECRET}",
            *self.path_evals("x86_64"),
            self.verify_call(),
        ])
        self.assertFalse(key_path.exists())
        self.assertNotIn(self.SECRET, result.stdout + result.stderr)
        self.assertNotIn("inherited-secret", self.calls())

    def test_export_removes_the_key_file_and_skips_verify_when_the_copy_fails(self):
        self.stub_nix(copy_status=3)
        result = self.run_cache("export", "x86_64", str(self.cache), secret=self.SECRET)
        self.assertEqual(result.returncode, 3)
        self.assertFalse(self.key_path().exists())
        self.assertNotIn(self.verify_call(), self.calls())

    def test_export_removes_the_key_file_when_terminated_or_interrupted(self):
        for signal_number, status in ((signal.SIGTERM, 143), (signal.SIGINT, 130)):
            with self.subTest(signal=signal_number):
                self.stub_nix(copy_sleep=2)
                process = subprocess.Popen(["bash", str(KERNEL_CACHE), "export", "x86_64", str(self.cache)],
                                           env=self.environment(self.SECRET),
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.addCleanup(process.kill)
                deadline = time.monotonic() + 10
                while not (self.base / "key-path").exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                process.send_signal(signal_number)
                self.assertEqual(process.wait(timeout=10), status)
                self.assertFalse(self.key_path().exists())

    def test_export_fails_when_verification_fails(self):
        self.stub_nix(verify_status=1)
        result = self.run_cache("export", "x86_64", str(self.cache), secret=self.SECRET)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls()[-1], self.verify_call())

    def test_export_refuses_a_key_the_daemon_does_not_trust(self):
        for trusted in (self.NIXOS, f"{self.NIXOS} {self.PUBLIC}x", ""):
            with self.subTest(trusted=trusted):
                self.log.unlink(missing_ok=True)
                self.stub_nix(trusted=trusted)
                result = self.run_cache("export", "x86_64", str(self.cache), secret=self.SECRET)
                self.assertEqual(result.returncode, 1)
                self.assertIn("is not in trusted-public-keys", result.stderr)
                self.assertFalse(any(call.startswith("copy") for call in self.calls()))
                self.assertFalse((self.base / "key-path").exists())

    def test_export_refuses_a_key_with_another_name(self):
        other = "other-key-1:62KZ76u3AzKRSSsmRDqEanDdgOu7j81BXH5VINsQj9c="
        self.stub_nix(public=other, trusted=f"{self.NIXOS} {other}")
        result = self.run_cache("export", "x86_64", str(self.cache), secret=self.SECRET)
        self.assertEqual(result.returncode, 1)
        self.assertIn("is not named piglor-qemu-kernel-1", result.stderr)
        self.assertFalse(any(call.startswith("copy") for call in self.calls()))

    def test_export_without_the_signing_key_does_nothing(self):
        for secret in (None, ""):
            with self.subTest(secret=secret):
                result = self.run_cache("export", "x86_64", str(self.cache), secret=secret)
                self.assertEqual(result.returncode, 1)
                self.assertIn("QEMU_KERNEL_CACHE_SIGNING_KEY is not set", result.stderr)
                self.assertEqual(self.calls(), [])

    def test_the_secret_never_reaches_a_command_line(self):
        self.run_cache("export", "x86_64", str(self.cache), secret=self.SECRET)
        command_lines = [call for call in self.calls() if not call.startswith(("stdin ", "key-content "))]
        self.assertTrue(command_lines)
        for call in command_lines:
            self.assertNotIn(self.SECRET, call)

    def test_verify_requires_signatures_on_every_output(self):
        for status in (0, 1):
            with self.subTest(status=status):
                self.log.unlink(missing_ok=True)
                self.stub_nix(verify_status=status)
                result = self.run_cache("verify", "aarch64", str(self.cache))
                self.assertEqual(result.returncode, status)
                self.assertEqual(self.calls(), [*self.path_evals("aarch64"), self.verify_call()])

    def test_import_copies_the_concrete_paths_with_signature_checks(self):
        result = self.run_cache("import", "aarch64", str(self.cache))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [
            *self.path_evals("aarch64"),
            f"copy --from file://{self.cache} {' '.join(self.OUTPUTS)}",
        ])

    def test_an_unexpected_output_path_stops_before_copying(self):
        for dev in ("", "/nix/store/short-dev", "/nix/store/0123456789abcdfghijklmnpqrsvwxyc-dev/../etc"):
            with self.subTest(dev=dev):
                self.stub_nix(outputs=(self.OUT, dev, self.MODULES))
                result = self.run_cache("import", "x86_64", str(self.cache))
                self.assertEqual(result.returncode, 1)
                self.assertIn("unexpected kernel output path", result.stderr)
                self.assertFalse(any(call.startswith("copy") for call in self.calls()))

    def test_a_kernel_without_outputs_stops_before_copying(self):
        self.stub_nix(outputs=())
        result = self.run_cache("import", "x86_64", str(self.cache))
        self.assertEqual(result.returncode, 1)
        self.assertIn("the kernel has no output paths", result.stderr)
        self.assertFalse(any(call.startswith("copy") for call in self.calls()))

    ASSET = "qemu-kernel-piglor-qemu-kernel-1-x86_64-0123456789abcdfghijklmnpqrsvwxya.tar"
    OLD_ASSET = "qemu-kernel-piglor-qemu-kernel-1-x86_64-0123456789abcdfghijklmnpqrsvwxyz.tar"
    OTHER_ARCH = "qemu-kernel-piglor-qemu-kernel-1-aarch64-0123456789abcdfghijklmnpqrsvwxyz.tar"

    def stub_gh(self, assets: tuple[str, ...] = (), release: str = "present", create_status: int = 0,
                archive: pathlib.Path | None = None) -> None:
        # Logs each call as "gh ARGS". `release view` lists the assets, reports
        # a missing release as gh does, or fails with another error; `upload`
        # logs the archive's member names.
        listing = " ".join(f"'{asset}'" for asset in assets)
        listing = f"printf '%s\\n' {listing}" if assets else ":"
        (self.bin / "gh").write_text(f"""#!/bin/bash
printf 'gh %s\\n' "$*" >>"{self.log}"
case "$1 $2" in
"release view")
  case "{release}" in
  missing) printf 'release not found\\n' >&2; exit 1 ;;
  broken) printf 'HTTP 502: Bad Gateway\\n' >&2; exit 4 ;;
  esac
  if [[ $* == *--json* ]]; then {listing}; fi ;;
"release create") exit {create_status} ;;
"release download")
  cp -- "{archive}" "$7/$5" ;;
"release upload")
  printf 'upload-listing %s\\n' "$(tar -tf "$4" | sort | tr '\\n' ' ')" >>"{self.log}" ;;
esac
""")
        (self.bin / "gh").chmod(0o755)

    def archive(self, *members: tuple[str, str]) -> pathlib.Path:
        source = self.base / "source"
        source.mkdir()
        for name, kind in members:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if kind == "link":
                path.symlink_to("/etc/passwd")
            else:
                path.write_text(name)
        archive = self.base / "archive.tar"
        subprocess.run(["tar", "-cf", str(archive), "-C", str(source), "."], check=True)
        return archive

    def gh_calls(self) -> list[str]:
        return [call for call in self.calls() if call.startswith(("gh ", "upload-listing "))]

    def test_fetch_unpacks_the_asset_named_by_the_kernel_derivation(self):
        archive = self.archive(("nix-cache-info", "file"), ("nar/a.nar.zst", "file"))
        self.stub_gh(assets=(self.OTHER_ARCH, self.ASSET), archive=archive)
        result = self.run_cache("fetch", "x86_64", str(self.cache))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "hit=true\n")
        self.assertEqual((self.cache / "nar" / "a.nar.zst").read_text(), "nar/a.nar.zst")
        download = next(call for call in self.gh_calls() if call.startswith("gh release download"))
        self.assertRegex(download, rf"^gh release download qemu-kernel-cache --pattern {re.escape(self.ASSET)} --dir /")

    def test_fetch_misses_without_the_asset_or_the_release(self):
        for stub in ({"assets": (self.OLD_ASSET, self.OTHER_ARCH)}, {"release": "missing"}):
            with self.subTest(stub=stub):
                self.log.unlink(missing_ok=True)
                self.stub_gh(**stub)
                result = self.run_cache("fetch", "x86_64", str(self.cache))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "hit=false\n")
                self.assertEqual(self.gh_calls(),
                                 ["gh release view qemu-kernel-cache --json assets --jq .assets[].name"])
                self.assertFalse(self.cache.exists())

    def test_fetch_fails_when_the_release_cannot_be_listed(self):
        self.stub_gh(release="broken")
        result = self.run_cache("fetch", "x86_64", str(self.cache))
        self.assertEqual(result.returncode, 4)
        self.assertEqual(result.stdout, "")
        self.assertIn("HTTP 502", result.stderr)

    def test_fetch_refuses_links_and_paths_outside_the_cache(self):
        for members in ((("nix-cache-info", "file"), ("nar/link", "link")),
                        (("nix-cache-info", "file"), ("nar/a b", "file"))):
            with self.subTest(members=members):
                shutil.rmtree(self.base / "source", ignore_errors=True)
                self.stub_gh(assets=(self.ASSET,), archive=self.archive(*members))
                result = self.run_cache("fetch", "x86_64", str(self.cache))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertFalse(self.cache.exists())
        traversal = self.base / "traversal.tar"
        subprocess.run(["tar", "-cf", str(traversal), "-C", str(self.base), "--transform", "s,^,../,",
                        "nix.log"], check=True)
        self.stub_gh(assets=(self.ASSET,), archive=traversal)
        result = self.run_cache("fetch", "x86_64", str(self.cache))
        self.assertEqual(result.returncode, 1)
        self.assertIn("unexpected kernel cache archive entry: ../nix.log", result.stderr)
        self.assertFalse(self.cache.exists())

    def test_publish_uploads_the_cache_and_drops_this_architectures_older_assets(self):
        self.cache.mkdir()
        (self.cache / "nix-cache-info").write_text("StoreDir: /nix/store\n")
        self.stub_gh(assets=(self.OLD_ASSET, self.OTHER_ARCH, self.ASSET))
        result = self.run_cache("publish", "x86_64", str(self.cache))
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.gh_calls()
        self.assertEqual(calls[0], "gh release view qemu-kernel-cache")
        self.assertRegex(calls[1], rf"^gh release upload qemu-kernel-cache /.*/{re.escape(self.ASSET)}$")
        self.assertEqual(calls[2:], [
            "upload-listing ./ ./nix-cache-info ",
            "gh release view qemu-kernel-cache --json assets --jq .assets[].name",
            f"gh release delete-asset qemu-kernel-cache {self.OLD_ASSET} --yes",
        ])

    def test_publish_creates_the_release_or_finds_the_one_another_job_created(self):
        self.cache.mkdir()
        (self.cache / "nix-cache-info").write_text("StoreDir: /nix/store\n")
        for create_status, status in ((0, 0), (1, 1)):
            with self.subTest(create_status=create_status):
                self.log.unlink(missing_ok=True)
                self.stub_gh(release="missing", create_status=create_status)
                result = self.run_cache("publish", "x86_64", str(self.cache))
                self.assertEqual(result.returncode, status, result.stderr)
                calls = self.gh_calls()
                self.assertEqual(calls[0], "gh release view qemu-kernel-cache")
                self.assertTrue(calls[1].startswith("gh release create qemu-kernel-cache --prerelease --latest=false"))
                if create_status:
                    # The release still does not exist, so nothing is uploaded.
                    self.assertEqual(calls[2:], ["gh release view qemu-kernel-cache"])
                else:
                    self.assertTrue(calls[2].startswith("gh release upload qemu-kernel-cache "))

    def selftest(self, **stub) -> subprocess.CompletedProcess:
        self.stub_nix(**{"verify_status": 1, "import_status": 1, **stub})
        return self.run_cache("selftest", str(self.cache))

    def test_selftest_signs_verifies_and_is_refused_on_import(self):
        result = self.selftest()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kernel cache self-test passed", result.stdout)
        calls = self.calls()
        built = next(call for call in calls if call.startswith("build"))
        self.assertRegex(built, r'^build --impure --no-link --print-out-paths --expr derivation \{ '
                                r'+name = "qemu-kernel-cache-selftest-[0-9]+"; +system = builtins\.currentSystem; '
                                r'+builder = "/bin/sh"; +args = \[ "-c" "echo [0-9]+ > \$out" \]; +\}$')
        key_path = self.key_path()
        verify = f"store verify --recursive --store file://{self.cache} --sigs-needed 1 {self.SAMPLE}"
        self.assertEqual([call for call in calls if call != built], [
            "config show trusted-public-keys",
            "key generate-secret --key-name qemu-kernel-cache-selftest",
            "key convert-secret-to-public",
            f"stdin {self.THROWAWAY_SECRET}",
            f"path-info --json --json-format 1 {self.SAMPLE}",
            f"copy --to file://{self.cache}?compression=zstd&secret-key={key_path} {self.SAMPLE}",
            "key-mode 600",
            f"key-content {self.THROWAWAY_SECRET}",
            verify,
            f"NIX_CONFIG=trusted-public-keys = {self.THROWAWAY_PUBLIC}",
            verify,
            f"store delete {self.SAMPLE}",
            f"copy --from file://{self.cache} {self.SAMPLE}",
        ])
        self.assertFalse(key_path.exists())

    def test_selftest_requires_the_committed_signing_key_to_be_trusted(self):
        for trusted in (self.NIXOS, f"{self.NIXOS} piglor-qemu-kernel-1:short=",
                        f"{self.NIXOS} x{self.PUBLIC}"):
            with self.subTest(trusted=trusted):
                result = self.selftest(trusted=trusted)
                self.assertEqual(result.returncode, 1)
                self.assertIn("trusted-public-keys has no piglor-qemu-kernel-1 key", result.stderr)
                self.assertFalse(any(call.startswith("key") for call in self.calls()))

    def test_selftest_fails_when_the_throwaway_key_is_trusted(self):
        result = self.selftest(trusted=f"{self.NIXOS} {self.PUBLIC} {self.THROWAWAY_PUBLIC}")
        self.assertEqual(result.returncode, 1)
        self.assertIn("unexpectedly trusted", result.stderr)

    def test_selftest_splits_the_trust_list_on_any_whitespace(self):
        trusted = f"{self.NIXOS}\\t{self.PUBLIC}\\n{self.THROWAWAY_PUBLIC}"
        self.stub_nix(verify_status=1, import_status=1)
        stub = (self.bin / "nix").read_text()
        old = '"config show") printf \'%s\\n\' '
        self.assertIn(old, stub)
        (self.bin / "nix").write_text(stub.replace(
            old + f"'{self.NIXOS} {self.PUBLIC}'", f"\"config show\") printf '{trusted}\\n'", 1))
        result = self.run_cache("selftest", str(self.cache))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("unexpectedly trusted", result.stderr)

    def test_selftest_fails_when_an_untrusted_signature_verifies(self):
        result = self.selftest(verify_status=0)
        self.assertEqual(result.returncode, 1)
        self.assertIn("passed verification", result.stderr)

    def test_selftest_refuses_a_content_addressed_sample(self):
        result = self.selftest(sample_ca='"fixed:r:sha256:0123"')
        self.assertEqual(result.returncode, 1)
        self.assertIn("is content-addressed", result.stderr)
        self.assertFalse(any(call.startswith("copy") for call in self.calls()))

    def test_selftest_stops_when_path_info_fails(self):
        self.stub_nix(verify_status=1, import_status=1)
        stub = (self.bin / "nix").read_text().replace('"path-info --json")', '"path-info --json") exit 4 ;;\n"unused")')
        (self.bin / "nix").write_text(stub)
        result = self.run_cache("selftest", str(self.cache))
        self.assertEqual(result.returncode, 4)
        self.assertNotIn("content-addressed", result.stderr)
        self.assertFalse(any(call.startswith("copy") for call in self.calls()))

    def selftest_with(self, case: str, action: str) -> subprocess.CompletedProcess:
        self.stub_nix(verify_status=1, import_status=1)
        stub = (self.bin / "nix").read_text()
        self.assertIn(f"{case})", stub)
        (self.bin / "nix").write_text(stub.replace(f"{case})", f'{case}) {action} ;;\n"unused")', 1))
        return self.run_cache("selftest", str(self.cache))

    def test_selftest_stops_when_the_trust_list_cannot_be_read(self):
        result = self.selftest_with('"config show"', "exit 5")
        self.assertEqual(result.returncode, 5)
        self.assertFalse(any(call.startswith(("key", "copy")) for call in self.calls()))

    def test_selftest_refuses_empty_path_info_output(self):
        result = self.selftest_with('"path-info --json"', ":")
        self.assertEqual(result.returncode, 1)
        self.assertIn("is content-addressed", result.stderr)
        self.assertFalse(any(call.startswith("copy") for call in self.calls()))

    def test_selftest_fails_when_verification_fails_for_another_reason(self):
        result = self.selftest(verify_message="error: opening directory: No such file")
        self.assertEqual(result.returncode, 1)
        self.assertIn("other than trust", result.stderr)
        self.assertFalse(any(call.startswith("store delete") for call in self.calls()))

    def test_selftest_fails_when_the_daemon_imports_an_untrusted_path(self):
        result = self.selftest(import_status=0)
        self.assertEqual(result.returncode, 1)
        self.assertIn("the daemon imported", result.stderr)

    def test_selftest_fails_when_the_import_fails_for_another_reason(self):
        result = self.selftest(import_message="error: unsupported URI")
        self.assertEqual(result.returncode, 1)
        self.assertIn("other than its signature", result.stderr)
        self.assertIn("error: unsupported URI", result.stderr)


if __name__ == "__main__":
    unittest.main()
