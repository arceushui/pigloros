"""Throwaway hosted diagnostic. Never execute this monitor locally."""

import datetime
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

if os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("This diagnostic may only run on its isolated hosted worker")

WORKSPACE = Path(os.environ["GITHUB_WORKSPACE"])
TEMP = Path(os.environ["RUNNER_TEMP"])
RECORD = TEMP / "asan-consumer-capacity"
RECORD.mkdir(exist_ok=True)
REPORT = RECORD / "capacity.json"
MIN_FREE = 8 * 1024**3
MIN_INODES = 100_000
ARCHIVE_ZIP_BYTES = 5_978_046_080
CHECKOUT = "fa5b199853290bc21187b48efce96ad030a0c86e"


def load():
    if REPORT.exists():
        return json.loads(REPORT.read_text())
    return {
        "case": "remainder-1", "checkout": CHECKOUT,
        "archive_run": 41944696339, "archive_artifact": 13379068961,
        "guard_bytes": MIN_FREE, "guard_inodes": MIN_INODES,
        "started_monotonic": time.monotonic(),
        "phases": [], "samples": [], "commands": [],
    }


def save(report):
    temporary = REPORT.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(REPORT)


def capacity():
    volumes = []
    for path in (Path("/"), WORKSPACE, TEMP, Path("/mnt")):
        try:
            info = path.stat()
            fs = os.statvfs(path)
        except OSError as error:
            volumes.append({"path": str(path), "error_type": type(error).__name__})
            continue
        volumes.append({
            "path": str(path), "device": info.st_dev,
            "total_bytes": fs.f_blocks * fs.f_frsize,
            "available_bytes": fs.f_bavail * fs.f_frsize,
            "total_inodes": fs.f_files, "available_inodes": fs.f_favail,
        })
    archive = TEMP / "asan-archive/asan-tests.tar.zst"
    return {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "volumes": volumes,
        "archive_bytes": archive.stat().st_size if archive.exists() else 0,
    }


def footprint():
    directories = []
    for path in (WORKSPACE / "target", TEMP, Path("/tmp"),
                 Path.home() / ".cargo", Path.home() / ".rustup"):
        if not path.exists():
            directories.append({"path": str(path), "absent": True})
            continue
        try:
            result = subprocess.run(
                ["du", "-sx", "-B1", "--", str(path)],
                text=True, capture_output=True, timeout=30, check=False,
            )
        except subprocess.TimeoutExpired:
            directories.append({"path": str(path), "measurement": "timeout"})
            continue
        first = result.stdout.split(None, 1)
        directories.append({
            "path": str(path), "allocated_bytes": int(first[0]) if first else None,
            "measurement_returncode": result.returncode,
        })
    totals = {}
    largest = []
    seen = set()
    for directory, _, names in os.walk(WORKSPACE / "target", followlinks=False):
        for name in names:
            path = Path(directory) / name
            try:
                info = path.lstat()
            except OSError:
                continue
            identity = (info.st_dev, info.st_ino)
            if not stat.S_ISREG(info.st_mode) or identity in seen:
                continue
            seen.add(identity)
            row = totals.setdefault(path.suffix or "<none>", {
                "files": 0, "logical_bytes": 0, "allocated_bytes": 0,
            })
            row["files"] += 1
            row["logical_bytes"] += info.st_size
            row["allocated_bytes"] += info.st_blocks * 512
            largest.append({"path": str(path.relative_to(WORKSPACE)),
                            "logical_bytes": info.st_size,
                            "allocated_bytes": info.st_blocks * 512})
    largest.sort(key=lambda row: row["allocated_bytes"], reverse=True)
    return {"directories": directories, "target_by_suffix": totals,
            "largest_target_files": largest[:30]}


def low_capacity(sample):
    relevant = [row for row in sample["volumes"] if row["path"] != "/mnt"]
    return any("available_bytes" not in row or row["available_bytes"] < MIN_FREE or
               row["available_inodes"] < MIN_INODES for row in relevant)


def phase(report, name):
    report["phases"].append({"phase": name, **capacity(), **footprint()})
    save(report)
    print("[DEBUG-asan-consumer-860] " + json.dumps({"phase": name}), flush=True)


report = load()
if sys.argv[1] == "snapshot":
    phase(report, sys.argv[2])
    sample = capacity()
    if sys.argv[2] == "before-download" and any(
        row.get("available_bytes", 0) < MIN_FREE + 2 * ARCHIVE_ZIP_BYTES
        for row in sample["volumes"] if row["path"] != "/mnt"
    ):
        report["download_guard_sample"] = sample
        save(report)
        raise SystemExit(97)
    raise SystemExit(0)

assert sys.argv[1] == "run"
argv = sys.argv[2:]
assert argv[:4] == ["cargo", "+nightly-2026-07-01", "nextest", "run"]
number = len(report["commands"]) + 1
command = {"invocation": number, "argv": argv}
report["commands"].append(command)
phase(report, f"before-invocation-{number}")
if low_capacity(capacity()):
    command["outcome"] = "preflight-capacity-guard"
    phase(report, f"guard-before-invocation-{number}")
    raise SystemExit(97)

child = subprocess.Popen(argv, cwd=WORKSPACE, start_new_session=True)
command["pid"] = child.pid
save(report)
last_saved = -100.0
guarded = False
timed_out = False


def stop_child():
    if child.poll() is None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=15)


try:
    while child.poll() is None:
        sample = capacity()
        elapsed = time.monotonic() - report["started_monotonic"]
        guarded = low_capacity(sample)
        timed_out = elapsed > 55 * 60
        if guarded or timed_out:
            command["guard_sample"] = sample
            command["outcome"] = "capacity-guard" if guarded else "time-guard"
            save(report)
            # Stop only this diagnostic's session before worker log loss.
            stop_child()
            break
        if elapsed - last_saved >= 10:
            report["samples"].append({"invocation": number, **sample})
            report["samples"] = report["samples"][-400:]
            save(report)
            last_saved = elapsed
        time.sleep(0.5)
finally:
    stop_child()

command["returncode"] = child.wait(timeout=15)
command.setdefault("outcome", "command-finished")
phase(report, f"after-invocation-{number}")
raise SystemExit(97 if guarded else 124 if timed_out else command["returncode"])
