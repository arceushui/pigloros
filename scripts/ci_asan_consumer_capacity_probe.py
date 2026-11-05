"""Hosted read-only archive inventory; never execute this diagnostic locally."""
import datetime
import heapq
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile

if (os.environ.get("GITHUB_ACTIONS") != "true" or
        os.environ.get("PROBE_RUNNER_ENVIRONMENT") != "github-hosted" or
        os.environ.get("PROBE_RUNNER_OS") != "Linux" or os.getuid() == 0):
    raise SystemExit("This diagnostic requires its isolated non-root hosted Linux worker")

WORKSPACE = Path(os.environ["GITHUB_WORKSPACE"])
TEMP = Path(os.environ["RUNNER_TEMP"])
RECORD = TEMP / "asan-consumer-capacity"
RECORD.mkdir(exist_ok=True)
REPORT = RECORD / "capacity.json"
MIN_FREE = 8 * 1024**3
ARCHIVE_ZIP_BYTES = 5_978_046_080
MAX_HEADERS = 10_000
MAX_LOGICAL_BYTES = 512 * 1024**3
MAX_REPORT_BYTES = 1024**2


def capacity():
    volumes = []
    for path in (Path("/"), WORKSPACE, TEMP, Path("/mnt")):
        try:
            fs = os.statvfs(path)
            volumes.append({
                "path": str(path), "device": path.stat().st_dev,
                "total_bytes": fs.f_blocks * fs.f_frsize,
                "available_bytes": fs.f_bavail * fs.f_frsize,
                "total_inodes": fs.f_files, "available_inodes": fs.f_favail,
            })
        except OSError as error:
            volumes.append({"path": str(path), "error_type": type(error).__name__})
    return {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "volumes": volumes}


def save(report):
    data = (json.dumps(report, indent=2) + "\n").encode()
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Numeric report exceeds its fixed byte bound")
    temporary = REPORT.with_suffix(".tmp")
    temporary.write_bytes(data)
    temporary.replace(REPORT)


def snapshot(report, name):
    if len(report["phases"]) >= 12:
        raise ValueError("Phase bound exceeded")
    report["phases"].append({"phase": name, **capacity()})
    save(report)
    print("[DEBUG-asan-consumer-860] " + json.dumps({"phase": name}), flush=True)


report = json.loads(REPORT.read_text()) if REPORT.exists() else {
    "case": "archive-inventory-only", "checkout": "fa5b199853290bc21187b48efce96ad030a0c86e",
    "archive_run": 41944696339, "archive_artifact": 13379068961,
    "archive_zip_bytes": ARCHIVE_ZIP_BYTES, "phases": [],
    "limits": {"headers": MAX_HEADERS, "logical_bytes": MAX_LOGICAL_BYTES,
               "report_bytes": MAX_REPORT_BYTES, "largest_members": 30,
               "member_name_bytes": 512, "inventory_seconds": 900},
    "qualification": "Header inventory only; no extraction or workspace test execution. Logical header sizes do not prove allocated extraction size or runtime capacity.",
}
if sys.argv[1] == "snapshot":
    name = sys.argv[2]
    snapshot(report, name)
    required = MIN_FREE + (2 * ARCHIVE_ZIP_BYTES if name == "before-download" else 0)
    if name != "before-setup" and any(row.get("available_bytes", 0) < required or
           row.get("available_inodes", 0) < 100_000
           for row in report["phases"][-1]["volumes"] if row["path"] != "/mnt"):
        report["outcome"] = "preflight-capacity-guard"
        save(report)
        raise SystemExit(97)
    raise SystemExit(0)

assert sys.argv[1] == "inventory"
archive = TEMP / "asan-archive/asan-tests.tar.zst"
assert archive.is_file() and not archive.is_symlink()
report["archive_file_bytes"] = archive.stat().st_size
report["inventory"] = {
    "headers": 0, "regular_files": 0, "hardlinks": 0, "symlinks": 0,
    "directories": 0, "other": 0, "sparse_files": 0,
    "regular_logical_bytes": 0, "regular_rounded_4096_bytes": 0,
}
snapshot(report, "before-inventory")
largest = []
child = subprocess.Popen(
    ["zstd", "--decompress", "--stdout", "--quiet", "--", str(archive)],
    stdout=subprocess.PIPE, start_new_session=True,
)


def deadline(_signum, _frame):
    raise TimeoutError("Archive inventory reached its 900-second bound")


try:
    report["decoder_pid"] = child.pid
    save(report)
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    assert child.stdout is not None
    with tarfile.open(fileobj=child.stdout, mode="r|") as stream:
        for member in stream:
            row = report["inventory"]
            row["headers"] += 1
            if row["headers"] > MAX_HEADERS or len(member.name.encode()) > 4096:
                raise ValueError("Archive header/name bound exceeded")
            if member.isfile():
                row["regular_files"] += 1
                row["regular_logical_bytes"] += member.size
                row["regular_rounded_4096_bytes"] += ((member.size + 4095) // 4096) * 4096
                if row["regular_logical_bytes"] > MAX_LOGICAL_BYTES:
                    raise ValueError("Archive logical-size bound exceeded")
                if member.sparse is not None:
                    row["sparse_files"] += 1
                item = (member.size, row["headers"], member.name.encode()[:512].decode("utf-8", "ignore"))
                heapq.heappush(largest, item)
                if len(largest) > 30:
                    heapq.heappop(largest)
            elif member.islnk():
                row["hardlinks"] += 1
            elif member.issym():
                row["symlinks"] += 1
            elif member.isdir():
                row["directories"] += 1
            else:
                row["other"] += 1
    # Drain tar padding/trailing decoded data without retaining it.
    while child.stdout.read(1024 * 1024):
        pass
    report["decoder_returncode"] = child.wait(timeout=15)
    if report["decoder_returncode"] != 0:
        raise ValueError("Archive decoder failed")
    report["outcome"] = "inventory-complete"
except Exception as error:
    report["outcome"] = "inventory-error"
    report["error_type"] = type(error).__name__
    raise
finally:
    signal.alarm(0)
    # zstd is the only launched program; no test process groups exist.
    if child.poll() is None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=15)
    if child.stdout is not None:
        child.stdout.close()
    report["largest_regular_members"] = [
        {"logical_bytes": size, "name": name} for size, _, name in sorted(largest, reverse=True)
    ]
    snapshot(report, "after-inventory")
print(json.dumps({"outcome": report["outcome"], "inventory": report["inventory"]}))
