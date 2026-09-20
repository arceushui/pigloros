#!/usr/bin/env python3
"""Throwaway ADR-084 release-barrier driver; never production code."""

from __future__ import annotations

import argparse
import errno
import json
import os
import pathlib
import select
import socket
import subprocess
import sys
import time
import uuid


def run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=check, text=True, capture_output=True)


def wait_for_file(path: pathlib.Path, process: subprocess.Popen[bytes]) -> str:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if path.exists():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
        if process.poll() is not None:
            stderr = process.stderr.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"podman exited before cidfile: {process.returncode}: {stderr}")
        time.sleep(0.05)
    raise TimeoutError("cidfile was not published")


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        return f"UNAVAILABLE: {error}\n"


def process_snapshot(pid: int) -> dict[str, object]:
    proc = pathlib.Path("/proc") / str(pid)
    descriptors: list[dict[str, object]] = []
    descriptor_access_error: str | None = None
    try:
        descriptor_entries = sorted(
            (proc / "fd").iterdir(), key=lambda item: int(item.name)
        )
    except OSError as error:
        descriptor_entries = []
        descriptor_access_error = f"UNAVAILABLE: {error}"
    for entry in descriptor_entries:
        try:
            target = os.readlink(entry)
        except OSError as error:
            target = f"UNAVAILABLE: {error}"
        descriptors.append({"fd": int(entry.name), "target": target})
    namespaces: dict[str, str] = {}
    namespace_access_error: str | None = None
    try:
        namespace_entries = sorted((proc / "ns").iterdir())
    except OSError as error:
        namespace_entries = []
        namespace_access_error = f"UNAVAILABLE: {error}"
    for entry in namespace_entries:
        try:
            namespaces[entry.name] = os.readlink(entry)
        except OSError as error:
            namespaces[entry.name] = f"UNAVAILABLE: {error}"
    cgroup_text = read_text(proc / "cgroup")
    unified = next(
        (line.split("::", 1)[1] for line in cgroup_text.splitlines() if "::" in line),
        "",
    )
    cgroup_root = pathlib.Path("/sys/fs/cgroup") / unified.lstrip("/")
    cgroup_values = {
        name: read_text(cgroup_root / name).strip()
        for name in (
            "cgroup.controllers",
            "cgroup.events",
            "cgroup.procs",
            "cpu.max",
            "cpu.stat",
            "memory.max",
            "memory.swap.max",
            "pids.max",
            "pids.events",
        )
    }
    cgroup_values["cgroup.kill_exists"] = str((cgroup_root / "cgroup.kill").exists())
    return {
        "pid": pid,
        "status": read_text(proc / "status"),
        "cgroup": cgroup_text,
        "cgroup_path": str(cgroup_root),
        "cgroup_values": cgroup_values,
        "descriptor_access_error": descriptor_access_error,
        "descriptors": descriptors,
        "mountinfo": read_text(proc / "mountinfo"),
        "namespace_access_error": namespace_access_error,
        "namespaces": namespaces,
    }


def assert_launcher_snapshot(snapshot: dict[str, object]) -> None:
    status = str(snapshot["status"])
    required_status = ("NoNewPrivs:\t1", "Seccomp:\t2", "CapEff:\t0000000000000000")
    for expected in required_status:
        if expected not in status:
            raise AssertionError(f"missing launcher status evidence: {expected}")
    descriptor_numbers = [entry["fd"] for entry in snapshot["descriptors"]]  # type: ignore[index]
    if descriptor_numbers and descriptor_numbers != [0, 1, 2, 3]:
        raise AssertionError(f"launcher descriptor set is not 0..3: {descriptor_numbers}")
    if not descriptor_numbers and "Permission denied" not in str(snapshot["descriptor_access_error"]):
        raise AssertionError("launcher descriptor evidence was unavailable for an unknown reason")
    values = snapshot["cgroup_values"]  # type: ignore[assignment]
    if values["memory.max"] != "67108864":  # type: ignore[index]
        raise AssertionError(f"memory.max not enforced: {values['memory.max']}")  # type: ignore[index]
    if values["memory.swap.max"] != "0":  # type: ignore[index]
        raise AssertionError(f"memory.swap.max not enforced: {values['memory.swap.max']}")  # type: ignore[index]
    if values["pids.max"] != "16":  # type: ignore[index]
        raise AssertionError(f"pids.max not enforced: {values['pids.max']}")  # type: ignore[index]
    if not str(values["cpu.max"]).startswith("50000 100000"):  # type: ignore[index]
        raise AssertionError(f"cpu.max not enforced: {values['cpu.max']}")  # type: ignore[index]
    root_mounts = [
        line for line in str(snapshot["mountinfo"]).splitlines() if " / / " in line
    ]
    if len(root_mounts) != 1 or " ro," not in root_mounts[0]:
        raise AssertionError(f"container root is not uniquely read-only: {root_mounts}")


def launch(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    artifact_dir: pathlib.Path,
    input_bytes: bytes,
    scenario: str,
) -> tuple[subprocess.Popen[bytes], socket.socket, str, pathlib.Path]:
    parent_control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    if parent_control.fileno() == 3:
        relocated_parent = socket.socket(fileno=os.dup(parent_control.fileno()))
        parent_control.close()
        parent_control = relocated_parent
    child_fd = child_control.fileno()
    child_control.set_inheritable(True)
    cidfile = artifact_dir / f"{scenario}.cid"
    name = f"pigloros-adr084-{scenario}-{uuid.uuid4().hex[:12]}"
    command = [
        "/usr/bin/podman",
        "run",
        "--runtime=/usr/bin/crun",
        "--pull=never",
        f"--name={name}",
        f"--cidfile={cidfile}",
        "--preserve-fds=1",
        "--network=none",
        "--no-hosts",
        "--hostname=pigloros-adapter",
        "--read-only",
        "--read-only-tmpfs=false",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={seccomp}",
        f"--annotation=run.oci.seccomp_bpf_data={seccomp_bpf_base64}",
        "--stop-signal=15",
        "--memory=64m",
        "--memory-swap=64m",
        "--pids-limit=16",
        "--cpus=0.5",
        "--ulimit=nofile=64:64",
        "--ulimit=fsize=1048576:1048576",
        "--user=65532:65532",
        "--label=io.pigloros.prototype=adr084",
        f"--label=io.pigloros.scenario={scenario}",
        "--rm=false",
        "-i",
        image,
    ]

    saved_fd3: int | None = None
    if child_fd != 3:
        try:
            saved_fd3 = os.dup(3)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        os.dup2(child_fd, 3, inheritable=True)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(3,),
        )
    finally:
        if child_fd != 3:
            os.close(3)
            if saved_fd3 is not None:
                os.dup2(saved_fd3, 3)
                os.close(saved_fd3)
    child_control.close()
    container_id = wait_for_file(cidfile, process)
    ready = parent_control.recv(64)
    if ready != b"READY\n":
        return_code = process.wait(timeout=10)
        stderr = process.stderr.read().decode("utf-8", errors="replace")
        (artifact_dir / f"{scenario}.pre-ready.stderr").write_text(
            stderr, encoding="utf-8"
        )
        raise AssertionError(
            f"unexpected launcher readiness: {ready!r}; "
            f"exit={return_code}; stderr={stderr!r}"
        )
    readable, _, _ = select.select([process.stdout], [], [], 0.2)
    if readable:
        premature = process.stdout.read1(64)
        raise AssertionError(f"adapter emitted before ReleaseV1: {premature!r}")
    inspect = run("/usr/bin/podman", "inspect", container_id).stdout
    (artifact_dir / f"{scenario}.inspect.json").write_text(inspect, encoding="utf-8")
    inspected = json.loads(inspect)[0]
    annotations = inspected["Config"]["Annotations"]
    expected_annotations = {
        "io.container.manager": "libpod",
        "io.podman.annotations.seccomp": str(seccomp),
        "org.opencontainers.image.stopSignal": "15",
        "run.oci.seccomp_bpf_data": seccomp_bpf_base64,
    }
    (artifact_dir / f"{scenario}.runtime-annotations.json").write_text(
        json.dumps(annotations, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if annotations != expected_annotations:
        raise AssertionError(
            f"effective runtime annotations differ: {annotations!r}"
        )
    pid = int(inspected["State"]["Pid"])
    snapshot = process_snapshot(pid)
    assert_launcher_snapshot(snapshot)
    (artifact_dir / f"{scenario}.launcher.json").write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    parent_control.sendall(b"RELEASE\n")
    assert process.stdin is not None
    process.stdin.write(input_bytes)
    process.stdin.flush()
    return process, parent_control, container_id, cidfile


def normal_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    artifact_dir: pathlib.Path,
) -> None:
    process, control, container_id, _ = launch(
        image, seccomp, seccomp_bpf_base64, artifact_dir, b"hello\n", "normal"
    )
    assert process.stdin is not None
    process.stdin.close()
    assert process.stdout is not None
    assert process.stderr is not None
    output = process.stdout.read()
    errors = process.stderr.read()
    return_code = process.wait(timeout=20)
    control.close()
    (artifact_dir / "normal.stdout").write_bytes(output)
    (artifact_dir / "normal.stderr").write_bytes(errors)
    if return_code != 0 or output != b"EAO1:hello\n":
        raise AssertionError(
            f"normal adapter failed: code={return_code} output={output!r} stderr={errors!r}"
        )
    run("/usr/bin/podman", "rm", container_id)


def cancellation_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    artifact_dir: pathlib.Path,
) -> None:
    process, control, container_id, _ = launch(
        image, seccomp, seccomp_bpf_base64, artifact_dir, b"HOLD\n", "cancel"
    )
    assert process.stdout is not None
    readable, _, _ = select.select([process.stdout], [], [], 10)
    if not readable:
        raise TimeoutError("holding adapter did not report its descendant")
    holding = process.stdout.readline()
    if not holding.startswith(b"HOLDING child="):
        raise AssertionError(f"unexpected holding output: {holding!r}")
    (artifact_dir / "cancel.stdout").write_bytes(holding)
    before = json.loads((artifact_dir / "cancel.launcher.json").read_text(encoding="utf-8"))
    cgroup_path = pathlib.Path(before["cgroup_path"])
    run("/usr/bin/podman", "kill", "--signal=KILL", container_id)
    return_code = process.wait(timeout=20)
    control.close()
    deadline = time.monotonic() + 10
    cgroup_procs = cgroup_path / "cgroup.procs"
    while time.monotonic() < deadline and cgroup_procs.exists() and read_text(cgroup_procs).strip():
        time.sleep(0.05)
    residual = read_text(cgroup_procs).strip() if cgroup_procs.exists() else ""
    (artifact_dir / "cancel.cleanup.txt").write_text(
        f"return_code={return_code}\nresidual_cgroup_procs={residual}\n",
        encoding="utf-8",
    )
    if residual:
        raise AssertionError(f"descendants survived cancellation: {residual}")
    run("/usr/bin/podman", "rm", "--force", container_id)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--seccomp", required=True, type=pathlib.Path)
    parser.add_argument("--seccomp-bpf-base64", required=True, type=pathlib.Path)
    parser.add_argument("--artifact-dir", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    arguments.artifact_dir.mkdir(parents=True, exist_ok=True)
    seccomp_bpf_base64 = arguments.seccomp_bpf_base64.read_text(
        encoding="ascii"
    )
    if not seccomp_bpf_base64 or any(
        character.isspace() for character in seccomp_bpf_base64
    ):
        raise ValueError("seccomp BPF base64 is empty or contains whitespace")
    normal_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.artifact_dir,
    )
    cancellation_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.artifact_dir,
    )
    print("ADR-084 Podman release-barrier prototype passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"prototype failed: {error}", file=sys.stderr)
        subprocess.run(
            ["/usr/bin/podman", "ps", "--all", "--no-trunc"], check=False
        )
        raise
