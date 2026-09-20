#!/usr/bin/env python3
"""Throwaway ADR-084 release-barrier driver; never production code."""

from __future__ import annotations

import argparse
import base64
import binascii
import errno
import hashlib
import json
import os
import pathlib
import select
import signal
import socket
import subprocess
import struct
import sys
import time
import uuid


def run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=check, text=True, capture_output=True)


def wait_for_container(name: str, process: subprocess.Popen[bytes]) -> str:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        inspected = run("/usr/bin/podman", "inspect", name, check=False)
        if inspected.returncode == 0:
            value = json.loads(inspected.stdout)
            if len(value) == 1 and value[0].get("Id"):
                return str(value[0]["Id"])
        if process.poll() is not None:
            stderr = process.stderr.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"podman exited before identity acquisition: {process.returncode}: {stderr}"
            )
        time.sleep(0.05)
    raise TimeoutError("container identity was not acquired through provider-owned name")


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


def assert_launcher_snapshot(
    snapshot: dict[str, object], expected_filter_count: int = 1
) -> None:
    status = str(snapshot["status"])
    required_status = (
        "NoNewPrivs:\t1",
        "Seccomp:\t2",
        f"Seccomp_filters:\t{expected_filter_count}",
        "CapEff:\t0000000000000000",
    )
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


def expected_runtime_annotations(
    seccomp: pathlib.Path, seccomp_bpf_base64: str
) -> dict[str, str]:
    return {
        "io.container.manager": "libpod",
        "io.podman.annotations.seccomp": str(seccomp),
        "org.opencontainers.image.stopSignal": "15",
        "run.oci.seccomp_bpf_data": seccomp_bpf_base64,
    }


def validate_runtime_annotations(
    annotations: object, seccomp: pathlib.Path, seccomp_bpf_base64: str
) -> None:
    expected = expected_runtime_annotations(seccomp, seccomp_bpf_base64)
    if annotations != expected:
        raise ValueError(f"effective runtime annotations differ: {annotations!r}")


def validate_bpf_annotation(value: str, expected_bpf: bytes) -> None:
    if not value or any(character.isspace() for character in value):
        raise ValueError("seccomp BPF base64 is empty or contains whitespace")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("seccomp BPF base64 is malformed") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("seccomp BPF base64 is not canonical padded RFC 4648")
    if decoded != expected_bpf:
        raise ValueError("seccomp BPF annotation differs from exported bytes")


def validate_launch_arguments(
    annotations: list[str],
    seccomp_profiles: list[str],
    stop_signals: list[str],
    expected_annotation: str,
    expected_profile: str,
) -> None:
    if annotations != [expected_annotation]:
        raise ValueError("launch requires exactly one exact BPF annotation argument")
    if seccomp_profiles != [expected_profile]:
        raise ValueError("launch requires exactly one descriptor-resolved seccomp profile")
    if stop_signals != ["15"]:
        raise ValueError("launch requires exactly one decimal stop signal 15")


def annotation_mutation_report(
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
) -> dict[str, object]:
    expected_bpf = seccomp_bpf.read_bytes()
    expected = expected_runtime_annotations(seccomp, seccomp_bpf_base64)
    rejected: list[str] = []

    def rejects(action, label: str) -> None:
        try:
            action()
        except ValueError:
            rejected.append(label)
            return
        raise AssertionError(f"annotation mutation was accepted: {label}")

    for key in expected:
        missing = {name: value for name, value in expected.items() if name != key}
        rejects(
            lambda candidate=missing: validate_runtime_annotations(
                candidate, seccomp, seccomp_bpf_base64
            ),
            f"missing effective map member: {key}",
        )
        wrong = {**expected, key: expected[key] + ".mutated"}
        rejects(
            lambda candidate=wrong: validate_runtime_annotations(
                candidate, seccomp, seccomp_bpf_base64
            ),
            f"wrong effective map value: {key}",
        )
    for label, key in (
        ("configured-default injection", "io.containers.default.annotation"),
        ("caller annotation injection", "org.pigloros.caller"),
        ("image annotation forwarding", "org.opencontainers.image.title"),
        ("arbitrary extra annotation", "fixture.extra"),
        ("security-affecting run.oci annotation", "run.oci.hooks"),
        ("systemd annotation injection", "org.systemd.property.DeviceAllow"),
    ):
        injected = {**expected, key: "mutated"}
        rejects(
            lambda candidate=injected: validate_runtime_annotations(
                candidate, seccomp, seccomp_bpf_base64
            ),
            label,
        )

    annotation_argument = f"run.oci.seccomp_bpf_data={seccomp_bpf_base64}"
    profile_argument = f"seccomp={seccomp}"
    launch_cases = (
        ("missing BPF annotation argument", [], [profile_argument], ["15"]),
        (
            "duplicate BPF annotation argument",
            [annotation_argument, annotation_argument],
            [profile_argument],
            ["15"],
        ),
        ("missing seccomp profile argument", [annotation_argument], [], ["15"]),
        (
            "duplicate seccomp profile argument",
            [annotation_argument],
            [profile_argument, profile_argument],
            ["15"],
        ),
        ("missing stop signal argument", [annotation_argument], [profile_argument], []),
        (
            "duplicate stop signal argument",
            [annotation_argument],
            [profile_argument],
            ["15", "15"],
        ),
        ("wrong stop signal argument", [annotation_argument], [profile_argument], ["9"]),
    )
    for label, annotations, profiles, stop_signals in launch_cases:
        rejects(
            lambda a=annotations, p=profiles, s=stop_signals: validate_launch_arguments(
                a, p, s, annotation_argument, profile_argument
            ),
            label,
        )

    changed_first = (
        ("A" if seccomp_bpf_base64[0] != "A" else "B")
        + seccomp_bpf_base64[1:]
    )
    bpf_cases = (
        ("empty BPF base64", ""),
        ("BPF base64 whitespace", seccomp_bpf_base64 + "\n"),
        ("BPF base64 invalid alphabet", "*" + seccomp_bpf_base64[1:]),
        ("BPF base64 truncation", seccomp_bpf_base64[:-1]),
        ("BPF base64 byte mutation", changed_first),
    )
    for label, candidate in bpf_cases:
        rejects(
            lambda value=candidate: validate_bpf_annotation(value, expected_bpf),
            label,
        )
    if len(rejected) != 26:
        raise AssertionError(f"annotation mutation matrix is incomplete: {len(rejected)}")
    return {"rejected": rejected, "rejected_count": len(rejected), "verdict": "passed"}


def launch(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    input_bytes: bytes,
    scenario: str,
    prefilter: pathlib.Path | None = None,
    expected_filter_count: int = 1,
    release: bool = True,
) -> tuple[subprocess.Popen[bytes], socket.socket, str]:
    parent_control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    if parent_control.fileno() == 3:
        relocated_parent = socket.socket(fileno=os.dup(parent_control.fileno()))
        parent_control.close()
        parent_control = relocated_parent
    child_fd = child_control.fileno()
    child_control.set_inheritable(True)
    name = f"pigloros-adr084-{scenario}-{uuid.uuid4().hex[:12]}"
    annotation_argument = f"run.oci.seccomp_bpf_data={seccomp_bpf_base64}"
    profile_argument = f"seccomp={seccomp}"
    validate_launch_arguments(
        [annotation_argument],
        [profile_argument],
        ["15"],
        annotation_argument,
        profile_argument,
    )
    podman_command = [
        "/usr/bin/podman",
        "run",
        "--runtime=/usr/bin/crun",
        "--pull=never",
        f"--name={name}",
        "--preserve-fds=1",
        "--network=none",
        "--no-hosts",
        "--hostname=pigloros-adapter",
        "--read-only",
        "--read-only-tmpfs=false",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        f"--security-opt={profile_argument}",
        f"--annotation={annotation_argument}",
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
    installed_bpf = artifact_dir / f"{scenario}.installed-seccomp.bpf"
    install_report = artifact_dir / f"{scenario}.seccomp-install.json"
    traced_command = (
        [str(prefilter), *podman_command] if prefilter is not None else podman_command
    )
    command = [
        str(seccomp_tracer),
        str(seccomp_bpf),
        str(installed_bpf),
        str(install_report),
        "--",
        *traced_command,
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
    container_id = wait_for_container(name, process)
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
    (artifact_dir / f"{scenario}.runtime-annotations.json").write_text(
        json.dumps(annotations, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    validate_runtime_annotations(annotations, seccomp, seccomp_bpf_base64)
    pid = int(inspected["State"]["Pid"])
    snapshot = process_snapshot(pid)
    assert_launcher_snapshot(snapshot, expected_filter_count)
    (artifact_dir / f"{scenario}.launcher.json").write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if release:
        parent_control.sendall(b"RELEASE\n")
        assert process.stdin is not None
        process.stdin.write(input_bytes)
        process.stdin.flush()
    return process, parent_control, container_id


def normal_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
) -> None:
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        b"hello\n",
        "normal",
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
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
) -> None:
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        b"HOLD\n",
        "cancel",
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


def stacked_filter_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    prefilter: pathlib.Path,
    artifact_dir: pathlib.Path,
) -> None:
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        b"",
        "stacked",
        prefilter=prefilter,
        expected_filter_count=2,
        release=False,
    )
    assert process.stdin is not None
    process.stdin.close()
    run("/usr/bin/podman", "kill", "--signal=KILL", container_id)
    return_code = process.wait(timeout=20)
    control.close()
    assert process.stdout is not None
    assert process.stderr is not None
    output = process.stdout.read()
    errors = process.stderr.read()
    (artifact_dir / "stacked.stdout").write_bytes(output)
    (artifact_dir / "stacked.stderr").write_bytes(errors)
    if output or return_code == 0:
        raise AssertionError(
            f"stacked filter was not denied before release: code={return_code} "
            f"output={output!r} stderr={errors!r}"
        )
    run("/usr/bin/podman", "rm", "--force", container_id)
    (artifact_dir / "stacked-rejection.json").write_text(
        json.dumps(
            {
                "adapter_output_bytes": 0,
                "observed_filter_count": 2,
                "release_sent": False,
                "return_code": return_code,
                "verdict": "denied before release",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def seccomp_probe_scenario(
    architecture: str,
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    artifact_dir: pathlib.Path,
    scenario: str = "probe",
) -> None:
    name = f"pigloros-adr084-{scenario}-{uuid.uuid4().hex[:12]}"
    podman_command = [
        "/usr/bin/podman",
        "run",
        "--runtime=/usr/bin/crun",
        "--pull=never",
        f"--name={name}",
        "--network=none",
        "--no-hosts",
        "--hostname=pigloros-seccomp-probe",
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
        "--entrypoint=/seccomp-probe",
        "--rm=false",
        image,
    ]
    completed = subprocess.run(
        podman_command,
        check=False,
        capture_output=True,
        timeout=20,
    )
    (artifact_dir / f"{scenario}.stdout").write_bytes(completed.stdout)
    (artifact_dir / f"{scenario}.stderr").write_bytes(completed.stderr)
    inspect_text = run("/usr/bin/podman", "inspect", name).stdout
    (artifact_dir / f"{scenario}.inspect.json").write_text(
        inspect_text, encoding="utf-8"
    )
    inspected = json.loads(inspect_text)[0]
    validate_runtime_annotations(
        inspected["Config"]["Annotations"], seccomp, seccomp_bpf_base64
    )
    exported = seccomp_bpf.read_bytes()
    installed = (artifact_dir / "normal.installed-seccomp.bpf").read_bytes()
    if installed != exported:
        raise AssertionError("normal installed BPF differs from boundary probe input")
    (artifact_dir / f"{scenario}-filter-binding.json").write_text(
        json.dumps(
            {
                "annotation_bpf_sha256": hashlib.sha256(exported).hexdigest(),
                "installed_bpf_sha256": hashlib.sha256(installed).hexdigest(),
                "installed_capture": "normal.installed-seccomp.bpf",
                "install_report": "normal.seccomp-install.json",
                "runtime_annotation_map": f"{scenario}.inspect.json",
                "verdict": "boundary helper uses the independently captured exact filter",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    try:
        observed = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"seccomp probe emitted invalid JSON: {completed.stdout!r}"
        ) from error
    expected: dict[str, object] = {
        "architecture": architecture,
        "foreign_signal": signal.SIGSYS,
    }
    if architecture == "x86_64":
        expected.update({"high_bit_signal": signal.SIGSYS, "sentinel_raw": -4094})
    if completed.returncode != 0 or observed != expected:
        raise AssertionError(
            "seccomp boundary probe failed: "
            f"code={completed.returncode} observed={observed!r} "
            f"stderr={completed.stderr!r}"
        )
    run("/usr/bin/podman", "rm", name)


def cache_probe_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    scenario: str,
) -> None:
    name = f"pigloros-adr084-{scenario}-{uuid.uuid4().hex[:12]}"
    podman_command = [
        "/usr/bin/podman",
        "run",
        "--runtime=/usr/bin/crun",
        "--pull=never",
        f"--name={name}",
        "--network=none",
        "--no-hosts",
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
        "--entrypoint=/cache-probe",
        "--rm=false",
        image,
    ]
    completed = subprocess.run(
        [
            str(seccomp_tracer),
            str(seccomp_bpf),
            str(artifact_dir / f"{scenario}.installed-seccomp.bpf"),
            str(artifact_dir / f"{scenario}.seccomp-install.json"),
            "--",
            *podman_command,
        ],
        check=False,
        capture_output=True,
        timeout=20,
    )
    (artifact_dir / f"{scenario}.stdout").write_bytes(completed.stdout)
    (artifact_dir / f"{scenario}.stderr").write_bytes(completed.stderr)
    inspect_text = run("/usr/bin/podman", "inspect", name).stdout
    (artifact_dir / f"{scenario}.inspect.json").write_text(
        inspect_text, encoding="utf-8"
    )
    inspected = json.loads(inspect_text)[0]
    validate_runtime_annotations(
        inspected["Config"]["Annotations"], seccomp, seccomp_bpf_base64
    )
    if completed.returncode != 0 or completed.stdout != b"CACHE-OK\n":
        raise AssertionError(
            "cache bypass probe failed: "
            f"code={completed.returncode} output={completed.stdout!r} "
            f"stderr={completed.stderr!r}"
        )
    run("/usr/bin/podman", "rm", name)


def crun_cache_checksum(profile: dict[str, object]) -> tuple[str, dict[str, object]]:
    package_version = "1.14.1"
    libseccomp_version = (2, 5, 5)
    installed_version = run(
        "/usr/bin/dpkg-query", "-W", "-f=${Version}", "libseccomp2"
    ).stdout
    if not installed_version.startswith("2.5.5-"):
        raise AssertionError(f"unexpected crun libseccomp package: {installed_version}")
    uname = os.uname()
    chunks = [package_version.encode("ascii")]
    chunks.extend(struct.pack("=I", value) for value in libseccomp_version)
    chunks.extend(
        value.encode("utf-8") for value in (uname.release, uname.version, uname.machine)
    )
    chunks.append(struct.pack("=I", 0))
    default_errno = profile.get("defaultErrnoRet")
    default_action = profile.get("defaultAction")
    architectures = profile.get("architectures")
    syscalls = profile.get("syscalls")
    if (
        not isinstance(default_errno, int)
        or not isinstance(default_action, str)
        or not isinstance(architectures, list)
        or not isinstance(syscalls, list)
    ):
        raise ValueError("seccomp profile cannot be checksummed")
    chunks.extend((struct.pack("=I", default_errno), default_action.encode("ascii")))
    for architecture in architectures:
        if not isinstance(architecture, str):
            raise ValueError("invalid seccomp architecture")
        chunks.append(architecture.encode("ascii"))
    for rule in syscalls:
        if not isinstance(rule, dict) or set(rule) != {"action", "names"}:
            raise ValueError("unsupported seccomp rule for checksum")
        action = rule["action"]
        names = rule["names"]
        if not isinstance(action, str) or not isinstance(names, list):
            raise ValueError("invalid seccomp rule for checksum")
        chunks.append(action.encode("ascii"))
        for name in names:
            if not isinstance(name, str):
                raise ValueError("invalid seccomp syscall name")
            chunks.append(name.encode("ascii"))
    result = subprocess.run(
        ["/usr/bin/b3sum"], input=b"".join(chunks), check=True, capture_output=True
    )
    checksum = result.stdout.decode("ascii").split()[0]
    return checksum, {
        "crun_package_version": package_version,
        "libseccomp_api_version": list(libseccomp_version),
        "libseccomp_package_version": installed_version,
        "seccomp_gen_options": 0,
        "uname": [uname.release, uname.version, uname.machine],
    }


def cache_snapshot(cache_dir: pathlib.Path) -> dict[str, object]:
    entries = []
    if cache_dir.exists():
        for entry in sorted(cache_dir.iterdir(), key=lambda item: item.name):
            if not entry.is_file() or entry.is_symlink():
                raise AssertionError(f"unexpected cache entry: {entry}")
            content = entry.read_bytes()
            metadata = entry.stat()
            entries.append(
                {
                    "name": entry.name,
                    "length": len(content),
                    "mode": metadata.st_mode & 0o7777,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "mtime_ns": metadata.st_mtime_ns,
                }
            )
    return {"directory": str(cache_dir), "entries": entries}


def cache_matrix_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
) -> None:
    profile = json.loads(seccomp.read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise ValueError("seccomp profile is not an object")
    candidate_checksum, checksum_inputs = crun_cache_checksum(profile)
    cache_dir = pathlib.Path(f"/run/user/{os.getuid()}/crun/.cache/seccomp")
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    exported = seccomp_bpf.read_bytes()
    if candidate_checksum in {"0" * 64, "1" * 64, "2" * 64}:
        raise AssertionError("candidate checksum collides with fixed cache fixture")
    states: list[tuple[str, str | None, bytes | None, int | None]] = [
        ("empty", None, None, None),
        ("valid", "0" * 64, exported, None),
        ("stale", "1" * 64, exported, 0),
        ("corrupt", "2" * 64, b"not-a-classic-bpf-program", None),
        ("adversarial", candidate_checksum, bytes(len(exported)), None),
    ]
    observations = []
    for state, filename, content, mtime_ns in states:
        for entry in cache_dir.iterdir():
            if not entry.is_file() or entry.is_symlink():
                raise AssertionError(f"refusing to clear unexpected cache entry: {entry}")
            entry.unlink()
        if filename is not None and content is not None:
            cache_file = cache_dir / filename
            cache_file.write_bytes(content)
            cache_file.chmod(0o700)
            if mtime_ns is not None:
                os.utime(cache_file, ns=(mtime_ns, mtime_ns))
        before = cache_snapshot(cache_dir)
        cache_probe_scenario(
            image,
            seccomp,
            seccomp_bpf_base64,
            seccomp_bpf,
            seccomp_tracer,
            artifact_dir,
            f"cache-{state}",
        )
        after = cache_snapshot(cache_dir)
        if after != before:
            raise AssertionError(f"crun checksum cache changed in {state} case")
        observations.append({"state": state, "before": before, "after": after})
    for entry in cache_dir.iterdir():
        entry.unlink()
    (artifact_dir / "cache-matrix.json").write_text(
        json.dumps(
            {
                "candidate_checksum": candidate_checksum,
                "checksum_inputs": checksum_inputs,
                "observations": observations,
                "verdict": "all states byte-identical before/after; tracer observed zero accesses",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--architecture", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--seccomp", required=True, type=pathlib.Path)
    parser.add_argument("--seccomp-bpf-base64", required=True, type=pathlib.Path)
    parser.add_argument("--seccomp-bpf", required=True, type=pathlib.Path)
    parser.add_argument("--seccomp-tracer", required=True, type=pathlib.Path)
    parser.add_argument("--prefilter", required=True, type=pathlib.Path)
    parser.add_argument("--artifact-dir", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    arguments.artifact_dir.mkdir(parents=True, exist_ok=True)
    provider_status = read_text(pathlib.Path("/proc/self/status"))
    if "Seccomp:\t0" not in provider_status or "Seccomp_filters:\t0" not in provider_status:
        raise AssertionError("provider process did not begin with a clean seccomp baseline")
    (arguments.artifact_dir / "provider-seccomp-baseline.txt").write_text(
        "\n".join(
            line
            for line in provider_status.splitlines()
            if line.startswith(("NoNewPrivs:", "Seccomp:", "Seccomp_filters:"))
        )
        + "\n",
        encoding="utf-8",
    )
    seccomp_bpf_base64 = arguments.seccomp_bpf_base64.read_text(
        encoding="ascii"
    )
    validate_bpf_annotation(
        seccomp_bpf_base64, arguments.seccomp_bpf.resolve().read_bytes()
    )
    mutation_report = annotation_mutation_report(
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
    )
    (arguments.artifact_dir / "annotation-mutation-report.json").write_text(
        json.dumps(mutation_report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    normal_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
    )
    cancellation_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
    )
    stacked_filter_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.prefilter.resolve(),
        arguments.artifact_dir,
    )
    seccomp_probe_scenario(
        arguments.architecture,
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.artifact_dir,
    )
    cache_matrix_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
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
