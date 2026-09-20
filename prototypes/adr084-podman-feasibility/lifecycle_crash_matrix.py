#!/usr/bin/env python3
"""Throwaway provider-death/restart evidence; never production code."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import time
import uuid


PROVIDER_ID = "adr084-podman-crun-prototype-v1"
CLOSED_STATES = {
    "Reserved",
    "LauncherStarting",
    "Ready",
    "Observed",
    "Released",
    "Terminal",
    "Cleaned",
}


def run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=check, text=True, capture_output=True)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def journal_paths(directory: pathlib.Path, scenario: str) -> tuple[pathlib.Path, pathlib.Path]:
    return directory / f"{scenario}.jsonl", directory / f"{scenario}.commit.json"


def parse_journal(path: pathlib.Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        offset += os.write(descriptor, value[offset:])


def append_journal(
    directory: pathlib.Path,
    scenario: str,
    state: str,
    event: str,
    details: dict[str, object],
    *,
    durable: bool = True,
) -> dict[str, object]:
    if state not in CLOSED_STATES:
        raise ValueError(f"unknown lifecycle state: {state}")
    journal_path, commit_path = journal_paths(directory, scenario)
    records = parse_journal(journal_path)
    unsigned = {
        "details": details,
        "event": event,
        "monotonic_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC),
        "ordinal": len(records),
        "previous_record_digest": records[-1]["record_digest"] if records else None,
        "state": state,
    }
    record = {
        **unsigned,
        "record_digest": hashlib.sha256(
            b"PiglorOS.ADR084PrototypeJournal.v1\0" + canonical_json(unsigned)
        ).hexdigest(),
    }
    descriptor = os.open(journal_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        write_all(descriptor, canonical_json(record) + b"\n")
        if durable:
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if durable:
        temporary = commit_path.with_suffix(".commit.tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(
                {"ordinal": record["ordinal"], "record_digest": record["record_digest"]},
                stream,
                separators=(",", ":"),
                sort_keys=True,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, commit_path)
        fsync_directory(directory)
    return record


def load_committed_journal(
    directory: pathlib.Path, scenario: str
) -> list[dict[str, object]]:
    journal_path, commit_path = journal_paths(directory, scenario)
    commit = json.loads(commit_path.read_text(encoding="utf-8"))
    records = parse_journal(journal_path)
    committed = records[: int(commit["ordinal"]) + 1]
    if not committed or committed[-1]["record_digest"] != commit["record_digest"]:
        raise AssertionError(f"journal commit pointer mismatch for {scenario}")
    previous: str | None = None
    for ordinal, record in enumerate(committed):
        unsigned = {key: value for key, value in record.items() if key != "record_digest"}
        expected = hashlib.sha256(
            b"PiglorOS.ADR084PrototypeJournal.v1\0" + canonical_json(unsigned)
        ).hexdigest()
        if (
            record["ordinal"] != ordinal
            or record["previous_record_digest"] != previous
            or record["record_digest"] != expected
            or record["state"] not in CLOSED_STATES
        ):
            raise AssertionError(f"invalid journal chain for {scenario} at {ordinal}")
        previous = str(record["record_digest"])
    return committed


def discard_uncommitted_tail(
    directory: pathlib.Path,
    scenario: str,
    committed: list[dict[str, object]],
) -> int:
    journal_path, _ = journal_paths(directory, scenario)
    record_count = len(parse_journal(journal_path))
    discarded = record_count - len(committed)
    if discarded <= 0:
        return 0
    descriptor = os.open(journal_path, os.O_WRONLY | os.O_TRUNC)
    try:
        for record in committed:
            write_all(descriptor, canonical_json(record) + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(directory)
    return discarded


def labels(attempt_id: str, nonce: str, scenario: str) -> dict[str, str]:
    return {
        "io.pigloros.attempt-id": attempt_id,
        "io.pigloros.creation-nonce": nonce,
        "io.pigloros.prototype": "adr084",
        "io.pigloros.provider-id": PROVIDER_ID,
        "io.pigloros.scenario": scenario,
    }


def container_arguments(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    name: str,
    expected_labels: dict[str, str],
) -> list[str]:
    arguments = [
        "/usr/bin/podman",
        "create",
        "--runtime=/usr/bin/crun",
        "--pull=never",
        f"--name={name}",
        "--entrypoint=/lifecycle-probe",
        "--network=none",
        "--no-hosts",
        "--hostname=pigloros-lifecycle",
        "--read-only",
        "--read-only-tmpfs=false",
        "--tmpfs=/work:rw,nosuid,nodev,noexec,size=65536",
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
        "--ulimit=fsize=32768:32768",
        "--user=65532:65532",
        "--rm=false",
    ]
    for key, value in sorted(expected_labels.items()):
        arguments.append(f"--label={key}={value}")
    return [*arguments, image]


def inspect_container(container_id: str) -> dict[str, object]:
    result = run("/usr/bin/podman", "inspect", container_id, check=False)
    if result.returncode != 0:
        raise FileNotFoundError(container_id)
    documents = json.loads(result.stdout)
    if len(documents) != 1:
        raise AssertionError(f"unexpected inspect cardinality for {container_id}")
    return documents[0]


def process_start_ticks(pid: int) -> int | None:
    if pid <= 0:
        return None
    try:
        fields = (pathlib.Path("/proc") / str(pid) / "stat").read_text(
            encoding="ascii"
        ).split()
    except OSError:
        return None
    return int(fields[21])


def process_cgroup(pid: int) -> pathlib.Path | None:
    if pid <= 0:
        return None
    try:
        lines = (pathlib.Path("/proc") / str(pid) / "cgroup").read_text(
            encoding="ascii"
        ).splitlines()
    except OSError:
        return None
    unified = next((line.split("::", 1)[1] for line in lines if "::" in line), None)
    return pathlib.Path("/sys/fs/cgroup") / unified.lstrip("/") if unified else None


def identity_from_inspect(document: dict[str, object]) -> dict[str, object]:
    state = document["State"]
    graph = document.get("GraphDriver", {})
    graph_data = graph.get("Data", {}) if isinstance(graph, dict) else {}
    pid = int(state["Pid"])  # type: ignore[index]
    return {
        "cgroup_path": str(process_cgroup(pid)) if pid > 0 else None,
        "container_id": document["Id"],
        "created": document["Created"],
        "image_id": document["Image"],
        "labels": document["Config"]["Labels"],  # type: ignore[index]
        "merged_dir": graph_data.get("MergedDir") if isinstance(graph_data, dict) else None,
        "pid": pid,
        "pid_start_ticks": process_start_ticks(pid),
        "running": bool(state["Running"]),  # type: ignore[index]
    }


def discover(expected_labels: dict[str, str]) -> list[str]:
    command = ["/usr/bin/podman", "ps", "--all", "--no-trunc", "--format={{.ID}}"]
    for key, value in sorted(expected_labels.items()):
        command.append(f"--filter=label={key}={value}")
    return [line for line in run(*command).stdout.splitlines() if line]


def wait_for_probe(container_id: str) -> str:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        logs = run("/usr/bin/podman", "logs", container_id, check=False)
        combined = logs.stdout + logs.stderr
        if "LIFECYCLE_PROBE parent=" in combined and " child=" in combined:
            return combined
        document = inspect_container(container_id)
        if not document["State"]["Running"]:  # type: ignore[index]
            raise AssertionError(f"lifecycle probe exited before observation: {combined}")
        time.sleep(0.02)
    raise TimeoutError(f"lifecycle probe did not report descendants: {container_id}")


def create_container(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    expected_labels: dict[str, str],
    scenario: str,
) -> str:
    name = f"pigloros-adr084-crash-{scenario}-{uuid.uuid4().hex[:10]}"
    result = run(
        *container_arguments(
            image, seccomp, seccomp_bpf_base64, name, expected_labels
        )
    )
    container_id = result.stdout.strip()
    if len(container_id) != 64:
        raise AssertionError(f"Podman create returned an invalid ID: {result.stdout!r}")
    return container_id


def crash_worker(
    scenario: str,
    image: str,
    image_id: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    journal_dir: pathlib.Path,
    attempt_id: str,
    nonce: str,
) -> None:
    expected_labels = labels(attempt_id, nonce, scenario)
    append_journal(
        journal_dir,
        scenario,
        "Reserved",
        "attempt-reserved",
        {
            "attempt_id": attempt_id,
            "creation_nonce": nonce,
            "expected_image_id": image_id,
            "labels": expected_labels,
            "provider_id": PROVIDER_ID,
        },
    )
    if scenario == "before-create":
        os.kill(os.getpid(), signal.SIGKILL)
    container_id = create_container(
        image, seccomp, seccomp_bpf_base64, expected_labels, scenario
    )
    if scenario == "after-create":
        os.kill(os.getpid(), signal.SIGKILL)
    created_identity = identity_from_inspect(inspect_container(container_id))
    append_journal(
        journal_dir,
        scenario,
        "LauncherStarting",
        "container-created",
        created_identity,
    )
    if scenario == "before-start":
        os.kill(os.getpid(), signal.SIGKILL)
    run("/usr/bin/podman", "start", container_id)
    probe_log = wait_for_probe(container_id)
    if scenario in {"after-start", "before-identity-capture"}:
        os.kill(os.getpid(), signal.SIGKILL)
    running_identity = identity_from_inspect(inspect_container(container_id))
    running_identity["probe_log"] = probe_log
    append_journal(
        journal_dir,
        scenario,
        "Observed",
        "identity-captured",
        running_identity,
    )
    if scenario in {
        "after-identity-capture",
        "before-stop",
        "before-kill",
    }:
        os.kill(os.getpid(), signal.SIGKILL)
    if scenario == "before-journal-fsync":
        append_journal(
            journal_dir,
            scenario,
            "Terminal",
            "pending-transition-before-fsync",
            {"container_id": container_id},
            durable=False,
        )
        os.kill(os.getpid(), signal.SIGKILL)
    if scenario == "after-journal-fsync":
        append_journal(
            journal_dir,
            scenario,
            "Terminal",
            "transition-fsynced",
            {"container_id": container_id},
        )
        os.kill(os.getpid(), signal.SIGKILL)
    if scenario in {"after-stop", "before-remove"}:
        run("/usr/bin/podman", "stop", "--time=1", container_id)
        if scenario == "after-stop":
            os.kill(os.getpid(), signal.SIGKILL)
    elif scenario in {"after-kill", "after-remove"}:
        run("/usr/bin/podman", "kill", "--signal=KILL", container_id)
        if scenario == "after-kill":
            os.kill(os.getpid(), signal.SIGKILL)
    else:
        raise AssertionError(f"unhandled crash scenario: {scenario}")
    append_journal(
        journal_dir,
        scenario,
        "Terminal",
        "container-terminal",
        identity_from_inspect(inspect_container(container_id)),
    )
    if scenario == "before-remove":
        os.kill(os.getpid(), signal.SIGKILL)
    run("/usr/bin/podman", "rm", "--force", container_id)
    os.kill(os.getpid(), signal.SIGKILL)


def exact_identity_matches(
    actual: dict[str, object], expected: dict[str, object]
) -> bool:
    for field in ("container_id", "created", "image_id"):
        if expected.get(field) is not None and actual.get(field) != expected.get(field):
            return False
    if actual.get("running"):
        if expected.get("pid") not in (None, 0) and actual.get("pid") != expected.get(
            "pid"
        ):
            return False
        if expected.get("pid_start_ticks") is not None and actual.get(
            "pid_start_ticks"
        ) != expected.get("pid_start_ticks"):
            return False
    return True


def last_recorded_identity(records: list[dict[str, object]]) -> dict[str, object] | None:
    for record in reversed(records):
        details = record["details"]
        if isinstance(details, dict) and "container_id" in details:
            return details
    return None


def last_running_identity(records: list[dict[str, object]]) -> dict[str, object] | None:
    for record in reversed(records):
        details = record["details"]
        if isinstance(details, dict) and details.get("running") is True:
            return details
    return None


def cgroup_empty_or_absent(path: str | None) -> bool:
    if path is None:
        return True
    cgroup = pathlib.Path(path)
    if not cgroup.exists():
        return True
    procs = cgroup / "cgroup.procs"
    return not procs.exists() or not procs.read_text(encoding="ascii").strip()


def reconcile(
    journal_dir: pathlib.Path,
    scenario: str,
    expected_labels: dict[str, str],
    expected_image_id: str,
) -> dict[str, object]:
    records = load_committed_journal(journal_dir, scenario)
    discarded_uncommitted_records = discard_uncommitted_tail(
        journal_dir, scenario, records
    )
    if records[-1]["state"] == "Cleaned":
        if discover(expected_labels):
            raise AssertionError("a cleaned attempt rediscovered owned state")
        return dict(records[-1]["details"])
    candidates = discover(expected_labels)
    if len(candidates) > 1:
        raise RuntimeError(f"ambiguous exact crash candidates: {candidates}")
    previous_identity = last_recorded_identity(records)
    if not candidates:
        if scenario not in {"before-create", "after-remove"}:
            raise AssertionError(f"owned crash candidate disappeared for {scenario}")
        prior_running = last_running_identity(records)
        prior_cgroup = prior_running.get("cgroup_path") if prior_running else None
        prior_merged = prior_running.get("merged_dir") if prior_running else None
        result = {
            "actions": [],
            "cgroup_empty_or_absent": cgroup_empty_or_absent(
                str(prior_cgroup) if prior_cgroup else None
            ),
            "container_absent": True,
            "descendants_terminated": cgroup_empty_or_absent(
                str(prior_cgroup) if prior_cgroup else None
            ),
            "discarded_uncommitted_records": discarded_uncommitted_records,
            "idempotent_absence": True,
            "merged_root_not_mounted": (
                not prior_merged
                or str(prior_merged)
                not in pathlib.Path("/proc/self/mountinfo").read_text(encoding="utf-8")
            ),
            "scenario": scenario,
        }
    else:
        container_id = candidates[0]
        document = inspect_container(container_id)
        actual_identity = identity_from_inspect(document)
        if actual_identity["image_id"] != expected_image_id:
            raise RuntimeError("discovered candidate image subject mismatch")
        actual_labels = actual_identity["labels"]
        if not isinstance(actual_labels, dict) or any(
            actual_labels.get(key) != value for key, value in expected_labels.items()
        ):
            raise RuntimeError("discovered candidate label identity mismatch")
        if previous_identity is not None and not exact_identity_matches(
            actual_identity, previous_identity
        ):
            raise RuntimeError("durable container creation/PID identity mismatch")
        prior_running = last_running_identity(records)
        cgroup_path = actual_identity["cgroup_path"] or (
            prior_running.get("cgroup_path") if prior_running else None
        )
        merged_dir = actual_identity["merged_dir"]
        actions: list[str] = []
        if actual_identity["running"]:
            run("/usr/bin/podman", "stop", "--time=1", container_id, check=False)
            actions.append("stop")
            stopped = inspect_container(container_id)
            if stopped["State"]["Running"]:  # type: ignore[index]
                run("/usr/bin/podman", "kill", "--signal=KILL", container_id)
                actions.append("kill")
        append_journal(
            journal_dir,
            scenario,
            "Terminal",
            "restart-terminal-observed",
            {"actions": actions, "identity": actual_identity},
        )
        run("/usr/bin/podman", "rm", "--force", container_id)
        actions.append("remove")
        result = {
            "actions": actions,
            "cgroup_empty_or_absent": cgroup_empty_or_absent(
                str(cgroup_path) if cgroup_path else None
            ),
            "container_absent": run(
                "/usr/bin/podman", "inspect", container_id, check=False
            ).returncode
            != 0,
            "descendants_terminated": cgroup_empty_or_absent(
                str(cgroup_path) if cgroup_path else None
            ),
            "discarded_uncommitted_records": discarded_uncommitted_records,
            "idempotent_absence": not discover(expected_labels),
            "merged_root_not_mounted": (
                not merged_dir
                or str(merged_dir)
                not in pathlib.Path("/proc/self/mountinfo").read_text(encoding="utf-8")
            ),
            "network_mode": document["HostConfig"]["NetworkMode"],  # type: ignore[index]
            "scenario": scenario,
        }
    if not all(
        result[field]
        for field in (
            "cgroup_empty_or_absent",
            "container_absent",
            "descendants_terminated",
            "idempotent_absence",
            "merged_root_not_mounted",
        )
    ):
        raise AssertionError(f"restart cleanup incomplete: {result!r}")
    if result.get("network_mode", "none") != "none":
        raise AssertionError(f"restart candidate used a network: {result!r}")
    if load_committed_journal(journal_dir, scenario)[-1]["state"] != "Terminal":
        append_journal(
            journal_dir,
            scenario,
            "Terminal",
            "restart-terminal-observed",
            {"actions": result["actions"], "candidate_absent": True},
        )
    final = append_journal(
        journal_dir,
        scenario,
        "Cleaned",
        "restart-reconciliation-complete",
        result,
    )
    return {**result, "terminal_response_digest": final["record_digest"]}


def cleanup_container(container_id: str) -> None:
    run("/usr/bin/podman", "kill", "--signal=KILL", container_id, check=False)
    run("/usr/bin/podman", "rm", "--force", container_id, check=False)


def negative_identity_cases(
    image: str,
    image_id: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
) -> dict[str, object]:
    attempt_id = uuid.uuid4().hex
    nonce = uuid.uuid4().hex + uuid.uuid4().hex
    scenario = "identity-reuse-defense"
    expected_labels = labels(attempt_id, nonce, scenario)
    container_id = create_container(
        image, seccomp, seccomp_bpf_base64, expected_labels, scenario
    )
    run("/usr/bin/podman", "start", container_id)
    wait_for_probe(container_id)
    actual = identity_from_inspect(inspect_container(container_id))
    rejected: list[str] = []
    for field, changed in (
        ("container_id", "0" * 64),
        ("created", str(actual["created"]) + ".changed"),
        ("pid_start_ticks", int(actual["pid_start_ticks"]) + 1),
    ):
        candidate = {**actual, field: changed}
        if exact_identity_matches(actual, candidate):
            raise AssertionError(f"identity mutation was accepted: {field}")
        if not inspect_container(container_id)["State"]["Running"]:  # type: ignore[index]
            raise AssertionError("identity refusal changed unrelated candidate state")
        rejected.append(field)
    if actual["image_id"] != image_id:
        raise AssertionError("identity defense used an unexpected image")
    cleanup_container(container_id)

    ambiguity_attempt = uuid.uuid4().hex
    ambiguity_nonce = uuid.uuid4().hex + uuid.uuid4().hex
    ambiguity_labels = labels(ambiguity_attempt, ambiguity_nonce, "ambiguity-defense")
    ambiguous = [
        create_container(
            image,
            seccomp,
            seccomp_bpf_base64,
            ambiguity_labels,
            f"ambiguity-defense-{index}",
        )
        for index in range(2)
    ]
    discovered = discover(ambiguity_labels)
    if sorted(discovered) != sorted(ambiguous):
        raise AssertionError("ambiguity fixture discovery mismatch")
    untouched = all(
        run("/usr/bin/podman", "inspect", container_id, check=False).returncode == 0
        for container_id in ambiguous
    )
    for ambiguous_id in ambiguous:
        cleanup_container(ambiguous_id)
    if not untouched:
        raise AssertionError("ambiguous candidates were changed before operator cleanup")
    return {
        "ambiguous_candidate_count": len(discovered),
        "ambiguous_candidates_untouched": untouched,
        "identity_mutations_rejected": rejected,
        "operator_intervention_required": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--seccomp", required=True, type=pathlib.Path)
    parser.add_argument("--seccomp-bpf-base64", required=True, type=pathlib.Path)
    parser.add_argument("--artifact-dir", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    seccomp_bpf_base64 = arguments.seccomp_bpf_base64.read_text(
        encoding="ascii"
    ).strip()
    image_document = json.loads(
        run("/usr/bin/podman", "image", "inspect", arguments.image).stdout
    )[0]
    image_id = str(image_document["Id"])
    journal_dir = arguments.artifact_dir / "lifecycle-crash-journals"
    journal_dir.mkdir(mode=0o700)
    fsync_directory(arguments.artifact_dir)

    sentinel_attempt = uuid.uuid4().hex
    sentinel_nonce = uuid.uuid4().hex + uuid.uuid4().hex
    sentinel_labels = labels(sentinel_attempt, sentinel_nonce, "unrelated-sentinel")
    sentinel = create_container(
        arguments.image,
        arguments.seccomp,
        seccomp_bpf_base64,
        sentinel_labels,
        "unrelated-sentinel",
    )
    run("/usr/bin/podman", "start", sentinel)
    wait_for_probe(sentinel)

    scenarios = (
        "before-create",
        "after-create",
        "before-start",
        "after-start",
        "before-identity-capture",
        "after-identity-capture",
        "before-stop",
        "after-stop",
        "before-kill",
        "after-kill",
        "before-remove",
        "after-remove",
        "before-journal-fsync",
        "after-journal-fsync",
    )
    results: list[dict[str, object]] = []
    for scenario in scenarios:
        attempt_id = uuid.uuid4().hex
        nonce = uuid.uuid4().hex + uuid.uuid4().hex
        pid = os.fork()
        if pid == 0:
            crash_worker(
                scenario,
                arguments.image,
                image_id,
                arguments.seccomp,
                seccomp_bpf_base64,
                journal_dir,
                attempt_id,
                nonce,
            )
            os._exit(72)
        waited, status = os.waitpid(pid, 0)
        if waited != pid or not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
            raise AssertionError(f"provider crash injection failed for {scenario}: {status}")
        expected_labels = labels(attempt_id, nonce, scenario)
        first = reconcile(journal_dir, scenario, expected_labels, image_id)
        replay = reconcile(journal_dir, scenario, expected_labels, image_id)
        if replay.get("scenario") != first.get("scenario"):
            raise AssertionError("reconcile replay changed semantic response")
        sentinel_document = inspect_container(sentinel)
        if not sentinel_document["State"]["Running"]:  # type: ignore[index]
            raise AssertionError("reconciliation touched the unrelated sentinel")
        committed = load_committed_journal(journal_dir, scenario)
        results.append(
            {
                "committed_record_count": len(committed),
                "crash_signal": signal.SIGKILL,
                "final_record_digest": committed[-1]["record_digest"],
                "reconciliation": first,
                "replay_semantically_identical": replay.get("scenario")
                == first.get("scenario"),
                "scenario": scenario,
            }
        )

    sentinel_untouched = inspect_container(sentinel)["State"]["Running"]  # type: ignore[index]
    cleanup_container(sentinel)
    negative = negative_identity_cases(
        arguments.image,
        image_id,
        arguments.seccomp,
        seccomp_bpf_base64,
    )
    report = {
        "closed_states": sorted(CLOSED_STATES),
        "crash_boundary_count": len(results),
        "fixture_image_id": image_id,
        "fixture_scope": "throwaway lifecycle image; not the admitted ADR-085 image",
        "identity_defenses": negative,
        "provider_id": PROVIDER_ID,
        "results": results,
        "unrelated_sentinel_untouched": sentinel_untouched,
        "verdict": (
            "provider SIGKILL followed by exact identity-authorized, idempotent cleanup "
            "at every split Podman lifecycle and journal-fsync boundary"
        ),
    }
    (arguments.artifact_dir / "lifecycle-crash-matrix.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
