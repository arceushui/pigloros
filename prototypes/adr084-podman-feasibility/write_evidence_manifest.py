#!/usr/bin/env python3
"""Write prototype provenance and an SPDX inventory of selected retained inputs."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha1(path: pathlib.Path) -> str:
    return hashlib.sha1(path.read_bytes(), usedforsecurity=False).hexdigest()


def spdx_file_name(name: str) -> str:
    relative = name.lstrip("/")
    parsed = pathlib.PurePosixPath(relative)
    if not relative or parsed.is_absolute() or ".." in parsed.parts:
        raise ValueError(f"invalid SPDX inventory path: {name!r}")
    return f"./{relative}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_dir", type=pathlib.Path)
    parser.add_argument("build_dir", type=pathlib.Path)
    parser.add_argument("prototype_dir", type=pathlib.Path)
    parser.add_argument("--architecture", required=True)
    arguments = parser.parse_args()
    foreign_source_name = {
        "amd64": "foreign_x86.S",
        "arm64": "foreign_arm.S",
    }[arguments.architecture]
    repository_root = arguments.prototype_dir.parents[1]
    evidence_architecture = {
        "amd64": "x86_64",
        "arm64": "aarch64",
    }[arguments.architecture]
    production_scs1 = (
        repository_root
        / "crates/pos-conformance/vectors/systemd-provider-v260.2"
        / f"systemd-v260.2-{evidence_architecture}.scs1.cbor"
    )
    retained_production_scs1 = arguments.artifact_dir / "seccomp/production.scs1.cbor"
    if production_scs1.read_bytes() != retained_production_scs1.read_bytes():
        raise ValueError("retained production SCS1 differs from the executed input")
    source_date_epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    github_sha = os.environ["GITHUB_SHA"]
    github_run_id = os.environ["GITHUB_RUN_ID"]
    github_run_attempt = os.environ["GITHUB_RUN_ATTEMPT"]
    created = datetime.datetime.fromtimestamp(
        source_date_epoch, datetime.UTC
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    files = [
        ("/launcher", arguments.build_dir / "launcher"),
        ("/adapter", arguments.build_dir / "adapter"),
        ("/cache-probe", arguments.build_dir / "cache-probe"),
        ("/seccomp-probe", arguments.build_dir / "seccomp-probe"),
        ("/foreign-probe", arguments.build_dir / "foreign-probe"),
        ("/native-matrix", arguments.build_dir / "native-matrix"),
        ("/memory-reclaimable", arguments.build_dir / "memory-reclaimable"),
        ("lifecycle-fixture/lifecycle-probe", arguments.build_dir / "lifecycle-probe"),
        (
            "/libseccomp-interface-v1.txt",
            arguments.build_dir / "libseccomp-interface-v1.txt",
        ),
        ("prototype/launcher.c", arguments.prototype_dir / "launcher.c"),
        ("prototype/README.md", arguments.prototype_dir / "README.md"),
        ("prototype/run.sh", arguments.prototype_dir / "run.sh"),
        (
            "prototype/run_coverage_probe.sh",
            arguments.prototype_dir / "run_coverage_probe.sh",
        ),
        ("prototype/driver.py", arguments.prototype_dir / "driver.py"),
        (
            "prototype/lifecycle_crash_matrix.py",
            arguments.prototype_dir / "lifecycle_crash_matrix.py",
        ),
        (
            "prototype/build_oci_archive.py",
            arguments.prototype_dir / "build_oci_archive.py",
        ),
        (
            "prototype/generate_runtime_subject.py",
            arguments.prototype_dir / "generate_runtime_subject.py",
        ),
        (
            "prototype/generate_vectors.py",
            arguments.prototype_dir / "generate_vectors.py",
        ),
        (
            "prototype/mount_and_manifest.sh",
            arguments.prototype_dir / "mount_and_manifest.sh",
        ),
        ("prototype/oci_layer.py", arguments.prototype_dir / "oci_layer.py"),
        (
            "prototype/rootfs_manifest.py",
            arguments.prototype_dir / "rootfs_manifest.py",
        ),
        (
            "prototype/validate_oci.py",
            arguments.prototype_dir / "validate_oci.py",
        ),
        (
            "prototype/validate_oci_archive.py",
            arguments.prototype_dir / "validate_oci_archive.py",
        ),
        (
            "prototype/validate_runtime_subject.py",
            arguments.prototype_dir / "validate_runtime_subject.py",
        ),
        (
            "prototype/validate_vectors.py",
            arguments.prototype_dir / "validate_vectors.py",
        ),
        (
            "prototype/write_evidence_manifest.py",
            arguments.prototype_dir / "write_evidence_manifest.py",
        ),
        ("dependency/blake3.c", arguments.build_dir / "blake3-source/c/blake3.c"),
        (
            "dependency/blake3_dispatch.c",
            arguments.build_dir / "blake3-source/c/blake3_dispatch.c",
        ),
        (
            "dependency/blake3_portable.c",
            arguments.build_dir / "blake3-source/c/blake3_portable.c",
        ),
        ("dependency/blake3.h", arguments.build_dir / "blake3-source/c/blake3.h"),
        (
            "dependency/blake3_impl.h",
            arguments.build_dir / "blake3-source/c/blake3_impl.h",
        ),
        ("prototype/adapter.c", arguments.prototype_dir / "adapter.c"),
        (
            "prototype/configured-default-injection.conf",
            arguments.prototype_dir / "configured-default-injection.conf",
        ),
        (
            "prototype/configured-security-default-injection.conf",
            arguments.prototype_dir / "configured-security-default-injection.conf",
        ),
        (
            "prototype/generate_adapter_transport.py",
            arguments.prototype_dir / "generate_adapter_transport.py",
        ),
        ("prototype/cache_probe.c", arguments.prototype_dir / "cache_probe.c"),
        (
            "prototype/derive_distinct_scs1.py",
            arguments.prototype_dir / "derive_distinct_scs1.py",
        ),
        ("prototype/native_matrix.c", arguments.prototype_dir / "native_matrix.c"),
        ("prototype/lifecycle_probe.c", arguments.prototype_dir / "lifecycle_probe.c"),
        ("prototype/compile_seccomp.c", arguments.prototype_dir / "compile_seccomp.c"),
        ("prototype/seccomp_probe.c", arguments.prototype_dir / "seccomp_probe.c"),
        (
            f"prototype/{foreign_source_name}",
            arguments.prototype_dir / foreign_source_name,
        ),
        ("prototype/prepare_seccomp.py", arguments.prototype_dir / "prepare_seccomp.py"),
        ("prototype/prefilter_exec.c", arguments.prototype_dir / "prefilter_exec.c"),
        ("prototype/trace_seccomp.c", arguments.prototype_dir / "trace_seccomp.c"),
        ("prototype/verify_seccomp_bpf.py", arguments.prototype_dir / "verify_seccomp_bpf.py"),
        ("prototype/Containerfile", arguments.prototype_dir / "Containerfile"),
        (
            "prototype/Containerfile.coverage",
            arguments.prototype_dir / "Containerfile.coverage",
        ),
        (
            "prototype/Containerfile.lifecycle",
            arguments.prototype_dir / "Containerfile.lifecycle",
        ),
        (
            "prototype/coverage-fixture/Cargo.toml",
            arguments.prototype_dir / "coverage-fixture/Cargo.toml",
        ),
        (
            "prototype/coverage-fixture/launcher/Cargo.toml",
            arguments.prototype_dir / "coverage-fixture/launcher/Cargo.toml",
        ),
        (
            "prototype/coverage-fixture/launcher/src/main.rs",
            arguments.prototype_dir / "coverage-fixture/launcher/src/main.rs",
        ),
        (
            "prototype/coverage-fixture/adapter/Cargo.toml",
            arguments.prototype_dir / "coverage-fixture/adapter/Cargo.toml",
        ),
        (
            "prototype/coverage-fixture/adapter/src/main.rs",
            arguments.prototype_dir / "coverage-fixture/adapter/src/main.rs",
        ),
        (
            "workflow/adr084-podman-feasibility.yml",
            repository_root / ".github/workflows/adr084-podman-feasibility.yml",
        ),
        ("input/production-scs1.cbor", production_scs1),
        (
            "input/derived-scs1.cbor",
            arguments.artifact_dir / "seccomp-distinct/derived-cachestat.scs1.cbor",
        ),
        (
            "policy/check_spdx_sbom.py",
            repository_root / "scripts/check_spdx_sbom.py",
        ),
        ("build/compile-seccomp", arguments.build_dir / "compile-seccomp"),
        ("build/trace-seccomp", arguments.build_dir / "trace-seccomp"),
        ("build/prefilter-exec", arguments.build_dir / "prefilter-exec"),
        (
            "build/adapter_transport_vectors.h",
            arguments.build_dir / "adapter_transport_vectors.h",
        ),
        (
            "build/libseccomp-2.6.1.tar.gz",
            arguments.build_dir / "libseccomp-2.6.1.tar.gz",
        ),
        (
            "build/libseccomp.a",
            arguments.build_dir / "libseccomp-install/lib/libseccomp.a",
        ),
        ("runtime/crun", pathlib.Path("/usr/bin/crun")),
        ("runtime/podman", pathlib.Path("/usr/bin/podman")),
    ]
    file_names = [name for name, _ in files]
    required_retained_inputs = {
        "input/derived-scs1.cbor",
        "input/production-scs1.cbor",
        "prototype/driver.py",
        "prototype/lifecycle_crash_matrix.py",
        "prototype/run.sh",
        "workflow/adr084-podman-feasibility.yml",
    }
    duplicated_inputs = len(file_names) != len(set(file_names))
    missing_required_inputs = not required_retained_inputs.issubset(file_names)
    if duplicated_inputs or missing_required_inputs:
        raise ValueError(
            "selected retained-input inventory is incomplete or duplicated"
        )
    sbom = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created,
            "creators": [
                f"Tool: PiglorOS-ADR-084-evidence-workflow-{github_sha}"
            ],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": (
            "https://github.com/arceushui/pigloros/adr084-evidence/"
            f"{github_run_id}/{github_run_attempt}/{arguments.architecture}"
        ),
        "files": [
            {
                "SPDXID": f"SPDXRef-File-{index}",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": sha1(path)},
                    {"algorithm": "SHA256", "checksumValue": sha256(path)},
                ],
                "copyrightText": "NOASSERTION",
                "fileName": spdx_file_name(name),
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
            }
            for index, (name, path) in enumerate(files, start=1)
        ],
        "name": "PiglorOS ADR-084 throwaway OCI fixture",
        "spdxVersion": "SPDX-2.3",
    }
    (arguments.artifact_dir / "fixture-sbom.spdx.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    retained = (
        "adr085-vectors.json",
        "adr085-vector-validation.json",
        "annotation-mutation-report.json",
        "adapter-transport-vectors.json",
        "adapter-transport-validation.json",
        "adapter-transport-runtime-rejections.json",
        "elm-provider-controls.json",
        "terminal-precedence-matrix.json",
        "barrier-provider-death.json",
        "lifecycle-crash-matrix.json",
        "lifecycle-image-inspect.json",
        "release-barrier-runtime-rejections.json",
        "lifecycle-concurrent.json",
        "lifecycle-concurrent.release",
        "blake3-LICENSE_A2.txt",
        "blake3-source-identity.txt",
        "fixture-sbom.spdx.json",
        "image.oci.tar",
        "installed-byte-mutation.json",
        "installed-byte-mutation.stderr",
        "installed-byte-mutation.stdout",
        "normal.installed-seccomp.bpf",
        "normal.seccomp-install.json",
        "normal.eai1",
        "normal-transport-validation.json",
        "normal.stderr",
        "normal.stdout",
        "native-matrix.json",
        "native-matrix.inspect.json",
        "native-matrix.stderr",
        "native-matrix.stdout",
        "cancel.installed-seccomp.bpf",
        "cancel.seccomp-install.json",
        "cancel.eai1",
        "cancel.json",
        "cancel.stderr",
        "terminal-cleanup-failed.json",
        "terminal-ipc-failure.json",
        *(
            f"terminal-ipc-failure.{suffix}"
            for suffix in (
                "installed-seccomp.bpf",
                "launch-context.cbor",
                "launcher-starting.json",
                "launcher.json",
                "ready2.cbor",
                "release2.cbor",
                "release-barrier.json",
                "seccomp-install.json",
            )
        ),
        "expected.eao1",
        "elm-memory.eai1",
        "elm-memory.installed-seccomp.bpf",
        "elm-memory.json",
        "elm-memory.launch-context.cbor",
        "elm-memory.launcher-starting.json",
        "elm-memory.launcher.json",
        "elm-memory.ready2.cbor",
        "elm-memory.release2.cbor",
        "elm-memory.release-barrier.json",
        "elm-memory.seccomp-install.json",
        "elm-memory.stderr",
        "elm-memory.stdout",
        "elm-swap.json",
        *(
            f"provider-death-{stage}.{suffix}"
            for stage in (
                "before-ready",
                "after-ready",
                "before-observe",
                "after-observe",
                "before-release",
                "after-release",
            )
            for suffix in (
                "crash-context.json",
                "installed-seccomp.bpf",
                "journal.json",
                "launch-context.cbor",
                "launcher-starting.json",
                "launcher.json",
                "ready2.cbor",
                "release2.cbor",
                "release-barrier.json",
                "seccomp-install.json",
            )
            if not (
                (stage == "before-ready" and suffix in (
                    "launcher.json",
                    "ready2.cbor",
                    "release2.cbor",
                    "release-barrier.json",
                ))
                or (
                    stage in ("after-ready", "before-observe")
                    and suffix in ("launcher.json", "release2.cbor", "release-barrier.json")
                )
                or (
                    stage in ("after-observe", "before-release")
                    and suffix in ("release2.cbor", "release-barrier.json")
                )
            )
        ),
        *(
            f"{scenario}.{suffix}"
            for scenario in (
                "elm-memory-limit",
                "elm-tasks",
                "elm-cpu-throttling",
                "elm-input",
                "elm-output",
                "elm-work",
                "elm-watchdog",
            )
            for suffix in (
                "eai1",
                "installed-seccomp.bpf",
                "json",
                "launch-context.cbor",
                "launcher-starting.json",
                "launcher.json",
                "ready2.cbor",
                "release2.cbor",
                "release-barrier.json",
                "seccomp-install.json",
                "stderr",
                "stdout",
            )
        ),
        *(
            f"elm-file.{suffix}"
            for suffix in (
                "eai1",
                "json",
                "launch-context.cbor",
                "launcher-starting.json",
                "launcher.json",
                "ready2.cbor",
                "release2.cbor",
                "release-barrier.json",
                "stderr",
                "stdout",
            )
        ),
        "cache-matrix.json",
        "cache-concurrent-identical.json",
        "cache-concurrent-distinct.json",
        "configured-default-injection.json",
        "configured-default-injection.stderr",
        "configured-default-injection.stdout",
        "configured-security-default-injection.json",
        "configured-security-default-injection.stderr",
        "configured-security-default-injection.stdout",
        "probe-filter-binding.json",
        "probe.stderr",
        "probe.stdout",
        "provider-subprocess-environment.json",
        "provider-seccomp-baseline.txt",
        "stacked.installed-seccomp.bpf",
        "stacked.seccomp-install.json",
        "stacked-rejection.json",
        "stacked.stderr",
        "stacked.stdout",
        *(
            f"{scenario}.{suffix}"
            for scenario in (
                "normal",
                "cancel",
                "transport-reject-changed-magic",
                "transport-reject-changed-transcript",
                "transport-reject-truncated",
                "transport-reject-trailing",
            )
            for suffix in (
                "launch-context.cbor",
                "launcher-starting.json",
                "ready2.cbor",
                "release2.cbor",
                "release-barrier.json",
            )
        ),
        *(
            f"release-reject-{mutation}.{suffix}"
            for mutation in (
                "noncanonical-record-length",
                "trailing-byte",
                "wrong-self-digest",
                "wrong-attempt",
                "wrong-nonce",
                "wrong-ready-binding",
                "invalid-anchor-order",
                "expired",
                "invalid-runtime-key-utf8",
            )
            for suffix in (
                "launch-context.cbor",
                "launcher-starting.json",
                "ready2.cbor",
                "release2.cbor",
                "release-barrier.json",
                "stderr",
                "stdout",
            )
        ),
        *(
            f"release-reject-{state}.{suffix}"
            for state in ("revoked", "missing")
            for suffix in (
                "launch-context.cbor",
                "launcher-starting.json",
                "ready2.cbor",
                "stderr",
                "stdout",
            )
        ),
        *(
            f"lifecycle-concurrent-{index}.{suffix}"
            for index in range(8)
            for suffix in (
                "installed-seccomp.bpf",
                "launch-context.cbor",
                "launcher-starting.json",
                "launcher.json",
                "observed.json",
                "ready2.cbor",
                "release2.cbor",
                "release-barrier.json",
                "seccomp-install.json",
                "stderr",
                "stdout",
            )
        ),
        *(
            f"{scenario}.{suffix}"
            for scenario in ("configured-default-injection", "stacked")
            for suffix in (
                "launch-context.cbor",
                "launcher-starting.json",
                "ready2.cbor",
            )
        ),
        "configured-security-default-injection.launch-context.cbor",
        "configured-security-default-injection.launcher-starting.json",
        *(
            f"cache-{state}.{suffix}"
            for state in ("empty", "valid", "stale", "corrupt", "adversarial")
            for suffix in (
                "installed-seccomp.bpf",
                "seccomp-install.json",
                "stderr",
                "stdout",
            )
        ),
        *(
            f"cache-concurrent-identical-{index}.{suffix}"
            for index in range(8)
            for suffix in (
                "installed-seccomp.bpf",
                "seccomp-install.json",
                "stderr",
                "stdout",
            )
        ),
        *(
            f"cache-concurrent-distinct-{index}.{suffix}"
            for index in range(8)
            for suffix in (
                "installed-seccomp.bpf",
                "seccomp-install.json",
                "stderr",
                "stdout",
            )
        ),
        "oci-archive-validation.json",
        "oci-validation.json",
        "rootfs-manifest.json",
        "runtime-subject-validation.json",
        "runtime-subject.json",
        "seccomp/bpf-verification.json",
        "seccomp/compiler-metadata.json",
        "seccomp/exported-seccomp.base64",
        "seccomp/exported-seccomp.bpf",
        "seccomp/libseccomp-interface-v1.txt",
        "seccomp/oci-seccomp-profile.json",
        "seccomp/production.scs1.cbor",
        "seccomp/readback-only-pnr.txt",
        "seccomp/seccomp-mapping-report.json",
        "seccomp/seccomp-mutation-report.json",
        "seccomp-distinct/bpf-verification.json",
        "seccomp-distinct/compiler-metadata.json",
        "seccomp-distinct/derived-cachestat.scs1.cbor",
        "seccomp-distinct/exported-seccomp.base64",
        "seccomp-distinct/exported-seccomp.bpf",
        "seccomp-distinct/libseccomp-interface-v1.txt",
        "seccomp-distinct/oci-seccomp-profile.json",
        "seccomp-distinct/readback-only-pnr.txt",
        "seccomp-distinct/seccomp-mapping-report.json",
        "seccomp-distinct/seccomp-mutation-report.json",
        *(
            str(path.relative_to(arguments.artifact_dir))
            for path in sorted((arguments.artifact_dir / "adr079").rglob("*"))
            if path.is_file()
        ),
    )
    provenance = {
        "architecture": arguments.architecture,
        "artifact_sha256": {
            name: sha256(arguments.artifact_dir / name) for name in retained
        },
        "commit": os.environ.get("GITHUB_SHA", "unknown"),
        "job": os.environ.get("GITHUB_JOB", "unknown"),
        "ref": os.environ.get("GITHUB_REF", "unknown"),
        "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
        "retention_days": 90,
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "unknown"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "unknown"),
        "run_url": (
            f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
            f"{os.environ.get('GITHUB_REPOSITORY', 'unknown')}/actions/runs/"
            f"{os.environ.get('GITHUB_RUN_ID', 'unknown')}/attempts/"
            f"{os.environ.get('GITHUB_RUN_ATTEMPT', 'unknown')}"
        ),
        "runner_image": os.environ.get("ImageOS", "unknown"),
        "runner_image_version": os.environ.get("ImageVersion", "unknown"),
        "workflow": os.environ.get("GITHUB_WORKFLOW", "unknown"),
    }
    (arguments.artifact_dir / "evidence-manifest.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
