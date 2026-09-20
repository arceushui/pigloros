#!/usr/bin/env python3
"""Write self-contained prototype provenance and a minimal SPDX file inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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

    files = [
        ("/launcher", arguments.build_dir / "launcher"),
        ("/adapter", arguments.build_dir / "adapter"),
        ("/cache-probe", arguments.build_dir / "cache-probe"),
        ("/seccomp-probe", arguments.build_dir / "seccomp-probe"),
        ("/foreign-probe", arguments.build_dir / "foreign-probe"),
        ("/native-matrix", arguments.build_dir / "native-matrix"),
        ("lifecycle-fixture/lifecycle-probe", arguments.build_dir / "lifecycle-probe"),
        (
            "/libseccomp-interface-v1.txt",
            arguments.build_dir / "libseccomp-interface-v1.txt",
        ),
        ("prototype/launcher.c", arguments.prototype_dir / "launcher.c"),
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
        (
            "prototype/lifecycle_crash_matrix.py",
            arguments.prototype_dir / "lifecycle_crash_matrix.py",
        ),
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
            "prototype/Containerfile.lifecycle",
            arguments.prototype_dir / "Containerfile.lifecycle",
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
    sbom = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "creators": ["Tool: PiglorOS ADR-084 throwaway evidence workflow"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": (
            "https://github.com/arceushui/pigloros/adr084-evidence/"
            f"{os.environ.get('GITHUB_RUN_ID', 'unknown')}/{arguments.architecture}"
        ),
        "files": [
            {
                "SPDXID": f"SPDXRef-File-{index}",
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(path)}],
                "copyrightText": "NOASSERTION",
                "fileName": name,
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
        "cancel.stderr",
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
    )
    provenance = {
        "architecture": arguments.architecture,
        "artifact_sha256": {
            name: sha256(arguments.artifact_dir / name) for name in retained
        },
        "commit": os.environ.get("GITHUB_SHA", "unknown"),
        "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
        "retention_days": 90,
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "unknown"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "unknown"),
        "runner_image": os.environ.get("ImageOS", "unknown"),
        "runner_image_version": os.environ.get("ImageVersion", "unknown"),
        "workflow": os.environ.get("GITHUB_WORKFLOW", "unknown"),
    }
    (arguments.artifact_dir / "evidence-manifest.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
