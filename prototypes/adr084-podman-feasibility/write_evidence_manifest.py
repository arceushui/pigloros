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

    files = [
        ("/launcher", arguments.build_dir / "launcher"),
        ("/adapter", arguments.build_dir / "adapter"),
        ("prototype/launcher.c", arguments.prototype_dir / "launcher.c"),
        ("prototype/adapter.c", arguments.prototype_dir / "adapter.c"),
        ("prototype/compile_seccomp.c", arguments.prototype_dir / "compile_seccomp.c"),
        ("prototype/prepare_seccomp.py", arguments.prototype_dir / "prepare_seccomp.py"),
        ("prototype/verify_seccomp_bpf.py", arguments.prototype_dir / "verify_seccomp_bpf.py"),
        ("prototype/Containerfile", arguments.prototype_dir / "Containerfile"),
        ("build/compile-seccomp", arguments.build_dir / "compile-seccomp"),
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
        "fixture-sbom.spdx.json",
        "image.oci.tar",
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
