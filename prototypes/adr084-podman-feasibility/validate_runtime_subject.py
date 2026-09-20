#!/usr/bin/env python3
"""Independently verify the mounted-image ORT1/OIS1 evidence."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import subprocess

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def blake3(domain: str, content: bytes) -> bytes:
    result = subprocess.run(
        ["b3sum"],
        input=domain.encode("ascii") + b"\0" + content,
        check=True,
        capture_output=True,
    )
    return bytes.fromhex(result.stdout.decode("ascii").split()[0])


def decode_canonical(encoded_hex: str, name: str) -> list[object]:
    encoded = bytes.fromhex(encoded_hex)
    stream = io.BytesIO(encoded)
    value = cbor2.CBORDecoder(stream).decode()
    if stream.read() or not isinstance(value, list):
        raise ValueError(f"invalid {name} encoding")
    if cbor2.dumps(value, canonical=True) != encoded:
        raise ValueError(f"noncanonical {name} encoding")
    return value


def descriptor(value: dict[str, object], ordinal: int) -> list[object]:
    algorithm, encoded = str(value["digest"]).split(":", 1)
    if algorithm != "sha256":
        raise ValueError("runtime subject requires SHA-256 OCI descriptors")
    return [ordinal, value["size"], bytes.fromhex(encoded)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("subject", type=pathlib.Path)
    parser.add_argument("oci_validation", type=pathlib.Path)
    parser.add_argument("rootfs_manifest", type=pathlib.Path)
    parser.add_argument("launcher", type=pathlib.Path)
    parser.add_argument("adapter", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    arguments = parser.parse_args()

    document = json.loads(arguments.subject.read_text(encoding="utf-8"))
    oci = json.loads(arguments.oci_validation.read_text(encoding="utf-8"))
    mounted = json.loads(arguments.rootfs_manifest.read_text(encoding="utf-8"))
    ort = decode_canonical(document["ort1"]["unsigned_cbor_hex"], "ORT1")
    ois = decode_canonical(document["ois1"]["unsigned_cbor_hex"], "OIS1")
    if ort[0:2] != ["ORT1", 1] or len(ort) != 3:
        raise ValueError("invalid ORT1 shape")
    if ois[0:2] != ["OIS1", 1] or len(ois) != 17:
        raise ValueError("invalid OIS1 shape")

    ort_encoded = bytes.fromhex(document["ort1"]["unsigned_cbor_hex"])
    ort_digest = blake3("PiglorOS.OciRootfsTree.v1", ort_encoded)
    if ort_digest.hex() != document["ort1"]["self_digest_hex"] or ois[8] != ort_digest:
        raise ValueError("mounted ORT1 digest mismatch")
    if {item["path"] for item in mounted["entries"]} != {
        "/",
        "/adapter",
        "/cache-probe",
        "/foreign-probe",
        "/launcher",
        "/seccomp-probe",
    }:
        raise ValueError("mounted fixture contains an unexpected path")
    expected_entries = []
    for item in mounted["entries"]:
        kind = {"directory": 0, "regular": 1, "symlink": 2}[item["kind"]]
        expected_entries.append(
            [
                item["path"],
                kind,
                item["mode"],
                item["uid"],
                item["gid"],
                item["length"],
                bytes.fromhex(item["content_digest"]) if kind == 1 else None,
                item.get("target") if kind == 2 else None,
            ]
        )
    if ort[2] != expected_entries:
        raise ValueError("ORT1 does not equal mounted rootfs walk")

    architecture = {"linux/amd64": 0, "linux/arm64": 1}[oci["native_platform"]]
    if document["architecture"] != architecture or ois[3] != architecture:
        raise ValueError("OIS1 architecture mismatch")
    binaries = {
        "/launcher": arguments.launcher.read_bytes(),
        "/adapter": arguments.adapter.read_bytes(),
    }
    entry_by_path = {entry[0]: entry for entry in ort[2]}
    for path, index in (("/launcher", 9), ("/adapter", 10)):
        content = binaries[path]
        entry = entry_by_path[path]
        if hashlib.sha256(content).hexdigest() != next(
            item["sha256"] for item in mounted["entries"] if item["path"] == path
        ):
            raise ValueError(f"{path} differs from mounted SHA-256")
        if entry[6] != blake3("PiglorOS.OciRootfsFile.v1", content):
            raise ValueError(f"{path} differs from mounted ORT1")
        if ois[index] != [
            path,
            len(content),
            blake3("PiglorOS.OciExecutable.v1", content),
            architecture,
            None,
            None,
        ]:
            raise ValueError(f"{path} executable descriptor mismatch")

    index_descriptor = oci["index"]["manifests"][0]
    expected_layers = [
        [descriptor(layer, 2), bytes.fromhex(diff_id.removeprefix("sha256:"))]
        for layer, diff_id in zip(
            oci["layers"], oci["verified_diff_ids"], strict=True
        )
    ]
    expected_identity = [
        index_descriptor["annotations"]["org.opencontainers.image.ref.name"],
        architecture,
        descriptor(index_descriptor, 0),
        descriptor(oci["config"], 1),
        expected_layers,
        bytes.fromhex(oci["verified_chain_id"].removeprefix("sha256:")),
    ]
    if ois[2:8] != expected_identity:
        raise ValueError("OIS1 differs from validated OCI closure")
    if ois[11:17] != [[], 65_532, 65_532, "/", 11, "test-image-project-key-01"]:
        raise ValueError("OIS1 execution policy mismatch")

    ois_encoded = bytes.fromhex(document["ois1"]["unsigned_cbor_hex"])
    ois_digest = blake3("PiglorOS.OciImageSubject.v1", ois_encoded)
    if ois_digest.hex() != document["ois1"]["self_digest_hex"]:
        raise ValueError("OIS1 self-digest mismatch")
    Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(document["ois1"]["signer_public_key_hex"])
    ).verify(
        bytes.fromhex(document["ois1"]["signature_hex"]),
        b"PiglorOS.OciImageSubjectSignature.v1\0" + ois_digest,
    )
    arguments.output.write_text(
        json.dumps(
            {
                "architecture": architecture,
                "ois1_digest": ois_digest.hex(),
                "ort1_digest": ort_digest.hex(),
                "verdict": "passed",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
