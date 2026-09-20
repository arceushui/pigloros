#!/usr/bin/env python3
"""Bind the remotely imported and mounted OCI fixture into signed ORT1/OIS1."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from generate_vectors import cbor


def blake3(domain: str, content: bytes) -> bytes:
    result = subprocess.run(
        ["b3sum"],
        input=domain.encode("ascii") + b"\0" + content,
        check=True,
        capture_output=True,
    )
    return bytes.fromhex(result.stdout.decode("ascii").split()[0])


def descriptor(value: dict[str, object], ordinal: int) -> list[object]:
    algorithm, encoded = str(value["digest"]).split(":", 1)
    if algorithm != "sha256":
        raise ValueError("runtime subject requires SHA-256 OCI descriptors")
    return [ordinal, value["size"], bytes.fromhex(encoded)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("oci_validation", type=pathlib.Path)
    parser.add_argument("rootfs_manifest", type=pathlib.Path)
    parser.add_argument("launcher", type=pathlib.Path)
    parser.add_argument("adapter", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    arguments = parser.parse_args()

    oci = json.loads(arguments.oci_validation.read_text(encoding="utf-8"))
    mounted = json.loads(arguments.rootfs_manifest.read_text(encoding="utf-8"))
    architecture = {"linux/amd64": 0, "linux/arm64": 1}[oci["native_platform"]]
    rootfs_entries = []
    for item in mounted["entries"]:
        kind = {"directory": 0, "regular": 1, "symlink": 2}[item["kind"]]
        rootfs_entries.append(
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
    ort_unsigned = ["ORT1", 1, rootfs_entries]
    ort_encoded = cbor(ort_unsigned)
    ort_digest = blake3("PiglorOS.OciRootfsTree.v1", ort_encoded)

    binaries = {
        "/launcher": arguments.launcher.read_bytes(),
        "/adapter": arguments.adapter.read_bytes(),
    }
    executable = {
        path: [
            path,
            len(content),
            blake3("PiglorOS.OciExecutable.v1", content),
            architecture,
            None,
            None,
        ]
        for path, content in binaries.items()
    }
    index_descriptor = oci["index"]["manifests"][0]
    image_id = index_descriptor["annotations"]["org.opencontainers.image.ref.name"]
    layers = [
        [descriptor(layer, 2), bytes.fromhex(diff_id.removeprefix("sha256:"))]
        for layer, diff_id in zip(
            oci["layers"], oci["verified_diff_ids"], strict=True
        )
    ]
    ois_unsigned = [
        "OIS1",
        1,
        image_id,
        architecture,
        descriptor(index_descriptor, 0),
        descriptor(oci["config"], 1),
        layers,
        bytes.fromhex(oci["verified_chain_id"].removeprefix("sha256:")),
        ort_digest,
        executable["/launcher"],
        executable["/adapter"],
        [],
        65_532,
        65_532,
        "/",
        11,
        "test-image-project-key-01",
    ]
    ois_encoded = cbor(ois_unsigned)
    ois_digest = blake3("PiglorOS.OciImageSubject.v1", ois_encoded)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signature = key.sign(b"PiglorOS.OciImageSubjectSignature.v1\0" + ois_digest)
    document = {
        "architecture": architecture,
        "ois1": {
            "self_digest_hex": ois_digest.hex(),
            "signature_hex": signature.hex(),
            "signer_public_key_hex": key.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex(),
            "unsigned_cbor_hex": ois_encoded.hex(),
        },
        "ort1": {
            "self_digest_hex": ort_digest.hex(),
            "unsigned_cbor_hex": ort_encoded.hex(),
        },
    }
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
