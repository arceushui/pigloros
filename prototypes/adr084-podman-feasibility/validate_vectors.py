#!/usr/bin/env python3
"""Independently validate ADR-085 positive and semantic rejection vectors."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import pathlib
import struct
import subprocess
import tarfile

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def blake3(domain: str, encoded: bytes) -> bytes:
    result = subprocess.run(
        ["b3sum"],
        input=domain.encode("ascii") + b"\0" + encoded,
        check=True,
        capture_output=True,
    )
    return bytes.fromhex(result.stdout.decode("ascii").split()[0])


def digest_domain(name: str, value: list[object]) -> str:
    if name.startswith("OciImageSubject") or name.startswith("OIS1-"):
        return "PiglorOS.OciImageSubject.v1"
    if name == "OciRootfsTree":
        return "PiglorOS.OciRootfsTree.v1"
    if value[0] == "RBS2":
        return "PiglorOS.SandboxReadbackSet.v2"
    return f"PiglorOS.{value[0]}.v{value[1]}"


def validate_vector(value: dict[str, str]) -> list[object]:
    encoded = bytes.fromhex(value["unsigned_cbor_hex"])
    decoded = cbor2.loads(encoded)
    if not isinstance(decoded, list) or cbor2.dumps(decoded, canonical=True) != encoded:
        raise ValueError(f"noncanonical vector {value['record']}")
    observed = blake3(digest_domain(value["record"], decoded), encoded)
    if observed.hex() != value["self_digest_hex"]:
        raise ValueError(f"self-digest mismatch for {value['record']}")
    if "signature_hex" in value:
        signature_domain = (
            "PiglorOS.OciImageSubjectSignature.v1"
            if value["record"].startswith(("OciImageSubject", "OIS1-"))
            else f"PiglorOS.{decoded[0]}.Signature.v{decoded[1]}"
        )
        key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(value["signer_public_key_hex"])
        )
        key.verify(
            bytes.fromhex(value["signature_hex"]),
            signature_domain.encode("ascii") + b"\0" + observed,
        )
    return decoded


def descriptor_blob(
    descriptor: list[object], blobs: dict[str, tuple[str, bytes]], expected_media: str
) -> bytes:
    media_ordinal, size, digest = descriptor
    media, content = blobs[bytes(digest).hex()]
    if media != expected_media or size != len(content) or hashlib.sha256(content).digest() != digest:
        raise ValueError(f"invalid descriptor for {expected_media} (ordinal {media_ordinal})")
    return content


def validate_positive(document: dict[str, object]) -> tuple[list[object], list[object]]:
    decoded = {
        item["record"]: validate_vector(item)  # type: ignore[arg-type]
        for item in document["vectors"]  # type: ignore[union-attr]
    }
    ort = decoded["OciRootfsTree"]
    ois = decoded["OciImageSubject"]
    if ois[8] != bytes.fromhex(next(
        item["self_digest_hex"]
        for item in document["vectors"]  # type: ignore[union-attr]
        if item["record"] == "OciRootfsTree"
    )):
        raise ValueError("OIS1 does not bind the positive ORT1")
    entries = {entry[0]: entry for entry in ort[2]}
    if set(entries) != {"/", "/adapter", "/launcher"}:
        raise ValueError("positive ORT1 has an unexpected path set")
    for descriptor in (ois[9], ois[10]):
        entry = entries[descriptor[0]]
        if entry[1] != 1 or entry[5] != descriptor[1]:
            raise ValueError("ELF descriptor metadata does not match ORT1")
        if descriptor[3] != 0 or descriptor[4:] != [None, None]:
            raise ValueError("unexpected ELF architecture/interpreter")

    blobs = {
        digest: (media, bytes.fromhex(encoded))
        for media, digest, encoded in document["fixture_blobs"]  # type: ignore[union-attr]
    }
    manifest_bytes = descriptor_blob(
        ois[4], blobs, "application/vnd.oci.image.manifest.v1+json"
    )
    manifest = json.loads(manifest_bytes)
    config_bytes = descriptor_blob(
        ois[5], blobs, "application/vnd.oci.image.config.v1+json"
    )
    config = json.loads(config_bytes)
    if set(config) != {"architecture", "config", "os", "rootfs"}:
        raise ValueError("fixture config is not closed")
    if config["architecture"] != "amd64" or config["os"] != "linux":
        raise ValueError("fixture config platform mismatch")
    if config["config"] != {
        "Entrypoint": ["/launcher"],
        "User": "65532:65532",
        "WorkingDir": "/",
    }:
        raise ValueError("fixture runtime config mismatch")
    layer_contents: list[bytes] = []
    diff_ids: list[bytes] = []
    for subject, manifest_descriptor in zip(ois[6], manifest["layers"], strict=True):
        compressed = descriptor_blob(
            subject[0], blobs, "application/vnd.oci.image.layer.v1.tar+gzip"
        )
        if manifest_descriptor["digest"] != f"sha256:{subject[0][2].hex()}":
            raise ValueError("OIS1 layer order differs from manifest")
        uncompressed = gzip.decompress(compressed)
        observed_diff = hashlib.sha256(uncompressed).digest()
        if observed_diff != subject[1]:
            raise ValueError("fixture DiffID mismatch")
        diff_ids.append(observed_diff)
        layer_contents.append(uncompressed)
    chain = hashlib.sha256(
        f"sha256:{diff_ids[0].hex()} sha256:{diff_ids[1].hex()}".encode("ascii")
    ).digest()
    if chain != ois[7]:
        raise ValueError("fixture ChainID mismatch")
    extracted: dict[str, tuple[int, int, int, bytes]] = {}
    for content in layer_contents:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
            for member in archive.getmembers():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("fixture layer contains a non-file entry")
                extracted["/" + member.name] = (
                    member.mode,
                    member.uid,
                    member.gid,
                    stream.read(),
                )
    for path in ("/launcher", "/adapter"):
        mode, uid, gid, content = extracted[path]
        entry = entries[path]
        descriptor = ois[9] if path == "/launcher" else ois[10]
        if (mode, uid, gid, len(content)) != tuple(entry[2:6]):
            raise ValueError("mounted file metadata differs from ORT1")
        if blake3("PiglorOS.OciRootfsFile.v1", content) != entry[6]:
            raise ValueError("mounted file content differs from ORT1")
        if blake3("PiglorOS.OciExecutable.v1", content) != descriptor[2]:
            raise ValueError("mounted executable differs from OIS1")
        if content[:4] != b"\x7fELF" or struct.unpack("<H", content[18:20])[0] != 62:
            raise ValueError("fixture executable is not x86_64 ELF")
    return ort, ois


def validate_rejections(document: dict[str, object], ort: list[object], ois: list[object]) -> None:
    rejections = {
        item["record"]: (item, validate_vector(item))  # type: ignore[arg-type]
        for item in document["rejection_vectors"]  # type: ignore[union-attr]
    }
    if rejections["OIS1-wrong-architecture"][1][3] in (0, 1):
        raise ValueError("wrong-architecture fixture is admitted")
    if rejections["OIS1-wrong-layer-order"][1][6] != list(reversed(ois[6])):
        raise ValueError("wrong-layer-order fixture is not an isolated reversal")
    if rejections["OIS1-wrong-rootfs"][1][8] == ois[8]:
        raise ValueError("wrong-rootfs fixture still binds positive ORT1")
    wrong_executable = rejections["OIS1-wrong-executable"][1]
    if wrong_executable[10][0] in {entry[0] for entry in ort[2]}:
        raise ValueError("wrong-executable fixture path exists in ORT1")
    revoked = rejections["RVS2-revoked-image"][1]
    positive_digest = bytes.fromhex(next(
        item["self_digest_hex"]
        for item in document["vectors"]  # type: ignore[union-attr]
        if item["record"] == "OciImageSubject"
    ))
    if positive_digest not in revoked[6]:
        raise ValueError("revoked-image fixture does not revoke positive OIS1")
    mixed_item, mixed_lps = rejections["mixed-version-closure"]
    mixed_apt = {
        "record": "APT",
        "unsigned_cbor_hex": mixed_item["referencing_apt2_unsigned_cbor_hex"],
        "self_digest_hex": mixed_item["referencing_apt2_self_digest_hex"],
        "signature_hex": mixed_item["referencing_apt2_signature_hex"],
        "signer_public_key_hex": next(
            item["signer_public_key_hex"]
            for item in document["vectors"]  # type: ignore[union-attr]
            if item["record"] == "APT"
        ),
    }
    apt = validate_vector(mixed_apt)
    if mixed_lps[0:2] != ["LPS1", 1] or bytes.fromhex(mixed_item["self_digest_hex"]) not in apt[5]:
        raise ValueError("mixed-version closure is not an isolated v1 LPS reference")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("vectors", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    arguments = parser.parse_args()
    document = json.loads(arguments.vectors.read_text(encoding="utf-8"))
    ort, ois = validate_positive(document)
    validate_rejections(document, ort, ois)
    arguments.output.write_text(
        json.dumps(
            {
                "canonical_vectors": len(document["vectors"]),
                "fixture_blobs": len(document["fixture_blobs"]),
                "semantic_rejections": len(document["rejection_vectors"]),
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
