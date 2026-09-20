#!/usr/bin/env python3
"""Independently validate ADR-085 positive and semantic rejection vectors."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import struct
import subprocess
import tarfile
import tempfile

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from oci_layer import diff_id_bytes


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


def decode_canonical(encoded: bytes, context: str) -> list[object]:
    stream = io.BytesIO(encoded)
    decoded = cbor2.CBORDecoder(stream).decode()
    if stream.read() or not isinstance(decoded, list):
        raise ValueError(f"noncanonical {context} CBOR")
    if cbor2.dumps(decoded, canonical=True) != encoded:
        raise ValueError(f"noncanonical {context} CBOR")
    return decoded


def validate_vector(value: dict[str, str]) -> list[object]:
    encoded = bytes.fromhex(value["unsigned_cbor_hex"])
    decoded = decode_canonical(encoded, value["record"])
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
        try:
            key.verify(
                bytes.fromhex(value["signature_hex"]),
                signature_domain.encode("ascii") + b"\0" + observed,
            )
        except InvalidSignature as error:
            record = "ReleaseV2" if decoded[0] == "RLS2" else str(decoded[0])
            raise ValueError(f"{record} signature verification failed") from error
    return decoded


MEDIA_TYPES = {
    0: "application/vnd.oci.image.manifest.v1+json",
    1: "application/vnd.oci.image.config.v1+json",
    2: "application/vnd.oci.image.layer.v1.tar+gzip",
}


def require_keys(value: dict[str, object], allowed: set[str], context: str) -> None:
    if set(value) != allowed:
        raise ValueError(f"unexpected {context} fields")


def load_json_bytes(content: bytes, context: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key in {context}")
            result[key] = value
        return result

    value = json.loads(content, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"{context} is not an object")
    return value


def descriptor_json(descriptor: list[object]) -> dict[str, object]:
    ordinal, size, digest = descriptor
    return {
        "digest": f"sha256:{bytes(digest).hex()}",
        "mediaType": MEDIA_TYPES[int(ordinal)],
        "size": size,
    }


def descriptor_blob(
    descriptor: list[object], blobs: dict[str, tuple[str, bytes]], expected_ordinal: int
) -> bytes:
    if len(descriptor) != 3 or descriptor[0] != expected_ordinal:
        raise ValueError("descriptor ordinal mismatch")
    media_ordinal, size, digest = descriptor
    digest_hex = bytes(digest).hex()
    if digest_hex not in blobs:
        raise ValueError("descriptor references a missing blob")
    media, content = blobs[digest_hex]
    if (
        media != MEDIA_TYPES[expected_ordinal]
        or size != len(content)
        or hashlib.sha256(content).digest() != digest
    ):
        raise ValueError(
            f"invalid descriptor for {MEDIA_TYPES[expected_ordinal]} "
            f"(ordinal {media_ordinal})"
        )
    return content


def validate_timestamp(value: object) -> None:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
        value,
    ):
        raise ValueError("invalid OCI timestamp")


def validate_config(
    config: dict[str, object], ois: list[object], diff_ids: list[bytes]
) -> None:
    allowed = {"architecture", "config", "os", "rootfs"}
    if "created" in config:
        allowed.add("created")
        validate_timestamp(config["created"])
    if "history" in config:
        allowed.add("history")
        history = config["history"]
        if not isinstance(history, list) or len(history) > 128:
            raise ValueError("invalid OCI history")
        for item in history:
            if not isinstance(item, dict) or not set(item).issubset(
                {"created", "created_by", "comment", "empty_layer"}
            ) or "created" not in item:
                raise ValueError("invalid OCI history entry")
            validate_timestamp(item["created"])
            for key, limit in (("created_by", 4096), ("comment", 256)):
                if key in item and (
                    not isinstance(item[key], str)
                    or len(item[key].encode("utf-8")) > limit
                ):
                    raise ValueError("invalid OCI history entry")
            if "empty_layer" in item and not isinstance(item["empty_layer"], bool):
                raise ValueError("invalid OCI history entry")
    require_keys(config, allowed, "config")
    if config["architecture"] != "amd64" or config["os"] != "linux":
        raise ValueError("fixture config platform mismatch")
    expected_runtime = {
        "Entrypoint": [ois[9][0]],
        "User": f"{ois[12]}:{ois[13]}",
        "WorkingDir": ois[14],
    }
    if config["config"] != expected_runtime:
        raise ValueError("fixture runtime config mismatch")
    rootfs = config["rootfs"]
    if not isinstance(rootfs, dict):
        raise ValueError("rootfs config is not an object")
    require_keys(rootfs, {"type", "diff_ids"}, "rootfs config")
    expected = [f"sha256:{value.hex()}" for value in diff_ids]
    if rootfs["type"] != "layers" or rootfs["diff_ids"] != expected:
        raise ValueError("config DiffID mismatch")


def validate_elf(content: bytes, architecture: int, path: str) -> None:
    if len(content) < 120 or content[:16] != b"\x7fELF\x02\x01\x01" + bytes(9):
        raise ValueError("fixture executable is not a native ELF")
    header = struct.unpack("<HHIQQQIHHHHHH", content[16:64])
    file_type, machine, version, entry, phoff, _, _, ehsize, phsize, phnum, _, _, _ = header
    expected_machine = {0: 62, 1: 183}.get(architecture)
    if (
        file_type != 2
        or machine != expected_machine
        or version != 1
        or ehsize != 64
        or phsize != 56
        or phnum < 1
        or phoff + phsize * phnum > len(content)
    ):
        raise ValueError("fixture executable is not a native ELF")
    entry_is_executable = False
    for offset in range(phoff, phoff + phsize * phnum, phsize):
        p_type, flags, file_offset, virtual, _, file_size, memory_size, alignment = struct.unpack(
            "<IIQQQQQQ", content[offset : offset + 56]
        )
        if file_offset + file_size > len(content) or memory_size < file_size:
            raise ValueError("invalid ELF program header")
        if p_type == 1 and flags & 1 and virtual <= entry < virtual + file_size:
            entry_file_offset = file_offset + entry - virtual
            entry_is_executable = entry_file_offset < len(content)
        if alignment not in (0, 1) and file_offset % alignment != virtual % alignment:
            raise ValueError("invalid ELF segment alignment")
    if not entry_is_executable:
        raise ValueError("ELF entry point is not executable")
    if platform.machine() == "x86_64" and architecture == 0:
        with tempfile.TemporaryDirectory() as directory:
            executable = pathlib.Path(directory) / "fixture"
            executable.write_bytes(content)
            os.chmod(executable, 0o500)
            expected_status = 0 if path == "/launcher" else 1
            result = subprocess.run([executable], check=False)
            if result.returncode != expected_status:
                raise ValueError("ELF fixture did not execute with its expected status")


def validate_ois(
    ois: list[object],
    ort: list[object],
    ort_digest: bytes,
    blobs: dict[str, tuple[str, bytes]],
) -> None:
    if len(ois) != 17 or ois[0:2] != ["OIS1", 1]:
        raise ValueError("invalid OIS1 shape")
    if ois[3] != 0:
        raise ValueError("unsupported architecture")
    if ois[8] != ort_digest:
        raise ValueError("mounted ORT1 digest mismatch")
    entries = {entry[0]: entry for entry in ort[2]}
    if set(entries) != {"/", "/adapter", "/launcher"}:
        raise ValueError("positive ORT1 has an unexpected path set")
    for name, descriptor in (("launcher", ois[9]), ("adapter", ois[10])):
        if descriptor[0] not in entries:
            raise ValueError(f"{name} identity mismatch")
        entry = entries[descriptor[0]]
        if entry[1] != 1 or entry[5] != descriptor[1]:
            raise ValueError("ELF descriptor metadata does not match ORT1")
        if descriptor[3] != ois[3] or descriptor[4:] != [None, None]:
            raise ValueError("unexpected ELF architecture/interpreter")

    manifest_bytes = descriptor_blob(ois[4], blobs, 0)
    manifest = load_json_bytes(manifest_bytes, "manifest")
    require_keys(
        manifest,
        {"annotations", "config", "layers", "mediaType", "schemaVersion"},
        "manifest",
    )
    if manifest["annotations"] != {
        "org.opencontainers.image.base.digest": "",
        "org.opencontainers.image.base.name": "",
    }:
        raise ValueError("unexpected manifest annotations")
    if manifest["schemaVersion"] != 2 or manifest["mediaType"] != MEDIA_TYPES[0]:
        raise ValueError("invalid manifest envelope")
    if manifest["config"] != descriptor_json(ois[5]):
        raise ValueError("manifest config descriptor differs from OIS1")
    expected_layers = [descriptor_json(subject[0]) for subject in ois[6]]
    if manifest["layers"] != expected_layers:
        raise ValueError("ordered layer closure mismatch")
    config_bytes = descriptor_blob(ois[5], blobs, 1)
    config = load_json_bytes(config_bytes, "config")
    layer_contents: list[bytes] = []
    diff_ids: list[bytes] = []
    cumulative_uncompressed_bytes = 0
    for subject in ois[6]:
        compressed = descriptor_blob(subject[0], blobs, 2)
        observed_diff, cumulative_uncompressed_bytes = diff_id_bytes(
            compressed, cumulative_uncompressed_bytes
        )
        if observed_diff != subject[1]:
            raise ValueError("fixture DiffID mismatch")
        diff_ids.append(observed_diff)
        layer_contents.append(gzip.decompress(compressed))
    validate_config(config, ois, diff_ids)
    chain_text = f"sha256:{diff_ids[0].hex()}"
    for diff_id in diff_ids[1:]:
        chain_text = "sha256:" + hashlib.sha256(
            f"{chain_text} sha256:{diff_id.hex()}".encode("ascii")
        ).hexdigest()
    chain = bytes.fromhex(chain_text.removeprefix("sha256:"))
    if chain != ois[7]:
        raise ValueError("fixture ChainID mismatch")
    expected_blob_digests = {
        bytes(ois[4][2]).hex(),
        bytes(ois[5][2]).hex(),
        *(bytes(subject[0][2]).hex() for subject in ois[6]),
    }
    if set(blobs) != expected_blob_digests:
        raise ValueError("fixture contains extra or missing blobs")
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
        validate_elf(content, int(ois[3]), path)


def validate_positive(
    document: dict[str, object],
) -> tuple[dict[str, list[object]], list[object], list[object], dict[str, tuple[str, bytes]]]:
    decoded = {
        item["record"]: validate_vector(item)  # type: ignore[arg-type]
        for item in document["vectors"]  # type: ignore[union-attr]
    }
    ort = decoded["OciRootfsTree"]
    ois = decoded["OciImageSubject"]
    ort_digest = bytes.fromhex(next(
        item["self_digest_hex"]
        for item in document["vectors"]  # type: ignore[union-attr]
        if item["record"] == "OciRootfsTree"
    ))
    blobs = {
        digest: (media, bytes.fromhex(encoded))
        for media, digest, encoded in document["fixture_blobs"]  # type: ignore[union-attr]
    }
    validate_ois(ois, ort, ort_digest, blobs)
    lpv = decoded["LPV"]
    ready = decoded["RDY"]
    release = decoded["RLS"]
    rbs_digest = bytes.fromhex(next(
        item["self_digest_hex"]
        for item in document["vectors"]  # type: ignore[union-attr]
        if item["record"] == "RBS"
    ))
    if len(lpv) != 8 or lpv[0:2] != ["LPV2", 2]:
        raise ValueError("invalid LPV2 shape")
    if lpv[4:7] != [
        bytes.fromhex(next(
            item["self_digest_hex"]
            for item in document["vectors"]  # type: ignore[union-attr]
            if item["record"] == "OciImageSubject"
        )),
        ois[10][0],
        ois[11],
    ]:
        raise ValueError("positive LPV2 equality mismatch")
    if len(ready) != 14 or ready[0:2] != ["RDY2", 2]:
        raise ValueError("invalid ReadyV2 shape")
    lpv_digest = bytes.fromhex(next(
        item["self_digest_hex"]
        for item in document["vectors"]  # type: ignore[union-attr]
        if item["record"] == "LPV"
    ))
    if (
        ready[2:4] != lpv[2:4]
        or ready[5] != ois[9][2]
        or ready[7] != lpv[4]
        or ready[8] != ort_digest
        or ready[9] != ois[10][2]
        or ready[11] != lpv_digest
        or ready[12] != lpv[7]
        or ready[13] != lpv[7]
    ):
        raise ValueError("positive ReadyV2 equality mismatch")
    if len(release) != 16 or release[0:2] != ["RLS2", 2]:
        raise ValueError("invalid ReleaseV2 shape")
    ready_digest = bytes.fromhex(next(
        item["self_digest_hex"]
        for item in document["vectors"]  # type: ignore[union-attr]
        if item["record"] == "RDY"
    ))
    watchdog_values = [value for limit_id, value in decoded["ELM"][2] if limit_id == 4]
    if len(watchdog_values) != 1:
        raise ValueError("ELM2 watchdog limit mismatch")
    expected_deadline = release[13] + watchdog_values[0] * 1_000_000
    if (
        release[2:4] != ready[2:4]
        or release[4] != ready_digest
        or release[11] != rbs_digest
        or release[12] != rbs_digest
        or release[14] != expected_deadline
        or release[15] != decoded["RBS"][9]
    ):
        raise ValueError("positive ReleaseV2 RBS2 equality mismatch")
    return decoded, ort, ois, blobs


def expect_rejection(expected: str, operation: object) -> None:
    try:
        operation()  # type: ignore[operator]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        if expected not in str(error):
            raise ValueError(f"expected rejection {expected!r}, got {error!r}") from error
        return
    raise ValueError(f"case was admitted instead of rejecting with {expected!r}")


def validate_not_revoked(ois_digest: bytes, revoked: list[object]) -> None:
    if ois_digest in revoked:
        raise ValueError("OIS1 self-digest is revoked")


def validate_version_closure(lps: list[object], apt: list[object], lps_digest: bytes) -> None:
    if lps[0:2] != ["LPS2", 2] or lps_digest not in apt[5]:
        raise ValueError("version-1 authority record in version-2 closure")


def validate_exact_fields(
    candidate: list[object],
    positive: list[object],
    record: str,
    field_names: tuple[str, ...],
) -> None:
    if len(candidate) != len(positive) or candidate[0:2] != positive[0:2]:
        raise ValueError(f"invalid {record} shape")
    for index, field_name in enumerate(field_names, start=2):
        if candidate[index] != positive[index]:
            raise ValueError(f"{record} {field_name} mismatch")


def validate_rejections(
    document: dict[str, object],
    decoded: dict[str, list[object]],
    ort: list[object],
    ois: list[object],
    blobs: dict[str, tuple[str, bytes]],
) -> None:
    rejections = {}
    for item in document["rejection_vectors"]:  # type: ignore[union-attr]
        candidate = (
            decode_canonical(
                bytes.fromhex(item["unsigned_cbor_hex"]), item["record"]
            )
            if item["record"] == "RLS2-wrong-signature"
            else validate_vector(item)
        )
        rejections[item["record"]] = (item, candidate)
    ort_digest = bytes.fromhex(next(
        item["self_digest_hex"]
        for item in document["vectors"]  # type: ignore[union-attr]
        if item["record"] == "OciRootfsTree"
    ))
    for name in (
        "OIS1-wrong-architecture",
        "OIS1-wrong-layer-order",
        "OIS1-wrong-DiffID",
        "OIS1-wrong-ChainID",
        "OIS1-wrong-rootfs",
        "OIS1-wrong-executable",
    ):
        item, candidate = rejections[name]
        expect_rejection(
            item["expected_rejection"],
            lambda candidate=candidate: validate_ois(candidate, ort, ort_digest, blobs),
        )
    revoked = rejections["RVS2-revoked-image"][1]
    positive_digest = bytes.fromhex(next(
        item["self_digest_hex"]
        for item in document["vectors"]  # type: ignore[union-attr]
        if item["record"] == "OciImageSubject"
    ))
    expect_rejection(
        "OIS1 self-digest is revoked",
        lambda: validate_not_revoked(positive_digest, revoked[6]),
    )
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
    expect_rejection(
        mixed_item["expected_rejection"],
        lambda: validate_version_closure(
            mixed_lps, apt, bytes.fromhex(mixed_item["self_digest_hex"])
        ),
    )
    mutation_groups = (
        (
            "LPV2",
            decoded["LPV"],
            (
                "LPV2-wrong-attempt", "LPV2-wrong-nonce", "LPV2-wrong-OIS1",
                "LPV2-wrong-path", "LPV2-wrong-arguments", "LPV2-wrong-FDL1",
            ),
            (
                "attempt ID", "nonce", "OIS1", "adapter path", "arguments",
                "expected FDL1",
            ),
        ),
        (
            "ReadyV2",
            decoded["RDY"],
            (
                "RDY2-wrong-attempt", "RDY2-wrong-nonce",
                "RDY2-wrong-mount-namespace", "RDY2-wrong-launcher-digest",
                "RDY2-wrong-launcher-FD", "RDY2-wrong-OIS1",
                "RDY2-wrong-ORT1", "RDY2-wrong-adapter-digest",
                "RDY2-wrong-adapter-FD", "RDY2-wrong-LPV2",
                "RDY2-wrong-expected-FDL1", "RDY2-wrong-observed-FDL1",
            ),
            (
                "attempt ID", "nonce", "mount namespace", "launcher digest",
                "launcher FD", "OIS1", "ORT1", "adapter digest", "adapter FD",
                "LPV2", "expected FDL1", "observed FDL1",
            ),
        ),
        (
            "ReleaseV2",
            decoded["RLS"],
            (
                "RLS2-wrong-attempt", "RLS2-wrong-nonce", "RLS2-wrong-ReadyV2",
                "RLS2-wrong-TRS1", "RLS2-wrong-RVS2", "RLS2-wrong-APT2",
                "RLS2-wrong-trust-epoch", "RLS2-wrong-revocation-epoch",
                "RLS2-wrong-policy-epoch", "RLS2-wrong-expected-RBS2",
                "RLS2-wrong-observed-RBS2", "RLS2-wrong-launch-anchor",
                "RLS2-wrong-deadline", "RLS2-wrong-runtime-key",
            ),
            (
                "attempt ID", "nonce", "ReadyV2", "TRS1", "RVS2", "APT2",
                "trust epoch", "revocation epoch", "policy epoch", "expected RBS2",
                "observed RBS2", "launch anchor", "deadline", "runtime key",
            ),
        ),
    )
    for record, positive, case_names, fields in mutation_groups:
        for case_name in case_names:
            item, candidate = rejections[case_name]
            expect_rejection(
                item["expected_rejection"],
                lambda candidate=candidate, positive=positive, record=record,
                fields=fields: validate_exact_fields(candidate, positive, record, fields),
            )
    signature_item, _ = rejections["RLS2-wrong-signature"]
    expect_rejection(
        signature_item["expected_rejection"],
        lambda: validate_vector(signature_item),
    )


def validate_malformed(document: dict[str, object], ois: list[object]) -> None:
    cases = {item["record"]: item for item in document["malformed_cases"]}  # type: ignore[union-attr]
    expect_rejection(
        cases["OIS1-noncanonical-CBOR"]["expected_rejection"],
        lambda: decode_canonical(
            bytes.fromhex(cases["OIS1-noncanonical-CBOR"]["input_hex"]), "OIS1"
        ),
    )
    expect_rejection(
        cases["manifest-duplicate-key"]["expected_rejection"],
        lambda: load_json_bytes(
            bytes.fromhex(cases["manifest-duplicate-key"]["input_hex"]), "manifest"
        ),
    )
    extra = load_json_bytes(
        bytes.fromhex(cases["manifest-extra-field"]["input_hex"]), "manifest"
    )
    expect_rejection(
        cases["manifest-extra-field"]["expected_rejection"],
        lambda: require_keys(
            extra,
            {"annotations", "config", "layers", "mediaType", "schemaVersion"},
            "manifest",
        ),
    )
    config = load_json_bytes(
        bytes.fromhex(cases["config-DiffID-mismatch"]["input_hex"]), "config"
    )
    expect_rejection(
        cases["config-DiffID-mismatch"]["expected_rejection"],
        lambda: validate_config(config, ois, [subject[1] for subject in ois[6]]),
    )
    expect_rejection(
        cases["layer-uncompressed-limit"]["expected_rejection"],
        lambda: diff_id_bytes(
            bytes.fromhex(cases["layer-uncompressed-limit"]["input_hex"]), 0
        ),
    )

    def validate_cumulative_limit() -> None:
        cumulative = 0
        for encoded in cases["layers-cumulative-limit"]["inputs_hex"]:
            _, cumulative = diff_id_bytes(bytes.fromhex(encoded), cumulative)

    expect_rejection(
        cases["layers-cumulative-limit"]["expected_rejection"],
        validate_cumulative_limit,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("vectors", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    arguments = parser.parse_args()
    document = json.loads(arguments.vectors.read_text(encoding="utf-8"))
    decoded, ort, ois, blobs = validate_positive(document)
    validate_rejections(document, decoded, ort, ois, blobs)
    validate_malformed(document, ois)
    arguments.output.write_text(
        json.dumps(
            {
                "canonical_vectors": len(document["vectors"]),
                "fixture_blobs": len(document["fixture_blobs"]),
                "malformed_rejections": len(document["malformed_cases"]),
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
