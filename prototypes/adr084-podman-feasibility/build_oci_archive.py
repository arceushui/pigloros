#!/usr/bin/env python3
"""Build the exact revision-19 deterministic OCI ustar fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from typing import BinaryIO


def load_json(path: pathlib.Path) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r} in {path}")
            result[key] = value
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
    )
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def blob(layout: pathlib.Path, value: dict[str, object]) -> bytes:
    algorithm, encoded = str(value["digest"]).split(":", 1)
    if algorithm != "sha256" or len(encoded) != 64:
        raise ValueError("source layout uses an unsupported digest")
    content = (layout / "blobs" / "sha256" / encoded).read_bytes()
    if len(content) != value["size"] or sha256(content) != encoded:
        raise ValueError("source layout descriptor mismatch")
    return content


def octal(value: int, digits: int) -> bytes:
    encoded = f"{value:0{digits}o}".encode("ascii")
    if len(encoded) != digits:
        raise ValueError("ustar numeric field overflow")
    return encoded + b"\0"


def header(name: str, size: int, directory: bool) -> bytes:
    encoded_name = name.encode("ascii")
    if not encoded_name or len(encoded_name) > 99:
        raise ValueError("ustar fixture path does not fit the name field")
    result = bytearray(512)
    result[0 : len(encoded_name)] = encoded_name
    result[100:108] = octal(0o755 if directory else 0o644, 7)
    result[108:116] = octal(0, 7)
    result[116:124] = octal(0, 7)
    result[124:136] = octal(size, 11)
    result[136:148] = octal(0, 11)
    result[148:156] = b"        "
    result[156] = ord("5" if directory else "0")
    result[257:263] = b"ustar\0"
    result[263:265] = b"00"
    result[329:337] = octal(0, 7)
    result[337:345] = octal(0, 7)
    checksum = sum(result)
    result[148:156] = f"{checksum:06o}".encode("ascii") + b"\0 "
    return bytes(result)


def write_entry(
    output: BinaryIO, name: str, content: bytes, directory: bool = False
) -> None:
    output.write(header(name, len(content), directory))
    output.write(content)
    padding = (-len(content)) % 512
    if padding:
        output.write(bytes(padding))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_layout", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--image-id", required=True)
    arguments = parser.parse_args()

    source_index = load_json(arguments.source_layout / "index.json")
    manifests = source_index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise ValueError("source layout must contain exactly one manifest")
    source_manifest_descriptor = manifests[0]
    if not isinstance(source_manifest_descriptor, dict):
        raise ValueError("source manifest descriptor is not an object")
    source_manifest = json.loads(
        blob(arguments.source_layout, source_manifest_descriptor)
    )
    if not isinstance(source_manifest, dict):
        raise ValueError("source manifest is not an object")
    source_config_descriptor = source_manifest["config"]
    if not isinstance(source_config_descriptor, dict):
        raise ValueError("source config descriptor is not an object")
    config = json.loads(blob(arguments.source_layout, source_config_descriptor))
    config_bytes = canonical_json(config)
    config_digest = sha256(config_bytes)

    layers = source_manifest["layers"]
    if not isinstance(layers, list) or not layers:
        raise ValueError("source manifest has no layers")
    layer_blobs = {}
    for layer in layers:
        if not isinstance(layer, dict):
            raise ValueError("source layer descriptor is not an object")
        content = blob(arguments.source_layout, layer)
        layer_blobs[sha256(content)] = content

    manifest = {
        "annotations": {
            "org.opencontainers.image.base.digest": "",
            "org.opencontainers.image.base.name": "",
        },
        "config": {
            "digest": f"sha256:{config_digest}",
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(config_bytes),
        },
        "layers": layers,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2,
    }
    manifest_bytes = canonical_json(manifest)
    manifest_digest = sha256(manifest_bytes)
    index = {
        "manifests": [
            {
                "annotations": {
                    "org.opencontainers.image.ref.name": arguments.image_id
                },
                "digest": f"sha256:{manifest_digest}",
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {
                    "architecture": arguments.architecture,
                    "os": "linux",
                },
                "size": len(manifest_bytes),
            }
        ],
        "schemaVersion": 2,
    }
    files = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": canonical_json(index),
        f"blobs/sha256/{config_digest}": config_bytes,
        f"blobs/sha256/{manifest_digest}": manifest_bytes,
        **{
            f"blobs/sha256/{digest}": content
            for digest, content in layer_blobs.items()
        },
    }
    with arguments.output.open("wb") as output:
        write_entry(output, "blobs/", b"", True)
        write_entry(output, "blobs/sha256/", b"", True)
        write_entry(output, "oci-layout", files.pop("oci-layout"))
        write_entry(output, "index.json", files.pop("index.json"))
        for name in sorted(files, key=str.encode):
            write_entry(output, name, files[name])
        output.write(bytes(1024))


if __name__ == "__main__":
    main()
