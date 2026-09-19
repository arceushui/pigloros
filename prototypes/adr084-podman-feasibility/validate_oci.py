#!/usr/bin/env python3
"""Validate the bounded OCI archive shape used by the ADR-084 prototype."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pathlib


def load_json(path: pathlib.Path) -> object:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate)


def blob(root: pathlib.Path, descriptor: dict[str, object]) -> pathlib.Path:
    algorithm, encoded = str(descriptor["digest"]).split(":", 1)
    if algorithm != "sha256" or len(encoded) != 64:
        raise ValueError(f"unsupported digest {descriptor['digest']}")
    path = root / "blobs" / algorithm / encoded
    content = path.read_bytes()
    if len(content) != descriptor["size"]:
        raise ValueError(f"size mismatch for {path}")
    if hashlib.sha256(content).hexdigest() != encoded:
        raise ValueError(f"digest mismatch for {path}")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("layout", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    arguments = parser.parse_args()
    layout = arguments.layout
    if load_json(layout / "oci-layout") != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("unexpected oci-layout")
    index = load_json(layout / "index.json")
    assert isinstance(index, dict)
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise ValueError("OCI index must select exactly one manifest")
    manifest_path = blob(layout, manifests[0])
    manifest = load_json(manifest_path)
    assert isinstance(manifest, dict)
    if manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise ValueError("unexpected manifest media type")
    config_descriptor = manifest.get("config")
    layers = manifest.get("layers")
    if not isinstance(config_descriptor, dict) or not isinstance(layers, list) or not layers:
        raise ValueError("manifest config/layer closure is incomplete")
    config_path = blob(layout, config_descriptor)
    layer_paths = [blob(layout, item) for item in layers]
    config = load_json(config_path)
    assert isinstance(config, dict)
    if config.get("architecture") != arguments.architecture or config.get("os") != "linux":
        raise ValueError(
            f"wrong native platform: {config.get('os')}/{config.get('architecture')}"
        )
    runtime = config.get("config") or {}
    if not isinstance(runtime, dict):
        raise ValueError("image runtime config is not an object")
    forbidden = ("Env", "Cmd", "Volumes", "ExposedPorts", "Labels", "Healthcheck")
    unexpected = {key: runtime[key] for key in forbidden if runtime.get(key) not in (None, [], {})}
    if unexpected:
        raise ValueError(f"unsafe OCI runtime defaults: {unexpected}")
    if runtime.get("Entrypoint") != ["/launcher"] or runtime.get("User") != "65532:65532":
        raise ValueError(f"unexpected entrypoint/user: {runtime}")
    rootfs = config.get("rootfs")
    if not isinstance(rootfs, dict) or len(rootfs.get("diff_ids", [])) != len(layers):
        raise ValueError("layer/DiffID cardinality mismatch")
    if rootfs.get("type") != "layers":
        raise ValueError("unsupported rootfs type")
    verified_diff_ids: list[str] = []
    for path, expected in zip(layer_paths, rootfs["diff_ids"], strict=True):
        compressed = path.read_bytes()
        uncompressed = gzip.decompress(compressed) if compressed.startswith(b"\x1f\x8b") else compressed
        observed = "sha256:" + hashlib.sha256(uncompressed).hexdigest()
        if observed != expected:
            raise ValueError(f"layer DiffID mismatch: expected {expected}, observed {observed}")
        verified_diff_ids.append(observed)
    chain_id = verified_diff_ids[0]
    for diff_id in verified_diff_ids[1:]:
        chain_id = "sha256:" + hashlib.sha256(f"{chain_id} {diff_id}".encode("ascii")).hexdigest()
    evidence = {
        "config": config_descriptor,
        "config_json": config,
        "index": index,
        "layers": layers,
        "manifest": manifests[0],
        "native_platform": f"linux/{arguments.architecture}",
        "verified_chain_id": chain_id,
        "verified_diff_ids": verified_diff_ids,
        "verified_blob_paths": [str(config_path), str(manifest_path), *map(str, layer_paths)],
    }
    arguments.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
