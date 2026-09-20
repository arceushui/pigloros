#!/usr/bin/env python3
"""Validate the bounded OCI archive shape used by the ADR-084 prototype."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re

from oci_layer import diff_id


def require_keys(value: dict[str, object], allowed: set[str], context: str) -> None:
    unexpected = set(value) - allowed
    if unexpected:
        raise ValueError(f"unexpected {context} fields: {sorted(unexpected)}")


def load_json(path: pathlib.Path) -> object:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate)


def require_timestamp(value: object, context: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
        value,
    ):
        raise ValueError(f"invalid {context} timestamp")


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
    require_keys(index, {"schemaVersion", "manifests"}, "index")
    if index.get("schemaVersion") != 2:
        raise ValueError("unexpected index schema version")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise ValueError("OCI index must select exactly one manifest")
    index_descriptor = manifests[0]
    if not isinstance(index_descriptor, dict):
        raise ValueError("index manifest descriptor is not an object")
    require_keys(
        index_descriptor,
        {"annotations", "digest", "mediaType", "size"},
        "index descriptor",
    )
    annotations = index_descriptor.get("annotations")
    if not isinstance(annotations, dict) or set(annotations) != {
        "org.opencontainers.image.ref.name"
    } or not isinstance(annotations["org.opencontainers.image.ref.name"], str):
        raise ValueError("unexpected transport-only index annotation")
    if index_descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise ValueError("unexpected index descriptor media type")
    manifest_path = blob(layout, index_descriptor)
    manifest = load_json(manifest_path)
    assert isinstance(manifest, dict)
    require_keys(
        manifest,
        {"annotations", "schemaVersion", "mediaType", "config", "layers"},
        "manifest",
    )
    if manifest.get("annotations") != {
        "org.opencontainers.image.base.digest": "",
        "org.opencontainers.image.base.name": "",
    }:
        raise ValueError("unexpected manifest provenance annotations")
    if manifest.get("schemaVersion") != 2:
        raise ValueError("unexpected manifest schema version")
    if manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise ValueError("unexpected manifest media type")
    config_descriptor = manifest.get("config")
    layers = manifest.get("layers")
    if not isinstance(config_descriptor, dict) or not isinstance(layers, list) or not layers:
        raise ValueError("manifest config/layer closure is incomplete")
    require_keys(config_descriptor, {"digest", "mediaType", "size"}, "config descriptor")
    if config_descriptor.get("mediaType") != "application/vnd.oci.image.config.v1+json":
        raise ValueError("unexpected config media type")
    for layer in layers:
        if not isinstance(layer, dict):
            raise ValueError("layer descriptor is not an object")
        require_keys(layer, {"digest", "mediaType", "size"}, "layer descriptor")
        if layer.get("mediaType") != "application/vnd.oci.image.layer.v1.tar+gzip":
            raise ValueError("unexpected layer media type")
    config_path = blob(layout, config_descriptor)
    layer_paths = [blob(layout, item) for item in layers]
    config = load_json(config_path)
    assert isinstance(config, dict)
    require_keys(
        config,
        {"architecture", "config", "created", "history", "os", "rootfs"},
        "image config",
    )
    if config.get("architecture") != arguments.architecture or config.get("os") != "linux":
        raise ValueError(
            f"wrong native platform: {config.get('os')}/{config.get('architecture')}"
        )
    runtime = config.get("config") or {}
    if not isinstance(runtime, dict):
        raise ValueError("image runtime config is not an object")
    require_keys(runtime, {"Entrypoint", "User", "WorkingDir"}, "runtime config")
    if runtime != {
        "Entrypoint": ["/launcher"],
        "User": "65532:65532",
        "WorkingDir": "/",
    }:
        raise ValueError(f"unexpected runtime config: {runtime}")
    require_timestamp(config.get("created"), "config created")
    history = config.get("history")
    if not isinstance(history, list) or not history or len(history) > 128:
        raise ValueError("invalid image history")
    for item in history:
        if not isinstance(item, dict):
            raise ValueError("history entry is not an object")
        if not set(item).issubset({"created", "created_by", "comment", "empty_layer"}):
            raise ValueError("unexpected history entry fields")
        require_timestamp(item.get("created"), "history created")
        for key, limit in (("created_by", 4096), ("comment", 256)):
            if key in item and (
                not isinstance(item[key], str)
                or len(item[key].encode("utf-8")) > limit
            ):
                raise ValueError(f"invalid history {key}")
        if "empty_layer" in item and not isinstance(item["empty_layer"], bool):
            raise ValueError("invalid history empty_layer")
    rootfs = config.get("rootfs")
    if not isinstance(rootfs, dict) or len(rootfs.get("diff_ids", [])) != len(layers):
        raise ValueError("layer/DiffID cardinality mismatch")
    require_keys(rootfs, {"diff_ids", "type"}, "rootfs config")
    if rootfs.get("type") != "layers":
        raise ValueError("unsupported rootfs type")
    verified_diff_ids: list[str] = []
    cumulative_uncompressed_bytes = 0
    for path, expected in zip(layer_paths, rootfs["diff_ids"], strict=True):
        with path.open("rb") as stream:
            observed_bytes, cumulative_uncompressed_bytes = diff_id(
                stream, cumulative_uncompressed_bytes
            )
        observed = "sha256:" + observed_bytes.hex()
        if observed != expected:
            raise ValueError(f"layer DiffID mismatch: expected {expected}, observed {observed}")
        verified_diff_ids.append(observed)
    chain_id = verified_diff_ids[0]
    for layer_diff_id in verified_diff_ids[1:]:
        chain_id = "sha256:" + hashlib.sha256(
            f"{chain_id} {layer_diff_id}".encode("ascii")
        ).hexdigest()
    reachable = {manifest_path.resolve(), config_path.resolve(), *(path.resolve() for path in layer_paths)}
    actual = {path.resolve() for path in (layout / "blobs" / "sha256").iterdir() if path.is_file()}
    if actual != reachable:
        raise ValueError("OCI layout contains extra or missing blobs")
    evidence = {
        "config": config_descriptor,
        "config_json": config,
        "index": index,
        "layers": layers,
        "manifest": manifests[0],
        "native_platform": f"linux/{arguments.architecture}",
        "verified_chain_id": chain_id,
        "verified_diff_ids": verified_diff_ids,
        "verified_uncompressed_bytes": cumulative_uncompressed_bytes,
        "verified_blob_paths": [str(config_path), str(manifest_path), *map(str, layer_paths)],
    }
    arguments.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
