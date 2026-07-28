#!/usr/bin/env python3
"""Validate semantic GitHub Action references in workflow and Action YAML."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

SUPPORTED_PYYAML_VERSIONS = {"5.4.1", "6.0.2"}
EXTERNAL_ACTION = re.compile(r"[^/@\s]+/[^@\s]+@[0-9a-f]{40}\Z")
DOCKER_ACTION = re.compile(r"docker://[^@\s]+@sha256:[0-9a-f]{64}\Z")


class PolicyError(Exception):
    """A checked configuration violates the pinning policy."""


class UniqueKeySafeLoader(yaml.SafeLoader):
    """SafeLoader with YAML 1.2 booleans and duplicate-key rejection."""

    yaml_implicit_resolvers = {
        key: list(resolvers)
        for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(None, None, "expected a mapping node", node.start_mark)
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from error
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


for resolver_key, resolvers in UniqueKeySafeLoader.yaml_implicit_resolvers.items():
    UniqueKeySafeLoader.yaml_implicit_resolvers[resolver_key] = [
        resolver for resolver in resolvers if resolver[0] != "tag:yaml.org,2002:bool"
    ]
UniqueKeySafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


class ReferenceInspector:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)
        self.state: dict[Path, str] = {}

    def run(self) -> None:
        roots = sorted(self.root.glob(".github/workflows/**/*.yml"))
        roots.extend(sorted(self.root.glob(".github/workflows/**/*.yaml")))
        roots.extend(sorted(self.root.glob(".github/actions/**/action.yml")))
        roots.extend(sorted(self.root.glob(".github/actions/**/action.yaml")))
        for config_file in roots:
            self.inspect_config(config_file)

    def inspect_config(self, config_file: Path) -> None:
        if not config_file.is_file():
            raise PolicyError(f"referenced YAML file does not exist: {self.display(config_file)}")
        canonical = config_file.resolve(strict=True)
        self.require_inside_root(canonical, "referenced YAML file escapes repository root")
        state = self.state.get(canonical)
        if state == "visiting":
            raise PolicyError(f"local uses cycle detected at {self.display(canonical)}")
        if state == "done":
            return
        self.state[canonical] = "visiting"
        data = self.load_yaml(canonical)
        self.walk(data, canonical, set(), set())
        self.state[canonical] = "done"

    def load_yaml(self, config_file: Path) -> dict[Any, Any]:
        try:
            with config_file.open(encoding="utf-8") as stream:
                documents = list(yaml.load_all(stream, Loader=UniqueKeySafeLoader))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise PolicyError(f"cannot safely parse {self.display(config_file)}: {error}") from error
        if len(documents) != 1 or not isinstance(documents[0], dict):
            raise PolicyError(
                f"checked YAML must contain exactly one mapping document: {self.display(config_file)}"
            )
        return documents[0]

    def walk(
        self,
        value: Any,
        source_file: Path,
        visiting: set[int],
        visited: set[int],
    ) -> None:
        if not isinstance(value, (dict, list)):
            return
        identity = id(value)
        if identity in visiting:
            raise PolicyError(f"collection alias cycle in {self.display(source_file)}")
        if identity in visited:
            return
        visiting.add(identity)
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "uses":
                    if not isinstance(child, str):
                        raise PolicyError(
                            f"uses must resolve to a string in {self.display(source_file)}"
                        )
                    self.inspect_reference(child, source_file)
                self.walk(child, source_file, visiting, visited)
        else:
            for child in value:
                self.walk(child, source_file, visiting, visited)
        visiting.remove(identity)
        visited.add(identity)

    def inspect_reference(self, reference: str, source_file: Path) -> None:
        if reference.startswith("./"):
            self.inspect_local_reference(reference, source_file)
        elif reference.startswith("docker://"):
            if DOCKER_ACTION.fullmatch(reference) is None:
                raise PolicyError(
                    f"Docker Action is not pinned to a sha256 digest: {reference} "
                    f"({self.display(source_file)})"
                )
        elif EXTERNAL_ACTION.fullmatch(reference) is None:
            raise PolicyError(
                f"external Action reference is not pinned to a 40-hex revision: {reference} "
                f"({self.display(source_file)})"
            )

    def inspect_local_reference(self, reference: str, source_file: Path) -> None:
        target = (self.root / reference.removeprefix("./")).resolve(strict=False)
        self.require_inside_root(
            target,
            f"local uses reference escapes repository root: {reference} "
            f"({self.display(source_file)})",
        )
        if target.suffix in {".yml", ".yaml"}:
            workflows = (self.root / ".github/workflows").resolve(strict=False)
            if workflows not in target.parents:
                raise PolicyError(
                    f"local reusable workflow must be under .github/workflows: {reference} "
                    f"({self.display(source_file)})"
                )
            self.inspect_config(target)
            return
        if not target.is_dir():
            raise PolicyError(
                f"local Action directory does not exist: {reference} ({self.display(source_file)})"
            )
        canonical = target.resolve(strict=True)
        self.require_inside_root(
            canonical,
            f"local Action directory escapes repository root: {reference} "
            f"({self.display(source_file)})",
        )
        metadata = [path for path in (canonical / "action.yml", canonical / "action.yaml") if path.is_file()]
        if len(metadata) > 1:
            raise PolicyError(f"local Action has ambiguous metadata: {reference}")
        if not metadata:
            raise PolicyError(
                f"local Action is missing action.yml or action.yaml: {reference} "
                f"({self.display(source_file)})"
            )
        self.inspect_config(metadata[0])

    def require_inside_root(self, path: Path, message: str) -> None:
        if path != self.root and self.root not in path.parents:
            raise PolicyError(message)

    def display(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)


def main() -> int:
    if yaml.__version__ not in SUPPORTED_PYYAML_VERSIONS:
        supported = ", ".join(sorted(SUPPORTED_PYYAML_VERSIONS))
        print(
            f"ERROR: unsupported PyYAML {yaml.__version__}; expected one of: {supported}",
            file=sys.stderr,
        )
        return 1
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    try:
        ReferenceInspector(root).run()
    except (OSError, PolicyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Pinned YAML reference policy OK (PyYAML {yaml.__version__}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
