#!/usr/bin/env python3
"""Resolve the workspace packages a pull request can affect.

``ci_change_scope`` runs this script from the pull request's trusted base
revision. It reads the pull request's changed files (JSON lines from the
GitHub pull-request files API, ``{"filename": ..., "previous_filename": ...}``)
and prints two lines:

    rust_packages=<--workspace | -p a -p b ...>
    rust_doc_packages=<--workspace | none | -p a ...>

``--workspace`` is the full gate. The script prints it whenever the answer is
not certain:

* the listing is malformed, or holds a different number of files than the
  pull request reports (the API stops at 3000 files);
* a changed path (a renamed file's old and new path both count) is outside
  every workspace member directory and is not documentation-only under the
  ``rust`` excludes of ``.github/rust-scope.yml`` (so the root manifest,
  ``Cargo.lock``, toolchain, ``.cargo/``, ``.config/``, ``scripts/``,
  ``fixtures/``, workflows and any new directory all run everything);
* the workspace manifests cannot be read or resolved.

Otherwise the affected set is every member that contains a changed path,
every member whose Rust sources name a changed path or a file of an affected
member (see ``scan_reads``), and, transitively, every member that depends on
an affected member through any dependency kind or reads its files.

Why the base revision's graph is sufficient: an internal path dependency is
recorded in ``Cargo.lock`` (dev, build and target-specific dependencies
included), and every Cargo command in CI runs with ``--locked``. A pull
request that adds, removes or renames a member, a package or an internal
dependency therefore changes ``Cargo.lock`` or the root manifest, which are
outside every member and select the full workspace. A source read that the
head revision adds lives in a changed file, so its reader is affected directly.

``rust_doc_packages`` narrows the set to members with a library target, since
``cargo test --doc`` refuses a package selection without one. ``none`` means
the affected members have no library target and so no doctest.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import posixpath
import re
import sys
import tomllib
from dataclasses import dataclass, field

FULL = "--workspace"
NO_DOCTESTS = "none"
SCOPE_FILTER = pathlib.Path(".github") / "rust-scope.yml"
PACKAGE_NAME = re.compile(r"[A-Za-z0-9_-]+")
DEPENDENCY_TABLES = (
    "dependencies",
    "dev-dependencies",
    "dev_dependencies",
    "build-dependencies",
    "build_dependencies",
)
STRING_LITERAL = re.compile(r'"((?:[^"\\\n]|\\.)*)"')


class ScopeError(Exception):
    """The affected set cannot be determined; the caller runs the workspace."""


@dataclass
class Member:
    path: str
    name: str
    has_lib: bool
    dependencies: set[str] = field(default_factory=set)


def is_within(path: str, directory: str) -> bool:
    """Whether ``path`` is ``directory`` or below it (``"."`` is the root)."""
    return directory == "." or path == directory or path.startswith(directory + "/")


def load_toml(path: pathlib.Path) -> dict:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ScopeError(f"cannot read {path}: {error}") from error


def relative(base: str, target: str) -> str | None:
    """Normalise ``target`` against workspace-relative ``base``; None if outside."""
    joined = posixpath.normpath(posixpath.join(base, target))
    if joined == ".." or joined.startswith("../") or posixpath.isabs(joined):
        return None
    return joined


def member_paths(root: pathlib.Path, workspace: dict) -> list[str]:
    patterns = workspace.get("members")
    excluded = workspace.get("exclude", [])
    if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
        raise ScopeError("[workspace] members must be a list of strings")
    if not isinstance(excluded, list) or not all(isinstance(p, str) for p in excluded):
        raise ScopeError("[workspace] exclude must be a list of strings")
    excluded_paths = {posixpath.normpath(path) for path in excluded}
    paths: set[str] = set()
    for pattern in patterns:
        if any(character in pattern for character in "*?["):
            matches = [
                match.relative_to(root).as_posix()
                for match in root.glob(pattern)
                if (match / "Cargo.toml").is_file()
            ]
        else:
            matches = [posixpath.normpath(pattern)]
        for path in matches:
            if relative(".", path) in (None, "."):
                raise ScopeError(f"workspace member {path} is not below the root")
            if path not in excluded_paths:
                paths.add(path)
    if not paths:
        raise ScopeError("the workspace has no members")
    return sorted(paths)


def dependency_tables(manifest: dict) -> list[dict]:
    tables = [manifest.get(name) for name in DEPENDENCY_TABLES]
    targets = manifest.get("target", {})
    if not isinstance(targets, dict):
        raise ScopeError("[target] must be a table")
    for target in targets.values():
        if not isinstance(target, dict):
            raise ScopeError("[target.<cfg>] must be a table")
        tables.extend(target.get(name) for name in DEPENDENCY_TABLES)
    resolved = []
    for table in tables:
        if table is None:
            continue
        if not isinstance(table, dict):
            raise ScopeError("dependency tables must be tables")
        resolved.append(table)
    return resolved


def dependency_path(member: str, key: str, spec: object, inherited: dict) -> str | None:
    """The workspace-relative path of a path dependency, else None."""
    if not isinstance(spec, dict):
        return None
    if spec.get("workspace") is True:
        shared = inherited.get(key)
        if isinstance(shared, dict) and isinstance(shared.get("path"), str):
            return relative(".", shared["path"])
        return None
    if isinstance(spec.get("path"), str):
        return relative(member, spec["path"])
    return None


def has_library(root: pathlib.Path, path: str, manifest: dict) -> bool:
    if "lib" in manifest:
        return True
    package = manifest.get("package", {})
    if package.get("autolib") is False:
        return False
    return (root / path / "src" / "lib.rs").is_file()


def load_workspace(root: pathlib.Path) -> dict[str, Member]:
    workspace_manifest = load_toml(root / "Cargo.toml")
    workspace = workspace_manifest.get("workspace")
    if not isinstance(workspace, dict):
        raise ScopeError("the root manifest has no [workspace]")
    inherited = workspace.get("dependencies", {})
    if not isinstance(inherited, dict):
        raise ScopeError("[workspace.dependencies] must be a table")
    paths = member_paths(root, workspace)
    manifests = {path: load_toml(root / path / "Cargo.toml") for path in paths}
    members: dict[str, Member] = {}
    names: set[str] = set()
    for path, manifest in manifests.items():
        package = manifest.get("package")
        name = package.get("name") if isinstance(package, dict) else None
        if not isinstance(name, str) or PACKAGE_NAME.fullmatch(name) is None:
            raise ScopeError(f"{path}/Cargo.toml has no usable package name")
        if name in names:
            raise ScopeError(f"duplicate package name {name}")
        names.add(name)
        members[path] = Member(path, name, has_library(root, path, manifest))
    for path, manifest in manifests.items():
        for table in dependency_tables(manifest):
            for key, spec in table.items():
                target = dependency_path(path, key, spec, inherited)
                if target in members and target != path:
                    members[path].dependencies.add(target)
    return members


def owner(path: str, members: dict[str, Member] | list[str]) -> str | None:
    """The member whose directory contains ``path`` (longest prefix wins)."""
    found = None
    for member in members:
        if is_within(path, member) and (found is None or len(member) > len(found)):
            found = member
    return found


def literal_targets(
    literal: str, file_dir: str, member: str, member_list: list[str]
) -> set[str]:
    """Workspace paths a string literal in a member's source may name.

    A literal with a ``..`` segment is resolved against both the source file's
    directory (``include_bytes!``/``include_str!``) and the member directory
    (``env!("CARGO_MANIFEST_DIR")`` joins); a leading ``/`` from a ``concat!``
    with the manifest directory is dropped. A literal naming another member's
    directory or a path below it (``"crates/pos-reference/src/x.rs"``, joined to
    a computed workspace root) is taken as workspace-relative.
    """
    targets: set[str] = set()
    stripped = literal.strip()
    while stripped.startswith("./"):
        stripped = stripped[2:]
    if ".." in stripped.strip("/").split("/") and stripped.strip("/") != "..":
        for base in (file_dir, member):
            resolved = relative(base, stripped.lstrip("/"))
            if resolved is not None:
                targets.add(resolved)
    for other in member_list:
        if re.search(r"(?:^|[^A-Za-z0-9_./-])" + re.escape(other) + r"(?:/|$)", stripped):
            targets.add(other)
    return targets


@dataclass
class Reads:
    """Workspace paths each member's Rust sources name.

    ``library`` holds what a member's library, binaries or build script name
    (``src/``, ``build.rs`` and anything else outside the test-only target
    directories): a change there can change what the member's dependents link.
    ``tests`` holds what only its ``tests/``, ``benches/`` and ``examples/``
    targets name, which no dependent can observe.
    """

    library: dict[str, set[str]]
    tests: dict[str, set[str]]


TEST_ONLY_DIRECTORIES = ("tests", "benches", "examples")


def scan_reads(root: pathlib.Path, members: dict[str, Member]) -> Reads:
    """Scan every ``.rs`` file each member owns for the paths it names.

    This is a conservative text scan of string literals (see
    ``literal_targets``). Evidence in the tree when it was written:
    ``pos-runtime``'s library embeds gateway, Plugin and ``pos-experiment``
    sources with ``include_bytes!`` (``src/output_admission.rs``), so they
    change what its dependents link; ``pos-store``, ``pos-time`` and
    ``pos-runtime`` include test support from ``pos-core`` and ``pos-store``;
    ``pos-sandboxd`` reads ``pos-conformance`` vectors and
    ``pos-reference``/``pos-root-selector`` sources; ``pos-plugin-worker``
    includes the gateway pipeline harness; ``pos-experiment`` reads
    ``pos-reference``; ``pos-reference`` names ``plugins/eval`` in an import
    policy test; and the ``pos-root-selector`` and ``pos-experiment`` tests join
    ``CARGO_MANIFEST_DIR`` to ``../..``, the workspace root, which counts as
    naming every path. Paths assembled at run time from non-literal parts are
    not visible to the scan; the merge queue always runs the whole workspace.
    """
    member_list = sorted(members)
    reads = Reads({path: set() for path in members}, {path: set() for path in members})
    for member in member_list:
        for source in sorted((root / member).rglob("*.rs")):
            relative_source = source.relative_to(root).as_posix()
            if owner(relative_source, member_list) != member:
                continue
            inside = relative_source[len(member) + 1 :]
            test_only = inside.split("/", 1)[0] in TEST_ONLY_DIRECTORIES
            bucket = (reads.tests if test_only else reads.library)[member]
            file_dir = posixpath.dirname(relative_source)
            text = source.read_text(encoding="utf-8", errors="replace")
            for literal in STRING_LITERAL.findall(text):
                for target in literal_targets(literal, file_dir, member, member_list):
                    if not is_within(target, member):
                        bucket.add(target)
    return reads


def glob_regex(pattern: str) -> re.Pattern[str]:
    """picomatch's ``dot: true`` subset used by ``.github/rust-scope.yml``."""
    if any(character in pattern for character in "{}[]()+@!"):
        raise ScopeError(f"unsupported scope pattern: {pattern}")
    parts = pattern.split("/")
    regex = ""
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        if part == "**":
            regex += ".*" if last else "(?:[^/]+/)*"
            continue
        if "**" in part:
            raise ScopeError(f"unsupported scope pattern: {pattern}")
        regex += "".join(
            "[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in part
        )
        if not last:
            regex += "/"
    return re.compile(regex)


def documentation_excludes(root: pathlib.Path) -> list[re.Pattern[str]]:
    """The negated ``rust`` patterns of the trusted scope filter.

    The filter is a flat YAML list; this reads only the ``rust:`` block. Any
    shape it does not recognise yields no excludes, which can only widen the
    selection.
    """
    try:
        lines = (root / SCOPE_FILTER).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    excludes: list[re.Pattern[str]] = []
    inside = False
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "-")):
            inside = line.rstrip() == "rust:"
            continue
        if not inside:
            continue
        match = re.fullmatch(r"\s*-\s*(['\"])(.*)\1\s*", line)
        if match is None:
            return []
        if match.group(2).startswith("!"):
            try:
                excludes.append(glob_regex(match.group(2)[1:]))
            except ScopeError:
                return []
    return excludes


def parse_listing(text: str, expected: int) -> list[str]:
    """Changed paths from the files API, refusing a truncated or odd listing."""
    paths: list[str] = []
    entries = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise ScopeError(f"malformed changed-file entry: {line!r}") from error
        if not isinstance(entry, dict):
            raise ScopeError(f"malformed changed-file entry: {line!r}")
        entries += 1
        for key in ("filename", "previous_filename"):
            value = entry.get(key)
            if value is None and key == "previous_filename":
                continue
            if (
                not isinstance(value, str)
                or not value
                or value.startswith("/")
                or "\\" in value
                or posixpath.normpath(value) != value
                or value.startswith("..")
            ):
                raise ScopeError(f"unattributable changed path: {value!r}")
            paths.append(value)
    if entries != expected:
        raise ScopeError(f"listed {entries} changed files, expected {expected}")
    if not paths:
        raise ScopeError("the pull request lists no changed file")
    return paths


def names_member(targets: set[str], member: str) -> bool:
    """Whether a named path is inside ``member`` or at or above its directory."""
    return any(is_within(target, member) or is_within(member, target) for target in targets)


def affected_members(
    paths: list[str],
    members: dict[str, Member],
    reads: Reads,
    excludes: list[re.Pattern[str]],
) -> set[str]:
    """Every member whose build or tests a change to ``paths`` can affect."""
    member_list = sorted(members)
    changed: set[str] = set()
    named: set[str] = set()
    for path in paths:
        home = owner(path, member_list)
        if home is not None:
            changed.add(home)
            continue
        if not any(pattern.fullmatch(path) for pattern in excludes):
            raise ScopeError(f"{path} is outside every workspace member")
        named.add(path)

    def reads_change(targets: set[str]) -> bool:
        return any(is_within(path, target) for target in targets for path in named)

    # Members whose library, binaries or build output may differ: close over
    # every dependency kind and over library-side reads.
    built = changed | {m for m in member_list if reads_change(reads.library[m])}
    growing = True
    while growing:
        growing = False
        for member in member_list:
            if member in built:
                continue
            if members[member].dependencies & built or any(
                names_member(reads.library[member], other) for other in built
            ):
                built.add(member)
                growing = True
    # Test-only readers rerun their own tests; nothing links them.
    tested = {
        member
        for member in member_list
        if reads_change(reads.tests[member])
        or any(names_member(reads.tests[member], other) for other in built)
    }
    return built | tested


def selection(paths: list[str], root: pathlib.Path) -> tuple[str, str]:
    members = load_workspace(root)
    reads = scan_reads(root, members)
    affected = affected_members(paths, members, reads, documentation_excludes(root))
    names = sorted(members[path].name for path in affected)
    if not names:
        # Only documentation outside the members changed; the Rust gate is
        # skipped upstream for such a pull request, so be explicit and full.
        raise ScopeError("no workspace member is affected")
    libraries = sorted(members[path].name for path in affected if members[path].has_lib)
    packages = " ".join(f"-p {name}" for name in names)
    doc_packages = " ".join(f"-p {name}" for name in libraries) or NO_DOCTESTS
    return packages, doc_packages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("listing", type=pathlib.Path, help="JSON lines from the files API")
    parser.add_argument("--expected-files", type=int, required=True)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd())
    arguments = parser.parse_args(argv)
    try:
        if not 0 < arguments.expected_files < 3000:
            raise ScopeError("the changed-file list may be truncated")
        try:
            text = arguments.listing.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ScopeError(f"cannot read the changed-file listing: {error}") from error
        paths = parse_listing(text, arguments.expected_files)
        packages, doc_packages = selection(paths, arguments.root.resolve())
    except ScopeError as error:
        print(f"Running the whole workspace: {error}", file=sys.stderr)
        packages, doc_packages = FULL, FULL
    print(f"rust_packages={packages}")
    print(f"rust_doc_packages={doc_packages}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
