#!/usr/bin/env python3
"""Generate and check the third-party notice bundle (#545).

The bundle covers the crates in the non-dev dependency graph of every
workspace binary, the crates in each Rust guest fixture's own Cargo.lock, and
the non-Cargo components that the committed compatibility fixtures statically
contain (wasi-libc, the BLAKE3 C sources, compiler-rt, Rust core/alloc).

Commands:

* ``check`` runs every offline check: the cargo-about configurations mirror
  deny.toml, the notice manifest is well formed, every committed notice text
  matches its recorded digest, and every committed fixture is mapped.
* ``verify-upstream`` re-fetches every notice text from its recorded upstream
  commit, checks that each tag and submodule still resolves to that commit,
  and compares the digests with the committed bytes. It needs the network.
* ``rust-std-report`` checks that the toolchain's rust-src ``library/`` lockfile
  and std manifest are the ones at the pinned Rust tag, then runs cargo-about
  on std for wasm32-unknown-unknown with the features the Rust release builds
  std with. That graph is the crates.io code std links into the Rust guests.
* ``assemble`` runs ``check``, validates each cargo-about JSON report, and
  writes ``THIRD-PARTY-NOTICES.txt`` and ``third-party-notices.json``. It fails
  on an unknown or unaccepted licence and on any crate or component with no
  licence text.

The output depends only on the committed inputs and the locked graphs, so two
runs on one commit write identical bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTICES_DIR = Path("third_party/notices")
MANIFEST = NOTICES_DIR / "manifest.toml"
DENY = Path("deny.toml")
HOST_ABOUT = Path("about.toml")
GUEST_ABOUT = Path("third_party/about-guest.toml")
HOST_LOCK = "Cargo.lock"
GUEST_ROOT = Path("plugins/community/examples")
GUEST_TARGETS = ["wasm32-unknown-unknown"]
RUST_STD = "rust-std"
RUST_SRC = Path("lib/rustlib/src/rust")
RUST_STD_RLIBS = Path("lib/rustlib/wasm32-unknown-unknown/lib")
RUST_STD_KEYS = [
    "component",
    "features",
    "lockfile",
    "lockfile_sha256",
    "std_manifest",
    "std_manifest_sha256",
]
ABOUT_GLOBAL_KEYS = frozenset(
    {
        "accepted",
        "targets",
        "private",
        "max-depth",
        "ignore-build-dependencies",
        "ignore-dev-dependencies",
        "ignore-transitive-dependencies",
        "workarounds",
    }
)
TEXT_NAME = "THIRD-PARTY-NOTICES.txt"
INDEX_NAME = "third-party-notices.json"
RULE = "=" * 78
FETCH_ATTEMPTS = 3


class NoticeError(Exception):
    """A violation that stops the bundle from being generated."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_toml(root: Path, relative: Path) -> dict:
    with (root / relative).open("rb") as handle:
        return tomllib.load(handle)


# ── Licence policy mirror ────────────────────────────────────────────────────


def deny_policy(deny: dict) -> tuple[list[str], dict[str, list[str]]]:
    """Return deny.toml's allow list and its crate-scoped exceptions."""
    licences = deny.get("licenses", {})
    exceptions: dict[str, list[str]] = {}
    for entry in licences.get("exceptions", []):
        name = entry.get("crate", entry.get("name"))
        if not isinstance(name, str) or "@" in name or ":" in name:
            raise NoticeError(
                f"deny.toml exception {entry!r} must name one crate without a version"
            )
        exceptions[name] = list(entry.get("allow", []))
    return list(licences.get("allow", [])), exceptions


def about_policy(about: dict) -> tuple[list[str], dict[str, list[str]]]:
    """Return a cargo-about config's accepted list and its crate-scoped lists."""
    crates = {
        key: list(value.get("accepted", []))
        for key, value in about.items()
        if key not in ABOUT_GLOBAL_KEYS and isinstance(value, dict)
    }
    return list(about.get("accepted", [])), crates


def check_about_config(about: dict, deny: dict, label: str, targets: list[str]) -> list[str]:
    """Check that one cargo-about config mirrors deny.toml and has the scope."""
    errors: list[str] = []
    allow, exceptions = deny_policy(deny)
    accepted, crates = about_policy(about)
    if accepted != allow:
        errors.append(f"{label} accepted {accepted} must equal deny.toml allow {allow}, in order")
    if crates != exceptions:
        errors.append(
            f"{label} crate-scoped accepted {crates} must equal deny.toml "
            f"exceptions {exceptions}"
        )
    if about.get("targets") != targets:
        errors.append(f"{label} targets {about.get('targets')} must be {targets}")
    if about.get("ignore-dev-dependencies") is not True:
        errors.append(f"{label} must set ignore-dev-dependencies = true")
    if about.get("private") != {"ignore": True}:
        errors.append(f"{label} must set private = {{ ignore = true }}")
    for key in (
        "workarounds",
        "ignore-build-dependencies",
        "ignore-transitive-dependencies",
        "max-depth",
    ):
        if key in about:
            errors.append(f"{label} must not set {key}")
    return errors


def deny_targets(deny: dict) -> list[str]:
    return [target.get("triple") for target in deny.get("graph", {}).get("targets", [])]


# ── Notice manifest ──────────────────────────────────────────────────────────


def is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def is_commit(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def check_component(component: dict) -> list[str]:
    errors: list[str] = []
    label = f"component {component.get('id')!r}"
    for key in ("id", "name", "licence", "repository"):
        if not isinstance(component.get(key), str) or not component[key]:
            errors.append(f"{label} needs a non-empty {key}")
    repository = component.get("repository", "")
    if isinstance(repository, str) and not repository.startswith("https://github.com/"):
        errors.append(f"{label} repository must be a https://github.com/ URL")
    if not is_commit(component.get("commit")):
        errors.append(f"{label} needs a 40-hex commit")
    submodule = component.get("submodule")
    if "tag" not in component and submodule is None:
        errors.append(f"{label} needs a tag or a submodule pin")
    if submodule is not None and (
        not isinstance(submodule, dict)
        or sorted(submodule) != ["path", "repository", "tag"]
        or not str(submodule.get("repository", "")).startswith("https://github.com/")
    ):
        errors.append(f"{label} submodule needs exactly repository, tag and path")
    files = component.get("file", [])
    if not files:
        errors.append(f"{label} lists no notice file")
    for entry in files:
        errors.extend(check_file_entry(label, entry))
    return errors


def check_file_entry(label: str, entry: dict) -> list[str]:
    errors: list[str] = []
    name = f"{label} file {entry.get('path')!r}"
    required = {"path", "local", "sha256"}
    excerpt = {"lines", "excerpt_sha256"}
    if not required <= set(entry) or set(entry) - required - excerpt:
        errors.append(f"{name} needs exactly path, local, sha256 and an optional excerpt")
    if not is_digest(entry.get("sha256")):
        errors.append(f"{name} needs a sha256 digest")
    local = str(entry.get("local", ""))
    if local.startswith("/") or ".." in Path(local).parts or not local:
        errors.append(f"{name} local path must stay relative")
    if excerpt & set(entry):
        lines = entry.get("lines")
        if (
            not isinstance(lines, list)
            or len(lines) != 2
            or not all(type(line) is int for line in lines)
            or not 1 <= lines[0] <= lines[1]
            or not is_digest(entry.get("excerpt_sha256"))
        ):
            errors.append(f"{name} excerpt needs lines [first, last] and excerpt_sha256")
    return errors


def check_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema") != 1:
        errors.append("notice manifest schema must be 1")
    components = manifest.get("component", [])
    if not components:
        errors.append("notice manifest lists no component")
    ids = [component.get("id") for component in components]
    if len(ids) != len(set(ids)):
        errors.append(f"notice manifest component ids repeat: {ids}")
    locals_seen: set[str] = set()
    for component in components:
        errors.extend(check_component(component))
        for entry in component.get("file", []):
            local = entry.get("local")
            if local in locals_seen:
                errors.append(f"notice text {local!r} is listed twice")
            locals_seen.add(local)
    errors.extend(check_rust_std(manifest))
    return errors


def check_rust_std(manifest: dict) -> list[str]:
    """The std graph names the pinned Rust component, its files and features."""
    rust_std = manifest.get("rust_std")
    if not isinstance(rust_std, dict) or sorted(rust_std) != RUST_STD_KEYS:
        return [f"notice manifest rust_std needs exactly {RUST_STD_KEYS}"]
    errors: list[str] = []
    component = [c for c in manifest.get("component", []) if c.get("id") == rust_std["component"]]
    if len(component) != 1 or "tag" not in component[0]:
        errors.append(f"rust_std component {rust_std['component']!r} must be one tagged component")
    features = rust_std["features"]
    if not features or not all(isinstance(f, str) and f for f in features):
        errors.append("rust_std features must be a non-empty list of names")
    for key in ("lockfile", "std_manifest"):
        if not str(rust_std[key]).startswith("library/") or ".." in Path(rust_std[key]).parts:
            errors.append(f"rust_std {key} must be a path under library/")
        if not is_digest(rust_std[f"{key}_sha256"]):
            errors.append(f"rust_std {key}_sha256 must be a sha256 digest")
    return errors


def expected_local_digest(entry: dict) -> str:
    return entry.get("excerpt_sha256", entry["sha256"])


def check_local_texts(manifest: dict, notices_dir: Path) -> list[str]:
    """Check every committed text against its digest; reject unlisted texts."""
    errors: list[str] = []
    listed: set[Path] = set()
    for component in manifest.get("component", []):
        for entry in component.get("file", []):
            path = notices_dir / entry["local"]
            listed.add(path)
            if not path.is_file():
                errors.append(f"notice text {entry['local']} is missing")
                continue
            data = path.read_bytes()
            if not data.strip():
                errors.append(f"notice text {entry['local']} is empty")
            if sha256(data) != expected_local_digest(entry):
                errors.append(f"notice text {entry['local']} does not match its digest")
    for path in sorted(notices_dir.rglob("*")):
        if path.is_file() and path != notices_dir / MANIFEST.name and path not in listed:
            errors.append(f"notice text {path.relative_to(notices_dir)} is not in the manifest")
    return errors


def guest_lockfiles(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix() for path in (root / GUEST_ROOT).rglob("Cargo.lock")
    )


def check_fixtures(manifest: dict, root: Path) -> list[str]:
    """Every committed fixture is mapped to what it statically contains."""
    errors: list[str] = []
    fixtures = manifest.get("fixtures", {})
    directory = root / str(fixtures.get("directory", ""))
    if not fixtures.get("directory") or not directory.is_dir():
        return [f"fixture directory {fixtures.get('directory')!r} does not exist"]
    committed = sorted(path.name for path in directory.glob("*.wasm"))
    contents = fixtures.get("contents", {})
    if sorted(contents) != committed:
        errors.append(
            f"fixture map {sorted(contents)} must list exactly the committed "
            f"fixtures {committed}"
        )
    ids = {component.get("id") for component in manifest.get("component", [])}
    guests = {*guest_lockfiles(root), RUST_STD}
    used_components: set[str] = set()
    used_guests: set[str] = set()
    for name, content in sorted(contents.items()):
        if not isinstance(content, dict) or sorted(content) != ["cargo", "components"]:
            errors.append(f"fixture {name} needs exactly components and cargo")
            continue
        for component in content["components"]:
            if component not in ids:
                errors.append(f"fixture {name} names unknown component {component!r}")
            used_components.add(component)
        for lock in content["cargo"]:
            if lock not in guests:
                errors.append(f"fixture {name} names unknown Cargo graph {lock!r}")
            used_guests.add(lock)
    if ids - used_components:
        errors.append(f"components {sorted(ids - used_components)} are used by no fixture")
    if guests - used_guests:
        errors.append(f"Cargo graphs {sorted(guests - used_guests)} are used by no fixture")
    return errors


def offline_errors(root: Path) -> list[str]:
    deny = load_toml(root, DENY)
    manifest = load_toml(root, MANIFEST)
    errors = check_about_config(
        load_toml(root, HOST_ABOUT), deny, str(HOST_ABOUT), deny_targets(deny)
    )
    errors += check_about_config(
        load_toml(root, GUEST_ABOUT), deny, str(GUEST_ABOUT), GUEST_TARGETS
    )
    manifest_errors = check_manifest(manifest)
    errors += manifest_errors
    if not manifest_errors:
        errors += check_local_texts(manifest, root / NOTICES_DIR)
        errors += check_fixtures(manifest, root)
    return errors


# ── Upstream verification ────────────────────────────────────────────────────


def fetch_url(url: str) -> bytes:
    last: Exception | None = None
    for _ in range(FETCH_ATTEMPTS):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
                return response.read()
        except OSError as error:
            last = error
    raise NoticeError(f"could not fetch {url}: {last}")


GIT_TIMEOUT_SECONDS = 300


def git(*args: str, cwd: Path | None = None) -> str:
    """Run git, retrying transient failures; report its stderr on failure."""
    failure = ""
    for _ in range(FETCH_ATTEMPTS):
        try:
            return subprocess.run(
                ["git", *args],
                cwd=cwd,
                check=True,
                capture_output=True,
                text=True,
                timeout=GIT_TIMEOUT_SECONDS,
            ).stdout
        except subprocess.CalledProcessError as error:
            failure = error.stderr.strip()
        except subprocess.TimeoutExpired:
            failure = f"timed out after {GIT_TIMEOUT_SECONDS} s"
    raise NoticeError(f"git {' '.join(args)} failed: {failure}")


def resolve_tag(repository: str, tag: str) -> str:
    """Return the commit a tag names, peeling an annotated tag."""
    refs = git("ls-remote", repository, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
    found = dict(reversed(line.split("\t")) for line in refs.splitlines() if line)
    commit = found.get(f"refs/tags/{tag}^{{}}", found.get(f"refs/tags/{tag}"))
    if commit is None:
        raise NoticeError(f"{repository} has no tag {tag}")
    return commit


def resolve_submodule(repository: str, tag: str, path: str) -> str:
    """Return the gitlink commit at `path` in `repository` at `tag`."""
    with tempfile.TemporaryDirectory() as work:
        cwd = Path(work)
        git("init", "--quiet", cwd=cwd)
        git("fetch", "--quiet", "--depth=1", repository, f"refs/tags/{tag}", cwd=cwd)
        entry = git("ls-tree", "FETCH_HEAD", "--", path, cwd=cwd).split()
    if len(entry) != 4 or entry[1] != "commit":
        raise NoticeError(f"{repository} at {tag} has no submodule {path}")
    return entry[2]


def raw_url(repository: str, commit: str, path: str) -> str:
    slug = repository.removeprefix("https://github.com/")
    return f"https://raw.githubusercontent.com/{slug}/{commit}/{path}"


def excerpt_bytes(data: bytes, lines: list[int]) -> bytes:
    selected = data.splitlines(keepends=True)[lines[0] - 1 : lines[1]]
    if len(selected) != lines[1] - lines[0] + 1:
        raise NoticeError(f"upstream file has fewer than {lines[1]} lines")
    return b"".join(selected)


def upstream_errors(
    manifest: dict,
    notices_dir: Path,
    fetch: Callable[[str], bytes] = fetch_url,
    tag_commit: Callable[[str, str], str] = resolve_tag,
    submodule_commit: Callable[[str, str, str], str] = resolve_submodule,
) -> list[str]:
    errors: list[str] = []
    for component in manifest.get("component", []):
        label = f"component {component['id']}"
        commit = component["commit"]
        if "tag" in component:
            found = tag_commit(component["repository"], component["tag"])
            if found != commit:
                errors.append(f"{label} tag {component['tag']} is {found}, not {commit}")
        submodule = component.get("submodule")
        if submodule:
            found = submodule_commit(submodule["repository"], submodule["tag"], submodule["path"])
            if found != commit:
                errors.append(
                    f"{label} submodule {submodule['path']} at {submodule['tag']} is "
                    f"{found}, not {commit}"
                )
        for entry in component["file"]:
            data = fetch(raw_url(component["repository"], commit, entry["path"]))
            if sha256(data) != entry["sha256"]:
                errors.append(f"{label} upstream {entry['path']} does not match its sha256")
                continue
            expected = excerpt_bytes(data, entry["lines"]) if "lines" in entry else data
            local = notices_dir / entry["local"]
            if not local.is_file() or local.read_bytes() != expected:
                errors.append(f"{label} committed {entry['local']} differs from upstream")
    rust_std = manifest["rust_std"]
    (component,) = (c for c in manifest["component"] if c["id"] == rust_std["component"])
    for key in ("lockfile", "std_manifest"):
        data = fetch(raw_url(component["repository"], component["commit"], rust_std[key]))
        if sha256(data) != rust_std[f"{key}_sha256"]:
            errors.append(f"rust_std upstream {rust_std[key]} does not match its sha256")
    return errors


# ── Rust std graph ───────────────────────────────────────────────────────────


def rust_src_errors(manifest: dict, sysroot: Path) -> list[str]:
    """The toolchain's rust-src files must be the ones at the pinned Rust tag."""
    rust_std = manifest["rust_std"]
    errors = []
    for key in ("lockfile", "std_manifest"):
        path = sysroot / RUST_SRC / rust_std[key]
        if not path.is_file():
            errors.append(f"rust-src {rust_std[key]} is missing from {sysroot}")
        elif sha256(path.read_bytes()) != rust_std[f"{key}_sha256"]:
            errors.append(f"rust-src {rust_std[key]} differs from the pinned Rust tag")
    return errors


def rust_std_command(root: Path, manifest: dict, sysroot: Path, output: Path) -> list[str]:
    rust_std = manifest["rust_std"]
    return [
        "cargo",
        "about",
        "generate",
        "--locked",
        "--fail",
        "--manifest-path",
        str(sysroot / RUST_SRC / rust_std["std_manifest"]),
        "--features",
        " ".join(rust_std["features"]),
        "--config",
        str(root / GUEST_ABOUT),
        "--format",
        "json",
        "--output-file",
        str(output),
    ]


def run_rust_std_report(
    root: Path,
    sysroot: Path,
    output: Path,
    run: Callable[..., object] = subprocess.run,
) -> list[str]:
    """Generate the std graph report after checking its rust-src inputs."""
    manifest = load_toml(root, MANIFEST)
    errors = check_manifest(manifest)
    if errors:
        return errors
    errors = rust_src_errors(manifest, sysroot)
    if errors:
        return errors
    # The library workspace declares `cargo-features`, which stable Cargo
    # reads only with RUSTC_BOOTSTRAP=1, as the repository's coverage job does.
    environment = {**os.environ, "RUSTC_BOOTSTRAP": "1"}
    try:
        run(rust_std_command(root, manifest, sysroot, output), check=True, env=environment)
    except subprocess.CalledProcessError as error:
        return [f"cargo about on Rust std failed with exit status {error.returncode}"]
    return []


def shipped_rlibs(sysroot: Path) -> set[str]:
    """Crate names of the rlibs the toolchain ships for wasm32-unknown-unknown."""
    return {
        path.name.removeprefix("lib").rsplit("-", 1)[0]
        for path in (sysroot / RUST_STD_RLIBS).glob("lib*-*.rlib")
    }


def check_std_rlibs(report: dict, rlibs: set[str]) -> list[str]:
    """Every crate in the std graph must be shipped as a wasm32 rlib."""
    return [
        f"{RUST_STD}: {crate_label(crate['package'])} has no wasm32-unknown-unknown rlib"
        for crate in report.get("crates", [])
        if crate["package"]["name"].replace("-", "_") not in rlibs
    ]


# ── cargo-about reports ──────────────────────────────────────────────────────


def crate_label(package: dict) -> str:
    return f"{package['name']} {package['version']}"


def check_report(report: dict, label: str) -> list[str]:
    """Every crate in one cargo-about report has an accepted licence text."""
    errors: list[str] = []
    crates = report.get("crates", [])
    licences = report.get("licenses", [])
    if not crates or not licences:
        return [f"{label}: the cargo-about report lists no crates or no licences"]
    covered: set[str] = set()
    for licence in licences:
        if not str(licence.get("text", "")).strip():
            errors.append(f"{label}: licence {licence.get('id')} has an empty text")
            continue
        covered.update(used["crate"]["id"] for used in licence.get("used_by", []))
    for crate in crates:
        package = crate["package"]
        if crate.get("license") in ("Unknown", "", None):
            errors.append(f"{label}: {crate_label(package)} has an unknown licence")
        elif package["id"] not in covered:
            errors.append(f"{label}: {crate_label(package)} has no licence text")
    return errors


def lock_packages(path: Path) -> set[tuple[str, str]]:
    """Return the (name, version) of every registry package in a lockfile."""
    with path.open("rb") as handle:
        packages = tomllib.load(handle).get("package", [])
    return {
        (package["name"], package["version"])
        for package in packages
        if str(package.get("source", "")).startswith("registry+")
    }


def is_in_tree(package: dict, in_tree: Path | None) -> bool:
    """A path package whose manifest lies under `in_tree` (Rust's library/)."""
    if in_tree is None or package.get("source") is not None:
        return False
    manifest = Path(str(package.get("manifest_path", ""))).resolve()
    return manifest.is_relative_to(in_tree.resolve())


def check_report_graph(
    report: dict, packages: set[tuple[str, str]], label: str, in_tree: Path | None = None
) -> list[str]:
    """A report may list only registry packages that its lockfile pins.

    The std graph may also list Rust's own in-tree library crates, such as
    `alloc`, which the Rust component's texts cover.
    """
    return [
        f"{label}: {crate_label(crate['package'])} is not a registry package of {label}"
        for crate in report.get("crates", [])
        if (crate["package"]["name"], crate["package"]["version"]) not in packages
        and not is_in_tree(crate["package"], in_tree)
    ]


def text_source(licence: dict) -> str:
    path = licence.get("source_path")
    if not path:
        return "the SPDX licence list text (the crate ships none)"
    return f"the crate's {Path(path).name}"


def render_report(lock: str, lock_digest: str, report: dict) -> tuple[list[str], dict]:
    crates = sorted(report["crates"], key=lambda crate: crate["package"]["id"])
    lines = [
        RULE,
        f"Cargo graph: {lock} (SHA-256 {lock_digest})",
        RULE,
        "",
        f"{len(crates)} crates:",
    ]
    lines += [f"  {crate_label(crate['package'])}: {crate['license']}" for crate in crates]
    texts = []
    licences = sorted(
        report["licenses"], key=lambda licence: (licence["id"], sha256(licence["text"].encode()))
    )
    for licence in licences:
        users = sorted(crate_label(used["crate"]) for used in licence["used_by"])
        lines += [
            "",
            "-" * 78,
            f"{licence['name']} ({licence['id']}), from {text_source(licence)}",
            f"Used by: {', '.join(users)}",
            "-" * 78,
            "",
            licence["text"].rstrip("\n"),
        ]
        texts.append(
            {
                "id": licence["id"],
                "sha256": sha256(licence["text"].encode()),
                "source": text_source(licence),
                "used_by": users,
            }
        )
    index = {
        "lockfile": lock,
        "lockfile_sha256": lock_digest,
        "crates": [
            {
                "name": crate["package"]["name"],
                "version": crate["package"]["version"],
                "license": crate["license"],
            }
            for crate in crates
        ],
        "texts": texts,
    }
    return lines, index


def render_components(manifest: dict, notices_dir: Path) -> tuple[list[str], list[dict]]:
    lines: list[str] = []
    index = []
    for component in manifest["component"]:
        pin = f"tag {component['tag']}" if "tag" in component else ""
        submodule = component.get("submodule")
        if submodule:
            via = f"submodule {submodule['path']} of {submodule['repository']} {submodule['tag']}"
            pin = f"{pin}; {via}" if pin else via
        lines += [
            RULE,
            f"Component: {component['name']}",
            f"Licence: {component['licence']}",
            f"Source: {component['repository']} commit {component['commit']} ({pin})",
            RULE,
        ]
        files = []
        for entry in component["file"]:
            where = entry["path"]
            if "lines" in entry:
                where += f", lines {entry['lines'][0]}-{entry['lines'][1]}"
            lines += [
                "",
                "-" * 78,
                f"{where} (upstream SHA-256 {entry['sha256']})",
                "-" * 78,
                "",
                (notices_dir / entry["local"]).read_text(encoding="utf-8").rstrip("\n"),
            ]
            files.append({"path": entry["path"], "sha256": entry["sha256"]})
        lines.append("")
        index.append(
            {
                "id": component["id"],
                "name": component["name"],
                "licence": component["licence"],
                "repository": component["repository"],
                "commit": component["commit"],
                "files": files,
            }
        )
    return lines, index


def assemble(root: Path, reports: dict[str, dict], sysroot: Path) -> tuple[str, str]:
    """Return the bundle text and its JSON index; raise on any violation."""
    errors = offline_errors(root)
    if errors:
        raise NoticeError("\n".join(errors))
    manifest = load_toml(root, MANIFEST)
    errors = rust_src_errors(manifest, sysroot)
    lockfiles = {lock: root / lock for lock in [HOST_LOCK, *guest_lockfiles(root)]}
    lockfiles[RUST_STD] = sysroot / RUST_SRC / manifest["rust_std"]["lockfile"]
    expected = list(lockfiles)
    if sorted(reports) != sorted(expected):
        errors.append(f"cargo-about reports {sorted(reports)} must be exactly {sorted(expected)}")
    rlibs = shipped_rlibs(sysroot)
    for lock in sorted(reports):
        errors += check_report(reports[lock], lock)
        if lock in lockfiles and lockfiles[lock].is_file():
            in_tree = lockfiles[lock].parent if lock == RUST_STD else None
            errors += check_report_graph(
                reports[lock], lock_packages(lockfiles[lock]), lock, in_tree
            )
    if RUST_STD in reports:
        errors += check_std_rlibs(reports[RUST_STD], rlibs)
    if errors:
        raise NoticeError("\n".join(errors))

    lines = [
        "PiglorOS third-party notices",
        "",
        "This bundle covers the crates in the non-dev dependency graph of every",
        "PiglorOS workspace binary (x86_64-unknown-linux-gnu), the crates in each",
        "Rust guest fixture's Cargo.lock (wasm32-unknown-unknown), the crates.io",
        "crates that Rust's std links into those guests, and the non-Cargo",
        "components that the committed compatibility fixtures statically contain.",
        "PiglorOS's own crates are MIT-licensed and not listed.",
        "",
    ]
    index: dict = {"schema": 1, "graphs": [], "components": [], "fixtures": {}}
    for lock in expected:
        digest = sha256(lockfiles[lock].read_bytes())
        label = lock
        if lock == RUST_STD:
            rust_std = manifest["rust_std"]
            (rust,) = (c for c in manifest["component"] if c["id"] == rust_std["component"])
            label = (
                f"{RUST_STD}: Rust {rust['tag']} {rust_std['lockfile']}, std with "
                f"features {', '.join(rust_std['features'])}, wasm32-unknown-unknown"
            )
        graph_lines, graph_index = render_report(label, digest, reports[lock])
        if lock == RUST_STD:
            listed = {
                c["package"]["name"].replace("-", "_")
                for c in reports[lock]["crates"]
                if c["package"].get("source") is not None
            }
            in_tree = sorted(rlibs - listed)
            graph_lines += [
                "",
                "Shipped wasm32-unknown-unknown rlibs that are not crates.io crates of this",
                "graph (in-tree Rust library crates, covered by the Rust component below):",
                f"  {', '.join(in_tree)}",
            ]
            graph_index["in_tree_rlibs"] = in_tree
        lines += [*graph_lines, ""]
        index["graphs"].append(graph_index)
    component_lines, index["components"] = render_components(manifest, root / NOTICES_DIR)
    lines += component_lines
    fixtures = manifest["fixtures"]
    lines += [RULE, f"Fixtures in {fixtures['directory']}", RULE, ""]
    for name, content in sorted(fixtures["contents"].items()):
        parts = [*content["components"], *content["cargo"]]
        lines.append(f"  {name}: {', '.join(parts) if parts else 'first-party code only'}")
        index["fixtures"][name] = content
    text = "\n".join(lines) + "\n"
    return text, json.dumps(index, indent=2, sort_keys=True) + "\n"


# ── Command line ─────────────────────────────────────────────────────────────


def parse_graph(value: str) -> tuple[str, Path]:
    lock, separator, report = value.partition("=")
    if not separator or not lock or not report:
        raise argparse.ArgumentTypeError("expected LOCKFILE=REPORT.json")
    return lock, Path(report)


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    commands.add_parser("verify-upstream")
    assemble_parser = commands.add_parser("assemble")
    assemble_parser.add_argument("--graph", action="append", type=parse_graph, default=[])
    assemble_parser.add_argument("--sysroot", type=Path, required=True)
    assemble_parser.add_argument("--output", type=Path, required=True)
    std_parser = commands.add_parser("rust-std-report")
    std_parser.add_argument("--sysroot", type=Path, required=True)
    std_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "check":
            errors = offline_errors(root)
        elif args.command == "verify-upstream":
            errors = offline_errors(root) or upstream_errors(
                load_toml(root, MANIFEST), root / NOTICES_DIR
            )
        elif args.command == "rust-std-report":
            errors = run_rust_std_report(root, args.sysroot, args.output)
        else:
            reports = {}
            for lock, path in args.graph:
                if lock in reports:
                    raise NoticeError(f"cargo-about report for {lock} given twice")
                reports[lock] = json.loads(path.read_text(encoding="utf-8"))
            text, index = assemble(root, reports, args.sysroot)
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / TEXT_NAME).write_text(text, encoding="utf-8")
            (args.output / INDEX_NAME).write_text(index, encoding="utf-8")
            errors = []
    except NoticeError as error:
        errors = [str(error)]
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
