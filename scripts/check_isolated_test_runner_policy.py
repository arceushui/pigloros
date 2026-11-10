#!/usr/bin/env python3
"""Enforce the repository contract for delegated isolated test runners."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
from pathlib import Path


def require(text: str, fragment: str, source: Path) -> None:
    if fragment not in text:
        raise SystemExit(f"{source}: missing required policy fragment: {fragment}")


# Every isolated test runner, pinned to the SHA-256 of its exact content.
# Shell cannot be checked by matching its text, so a runner may change only
# together with its pin here: one reviewed change to both files. The
# structural checks below still hold over the pinned text, so a pin cannot be
# moved to a runner that drops them.
RUNNER_DIGESTS = {
    "run-isolated-test.sh": "af2939a6ecdf3fc38d058bea21ff9e89304634c7d1c21e7d3253fa95bbf4f33c",
    "run-isolated-with-net-admin-test.sh": "50568c1ee22a21e0e0eaa03a39a54db2b93d9e47fce22bff8badec9c04ee733a",
}
# Owner decision 2026-11-09 (#911): the one runner that may add capabilities,
# exactly these, for the Local namespace adapter tests that own it.
NET_ADMIN_RUNNER = "run-isolated-with-net-admin-test.sh"
CAPABILITIES = {NET_ADMIN_RUNNER: ["NET_ADMIN", "SYS_ADMIN"]}
# Every runner keeps no-new-privileges; only the NET_ADMIN runner may also
# drop AppArmor, and only behind the guard that admits the namespace-pinning
# tests (owner decision 2026-11-09, #911; NET_ADMIN_GUARDS).
SECURITY_OPTIONS = {NET_ADMIN_RUNNER: ["no-new-privileges", "apparmor=unconfined"]}
NET_ADMIN_OWNER_ROOT = "apps/pos-sandboxd/src/namespace_network/"
# Where Rust sources live; every one is scanned for runner references.
RUST_ROOTS = ("apps", "crates", "fuzz", "plugins", "scripts")
# A Rust test self-locates a runner through exactly this literal.
RUNNER_REFERENCE = re.compile(r'\.join\("\.\./\.\./scripts/([^"\n]+)"\)')
# Comments, then string literals (raw, plain, byte) and char literals, in the
# order a Rust lexer meets them, so a quote inside one never starts another.
RUST_TOKEN = re.compile(
    r"//[^\n]*"
    r"|/\*(?:[^*]|\*(?!/))*\*/"
    r'|(?<![A-Za-z0-9_])b?r(?P<hashes>#*)"(?P<raw>.*?)"(?P=hashes)'
    r'|(?<![A-Za-z0-9_])b?"(?P<text>(?:[^"\\]|\\.)*)"'
    r"|(?<![A-Za-z0-9_])b?'(?P<char>[^'\\\n]|\\[^'\n]{1,10})'",
    re.S,
)
# The distinctive pieces of a runner name, as they read once every string and
# char literal of a source is joined in order and stripped of all but letters
# and digits. This is a best-effort lint against accidental references, such
# as a runner named through concat! or char by char; code that sets out to
# evade it can (format!("run-{}-test.sh", "isolated") reorders the pieces).
# The enforcement is the runner's own guards on its test harness and test
# names.
ISOLATED_FRAGMENT = "runisolated"
NET_ADMIN_FRAGMENT = "netadmin"
# The guards that run before Docker: only a pos-sandboxd test harness under
# target/, never the daemon, only the named privileged tests, no comma in a
# bind source, and a read-only worktree bind checked inside the container.
NET_ADMIN_GUARDS = (
    "readonly TEST_DIRECTORY=$(dirname -- \"$TEST_BINARY\")",
    "readonly TEST_RELATIVE=${TEST_BINARY#\"$REPOSITORY_ROOT\"/}",
    "readonly TEST_TARGET='^target/([A-Za-z0-9_-]+/){1,2}deps/pos_sandboxd-[0-9a-f]{16}$'",
    "if [[ ! $TEST_RELATIVE =~ $TEST_TARGET || ! -f $TEST_BINARY || ! -x $TEST_BINARY ||\n"
    "  $TEST_BINARY -ef $TEST_DIRECTORY/../pos-sandboxd ]]; then\n"
    '  echo "only the pos-sandboxd library test harness may use this runner" >&2\n'
    "  exit 2\n"
    "fi",
    "readonly TEST_PATTERN='^namespace_network::(netlink|control|attempt_network)::tests::privileged::[a-z0-9_]+$'",
    "if [[ ! $TEST_NAME =~ $TEST_PATTERN ]]; then\n"
    '  echo "only the #911 namespace adapter tests may use this runner" >&2\n'
    "  exit 2\n"
    "fi",
    "if [[ $REPOSITORY_ROOT == *,* ]]; then",
    "  if [[ $profile_directory == *,* ]]; then",
    "readonly UNCONFINED_PATTERN='^namespace_network::(control|attempt_network)::tests::privileged::[a-z0-9_]+$'\n"
    "if [[ $TEST_NAME =~ $UNCONFINED_PATTERN ]]; then\n"
    "  docker_arguments+=(--security-opt apparmor=unconfined)\n"
    "fi",
    "readonly READ_ONLY_PROBE='if [ -w \"$1\" ]; then echo \"the test binary bind is writable\" >&2; "
    'exit 1; fi; "$@"; status=$?; if [ -w "$1" ]; then '
    'echo "the test binary bind became writable" >&2; exit 1; fi; exit "$status"\'',
    '/bin/sh -c "$READ_ONLY_PROBE" read-only-probe \\\n'
    '  "$TEST_BINARY" --exact "$TEST_NAME" --nocapture',
    "--workdir /tmp",
)
# bash -p reads no BASH_ENV or ENV file and imports no shell functions.
RUNNER_SHEBANG = "#!/bin/bash -p\n"
# Before anything else runs, a fixed PATH, and Docker only under exactly the
# environment `env -i` names: the caller's environment picks no program,
# Docker daemon, context or configuration.
RUNNER_ENVIRONMENT = (
    "set -euo pipefail\n"
    "readonly RUNNER_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    "export PATH=$RUNNER_PATH\n"
)
# The daemon is the system socket, or a unix socket at an absolute path the
# runner's own override names; DOCKER_HOST, DOCKER_CONTEXT and DOCKER_CONFIG
# never reach Docker.
RUNNER_DOCKER_SOCKET = (
    "readonly DOCKER_SOCKET=${PIGLOR_ISOLATED_DOCKER_HOST:-unix:///var/run/docker.sock}\n"
    "if [[ ! $DOCKER_SOCKET =~ ^unix:///[A-Za-z0-9._/-]+$ || $DOCKER_SOCKET == *..* ]]; then\n"
    '  echo "PIGLOR_ISOLATED_DOCKER_HOST must be unix:// and an absolute socket path" >&2\n'
    "  exit 2\n"
    "fi\n"
)
RUNNER_DOCKER = (
    'env -i "PATH=$RUNNER_PATH" HOME=/nonexistent "DOCKER_HOST=$DOCKER_SOCKET" \\\n'
    '  docker run "${docker_arguments[@]}" "$ISOLATION_IMAGE"'
)
# What the container sees of the host: the worktree read-only, or for the
# NET_ADMIN runner, whose test may remount, only the test binary read-only.
HOST_BIND_SOURCES = {NET_ADMIN_RUNNER: "$TEST_BINARY"}
WORKTREE_SOURCE = "$REPOSITORY_ROOT"
# What every runner keeps: a bounded, networkless, read-only container that
# drops every capability and sees the host read-only.
RUNNER_FRAGMENTS = (
    RUNNER_ENVIRONMENT,
    RUNNER_DOCKER_SOCKET,
    RUNNER_DOCKER,
    "[[ $# -ne 2 ]]",
    "timeout --signal=TERM --kill-after=5s 30s",
    "docker run",
    "--network none",
    "--read-only",
    "--cap-drop ALL",
    "--security-opt no-new-privileges",
    "--pids-limit 256",
    "--memory 2g",
    "--memory-swap 2g",
    "--ulimit fsize=268435456:268435456",
    "--tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=512m",
    "--tmpfs /var/lib:rw,nosuid,nodev,mode=0755,size=64m",
    "--tmpfs /run:rw,nosuid,nodev,mode=0755,size=64m",
    '"$REPOSITORY_ROOT"/target/*',
    'mktemp "$profile_directory/isolated-profile.XXXXXX.profraw"',
    'chmod 0666 "$profile_output"',
    "LLVM_PROFILE_FILE=/pigloros-profile.profraw",
    "source=$profile_output,target=/pigloros-profile.profraw",
    'chmod 0600 "$profile_output"',
    "[[ -n $profile_output && ! -s $profile_output ]]",
    '"$TEST_BINARY" --exact "$TEST_NAME" --nocapture',
    "for variable in ASAN_OPTIONS LSAN_OPTIONS; do",
)


def check_runner(runner_path: Path) -> None:
    """Fail unless the runner is exactly its pinned content, and that content
    keeps every structural guarantee."""
    pinned = RUNNER_DIGESTS.get(runner_path.name)
    if pinned is None:
        raise SystemExit(f"{runner_path}: isolated test runner has no pinned digest")
    # Open the runner itself, never what a symlink names, and only as a
    # regular file.
    try:
        descriptor = os.open(runner_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise SystemExit(f"{runner_path}: isolated test runner must be a regular file: {error}")
    with os.fdopen(descriptor, "rb") as runner_file:
        status = os.fstat(runner_file.fileno())
        if not stat.S_ISREG(status.st_mode):
            raise SystemExit(f"{runner_path}: isolated test runner must be a regular file")
        content = runner_file.read()
    if hashlib.sha256(content).hexdigest() != pinned:
        raise SystemExit(
            f"{runner_path}: differs from its pinned content; review the change and "
            "update RUNNER_DIGESTS in the same commit"
        )
    if not status.st_mode & stat.S_IXUSR:
        raise SystemExit(f"{runner_path}: isolated test runner must be executable")
    runner = content.decode("utf-8")
    if not runner.startswith(RUNNER_SHEBANG):
        raise SystemExit(f"{runner_path}: isolated test runner must start with {RUNNER_SHEBANG!r}")
    if runner.count("docker run") != 1 or runner.count("env -i") != 1:
        raise SystemExit(f"{runner_path}: Docker must run exactly once, under env -i")
    if re.search(r"\bsudo\b", runner) or "--privileged" in runner:
        raise SystemExit(f"{runner_path}: ambient sudo and privileged containers are forbidden")
    if re.search(r"(?m)(?:^[ \t]*|[;&|][ \t]*)rm[ \t]+-[^\n]*r", runner):
        raise SystemExit(f"{runner_path}: recursive host-path deletion is forbidden")
    if not re.search(r"readonly ISOLATION_IMAGE='[^']+@sha256:[0-9a-f]{64}'", runner):
        raise SystemExit(f"{runner_path}: isolation image must be digest-pinned")
    for fragment in RUNNER_FRAGMENTS:
        require(runner, fragment, runner_path)
    source = HOST_BIND_SOURCES.get(runner_path.name, WORKTREE_SOURCE)
    require(runner, f'--mount "type=bind,source={source},target={source},readonly"', runner_path)
    sources = re.findall(r"source=([^,\s\"]*)", runner)
    if sources != [source, "$profile_output"]:
        raise SystemExit(f"{runner_path}: binds host paths other than its own: {sources}")
    added = re.findall(r"--cap-add[ =]+(\S+)", runner)
    if added != CAPABILITIES.get(runner_path.name, []):
        raise SystemExit(f"{runner_path}: adds capabilities other than its own: {added}")
    options = re.findall(r"--security-opt[ =]+([^\s)]+)", runner)
    if options != SECURITY_OPTIONS.get(runner_path.name, ["no-new-privileges"]):
        raise SystemExit(f"{runner_path}: security options other than its own: {options}")
    if runner_path.name == NET_ADMIN_RUNNER:
        for fragment in NET_ADMIN_GUARDS:
            require(runner, fragment, runner_path)


def literal_text(text: str) -> str:
    """Every string and char literal of a Rust source joined in order,
    lowercased and stripped of all but letters and digits."""
    joined = "".join(
        (token.group("raw") or "") + (token.group("text") or "") + (token.group("char") or "")
        for token in RUST_TOKEN.finditer(text)
    )
    return re.sub(r"[^a-z0-9]", "", joined.lower())


def check_runner_references(
    root: Path, source: Path, text: str, references: list[str], runner_names: set[str]
) -> None:
    """Fail unless every runner `source` names is a discovered one, named by
    the one literal form the checker follows, and only the Local namespace
    adapter names anything of the NET_ADMIN runner."""
    for reference in references:
        if reference not in runner_names:
            raise SystemExit(
                f"{source}: delegated test runner is not a discovered isolated runner: {reference}"
            )
    literals = literal_text(text)
    if literals.count(ISOLATED_FRAGMENT) != len(references):
        raise SystemExit(
            f"{source}: names an isolated test runner other than through "
            '.join("../../scripts/<runner>")'
        )
    if NET_ADMIN_FRAGMENT in literals and not source.relative_to(root).as_posix().startswith(
        NET_ADMIN_OWNER_ROOT
    ):
        raise SystemExit(f"{source}: only the Local namespace adapter may own {NET_ADMIN_RUNNER}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    root = args.root.resolve()
    workflow_path = root / ".github/workflows/ci.yml"
    mutation_path = root / ".github/workflows/mutation.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    mutation_workflow = mutation_path.read_text(encoding="utf-8")

    for fragment in (
        "python scripts/check_isolated_test_runner_policy.py",
        "python scripts/test_check_isolated_test_runner_policy.py",
        "cargo nextest run --workspace --all-features --locked",
        "--run-ignored all --no-fail-fast",
        '--partition "slice:${SHARD}/3"',
        "assert-no-ignored-in-test-summary.sh --partitioned=3",
        "cargo test --workspace --all-features --locked --doc -- --include-ignored",
        "cargo llvm-cov nextest --workspace --all-features --locked",
        "--user-config-file none --ignore-default-filter",
        "name: cargo test with ASan",
        "uses: ./.github/workflows/mutation.yml",
    ):
        require(workflow, fragment, workflow_path)
    require(mutation_workflow, "cargo mutants", mutation_path)

    runners = sorted((root / "scripts").glob("run-isolated*-test.sh"))
    if not runners:
        raise SystemExit("no delegated isolated test runners were discovered")
    rust_sources = {
        source: source.read_text(encoding="utf-8")
        for top in RUST_ROOTS
        for source in sorted((root / top).glob("**/*.rs"))
    }
    runner_names = {runner.name for runner in runners}
    references = {}
    for source, text in rust_sources.items():
        references[source] = RUNNER_REFERENCE.findall(text)
        check_runner_references(root, source, text, references[source], runner_names)

    missing = set(RUNNER_DIGESTS) - runner_names
    if missing:
        raise SystemExit(f"pinned isolated test runners are missing: {sorted(missing)}")
    for runner_path in runners:
        check_runner(runner_path)
        owners = [
            (source, text)
            for source, text in rust_sources.items()
            if runner_path.name in references[source]
        ]
        if not owners:
            raise SystemExit(f"{runner_path}: no Rust test self-locates this runner")
        for source, text in owners:
            require(text, 'env!("CARGO_MANIFEST_DIR")', source)
            require(text, f'join("../../scripts/{runner_path.name}")', source)
            require(text, '.arg(std::env::current_exe()?)', source)
            if re.search(r"PIGLOROS_[A-Z0-9_]*RUNNER", text):
                raise SystemExit(f"{source}: isolated runner selection must not be optional")


if __name__ == "__main__":
    main()
