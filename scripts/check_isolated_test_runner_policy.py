#!/usr/bin/env python3
"""Enforce the repository contract for delegated isolated test runners."""

from __future__ import annotations

import argparse
import re
import stat
from pathlib import Path


def require(text: str, fragment: str, source: Path) -> None:
    if fragment not in text:
        raise SystemExit(f"{source}: missing required policy fragment: {fragment}")


def require_option_once(text: str, option: str, source: Path) -> None:
    pattern = rf"(?<![A-Za-z0-9_-]){re.escape(option)}(?=$|[=\s])"
    count = len(re.findall(pattern, text, flags=re.MULTILINE))
    if count != 1:
        raise SystemExit(
            f"{source}: protected Docker option {option} must occur exactly once; found {count}"
        )


# Owner decision 2026-11-09 (#911): the one runner that may add capabilities,
# exactly these, for the Local namespace adapter tests that own it.
NET_ADMIN_RUNNER = "run-isolated-with-net-admin-test.sh"
NET_ADMIN_CAPABILITIES = ["NET_ADMIN", "SYS_ADMIN"]
NET_ADMIN_OWNER_ROOT = "apps/pos-sandboxd/src/namespace_network/"
# The exact guards that run before Docker: only a pos-sandboxd test harness
# under target/, never the daemon, only the named privileged tests, no comma
# in a bind source, and a read-only worktree bind checked inside the container.
NET_ADMIN_GUARDS = (
    "readonly TEST_DIRECTORY=$(dirname -- \"$TEST_BINARY\")",
    "readonly TEST_RELATIVE=${TEST_BINARY#\"$REPOSITORY_ROOT\"/}",
    "readonly TEST_TARGET='^target/([A-Za-z0-9_-]+/){1,2}deps/pos_sandboxd-[0-9a-f]{16}$'",
    "if [[ ! $TEST_RELATIVE =~ $TEST_TARGET || ! -f $TEST_BINARY || ! -x $TEST_BINARY ||\n"
    "  $TEST_BINARY -ef $TEST_DIRECTORY/../pos-sandboxd ]]; then\n"
    '  echo "only the pos-sandboxd library test harness may use this runner" >&2\n'
    "  exit 2\n"
    "fi",
    "readonly TEST_PATTERN='^namespace_network::(netlink|control)::tests::privileged::[a-z0-9_]+$'",
    "if [[ ! $TEST_NAME =~ $TEST_PATTERN ]]; then\n"
    '  echo "only the #911 namespace adapter tests may use this runner" >&2\n'
    "  exit 2\n"
    "fi",
    "if [[ $REPOSITORY_ROOT == *,* ]]; then",
    "  if [[ $profile_directory == *,* ]]; then",
    "readonly UNCONFINED_PATTERN='^namespace_network::control::tests::privileged::[a-z0-9_]+$'\n"
    "if [[ $TEST_NAME =~ $UNCONFINED_PATTERN ]]; then\n"
    "  docker_arguments+=(--security-opt apparmor=unconfined)\n"
    "fi",
    "readonly READ_ONLY_PROBE='if [ -w \"$1\" ]; then echo \"the worktree bind is writable\" >&2; "
    "exit 1; fi; shift; exec \"$@\"'",
    '/bin/sh -c "$READ_ONLY_PROBE" read-only-probe "$REPOSITORY_ROOT" \\\n'
    '  "$TEST_BINARY" --exact "$TEST_NAME" --nocapture',
)
CAP_ADD = r"(?<![A-Za-z0-9_-])--cap-add(?=$|[=\s])"
CAP_ADD_VALUE = r"(?<![A-Za-z0-9_-])--cap-add[ =]+(\S+)"
SECURITY_OPT = r"(?<![A-Za-z0-9_-])--security-opt(?=$|[=\s])"
SECURITY_OPT_VALUE = r"(?<![A-Za-z0-9_-])--security-opt[ =]+([^\s)]+)"
# Owner decision 2026-11-09 (#911): only the NET_ADMIN runner, and there only
# for the namespace-pinning tests, may drop Docker's AppArmor profile.
SECURITY_OPTIONS = ["no-new-privileges"]
NET_ADMIN_SECURITY_OPTIONS = ["apparmor=unconfined", "no-new-privileges"]
# Options that would widen what a test container sees or may do.
FORBIDDEN_OPTIONS = (
    "--device",
    "--pid",
    "--ipc",
    "--uts",
    "--userns",
    "--cgroupns",
    "-v",
    "--volume",
    "--user",
    "-u",
    "--env-file",
    "--privileged",
    "--group-add",
)


def reject(text: str, pattern: str, description: str, source: Path) -> None:
    if re.search(pattern, text, flags=re.MULTILINE):
        raise SystemExit(f"{source}: forbidden Docker policy override: {description}")


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
        for source in (root / "crates").glob("**/*.rs")
    }
    net_admin_sources = {
        source: source.read_text(encoding="utf-8")
        for source in (root / "apps").glob("**/*.rs")
    }
    runner_names = {runner.name for runner in runners}
    for source, text in rust_sources.items():
        for reference in re.findall(r'\.join\("\.\./\.\./scripts/([^"\n]+)"\)', text):
            if reference not in runner_names:
                raise SystemExit(
                    f"{source}: delegated test runner is not a discovered isolated runner: {reference}"
                )

    for runner_path in runners:
        runner = runner_path.read_text(encoding="utf-8")
        if not runner_path.stat().st_mode & stat.S_IXUSR:
            raise SystemExit(f"{runner_path}: isolated test runner must be executable")
        if re.search(r"\bsudo\b", runner):
            raise SystemExit(f"{runner_path}: ambient sudo is forbidden")
        if re.search(r"(?m)(?:^[ \t]*|[;&|][ \t]*)rm[ \t]+-[^\n]*r", runner):
            raise SystemExit(f"{runner_path}: recursive host-path deletion is forbidden")
        if not re.search(
            r"readonly ISOLATION_IMAGE='[^']+@sha256:[0-9a-f]{64}'", runner
        ):
            raise SystemExit(f"{runner_path}: isolation image must be digest-pinned")
        for fragment in (
            "set -euo pipefail",
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
            'source=$REPOSITORY_ROOT,target=$REPOSITORY_ROOT,readonly',
            '"$REPOSITORY_ROOT"/target/*',
            'mktemp "$profile_directory/isolated-profile.XXXXXX.profraw"',
            'chmod 0666 "$profile_output"',
            "LLVM_PROFILE_FILE=/pigloros-profile.profraw",
            'source=$profile_output,target=/pigloros-profile.profraw',
            'chmod 0600 "$profile_output"',
            '[[ -n $profile_output && ! -s $profile_output ]]',
            '"$TEST_BINARY" --exact "$TEST_NAME" --nocapture',
        ):
            require(runner, fragment, runner_path)

        security_options = sorted(re.findall(SECURITY_OPT_VALUE, runner, flags=re.MULTILINE))
        allowed_security_options = (
            NET_ADMIN_SECURITY_OPTIONS
            if runner_path.name == NET_ADMIN_RUNNER
            else SECURITY_OPTIONS
        )
        if security_options != allowed_security_options or len(
            re.findall(SECURITY_OPT, runner, flags=re.MULTILINE)
        ) != len(allowed_security_options):
            raise SystemExit(
                f"{runner_path}: security options must be exactly {allowed_security_options};"
                f" found {security_options}"
            )
        for option in (
            "--network",
            "--read-only",
            "--cap-drop",
            "--pids-limit",
            "--memory",
            "--memory-swap",
            "--ulimit",
        ):
            require_option_once(runner, option, runner_path)
        reject(
            runner,
            r"(?<![A-Za-z0-9_-])-m(?=$|[=\s])",
            "short memory option",
            runner_path,
        )
        reject(
            runner,
            r"(?<![A-Za-z0-9_-])--read-write(?=$|[=\s])",
            "writable root filesystem",
            runner_path,
        )
        if runner_path.name == NET_ADMIN_RUNNER:
            for fragment in NET_ADMIN_GUARDS:
                require(runner, fragment, runner_path)
            capabilities = sorted(re.findall(CAP_ADD_VALUE, runner, flags=re.MULTILINE))
            if (
                capabilities != NET_ADMIN_CAPABILITIES
                or len(re.findall(CAP_ADD, runner, flags=re.MULTILINE)) != 2
            ):
                raise SystemExit(
                    f"{runner_path}: only {', '.join(NET_ADMIN_CAPABILITIES)} may be added;"
                    f" found {capabilities}"
                )
        else:
            reject(runner, CAP_ADD, "capability addition", runner_path)
        for option in FORBIDDEN_OPTIONS:
            reject(
                runner,
                rf"(?<![A-Za-z0-9_-]){re.escape(option)}(?=$|[=\s])",
                f"option {option}",
                runner_path,
            )
        mounts = len(re.findall(r"(?<![A-Za-z0-9_-])--mount(?=$|[=\s])", runner))
        if mounts != 2:
            raise SystemExit(
                f"{runner_path}: only the worktree and profile binds may be mounted; found {mounts}"
            )
        reject(
            runner,
            r"source=\$profile_directory,target=/pigloros-profile(?:[,\"\s]|$)",
            "writable profile directory bind",
            runner_path,
        )

        sources = rust_sources
        if runner_path.name == NET_ADMIN_RUNNER:
            sources = {**rust_sources, **net_admin_sources}
        owners = [
            (source, text)
            for source, text in sources.items()
            if runner_path.name in text
        ]
        if runner_path.name == NET_ADMIN_RUNNER:
            for source, _ in owners:
                if not source.relative_to(root).as_posix().startswith(NET_ADMIN_OWNER_ROOT):
                    raise SystemExit(
                        f"{source}: only the Local namespace adapter may own {NET_ADMIN_RUNNER}"
                    )
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
