#!/usr/bin/env python3
"""Enforce the repository contract for delegated isolated test runners."""

from __future__ import annotations

import argparse
import re
import shlex
import stat
from pathlib import Path


def require(text: str, fragment: str, source: Path) -> None:
    if fragment not in text:
        raise SystemExit(f"{source}: missing required policy fragment: {fragment}")


def strip_comments(text: str) -> str:
    """The shell code of `text` without its comments.

    A `#` starts a comment where it starts a word outside quotes, as in bash,
    so a guard or an option that is only mentioned in a comment is absent.
    """
    code = []
    quote = ""
    escaped = False
    in_comment = False
    previous = "\n"
    for character in text:
        if in_comment:
            if character == "\n":
                in_comment = False
                code.append(character)
            previous = character
            continue
        if escaped:
            escaped = False
        elif quote == "'":
            quote = "" if character == "'" else quote
        elif character == "\\":
            escaped = True
        elif quote == '"':
            quote = "" if character == '"' else quote
        elif character in "'\"":
            quote = character
        elif character == "#" and previous in " \t\n;&|(":
            in_comment = True
            previous = character
            continue
        code.append(character)
        previous = character
    return "".join(code)


def closing_parenthesis(code: str, start: int, source: Path) -> int:
    """The index of the `)` that closes the array opened just before `start`."""
    quote = ""
    for index in range(start, len(code)):
        character = code[index]
        if quote:
            quote = "" if character == quote else quote
        elif character in "'\"":
            quote = character
        elif character == ")":
            return index
    raise SystemExit(f"{source}: unterminated Docker argument array")


# Docker options that take no value.
DOCKER_FLAGS = {"--rm", "--read-only"}
# Owner decisions Q9.x and 2026-11-09 (#911): every Docker option an isolated
# runner passes, exactly and nothing else. Any other option, such as
# `--net`, `--volumes-from`, `--sysctl`, `--cgroup-parent`, `--runtime`,
# another `--tmpfs` or `--mount`, or a short option, is refused.
DOCKER_OPTIONS = [
    ("--rm", None),
    ("--network", "none"),
    ("--read-only", None),
    ("--cap-drop", "ALL"),
    ("--security-opt", "no-new-privileges"),
    ("--pids-limit", "256"),
    ("--memory", "2g"),
    ("--memory-swap", "2g"),
    ("--ulimit", "fsize=268435456:268435456"),
    ("--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777,size=512m"),
    ("--tmpfs", "/var/lib:rw,nosuid,nodev,mode=0755,size=64m"),
    ("--tmpfs", "/run:rw,nosuid,nodev,mode=0755,size=64m"),
    ("--mount", "type=bind,source=$REPOSITORY_ROOT,target=$REPOSITORY_ROOT,readonly"),
    ("--workdir", "$REPOSITORY_ROOT"),
    ("--env", "PIGLOROS_PRIVILEGED_COMPOSITION_TEST=1"),
    ("--env", "$variable=${!variable}"),
    ("--env", "LLVM_PROFILE_FILE=/pigloros-profile.profraw"),
    ("--mount", "type=bind,source=$profile_output,target=/pigloros-profile.profraw"),
]


def docker_options(code: str, source: Path) -> list[tuple[str, str | None]]:
    """Every Docker option the runner can pass, read from its argument array.

    The array may only be assigned once, appended to, and expanded once as
    the whole of `docker run`'s options; `docker` runs nowhere else.
    """
    references = re.findall(r"(.{0,3})\bdocker_arguments\b(.{0,6})", code)
    assignments = [after for _, after in references if after.startswith("=(")]
    expansions = [
        (before, after)
        for before, after in references
        if before.endswith('"${') and after.startswith('[@]}"')
    ]
    appends = [after for _, after in references if after.startswith("+=(")]
    if len(assignments) != 1 or len(expansions) != 1 or len(references) != 2 + len(appends):
        raise SystemExit(f"{source}: the Docker argument array is used in an unrecognised way")
    if len(re.findall(r"\bdocker\b(?!_)", code)) != 1:
        raise SystemExit(f"{source}: docker must run exactly once")
    invocation = re.search(r"\bdocker\s+run\s+(.*?)\"\$ISOLATION_IMAGE\"", code, re.DOTALL)
    if invocation is None or shlex.split(invocation.group(1).replace("\\\n", " ")) != [
        "${docker_arguments[@]}"
    ]:
        raise SystemExit(f"{source}: docker run must take exactly the argument array")
    tokens: list[str] = []
    for match in re.finditer(r"\bdocker_arguments\+?=\(", code):
        tokens.extend(shlex.split(code[match.end() : closing_parenthesis(code, match.end(), source)]))
    options: list[tuple[str, str | None]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("--"):
            raise SystemExit(f"{source}: unrecognised Docker argument {token}")
        if "=" in token:
            option, value = token.split("=", 1)
            options.append((option, value))
        elif token in DOCKER_FLAGS:
            options.append((token, None))
        elif index + 1 < len(tokens):
            index += 1
            options.append((token, tokens[index]))
        else:
            raise SystemExit(f"{source}: Docker option {token} has no value")
        index += 1
    return options


def option_key(option: tuple[str, str | None]) -> tuple[str, str]:
    return (option[0], option[1] or "")


# Owner decision 2026-11-09 (#911): the one runner that may add capabilities,
# exactly these, for the Local namespace adapter tests that own it.
NET_ADMIN_RUNNER = "run-isolated-with-net-admin-test.sh"
NET_ADMIN_DOCKER_OPTIONS = [
    *DOCKER_OPTIONS,
    ("--cap-add", "NET_ADMIN"),
    ("--cap-add", "SYS_ADMIN"),
    # Owner decision 2026-11-09 (#911): added only behind the guard that
    # admits the namespace-pinning tests (NET_ADMIN_GUARDS).
    ("--security-opt", "apparmor=unconfined"),
]
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
    "readonly READ_ONLY_PROBE='if [ -w \"$1\" ]; then echo \"the worktree bind is writable\" >&2; "
    "exit 1; fi; shift; exec \"$@\"'",
    '/bin/sh -c "$READ_ONLY_PROBE" read-only-probe "$REPOSITORY_ROOT" \\\n'
    '  "$TEST_BINARY" --exact "$TEST_NAME" --nocapture',
)
# Shell constructs whose quoting the comment stripper cannot follow (ANSI-C
# quotes, heredocs, backticks) or that run arbitrary code (command
# substitution) are allowed only on these exact lines, and in the guards.
SPECIAL_SEQUENCES = ("$'", "<<", "`", "$(")
SPECIAL_LINES = {
    'readonly SCRIPT_DIRECTORY=$(realpath -- "$(dirname -- "$0")")',
    'readonly REPOSITORY_ROOT=$(realpath -- "$SCRIPT_DIRECTORY/..")',
    'readonly TEST_BINARY=$(realpath -- "$1")',
    'profile_directory=$(realpath -- "$(dirname -- "$LLVM_PROFILE_FILE")")',
    'profile_output=$(mktemp "$profile_directory/isolated-profile.XXXXXX.profraw")',
}
# The only additions to the Docker argument array after its definition.
DOCKER_APPENDS = {
    'docker_arguments+=(--env "$variable=${!variable}")',
    "docker_arguments+=(\n"
    "--env LLVM_PROFILE_FILE=/pigloros-profile.profraw\n"
    '--mount "type=bind,source=$profile_output,target=/pigloros-profile.profraw"\n'
    ")",
}
NET_ADMIN_DOCKER_APPENDS = {"docker_arguments+=(--security-opt apparmor=unconfined)"}


def special_constructs(raw: str, allowed: set[str], source: Path) -> None:
    """Fail on any line with a special construct outside `allowed`."""
    for line in raw.splitlines():
        if any(sequence in line for sequence in SPECIAL_SEQUENCES) and line.strip() not in allowed:
            raise SystemExit(f"{source}: unrecognised shell construct on line: {line.strip()}")


def appends(code: str, allowed: set[str], source: Path) -> None:
    """Fail on any addition to the Docker argument array outside `allowed`."""
    for match in re.finditer(r"\bdocker_arguments\+=\(", code):
        end = closing_parenthesis(code, match.end(), source)
        block = "\n".join(line.strip() for line in code[match.start() : end + 1].splitlines())
        if block not in allowed:
            raise SystemExit(f"{source}: unrecognised Docker argument addition: {block}")


# Words that open and close a shell compound command.
OPENERS = re.compile(r"(?<![\w$-])(if|case|for|while|until)(?![\w-])")
CLOSERS = re.compile(r"(?<![\w$-])(fi|esac|done)(?![\w-])")


def at_top_level(code: str, fragment: str, source: Path) -> None:
    """Fail unless `fragment` starts a line outside every compound command,
    so no `if false`, loop or case arm can make a guard inert."""
    start = code.find(fragment)
    if start < 0 or (start > 0 and code[start - 1] != "\n") or fragment[:1].isspace():
        raise SystemExit(f"{source}: guard is not at the top level: {fragment.splitlines()[0]}")
    before = code[:start]
    if len(OPENERS.findall(before)) != len(CLOSERS.findall(before)):
        raise SystemExit(f"{source}: guard is inside a compound command: {fragment.splitlines()[0]}")
    if re.search(r"(?m)^\s*(function\s|[A-Za-z_]\w*\s*\(\)|\{\s*$|\(\s*$)", code):
        raise SystemExit(f"{source}: functions and grouping commands are forbidden")


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
        raw = runner_path.read_text(encoding="utf-8")
        runner = strip_comments(raw)
        net_admin = runner_path.name == NET_ADMIN_RUNNER
        guard_lines = {
            line.strip() for fragment in NET_ADMIN_GUARDS for line in fragment.splitlines()
        }
        special_constructs(raw, SPECIAL_LINES | (guard_lines if net_admin else set()), runner_path)
        appends(
            runner, DOCKER_APPENDS | (NET_ADMIN_DOCKER_APPENDS if net_admin else set()), runner_path
        )
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
            "for variable in ASAN_OPTIONS LSAN_OPTIONS; do",
        ):
            require(runner, fragment, runner_path)

        expected = DOCKER_OPTIONS
        if runner_path.name == NET_ADMIN_RUNNER:
            expected = NET_ADMIN_DOCKER_OPTIONS
            for fragment in NET_ADMIN_GUARDS:
                require(runner, fragment, runner_path)
                if fragment.startswith(("readonly ", "if ")):
                    at_top_level(runner, fragment, runner_path)
        options = sorted(map(option_key, docker_options(runner, runner_path)))
        if options != sorted(map(option_key, expected)):
            unexpected = [option for option in options if option not in map(option_key, expected)]
            raise SystemExit(
                f"{runner_path}: Docker options differ from the allowlist; unexpected: {unexpected}"
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
