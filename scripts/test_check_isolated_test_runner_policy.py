#!/usr/bin/env python3
"""Adversarial tests for the generic isolated-runner policy checker."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_isolated_test_runner_policy.py"
RUNNERS = tuple(sorted((ROOT / "scripts").glob("run-isolated*-test.sh")))
if not RUNNERS:
    raise SystemExit("no delegated isolated test runners were discovered")
RUNNER_PATHS = tuple(path.relative_to(ROOT) for path in RUNNERS)
OWNER_PATHS = tuple(
    source.relative_to(ROOT)
    for source in sorted((ROOT / "crates").glob("**/*.rs"))
    if any(runner.name in source.read_text(encoding="utf-8") for runner in RUNNERS)
)
NET_ADMIN_RUNNER = Path("scripts/run-isolated-with-net-admin-test.sh")
NET_ADMIN_OWNER_PATHS = tuple(
    source.relative_to(ROOT)
    for source in sorted((ROOT / "apps").glob("**/*.rs"))
    if NET_ADMIN_RUNNER.name in source.read_text(encoding="utf-8")
)
if not NET_ADMIN_OWNER_PATHS:
    raise SystemExit("no Rust owner of the NET_ADMIN isolated test runner was discovered")
if not OWNER_PATHS:
    raise SystemExit("no Rust owners of delegated isolated test runners were discovered")
FIXTURES = (
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/mutation.yml"),
    *OWNER_PATHS,
    *NET_ADMIN_OWNER_PATHS,
    *RUNNER_PATHS,
)
PRIMARY_OWNER = OWNER_PATHS[0]
PRIMARY_RUNNER = RUNNER_PATHS[0]


def invoke(root: Path, checker: Path = CHECKER) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(checker), "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def copy_fixture(root: Path) -> None:
    for relative in FIXTURES:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)


def run_runner(
    root: Path, binary: Path, name: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(root / NET_ADMIN_RUNNER), str(binary), name],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], **environment},
    )


def check_net_admin_runner_guards(temporary: Path) -> None:
    """The NET_ADMIN runner refuses, before Docker, everything but a named
    privileged test of a pos-sandboxd test harness under target/."""
    root = temporary / "net-admin-guards"
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(ROOT / NET_ADMIN_RUNNER, root / NET_ADMIN_RUNNER)
    deps = root / "target/debug/deps"
    deps.mkdir(parents=True)
    harness = deps / "pos_sandboxd-0123456789abcdef"
    harness.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    harness.chmod(0o755)
    misnamed = deps / "pos_sandboxd-daemon"
    shutil.copy2(harness, misnamed)
    outside = deps / "pos_sandboxd-fedcba9876543210"
    outside.symlink_to(shutil.which("true") or "/bin/true")
    # Cargo hard-links the daemon from its hashed copy in deps/.
    daemon_harness = deps / "pos_sandboxd-00112233445566aa"
    shutil.copy2(harness, daemon_harness)
    os.link(daemon_harness, root / "target/debug/pos-sandboxd")
    named = "namespace_network::netlink::tests::privileged::a_test"
    profiles = temporary / "profiles"
    profiles.mkdir()
    comma = temporary / "a,b"
    shutil.copytree(root, comma, symlinks=True)
    binary_refusal = "only the pos-sandboxd library test harness may use this runner"
    name_refusal = "only the #911 namespace adapter tests may use this runner"
    true = Path(shutil.which("true") or "/bin/true")
    refused = {
        "a test outside the privileged module": (
            root,
            harness,
            "namespace_network::netlink::tests::a_test",
            {},
            name_refusal,
        ),
        "a privileged test of another module": (
            root,
            harness,
            "namespace_network::route::tests::privileged::a_test",
            {},
            name_refusal,
        ),
        "an extra flag after the test name": (
            root,
            harness,
            f"{named} --ignored",
            {},
            name_refusal,
        ),
        "a binary outside the repository": (
            root,
            true,
            named,
            {},
            "test binary must be inside the repository worktree",
        ),
        "a symlink that leaves the repository": (
            root,
            outside,
            named,
            {},
            "test binary must be inside the repository worktree",
        ),
        "another binary name": (root, misnamed, named, {}, binary_refusal),
        "the daemon binary": (root, daemon_harness, named, {}, binary_refusal),
        "a profile outside target/": (
            root,
            harness,
            named,
            {"LLVM_PROFILE_FILE": str(profiles / "x.profraw")},
            "LLVM profile output must be inside the worktree target directory",
        ),
        "a comma in the repository path": (
            comma,
            comma / harness.relative_to(root),
            named,
            {},
            "the repository path must not contain a comma",
        ),
    }
    check_net_admin_runner_happy_path(root, harness, named)
    for description, (runner_root, binary, name, environment, message) in refused.items():
        result = run_runner(runner_root, binary, name, environment)
        if result.returncode != 2 or message not in result.stderr:
            raise SystemExit(
                f"NET_ADMIN runner did not refuse {description}:"
                f" exit {result.returncode}: {result.stderr}"
            )


def docker_run_arguments(
    root: Path, harness: Path, name: str, environment: dict[str, str]
) -> list[str]:
    """Run the NET_ADMIN runner against a fake `docker` and return the
    arguments it passed, after requiring that the runner succeeded."""
    fake = root / "fake-bin"
    fake.mkdir(exist_ok=True)
    log = root / "docker-arguments"
    docker = fake / "docker"
    docker.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        f"open({str(log)!r}, 'w').write('\\0'.join(sys.argv[1:]))\n"
        "for argument in sys.argv[1:]:\n"
        "    if argument.endswith(',target=/pigloros-profile.profraw'):\n"
        "        source = argument.split('source=', 1)[1].split(',', 1)[0]\n"
        "        open(source, 'w').write('profile')\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    result = run_runner(
        root,
        harness,
        name,
        {**environment, "PATH": f"{fake}:{os.environ['PATH']}"},
    )
    if result.returncode != 0:
        raise SystemExit(f"NET_ADMIN runner failed on its happy path: {result.stderr}")
    return log.read_text(encoding="utf-8").split("\0")


def check_net_admin_runner_happy_path(root: Path, harness: Path, named: str) -> None:
    """The runner passes exactly its pinned options to `docker run`."""
    profiles = root / "target/llvm-cov-target"
    profiles.mkdir(parents=True, exist_ok=True)
    arguments = docker_run_arguments(
        root,
        harness,
        named,
        {"LLVM_PROFILE_FILE": str(profiles / "x.profraw"), "ASAN_OPTIONS": "detect_leaks=1"},
    )
    expected_tail = [
        "/bin/sh",
        "-c",
        'if [ -w "$1" ]; then echo "the worktree bind is writable" >&2; exit 1; fi; shift; exec "$@"',
        "read-only-probe",
        str(root),
        str(harness),
        "--exact",
        named,
        "--nocapture",
    ]
    if arguments[0] != "run" or arguments[-len(expected_tail) :] != expected_tail:
        raise SystemExit(f"NET_ADMIN runner ran docker unexpectedly: {arguments}")
    options = arguments[1 : -len(expected_tail) - 1]
    for required in (
        ["--cap-drop", "ALL"],
        ["--cap-add", "NET_ADMIN"],
        ["--cap-add", "SYS_ADMIN"],
        ["--network", "none"],
        ["--env", "ASAN_OPTIONS=detect_leaks=1"],
    ):
        if not any(options[i : i + 2] == required for i in range(len(options))):
            raise SystemExit(f"NET_ADMIN runner omitted {required}: {options}")
    if any(option.startswith("apparmor") for option in options):
        raise SystemExit(f"NET_ADMIN runner dropped AppArmor for {named}: {options}")
    # The namespace-pinning tests, and only they, run without AppArmor.
    pinning = named.replace("::netlink::", "::control::")
    pinned = docker_run_arguments(root, harness, pinning, {})
    if "apparmor=unconfined" not in pinned or pinned.count("--security-opt") != 2:
        raise SystemExit(f"NET_ADMIN runner kept AppArmor for {pinning}: {pinned}")


def edited_bytes(content: bytes) -> list[bytes]:
    """`content` with one byte changed, added or removed, at its start,
    middle and end."""
    middle = len(content) // 2
    flipped = [
        content[:index] + bytes([content[index] ^ 0x01]) + content[index + 1 :]
        for index in (0, middle, len(content) - 1)
    ]
    return [*flipped, content + b" ", content[:-1], content[:middle] + content[middle + 1 :]]


def check_runner_pins(temporary: Path) -> None:
    """A runner passes only as exactly its pinned content: any one-byte edit,
    an unpinned runner and a missing pinned runner all fail."""
    for runner in RUNNER_PATHS:
        content = (ROOT / runner).read_bytes()
        for index, edited in enumerate(edited_bytes(content)):
            root = temporary / f"edited-{runner.name}-{index}"
            copy_fixture(root)
            (root / runner).write_bytes(edited)
            if invoke(root).returncode == 0:
                raise SystemExit(f"checker accepted a one-byte edit {index} of {runner}")
    unpinned = temporary / "unpinned"
    copy_fixture(unpinned)
    shutil.copy2(ROOT / PRIMARY_RUNNER, unpinned / "scripts/run-isolated-extra-test.sh")
    if invoke(unpinned).returncode == 0:
        raise SystemExit("checker accepted a runner without a pin")
    missing = temporary / "missing"
    copy_fixture(missing)
    (missing / PRIMARY_RUNNER).unlink()
    if invoke(missing).returncode == 0:
        raise SystemExit("checker accepted a missing pinned runner")
    unexecutable = temporary / "unexecutable"
    copy_fixture(unexecutable)
    (unexecutable / PRIMARY_RUNNER).chmod(0o644)
    if invoke(unexecutable).returncode == 0:
        raise SystemExit("checker accepted a runner that is not executable")


def repinned(
    temporary: Path, name: str, runner: Path, old: str, new: str
) -> subprocess.CompletedProcess[str]:
    """The checker's verdict on `runner` edited from `old` to `new` with its
    pin moved to the edited content."""
    root = temporary / f"repinned-{name}"
    copy_fixture(root)
    target = root / runner
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"fixture fragment missing in {runner}: {old}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    checker = root / "scripts/check_isolated_test_runner_policy.py"
    pin = hashlib.sha256((ROOT / runner).read_bytes()).hexdigest()
    moved = hashlib.sha256(target.read_bytes()).hexdigest()
    source = CHECKER.read_text(encoding="utf-8")
    if pin not in source:
        raise SystemExit(f"the checker does not pin {runner}")
    checker.write_text(source.replace(pin, moved), encoding="utf-8")
    return invoke(root, checker)


def check_repinned_runners(temporary: Path) -> None:
    """A pin moved to a runner that drops a structural guarantee still fails,
    and one moved to a harmless edit passes."""
    harmless = repinned(
        temporary, "comment", NET_ADMIN_RUNNER, "set -euo pipefail\n", "set -euo pipefail\n# reviewed\n"
    )
    if harmless.returncode != 0:
        raise SystemExit(f"checker refused a re-pinned harmless edit: {harmless.stderr}")
    unsafe = (
        (PRIMARY_RUNNER, "--network none", "--network host"),
        (PRIMARY_RUNNER, "  --cap-drop ALL\n", "  --cap-drop ALL\n  --cap-add SYS_ADMIN\n"),
        (PRIMARY_RUNNER, "  --rm\n", "  --rm\n  --privileged\n"),
        (PRIMARY_RUNNER, "@sha256:", ":latest@x"),
        (PRIMARY_RUNNER, "docker run", "sudo -n docker run"),
        (NET_ADMIN_RUNNER, "  --cap-drop ALL\n", "  --cap-add ALL\n"),
        (NET_ADMIN_RUNNER, "  --cap-add NET_ADMIN\n", "  --cap-add NET_RAW\n"),
        (NET_ADMIN_RUNNER, "  --read-only\n", "\n"),
        (NET_ADMIN_RUNNER, "readonly TEST_PATTERN=", "readonly UNUSED_PATTERN="),
        (NET_ADMIN_RUNNER, "if [[ $REPOSITORY_ROOT == *,* ]]; then", "if false; then"),
        (NET_ADMIN_RUNNER, "if [ -w \"$1\" ]; then", "if false; then"),
        # AppArmor stays for every other test and every other runner.
        (PRIMARY_RUNNER, "  --rm\n", "  --rm\n  --security-opt apparmor=unconfined\n"),
        (
            NET_ADMIN_RUNNER,
            "readonly UNCONFINED_PATTERN='^namespace_network::control::tests::privileged::[a-z0-9_]+$'",
            "readonly UNCONFINED_PATTERN='^namespace_network::'",
        ),
        (NET_ADMIN_RUNNER, "--security-opt apparmor=unconfined", "--security-opt seccomp=unconfined"),
        (NET_ADMIN_RUNNER, "  --rm\n", "  --rm\n  --security-opt seccomp=unconfined\n"),
    )
    for index, (runner, old, new) in enumerate(unsafe):
        if repinned(temporary, str(index), runner, old, new).returncode == 0:
            raise SystemExit(f"checker accepted re-pinned unsafe {runner}: {old} -> {new}")


def main() -> None:
    baseline = invoke(ROOT)
    if baseline.returncode != 0:
        raise SystemExit(baseline.stderr or baseline.stdout)

    mutations = (
        (
            Path(".github/workflows/ci.yml"),
            "name: cargo test with ASan",
            "name: reduced sanitizer test",
        ),
        (
            Path(".github/workflows/mutation.yml"),
            "cargo mutants",
            "cargo test",
        ),
        (
            PRIMARY_OWNER,
            PRIMARY_RUNNER.name,
            "missing-isolated-runner.sh",
        ),
    )
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        check_net_admin_runner_guards(temporary)
        check_runner_pins(temporary)
        check_repinned_runners(temporary)
        # A changed caller must still be rejected when another caller retains
        # the valid runner reference, so owner discovery cannot hide the fault.
        multiple_owners = temporary / "multiple-owners"
        copy_fixture(multiple_owners)
        caller = multiple_owners / PRIMARY_OWNER
        (multiple_owners / "crates/extra-runner-owner.rs").write_text(
            caller.read_text(encoding="utf-8"), encoding="utf-8"
        )
        caller.write_text(
            caller.read_text(encoding="utf-8").replace(
                PRIMARY_RUNNER.name, "unrecognized-runner.sh"
            ),
            encoding="utf-8",
        )
        if invoke(multiple_owners).returncode == 0:
            raise SystemExit("another valid caller concealed an unrecognized runner")
        # Only the Local namespace adapter may own the NET_ADMIN runner.
        foreign_owner = temporary / "foreign-net-admin-owner"
        copy_fixture(foreign_owner)
        (foreign_owner / "apps/pos-sandboxd/src/foreign_owner.rs").write_text(
            (foreign_owner / NET_ADMIN_OWNER_PATHS[0]).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        if invoke(foreign_owner).returncode == 0:
            raise SystemExit("a foreign owner of the NET_ADMIN runner was accepted")
        for index, (relative, old, new) in enumerate(mutations):
            fixture_root = temporary / str(index)
            copy_fixture(fixture_root)
            target = fixture_root / relative
            text = target.read_text(encoding="utf-8")
            if old not in text:
                raise SystemExit(f"fixture fragment missing in {relative}: {old}")
            target.write_text(text.replace(old, new, 1), encoding="utf-8")
            if invoke(fixture_root).returncode == 0:
                raise SystemExit(f"checker accepted invalid {relative}: {old}")


if __name__ == "__main__":
    main()
