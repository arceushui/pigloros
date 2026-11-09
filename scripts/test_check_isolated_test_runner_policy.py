#!/usr/bin/env python3
"""Adversarial tests for the generic isolated-runner policy checker."""

from __future__ import annotations

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


def invoke(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
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
        (
            PRIMARY_RUNNER,
            "--network none",
            "--network host",
        ),
        (
            PRIMARY_RUNNER,
            "timeout --signal=TERM --kill-after=5s 30s",
            "timeout 30s",
        ),
        (
            PRIMARY_RUNNER,
            "docker run",
            "sudo -n docker run",
        ),
        (
            PRIMARY_RUNNER,
            "--tmpfs /run:rw,nosuid,nodev,mode=0755,size=64m",
            "rm -rf /run",
        ),
        (
            PRIMARY_RUNNER,
            "--memory 2g",
            "--memory 0",
        ),
        (
            PRIMARY_RUNNER,
            "--memory-swap 2g",
            "--memory-swap -1",
        ),
        (
            PRIMARY_RUNNER,
            "--ulimit fsize=268435456:268435456",
            "--ulimit fsize=-1:-1",
        ),
        (
            PRIMARY_RUNNER,
            "--tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=512m",
            "--tmpfs /tmp:rw,nosuid,nodev,mode=1777",
        ),
        (
            PRIMARY_RUNNER,
            "--read-only",
            "--read-write",
        ),
        (
            PRIMARY_RUNNER,
            "--cap-drop ALL",
            "--cap-drop NET_ADMIN",
        ),
        (
            PRIMARY_RUNNER,
            "source=$profile_output,target=/pigloros-profile.profraw",
            "source=$profile_directory,target=/pigloros-profile",
        ),
        (
            PRIMARY_RUNNER,
            'chmod 0666 "$profile_output"',
            'chmod 0600 "$profile_output"',
        ),
        (
            PRIMARY_RUNNER,
            "@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254",
            ":latest",
        ),
        (
            PRIMARY_RUNNER,
            "set +e",
            "docker_arguments+=(--memory 0)\nset +e",
        ),
        (
            PRIMARY_RUNNER,
            "set +e",
            "docker_arguments+=(--read-only=false)\nset +e",
        ),
        (
            PRIMARY_RUNNER,
            "set +e",
            "docker_arguments+=(--cap-add SYS_ADMIN)\nset +e",
        ),
        (
            NET_ADMIN_RUNNER,
            "set +e",
            "docker_arguments+=(--cap-add SYS_PTRACE)\nset +e",
        ),
        (
            NET_ADMIN_RUNNER,
            "  --cap-add NET_ADMIN\n",
            "  --cap-add NET_RAW\n",
        ),
        (
            NET_ADMIN_RUNNER,
            "readonly TEST_PATTERN='^namespace_network::(netlink|control)::tests::privileged::[a-z0-9_]+$'",
            "readonly TEST_PATTERN='^namespace_network::'",
        ),
        (
            NET_ADMIN_RUNNER,
            "--network none",
            "--network host",
        ),
        # A commented-out capability cannot stand in for a widened one.
        (
            NET_ADMIN_RUNNER,
            "  --cap-add NET_ADMIN\n",
            "  # --cap-add NET_ADMIN\n  --cap-add ALL\n",
        ),
        (
            NET_ADMIN_RUNNER,
            "  --cap-add SYS_ADMIN\n",
            "  --cap-add=ALL\n",
        ),
        (
            NET_ADMIN_RUNNER,
            " ||\n  $TEST_BINARY -ef $TEST_DIRECTORY/../pos-sandboxd ]]; then",
            " ]]; then",
        ),
        (
            NET_ADMIN_RUNNER,
            "pos_sandboxd-[0-9a-f]{16}$'",
            "pos_sandboxd-.*$'",
        ),
        (
            NET_ADMIN_RUNNER,
            "if [ -w \"$1\" ]; then",
            "if false; then",
        ),
        (
            NET_ADMIN_RUNNER,
            "if [[ $REPOSITORY_ROOT == *,* ]]; then",
            "if false; then",
        ),
        (
            NET_ADMIN_RUNNER,
            "  --rm\n",
            "  --rm\n  --device /dev/kmsg\n",
        ),
        (
            NET_ADMIN_RUNNER,
            "  --rm\n",
            "  --rm\n  --pid host\n",
        ),
        (
            NET_ADMIN_RUNNER,
            "  --rm\n",
            "  --rm\n  -v /:/host\n",
        ),
        (
            NET_ADMIN_RUNNER,
            "  --rm\n",
            "  --rm\n  --mount type=bind,source=/,target=/host\n",
        ),
        (
            NET_ADMIN_RUNNER,
            "  --rm\n",
            "  --rm\n  --userns host\n",
        ),
        (
            NET_ADMIN_RUNNER,
            "  --rm\n",
            "  --rm\n  --env-file /etc/environment\n",
        ),
        (
            PRIMARY_RUNNER,
            "  --rm\n",
            "  --rm\n  --security-opt apparmor=unconfined\n",
        ),
        # AppArmor stays for every other test, and no other confinement is
        # dropped.
        (
            NET_ADMIN_RUNNER,
            "readonly UNCONFINED_PATTERN='^namespace_network::control::tests::privileged::[a-z0-9_]+$'",
            "readonly UNCONFINED_PATTERN='^namespace_network::'",
        ),
        (
            NET_ADMIN_RUNNER,
            "if [[ $TEST_NAME =~ $UNCONFINED_PATTERN ]]; then",
            "if true; then",
        ),
        (
            NET_ADMIN_RUNNER,
            "  docker_arguments+=(--security-opt apparmor=unconfined)\n",
            "  docker_arguments+=(--security-opt seccomp=unconfined)\n",
        ),
        (
            NET_ADMIN_RUNNER,
            "  --rm\n",
            "  --rm\n  --security-opt=apparmor=unconfined\n",
        ),
        # The allowlist refuses every option it does not name.
        *(
            (runner, "  --rm\n", f"  --rm\n  {option}\n")
            for runner in (PRIMARY_RUNNER, NET_ADMIN_RUNNER)
            for option in (
                "--net host",
                "--net=host",
                "--volumes-from other",
                "--sysctl net.ipv4.ip_forward=1",
                "--cgroup-parent /",
                "--runtime runc",
                "--tmpfs /dev/shm",
                "-e DOCKER=1",
            )
        ),
        (
            NET_ADMIN_RUNNER,
            'docker run "${docker_arguments[@]}" "$ISOLATION_IMAGE"',
            'docker run "${docker_arguments[@]}" --net host "$ISOLATION_IMAGE"',
        ),
        (
            NET_ADMIN_RUNNER,
            "profile_output=\n",
            "profile_output=\ndocker_arguments[0]=--privileged\n",
        ),
        (
            NET_ADMIN_RUNNER,
            "profile_output=\n",
            "profile_output=\nextra=(--privileged)\ndocker_arguments+=(\"${extra[@]}\")\n",
        ),
        (
            NET_ADMIN_RUNNER,
            "set +e\n",
            "set +e\ndocker create --privileged \"$ISOLATION_IMAGE\"\n",
        ),
        # A guard that only a comment mentions is absent.
        (
            NET_ADMIN_RUNNER,
            "if [[ $REPOSITORY_ROOT == *,* ]]; then",
            "# if [[ $REPOSITORY_ROOT == *,* ]]; then\nif false; then",
        ),
        (
            NET_ADMIN_RUNNER,
            "readonly TEST_PATTERN=",
            "# readonly TEST_PATTERN='^namespace_network::netlink::tests::privileged::[a-z0-9_]+$'\n"
            "readonly TEST_PATTERN='.*'\n# readonly TEST_PATTERN=",
        ),
    )
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        check_net_admin_runner_guards(temporary)
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
