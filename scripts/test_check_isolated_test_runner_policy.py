#!/usr/bin/env python3
"""Adversarial tests for the generic isolated-runner policy checker."""

from __future__ import annotations

import hashlib
import os
import re
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
NET_ADMIN_RUNNER = Path("scripts/run-isolated-with-net-admin-test.sh")
RUST_SOURCES = tuple(
    source.relative_to(ROOT)
    for top in ("apps", "crates", "fuzz", "plugins", "scripts")
    for source in sorted((ROOT / top).glob("**/*.rs"))
)
OWNER_PATHS = tuple(
    source
    for source in RUST_SOURCES
    if any(
        runner.name in (ROOT / source).read_text(encoding="utf-8")
        for runner in RUNNERS
        if runner.name != NET_ADMIN_RUNNER.name
    )
)
NET_ADMIN_OWNER_PATHS = tuple(
    source
    for source in RUST_SOURCES
    if NET_ADMIN_RUNNER.name in (ROOT / source).read_text(encoding="utf-8")
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
    check_net_admin_runner_environment(root, harness, named)
    for description, (runner_root, binary, name, environment, message) in refused.items():
        result = run_runner(runner_root, binary, name, environment)
        if result.returncode != 2 or message not in result.stderr:
            raise SystemExit(
                f"NET_ADMIN runner did not refuse {description}:"
                f" exit {result.returncode}: {result.stderr}"
            )


SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
RUNNER_PATH = f"readonly RUNNER_PATH={SYSTEM_PATH}\n"


def fake_docker(root: Path) -> Path:
    """The runner in `root`, its fixed PATH led by a directory holding a fake
    `docker` that logs its arguments and environment and writes the coverage
    profile it is handed; returns that directory."""
    fake = root / "fake-bin"
    if fake.exists():
        return fake
    fake.mkdir()
    docker = fake / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\0' \"$@\" > '{root}/docker-arguments'\n"
        f"env > '{root}/docker-environment'\n"
        'for argument in "$@"; do\n'
        '  case $argument in\n'
        "    *,target=/pigloros-profile.profraw)\n"
        '      source=${argument#*source=}\n'
        '      echo profile > "${source%%,*}"\n'
        "      ;;\n"
        "  esac\n"
        "done\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    runner = root / NET_ADMIN_RUNNER
    text = runner.read_text(encoding="utf-8")
    if text.count(RUNNER_PATH) != 1:
        raise SystemExit(f"{NET_ADMIN_RUNNER} does not fix its PATH: {RUNNER_PATH}")
    runner.write_text(
        text.replace(RUNNER_PATH, f"readonly RUNNER_PATH={fake}:{SYSTEM_PATH}\n"),
        encoding="utf-8",
    )
    return fake


def docker_run_arguments(
    root: Path, harness: Path, name: str, environment: dict[str, str]
) -> list[str]:
    """Run the NET_ADMIN runner against a fake `docker` and return the
    arguments it passed, after requiring that the runner succeeded."""
    fake_docker(root)
    result = run_runner(root, harness, name, environment)
    if result.returncode != 0:
        raise SystemExit(f"NET_ADMIN runner failed on its happy path: {result.stderr}")
    return (root / "docker-arguments").read_text(encoding="utf-8").split("\0")[:-1]


def check_net_admin_runner_environment(root: Path, harness: Path, named: str) -> None:
    """Nothing in the caller's environment runs, picks a program or reaches
    Docker: no BASH_ENV or ENV file, no PATH entry, no Docker variable."""
    fake = fake_docker(root)
    marker = root / "caller-environment-ran"
    hostile = root / "hostile-bin"
    hostile.mkdir()
    for program in ("docker", "env", "timeout", "realpath", "mktemp", "chmod", "dirname"):
        (hostile / program).write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
        (hostile / program).chmod(0o755)
    startup = root / "startup.sh"
    startup.write_text(f"touch '{marker}'\n", encoding="utf-8")
    docker_run_arguments(
        root,
        harness,
        named,
        {
            "PATH": f"{hostile}:{os.environ['PATH']}",
            "BASH_ENV": str(startup),
            "ENV": str(startup),
            "DOCKER_HOST": "tcp://192.0.2.1:2375",
            "DOCKER_CONTEXT": "hostile",
            "DOCKER_CONFIG": str(hostile),
            "BASH_FUNC_docker%%": f"() {{ touch '{marker}'; }}",
        },
    )
    if marker.exists():
        raise SystemExit("the NET_ADMIN runner ran something its caller's environment named")
    expected = {
        "PATH": f"{fake}:{SYSTEM_PATH}",
        "HOME": "/nonexistent",
        "DOCKER_HOST": "unix:///var/run/docker.sock",
    }
    if docker_environment(root) != expected:
        raise SystemExit(f"Docker ran under an environment other than its own: {docker_environment(root)}")
    # The runner's own override names a rootless daemon's unix socket.
    rootless = "unix:///run/user/1000/docker.sock"
    docker_run_arguments(root, harness, named, {"PIGLOR_ISOLATED_DOCKER_HOST": rootless})
    if docker_environment(root) != {**expected, "DOCKER_HOST": rootless}:
        raise SystemExit(f"Docker ignored the runner's socket override: {docker_environment(root)}")
    # Anything but a unix socket at an absolute path is refused before Docker.
    for invalid in (
        "tcp://192.0.2.1:2375",
        "ssh://host",
        "unix://run/docker.sock",
        "unix:///run/../tmp/docker.sock",
        "unix:///run/docker.sock extra",
        "unix:///run/docker.sock\nunix:///x",
    ):
        (root / "docker-arguments").unlink(missing_ok=True)
        result = run_runner(root, harness, named, {"PIGLOR_ISOLATED_DOCKER_HOST": invalid})
        refused = "PIGLOR_ISOLATED_DOCKER_HOST must be unix:// and an absolute socket path"
        if (
            result.returncode != 2
            or refused not in result.stderr
            or (root / "docker-arguments").exists()
        ):
            raise SystemExit(
                f"the runner accepted the Docker socket override {invalid!r}:"
                f" exit {result.returncode}: {result.stderr}"
            )


def docker_environment(root: Path) -> dict[str, str]:
    """The environment the fake `docker` in `root` last ran under."""
    seen = dict(
        line.split("=", 1)
        for line in (root / "docker-environment").read_text(encoding="utf-8").splitlines()
    )
    seen.pop("PWD", None)
    return seen


def check_read_only_probe(temporary: Path) -> None:
    """The in-container probe starts the test only while the binary's bind
    refuses writes, passes on the test's status, and fails if the test left
    the bind writable."""
    match = re.search(
        r"^readonly READ_ONLY_PROBE='([^']+)'$",
        (ROOT / NET_ADMIN_RUNNER).read_text(encoding="utf-8"),
        re.M,
    )
    if match is None:
        raise SystemExit(f"{NET_ADMIN_RUNNER} has no read-only probe")
    binary = temporary / "probed-binary"
    started = temporary / "probed-binary-started"
    cases = (
        ("a writable bind", 0o755, f"touch '{started}'", 1, "the test binary bind is writable"),
        ("a test that fails", 0o555, "exit 3", 3, ""),
        ("a test that passes", 0o555, f"touch '{started}'", 0, ""),
        (
            "a test that makes the bind writable",
            0o555,
            'chmod 0755 "$0"',
            1,
            "the test binary bind became writable",
        ),
    )
    for description, mode, test, status, message in cases:
        started.unlink(missing_ok=True)
        if binary.exists():
            binary.chmod(0o755)
        binary.write_text(f"#!/bin/sh\n[ \"$*\" = '--exact a_test' ] || exit 9\n{test}\n", encoding="utf-8")
        binary.chmod(mode)
        if os.access(binary, os.W_OK) != bool(mode & 0o200):
            raise SystemExit("the probe self-test needs an unprivileged user")
        result = subprocess.run(
            ["/bin/sh", "-c", match.group(1), "read-only-probe", str(binary), "--exact", "a_test"],
            check=False,
            capture_output=True,
            text=True,
        )
        if (
            result.returncode != status
            or message not in result.stderr
            or started.exists() != (description == "a test that passes")
        ):
            raise SystemExit(
                f"the read-only probe mishandled {description}:"
                f" exit {result.returncode}: {result.stderr}"
            )


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
        'if [ -w "$1" ]; then echo "the test binary bind is writable" >&2; exit 1; fi; "$@"; '
        'status=$?; if [ -w "$1" ]; then echo "the test binary bind became writable" >&2; '
        'exit 1; fi; exit "$status"',
        "read-only-probe",
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
        ["--mount", f"type=bind,source={harness},target={harness},readonly"],
        ["--workdir", "/tmp"],
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
    # The container sees the test binary and its profile, not the worktree.
    binds = [option for option in options if "source=" in option]
    if len(binds) != 2 or any(str(harness) not in bind and "profraw" not in bind for bind in binds):
        raise SystemExit(f"NET_ADMIN runner binds more of the host than the test binary: {binds}")


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
    # A runner that is a symlink fails even when it names a byte-identical,
    # executable copy.
    linked = temporary / "linked"
    copy_fixture(linked)
    shutil.copy2(ROOT / PRIMARY_RUNNER, linked / "linked-runner.sh")
    (linked / PRIMARY_RUNNER).unlink()
    (linked / PRIMARY_RUNNER).symlink_to(linked / "linked-runner.sh")
    result = invoke(linked)
    if result.returncode == 0 or "must be a regular file" not in result.stderr:
        raise SystemExit(f"checker accepted a runner that is a symlink: {result.stderr}")
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
        temporary,
        "comment",
        NET_ADMIN_RUNNER,
        "readonly ISOLATION_IMAGE=",
        "# reviewed\nreadonly ISOLATION_IMAGE=",
    )
    if harmless.returncode != 0:
        raise SystemExit(f"checker refused a re-pinned harmless edit: {harmless.stderr}")
    unsafe = (
        (PRIMARY_RUNNER, "--network none", "--network host"),
        (PRIMARY_RUNNER, "  --cap-drop ALL\n", "  --cap-drop ALL\n  --cap-add SYS_ADMIN\n"),
        (PRIMARY_RUNNER, "  --rm\n", "  --rm\n  --privileged\n"),
        (PRIMARY_RUNNER, "@sha256:", ":latest@x"),
        (PRIMARY_RUNNER, "docker run", "sudo -n docker run"),
        (PRIMARY_RUNNER, "#!/bin/bash -p\n", "#!/usr/bin/env bash\n"),
        (PRIMARY_RUNNER, "export PATH=$RUNNER_PATH\n", "\n"),
        (PRIMARY_RUNNER, "set -euo pipefail\nreadonly", "set -euo pipefail\nsource \"$BASH_ENV\"\nreadonly"),
        (
            PRIMARY_RUNNER,
            'env -i "PATH=$RUNNER_PATH" HOME=/nonexistent "DOCKER_HOST=$DOCKER_SOCKET" \\\n',
            "",
        ),
        (PRIMARY_RUNNER, '"DOCKER_HOST=$DOCKER_SOCKET"', 'DOCKER_HOST="$DOCKER_HOST"'),
        (PRIMARY_RUNNER, " || $DOCKER_SOCKET == *..* ]]", " ]]"),
        (PRIMARY_RUNNER, "^unix:///[A-Za-z0-9._/-]+$", "^[a-z]+://.+$"),
        (PRIMARY_RUNNER, "set +e\n", 'set +e\ndocker run --rm "$ISOLATION_IMAGE" true\n'),
        (PRIMARY_RUNNER, "source=$REPOSITORY_ROOT,", "source=/,"),
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
            "readonly UNCONFINED_PATTERN='^namespace_network::(control|attempt_network)::tests::privileged::[a-z0-9_]+$'",
            "readonly UNCONFINED_PATTERN='^namespace_network::'",
        ),
        (NET_ADMIN_RUNNER, "--security-opt apparmor=unconfined", "--security-opt seccomp=unconfined"),
        (NET_ADMIN_RUNNER, "  --rm\n", "  --rm\n  --security-opt seccomp=unconfined\n"),
        (NET_ADMIN_RUNNER, '"$@"; status=$?; if [ -w "$1" ]; then', 'exec "$@"; if false; then'),
        (NET_ADMIN_RUNNER, "source=$TEST_BINARY,target=$TEST_BINARY", "source=$REPOSITORY_ROOT,target=$REPOSITORY_ROOT"),
        (
            NET_ADMIN_RUNNER,
            '  --workdir /tmp\n',
            '  --workdir /tmp\n  --mount "type=bind,source=$REPOSITORY_ROOT,target=$REPOSITORY_ROOT,readonly"\n',
        ),
    )
    for index, (runner, old, new) in enumerate(unsafe):
        if repinned(temporary, str(index), runner, old, new).returncode == 0:
            raise SystemExit(f"checker accepted re-pinned unsafe {runner}: {old} -> {new}")


def check_runner_name_pieces(temporary: Path) -> None:
    """A runner named in pieces fails wherever it is, and the NET_ADMIN
    runner's name fails outside the Local namespace adapter in any form;
    comments and quotes inside char literals do not count."""
    allowed = Path("apps/pos-sandboxd/src/namespace_network/pieces.rs")
    refused = {
        "a concatenated NET_ADMIN runner in apps": (
            Path("apps/pos-sandboxd/src/pieces.rs"),
            'const RUNNER: &str = concat!("../../scripts/run-isolated-with-", "net-admin-test.sh");\n',
        ),
        "a NET_ADMIN runner split inside its distinctive piece": (
            Path("crates/pieces/src/lib.rs"),
            'const RUNNER: &str = concat!("run-isolated-with-net", "-admin-test.sh");\n',
        ),
        "a formatted NET_ADMIN runner": (
            Path("plugins/pieces/src/lib.rs"),
            'fn runner() -> String { format!("{}-{}", "with-NET", r#"ADMIN"#) }\n',
        ),
        "a concatenated runner inside the adapter": (
            allowed,
            'const RUNNER: &str = concat!("../../scripts/run-", "isolated-test.sh");\n',
        ),
        "a NET_ADMIN fragment spelled as a char array": (
            Path("crates/pieces/src/lib.rs"),
            "const PIECE: [char; 8] = ['n', 'e', 't', '-', 'a', 'd', 'm', 'i'];\n"
            "const REST: [u8; 1] = [b'n'];\n",
        ),
        "a runner spelled as a char array": (
            Path("apps/pos-sandboxd/src/pieces.rs"),
            "const NAME: [char; 11] = ['r', 'u', 'n', '-', 'i', 's', 'o', 'l', 'a', 't', 'e'];\n"
            "const END: char = 'd';\n",
        ),
        "an undiscovered runner in apps": (
            Path("apps/pos-sandboxd/src/pieces.rs"),
            'fn f(p: &Path) -> PathBuf { p.join("../../scripts/run-isolated-other-test.sh") }\n',
        ),
    }
    accepted = {
        "comments and char literals": (
            Path("crates/pieces/src/lib.rs"),
            "// run-isolated-with-net-admin-test.sh is the NET_ADMIN runner.\n"
            "/* run-isolated-test.sh */\n"
            "const QUOTE: char = '\"'; const LABEL: &str = \"net\"; fn f<'a>(_: &'a str) {}\n"
            "const OTHER: char = '\"'; const ADMINISTRATOR: &str = \"x\";\n",
        ),
        # A known gap of this best-effort lint: format! may reorder the pieces
        # of a name. The runner's own harness and test-name guards still
        # refuse any test it was not written for.
        "a runner whose pieces format! reorders": (
            Path("crates/pieces/src/lib.rs"),
            'fn runner() -> String { format!("run-{}-test.sh", "isolated") }\n',
        ),
        "the adapter naming its own runner's capability": (
            allowed,
            'const CAPABILITY: &str = "NET_ADMIN";\n',
        ),
    }
    for verdict, cases in ((False, refused), (True, accepted)):
        for index, (description, (relative, source)) in enumerate(cases.items()):
            root = temporary / f"pieces-{verdict}-{index}"
            copy_fixture(root)
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(source, encoding="utf-8")
            result = invoke(root)
            if (result.returncode == 0) != verdict:
                raise SystemExit(
                    f"checker {'refused' if verdict else 'accepted'} {description}: {result.stderr}"
                )


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
        check_read_only_probe(temporary)
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
        check_runner_name_pieces(temporary)
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
