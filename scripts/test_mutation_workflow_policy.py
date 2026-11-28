#!/usr/bin/env python3
"""Keep mutation evidence dependent on a passing, identical test harness."""

from __future__ import annotations

import copy
import hashlib
import os
import pathlib
import subprocess
import tempfile
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
NIGHTLY = "nightly-2026-07-01"
BASELINE_RUN = """set -euo pipefail
cargo test --workspace --all-features --locked -- \\
  -Zunstable-options --fail-fast --include-ignored --test-threads=4 \\
  2>&1 | tee "${RUNNER_TEMP}/mutation-baseline.log"
bash scripts/assert-no-ignored-in-test-summary.sh "${RUNNER_TEMP}/mutation-baseline.log"
"""
CHANGES_RUN = """set -euo pipefail
relevant=false
if [[ "$FORCE_MUTATION" = true ]]; then
  relevant=true
else
  changed_paths="${RUNNER_TEMP}/mutation-changes.paths"
  git diff --name-only --diff-filter=ACMRT -z "$BASE_SHA...$HEAD_SHA" \\
    > "$changed_paths"
  while IFS= read -r -d '' path; do
    case "$path" in
      *.rs|Cargo.toml|*/Cargo.toml|Cargo.lock|rust-toolchain.toml|.cargo/config.toml|fixtures/conformance/*|.github/workflows/mutation.yml|scripts/run_mutation_canary.sh|scripts/test_mutation_workflow_policy.py)
        relevant=true
        break
        ;;
    esac
  done < "$changed_paths"
fi
echo "relevant=$relevant" >> "$GITHUB_OUTPUT"
"""
MUTATION_IF = (
    "needs.mutation-changes.outputs.relevant == 'true' && "
    "needs.mutation-baseline.result == 'success' && "
    "needs.mutation-canary.result == 'success'"
)
GATE_RUN = """set -euo pipefail
test "${{ needs.mutation-changes.result }}" = success
if [[ "${{ needs.mutation-changes.outputs.relevant }}" = true ]]; then
  test "${{ needs.mutation-baseline.result }}" = success
  test "${{ needs.mutation-canary.result }}" = success
  test "${{ needs.mutation.result }}" = success
else
  test "${{ needs.mutation-baseline.result }}" = skipped
  test "${{ needs.mutation-canary.result }}" = skipped
  test "${{ needs.mutation.result }}" = skipped
fi
"""
CANARY_RUN = "bash scripts/run_mutation_canary.sh"
CANARY_SCRIPT_SHA256 = "63b2cd804a68009427485f06dc24a7880cabda0968e9a8fdb104c55d89cb6792"
# Pin the complete reviewed parsed program, including comments and heredoc data.
# This policy snapshot is not a shell-semantics oracle; digest changes need review.
MUTATION_RUN_SHA256 = (
    "8db86bdd9fb7b873e7014b286b0e61ec0f3134a508fe490a0cc2be044746a70b"
)
SHARED_HARNESS_ARGS = [
    "--workspace", "--all-features", "--no-shuffle", "--baseline", "run",
    "--jobs", "1", "--cap-lints", "true", "--cargo-arg=--locked",
    "--", "--", "-Zunstable-options", "--fail-fast", "--include-ignored",
    "--test-threads=4",
]
BASELINE_STEPS = [
    {
        "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    },
    {
        "uses": "dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8",
        "with": {"toolchain": "${{ env.RUSTUP_TOOLCHAIN }}"},
    },
    {
        "uses": "Swatinem/rust-cache@eedcf2fb1c22f010a0eb66b92f378c110977f266",
        "with": {"shared-key": "mutation"},
    },
    {
        "name": "Prove the mutation test harness",
        "env": {"CARGO_INCREMENTAL": "1"},
        "run": BASELINE_RUN,
    },
    {
        "name": "Upload mutation baseline log",
        "if": "always()",
        "uses": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
        "with": {
            "name": "mutation-baseline",
            "path": "${{ runner.temp }}/mutation-baseline.log",
            "if-no-files-found": "error",
        },
    },
]
MUTATION_DIFF_RUN = """set -euo pipefail
base_ref="${{ github.event.pull_request.base.ref || github.event.repository.default_branch }}"
git diff --relative --unified=0 \\
  "origin/${base_ref}...HEAD" \\
  > "${RUNNER_TEMP}/changes.diff"
"""


def cargo_mutants_arguments(command: str) -> list[str]:
    tokens = " ".join(command.replace("\\\n", " ").split()).split()
    start = next(
        (index for index in range(len(tokens) - 1)
         if tokens[index:index + 2] == ["cargo", "mutants"]),
        None,
    )
    if start is None:
        raise AssertionError("mutation producer command must invoke cargo mutants")
    end = next(
        (index for index in range(start + 2, len(tokens))
         if tokens[index].startswith("--test-threads=")),
        None,
    )
    if end is None:
        raise AssertionError("mutation producer command must select its libtest threads")
    return tokens[start + 2:end + 1]


def shared_harness_arguments(arguments: list[str]) -> list[str]:
    shared: list[str] = []
    index = 0
    value_options = {"--baseline", "--jobs", "--cap-lints"}
    standalone_options = {"--workspace", "--all-features", "--no-shuffle"}
    while index < len(arguments):
        argument = arguments[index]
        if argument in standalone_options or argument == "--cargo-arg=--locked":
            shared.append(argument)
        elif argument in value_options:
            shared.extend(arguments[index:index + 2])
            index += 1
        elif argument == "--":
            shared.extend(arguments[index:])
            break
        index += 1
    return shared


def check_contract(workflow: dict, canary_script: str | None = None) -> None:
    """Reject toolchain drift, baseline bypasses, and permissive fan-in."""
    events_key = "on" if "on" in workflow else True
    if set(workflow) != {
        "name", events_key, "permissions", "concurrency", "env", "jobs",
    }:
        raise AssertionError("preserve the reviewed workflow-level controls")
    if workflow.get(events_key) != {
        "workflow_call": None,
        "workflow_dispatch": None,
    }:
        raise AssertionError("preserve the reviewed mutation workflow triggers")
    if workflow.get("permissions") != {"contents": "read"}:
        raise AssertionError("mutation workflow permissions must remain read-only")
    if workflow.get("concurrency") != {
        "group": "mutation-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}",
        "cancel-in-progress": True,
    }:
        raise AssertionError("preserve mutation workflow concurrency controls")
    if workflow.get("env") != {
        "RUSTUP_TOOLCHAIN": NIGHTLY,
        "CARGO_PROFILE_TEST_DEBUG": "line-tables-only",
        "CARGO_BUILD_JOBS": "1",
    }:
        raise AssertionError(
            "baseline and mutants must share the pinned nightly and serial compiler jobs"
        )
    jobs = workflow["jobs"]
    if set(jobs) != {
        "mutation-changes", "mutation-baseline", "mutation-canary",
        "mutation", "mutation-gate",
    }:
        raise AssertionError("preserve the reviewed mutation workflow job set")
    harness_steps = {
        "mutation-baseline": "Prove the mutation test harness",
        "mutation": "Run mutants in changed lines",
    }
    for name in ("mutation-baseline", "mutation"):
        job = jobs[name]
        expected_env = {"CARGO_BUILD_JOBS": "3"} if name == "mutation-baseline" else None
        if job.get("env") != expected_env or "continue-on-error" in job:
            raise AssertionError(
                "only the baseline may select three compiler jobs; failures stay blocking"
            )
        toolchains = [
            step for step in job["steps"]
            if step.get("uses", "").startswith("dtolnay/rust-toolchain@")
        ]
        if len(toolchains) != 1 or toolchains[0].get("with") != {
            "toolchain": "${{ env.RUSTUP_TOOLCHAIN }}"
        }:
            raise AssertionError("install the selected nightly in both jobs")
        for step in job["steps"]:
            expected_step_env = (
                {"CARGO_INCREMENTAL": "1"}
                if step.get("name") == harness_steps[name] else None
            )
            if "continue-on-error" in step or step.get("env") != expected_step_env:
                raise AssertionError(
                    "only harness steps must override incremental compilation; "
                    "all failures stay blocking"
                )
    baseline = jobs["mutation-baseline"]
    if set(baseline) != {
        "name", "needs", "if", "runs-on", "env", "timeout-minutes", "steps",
    }:
        raise AssertionError("baseline job controls must remain allowlisted")
    if (
        baseline.get("name") != "mutation test baseline"
        or baseline.get("needs") != "mutation-changes"
        or baseline.get("runs-on") != "ubuntu-24.04"
        or baseline.get("if") != "needs.mutation-changes.outputs.relevant == 'true'"
        or baseline.get("timeout-minutes") != 30
    ):
        raise AssertionError("baseline must run for every relevant change")
    baseline_runs = [step for step in baseline["steps"] if "run" in step]
    if baseline_runs != [{
        "name": "Prove the mutation test harness",
        "env": {"CARGO_INCREMENTAL": "1"},
        "run": BASELINE_RUN,
    }]:
        raise AssertionError("baseline must execute the complete mutation harness")
    if baseline["steps"] != BASELINE_STEPS:
        raise AssertionError("baseline must retain its ordered, blocking steps and report")
    changes = jobs["mutation-changes"]
    if changes != {
        "name": "detect mutation-relevant changes",
        "runs-on": "ubuntu-24.04",
        "outputs": {"relevant": "${{ steps.changes.outputs.relevant }}"},
        "steps": [
            {
                "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "with": {"fetch-depth": 0},
            },
            {
                "id": "changes",
                "name": "Classify changed paths",
                "env": {
                    "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
                    "HEAD_SHA": "${{ github.event.pull_request.head.sha || github.sha }}",
                    "FORCE_MUTATION": "${{ github.event_name == 'workflow_dispatch' }}",
                },
                "run": CHANGES_RUN,
            },
        ],
    }:
        raise AssertionError("preserve the changed-path producer and canary trigger")
    canary = jobs["mutation-canary"]
    if canary != {
        "name": "mutation gate canary",
        "needs": "mutation-changes",
        "if": "needs.mutation-changes.outputs.relevant == 'true'",
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 10,
        "steps": [
            {
                "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            },
            {
                "uses": "dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8",
                "with": {"toolchain": "${{ env.RUSTUP_TOOLCHAIN }}"},
            },
            {
                "uses": "taiki-e/install-action@ab49d3c64680143e184118bed66a46419fc15519",
                "with": {"tool": "cargo-mutants@27.1.0"},
            },
            {
                "name": "Run the deliberately weakened-test canary",
                "run": CANARY_RUN,
            },
            {
                "name": "Upload mutation canary report",
                "if": "always()",
                "uses": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
                "with": {
                    "name": "mutation-canary",
                    "path": "${{ runner.temp }}/mutation-canary.*/",
                    "if-no-files-found": "error",
                },
            },
        ],
    }:
        raise AssertionError("preserve the ordered, blocking canary execution graph")
    if canary_script is None:
        canary_script = (ROOT / "scripts/run_mutation_canary.sh").read_text(encoding="utf-8")
    if (
        'cp "${script_directory}/../rust-toolchain.toml" "${project}/rust-toolchain.toml"'
        not in canary_script
        or 'pipeline_status=("${PIPESTATUS[@]}")' not in canary_script
        or 'tee_status="${pipeline_status[1]}"' not in canary_script
    ):
        raise AssertionError("the canary must use the repository toolchain and retain its full report")
    mutation = jobs["mutation"]
    if set(mutation) != {
        "name", "needs", "if", "runs-on", "timeout-minutes", "strategy", "steps",
    }:
        raise AssertionError("mutation worker controls must remain allowlisted")
    if (
        mutation.get("name") != "diff mutation testing (shard ${{ matrix.shard }})"
        or mutation.get("needs") != [
            "mutation-changes", "mutation-baseline", "mutation-canary"
        ]
        or mutation.get("if") != MUTATION_IF
        or mutation.get("runs-on") != "ubuntu-24.04"
        or mutation.get("timeout-minutes") != 70
    ):
        raise AssertionError("mutation workers require the reviewed blocking controls")
    if mutation["strategy"] != {
        "fail-fast": False,
        "max-parallel": 8,
        "matrix": {"shard": list(range(16))},
    }:
        raise AssertionError("retain all sixteen blocking shards on at most eight runners")
    installers = [
        step for step in mutation["steps"]
        if step.get("uses", "").startswith("taiki-e/install-action@")
    ]
    if len(installers) != 1 or installers[0].get("with") != {
        "tool": "cargo-mutants@27.1.0"
    }:
        raise AssertionError("retain the validated cargo-mutants version")
    mutation_step = next(
        step for step in mutation["steps"]
        if step.get("name") == "Run mutants in changed lines"
    )
    if "if" in mutation_step:
        raise AssertionError("mutation execution must be unconditional")
    if mutation["steps"] != [
        {
            "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "with": {"fetch-depth": 0},
        },
        {
            "uses": "dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8",
            "with": {"toolchain": "${{ env.RUSTUP_TOOLCHAIN }}"},
        },
        {
            "uses": "Swatinem/rust-cache@eedcf2fb1c22f010a0eb66b92f378c110977f266",
            "with": {"shared-key": "mutation"},
        },
        {
            "uses": "taiki-e/install-action@ab49d3c64680143e184118bed66a46419fc15519",
            "with": {"tool": "cargo-mutants@27.1.0"},
        },
        {"name": "Capture pull-request diff", "run": MUTATION_DIFF_RUN},
        {
            "name": "Run mutants in changed lines",
            "env": {"CARGO_INCREMENTAL": "1"},
            "run": mutation_step["run"],
        },
        {
            "name": "Upload mutation report",
            "if": "always()",
            "uses": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
            "with": {
                "name": "mutation-report-shard-${{ matrix.shard }}",
                "path": "mutants.out",
                "if-no-files-found": "ignore",
            },
        },
    ]:
        raise AssertionError("mutation workers must retain their ordered reviewed steps")
    command = " ".join(mutation_step["run"].replace("\\\n", " ").split())
    required = (
        "timeout --foreground 60m cargo mutants --workspace --all-features "
        '--in-diff "${{ runner.temp }}/changes.diff" --no-shuffle '
        '--shard "${{ matrix.shard }}/16" --baseline run --jobs 1 '
        "--timeout 240 --build-timeout 600 --cap-lints true --cargo-arg=--locked "
        "-- -- -Zunstable-options --fail-fast --include-ignored --test-threads=4 "
        "mutation_status=$? set -e"
    )
    if required not in command or not command.endswith('exit "$mutation_status"'):
        raise AssertionError("preserve mutation scope, limits, harness and exit status")
    if (
        hashlib.sha256(mutation_step["run"].encode("utf-8")).hexdigest()
        != MUTATION_RUN_SHA256
    ):
        raise AssertionError("preserve the reviewed mutation program, not inert command text")
    canary_arguments = cargo_mutants_arguments(canary_script)
    worker_arguments = cargo_mutants_arguments(mutation_step["run"])
    canary_harness = shared_harness_arguments(canary_arguments)
    worker_harness = shared_harness_arguments(worker_arguments)
    if canary_harness != SHARED_HARNESS_ARGS or worker_harness != SHARED_HARNESS_ARGS:
        raise AssertionError("canary and mutation shards must share the test harness")
    if "--annotations=none" not in canary_arguments:
        raise AssertionError("the expected canary survivor must not emit a GitHub warning")
    if hashlib.sha256(canary_script.encode("utf-8")).hexdigest() != CANARY_SCRIPT_SHA256:
        raise AssertionError("preserve the reviewed mutation-canary program")
    gate = jobs["mutation-gate"]
    if gate != {
        "name": "diff mutation testing",
        "if": "always()",
        "needs": [
            "mutation-changes", "mutation-baseline", "mutation-canary", "mutation"
        ],
        "runs-on": "ubuntu-24.04",
        "steps": [{
            "name": "Require every relevant mutation shard to pass",
            "run": GATE_RUN,
        }]
    }:
        raise AssertionError("fan-in must require the baseline and every shard")


class MutationWorkflowPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = yaml.safe_load(
            (ROOT / ".github/workflows/mutation.yml").read_text(encoding="utf-8")
        )

    def test_repository_contract(self) -> None:
        check_contract(self.workflow)
        ci = yaml.safe_load(
            (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        )
        self.assertIn(
            {"name": "Test mutation workflow policy",
             "run": "python scripts/test_mutation_workflow_policy.py"},
            ci["jobs"]["pinned-dependencies"]["steps"],
        )

    def test_rejects_trigger_permission_and_job_set_drift(self) -> None:
        on_key = "on" if "on" in self.workflow else True
        cases = []

        missing_trigger = copy.deepcopy(self.workflow)
        missing_trigger[on_key].pop("workflow_dispatch")
        cases.append(("missing dispatch trigger", missing_trigger))

        elevated_permissions = copy.deepcopy(self.workflow)
        elevated_permissions["permissions"]["contents"] = "write"
        cases.append(("write permission", elevated_permissions))

        extra_job = copy.deepcopy(self.workflow)
        extra_job["jobs"]["unreviewed"] = {"runs-on": "ubuntu-latest", "steps": []}
        cases.append(("extra job", extra_job))

        workflow_shell_override = copy.deepcopy(self.workflow)
        workflow_shell_override["defaults"] = {"run": {"shell": "bash {0}"}}
        cases.append(("workflow shell override", workflow_shell_override))

        for description, changed in cases:
            with self.subTest(change=description), self.assertRaises(AssertionError):
                check_contract(changed)

    def test_rejects_job_graph_bypasses(self) -> None:
        cases = []

        gate_shell_override = copy.deepcopy(self.workflow)
        gate_shell_override["jobs"]["mutation-gate"]["defaults"] = {
            "run": {"shell": "bash {0}"},
        }
        cases.append(("gate shell override", gate_shell_override))

        gate_without_strict_mode = copy.deepcopy(self.workflow)
        gate_step = gate_without_strict_mode["jobs"]["mutation-gate"]["steps"][0]
        gate_step["run"] = gate_step["run"].replace("set -euo pipefail\n", "", 1)
        cases.append(("gate without strict mode", gate_without_strict_mode))

        baseline_action = copy.deepcopy(self.workflow)
        baseline_action["jobs"]["mutation-baseline"]["steps"].insert(
            2, {"uses": "actions/checkout@unreviewed"},
        )
        cases.append(("injected baseline action", baseline_action))

        skipped_installer = copy.deepcopy(self.workflow)
        skipped_installer["jobs"]["mutation-baseline"]["steps"][1]["if"] = "false"
        cases.append(("skipped baseline toolchain", skipped_installer))

        worker_permissions = copy.deepcopy(self.workflow)
        worker_permissions["jobs"]["mutation"]["permissions"] = {"contents": "write"}
        cases.append(("worker write permission", worker_permissions))

        for description, changed in cases:
            with self.subTest(change=description), self.assertRaises(AssertionError):
                check_contract(changed)

    def test_classifier_fails_when_git_diff_fails(self) -> None:
        run = self.workflow["jobs"]["mutation-changes"]["steps"][1]["run"]
        with tempfile.TemporaryDirectory() as temporary:
            fake_bin = pathlib.Path(temporary) / "bin"
            fake_bin.mkdir()
            fake_git = fake_bin / "git"
            fake_git.write_text("#!/usr/bin/env bash\nexit 47\n", encoding="utf-8")
            fake_git.chmod(0o755)
            output = pathlib.Path(temporary) / "github-output"
            env = dict(os.environ)
            env.update({
                "BASE_SHA": "missing-base",
                "HEAD_SHA": "deadbeef",
                "FORCE_MUTATION": "false",
                "GITHUB_OUTPUT": str(output),
                "RUNNER_TEMP": temporary,
                "PATH": str(fake_bin) + os.pathsep + env["PATH"],
            })
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", run],
                capture_output=True,
                check=False,
                env=env,
            )
            self.assertEqual(result.returncode, 47, result.stderr.decode())
            self.assertFalse(output.exists())

    def test_rejects_canary_execution_graph_drift(self) -> None:
        changes_run = self.workflow["jobs"]["mutation-changes"]["steps"][1]["run"]

        def changed_checkout_order(workflow: dict) -> None:
            steps = workflow["jobs"]["mutation-canary"]["steps"]
            steps[0], steps[3] = steps[3], steps[0]

        def added_action(workflow: dict) -> None:
            workflow["jobs"]["mutation-canary"]["steps"].insert(
                3, {"uses": "actions/checkout@unreviewed"},
            )

        def replaced_artifact(workflow: dict) -> None:
            workflow["jobs"]["mutation-canary"]["steps"][-1] = {
                "name": "Upload mutation canary report",
                "if": "always()",
                "uses": "actions/checkout@unreviewed",
            }

        def made_producer_nonblocking(workflow: dict) -> None:
            workflow["jobs"]["mutation-canary"]["steps"][3]["continue-on-error"] = True

        def hid_canary_path(workflow: dict) -> None:
            workflow["jobs"]["mutation-changes"]["steps"][1]["run"] = (
                changes_run.replace("|scripts/run_mutation_canary.sh", "|scripts/other.sh")
                .replace("fi\n", "# scripts/run_mutation_canary.sh\nfi\n", 1)
            )

        for description, mutate in (
            ("checkout after producer", changed_checkout_order),
            ("extra action", added_action),
            ("artifact replaced", replaced_artifact),
            ("nonblocking producer", made_producer_nonblocking),
            ("canary path only in comment", hid_canary_path),
        ):
            changed = copy.deepcopy(self.workflow)
            mutate(changed)
            with self.subTest(change=description), self.assertRaises(AssertionError):
                check_contract(changed)

    def test_rejects_canary_harness_and_report_drift(self) -> None:
        script = (ROOT / "scripts/run_mutation_canary.sh").read_text(encoding="utf-8")
        weakened_harness = script.replace("--include-ignored", "", 1)
        with self.assertRaisesRegex(AssertionError, "share the test harness"):
            check_contract(self.workflow, weakened_harness)

        unrecorded_output = script.replace(
            'tee_status="${pipeline_status[1]}"', "", 1,
        )
        with self.assertRaisesRegex(AssertionError, "retain its full report"):
            check_contract(self.workflow, unrecorded_output)

    def test_rejects_wrong_or_missing_toolchain(self) -> None:
        for value in (
            {},
            {"RUSTUP_TOOLCHAIN": "1.97.1"},
            dict(self.workflow["env"], RUSTUP_TOOLCHAIN="nightly-2026-08-28"),
        ):
            with self.subTest(value=value):
                changed = copy.deepcopy(self.workflow)
                changed["env"] = value
                with self.assertRaisesRegex(AssertionError, "pinned nightly"):
                    check_contract(changed)

    def test_rejects_bypasses_and_harness_drift(self) -> None:
        for name, field, value in (
            ("mutation-baseline", "if", "false"),
            ("mutation-baseline", "continue-on-error", True),
            ("mutation", "needs", ["mutation-changes"]),
            ("mutation", "if", "always()"),
            ("mutation", "env", {"RUSTUP_TOOLCHAIN": "stable"}),
            ("mutation-gate", "needs", ["mutation-changes", "mutation"]),
            ("mutation-gate", "continue-on-error", True),
        ):
            with self.subTest(job=name, field=field):
                changed = copy.deepcopy(self.workflow)
                changed["jobs"][name][field] = value
                with self.assertRaises(AssertionError):
                    check_contract(changed)
        for name in ("mutation-baseline", "mutation"):
            changed = copy.deepcopy(self.workflow)
            run = next(step for step in changed["jobs"][name]["steps"]
                       if "--include-ignored" in step.get("run", ""))
            run["run"] = run["run"].replace("--include-ignored", "")
            with self.subTest(job=name), self.assertRaises(AssertionError):
                check_contract(changed)

    def test_rejects_inert_mutant_programs(self) -> None:
        run = next(
            step["run"] for step in self.workflow["jobs"]["mutation"]["steps"]
            if step.get("name") == "Run mutants in changed lines"
        )
        for name, inert in (
            ("early success", "exit 0\n" + run),
            ("false branch", "mutation_status=0\nif false; then\n" + run
             + 'fi\nexit "$mutation_status"\n'),
            ("unused function", "never_run_mutants() {\n" + run
             + '}\nmutation_status=0\nexit "$mutation_status"\n'),
            ("inert heredoc", ": <<'DISABLED_MUTATION'\n" + run
             + 'DISABLED_MUTATION\nmutation_status=0\nexit "$mutation_status"\n'),
        ):
            with self.subTest(program=name):
                changed = copy.deepcopy(self.workflow)
                step = next(
                    step for step in changed["jobs"]["mutation"]["steps"]
                    if step.get("name") == "Run mutants in changed lines"
                )
                step["run"] = inert
                with self.assertRaisesRegex(AssertionError, "reviewed mutation program"):
                    check_contract(changed)

    def test_rejects_incomplete_or_overcommitted_shards(self) -> None:
        for strategy in (
            {"fail-fast": False, "max-parallel": 8,
             "matrix": {"shard": list(range(15))}},
            {"fail-fast": False, "max-parallel": 8,
             "matrix": {"shard": list(range(15)) + [0]}},
            {"fail-fast": False, "max-parallel": 8,
             "matrix": {"shard": list(range(15)) + [16]}},
            {"fail-fast": False, "max-parallel": 16,
             "matrix": {"shard": list(range(16))}},
            {"fail-fast": True, "max-parallel": 8,
             "matrix": {"shard": list(range(16))}},
        ):
            with self.subTest(strategy=strategy):
                changed = copy.deepcopy(self.workflow)
                changed["jobs"]["mutation"]["strategy"] = strategy
                with self.assertRaisesRegex(AssertionError, "sixteen blocking shards"):
                    check_contract(changed)

    def test_rejects_missing_or_wrong_mutator_version(self) -> None:
        for value in (None, {}, {"tool": "cargo-mutants"},
                      {"tool": "cargo-mutants@27.0.0"}):
            with self.subTest(value=value):
                changed = copy.deepcopy(self.workflow)
                step = next(
                    step for step in changed["jobs"]["mutation"]["steps"]
                    if step.get("uses", "").startswith("taiki-e/install-action@")
                )
                if value is None:
                    step.pop("with")
                else:
                    step["with"] = value
                with self.assertRaisesRegex(AssertionError, "validated cargo-mutants"):
                    check_contract(changed)

    def test_rejects_worker_harness_and_deadline_drift(self) -> None:
        for before, after in (
            ('--shard "${{ matrix.shard }}/16"', '--shard "${{ matrix.shard }}/8"'),
            ("--baseline run", "--baseline skip"),
            ("--jobs 1", "--jobs 0"),
            ("--jobs 1", "--jobs 2"),
            ("--jobs 1", "--jobs 4"),
            ("--test-threads=4", "--test-threads=2"),
            ("--timeout 240", "--timeout 120"),
            ("--timeout 240", "--timeout 241"),
            ("--build-timeout 600", "--build-timeout 601"),
            ("--foreground 60m", "--foreground 61m"),
        ):
            with self.subTest(before=before, after=after):
                changed = copy.deepcopy(self.workflow)
                step = next(
                    step for step in changed["jobs"]["mutation"]["steps"]
                    if step.get("name") == "Run mutants in changed lines"
                )
                self.assertEqual(step["run"].count(before), 1)
                step["run"] = step["run"].replace(before, after)
                with self.assertRaisesRegex(AssertionError, "scope, limits, harness"):
                    check_contract(changed)
        changed = copy.deepcopy(self.workflow)
        step = next(
            step for step in changed["jobs"]["mutation-baseline"]["steps"]
            if step.get("name") == "Prove the mutation test harness"
        )
        step["run"] = step["run"].replace("--test-threads=4", "--test-threads=2")
        with self.assertRaisesRegex(AssertionError, "complete mutation harness"):
            check_contract(changed)

    def test_rejects_missing_or_nonserial_compiler_jobs(self) -> None:
        for value in (None, "", "auto", "2", "4", 1):
            with self.subTest(value=value):
                changed = copy.deepcopy(self.workflow)
                if value is None:
                    changed["env"].pop("CARGO_BUILD_JOBS")
                else:
                    changed["env"]["CARGO_BUILD_JOBS"] = value
                with self.assertRaisesRegex(AssertionError, "serial compiler jobs"):
                    check_contract(changed)

    def test_rejects_incorrect_baseline_compiler_budget(self) -> None:
        for value in (
            None, {},
            {"CARGO_BUILD_JOBS": "1"}, {"CARGO_BUILD_JOBS": "2"},
            {"CARGO_BUILD_JOBS": "4"}, {"CARGO_BUILD_JOBS": 3},
            {"CARGO_BUILD_JOBS": "3", "RUSTUP_TOOLCHAIN": "stable"},
        ):
            with self.subTest(value=value):
                changed = copy.deepcopy(self.workflow)
                if value is None:
                    changed["jobs"]["mutation-baseline"].pop("env")
                else:
                    changed["jobs"]["mutation-baseline"]["env"] = value
                with self.assertRaisesRegex(AssertionError, "only the baseline"):
                    check_contract(changed)

    def test_rejects_missing_or_wrong_harness_incremental_mode(self) -> None:
        for name in ("mutation-baseline", "mutation"):
            for value in (None, {}, {"CARGO_INCREMENTAL": "0"},
                          {"CARGO_INCREMENTAL": 1},
                          {"CARGO_INCREMENTAL": "1", "RUSTUP_TOOLCHAIN": "stable"}):
                with self.subTest(job=name, value=value):
                    changed = copy.deepcopy(self.workflow)
                    step = next(step for step in changed["jobs"][name]["steps"]
                                if "--include-ignored" in step.get("run", ""))
                    if value is None:
                        step.pop("env", None)
                    else:
                        step["env"] = value
                    with self.assertRaisesRegex(AssertionError, "incremental compilation"):
                        check_contract(changed)

    def test_rejects_incremental_override_outside_harness_steps(self) -> None:
        for name in ("mutation-baseline", "mutation"):
            changed = copy.deepcopy(self.workflow)
            changed["jobs"][name]["steps"][0]["env"] = {"CARGO_INCREMENTAL": "1"}
            with self.subTest(job=name), self.assertRaisesRegex(
                AssertionError, "incremental compilation",
            ):
                check_contract(changed)

    def test_real_fan_in_rejects_unsuccessful_baseline_and_shards(self) -> None:
        run = self.workflow["jobs"]["mutation-gate"]["steps"][0]["run"]

        def verdict(
            relevant: bool, changes: str, baseline: str, canary: str, shards: str
        ) -> int:
            script = run
            for key, value in {
                "mutation-changes.result": changes,
                "mutation-changes.outputs.relevant": str(relevant).lower(),
                "mutation-baseline.result": baseline,
                "mutation-canary.result": canary,
                "mutation.result": shards,
            }.items():
                script = script.replace("${{ needs." + key + " }}", value)
            return subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", script],
                capture_output=True, check=False,
            ).returncode

        self.assertEqual(verdict(True, "success", "success", "success", "success"), 0)
        self.assertEqual(verdict(False, "success", "skipped", "skipped", "skipped"), 0)
        for state in ("failure", "cancelled", "skipped", ""):
            with self.subTest(state=state):
                self.assertNotEqual(
                    verdict(True, state, "success", "success", "success"), 0
                )
                self.assertNotEqual(
                    verdict(True, "success", state, "success", "success"), 0
                )
                self.assertNotEqual(
                    verdict(True, "success", "success", state, "success"), 0
                )
                self.assertNotEqual(
                    verdict(True, "success", "success", "success", state), 0
                )
        self.assertNotEqual(verdict(False, "success", "success", "skipped", "skipped"), 0)
        self.assertNotEqual(verdict(False, "success", "skipped", "success", "skipped"), 0)
        self.assertNotEqual(verdict(False, "success", "skipped", "skipped", "failure"), 0)

    def test_timeout_log_selector_preserves_the_timeout_status(self) -> None:
        run = next(
            step["run"] for step in self.workflow["jobs"]["mutation"]["steps"]
            if step.get("name") == "Run mutants in changed lines"
        )
        self.assertEqual(run.count("| sort -nr | "), 1)
        selector = "sort -nr | " + run.split("| sort -nr | ", 1)[1].split(')"', 1)[0]
        # Exercise the real pipeline, not Cargo or filesystem fixture creation.
        # Exceed pipe capacity so an early-closing consumer exposes SIGPIPE.
        many = "".join(f"{index}.0 mutants.out/log/case {index}.log\n"
                       for index in range(20_000))
        for listing, expected in (
            ("", ""),
            ("1.0 mutants.out/log/only.log\n", "mutants.out/log/only.log"),
            (many, "mutants.out/log/case 19999.log"),
        ):
            with self.subTest(entries=listing.count("\n")):
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c",
                     'mutation_status=124\nlatest_log="$(' + selector + ')"\n'
                     'printf "%s\\n" "$latest_log"\nexit "$mutation_status"'],
                    input=listing, capture_output=True, text=True, check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 124, result.stderr)
                self.assertEqual(result.stdout, expected + "\n")
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
