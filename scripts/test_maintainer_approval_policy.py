#!/usr/bin/env python3
"""Contract tests for the maintainer-approval required status."""

from __future__ import annotations

import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import textwrap
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "maintainer-approval.yml"
HEAD = "a" * 40
OLD = "b" * 40
STATUS_CALL = f"api --method POST repos/arceushui/pigloros/statuses/{HEAD} "

# Stands in for the GitHub CLI: serves reviews and collaborator roles from the
# environment and records every call so tests can assert on side effects.
FAKE_GH = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys
    args = sys.argv[1:]
    with open(os.environ["GH_CALLS"], "a", encoding="utf-8") as calls:
        calls.write(" ".join(args) + "\\n")
    path = next(arg for arg in args if arg.startswith("repos/"))
    if path.endswith("/reviews"):
        print(os.environ["FAKE_REVIEWS"])
    elif "/collaborators/" in path:
        login = path.split("/collaborators/")[1].split("/")[0]
        role = json.loads(os.environ["FAKE_ROLES"]).get(login)
        if role is None:
            sys.exit(1)
        print(json.dumps({"role_name": role}))
    """
)


def load_workflow() -> dict:
    with WORKFLOW_PATH.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def review(login: str, state: str, commit: str, submitted: str) -> dict:
    return {
        "user": {"login": login},
        "state": state,
        "commit_id": commit,
        "submitted_at": submitted,
    }


class MaintainerApprovalPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        workflow = load_workflow()
        self.workflow = workflow
        self.job = workflow["jobs"]["maintainer-approval-gate"]
        self.step = self.job["steps"][0]

    def run_gate(
        self,
        *,
        author: str = "contributor",
        action: str = "labeled",
        has_label: bool = True,
        reviews: list[dict] | None = None,
        roles: dict[str, str] | None = None,
    ) -> tuple[str, list[str]]:
        """Run the gate script and return the reported status and all gh calls."""
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = pathlib.Path(directory)
            gh = bin_dir / "gh"
            gh.write_text(FAKE_GH, encoding="utf-8")
            gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
            calls_file = bin_dir / "calls"
            calls_file.touch()
            env = {
                **os.environ,
                "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                "GH_CALLS": str(calls_file),
                "FAKE_REVIEWS": json.dumps(reviews or []),
                "FAKE_ROLES": json.dumps(roles or {}),
                "REPOSITORY": "arceushui/pigloros",
                "PR_NUMBER": "42",
                "HEAD_SHA": HEAD,
                "AUTHOR": author,
                "ACTION": action,
                "HAS_APPROVAL_LABEL": "true" if has_label else "false",
                "RUN_URL": "https://github.com/arceushui/pigloros/actions/runs/1",
            }
            result = subprocess.run(
                ["bash", "-c", self.step["run"]],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            calls = calls_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(result.returncode, 0, result.stderr)
        statuses = [call for call in calls if call.startswith(STATUS_CALL)]
        self.assertEqual(len(statuses), 1, calls)
        self.assertIn("-f context=maintainer-approval", statuses[0])
        state = re.search(r"-f state=(\w+)", statuses[0])
        assert state is not None
        return state.group(1), calls

    def test_gate_runs_trusted_base_workflow_without_checkout(self) -> None:
        trigger = self.workflow[True]["pull_request_target"]
        self.assertEqual(
            set(trigger["types"]),
            {"opened", "reopened", "synchronize", "ready_for_review", "labeled", "unlabeled"},
        )
        self.assertEqual(
            self.workflow["permissions"],
            {"pull-requests": "write", "statuses": "write"},
        )
        self.assertEqual(len(self.job["steps"]), 1)
        self.assertNotIn("uses", self.step)
        self.assertEqual(self.step["env"]["HEAD_SHA"], "${{ github.event.pull_request.head.sha }}")

    def test_job_name_differs_from_the_required_status_context(self) -> None:
        self.assertNotEqual(self.job["name"], "maintainer-approval")

    def test_allowed_authors_succeed_without_review_lookups(self) -> None:
        for author in ("arceushui", "trunk-io[bot]"):
            with self.subTest(author=author):
                state, calls = self.run_gate(author=author, has_label=False)
                self.assertEqual(state, "success")
                self.assertEqual(len(calls), 1)

    def test_other_authors_wait_without_an_approval(self) -> None:
        for author in ("contributor", "dependabot[bot]"):
            with self.subTest(author=author):
                state, _ = self.run_gate(author=author)
                self.assertEqual(state, "pending")

    def test_maintainer_approval_of_head_commit_succeeds(self) -> None:
        for role in ("admin", "maintain"):
            with self.subTest(role=role):
                state, _ = self.run_gate(
                    reviews=[review("arceushui", "APPROVED", HEAD, "2026-10-02T01:00:00Z")],
                    roles={"arceushui": role},
                )
                self.assertEqual(state, "success")

    def test_approval_of_an_older_commit_keeps_waiting(self) -> None:
        state, _ = self.run_gate(
            reviews=[review("arceushui", "APPROVED", OLD, "2026-10-02T01:00:00Z")],
            roles={"arceushui": "admin"},
        )
        self.assertEqual(state, "pending")

    def test_approval_from_lower_roles_or_non_collaborators_keeps_waiting(self) -> None:
        for role in ("write", "triage", "read", None):
            with self.subTest(role=role):
                state, _ = self.run_gate(
                    reviews=[review("helper", "APPROVED", HEAD, "2026-10-02T01:00:00Z")],
                    roles={} if role is None else {"helper": role},
                )
                self.assertEqual(state, "pending")

    def test_latest_decisive_review_wins(self) -> None:
        state, _ = self.run_gate(
            reviews=[
                review("arceushui", "APPROVED", HEAD, "2026-10-02T01:00:00Z"),
                review("arceushui", "CHANGES_REQUESTED", HEAD, "2026-10-02T02:00:00Z"),
                review("arceushui", "COMMENTED", HEAD, "2026-10-02T03:00:00Z"),
            ],
            roles={"arceushui": "admin"},
        )
        self.assertEqual(state, "pending")

    def test_new_commits_remove_the_label_and_need_fresh_approval(self) -> None:
        state, calls = self.run_gate(
            action="synchronize",
            reviews=[review("arceushui", "APPROVED", OLD, "2026-10-02T01:00:00Z")],
            roles={"arceushui": "admin"},
        )
        self.assertEqual(state, "pending")
        self.assertIn(
            "api --method DELETE repos/arceushui/pigloros/issues/42/labels/maintainer-approved",
            calls,
        )

    def test_label_without_approval_grants_nothing(self) -> None:
        state, calls = self.run_gate(action="labeled", has_label=True, reviews=[])
        self.assertEqual(state, "pending")
        self.assertFalse(any("DELETE" in call for call in calls))


if __name__ == "__main__":
    unittest.main()
