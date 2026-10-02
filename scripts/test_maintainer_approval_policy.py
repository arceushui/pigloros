#!/usr/bin/env python3
"""Contract tests for the maintainer-approval required check."""

from __future__ import annotations

import json
import os
import pathlib
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
        self.job = workflow["jobs"]["maintainer-approval"]
        self.step = self.job["steps"][0]
        self.workflow = workflow

    def run_gate(
        self,
        *,
        author: str = "contributor",
        action: str = "labeled",
        has_label: bool = True,
        reviews: list[dict] | None = None,
        roles: dict[str, str] | None = None,
    ) -> tuple[int, list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = pathlib.Path(directory)
            gh = bin_dir / "gh"
            gh.write_text(FAKE_GH, encoding="utf-8")
            gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
            calls = bin_dir / "calls"
            calls.touch()
            env = {
                **os.environ,
                "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                "GH_CALLS": str(calls),
                "FAKE_REVIEWS": json.dumps(reviews or []),
                "FAKE_ROLES": json.dumps(roles or {}),
                "REPOSITORY": "arceushui/pigloros",
                "PR_NUMBER": "42",
                "HEAD_SHA": HEAD,
                "AUTHOR": author,
                "ACTION": action,
                "HAS_APPROVAL_LABEL": "true" if has_label else "false",
            }
            result = subprocess.run(
                ["bash", "-c", self.step["run"]],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode, calls.read_text(encoding="utf-8").splitlines()

    def test_gate_runs_trusted_base_workflow_without_checkout(self) -> None:
        trigger = self.workflow[True]["pull_request_target"]
        self.assertEqual(
            set(trigger["types"]),
            {"opened", "reopened", "synchronize", "ready_for_review", "labeled", "unlabeled"},
        )
        self.assertEqual(self.workflow["permissions"], {"pull-requests": "write"})
        self.assertEqual(len(self.job["steps"]), 1)
        self.assertNotIn("uses", self.step)
        self.assertEqual(self.step["env"]["HEAD_SHA"], "${{ github.event.pull_request.head.sha }}")

    def test_allowed_authors_pass_without_api_calls(self) -> None:
        for author in ("arceushui", "trunk-io[bot]"):
            with self.subTest(author=author):
                status, calls = self.run_gate(author=author, has_label=False)
                self.assertEqual(status, 0)
                self.assertEqual(calls, [])

    def test_other_authors_fail_without_an_approval(self) -> None:
        for author in ("contributor", "dependabot[bot]"):
            with self.subTest(author=author):
                status, _ = self.run_gate(author=author)
                self.assertEqual(status, 1)

    def test_maintainer_approval_of_head_commit_passes(self) -> None:
        for role in ("admin", "maintain"):
            with self.subTest(role=role):
                status, _ = self.run_gate(
                    reviews=[review("arceushui", "APPROVED", HEAD, "2026-10-02T01:00:00Z")],
                    roles={"arceushui": role},
                )
                self.assertEqual(status, 0)

    def test_approval_of_an_older_commit_does_not_pass(self) -> None:
        status, _ = self.run_gate(
            reviews=[review("arceushui", "APPROVED", OLD, "2026-10-02T01:00:00Z")],
            roles={"arceushui": "admin"},
        )
        self.assertEqual(status, 1)

    def test_approval_from_lower_roles_or_non_collaborators_does_not_pass(self) -> None:
        for role in ("write", "triage", "read", None):
            with self.subTest(role=role):
                status, _ = self.run_gate(
                    reviews=[review("helper", "APPROVED", HEAD, "2026-10-02T01:00:00Z")],
                    roles={} if role is None else {"helper": role},
                )
                self.assertEqual(status, 1)

    def test_latest_decisive_review_wins(self) -> None:
        status, _ = self.run_gate(
            reviews=[
                review("arceushui", "APPROVED", HEAD, "2026-10-02T01:00:00Z"),
                review("arceushui", "CHANGES_REQUESTED", HEAD, "2026-10-02T02:00:00Z"),
                review("arceushui", "COMMENTED", HEAD, "2026-10-02T03:00:00Z"),
            ],
            roles={"arceushui": "admin"},
        )
        self.assertEqual(status, 1)

    def test_new_commits_remove_the_label_and_need_fresh_approval(self) -> None:
        status, calls = self.run_gate(
            action="synchronize",
            reviews=[review("arceushui", "APPROVED", OLD, "2026-10-02T01:00:00Z")],
            roles={"arceushui": "admin"},
        )
        self.assertEqual(status, 1)
        self.assertIn(
            "api --method DELETE repos/arceushui/pigloros/issues/42/labels/maintainer-approved",
            calls,
        )

    def test_label_without_approval_grants_nothing(self) -> None:
        status, calls = self.run_gate(action="labeled", has_label=True, reviews=[])
        self.assertEqual(status, 1)
        self.assertFalse(any("DELETE" in call for call in calls))


if __name__ == "__main__":
    unittest.main()
