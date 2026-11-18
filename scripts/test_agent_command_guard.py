#!/usr/bin/env python3
"""Tests for scripts/agent_command_guard.py and its .claude/settings.json hook.

The denied and asked commands below are the real mistakes the owner
corrected (see AGENTS.md 'Agent rules').
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import agent_command_guard as guard  # noqa: E402


def decision(command: str) -> str | None:
    verdict = guard.check_command(command)
    return verdict[0] if verdict else None


class PastMistakes(unittest.TestCase):
    def test_local_cargo_runs_are_denied(self) -> None:
        for command in (
            "cargo fmt --all -- --check",  # 2026-10-17 timing run the owner rejected
            "cargo test --workspace --locked -- --include-ignored",
            "RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --summary-only",
            "cd crates/pos-store && cargo clippy --all-targets",
            "cargo +nightly check",
            "timeout 600 cargo nextest run",
            "env CARGO_TERM_COLOR=never cargo build",
            "bash -c 'cargo test -p pos-core'",
            "rustup run stable cargo doc",
            "/home/u/.cargo/bin/cargo metadata --format-version 1",
            "cargo-mutants --in-diff x.diff",
            "git status; cargo build",
        ):
            with self.subTest(command=command):
                self.assertEqual(decision(command), guard.DENY)

    def test_hook_skips_need_the_owner(self) -> None:
        for command in (
            "git commit --no-verify -m 'refresh Cargo.lock'",  # #1057, a one-time owner exception
            "git commit -nm wip",
            "git push --no-verify origin HEAD",
            "git -c core.hooksPath=/dev/null commit -m x",
            "git config core.hooksPath ''",
            "git merge --no-verify origin/main",
        ):
            with self.subTest(command=command):
                self.assertEqual(decision(command), guard.ASK)

    def test_history_rewrites_need_the_owner(self) -> None:
        for command in (
            "git push --force-with-lease origin redmine/737",  # 2026-11-14/15 stack rebase
            "git push -f",
            "git push origin +HEAD:redmine/737",
            "git rebase origin/main",
            "git pull --rebase origin main",
            "git commit --amend --no-edit",
            "git -C ../pigloros-x push --force",
        ):
            with self.subTest(command=command):
                self.assertEqual(decision(command), guard.ASK)


class AllowedCommands(unittest.TestCase):
    def test_owner_approved_and_unrelated_commands_pass(self) -> None:
        for command in (
            "cargo generate-lockfile",
            "cargo --version",
            "git fetch origin && git merge --no-edit origin/main",
            "git commit -m 'Explain why cargo test failed' -m 'git push --force is not used'",
            "git push origin HEAD",
            "git push -u origin ci/agent-command-guard",
            "git rebase --abort",
            "gh run view 1 --log-failed | grep cargo",
            "echo cargo build",
            "grep -rn 'cargo test' docs/",
            "git commit -F - <<'EOF'\ncargo test is run by CI\ngit push --force\nEOF",
            "git log --oneline -5 # cargo build",
            "python3 scripts/test_ci_workflow_policy.py",
        ):
            with self.subTest(command=command):
                self.assertIsNone(decision(command))

    def test_unparseable_command_asks(self) -> None:
        self.assertEqual(decision("echo 'unterminated"), guard.ASK)


class HookWiring(unittest.TestCase):
    def run_hook(self, payload: dict) -> str:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "agent_command_guard.py")],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout

    def test_hook_prints_claude_code_decision(self) -> None:
        payload = {"tool_name": "Bash", "tool_input": {"command": "cargo test"}}
        out = json.loads(self.run_hook(payload))
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("gh run view", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_hook_is_silent_when_allowed(self) -> None:
        for payload in (
            {"tool_name": "Bash", "tool_input": {"command": "git status"}},
            {"tool_name": "Read", "tool_input": {"file_path": "x"}},
        ):
            self.assertEqual(self.run_hook(payload), "")

    def test_project_settings_register_the_guard(self) -> None:
        settings = json.loads((ROOT / ".claude" / "settings.json").read_text())
        entries = settings["hooks"]["PreToolUse"]
        commands = [
            hook["command"]
            for entry in entries
            if entry.get("matcher") == "Bash"
            for hook in entry["hooks"]
            if hook.get("type") == "command"
        ]
        expected = 'python3 "$CLAUDE_PROJECT_DIR/scripts/agent_command_guard.py"'
        self.assertIn(expected, commands)


if __name__ == "__main__":
    unittest.main()
