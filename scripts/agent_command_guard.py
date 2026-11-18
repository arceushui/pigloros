#!/usr/bin/env python3
"""Claude Code PreToolUse guard for Bash commands agents run in this repository.

It enforces the owner rules that agents kept breaking (see the rule table in
AGENTS.md):

* Local Cargo is denied. Hosted CI is the build, test, lint and coverage
  evidence; only ``cargo generate-lockfile`` (light, owner 2026-11-15) and
  ``cargo --version`` may run. The versioned pre-commit hook still runs its
  own Cargo checks, because the hook is not a Bash tool call.
* Skipping hooks (``--no-verify``, ``git commit -n``, overriding
  ``core.hooksPath``), rewriting pushed history (force-push, ``+refspec``,
  ``git rebase``, ``git pull --rebase``, ``git commit --amend``) need the
  owner's approval, so the hook asks instead of allowing. Bring a branch up to
  date with ``git fetch origin && git merge origin/main``.

The hook reads the PreToolUse JSON on stdin and prints a decision as JSON, or
nothing when the command is allowed. It never inspects quoted arguments or
here-document bodies as commands, so commit messages that mention Cargo pass.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys

DENY = "deny"
ASK = "ask"

CARGO_ALLOWED = {"generate-lockfile", "--version", "-V"}
CARGO_REASON = (
    "Local cargo is not run on this machine (owner rule, AGENTS.md 'Agent rules'). "
    "Push the branch and read the hosted job instead: "
    "`gh run view <run-id> --log-failed`. Only `cargo generate-lockfile` may run "
    "locally; the .githooks/pre-commit hook runs fmt and clippy itself."
)
NO_VERIFY_REASON = (
    "Skipping git hooks needs the owner's explicit approval for this one commit "
    "(AGENTS.md 'Agent rules'). Fix what the hook reports instead."
)
REWRITE_REASON = (
    "Rewriting pushed history needs the owner's approval (AGENTS.md 'Agent rules'). "
    "Update a branch with `git fetch origin && git merge origin/main` and push "
    "a normal fast-forward."
)
PARSE_REASON = "The guard could not parse this command; confirm it by hand."

# Wrappers that run their remaining arguments as a command.
PASSTHROUGH = {"env", "sudo", "time", "nice", "nohup", "command", "exec", "builtin"}
SHELLS = {"bash", "sh", "zsh", "dash"}
OPERATORS = {"&&", "||", ";", "|", "&", "|&", ";;", "(", ")", "\n"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def strip_heredocs(command: str) -> str:
    """Drop here-document bodies so their text is never read as commands."""
    lines = command.split("\n")
    out: list[str] = []
    pending: list[tuple[bool, str]] = []
    for line in lines:
        if pending:
            dash, tag = pending[0]
            if (line.lstrip("\t") if dash else line) == tag:
                pending.pop(0)
            continue
        out.append(line)
        pending.extend((m.group(1) == "-", m.group(3)) for m in HEREDOC.finditer(line))
    return "\n".join(out)


def tokenize(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars="();<>|&\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = "#"
    return list(lexer)


def segments(tokens: list[str]) -> list[list[str]]:
    result: list[list[str]] = [[]]
    for token in tokens:
        if token in OPERATORS:
            result.append([])
        else:
            result[-1].append(token)
    return [segment for segment in result if segment]


def strip_wrappers(words: list[str]) -> list[str]:
    while words:
        head = os.path.basename(words[0])
        if ASSIGNMENT.match(words[0]):
            words = words[1:]
        elif head in PASSTHROUGH:
            words = words[1:]
            while words and (words[0].startswith("-") or ASSIGNMENT.match(words[0])):
                words = words[1:]
        elif head == "timeout":
            words = words[1:]
            while words and words[0].startswith("-"):
                words = words[1:]
            words = words[1:]  # the duration
        elif head == "rustup" and len(words) > 2 and words[1] == "run":
            words = words[3:]
        else:
            return words
    return words


def check_cargo(args: list[str]) -> tuple[str, str] | None:
    rest = [word for word in args if not word.startswith("+")]
    if rest and rest[0] in CARGO_ALLOWED:
        return None
    return DENY, CARGO_REASON


GIT_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}


def check_git(args: list[str]) -> tuple[str, str] | None:
    while args and args[0].startswith("-"):
        option = args[0]
        if option == "-c" and len(args) > 1 and args[1].lower().startswith("core.hookspath"):
            return ASK, NO_VERIFY_REASON
        args = args[2:] if option in GIT_VALUE_OPTIONS else args[1:]
    if not args:
        return None
    sub, rest = args[0], args[1:]
    flags = [word for word in rest if word.startswith("-")]
    short = "".join(word[1:] for word in flags if not word.startswith("--"))
    if "--no-verify" in flags or (sub == "commit" and "n" in short):
        return ASK, NO_VERIFY_REASON
    if sub == "config" and any(word.lower() == "core.hookspath" for word in rest):
        return ASK, NO_VERIFY_REASON
    if sub == "rebase" and not {"--abort", "--quit"} & set(flags):
        return ASK, REWRITE_REASON
    rebase_pull = "--rebase" in flags or "r" in short or any(
        word.startswith("--rebase=") and word != "--rebase=false" for word in flags
    )
    if sub == "pull" and rebase_pull:
        return ASK, REWRITE_REASON
    if sub == "commit" and "--amend" in flags:
        return ASK, REWRITE_REASON
    if sub == "push":
        forced = any(
            word in {"--force", "--force-if-includes"} or word.startswith("--force-with-lease")
            for word in flags
        )
        if forced or "f" in short or any(word.startswith("+") for word in rest):
            return ASK, REWRITE_REASON
    return None


def check_words(words: list[str], depth: int = 0) -> tuple[str, str] | None:
    words = strip_wrappers(words)
    if not words:
        return None
    head = os.path.basename(words[0])
    if head == "cargo" or head.startswith("cargo-"):
        return check_cargo(words[1:] if head == "cargo" else ["<plugin>"])
    if head == "git":
        return check_git(words[1:])
    if head in SHELLS and depth < 3:
        for index, word in enumerate(words[1:-1], start=1):
            short_c = word.startswith("-") and not word.startswith("--") and word.endswith("c")
            if word == "-c" or short_c:
                return check_command(words[index + 1], depth + 1)
    return None


def check_command(command: str, depth: int = 0) -> tuple[str, str] | None:
    try:
        tokens = tokenize(strip_heredocs(command))
    except ValueError:
        return ASK, PARSE_REASON
    verdict: tuple[str, str] | None = None
    for segment in segments(tokens):
        found = check_words(segment, depth)
        if found and (verdict is None or found[0] == DENY):
            verdict = found
    return verdict


def main() -> int:
    payload = json.load(sys.stdin)
    if payload.get("tool_name") != "Bash":
        return 0
    verdict = check_command(payload.get("tool_input", {}).get("command", ""))
    if verdict is None:
        return 0
    decision, reason = verdict
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        },
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
