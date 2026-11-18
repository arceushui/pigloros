#!/usr/bin/env python3
"""Claude Code PreToolUse guard for Bash commands agents run in this repository.

It enforces the owner rules that agents kept breaking (see the rule table in
AGENTS.md):

* Local Cargo is denied. Hosted CI is the build, test, lint and coverage
  evidence; only ``cargo generate-lockfile`` (light, owner 2026-11-15) and
  ``cargo --version`` may run. The versioned pre-commit hook still runs its
  own Cargo checks, because the hook is not a Bash tool call.
* Skipping hooks (``--no-verify``, ``git commit -n``, overriding
  ``core.hooksPath``) and rewriting pushed history (force-push, ``+refspec``,
  ``--mirror``, ``git rebase``, ``git pull --rebase``, rebase-on-pull config,
  ``git commit --amend``) need the owner's approval, so the hook asks. Bring a
  branch up to date with ``git fetch origin && git merge origin/main``.

Commands are tokenized like a shell: words inside quotes, comments and quoted
here-document bodies are arguments, not commands, so a commit message that
mentions Cargo passes. Command and process substitutions are checked wherever
they expand (bare, inside double quotes, and in unquoted here-documents).
Common wrappers (``env``, ``sudo``, ``nice``, ``timeout``, ``xargs``, ``time``,
``stdbuf``, ``watch``, ``eval``, ``bash -c``, ``rustup run``, ``find -exec``)
are unwrapped. Not covered: scripts a command runs from a file (``bash x.sh``,
``source``, ``make``), and remote commands (``ssh``), which do not run Cargo on
this machine's shell directly. A command the guard cannot parse asks.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from typing import Optional, Tuple

DENY = "deny"
ASK = "ask"
Verdict = Optional[Tuple[str, str]]

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

SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
SEPARATOR_CHARS = set(";|&()\n")
PUNCTUATION = "();<>|&\n"
KEYWORDS = {"if", "then", "else", "elif", "while", "until", "do", "{", "!"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
# ``<<`` but not the ``<<<`` here-string, which has no body.
HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")

# Wrappers that run their remaining arguments as a command, with the options
# that take a separate value word. A ``--long=value`` or attached short value
# never consumes the next word.
WRAPPERS: dict[str, set[str]] = {
    "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"},
    "sudo": {"-u", "--user", "-g", "--group", "-C", "--close-from", "-D", "--chdir",
             "-h", "--host", "-p", "--prompt", "-r", "--role", "-t", "--type",
             "-U", "--other-user", "-T", "--command-timeout"},
    "nice": {"-n", "--adjustment"},
    "nohup": set(),
    "command": set(),
    "builtin": set(),
    "exec": {"-a"},
    "time": {"-f", "--format", "-o", "--output"},
    "stdbuf": {"-i", "--input", "-o", "--output", "-e", "--error"},
    "ionice": {"-c", "--class", "-n", "--classdata", "-p", "--pid"},
    "xargs": {"-a", "--arg-file", "-d", "--delimiter", "-E", "-I", "-L",
              "--max-lines", "-n", "--max-args", "-P", "--max-procs", "-s",
              "--max-chars", "--process-slot-var"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "watch": {"-n", "--interval", "-d", "--differences", "-q", "--equexit"},
}
# Wrappers whose first positional argument is not the command.
POSITIONAL_PREFIX = {"timeout": 1}
# Wrappers that join their arguments into one shell string.
STRING_WRAPPERS = {"eval", "watch"}

GIT_GLOBAL_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                            "--config-env", "--super-prefix", "--exec-path"}
# Per-subcommand options that take a separate value word.
GIT_VALUE_OPTIONS: dict[str, set[str]] = {
    "commit": {"-m", "--message", "-F", "--file", "-C", "--reuse-message", "-c",
               "--reedit-message", "-t", "--template", "--author", "--date",
               "--cleanup", "--fixup", "--squash", "--trailer", "-S", "--gpg-sign",
               "--pathspec-from-file"},
    "merge": {"-m", "--message", "-F", "--file", "-s", "--strategy", "-X",
              "--strategy-option", "--into-name", "--cleanup", "-S", "--gpg-sign"},
    "push": {"--repo", "-o", "--push-option", "--receive-pack", "--exec"},
    "pull": {"-s", "--strategy", "-X", "--strategy-option", "--depth", "--upload-pack",
             "-j", "--jobs", "-o", "--server-option"},
    "rebase": {"-s", "--strategy", "-X", "--strategy-option", "--onto", "-x",
               "--exec", "--whitespace", "-C"},
}
# Long options whose abbreviations git also accepts.
NO_VERIFY_OPTIONS = {"--no-verify"}
FORCE_OPTIONS = {"--force", "--force-with-lease", "--mirror"}
REBASE_CONFIG = re.compile(r"^(pull\.rebase|branch\..+\.rebase)$", re.IGNORECASE)
REBASE_CONTROL = {"--abort", "--quit", "--continue", "--skip", "--edit-todo",
                  "--show-current-patch"}


def merge_verdicts(*verdicts: Verdict) -> Verdict:
    result = None
    for verdict in verdicts:
        if verdict and (result is None or verdict[0] == DENY):
            result = verdict
    return result


def split_heredocs(command: str) -> tuple[str, list[str]]:
    """Drop here-document bodies; return expanding bodies separately."""
    out: list[str] = []
    expanding: list[str] = []
    pending: list[tuple[bool, bool, str]] = []
    for line in command.split("\n"):
        if pending:
            dash, quoted, tag = pending[0]
            if (line.lstrip("\t") if dash else line) == tag:
                pending.pop(0)
            elif not quoted:
                expanding.append(line)
            continue
        out.append(line)
        pending.extend(
            (m.group(1) == "-", bool(m.group(2)), m.group(3)) for m in HEREDOC.finditer(line)
        )
    return "\n".join(out), expanding


def normalize(text: str) -> str:
    """Drop ``#`` comments and fold ANSI-C ``$'...'`` strings into a literal.

    One quote-aware pass: a ``#`` starts a comment only at the start of a
    word outside quotes, and ``$'`` opens an ANSI-C string (in which ``\\'``
    does not end it) only outside quotes; shlex knows neither rule.
    """
    out: list[str] = []
    index, quote, length = 0, "", len(text)
    while index < length:
        char = text[index]
        if quote == "'":
            quote = "" if char == "'" else quote
        elif char == "\\":
            out.append(text[index:index + 2])
            index += 2
            continue
        elif char == '"':
            quote = "" if quote == '"' else '"'
        elif quote:
            pass
        elif char == "'":
            quote = "'"
        elif char == "$" and text.startswith("'", index + 1):
            end = index + 2
            while end < length and text[end] != "'":
                end += 2 if text[end] == "\\" else 1
            out.append("'ansi-c'")
            index = end + 1
            continue
        elif char == "#" and (index == 0 or text[index - 1] in " \t\n;&|()"):
            newline = text.find("\n", index)
            index = length if newline == -1 else newline
            continue
        out.append(char)
        index += 1
    return "".join(out)


def matching_paren(text: str, start: int) -> int:
    """Index just past the ``)`` that closes the ``(`` before ``start``."""
    depth, quote, index, length = 1, "", start, len(text)
    while index < length and depth:
        char = text[index]
        if quote == "'":
            quote = "" if char == "'" else quote
        elif char == "\\":
            index += 1
        elif char == '"':
            quote = "" if quote == '"' else '"'
        elif char == "'" and not quote:
            quote = "'"
        elif not quote and char in "()":
            depth += 1 if char == "(" else -1
        index += 1
    return index


def substitutions(text: str) -> list[str]:
    """Bodies of $(...), <(...), >(...) and `...` that the shell expands.

    Single-quoted text is literal; double-quoted text still expands.
    """
    bodies: list[str] = []
    index, quote, length = 0, "", len(text)
    while index < length:
        char = text[index]
        if quote == "'":
            if char == "'":
                quote = ""
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if char == '"':
            quote = "" if quote == '"' else '"'
        elif char == "'" and not quote:
            quote = "'"
        elif char in "$<>" and text.startswith("(", index + 1):
            end = matching_paren(text, index + 2)
            bodies.append(text[index + 2:end - 1])
            index = end
            continue
        elif char == "`":
            end = text.find("`", index + 1)
            end = length if end == -1 else end
            bodies.append(text[index + 1:end])
            index = end + 1
            continue
        index += 1
    return bodies


def tokenize(command: str) -> list[str]:
    lexer = shlex.shlex(normalize(command), posix=True, punctuation_chars=PUNCTUATION)
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def is_separator(token: str) -> bool:
    """A punctuation run such as ``;``, ``&&``, ``)\\n`` ends a command.

    shlex groups adjacent punctuation into one token, so ``a;\\nb`` yields
    ``;\\n``. Redirections (``>``, ``2>&1``'s ``>&``) start with ``<`` or ``>``
    and keep their target word in the command.
    """
    return (
        bool(token)
        and set(token) <= set(PUNCTUATION)
        and bool(set(token) & SEPARATOR_CHARS)
        and token[0] not in "<>"
    )


def segments(tokens: list[str]) -> list[list[str]]:
    result: list[list[str]] = [[]]
    for token in tokens:
        if is_separator(token):
            result.append([])
        else:
            result[-1].append(token)
    return [segment for segment in result if segment]


def skip_options(words: list[str], value_options: set[str]) -> list[str]:
    while words and words[0].startswith("-") and words[0] != "-":
        option = words[0]
        words = words[1:]
        if option == "--":
            break
        if option in value_options and words:
            words = words[1:]
    return words


def check_find(words: list[str], depth: int) -> Verdict:
    verdicts = []
    for index, word in enumerate(words):
        if word in {"-exec", "-execdir", "-ok", "-okdir"}:
            command = []
            for item in words[index + 1:]:
                if item in {";", "+", "\\;"}:
                    break
                command.append(item)
            verdicts.append(check_words(command, depth + 1))
    return merge_verdicts(*verdicts)


def split_string(args: list[str]) -> str | None:
    """The command string of ``env -S``/``--split-string``, in any spelling."""
    for index, word in enumerate(args):
        if word in {"-S", "--split-string"}:
            return args[index + 1] if index + 1 < len(args) else ""
        if word.startswith("--split-string="):
            return word.split("=", 1)[1]
        if word.startswith("-S"):
            return word[2:]
        if not word.startswith("-"):
            return None
    return None


def check_words(words: list[str], depth: int = 0) -> Verdict:
    if depth > 4:
        return None
    while words:
        head = os.path.basename(words[0])
        if words[0] in KEYWORDS or ASSIGNMENT.match(words[0]):
            words = words[1:]
        elif head in STRING_WRAPPERS:
            rest = skip_options(words[1:], WRAPPERS.get(head, set()))
            return check_command(" ".join(rest), depth + 1)
        elif head == "env" and split_string(words[1:]) is not None:
            return check_command(split_string(words[1:]) or "", depth + 1)
        elif head in WRAPPERS:
            words = skip_options(words[1:], WRAPPERS[head])
            words = words[POSITIONAL_PREFIX.get(head, 0):]
        elif head == "rustup" and len(words) > 2 and words[1] == "run":
            words = words[3:]
        else:
            break
    if not words:
        return None
    head = os.path.basename(words[0])
    if head == "cargo" or head.startswith("cargo-"):
        return check_cargo(words[1:] if head == "cargo" else ["<plugin>"])
    if head == "git":
        return check_git(words[1:])
    if head == "find":
        return check_find(words[1:], depth)
    if head in SHELLS or head == "script":
        for index, word in enumerate(words[1:-1], start=1):
            short_c = word.startswith("-") and not word.startswith("--") and "c" in word
            if short_c:
                return check_command(words[index + 1], depth + 1)
    return None


def check_cargo(args: list[str]) -> Verdict:
    rest = [word for word in args if not word.startswith("+")]
    if rest and rest[0] in CARGO_ALLOWED:
        return None
    return DENY, CARGO_REASON


def abbreviates(word: str, options: set[str]) -> bool:
    name = word.split("=", 1)[0]
    return len(name) >= 4 and any(option.startswith(name) for option in options)


def config_verdict(assignment: str) -> Verdict:
    key, _, value = assignment.partition("=")
    if key.lower() == "core.hookspath":
        return ASK, NO_VERIFY_REASON
    if REBASE_CONFIG.match(key) and value.lower() not in {"false", "0", "no", "off"}:
        return ASK, REWRITE_REASON
    return None


def parse_git_args(sub: str, rest: list[str]) -> tuple[list[str], set[str], list[str]]:
    """Split a subcommand's arguments into long flags, short letters, positionals."""
    value_options = GIT_VALUE_OPTIONS.get(sub, set())
    long_flags: list[str] = []
    short: set[str] = set()
    positionals: list[str] = []
    index = 0
    while index < len(rest):
        word = rest[index]
        index += 1
        if word == "--":
            positionals.extend(rest[index:])
            break
        if word.startswith("--"):
            long_flags.append(word)
            if word in value_options:
                index += 1
        elif word.startswith("-") and word != "-":
            for position, letter in enumerate(word[1:], start=1):
                if f"-{letter}" in value_options:
                    if position == len(word) - 1:
                        index += 1
                    break
                short.add(letter)
        else:
            positionals.append(word)
    return long_flags, short, positionals


def check_git(args: list[str]) -> Verdict:
    while args and args[0].startswith("-"):
        option = args[0]
        if option.startswith("-c") and len(option) > 2:
            if found := config_verdict(option[2:]):
                return found
        elif option.startswith("--config-env="):
            if found := config_verdict(option.split("=", 1)[1]):
                return found
        elif option in {"-c", "--config-env"} and len(args) > 1:
            if found := config_verdict(args[1]):
                return found
        args = args[2:] if option in GIT_GLOBAL_VALUE_OPTIONS else args[1:]
    if not args:
        return None
    sub, rest = args[0], args[1:]
    long_flags, short, positionals = parse_git_args(sub, rest)
    if any(abbreviates(flag, NO_VERIFY_OPTIONS) for flag in long_flags) or (
        sub == "commit" and "n" in short
    ):
        return ASK, NO_VERIFY_REASON
    if sub == "config":
        if len(positionals) >= 2:
            return config_verdict(f"{positionals[0]}={positionals[1]}")
        return None
    if sub == "rebase" and not REBASE_CONTROL & {flag.split("=")[0] for flag in long_flags}:
        return ASK, REWRITE_REASON
    if sub == "pull":
        rebase = [flag for flag in long_flags if abbreviates(flag, {"--rebase"})]
        if "r" in short or any(flag.partition("=")[2] != "false" for flag in rebase):
            return ASK, REWRITE_REASON
    if sub == "commit" and any(abbreviates(flag, {"--amend"}) for flag in long_flags):
        return ASK, REWRITE_REASON
    if sub == "push":
        forced = any(abbreviates(flag, FORCE_OPTIONS) for flag in long_flags)
        plus_refspec = any(word.startswith("+") or ":+" in word for word in positionals)
        if forced or "f" in short or plus_refspec:
            return ASK, REWRITE_REASON
    return None


def check_command(command: str, depth: int = 0) -> Verdict:
    if depth > 4:
        return None
    command = command.replace("\\\r\n", "").replace("\\\n", "")
    body, expanding = split_heredocs(command)
    try:
        tokens = tokenize(body)
    except ValueError:
        return ASK, PARSE_REASON
    nested = [
        check_command(inner, depth + 1)
        for text in [body, *expanding]
        for inner in substitutions(text)
    ]
    return merge_verdicts(*nested, *(check_words(seg, depth) for seg in segments(tokens)))


def emit(decision: str, reason: str) -> None:
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


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        emit(ASK, PARSE_REASON)
        return 0
    if not isinstance(payload, dict) or payload.get("tool_name") != "Bash":
        return 0
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        emit(ASK, PARSE_REASON)
        return 0
    verdict = check_command(command)
    if verdict is not None:
        emit(*verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main())
