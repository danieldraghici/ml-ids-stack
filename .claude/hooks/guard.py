#!/usr/bin/env python3
"""PreToolUse guard for Claude Code (R-01, R-02, R-05, R-06).

Claude Code sends the pending tool call as JSON on stdin. Exit code 2 blocks the
call and stderr is the reason the agent sees; exit code 0 lets it through.

This hook is defence in depth, written so the rules hold even when a poisoned
memory file or a crafted alert talks the agent into trying. The controls that hold
even if the hook is bypassed are the server-side rulesets (R-01) and the code
owner review (R-05). The student edits this file by hand; the hook blocks the agent
from editing it. Every rule has a test in tests/test_hook.py.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys

# --- paths -------------------------------------------------------------------

SECRET_GLOBS = [
    ".env", "*/.env", ".env.*", "*/.env.*",      # decrypted env files (.env.secrets)
    "*.agekey", "keys.txt", "*/keys.txt",          # age private keys
    "certs/*.key", "*/certs/*.key",                # lab PKI private keys
    "*.pem", "run/secrets/*", "*/agent-token",     # the agent's token and the App key (R-03)
    "*/.git-credentials", "*/.config/gh/hosts.yml",  # the student's own credentials
]
# Key material named anywhere in a shell command, even inside a quoted script.
SECRET_IN_COMMAND = re.compile(r"\.pem\b|\.agekey\b|keys\.txt\b|\.env\.secrets\b|/run/secrets/|agent-token\b")
SECRET_ALLOW = [".env.example", "*/.env.example"]
SECRETS_DIR = ["secrets/*"]                        # agent never writes here
SECRETS_DIR_READ_ALLOW = ["secrets/*.enc.yaml"]    # ciphertext is safe to read

PROTECTED_GLOBS = [                                # write-blocked for the agent
    ".claude/settings*.json", "*/.claude/settings*.json",   # project, local and user settings
    ".claude/hooks", ".claude/hooks/*", "*/.claude/hooks/*",
    ".github/CODEOWNERS", ".github/rulesets", ".github/rulesets/*",
    "detector/thresholds.json", "models", "models/*",
    "tests/regression", "tests/regression/*",
]
# Directories whose removal would take protected files with them.
PROTECTED_PARENTS = {"", ".", "*", ".claude", ".github", "tests", "detector"}
DESTRUCTIVE_CMDS = {"rm", "mv", "shred", "unlink", "rmdir"}

READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead"}
WRITE_TOOLS = {"Edit", "MultiEdit", "Write", "NotebookEdit"}


def norm(path: str, root: str) -> str:
    """Repository-relative POSIX path with '.' and '..' resolved."""
    p = path.replace("\\", "/")
    r = root.replace("\\", "/").rstrip("/")
    if r and p.lower().startswith(r.lower() + "/"):
        p = p[len(r) + 1:]
    parts: list[str] = []
    for part in p.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def match(rel: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(rel, g) for g in globs)


def is_secret(rel: str) -> bool:
    if match(rel, SECRET_ALLOW):
        return False
    return match(rel, SECRET_GLOBS)


def is_protected(rel: str) -> bool:
    return match(rel, PROTECTED_GLOBS) or match(rel, SECRETS_DIR)


# --- Bash parsing --------------------------------------------------------------

SEPARATORS = re.compile(r"&&|\|\||;|\||\n|`|\$\(|\)")
WRAPPERS = {"sudo", "command", "env", "nohup", "time", "exec", "nice", "xargs"}
SHELLS = {"sh", "bash", "zsh", "dash"}
WRITE_CMDS = {"rm", "mv", "cp", "tee", "truncate", "dd", "ln", "install", "rsync",
              "unlink", "chmod", "chown", "touch", "patch", "shred"}
INTERPRETERS = {"python", "python3", "py", "node", "ruby", "perl"}
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
FORCE_FLAGS = {"-f", "--force", "--force-with-lease", "--force-if-includes",
               "--mirror", "--delete", "-d", "--prune"}
GH_SENSITIVE_API = re.compile(
    r"rulesets|/protection|/collaborators|/actions/permissions|/hooks|/keys|/environments")
GH_API_OPTS_WITH_VALUE = {"-H", "--header", "-q", "--jq", "-t", "--template",
                          "--hostname", "--cache", "-p", "--preview"}
REDIRECT = re.compile(r">>?\s*([^\s;&|<>]+)")


class Blocked(Exception):
    pass


def block(risk: str, reason: str) -> None:
    raise Blocked(f"Blocked by guard ({risk}): {reason}")


def tokens_of(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def strip_prefix(tokens: list[str]) -> list[str]:
    i = 0
    while i < len(tokens) and (re.match(r"^\w+=", tokens[i]) or tokens[i] in WRAPPERS):
        i += 1
    return tokens[i:]


def pieces(token: str) -> list[str]:
    """Split a token like --env-file=.env or <.env into path-like pieces."""
    return [p for p in re.split(r"[=<>,]", token) if p]


def git_subcommand(tokens: list[str]) -> tuple[str, list[str]]:
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t in GIT_OPTS_WITH_VALUE:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        return t, tokens[i + 1:]
    return "", []


def current_branch(cwd: str) -> str:
    try:
        # symbolic-ref also works on a branch with no commits yet, unlike rev-parse
        out = subprocess.run(["git", "symbolic-ref", "--short", "-q", "HEAD"], cwd=cwd or None,
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def check_git(tokens: list[str], root: str, cwd: str) -> None:
    sub, args = git_subcommand(tokens)
    joined = " ".join(tokens).lower()
    if "core.hookspath" in joined:
        block("R-02, R-05", "changing core.hooksPath would switch off the pre-commit checks")
    if sub == "commit":
        for a in args:
            if a == "--no-verify" or (re.fullmatch(r"-[a-zA-Z]+", a) and "n" in a[1:]):
                block("R-02", "git commit --no-verify skips gitleaks and the other pre-commit checks")
    if sub == "push":
        positional = []
        for a in args:
            if a == "--no-verify":
                block("R-02", "git push --no-verify skips the pre-push checks")
            if a in FORCE_FLAGS or a.startswith("--force-with-lease="):
                block("R-01", f"git push {a} can rewrite or delete history")
            if re.fullmatch(r"-[a-zA-Z]+", a) and ("f" in a[1:] or "d" in a[1:]):
                block("R-01", f"git push {a} can rewrite or delete history")
            if not a.startswith("-"):
                positional.append(a)
        for ref in positional[1:]:
            if ref.startswith("+") or ref.startswith(":"):
                block("R-01", f"refspec {ref} forces or deletes a remote branch")
            dst = ref.split(":")[-1]
            if dst in ("main", "refs/heads/main"):
                block("R-01", "pushing to main; open a pull request from a branch instead")
        if len(positional) <= 1 and current_branch(cwd) == "main":
            block("R-01", "the current branch is main; push a feature branch instead")
    if sub in ("checkout", "restore", "rm", "mv", "apply", "am"):
        for a in args:
            for p in pieces(a):
                if is_protected(norm(p, root)):
                    block("R-05, R-06", f"git {sub} would change protected path {p}")


def check_gh(tokens: list[str]) -> None:
    sub = tokens[1:3]
    if sub[:2] == ["auth", "token"] or (sub[:2] == ["auth", "status"] and {"-t", "--show-token"} & set(tokens)):
        block("R-02, R-03", "printing the GitHub token would expose it in the transcript")
    if sub[:2] == ["auth", "login"] or sub[:2] == ["auth", "refresh"]:
        block("R-03", "the agent keeps the scoped token it started with; it never logs in with another")
    if sub[:2] == ["pr", "merge"]:
        block("R-01, R-05", "the agent never merges; the student merges after review")
    if sub[:2] == ["pr", "review"] and ({"--approve", "-a"} & set(tokens)):
        block("R-01, R-05", "the agent never approves a pull request")
    if sub[:1] == ["repo"] and len(sub) > 1 and sub[1] in {"edit", "delete", "rename", "archive"}:
        block("R-01, R-03", f"gh repo {sub[1]} changes repository settings")
    if sub[:1] in (["secret"], ["variable"]) and len(sub) > 1 and sub[1] in {"set", "delete", "remove"}:
        block("R-02, R-03", f"gh {sub[0]} {sub[1]} changes repository secrets or variables")
    if sub[:1] == ["api"]:
        endpoint, method, has_body = "", "", False
        i = 2
        while i < len(tokens):
            t = tokens[i]
            if t in ("-X", "--method"):
                method = tokens[i + 1].upper() if i + 1 < len(tokens) else method
                i += 2
                continue
            if t.startswith("--method="):
                method = t.split("=", 1)[1].upper()
            elif t in ("-f", "-F", "--field", "--raw-field", "--input"):
                has_body = True
                i += 2
                continue
            elif t in GH_API_OPTS_WITH_VALUE:
                i += 2
                continue
            elif not t.startswith("-") and not endpoint:
                endpoint = t
            i += 1
        method = method or ("POST" if has_body else "GET")
        if GH_SENSITIVE_API.search(endpoint) and method != "GET":
            block("R-01, R-03", f"gh api {method} {endpoint} changes protection or access")


def is_pytest(tokens: list[str]) -> bool:
    if not tokens:
        return False
    if os.path.basename(tokens[0]) == "pytest":
        return True
    return (os.path.basename(tokens[0]) in INTERPRETERS and len(tokens) > 2
            and tokens[1] == "-m" and tokens[2] == "pytest")


def check_segment(segment: str, root: str, cwd: str, depth: int = 0) -> None:
    tokens = strip_prefix(tokens_of(segment))
    if not tokens:
        return
    cmd = os.path.basename(tokens[0])

    # nested shells: bash -c '...', eval '...'
    if depth < 3 and cmd in SHELLS and "-c" in tokens:
        i = tokens.index("-c")
        if i + 1 < len(tokens):
            check_command(tokens[i + 1], root, cwd, depth + 1)
    if depth < 3 and cmd == "eval":
        check_command(" ".join(tokens[1:]), root, cwd, depth + 1)

    # secrets (R-02)
    for t in tokens[1:]:
        for p in pieces(t):
            if is_secret(norm(p, root)):
                block("R-02", f"{p} holds secrets; use the make targets instead")
    for target in REDIRECT.findall(segment):
        if is_secret(norm(target, root)):
            block("R-02", f"{target} holds secrets")
    if cmd == "sops" and {"-d", "--decrypt", "decrypt", "edit", "exec-env", "exec-file"} & set(tokens):
        block("R-02", "sops decryption prints the plaintext secret; make secrets writes it for compose")
    if cmd == "pre-commit" and "uninstall" in tokens:
        block("R-02", "removing the pre-commit hooks switches off gitleaks")

    if cmd == "git":
        check_git(tokens, root, cwd)
    if cmd == "gh":
        check_gh(tokens)

    # writes to protected paths (R-05, R-06)
    for target in REDIRECT.findall(segment):
        if is_protected(norm(target, root)):
            block("R-05, R-06", f"redirect writes to protected path {target}")
    if cmd in DESTRUCTIVE_CMDS:
        for t in tokens[1:]:
            if not t.startswith("-") and norm(t, root) in PROTECTED_PARENTS:
                block("R-05, R-06", f"{cmd} {t} would remove protected files")
    mentioned = [p for t in tokens[1:] for p in pieces(t) if is_protected(norm(p, root))]
    if mentioned and not is_pytest(tokens):
        in_place = cmd in ("sed", "perl") and any(t.startswith("-i") or t == "--in-place" for t in tokens)
        inline = cmd in INTERPRETERS and ({"-c", "-e"} & set(tokens))
        if cmd in WRITE_CMDS or in_place or inline:
            block("R-05, R-06", f"{cmd} would change protected path {mentioned[0]}")
    if cmd in INTERPRETERS and ({"-c", "-e"} & set(tokens)) and not is_pytest(tokens):
        for g in ("thresholds.json", "models/", "tests/regression", ".claude/hooks", ".claude/settings"):
            if g in segment:
                block("R-05, R-06", f"inline script touches protected path {g}")


def check_command(command: str, root: str, cwd: str, depth: int = 0) -> None:
    found = SECRET_IN_COMMAND.search(command)
    if found:
        block("R-02, R-03", f"the command names key material ({found.group(0)})")
    for segment in SEPARATORS.split(command):
        if segment.strip():
            check_segment(segment.strip(), root, cwd, depth)


# --- entry point ---------------------------------------------------------------

def check(payload: dict) -> None:
    tool = payload.get("tool_name", "")
    data = payload.get("tool_input", {}) or {}
    root = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd", "")
    cwd = payload.get("cwd", "") or root

    if tool == "Bash":
        check_command(data.get("command", ""), root, cwd)
        return

    if tool.startswith("mcp__"):
        low = tool.lower()
        if "merge_pull_request" in low:
            block("R-01, R-05", "the agent never merges; the student merges after review")
        if "review" in low and str(data.get("event", "")).upper() == "APPROVE":
            block("R-01, R-05", "the agent never approves a pull request")
        if "branch_protection" in low or "ruleset" in low:
            block("R-01", "the agent never changes branch protection or rulesets")
        return

    paths = [data.get(k) for k in ("file_path", "notebook_path", "path")]
    paths = [p for p in paths if p]
    if data.get("glob"):
        paths.append(data["glob"])
    if tool == "Glob" and data.get("pattern"):
        paths.append(data["pattern"])

    for raw in paths:
        rel = norm(raw, root)
        if is_secret(rel):
            block("R-02", f"{raw} holds secrets")
        if tool in READ_TOOLS and match(rel, SECRETS_DIR) and not match(rel, SECRETS_DIR_READ_ALLOW):
            block("R-02", f"{raw} is not an encrypted file")
        if tool in WRITE_TOOLS and is_protected(rel):
            block("R-05, R-06", f"{raw} is protected; the student changes it by hand in a reviewed PR")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("Blocked by guard: hook input is not valid JSON", file=sys.stderr)
        return 2
    try:
        check(payload)
    except Blocked as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
