"""The guard hook blocks what it must and lets normal work through (R-01, R-02, R-05, R-06).

Each case runs .claude/hooks/guard.py as Claude Code would: JSON on stdin, exit 2
means blocked. Every blocked case has a matching allowed case nearby, so the hook
cannot pass by blocking everything.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / ".claude" / "hooks" / "guard.py"
PROJECT = "/work/ml-ids-stack"


def run_hook(tool, tool_input, cwd=PROJECT):
    payload = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "cwd": cwd}
    env = dict(os.environ, CLAUDE_PROJECT_DIR=PROJECT)
    return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                          capture_output=True, text=True, env=env, timeout=30)


def bash(command, cwd=PROJECT):
    return run_hook("Bash", {"command": command}, cwd)


# --- file tools ----------------------------------------------------------------

FILE_BLOCKED = [
    ("Read", {"file_path": f"{PROJECT}/.env"}, "R-02"),
    ("Read", {"file_path": f"{PROJECT}/.env.secrets"}, "R-02"),
    ("Read", {"file_path": "C:\\Users\\student\\ml-ids-stack\\.env.secrets"}, "R-02"),
    ("Read", {"file_path": "/home/vscode/.config/sops/age/keys.txt"}, "R-02"),
    ("Read", {"file_path": f"{PROJECT}/certs/frontdoor.key"}, "R-02"),
    ("Read", {"file_path": f"{PROJECT}/secrets/notes.txt"}, "R-02"),
    ("Read", {"file_path": "/run/secrets/agent-app.pem"}, "R-02"),
    ("Read", {"file_path": "/run/secrets/agent-gh-token"}, "R-02"),
    ("Read", {"file_path": "/home/vscode/.config/ml-ids-stack/agent-token"}, "R-02"),
    ("Read", {"file_path": "/home/vscode/Downloads/ml-ids-stack-agent.2026-11-08.private-key.pem"}, "R-02"),
    ("Grep", {"pattern": "PASSWORD", "path": f"{PROJECT}/.env"}, "R-02"),
    ("Grep", {"pattern": "PASSWORD", "path": PROJECT, "glob": ".env.*"}, "R-02"),
    ("Write", {"file_path": f"{PROJECT}/secrets/plain.yaml", "content": "x"}, "R-05"),
    ("Edit", {"file_path": f"{PROJECT}/detector/thresholds.json"}, "R-06"),
    ("Edit", {"file_path": f"{PROJECT}/detector/../detector/thresholds.json"}, "R-06"),
    ("Write", {"file_path": f"{PROJECT}/models/nfv3_window_xgb_latest.joblib"}, "R-06"),
    ("Edit", {"file_path": f"{PROJECT}/tests/regression/test_detection_quality.py"}, "R-06"),
    ("Edit", {"file_path": f"{PROJECT}/.claude/hooks/guard.py"}, "R-05"),
    ("Write", {"file_path": f"{PROJECT}/.claude/settings.json"}, "R-05"),
    ("Write", {"file_path": f"{PROJECT}/.claude/settings.local.json"}, "R-05"),
    ("Write", {"file_path": "/home/vscode/.claude/settings.json"}, "R-05"),
    ("Edit", {"file_path": f"{PROJECT}/.github/CODEOWNERS"}, "R-05"),
    ("Edit", {"file_path": f"{PROJECT}/.github/rulesets/main-review.json"}, "R-05"),
]

FILE_ALLOWED = [
    ("Read", {"file_path": f"{PROJECT}/README.md"}),
    ("Read", {"file_path": f"{PROJECT}/.env.example"}),
    ("Read", {"file_path": f"{PROJECT}/secrets/stack.enc.yaml"}),
    ("Read", {"file_path": f"{PROJECT}/.claude/settings.json"}),
    ("Read", {"file_path": f"{PROJECT}/detector/thresholds.json"}),
    ("Grep", {"pattern": "TODO", "path": PROJECT, "glob": "*.py"}),
    ("Edit", {"file_path": f"{PROJECT}/detector/live.py"}),
    ("Write", {"file_path": f"{PROJECT}/memory/new-correction.md", "content": "x"}),
    ("Edit", {"file_path": f"{PROJECT}/memory/MEMORY.md"}),
    ("Write", {"file_path": f"{PROJECT}/.github/workflows/ci.yml", "content": "x"}),
    ("Edit", {"file_path": f"{PROJECT}/tests/test_hook.py"}),
]


@pytest.mark.parametrize("tool,tool_input,risk", FILE_BLOCKED)
def test_file_tool_blocked(tool, tool_input, risk):
    r = run_hook(tool, tool_input)
    assert r.returncode == 2, r.stderr
    assert "Blocked by guard" in r.stderr and risk in r.stderr


@pytest.mark.parametrize("tool,tool_input", FILE_ALLOWED)
def test_file_tool_allowed(tool, tool_input):
    r = run_hook(tool, tool_input)
    assert r.returncode == 0, r.stderr


# --- Bash ----------------------------------------------------------------------

BASH_BLOCKED = [
    # secrets (R-02)
    ("cat .env.secrets", "R-02"),
    ("cp .env.example .env", "R-02"),
    ("docker compose --env-file=.env up -d", "R-02"),
    ("echo $(cat .env)", "R-02"),
    ("grep PASSWORD < .env.secrets", "R-02"),
    ("sops -d secrets/stack.enc.yaml", "R-02"),
    ("sops decrypt secrets/stack.enc.yaml", "R-02"),
    ("cat ~/.config/sops/age/keys.txt", "R-02"),
    ("cat /run/secrets/agent-app.pem", "R-03"),
    ("python3 -c \"print(open('/run/secrets/agent-app.pem').read())\"", "R-03"),
    ("openssl rsa -in app.pem -text", "R-03"),
    ("base64 ~/.config/ml-ids-stack-agent/app.pem", "R-03"),
    ("cat /run/secrets/agent-gh-token", "R-03"),
    ("cat ~/.config/ml-ids-stack/agent-token", "R-03"),
    ("gh auth token", "R-03"),
    ("gh auth status --show-token", "R-03"),
    ("gh auth login --with-token < /tmp/other-token", "R-03"),
    ("git credential fill", "R-03"),
    ("git credential-store get", "R-03"),
    ("gh auth git-credential get", "R-03"),
    ("git commit --no-verify -m 'feat: x (R-01)'", "R-02"),
    ("git commit -nm 'feat: x'", "R-02"),
    ("git config core.hooksPath /dev/null", "R-02"),
    ("git -c core.hooksPath=/tmp commit -m x", "R-02"),
    ("pre-commit uninstall", "R-02"),
    # history and main (R-01)
    ("git push --force", "R-01"),
    ("git push -f origin feat/hook", "R-01"),
    ("git push -fu origin feat/hook", "R-01"),
    ("git push --force-with-lease origin feat/hook", "R-01"),
    ("git push origin +feat/hook:feat/hook", "R-01"),
    ("git push origin :feat/old", "R-01"),
    ("git push origin --delete feat/old", "R-01"),
    ("git push origin main", "R-01"),
    ("git push origin HEAD:main", "R-01"),
    ("git push origin feat/x:refs/heads/main", "R-01"),
    ("git push --no-verify origin feat/x", "R-02"),
    ("git -C /work/ml-ids-stack push -f", "R-01"),
    ("FOO=1 git push --force", "R-01"),
    ("ls && git push -f", "R-01"),
    ("bash -c 'git push --force origin feat/x'", "R-01"),
    ("eval git push --force", "R-01"),
    # review and settings (R-01, R-05)
    ("gh pr merge 5 --squash", "R-05"),
    ("gh pr review 5 --approve", "R-05"),
    ("gh pr review 5 -a -b ok", "R-05"),
    # the same merge and approve through the API (R-01, R-05)
    ("gh api -X PUT repos/o/r/pulls/5/merge", "R-01"),
    ("gh api -XPUT repos/o/r/pulls/5/merge", "R-01"),
    ("gh api repos/o/r/pulls/5/merge --method PUT -f merge_method=squash", "R-01"),
    ("gh api repos/o/r/pulls/5/reviews -f event=APPROVE", "R-05"),
    ("gh api -X POST repos/o/r/merges -f base=main -f head=feat/x", "R-01"),
    ("gh api graphql -f query='mutation { mergePullRequest(input: {pullRequestId: \"x\"}) { clientMutationId } }'", "R-01"),
    ("gh api graphql --input /tmp/query.json", "R-05"),
    ("gh api graphql -F query=@/tmp/merge.graphql", "R-05"),
    ("gh api -X PUT repos/o/r/rulesets/1", "R-01"),
    ("gh api repos/o/r/branches/main/protection --method DELETE", "R-01"),
    ("gh api repos/o/r/collaborators/someone -f permission=admin", "R-03"),
    ("gh repo edit --visibility public", "R-03"),
    ("gh secret set SHODAN_KEY", "R-02"),
    # protected paths (R-05, R-06)
    ("echo '{\"threshold\": 0.5}' > detector/thresholds.json", "R-06"),
    ("sed -i s/0.00515/0.5/ detector/thresholds.json", "R-06"),
    ("rm -rf models/", "R-06"),
    ("rm -rf tests", "R-06"),
    ("rm -rf .", "R-06"),
    ("cp /tmp/x.py tests/regression/test_detection_quality.py", "R-06"),
    ("tee .claude/settings.json < /tmp/s.json", "R-05"),
    ("mv .claude/hooks/guard.py /tmp/", "R-05"),
    ("python3 -c \"open('detector/thresholds.json','w').write('{}')\"", "R-06"),
    ("git checkout -- tests/regression/fixtures.json", "R-06"),
    # releases and tags are the student's (R-04, R-07)
    ("git tag v0.4.0", "R-04"),
    ("git tag -a v0.4.0 -m 'release'", "R-04"),
    ("git tag -f v0.4.0 HEAD", "R-04"),
    ("git tag -d v0.4.0", "R-04"),
    ("git push origin v0.4.0", "R-04"),
    ("git push origin refs/tags/v0.4.0", "R-04"),
    ("git push origin HEAD:refs/tags/model-v2", "R-04"),
    ("git push --tags", "R-04"),
    ("git push --follow-tags origin feat/x", "R-04"),
    ("gh release create v0.4.0 --generate-notes", "R-04"),
    ("gh release upload model-v1 models/other.joblib --clobber", "R-07"),
    ("gh release delete model-v1 --yes", "R-04"),
    ("gh release edit v0.4.0 --draft", "R-04"),
    ("gh api -X POST repos/o/r/releases -f tag_name=v9", "R-04"),
    ("gh api repos/o/r/git/refs -f ref=refs/tags/v9 -f sha=abc", "R-04"),
    ("gh api -X PATCH repos/o/r/git/refs/tags/v0.4.0 -f sha=abc", "R-04"),
]

BASH_ALLOWED = [
    "git status",
    "git push origin feat/hook",
    "git push -u origin feat/hook",
    "git commit -m 'feat: guard hook (R-05)'",
    "git commit -am 'docs: update .env.example notes'",
    "git log --oneline -- models/",
    "make up",
    "make test",
    "cat .claude/settings.json",
    "cat detector/thresholds.json",
    "python3 -m pytest -q tests/regression",
    "pytest tests/regression -q",
    "python3 -m pytest -q tests/test_register.py",
    "gh auth status",
    "gh pr create --fill",
    "gh pr view 3",
    "gh pr review 5 --comment -b 'see the findings'",
    "gh api repos/o/r/rulesets",
    "gh api repos/o/r/pulls/5",
    "gh api repos/o/r/pulls/5/merge",
    "gh api repos/o/r/pulls/5/reviews",
    "gh api graphql -f query='query { viewer { login } }'",
    "git config --get credential.helper",
    "sops --encrypt --in-place secrets/new.enc.yaml",
    "ls -la secrets/",
    "echo done > /tmp/out.txt",
    "docker compose logs 2>&1 | tail -5",
    "rm -rf /tmp/build",
    "git tag",
    "git tag -l 'v*'",
    "git tag --contains HEAD",
    "git push -u origin ci/supply-chain",
    "gh release list",
    "gh release view v0.4.0",
    "gh release download model-v1 --dir models --pattern '*.joblib'",
    "gh api repos/o/r/releases",
    "make gate",
    "make model-release",
]


@pytest.mark.parametrize("command,risk", BASH_BLOCKED)
def test_bash_blocked(command, risk):
    r = bash(command)
    assert r.returncode == 2, f"not blocked: {command}"
    assert "Blocked by guard" in r.stderr and risk in r.stderr, r.stderr


@pytest.mark.parametrize("command", BASH_ALLOWED)
def test_bash_allowed(command):
    r = bash(command)
    assert r.returncode == 0, f"blocked: {command}: {r.stderr}"


# --- current branch is main -----------------------------------------------------

def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def test_bare_push_blocked_on_main(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    assert bash("git push", cwd=str(tmp_path)).returncode == 2
    assert bash("git push origin", cwd=str(tmp_path)).returncode == 2


def test_bare_push_allowed_on_branch(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "feat/x")
    assert bash("git push", cwd=str(tmp_path)).returncode == 0


# --- MCP tools and bad input ----------------------------------------------------

def test_mcp_merge_blocked():
    r = run_hook("mcp__github__merge_pull_request", {"owner": "o", "repo": "r", "pullNumber": 5})
    assert r.returncode == 2 and "R-05" in r.stderr


def test_mcp_approve_blocked():
    r = run_hook("mcp__github__create_pull_request_review", {"pullNumber": 5, "event": "APPROVE"})
    assert r.returncode == 2


def test_mcp_comment_review_allowed():
    r = run_hook("mcp__github__create_pull_request_review", {"pullNumber": 5, "event": "COMMENT"})
    assert r.returncode == 0


def test_invalid_json_is_blocked():
    r = subprocess.run([sys.executable, str(HOOK)], input="not json", capture_output=True, text=True)
    assert r.returncode == 2
