"""The automated pull-request reviewer: ci/review.py and .github/workflows/review.yml (R-01, R-04, R-05).

The model call is stubbed. These tests check what the reviewer sends, how it reads the answer,
and that every way a review can fall short fails the check ai-review closed.
"""
import importlib.util
import sys
import types
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("review", ROOT / "ci" / "review.py")
review = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(review)

REVIEWER_APP_ID = 5667084       # ml-ids-stack-agent
ACTIONS_APP_ID = 15368          # GitHub Actions

GIT_DIFF = """\
diff --git a/ci/tool.sh b/ci/tool.sh
index 1111111..2222222 100644
--- a/ci/tool.sh
+++ b/ci/tool.sh
@@ -1,3 +1,3 @@
 set -e
-echo old
+echo new
 exit 0
diff --git a/docs/new.md b/docs/new.md
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/docs/new.md
@@ -0,0 +1,2 @@
+# New
+text
diff --git a/RISK-REGISTER.xlsx b/RISK-REGISTER.xlsx
index 4444444..5555555 100644
Binary files a/RISK-REGISTER.xlsx and b/RISK-REGISTER.xlsx differ
diff --git a/old.txt b/old.txt
deleted file mode 100644
index 6666666..0000000
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-gone
"""


def message(*blocks, stop_reason="end_turn", model="claude-opus-5-5", stop_details=None):
    return NS(stop_reason=stop_reason, stop_details=stop_details, model=model,
              content=list(blocks), usage=NS(input_tokens=10_000, output_tokens=2_000))


def text(t):
    return NS(type="text", text=t)


VERDICT = '{"summary": "Adds a script.", "findings": [{"severity": "note", "path": "a.py", "line": 3, "rule": "R-04 x", "message": "m"}]}'


class FakeClient:
    """Stands in for anthropic.Anthropic: records each request, answers or raises."""

    def __init__(self, answer=None, error=None):
        self.calls, self.answer, self.error = [], answer, error
        self.beta = NS(messages=NS(stream=self.stream))

    @contextmanager
    def stream(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        yield NS(get_final_message=lambda: self.answer)


@pytest.fixture
def anthropic_errors(monkeypatch):
    """A stand-in anthropic module with the SDK's exception hierarchy, so no SDK is needed here."""
    mod = types.ModuleType("anthropic")

    class APIError(Exception):
        def __init__(self, message="", status_code=0):
            super().__init__(message)
            self.message, self.status_code = message, status_code

    class APIStatusError(APIError):
        pass

    classes = {"APIError": APIError, "APIStatusError": APIStatusError,
               "APIConnectionError": type("APIConnectionError", (APIError,), {})}
    for name in ("AuthenticationError", "PermissionDeniedError", "RateLimitError"):
        classes[name] = type(name, (APIStatusError,), {})
    for name, cls in classes.items():
        setattr(mod, name, cls)
    mod.Anthropic = lambda **kw: pytest.fail("tests pass their own client")
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    return mod


# ---------------------------------------------------------------- what the model reads

def test_rules_are_the_conventions_and_banned_patterns_of_claude_md():
    rules = review.repo_rules((ROOT / "CLAUDE.md").read_text())
    assert "## Stack conventions" in rules and "## Banned patterns" in rules
    assert "## Role" not in rules and "## Commands" not in rules


def test_claude_md_without_its_rule_sections_fails_closed():
    with pytest.raises(review.ReviewIncomplete, match="no longer has the sections"):
        review.repo_rules("## Role\nYou are helpful.\n")


def test_risk_ids_come_from_the_register_summary():
    ids = review.risk_ids((ROOT / "RISK-REGISTER.md").read_text())
    assert ids == [f"R-{n:02d}" for n in range(1, 11)]
    assert review.risk_ids("R-01 in prose, no table row") == []


def test_every_diff_line_carries_its_new_line_number():
    patch = "@@ -1,3 +1,4 @@\n a\n-b\n+c\n+d\n e\n@@ -20 +21 @@\n-x\n+y"
    lines = review.number_patch(patch).splitlines()
    assert lines[1] == "     1  a"
    assert lines[2] == " " * 7 + "-b"           # removed lines have no number in the new file
    assert lines[3:6] == ["     2 +c", "     3 +d", "     4  e"]
    assert lines[6].startswith("@@") and lines[8] == "    21 +y"


def test_the_diff_says_what_it_leaves_out(monkeypatch):
    monkeypatch.setattr(review, "FILE_LIMIT", 50)
    files = [{"filename": "big.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+" + "x" * 100},
             {"filename": "a.png", "status": "added", "patch": None},
             {"filename": "ok.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"}]
    diff, reviewed, skipped = review.build_diff(files)
    assert reviewed == {"big.py", "ok.py"}
    assert "### ok.py (modified, +0 -0)" in diff and "[cut at 50 characters]" in diff
    assert any(s.startswith("a.png (binary") for s in skipped)
    assert any(s.startswith("big.py (only the first 50") for s in skipped)


def test_files_past_the_budget_are_listed_not_dropped(monkeypatch):
    monkeypatch.setattr(review, "DIFF_LIMIT", 10)
    files = [{"filename": f"f{i}.py", "patch": "@@ -1 +1 @@\n-a\n+b"} for i in range(3)]
    _, reviewed, skipped = review.build_diff(files)
    assert reviewed == {"f0.py"}
    assert [s.split()[0] for s in skipped] == ["f1.py", "f2.py"]
    assert all("over the review budget" in s for s in skipped)


def test_local_mode_rebuilds_the_github_files_list_from_git_diff():
    files = {f["filename"]: f for f in review.files_from_git_diff(GIT_DIFF)}
    assert set(files) == {"ci/tool.sh", "docs/new.md", "RISK-REGISTER.xlsx", "old.txt"}
    assert files["ci/tool.sh"]["status"] == "modified" and files["ci/tool.sh"]["patch"].startswith("@@ -1,3 +1,3 @@")
    assert (files["ci/tool.sh"]["additions"], files["ci/tool.sh"]["deletions"]) == (1, 1)
    assert files["docs/new.md"]["status"] == "added"
    assert files["old.txt"]["status"] == "removed"
    assert files["RISK-REGISTER.xlsx"]["patch"] is None      # binary: listed as not reviewed


# ---------------------------------------------------------------- the model call

def test_verdict_is_the_last_text_block_after_a_fallback():
    msg = message(NS(type="thinking", thinking=""), text('{"summary": "partial'),
                  NS(type="fallback"), text(VERDICT), model="claude-opus-4-8")
    verdict, meta = review.read_verdict(msg)
    assert verdict["findings"][0]["path"] == "a.py"
    assert meta == {"model": "claude-opus-4-8", "fallback": True, "input": 10_000, "output": 2_000}


@pytest.mark.parametrize("msg, reason", [
    (message(stop_reason="refusal", stop_details=NS(category="cyber")), "declined.*cyber"),
    (message(text('{"summ'), stop_reason="max_tokens"), "used all"),
    (message(text("not json")), "not valid JSON"),
    (message(NS(type="thinking", thinking="")), "no verdict"),
])
def test_anything_short_of_a_verdict_fails_closed(msg, reason):
    with pytest.raises(review.ReviewIncomplete, match=reason):
        review.read_verdict(msg)


def test_the_request_has_no_tools_and_asks_for_the_verdict_schema(anthropic_errors):
    client = FakeClient(answer=message(text(VERDICT)))
    review.ask_claude("system text", "user text", client)
    call = client.calls[0]
    assert call["model"] == review.MODEL and "tools" not in call
    assert call["betas"] == [review.FALLBACK_BETA] and call["fallbacks"] == "default"
    assert call["output_config"]["effort"] == review.EFFORT
    assert call["output_config"]["format"]["schema"] == review.VERDICT_SCHEMA
    assert call["messages"] == [{"role": "user", "content": "user text"}]


@pytest.mark.parametrize("error, reason", [
    ("AuthenticationError", "rejected the key"),
    ("RateLimitError", "rate limit"),
    ("APIStatusError", "answered 500"),
    ("APIConnectionError", "could not be reached"),
])
def test_api_errors_fail_closed(anthropic_errors, error, reason):
    client = FakeClient(error=getattr(anthropic_errors, error)("credit balance too low", 500))
    with pytest.raises(review.ReviewIncomplete, match=reason):
        review.ask_claude("s", "u", client)


def test_review_sends_main_rules_risk_ids_and_the_numbered_diff(anthropic_errors):
    client = FakeClient(answer=message(text(VERDICT)))
    files = [{"filename": "a.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+print(1)"}]
    verdict, meta, reviewed, _ = review.review(
        "feat: x", "Risks: R-04", files, (ROOT / "CLAUDE.md").read_text(), (ROOT / "RISK-REGISTER.md").read_text(), client)
    call = client.calls[0]
    assert call["system"].startswith(review.PROMPT.read_text()) and "## Banned patterns" in call["system"]
    user = call["messages"][0]["content"]
    assert "Risk IDs in RISK-REGISTER.md on main: R-01, R-02" in user
    assert "<diff>\n### a.py (added, +0 -0)\n@@ -0,0 +1 @@\n     1 +print(1)\n</diff>" in user
    assert reviewed == {"a.py"} and meta["model"] == "claude-opus-5-5"


def test_the_reviewer_model_and_its_price_are_known():
    assert review.MODEL == "claude-sonnet-5-5" and review.MODEL in review.PRICES
    meta = {"model": review.MODEL, "fallback": False, "input": 40_000, "output": 8_000}
    assert "about $0.16" in review.cost_line(meta)     # 40k x $2 + 8k x $10 per million


def test_a_binary_only_pull_request_needs_no_model_call(anthropic_errors):
    client = FakeClient(error=AssertionError("no call expected"))
    verdict, meta, _, skipped = review.review(
        "docs: screenshot", "", [{"filename": "docs/evidence/x.png", "patch": None}],
        (ROOT / "CLAUDE.md").read_text(), (ROOT / "RISK-REGISTER.md").read_text(), client)
    assert verdict["findings"] == [] and meta is None and client.calls == []
    assert skipped[0].startswith("docs/evidence/x.png")


# ---------------------------------------------------------------- what GitHub shows

BLOCKING = {"severity": "blocking", "path": "ci/a.sh", "line": 4, "rule": "R-02 secret", "message": "key in\n`code`"}
NOTE = {"severity": "note", "path": "README.md", "line": 0, "rule": "docs", "message": "unit missing"}


def test_a_blocking_finding_fails_the_check_and_notes_alone_do_not():
    assert review.conclusion([NOTE, BLOCKING]) == "failure"
    assert review.conclusion([NOTE]) == "success" and review.conclusion([]) == "success"
    assert review.title([NOTE, BLOCKING]) == "1 blocking, 1 note"
    assert review.title([]) == "No findings"


def test_the_review_puts_blocking_first_and_states_it_cannot_approve():
    verdict = {"summary": "Two\nlines.", "findings": [NOTE, BLOCKING]}
    meta = {"model": "claude-opus-5-5", "fallback": False, "input": 10_000, "output": 2_000}
    body = review.review_body("0123456789abcdef", verdict, meta, ["x.png (binary)"])
    lines = body.splitlines()
    assert lines[0] == "### ai-review of 0123456: 1 blocking, 1 note"
    assert lines[2] == "Two lines."
    assert lines[4] == "- **blocking** `ci/a.sh:4`, R-02 secret: key in 'code'"
    assert lines[5] == "- **note** `README.md`, docs: unit missing"
    assert "- x.png (binary)" in lines
    assert "about $0.08" in body and "Neither can approve" in body      # 10k x $4 + 2k x $20 per million


def test_no_price_is_claimed_for_a_fallback_or_an_unknown_model():
    meta = {"model": "claude-opus-4-8", "fallback": True, "input": 1, "output": 1}
    assert "$" not in review.cost_line(meta) and "fallback after a decline" in review.cost_line(meta)
    assert review.cost_line(None) == "No model call."


def test_comments_go_through_the_workflow_token_and_nothing_reviews():
    # The App token sets the check only; the workflow token, which may not approve, posts the
    # comment; nothing calls the reviews endpoint, where an approval would go (R-01).
    source = (ROOT / "ci" / "review.py").read_text()
    assert "/reviews" not in source
    assert 'return post_comment(repo, number, os.environ["COMMENT_TOKEN"], summary)' in source
    assert '"POST", f"/repos/{repo}/check-runs", token' in source


class FakeGitHub:
    def __init__(self, comments, fail=None):
        self.comments, self.fail, self.calls = comments, fail, []

    def __call__(self, method, path, token, body=None):
        self.calls.append((method, path, body))
        if self.fail and method == self.fail:
            raise review.urllib.error.HTTPError(path, 403, "Forbidden", {}, None)
        return self.comments if method == "GET" else {}


def test_the_review_comment_is_updated_in_place(monkeypatch):
    old = {"id": 7, "user": {"login": "github-actions[bot]"}, "body": review.MARKER + "\nold"}
    other = {"id": 8, "user": {"login": "danieldraghici"}, "body": review.MARKER + " quoted"}
    gh = FakeGitHub([old, other])
    monkeypatch.setattr(review, "github", gh)
    assert review.post_comment("o/r", "5", "t", "new") == 0
    assert gh.calls[-1] == ("PATCH", "/repos/o/r/issues/comments/7", {"body": review.MARKER + "\nnew"})


def test_a_first_review_posts_and_a_refused_comment_fails_only_the_job(monkeypatch):
    gh = FakeGitHub([])
    monkeypatch.setattr(review, "github", gh)
    assert review.post_comment("o/r", "5", "t", "x") == 0 and gh.calls[-1][0] == "POST"
    monkeypatch.setattr(review, "github", FakeGitHub([], fail="POST"))
    assert review.post_comment("o/r", "5", "t", "x") == 1


def test_annotations_only_for_reviewed_paths_and_real_lines():
    stray = dict(BLOCKING, path="not/in/diff.py")
    notes = review.annotations([BLOCKING, NOTE, stray], {"ci/a.sh", "README.md"})
    assert notes == [{"path": "ci/a.sh", "start_line": 4, "end_line": 4, "annotation_level": "failure",
                      "title": "R-02 secret", "message": "key in 'code'"}]


def test_an_incomplete_review_says_why_and_how_to_retry():
    body = review.incomplete_body("abcdef0123", "the model declined")
    assert "review not completed" in body and "because the model declined" in body and "Re-run" in body


# ---------------------------------------------------------------- workflow and ruleset

def workflow_problems(wf: dict) -> list[str]:
    """What would let a branch reach the secrets or the reviewer approve; empty when safe."""
    problems = []
    on = wf.get("on", wf.get(True))            # PyYAML reads the key `on` as True
    if list(on) != ["pull_request_target"]:
        problems.append("trigger is not only pull_request_target")
    for job in wf["jobs"].values():
        if job.get("environment") != "ai-review":
            problems.append("secrets outside the environment ai-review")
        for step in job["steps"]:
            uses, with_ = step.get("uses", ""), step.get("with", {})
            if uses.startswith("actions/checkout@") and ({"ref", "repository"} & set(with_)):
                problems.append("checkout of something other than main")
            if uses.startswith("actions/checkout@") and with_.get("persist-credentials") is not False:
                problems.append("checkout leaves a token in .git")
            if "${{" in step.get("run", ""):
                problems.append(f"expression inside run: {step['run']}")
            if uses.startswith("actions/create-github-app-token@"):
                writes = {k for k, v in with_.items() if k.startswith("permission-") and v == "write"}
                if writes != {"permission-checks"}:
                    problems.append(f"App token writes {sorted(writes)}")
        if job.get("permissions") != {"contents": "read", "pull-requests": "write"}:
            problems.append(f"job token permissions {job.get('permissions')}")
    return problems


def load_workflow():
    return yaml.safe_load((ROOT / ".github" / "workflows" / "review.yml").read_text())


def test_review_workflow_never_hands_the_branch_a_secret_or_an_approval():
    assert workflow_problems(load_workflow()) == []


def test_the_workflow_check_catches_an_unsafe_variant():
    wf = load_workflow()
    steps = wf["jobs"]["review"]["steps"]
    steps[0]["with"]["ref"] = "${{ github.event.pull_request.head.sha }}"
    steps[3]["with"]["permission-pull-requests"] = "write"
    steps[4]["run"] = "echo ${{ github.event.pull_request.title }}"
    problems = workflow_problems(wf)
    assert "checkout of something other than main" in problems
    assert any("permission-pull-requests" in p for p in problems)
    assert any(p.startswith("expression inside run") for p in problems)


def test_ai_review_is_required_from_the_reviewer_app_only():
    ruleset = (ROOT / ".github" / "rulesets" / "main-checks.json").read_text()
    rules = {r["type"]: r for r in yaml.safe_load(ruleset)["rules"]}
    checks = rules["required_status_checks"]["parameters"]["required_status_checks"]
    by_name = {c["context"]: c["integration_id"] for c in checks}
    # Bound to the App: a job named ai-review in a branch's workflow runs as GitHub Actions
    # and does not satisfy the rule.
    assert by_name["ai-review"] == REVIEWER_APP_ID
    assert {by_name[c] for c in ("lint", "test", "scan", "detection-gate")} == {ACTIONS_APP_ID}
