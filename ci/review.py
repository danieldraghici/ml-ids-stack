"""Automated pull-request review as the GitHub App ml-ids-stack-agent (R-01, R-04, R-05).

.github/workflows/review.yml runs this file from main's own checkout on pull_request_target.
It reads the pull request through the GitHub API and never checks out or runs the pull
request's code. The diff goes to Claude as data, with no tools. The App then posts one
comment and sets the check run ai-review, which ruleset main-checks requires. The App has no
pull-request write permission, so it cannot approve: every merge stays the student's decision.

    python ci/review.py           # workflow: REPO, PR_NUMBER, HEAD_SHA, APP_TOKEN, ANTHROPIC_API_KEY
    python ci/review.py --local   # student: reviews git diff origin/main...HEAD, prints the comment

The check fails closed: a blocking finding, a declined request, an API error or a verdict that
cannot be read all set ai-review to failure, with the reason in the comment.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPT = Path(__file__).with_name("review-prompt.md")
CHECK_NAME = "ai-review"
MARKER = "<!-- ai-review -->"
API = "https://api.github.com"

# Claude Opus 5.5 at effort high: a review is judgement work, and one costs cents (docs/review.md).
# fallbacks "default" re-runs a request the model's safety classifiers decline on the model
# Anthropic recommends for that category, so security code in a diff does not end the review.
MODEL = "claude-opus-5-5"
EFFORT = "high"
MAX_TOKENS = 32_000          # thinking plus the verdict; bounds the output cost of one review
FALLBACK_BETA = "server-side-fallback-2026-07-01"
PRICES = {"claude-opus-5-5": (4.0, 20.0)}   # USD per million input and output tokens, 2026-11

FILE_LIMIT = 60_000          # characters of one file's patch sent to the model
DIFF_LIMIT = 400_000         # characters of the whole diff, about 100,000 tokens
ANNOTATION_LIMIT = 50        # GitHub takes at most 50 annotations per request
TEXT_LIMIT = 60_000          # comments and check summaries stop at 65,535 characters

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["blocking", "note"]},
                    "path": {"type": "string"},
                    "line": {"type": "integer"},
                    "rule": {"type": "string"},
                    "message": {"type": "string"},
                },
                "required": ["severity", "path", "line", "rule", "message"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "findings"],
    "additionalProperties": False,
}

RULE_SECTIONS = ("## Stack conventions", "## Banned patterns")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class ReviewIncomplete(Exception):
    """The review could not finish; ai-review fails with this reason."""


# ---------------------------------------------------------------- what the model reads

def repo_rules(claude_md: str) -> str:
    """The stack conventions and banned patterns of CLAUDE.md, the rules every change follows."""
    sections = [s.strip() for s in re.split(r"(?m)^(?=## )", claude_md) if s.startswith(RULE_SECTIONS)]
    if len(sections) != len(RULE_SECTIONS):
        raise ReviewIncomplete("CLAUDE.md on main no longer has the sections " + " and ".join(RULE_SECTIONS))
    return "\n\n".join(sections)


def risk_ids(register_md: str) -> list[str]:
    """Risk IDs in the summary table of RISK-REGISTER.md."""
    return sorted(set(re.findall(r"(?m)^\| (R-\d{2}) \|", register_md)))


def number_patch(patch: str) -> str:
    """Prefix each line of a unified-diff patch with its line number in the new file."""
    out, new = [], 0
    for line in patch.splitlines():
        hunk = HUNK.match(line)
        if hunk:
            new = int(hunk.group(1))
            out.append(line)
        elif line.startswith(("-", "\\")):      # removed, or "\ No newline at end of file"
            out.append(f"{'':>6} {line}")
        else:
            out.append(f"{new:>6} {line}")
            new += 1
    return "\n".join(out)


def build_diff(files: list[dict]) -> tuple[str, set[str], list[str]]:
    """Diff text for the model, the paths it covers, and what it leaves out (said, never silent)."""
    parts, reviewed, skipped, used = [], set(), [], 0
    for f in files:
        name, patch = f["filename"], f.get("patch")
        if not patch:
            skipped.append(f"{name} (binary, renamed without changes, or too large for the API)")
            continue
        if used >= DIFF_LIMIT:
            skipped.append(f"{name} (over the review budget of {DIFF_LIMIT:,} characters)")
            continue
        cut = ""
        if len(patch) > FILE_LIMIT:
            patch, cut = patch[:FILE_LIMIT], f" [cut at {FILE_LIMIT:,} characters]"
            skipped.append(f"{name} (only the first {FILE_LIMIT:,} characters reviewed)")
        body = number_patch(patch)
        parts.append(f"### {name} ({f.get('status', 'modified')}, "
                     f"+{f.get('additions', 0)} -{f.get('deletions', 0)}){cut}\n{body}")
        reviewed.add(name)
        used += len(body)
    return "\n\n".join(parts), reviewed, skipped


def files_from_git_diff(diff: str) -> list[dict]:
    """The GitHub pull-request files list, rebuilt from `git diff` output for --local."""
    files = []
    for chunk in re.split(r"(?m)^diff --git ", diff)[1:]:
        head, sep, rest = chunk.partition("\n@@")
        target = re.search(r"(?m)^\+\+\+ b/(.+)$", head)
        name = target.group(1) if target else chunk.split("\n", 1)[0].split(" b/", 1)[-1]
        status = ("added" if "\nnew file mode" in head else
                  "removed" if "\ndeleted file mode" in head else "modified")
        patch = "@@" + rest.rstrip("\n") if sep else None
        lines = patch.splitlines() if patch else []
        files.append({"filename": name, "status": status, "patch": patch,
                      "additions": sum(1 for x in lines if x.startswith("+")),
                      "deletions": sum(1 for x in lines if x.startswith("-"))})
    return files


def user_message(title: str, body: str, risks: list[str], diff: str, skipped: list[str]) -> str:
    left_out = "\n".join(f"- {s}" for s in skipped) or "- none"
    return (f"<pull_request>\n<title>{title}</title>\n<description>\n{body or '(empty)'}\n"
            f"</description>\n</pull_request>\n\n"
            f"Risk IDs in RISK-REGISTER.md on main: {', '.join(risks)}\n\n"
            f"Files changed but not in the diff below:\n{left_out}\n\n<diff>\n{diff}\n</diff>")


# ---------------------------------------------------------------- the model call

def read_verdict(message) -> tuple[dict, dict]:
    """The verdict and its usage from a final message; anything short of a verdict fails closed."""
    if message.stop_reason == "refusal":
        category = getattr(message.stop_details, "category", None) if message.stop_details else None
        raise ReviewIncomplete(f"the model declined to review this diff (category: {category or 'none given'})")
    if message.stop_reason == "max_tokens":
        raise ReviewIncomplete(f"the review used all {MAX_TOKENS:,} output tokens before it finished")
    texts = [b.text for b in message.content if b.type == "text"]
    if not texts:
        raise ReviewIncomplete("the model returned no verdict")
    try:
        verdict = json.loads(texts[-1])         # after a fallback, the last text block is the answer
    except json.JSONDecodeError as err:
        raise ReviewIncomplete("the verdict was not valid JSON") from err
    meta = {"model": message.model,
            "fallback": any(b.type == "fallback" for b in message.content),
            "input": message.usage.input_tokens, "output": message.usage.output_tokens}
    return verdict, meta


def ask_claude(system: str, user: str, client=None) -> tuple[dict, dict]:
    import anthropic    # only the review needs the SDK; the helpers above stay testable without it

    client = client or anthropic.Anthropic(max_retries=4)   # key from ANTHROPIC_API_KEY
    try:
        with client.beta.messages.stream(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            betas=[FALLBACK_BETA],
            fallbacks="default",
            output_config={"effort": EFFORT,
                           "format": {"type": "json_schema", "schema": VERDICT_SCHEMA}},
            system=system,
            messages=[{"role": "user", "content": user}],
        ) as stream:
            message = stream.get_final_message()
    except anthropic.AuthenticationError as err:
        raise ReviewIncomplete("the Claude API rejected the key (secret ANTHROPIC_API_KEY)") from err
    except anthropic.PermissionDeniedError as err:
        raise ReviewIncomplete("the API key may not use this model") from err
    except anthropic.RateLimitError as err:
        raise ReviewIncomplete("the Claude API rate limit was reached; re-run the review later") from err
    except anthropic.APIStatusError as err:
        raise ReviewIncomplete(f"the Claude API answered {err.status_code}: {clean(err.message)[:300]}") from err
    except anthropic.APIConnectionError as err:
        raise ReviewIncomplete("the Claude API could not be reached") from err
    return read_verdict(message)


def review(title: str, body: str, files: list[dict], claude_md: str, register_md: str, client=None):
    """Verdict, usage, reviewed paths and skipped files for one pull request."""
    rules = repo_rules(claude_md)
    diff, reviewed, skipped = build_diff(files)
    if not diff:
        verdict = {"summary": "This pull request changes only binary files, so there is no text to review.",
                   "findings": []}
        return verdict, None, reviewed, skipped
    system = PROMPT.read_text() + "\n\n# Repository rules (CLAUDE.md on main)\n\n" + rules
    verdict, meta = ask_claude(system, user_message(title, body, risk_ids(register_md), diff, skipped), client)
    return verdict, meta, reviewed, skipped


# ---------------------------------------------------------------- what GitHub shows

def clean(text) -> str:
    """One line, no backticks that could break the Markdown around it."""
    return " ".join(str(text).split()).replace("`", "'")


def conclusion(findings: list[dict]) -> str:
    return "failure" if any(f["severity"] == "blocking" for f in findings) else "success"


def title(findings: list[dict]) -> str:
    blocking = sum(f["severity"] == "blocking" for f in findings)
    notes = len(findings) - blocking
    if not findings:
        return "No findings"
    return f"{blocking} blocking, {notes} {'note' if notes == 1 else 'notes'}"


def finding_line(f: dict) -> str:
    path = clean(f["path"])
    where = f"`{path}:{f['line']}`" if path and f["line"] > 0 else f"`{path}`" if path else "general"
    return f"- **{f['severity']}** {where}, {clean(f['rule'])}: {clean(f['message'])}"


def cost_line(meta: dict | None) -> str:
    if meta is None:
        return "No model call."
    tokens = f"{meta['input']:,} input and {meta['output']:,} output tokens"
    price = PRICES.get(meta["model"])
    if price and not meta["fallback"]:
        tokens += f", about ${(meta['input'] * price[0] + meta['output'] * price[1]) / 1e6:.2f}"
    served = meta["model"] + (" (fallback after a decline)" if meta["fallback"] else "")
    return f"Model {served}, effort {EFFORT}; {tokens}."


FOOTER = (f"This review comments and sets the check {CHECK_NAME}. It cannot approve; "
          "the student decides the merge.")


def comment_body(sha: str, verdict: dict, meta: dict | None, skipped: list[str]) -> str:
    findings = sorted(verdict["findings"], key=lambda f: f["severity"] != "blocking")
    lines = [MARKER, f"### {CHECK_NAME} of {sha[:7]}: {title(findings)}", "", clean(verdict["summary"])]
    if findings:
        lines += ["", *map(finding_line, findings)]
    if skipped:
        lines += ["", "Not reviewed:", *(f"- {clean(s)}" for s in skipped)]
    lines += ["", f"<sub>{cost_line(meta)} {FOOTER}</sub>"]
    return "\n".join(lines)[:TEXT_LIMIT]


def incomplete_body(sha: str, reason: str) -> str:
    return "\n".join([MARKER, f"### {CHECK_NAME} of {sha[:7]}: review not completed", "",
                      f"The check fails closed because {reason}. Re-run the workflow once the cause "
                      "is fixed; a pull request cannot merge without a completed review.",
                      "", f"<sub>{FOOTER}</sub>"])


def annotations(findings: list[dict], reviewed: set[str]) -> list[dict]:
    """Inline marks in Files changed, only for paths in the diff and real line numbers."""
    out = []
    for f in findings:
        if f["path"] in reviewed and f["line"] > 0:
            out.append({"path": f["path"], "start_line": f["line"], "end_line": f["line"],
                        "annotation_level": "failure" if f["severity"] == "blocking" else "notice",
                        "title": clean(f["rule"])[:255], "message": clean(f["message"])})
    return out[:ANNOTATION_LIMIT]


# ---------------------------------------------------------------- GitHub API and entry points

def github(method: str, path: str, token: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(API + path, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "ml-ids-stack-review"})
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def pr_files(repo: str, number: str, token: str) -> list[dict]:
    files = []
    for page in range(1, 31):                  # the API lists at most 3,000 files
        batch = github("GET", f"/repos/{repo}/pulls/{number}/files?per_page=100&page={page}", token)
        files += batch
        if len(batch) < 100:
            break
    return files


def run_in_ci() -> int:
    repo, number, sha, token = (os.environ[k] for k in ("REPO", "PR_NUMBER", "HEAD_SHA", "APP_TOKEN"))
    check = github("POST", f"/repos/{repo}/check-runs", token,
                   {"name": CHECK_NAME, "head_sha": sha, "status": "in_progress"})
    notes = []
    try:
        pr = github("GET", f"/repos/{repo}/pulls/{number}", token)
        verdict, meta, reviewed, skipped = review(
            pr["title"], pr.get("body") or "", pr_files(repo, number, token),
            (ROOT / "CLAUDE.md").read_text(), (ROOT / "RISK-REGISTER.md").read_text())
        result, heading = conclusion(verdict["findings"]), title(verdict["findings"])
        summary = comment_body(sha, verdict, meta, skipped)
        notes = annotations(verdict["findings"], reviewed)
    except ReviewIncomplete as err:
        result, heading, summary = "failure", "Review not completed", incomplete_body(sha, str(err))
    except Exception as err:    # any other failure still closes the check, then fails the job
        result, heading = "failure", "Review not completed"
        summary = incomplete_body(sha, f"the review job failed ({type(err).__name__})")
        finish(repo, check["id"], token, result, heading, summary, [])
        raise
    github("POST", f"/repos/{repo}/issues/{number}/comments", token, {"body": summary})
    finish(repo, check["id"], token, result, heading, summary, notes)
    print(f"{CHECK_NAME}: {result}, {heading}")
    return 0


def finish(repo, check_id, token, result, heading, summary, notes):
    output = {"title": heading, "summary": summary, "annotations": notes}
    path = f"/repos/{repo}/check-runs/{check_id}"
    try:
        github("PATCH", path, token, {"status": "completed", "conclusion": result, "output": output})
    except urllib.error.HTTPError as err:
        if err.code != 422 or not notes:
            raise
        output["annotations"] = []              # a line GitHub rejects must not keep the check open
        github("PATCH", path, token, {"status": "completed", "conclusion": result, "output": output})


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def run_local(base: str, body_file: str | None) -> int:
    files = files_from_git_diff(git("diff", "--no-color", "--no-ext-diff", f"{base}...HEAD"))
    subjects = git("log", "--format=- %s", f"{base}..HEAD")
    pr_title = git("rev-parse", "--abbrev-ref", "HEAD").strip()
    body = Path(body_file).read_text() if body_file else "Commits:\n" + subjects
    sha = git("rev-parse", "HEAD").strip()
    try:
        verdict, meta, _, skipped = review(pr_title, body, files, git("show", f"{base}:CLAUDE.md"),
                                           git("show", f"{base}:RISK-REGISTER.md"))
    except ReviewIncomplete as err:
        print(incomplete_body(sha, str(err)))
        return 1
    print(comment_body(sha, verdict, meta, skipped))
    return 1 if conclusion(verdict["findings"]) == "failure" else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--local", action="store_true", help="review the current branch, print the comment")
    parser.add_argument("--base", default="origin/main", help="base for --local (default origin/main)")
    parser.add_argument("--body-file", help="pull-request description for --local")
    args = parser.parse_args(argv)
    return run_local(args.base, args.body_file) if args.local else run_in_ci()


if __name__ == "__main__":
    sys.exit(main())
