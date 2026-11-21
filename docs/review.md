# Automated pull-request review (F7)

Every pull request to `main` gets an automated review before the student decides on the merge. The GitHub App `ml-ids-stack-agent` sets the check `ai-review`, with the review as its summary and as annotations under Files changed. The workflow's own token posts the same review as a comment on the pull request. Ruleset `main-checks` requires that check, so no pull request merges without a completed review. The App cannot approve, so the review never replaces the student's decision (R-01).

## How a review runs

1. A pull request is opened, gets a new push, or leaves draft. A description edit alone does not start a review, since it changes no code and each review costs money; re-running the job from the Actions tab reviews the new description. `.github/workflows/review.yml` starts on `pull_request_target`, so GitHub runs the workflow file as it is on `main`.
2. The job checks out `main`, never the pull request's branch, and installs `requirements-review.txt` with `--require-hashes`.
3. `actions/create-github-app-token` mints a one-hour installation token with checks write, pull requests and contents read. The token is revoked when the job ends.
4. `ci/review.py` opens the check run `ai-review`, then reads the pull request's title, description and changed files through the API.
5. The diff goes to Claude as data, with every line numbered as in the new file. There are no tools, so the model can read but not act. The system prompt is `ci/review-prompt.md` plus the sections "Stack conventions" and "Banned patterns" of `CLAUDE.md` on `main`. The risk IDs of `RISK-REGISTER.md` on `main` come with the diff.
6. The model answers in a fixed JSON schema: a summary and a list of findings, each `blocking` or `note`, with file, line, rule and message.
7. The App completes the check run with the review as its summary, opened from Details next to `ai-review` in the pull request's checks. Findings tied to a line also appear as annotations under Files changed.
8. The workflow's own token (`github-actions[bot]`) posts the review as one comment on the pull request and updates that comment on later runs.

| Outcome | Check `ai-review` |
|---|---|
| No findings, or notes only | success |
| At least one blocking finding | failure |
| The model declined, the API failed, the answer ran out of tokens or was not valid JSON | failure, "Review not completed", with the reason in the check's summary |
| The pull request changes only binary files (screenshots, the register xlsx) | success, no model call |
| A pull request from a fork, or the workflow did not run | missing, so the pull request cannot merge |

The check fails closed: a review that did not finish never counts as a pass. A blocking finding is cleared by a new push that fixes it. A false blocking finding is cleared by re-running the job from the Actions tab, or by answering it in the code. There is no override label or comment, because the agent's token acts as the student and could use it. The last resort is the student editing ruleset `main-checks`, which GitHub records.

## Why this design (R-01, R-03, R-04, R-05)

- **No approval.** The App has pull requests read only. Approving needs pull requests write, which it does not have, so a poisoned or wrong review cannot count toward ruleset `main-review`. For the same reason it does not comment: GitHub accepts a comment on a pull request only from a token that may write to pull requests (the first runs, on 2026-11-21, were refused with HTTP 403), so the App keeps out of the conversation. The comment comes from the workflow's own token instead: the job gives it pull-request write, and the repository setting that forbids GitHub Actions to approve pull requests keeps it from approving (`docs/evidence/R-04-workflow-permissions.png`). The required check stays the App's.
- **The check is bound to the App.** `main-checks` requires `ai-review` from integration 5667084, the App. A job named `ai-review` in a branch's own workflow runs as GitHub Actions (integration 15368) and does not satisfy the rule.
- **The branch cannot reach the secrets.** `pull_request_target` runs `main`'s workflow and `main`'s `ci/review.py`, and neither runs code from the branch. The pull request's title and description reach the script through the API, never inside a `run:` line, so they cannot inject shell commands. The App key and the API key are secrets of the environment `ai-review`, which only `main` may use.
- **The diff is data.** The diff is written by the pull request's author, possibly the agent, and may carry text aimed at the reviewer (R-05). The prompt says so, asks the model to report such text as a blocking finding, and the model has no tools to act on it. The worst a poisoned diff achieves is a wrong comment, which the student still reads.
- **Supply chain.** The Anthropic SDK and its closure are pinned with hashes in `requirements-review.txt`, held back 14 days, scanned by Trivy and updated by Dependabot. The token action is GitHub's own `actions/create-github-app-token`, pinned to a commit SHA.

## Model and cost

The reviewer uses Claude Sonnet 5.5 (`claude-sonnet-5-5`) at effort `high`. It started on Claude Opus 5.5, the stronger model. On the large monitoring pull request (22), each Opus review read 40,000 to 49,000 tokens and wrote 7,000 to 12,000, about USD 0.30 to 0.43. Each push and each description edit ran one, and the student's USD 5 budget did not last. Sonnet 5.5 costs half as much per token. The trade-off is accepted knowingly: Opus found subtle defects on pull request 22 (a hung replay that kept the heartbeat green, a done marker taken after the replay), and Sonnet may miss some of them. The student still reads every pull request, and the tests stay the gate for what they cover. Requests that the model's safety classifiers decline are re-run on the model Anthropic recommends for that category (`fallbacks: "default"`). Security code in a diff is ordinary review material, but a decline must not end the review.

Price on 2026-11-21: USD 2 per million input tokens and USD 10 per million output tokens, thinking included (Opus 5.5: USD 4 and 20). Each review is bounded:

| Part | Limit in `ci/review.py` | Most it can cost |
|---|---|---|
| Input | 400,000 characters of diff (`DIFF_LIMIT`), about 100,000 tokens | USD 0.20 |
| Output | 32,000 tokens (`MAX_TOKENS`) | USD 0.32 |

Measured with Opus 5.5 on 2026-11-21: pull request 19, 3,149 input and 1,311 output tokens, about USD 0.04, in 16 s; pull request 22, 49,163 input and 11,889 output tokens, about USD 0.43. Every review ends with its own token counts and cost, so the real figures are visible on each pull request. Files left out of the diff (binary, too large, over the budget) are listed in the review, never dropped silently.

## Run it locally

`make review` reviews the current branch against `origin/main` with the same prompt and model, and prints the review instead of setting the check. The API key is decrypted from `secrets/review.enc.yaml` into that one process only. Setup is in `docs/setup.md`, section 8.
