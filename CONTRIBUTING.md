# Contributing

The same rules bind the student and the AI agent.

## Branches and pull requests

- `main` only accepts pull requests (ruleset `main-checks`, R-01). Direct pushes, force pushes and branch deletion are refused for everyone.
- Branch names: `<type>/<topic>`, for example `feat/guard-hook`, `ci/session4`, `docs/memory-poisoning`.
- The required checks `lint` and `test` must pass before merge.
- Every pull request is authored by the student; when the agent helped, its commits carry `Co-Authored-By: Claude`. The student reviews the branch before the pull request is opened. The owner merges with the pull-request-only bypass of ruleset `main-review`, which never skips the required checks. From F7 the App reviewer (`ml-ids-stack-agent[bot]`) comments on every pull request and sets the required check `ai-review` before that merge; it never approves. The agent never merges or approves.

## Commits

Conventional commits that end with the risk IDs they address:

```
feat: guard hook blocks force push and push to main (R-01, R-05)
fix: gitleaks rule for the MISP auth key (R-02)
docs: memory-poisoning note and demo (R-05)
```

## The risk register

- `RISK-REGISTER.md` (reviewed in pull requests) and `RISK-REGISTER.xlsx` (the course template) hold the same rows. A pull request that changes a row changes both.
- A pull request that lands a control moves its row to `Implemented` in the same pull request. `Verified` means the evidence was reviewed.
- `tests/test_register.py` fails if an `Implemented` or `Verified` row points to a file that does not exist, if a score breaks the course scales, or if the xlsx and the Markdown disagree on IDs, scores or statuses.

## AI configuration

- `CLAUDE.md`, `memory/`, `.claude/` and `skills` are reviewed like code (CODEOWNERS, R-05).
- A correction to the agent becomes one file in `memory/` plus one line in `memory/MEMORY.md`, in the pull request where it happened.
- `.claude/settings.json` and `.claude/hooks/` are edited by the student by hand. The guard hook blocks the agent from changing them.
