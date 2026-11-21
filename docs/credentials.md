# Credentials for the AI agent and the reviewer (R-03)

Two credentials, two roles:

| Role | Identity | Credential | Reach |
|---|---|---|---|
| Agent session (Claude Code in the dev container): commits, pushes branches, opens pull requests | the student, with the agent as co-author in each commit (`Co-Authored-By: Claude`) | fine-grained personal access token created by the student | this repository only; contents, pull requests and workflows; no administration; 30 days |
| Automated pull-request review (CI, `docs/review.md`) | the GitHub App `ml-ids-stack-agent[bot]` | the App's private key, a secret of the environment `ai-review` that only `main` may use; each run mints a one-hour installation token | this repository only; checks write, contents and pull requests read; no administration |

## Why this split

- The student is the author of the work and must be able to defend every part of it, so commits and pull requests carry the student's name; the agent's share shows in the co-author trailer.
- The student's own `gh` login reaches every repository of the account and is admin on this one. The agent never holds it. Its token is limited to this repository and has no Administration permission, so it cannot change rulesets, settings or collaborators (R-03).
- An author cannot approve their own pull request, so nobody can give the approval that ruleset `main-review` asks for. The student merges with the pull-request-only bypass, which never skips the checks of `main-checks`; that merge is the human approval. The App reviewer reviews every pull request and puts the review in the required check `ai-review`; the workflow's own token posts the same review as a comment and, by repository setting, cannot approve. It never approves, so an automated review cannot merge anything (R-01, R-05).
- The agent's token is issued by the student's account, so GitHub cannot tell the agent from the student. The guard hook refuses every merge and approve path on the agent's side. `docs/evidence/R-01-agent-token-merge-test.txt` records the test: GitHub accepted the merge of an unapproved pull request with the agent's token, through the student's bypass, so the hook is what keeps the merge with the student (R-01).
- Releases and tags are the student's too. The hook refuses `git tag`, tag pushes and every `gh release` or API call that creates or changes a release, and ruleset `release-tags` stops anyone from moving or deleting a `v*` or `model-*` tag (R-04, R-07).
- A GitHub connector or MCP server signed in with the student's account would carry the full login, so it does not replace the scoped token.

## 1. The agent's fine-grained token (student, every 30 days)

GitHub, Settings, Developer settings, Personal access tokens, Fine-grained tokens, Generate new token:

- Token name: `ml-ids-stack-agent-session`; expiration: 30 days; resource owner: `danieldraghici`.
- Repository access: Only select repositories, `ml-ids-stack`.
- Repository permissions: Contents, Pull requests, Workflows: Read and write. Metadata: Read-only (set by GitHub). Actions, Commit statuses: Read-only. Everything else, Administration included: No access.
- Account permissions: none.

GitHub shows the token once. Store it in WSL without echoing it or leaving it in the shell history:

```bash
mkdir -p ~/.config/ml-ids-stack && chmod 700 ~/.config/ml-ids-stack
read -rsp 'Token: ' T && printf '%s' "$T" > ~/.config/ml-ids-stack/agent-token && unset T && chmod 600 ~/.config/ml-ids-stack/agent-token; echo
```

The token never goes into the repository, and the guard hook refuses any agent command that reads the file or prints a token (`gh auth token`).

## 2. The dev container

`.devcontainer/devcontainer.json`:

- mounts only `~/.config/ml-ids-stack/agent-token`, read-only, at `/run/secrets/agent-gh-token`;
- logs `gh` in with it when the container starts and lets git push through `gh`;
- takes the commit author from the host variables `STUDENT_GIT_NAME` and `STUDENT_GIT_EMAIL`.

VS Code forwards the host's git credentials and SSH agent into dev containers by default. Turn that off in the VS Code user settings before opening the container:

```json
"dev.containers.copyGitConfig": false,
"dev.containers.gitCredentialHelperConfigLocation": "none"
```

Or start the container with the dev container CLI, which forwards neither:

```bash
devcontainer up --workspace-folder . && devcontainer exec --workspace-folder . claude
```

Check from inside the container: `gh auth status` shows a fine-grained token, `gh api repos/danieldraghici/ml-ids-stack --jq .full_name` works, and the rulesets cannot be changed (`gh api -X POST repos/danieldraghici/ml-ids-stack/rulesets ...` answers 403).

## 3. The App reviewer

The App `ml-ids-stack-agent` is installed on this repository only. Its repository permissions are what a reviewer needs and nothing more: Checks write (the check run `ai-review`, which carries the review), Contents and Pull requests read (the diff), Metadata read. Pull requests write is left out on purpose: approving or commenting on a pull request needs it, so the App can do neither (R-01). Its private key and the Claude API key are secrets of the environment `ai-review`, which only `main` may use. The review workflow runs on `pull_request_target` from `main`'s own file and never checks out or runs pull-request code, so a branch cannot rewrite it to read the keys (R-04). Each run mints a one-hour token, limited again to those permissions, and revokes it when the job ends. How a review runs: `docs/review.md`.

## Rotation

- Agent token: revoke it on the Fine-grained tokens page, generate a new one with the same settings, replace the file. It expires by itself after 30 days.
- App key: delete it on the App page under Private keys, generate a new one, replace the environment secret `REVIEW_APP_KEY` (SECURITY.md).
- Claude API key: create a new key in the Claude Console, replace the environment secret `ANTHROPIC_API_KEY` and `secrets/review.enc.yaml`, then delete the old key (SECURITY.md).

## Docker stays outside the agent container

Running the stack, the replay and the CI tools needs Docker. Mounting the host Docker socket into the agent container would hand it root on the host, which undoes this isolation, so the container has no Docker. The student runs `make up`, `make gate`, `make scan` and `make lint-ci` in WSL, outside the container; in CI the same targets run on the GitHub runner.
