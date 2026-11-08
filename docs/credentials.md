# Credentials for the AI agent and the reviewer (R-03)

Two credentials, two roles:

| Role | Identity | Credential | Reach |
|---|---|---|---|
| Agent session (Claude Code in the dev container): commits, pushes branches, opens pull requests | the student, with the agent as co-author in each commit (`Co-Authored-By: Claude`) | fine-grained personal access token created by the student | this repository only; contents, pull requests and workflows; no administration; 30 days |
| Automated pull-request review (CI, from F7) | the GitHub App `ml-ids-stack-agent[bot]` | the App's private key, stored as an Actions secret; each run mints a one-hour installation token | this repository only; no administration |

## Why this split

- The student is the author of the work and must be able to defend every part of it, so commits and pull requests carry the student's name; the agent's share shows in the co-author trailer.
- The student's own `gh` login reaches every repository of the account and is admin on this one. The agent never holds it. Its token is limited to this repository and has no Administration permission, so it cannot change rulesets, settings or collaborators (R-03).
- An author cannot approve their own pull request. The approval that ruleset `main-review` asks for comes from the App reviewer, a separate identity, after the required checks pass (R-01). Until the reviewer workflow lands (F7), the student merges with the pull-request-only bypass, which never skips the checks of `main-checks`.
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

## 3. The App reviewer (F7)

The App `ml-ids-stack-agent` is installed on this repository only. In F7 its permissions shrink to what a reviewer needs (pull requests: write; contents, checks, statuses: read), its private key becomes an Actions secret, and a review workflow mints a one-hour token per run to post the review.

## Rotation

- Agent token: revoke it on the Fine-grained tokens page, generate a new one with the same settings, replace the file. It expires by itself after 30 days.
- App key: delete it on the App page under Private keys, generate a new one, replace the Actions secret (SECURITY.md).

## Open point for F3

Running the stack needs Docker. Mounting the host Docker socket into the agent container would hand it root on the host, which undoes this isolation. Decide in F3: the student runs `make up` outside the container, or the container gets a rootless Docker of its own.
