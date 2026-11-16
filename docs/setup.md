# Setup (phase F0)

Everything runs in WSL2 Ubuntu or in the dev container, never in PowerShell. The clone lives in the WSL home (`~/ml-ids-stack`), not under `/mnt/c` or `/mnt/d`: on the Windows mounts file permissions are not enforced, so `umask 077` does not protect the decrypted `.env.secrets` (R-02), and Docker bind mounts are slow. Reviews, approvals and merges happen in the browser on github.com.

## 1. Tools in WSL2 Ubuntu

```bash
sudo apt update && sudo apt install -y make jq git python3-venv age
python3 -m venv ~/.venvs/secops && . ~/.venvs/secops/bin/activate
pip install -r requirements-dev.txt
pre-commit install
```

The GitHub CLI comes from GitHub's own apt repository (https://cli.github.com). Log in once with `gh auth login -h github.com -p https -s workflow -w`.

sops and step come from their release pages, checked against the published checksums:

```bash
SOPS_V=3.13.3
curl -LO "https://github.com/getsops/sops/releases/download/v${SOPS_V}/sops-v${SOPS_V}.linux.amd64"
curl -LO "https://github.com/getsops/sops/releases/download/v${SOPS_V}/sops-v${SOPS_V}.checksums.txt"
sha256sum --ignore-missing -c "sops-v${SOPS_V}.checksums.txt"
sudo install -m 0755 "sops-v${SOPS_V}.linux.amd64" /usr/local/bin/sops
```

For step, follow the smallstep CLI install guide for Debian/Ubuntu (v0.31.0 or newer).

## 2. GitHub (route 2: personal private repository with GitHub Pro from GitHub Education)

The student's account belongs to no organization, so the ULBS organization route (route 1) does not apply. GitHub Pro comes from the Student Developer Pack; rulesets on this private repository prove it is active.

1. Create the private repository `ml-ids-stack` and push the first commit (section 3).
2. Code security: secret scanning and push protection are not available on a personal private repository (the API answers 422, `docs/evidence/R-02-secret-scanning-unavailable.txt`). The gitleaks scan in the required check `lint` takes their place (R-02).
3. Actions, General (`docs/evidence/R-03-R-04-actions-permissions.json`):
   - workflow permissions: read repository contents only (R-03);
   - GitHub Actions may not create or approve pull requests (R-05);
   - actions must be pinned to a full-length commit SHA (R-04);
   - fork pull request workflows from outside collaborators need approval (R-04).
4. Rules: import `.github/rulesets/main-checks.json` and `.github/rulesets/main-review.json` (R-01, `docs/evidence/R-01-rulesets-active.json`). The bypass of `main-review` stays on "For pull requests only".
5. Create the agent's fine-grained token, and the GitHub App that becomes the pull-request reviewer in F7, both limited to this repository (`docs/credentials.md`, R-03).

## 3. Bootstrap order

The register comes first, as the course requires. Only the first commit goes straight to `main`, before any control exists; everything after it arrives through a pull request.

1. Student account: first commit `docs: initial risk register (R-01..R-10)` on `main`, repository creation, the settings and ruleset import in section 2.
2. Student: create the agent's fine-grained token and the GitHub App.
3. Agent session, with the scoped token: branch `chore/governance` (F1) and branch `feat/ai-config` (F2), the student as author and the agent as co-author.
4. Student: review each branch before its pull request is opened; then the pull request, the required checks, and the merge.

## 4. Ahead of F6

- Create a free Shodan account; the API key goes into `secrets/stack.enc.yaml` in F3.
- Pull the misp-docker images in advance; they are several GB.
