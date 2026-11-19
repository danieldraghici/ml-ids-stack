# Setup (phase F0)

Everything runs in WSL2 Ubuntu or in the dev container, never in PowerShell. The clone lives in the WSL home (`~/ml-ids-stack`), not under `/mnt/c` or `/mnt/d`: on the Windows mounts file permissions are not enforced, so `umask 077` does not protect the decrypted `.env.secrets` (R-02), and Docker bind mounts are slow. Reviews, approvals and merges happen in the browser on github.com.

## 1. Tools in WSL2 Ubuntu

```bash
sudo apt update && sudo apt install -y make jq git python3-venv age
python3 -m venv ~/.venvs/secops && . ~/.venvs/secops/bin/activate
pip install --require-hashes -r requirements-dev.txt
pre-commit install
```

Docker Desktop with WSL integration for this distribution runs the stack, the detector and the CI tools (`ci/compose.yaml`).

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

cosign verifies signed releases on this machine (`make model-release`, section 6). Take the version pinned in `ci/compose.yaml` and check the binary against the release's checksum file the same way:

```bash
COSIGN_V=3.1.4
curl -LO "https://github.com/sigstore/cosign/releases/download/v${COSIGN_V}/cosign-linux-amd64"
curl -LO "https://github.com/sigstore/cosign/releases/download/v${COSIGN_V}/cosign_checksums.txt"
sha256sum --ignore-missing -c cosign_checksums.txt
sudo install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign
```

## 2. GitHub (route 2: personal private repository with GitHub Pro from GitHub Education)

The student's account belongs to no organization, so the ULBS organization route (route 1) does not apply. GitHub Pro comes from the Student Developer Pack; rulesets on this private repository prove it is active.

1. Create the private repository `ml-ids-stack` and push the first commit (section 3).
2. Code security: secret scanning and push protection are not available on a personal private repository (the API answers 422, `docs/evidence/R-02-secret-scanning-unavailable.txt`). The gitleaks scan in the required check `lint` takes their place (R-02).
3. Actions, General (`docs/evidence/R-03-R-04-actions-permissions.json`):
   - workflow permissions: read repository contents only (R-03);
   - GitHub Actions may not create or approve pull requests (R-05);
   - actions must be pinned to a full-length commit SHA (R-04);
   - fork pull request workflows from outside collaborators need approval (R-04).
4. Rules: import `.github/rulesets/main-checks.json`, `.github/rulesets/main-review.json` and `.github/rulesets/release-tags.json` (R-01, R-04, `docs/evidence/R-01-rulesets-active.json`). The bypass of `main-review` stays on "For pull requests only". A required check appears in the ruleset only after it has run once on a pull request.
5. Create the agent's fine-grained token, and the GitHub App that becomes the pull-request reviewer in F7, both limited to this repository (`docs/credentials.md`, R-03).

## 3. Bootstrap order

The register comes first, as the course requires. Only the first commit goes straight to `main`, before any control exists; everything after it arrives through a pull request.

1. Student account: first commit `docs: initial risk register (R-01..R-10)` on `main`, repository creation, the settings and ruleset import in section 2.
2. Student: create the agent's fine-grained token and the GitHub App.
3. Agent session, with the scoped token: branch `chore/governance` (F1) and branch `feat/ai-config` (F2), the student as author and the agent as co-author.
4. Student: review each branch before its pull request is opened; then the pull request, the required checks, and the merge.

## 4. Run the stack (F3)

Once per machine: create your age key (`age-keygen -o ~/.config/sops/age/keys.txt`, mode 600, `SOPS_AGE_KEY_FILE` pointing at it). Its public key is the recipient in `.sops.yaml`.

Once per repository clone:

```bash
cp .env.example .env
```

Encrypt the OpenSearch admin password (at least 8 characters with upper and lower case, a digit and a symbol; avoid `$`, `#`, quotes, spaces and colons). It is read without echo and never written in plaintext:

```bash
printf 'Admin password: ' && read -rs OS_PW && echo && printf 'OPENSEARCH_INITIAL_ADMIN_PASSWORD: %s\n' "$OS_PW" \
  | sops --encrypt --filename-override secrets/stack.enc.yaml --input-type yaml --output-type yaml /dev/stdin > secrets/stack.enc.yaml && unset OS_PW
```

Issue the front-door certificate (once, then every 30 days):

- `make pki`: on the first run creates the lab root CA and an intermediate CA with the step CLI, their keys encrypted with passwords you choose (asked twice) and kept outside the repository in `~/.config/ml-ids-stack/pki`; every run issues the `frontdoor.lab` certificate (also valid for `localhost` and `127.0.0.1`) into `certs/` (git-ignored) and verifies the chain.

Then:

- `make up`: decrypts into `.env.secrets` (mode 600), builds the nginx front door, starts OpenSearch, Dashboards and the front door, waits until all are healthy and prints the cluster health;
- `make health`: the cluster health again;
- `make tls`: the front door's certificate chain, verified against the lab root only;
- `make down`: removes the containers, the network and the data volume, and deletes `.env.secrets`.

`make down && make up` reaches the same green cluster every time (`docs/evidence/R-02-stack-up-down-twice.txt`). Dashboards publishes no port of its own: it answers only through the front door, `https://localhost:8443`, so the admin password never crosses plain HTTP (`docs/evidence/R-02-frontdoor-tls-chain.txt`). Nothing listens beyond localhost. To see the padlock instead of a warning, add `certs/root_ca.crt` to your browser's or your user's trusted roots; remove it at the end of the course.

## 5. Replay a capture through the detector (F3)

- `make model`: copies the model bundle from the dissertation workspace (`MODEL_SRC`) into `models/` (git-ignored) and checks its SHA-256 against `detector/thresholds.json`.
- `make replay PCAP=portscan.pcap`: builds the detector image and replays one fixture from `tests/fixtures/pcaps/` in a read-only container without network or capabilities. The flow alerts, the run status and the episodes grouped from the alerts (`detector/episodes.py`) land in `out/`.

The detector refuses a model whose SHA-256 differs from `detector/thresholds.json` before loading it (`docs/evidence/R-07-tampered-model-refused.txt`), and then a model whose feature list holds an address, a raw port or the TTL (`tests/test_model_verify.py`). Fixtures and their baseline: `tests/fixtures/pcaps/README.md`.

### The alerts in OpenSearch (F5)

With the stack up, Logstash reads `out/` and indexes every replay as it is written:

```bash
make up              # now also builds and starts Logstash; the first build takes a few minutes
make gate            # replays the four fixtures; the alerts and episodes reach OpenSearch
make dashboards      # index patterns and saved searches, into the global tenant
```

In Dashboards (`https://localhost:8443`), Discover, open the saved search "ML-IDS episodes, one per attacking source" or "ML-IDS flow alerts" and set the time range to August 2026, when the lab captures were recorded (`@timestamp` is the flow's own time).

## 6. Pipeline and releases (F4)

The CI jobs run the same Makefile targets, so a red check can be reproduced in WSL:

- `make lint-ci`: ShellCheck, Hadolint, Semgrep and zizmor, as containers pinned by digest in `ci/compose.yaml`;
- `make scan`: builds both images and runs Trivy on them and on the Python dependencies; a HIGH or CRITICAL finding with a fix fails;
- `make gate`: replays the four fixtures and compares the result with `tests/regression/baseline.json` (R-06);
- `make sbom`: the SPDX SBOM of each image, with Syft.

The model reaches CI as an asset of the release `model-v1`, uploaded once by the student (`gh release create model-v1 models/<model> --latest=false`). A release is cut by the student only: push a tag `vX.Y.Z` on `main`, and `.github/workflows/release.yml` scans and gates the images again, pushes them to GHCR, signs the image digests and the model with Cosign keyless and publishes the release with generated notes, the SBOMs, the model and its signature bundle. `make model-release` downloads the model of the latest release and keeps it only if `cosign verify-blob` proves it was signed by this repository's release workflow.

## 7. Ahead of F6

- Create a free Shodan account; the API key goes into `secrets/stack.enc.yaml` in F6.
- Pull the misp-docker images in advance; they are several GB.
