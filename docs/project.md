# Project document: ML-IDS detection stack

Risk and Damage Management, ULBS Cybersecurity master, Module 4A (instructor Dan Candea). Student: Daniel Draghici. This document grows with each phase; sections marked *to write* are filled when their phase lands.

## 1. Definition and scope

The security function this project serves is network intrusion detection for a small lab segment. Its main sensor is the ML-IDS from the student's dissertation: an XGBoost model on NetFlow-style flows with 10 s and 60 s windows, calibrated to a 0.1% false-alarm budget on held-out benign traffic. This repository does not train the model. It packages it as a sensor, runs it next to Suricata in a self-hosted stack (Logstash with ECS, OpenSearch, MISP, Prometheus, Grafana), enriches its alerts with threat intelligence, and governs every change through pull requests, CI and AI configuration the student authors.

The model is the student's own work. It is the one with the best measured results among the models compared in the dissertation, and its training data was cleaned in the student's project for the Cybersecurity and Machine Learning course. [RISK-REGISTER.md](../RISK-REGISTER.md) summarises the cleaning rules, their measured effect and the known limits; `docs/model-card.md` records them in full (F3).

In scope: the detector container on pcap replay, the stack as code, detection content with tests, MISP and Shodan enrichment, monitoring, and the AI-assisted engineering workflow.
Out of scope: model training and research (dissertation repository), live capture on the student's Windows laptop (Docker Desktop cannot capture the host Wi-Fi), production deployment.

## 2. Risks addressed

The register comes first: [RISK-REGISTER.md](../RISK-REGISTER.md), ten rows across the three registers the module asks for:

- operational risk from the AI agent in the engineering loop: R-01, R-02, R-03, R-05;
- internal risk in the detection function: R-06, R-07, R-08;
- external risk from the threat landscape: R-04, R-09, R-10.

Each row names the asset, the technique (ATT&CK or ATLAS), likelihood and impact, the control in this repository, the residual score with its justification, and the evidence a reviewer can open.

## 3. GitHub route and governance

Route 2 of the syllabus: a personal private repository with GitHub Pro from GitHub Education. Rulesets `main-checks` (pull request, required checks, no force push or deletion, no bypass) and `main-review` (one approving review) protect `main`. The student authors every commit and pull request, with the agent as co-author when it helped. The agent works with a fine-grained token limited to this repository, and a separate GitHub App reviews pull requests from F7. It comments and sets a required check but never approves, so every merge stays the student's decision. Details: `docs/setup.md`, `docs/credentials.md`.

The Git CLI push risks named in Session 1 each have a stated control:

| Push risk | Control | Row |
|---|---|---|
| Secret leakage | gitleaks pre-commit hook with MISP and Shodan rules, gitleaks on the full history in the required check `lint`, SOPS ciphertext only, the hook keeps the agent away from keys | R-02 |
| Force-push history rewrite | ruleset `main-checks` (no force push, no deletion, no bypass), ruleset `release-tags` (no moved or deleted release tag), the hook refuses `--force` and pushes to `main` | R-01, R-04 |
| Over-scoped credentials | the agent's fine-grained token for this repository only, without administration, 30 days; read-only workflow token, widened per job | R-03 |

### Pipeline: every job against its risk

Every job runs on every pull request and is a required check on `main`. The tools run as containers pinned by digest from `ci/compose.yaml` through the same Makefile targets the student runs in WSL; the only actions used are `checkout` and `setup-python`, pinned to commit SHAs.

| Job / step | What it blocks | Row |
|---|---|---|
| `lint` / pre-commit, gitleaks on the full history | A key or token in any commit of the branch; malformed YAML, JSON, TOML | R-02 |
| `lint` / ShellCheck, Hadolint | Broken shell scripts (`scripts/pki.sh`) and unsafe Dockerfile patterns | R-04 |
| `lint` / Semgrep | Known insecure code patterns (`p/ci` rules) | R-04 |
| `lint` / zizmor | Unpinned actions, credentials left by checkout, template injection, risky triggers, a Dependabot file without cooldown | R-03, R-04 |
| `test` | A broken guard hook rule, a floating image, action, revision or package, a model gate or feature contract that no longer refuses, a register row claiming evidence it lacks | R-01, R-04, R-05, R-07 |
| `scan` / Trivy | Either image, or a Python dependency, with a HIGH or CRITICAL vulnerability that has a fix | R-04 |
| `detection-gate` | Detection below 99% on an attack fixture, more benign alerts than the baseline, an alert naming the victim as source, a changed flow count, a replay without the pinned model and threshold | R-06, R-07 |
| `release` (tag `v*`) / Syft, Cosign | An image or model reaching users without an SBOM or a keyless signature bound to this repository's release workflow | R-04, R-07 |

Dependabot proposes updates to actions, images, compose files, Python pins, dev container features and pre-commit revisions, each held back 14 days by its cooldown, through the same checks. Workflows from forks do not run on this private repository, and Actions may not create or approve pull requests. The signing decision: keyless, accepting that the public Rekor log records the repository name and the release workflow path, so that no long-lived signing key exists to steal (R-04).

## 4. Architecture and components

State after F3 (later phases add Logstash, Suricata, MISP and monitoring to the same picture):

```
                       make replay PCAP=...                       make up / make down
  tests/fixtures/pcaps ───────────────────▶ detector container      compose.yaml (127.0.0.1 only)
  (lab pcaps < 5 MB)                        read-only, no network     ┌──────────────────────────────┐
                                            no capabilities           │ opensearch 2.19.6  :9200     │
  models/ (git-ignored) ──── SHA-256 ─────▶ run.py: verify model,     │ opensearch-dashboards        │
  detector/thresholds.json  checked          then live.py --replay    │   (no published port)        │
                                                 │                    │ frontdoor nginx 1.30.5 :8443 │
                                                 ▼                    │   TLS 1.2/1.3, lab CA cert   │
                                     out/<name>.alerts.jsonl          └──────────────────────────────┘
                                     out/<name>.episodes.json           ▲ admin password: SOPS/age
                                     (F5: into Logstash, ECS,           │ ciphertext in secrets/,
                                      OpenSearch)                       │ .env.secrets only while up
```

- **Stack** (`compose.yaml`): single-node OpenSearch and Dashboards, pinned by digest, host ports only on 127.0.0.1. Dashboards is reachable only through the nginx front door, which serves a 30-day certificate from an offline lab root and intermediate CA (`scripts/pki.sh`). `make up` and `make down` reach the same state every time (`docs/evidence/R-02-stack-up-down-twice.txt`).
- **Secrets**: the OpenSearch admin password lives in git only as SOPS ciphertext for the student's age key; `make secrets` writes an owner-only `.env.secrets` that `make down` deletes.
- **Detector** (`detector/`): the 16 inference files from the dissertation, unchanged, with their SHA-256 in `detector/SOURCES.tsv`; the model's SHA-256 is checked before it is unpickled; model, profile and threshold come only from `detector/thresholds.json`. Model details: `docs/model-card.md`.
- **Fixtures** (`tests/fixtures/pcaps/`): four lab captures under 5 MB (port scan, slowloris, Hulk, benign) with their sources, cut commands and the detector baseline.

## 5. AI workflow

The configuration below is in the repository and is reviewed like code (CODEOWNERS, R-05).

- **`CLAUDE.md`**: role, voice, stack conventions, banned patterns and default commands; it imports the memory index.
- **Memory** (`memory/`, indexed by `memory/MEMORY.md`): one correction per file, saved in the pull request where it happened (`docs/evidence/R-05-memory-correction-persists.png`).
- **Skill** (`.claude/skills/check/SKILL.md`): lint and test, failures grouped by file, the smallest fix proposed, never on a protected path.
- **Sub-agent and model routing** (`.claude/agents/reviewer.md`): a read-only reviewer on a cheaper model checks each branch before its pull request and marks findings blocking or note.
- **Enforced safety rules** (`.claude/settings.json`, `.claude/hooks/guard.py`, tested in `tests/test_hook.py`): deny rules and a PreToolUse hook refuse secret reads, skipped checks, force pushes, pushes to `main`, merges, approvals, tags, releases and edits to the threshold, the model, the regression tests and the hook itself.
- **Memory poisoning**: `docs/memory-poisoning.md` and the evidence `docs/evidence/R-05-poisoned-memory-*.png`.
- **Isolation**: the dev container and the agent's scoped token (`docs/credentials.md`, R-03).
- **Automated pull-request review** (F7): a GitHub App comments and sets the required check `ai-review`; it never approves.

## 6. Threat intelligence enrichment

*To write in F6*: MISP feeds and their lifecycle, the Logstash translate enrichment, the priority rule, Shodan exposure for the lab's own IP, and the evidence that enrichment changes an outcome.

## 7. Demonstration

*To write in F7*: what the recorded demonstration shows and how a reviewer reproduces it after cloning.
