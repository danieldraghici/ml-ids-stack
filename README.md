# ml-ids-stack

Course project for Risk and Damage Management (ULBS Cybersecurity, Module 4A). It deploys the ML-IDS detector from the student's dissertation as one sensor in a self-hosted detection stack. The stack is governed through pull requests and CI, driven by AI configuration in this repository, and enriched with MISP threat intelligence.

The risk register comes first: [RISK-REGISTER.md](RISK-REGISTER.md) (course template: `RISK-REGISTER.xlsx`). Every control in this repository answers a row there, and every pull request cites the risk IDs it addresses.

## Status

| Phase | Session | Content | State |
|---|---|---|---|
| F0 | prerequisites | GitHub Education route, agent token, reviewer App, WSL tools | in progress |
| F1 | 1 | register, rulesets, CODEOWNERS, pre-commit, gitleaks, minimal CI | merged (#1) |
| F2 | 2 | CLAUDE.md, memory, skills, reviewer sub-agent, guard hook, agent dev container | merged (#2, #3) |
| F3 | 3 | Compose stack, SOPS/age, step-ca, detector container, pcap fixtures | in progress |
| F4 | 4 | full CI: hadolint, semgrep, trivy, zizmor, detection gate, signed release | |
| F5 | 5 | ECS pipeline for ML alerts, Sigma rules, Suricata | |
| F6 | 6 | MISP, PyMISP, translate enrichment, GeoIP, Shodan | |
| F7 | 7 | Prometheus, Alertmanager, Grafana, App reviewer on every pull request, project document | |

## Layout

```
RISK-REGISTER.md / .xlsx   the risk register (Markdown for review, course xlsx template)
CLAUDE.md                  agent onboarding; imports memory/MEMORY.md
memory/                    one correction per file, indexed by MEMORY.md
.claude/settings.json      deny rules and the PreToolUse hook
.claude/hooks/guard.py     blocks secret reads, force push, push to main, merge, approve,
                           and edits to the threshold, models, regression fixtures and itself
.claude/skills/            check (lint + test, smallest fix)
.claude/agents/            reviewer: read-only pre-PR check on a cheaper model
.devcontainer/             where the agent runs, with only the scoped fine-grained token
.github/                   CODEOWNERS, rulesets to import, CI, pull request template
docs/                      project document, setup, credentials, memory poisoning, evidence/
compose.yaml               OpenSearch, Dashboards and the nginx TLS front door, pinned by digest
Makefile                   secrets, pki, up, down, health, tls, model, replay, lint, test
secrets/                   SOPS ciphertext only (age)
nginx/                     front-door image and site config
detector/                  the ML-IDS sensor: 16 files from the dissertation, model gate, image
tests/fixtures/pcaps/      four lab pcaps under 5 MB, with sources and baseline
scripts/pki.sh             lab root and intermediate CA, front-door certificate
tests/                     hook, gitleaks rules, register, compose
```

## Getting started

Read [docs/setup.md](docs/setup.md). In short, from WSL2 Ubuntu:

```bash
python3 -m venv ~/.venvs/secops && . ~/.venvs/secops/bin/activate
pip install -r requirements-dev.txt
pre-commit install
make test
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
