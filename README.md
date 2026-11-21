# ml-ids-stack

Course project for Risk and Damage Management (ULBS Cybersecurity, Module 4A). It deploys the ML-IDS detector from the student's dissertation as one sensor in a self-hosted detection stack:

- **Sensors:** the ML-IDS detector, next to Suricata.
- **Alert path:** Logstash with ECS into OpenSearch.
- **Enrichment:** MISP threat intelligence and GeoIP.
- **Monitoring:** Prometheus, Alertmanager and Grafana.

The stack is governed through pull requests, CI and an automated reviewer. AI configuration in this repository drives the agent that helps build it.

The risk register comes first: [RISK-REGISTER.md](RISK-REGISTER.md) (course template: `RISK-REGISTER.xlsx`). Every control in this repository answers a row there, and every pull request cites the risk IDs it addresses. All ten rows are Implemented, each with its evidence in [docs/evidence/](docs/evidence/).

The project document is [docs/project.md](docs/project.md). It covers definition and scope, the risks, architecture, the AI workflow, enrichment with evidence, and the demonstration.

## Run it as a reviewer

Clone the repository from WSL2 Ubuntu or Linux, on x86_64, with Docker. The student's secrets are encrypted for the student's age key, so a reviewer gets their own:

```bash
make reviewer-setup        # .env, new random passwords in .env.secrets, a self-signed certificate
gh auth login              # once; the model ships as a signed release asset
make model-release         # download the model, check its Cosign signature and SHA-256
make up                    # the whole stack; the first run builds three images and takes a few minutes
```

Then:

| Where | What |
|---|---|
| `https://localhost:8443` | OpenSearch Dashboards. User `admin`, password `OPENSEARCH_INITIAL_ADMIN_PASSWORD` in `.env.secrets`. Run `make dashboards` once for the saved searches. |
| `https://localhost:8443/grafana/` | Grafana, dashboard "ML-IDS stack health". User `admin`, password `GRAFANA_ADMIN_PASSWORD`. |
| `http://127.0.0.1:9090/alerts` | Prometheus alert rules |

Three demonstrations need nothing else:

```bash
make replay PCAP=portscan.pcap && make suricata PCAP=portscan.pcap   # both sensors, into OpenSearch
make ti-demo-offline       # threat-intel enrichment with the test dictionary, no MISP needed
make demo-sensor-down      # SensorDown fires in about 2 minutes; make demo-sensor-up ends it
```

A reviewer's stack starts with IocFeedStale firing: there is no MISP feed. That is the intended signal (`docs/monitoring.md`).

The full script of the recorded demonstration is [docs/demo.md](docs/demo.md). `make down` removes the stack, its volumes and `.env.secrets`.

## Status

| Phase | Session | Content | State |
|---|---|---|---|
| F0 | prerequisites | GitHub Education route, agent token, reviewer App, WSL tools | done |
| F1 | 1 | register, rulesets, CODEOWNERS, pre-commit, gitleaks, minimal CI | merged (#1) |
| F2 | 2 | CLAUDE.md, memory, skills, reviewer sub-agent, guard hook, agent dev container | merged (#2, #3) |
| F3 | 3 | Compose stack, SOPS/age, lab PKI, detector container, pcap fixtures | merged (#4) |
| F4 | 4 | full CI: Hadolint, Semgrep, Trivy, zizmor, detection gate, signed release | merged (#5, #9 to #11; demos #6 to #8 closed), v0.4.x |
| F5 | 5 | ECS pipeline for ML alerts and episodes, Suricata, Sigma rules | merged (#12, #13) |
| F6 | 6 | MISP, PyMISP pull, translate enrichment, GeoIP, Shodan exposure | merged (#14 to #16) |
| F7 | 7 | automated pull-request review, monitoring and alerting, scheduled intel, site calibration, reviewer path, project document | merged (#17 to #27; demo #19 closed), v0.5.0 |

## Layout

```
RISK-REGISTER.md / .xlsx   the risk register (Markdown for review, course xlsx template)
CLAUDE.md                  agent onboarding; imports memory/MEMORY.md
memory/                    one correction per file, indexed by MEMORY.md
.claude/                   deny rules, the PreToolUse guard hook, the check skill, the reviewer sub-agent
.devcontainer/             where the agent runs, with only the scoped fine-grained token
.github/                   CODEOWNERS, rulesets, CI, release and review workflows, pull request template
ci/                        CI tools pinned by digest (compose.yaml), the automated reviewer (review.py)
compose.yaml               the stack: OpenSearch, Dashboards, front door, Logstash, detector service,
                           exporter, Prometheus, Alertmanager, Grafana
detector/                  the ML-IDS sensor: dissertation files, model gate, inbox watcher, calibration
pipelines/                 Logstash: ECS mapping, MISP and GeoIP enrichment
rules/                     Sigma rules and their OpenSearch queries
suricata/                  the second sensor's configuration and local rules
enrichment/                MISP pull, Shodan exposure check, threat-intel demo capture
monitoring/                exporter, alert rules with promtool tests, Prometheus, Alertmanager, Grafana
geoip/                     DB-IP Lite databases, hash-checked
secrets/                   SOPS ciphertext only (age)
scripts/                   lab PKI, the exporter's OpenSearch user, reviewer secrets
docs/                      project document, setup, monitoring, review, credentials, evidence/
tests/                     pytest suites and fixtures; the detection gate under tests/regression/
```

## Develop

Read [docs/setup.md](docs/setup.md). In short, from WSL2 Ubuntu on x86_64:

```bash
python3 -m venv ~/.venvs/secops && . ~/.venvs/secops/bin/activate
pip install --require-hashes -r requirements-dev.txt
pre-commit install
make test
```

The Python pins carry hashes for Linux x86_64, the platform of CI. On another platform, the required checks of every pull request run the same suite.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).
