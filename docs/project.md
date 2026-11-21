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

Route 2 of the syllabus: a personal private repository with GitHub Pro from GitHub Education. Rulesets `main-checks` (pull request, required checks, no force push or deletion, no bypass) and `main-review` (one approving review) protect `main`. The student authors every commit and pull request, with the agent as co-author when it helped. The agent works with a fine-grained token limited to this repository, and a separate GitHub App reviews every pull request with Claude. It puts its review in the required check `ai-review` but cannot approve, so every merge stays the student's decision. Details: `docs/setup.md`, `docs/credentials.md`, `docs/review.md`.

The Git CLI push risks named in Session 1 each have a stated control:

| Push risk | Control | Row |
|---|---|---|
| Secret leakage | gitleaks pre-commit hook with MISP and Shodan rules, gitleaks on the full history in the required check `lint`, SOPS ciphertext only, the hook keeps the agent away from keys | R-02 |
| Force-push history rewrite | ruleset `main-checks` (no force push, no deletion, no bypass), ruleset `release-tags` (no moved or deleted release tag), the hook refuses `--force` and pushes to `main` | R-01, R-04 |
| Over-scoped credentials | the agent's fine-grained token for this repository only, without administration, 30 days; read-only workflow token, widened per job | R-03 |

### Pipeline: every job against its risk

Every job runs on every pull request and is a required check on `main`. The tools run as containers pinned by digest from `ci/compose.yaml` through the same Makefile targets the student runs in WSL; the only actions used are `checkout`, `setup-python` and, in the review, `create-github-app-token`, pinned to commit SHAs.

| Job / step | What it blocks | Row |
|---|---|---|
| `lint` / pre-commit, gitleaks on the full history | A key or token in any commit of the branch; malformed YAML, JSON, TOML | R-02 |
| `lint` / ShellCheck, Hadolint | Broken shell scripts (`scripts/pki.sh`) and unsafe Dockerfile patterns | R-04 |
| `lint` / Semgrep | Known insecure code patterns (`p/ci` rules) | R-04 |
| `lint` / promtool, amtool | An alert rule that no longer fires on its test case or fires when it should stay quiet; a broken Prometheus or Alertmanager configuration | R-06 |
| `lint` / zizmor | Unpinned actions, credentials left by checkout, template injection, risky triggers, a Dependabot file without cooldown | R-03, R-04 |
| `test` | A broken guard hook rule, a floating image, action, revision or package, a model gate or feature contract that no longer refuses, a register row claiming evidence it lacks | R-01, R-04, R-05, R-07 |
| `scan` / Trivy | Either image, or a Python dependency, with a HIGH or CRITICAL vulnerability that has a fix | R-04 |
| `detection-gate` | Detection below 99% on an attack fixture, more benign alerts than the baseline, an alert naming the victim as source, a changed flow count, a replay without the pinned model and threshold | R-06, R-07 |
| `ai-review` (GitHub App, `review.yml`) | A pull request nobody reviewed before the student's decision: a blocking finding (unpinned reference, plaintext secret, missing test, instruction aimed at the reviewer, visible defect) or a review that did not finish fails the check | R-01, R-04, R-05 |
| `release` (tag `v*`) / Syft, Cosign | An image or model reaching users without an SBOM or a keyless signature bound to this repository's release workflow | R-04, R-07 |

Dependabot proposes updates to actions, images, compose files, Python pins, dev container features and pre-commit revisions, each held back 14 days by its cooldown, through the same checks. Workflows from forks do not run on this private repository, and Actions may not create or approve pull requests. The signing decision: keyless, accepting that the public Rekor log records the repository name and the release workflow path, so that no long-lived signing key exists to steal (R-04).

## 4. Architecture and components

The sensors and the alert path as built in F5. F6 adds MISP and GeoIP enrichment inside Logstash (section 6). F7 adds the monitoring services next to them and the detector as a long-running service (the Monitoring item below and `docs/monitoring.md`):

```
                       make replay PCAP=...                       make up / make down
  tests/fixtures/pcaps ───────────────────▶ detector container      compose.yaml (127.0.0.1 only)
  (lab and synthetic                        read-only, no network     ┌───────────────────────────────┐
   pcaps < 5 MB)                            no capabilities           │ opensearch 2.19.6  :9200      │
         │          models/ ── SHA-256 ───▶ run.py: verify model      │   mlids-alert-*               │
         │          thresholds.json         and feature contract,     │   mlids-episode-*             │
         │                                  then live.py --replay     │   suricata-*                  │
         │                                       ▼                    │ opensearch-dashboards         │
         │                           out/<name>.alerts.jsonl          │   (no published port)         │
         │                           episodes.py ▼                    │ frontdoor nginx 1.30.7 :8443  │
         │                           out/<name>.episodes.jsonl ──────▶│ logstash (no published port)  │
         │  make suricata PCAP=...                                    │   mlids.conf    → ECS         │
         └──────────────▶ Suricata 8.0.7 (same hardening)            │   suricata.conf → ECS         │
                           local.rules ─▶ out/<name>.eve.json ───────▶│  (out/ mounted read-only)     │
                                                                      └───────────────────────────────┘
  rules/sigma/*.yml ─ sigma convert ─▶ rules/opensearch/*.json        ▲ admin password: SOPS/age,
  (tested on Suricata's ECS events, positive and near miss)           │ .env.secrets only while up
```

- **Stack** (`compose.yaml`): single-node OpenSearch and Dashboards, pinned by digest, host ports only on 127.0.0.1. Dashboards is reachable only through the nginx front door, which serves a 30-day certificate from an offline lab root and intermediate CA (`scripts/pki.sh`). `make up` and `make down` reach the same state every time (`docs/evidence/R-02-stack-up-down-twice.txt`).
- **Secrets**: the OpenSearch admin password lives in git only as SOPS ciphertext for the student's age key; `make secrets` writes an owner-only `.env.secrets` that `make down` deletes.
- **Detector** (`detector/`): the 16 inference files from the dissertation, unchanged, with their SHA-256 in `detector/SOURCES.tsv`; the model's SHA-256 is checked before it is unpickled; model, profile and threshold come only from `detector/thresholds.json`. Model details: `docs/model-card.md`.
- **Fixtures** (`tests/fixtures/pcaps/`): four lab captures under 5 MB (port scan, slowloris, Hulk, benign) with their sources, cut commands and the detector baseline, and four synthetic captures for techniques the lab lacks (ping sweep, SSH password guessing, DNS TXT tunnelling, and near misses for each), generated with scapy from fixed seeds so every run writes the same bytes.
- **Suricata** (`suricata/`, R-09): Suricata 8.0.7 replays the same captures with the same hardening as the detector and two local rules that count behaviour per source (ICMP sweep, many new SSH sessions). It runs only the rules in this repository; ET Open is not loaded, so payload attacks remain a gap.
- **Sigma** (`rules/sigma/`, R-09): rules on Suricata's ECS events (a long DNS TXT answer; an SSH client of a guessing tool), converted to OpenSearch queries in `rules/opensearch/` and tested on real EVE lines run through the real pipeline, each with a positive sample and a near miss. Coverage before and after: `docs/evidence/R-09-coverage.md`.
- **Episodes** (`detector/episodes.py`): the flow alerts grouped by attacking source, with a 120 s gap and the predicted families counted inside, so each fixture attack is one line for the analyst instead of the 2 to 5 that the dissertation's per-family tracker produced (R-08). It streams, so a live feed would group the same way.
- **Alert path** (`logstash/`, `pipelines/`): Logstash OSS 8.19, pinned and built with the OpenSearch output plugin, tails the detector's output folder and maps alerts and episodes to ECS (`source.ip`, `destination.ip` and `.port`, `rule.name`, `event.*`, the model's score and window features under `mlids.*`). `@timestamp` is the flow's own time; the document id is a fingerprint, so a repeated replay overwrites instead of duplicating. A record that is not JSON or lacks a field the rules read goes to `mlids-error`. The same filters run in the pipeline tests and in the detection gate. Suricata's EVE output takes the same path through `pipelines/suricata.conf` into `suricata-*`.
  - Every input line becomes exactly one document: on a clean stack, 20,079 lines in `out/` give 20,079 documents.
  - Until F6 the Suricata mapping lost some records silently. A ruby filter variable named `e` is shared by every worker thread in logstash-filter-ruby, so records took each other's document id and overwrote each other: 510 of 9,880 on one ingest. The pipeline's gate results were not affected, because the gate reads the EVE files directly.
  - `tests/test_suricata_ecs.py` now runs the mapping on four workers and forbids that variable name. `make dashboards` imports the index patterns and four saved searches, one of them every sensor's results for one source.
- **Monitoring** (`monitoring/`, `docs/monitoring.md`, R-06, F7):
  - The detector also runs as a service. It replays every capture dropped into `inbox/` with the same hardening and writes a heartbeat.
  - An exporter written here, standard library only, publishes the heartbeat, the records written against the documents indexed per pipeline, and the health of OpenSearch and Logstash.
  - Prometheus evaluates SensorDown, PipelineStalled, OpenSearchDown and ExporterDown, each tested by promtool in the required check `lint`. Alertmanager keeps the firing alerts.
  - Grafana shows them behind the front door, with a provisioned dashboard.
  - `make demo-sensor-down` stops the detector, and SensorDown fires within about 2 minutes.

## 5. AI workflow

The configuration below is in the repository and is reviewed like code (CODEOWNERS, R-05).

- **`CLAUDE.md`**: role, voice, stack conventions, banned patterns and default commands; it imports the memory index.
- **Memory** (`memory/`, indexed by `memory/MEMORY.md`): one correction per file, saved in the pull request where it happened (`docs/evidence/R-05-memory-correction-persists.png`).
- **Skill** (`.claude/skills/check/SKILL.md`): lint and test, failures grouped by file, the smallest fix proposed, never on a protected path.
- **Sub-agent and model routing** (`.claude/agents/reviewer.md`): a read-only reviewer on a cheaper model checks each branch before its pull request and marks findings blocking or note.
- **Enforced safety rules** (`.claude/settings.json`, `.claude/hooks/guard.py`, tested in `tests/test_hook.py`): deny rules and a PreToolUse hook refuse secret reads, skipped checks, force pushes, pushes to `main`, merges, approvals, tags, releases and edits to the threshold, the model, the regression tests and the hook itself.
- **Memory poisoning**: `docs/memory-poisoning.md` and the evidence `docs/evidence/R-05-poisoned-memory-*.png`.
- **Isolation**: the dev container and the agent's scoped token (`docs/credentials.md`, R-03).
- **Automated pull-request review** (`docs/review.md`): on every pull request the GitHub App `ml-ids-stack-agent` sends the diff to Claude Sonnet 5.5 as data, with no tools, then sets the required check `ai-review`, with the review as its summary and line annotations. The App can neither comment nor approve; the workflow's own token posts the same review as a comment, and a repository setting forbids it to approve. The CI review started on Opus 5.5 and moved to Sonnet 5.5 for cost, a trade-off stated in `docs/review.md`.

## 6. Threat intelligence enrichment

R-10: a lab host that talks to known-bad infrastructure scores low when the behaviour looks normal, such as a slow HTTPS beacon. Setup, feeds and rules of engagement are in `docs/misp-setup.md`.

- **MISP** (`misp/`, `scripts/misp-setup.sh`): misp-docker at a pinned commit, cloned next to this repository, every image pinned by digest, listening on 127.0.0.1 only. The client trusts exactly MISP's localhost certificate, and its API key is read-only and kept in `secrets/intel.enc.yaml` (SOPS, R-02).
- **Feeds**:

  | Feed | Publisher in MISP | Weight | Role |
  |---|---|---|---|
  | CIRCL OSINT Feed | CIRCL | 1.0 | curated reports. Its IP indicators date from 2014 to 2020, so all of them age out |
  | Feodo IP Blocklist (abuse.ch) | ADMIN | 0.8 | active botnet command-and-control servers |
  | blocklist.de | ADMIN | 0.8 | addresses reported for scans and brute force in the last 48 hours |

  Both open lists are marked `tlp:clear` on their MISP events. Eleven warninglists are enabled: private, special-use and multicast ranges, public DNS resolvers and the large cloud and CDN providers.
- **Lifecycle** (`enrichment/misp_pull.py`, tested in `tests/test_misp_pull.py`):
  - only attributes flagged `to_ids`, minus warninglist hits;
  - trust weighted by the publishing organisation (`enrichment/feeds.yml`);
  - a 30-day age-out, applied and counted locally;
  - one entry per address, IPv4 and IPv6;
  - CIDR ranges skipped and counted, since the translate filter matches exact values;
  - an empty pull never replaces the dictionary, which is written atomically.

  First pull, 2026-11-20: 60,445 attributes, 36,087 aged out and 12 CIDR ranges skipped, leaving 24,346 indicators. The dictionary (`enrich/`) and its counts are git-ignored live intelligence.
- **Enrichment** (`pipelines/threat-intel.conf`, tested in `tests/test_enrichment.py` in the pinned Logstash): every ML-IDS and Suricata record looks up `source.ip` and `destination.ip`. A match writes `threat.enrichments` (indicator, MISP event, provider, confidence, TLP, matched field) and `threat.indicator.matched`, and adds the tag `threat_match`. `threat.enrichments` is mapped as an object rather than nested as ECS suggests: each record carries one enrichment, and Discover can filter only on non-nested fields.

  | Record | Match | Result |
  |---|---|---|
  | sensor alert (ML-IDS alert or episode, Suricata alert) | yes | `labels.priority: high`, `event.risk_score` 90 × weight |
  | any other record (a flow nothing alerted on) | yes | `labels.priority: medium`, `event.risk_score` 60 × weight |
  | any record | no | unchanged |

- **GeoIP** (`geoip/`, the first filters of `pipelines/threat-intel.conf`): every public `source.ip` and `destination.ip` gets its country (`*.geo.country_iso_code`, `country_name`, `continent_name`) and autonomous system (`*.as.number`, `*.as.organization.name`).
  - The data comes from the DB-IP Lite databases of 2026-11 (CC BY 4.0), committed compressed with their SHA-256 and unpacked by `make geoip` only after the hashes match.
  - It is context, not a verdict: GeoIP never sets a priority or a tag. Private and documentation addresses stay untouched.
  - Tested in `tests/test_enrichment.py`: `8.8.8.8` resolves to US and AS15169, and a lab address gets nothing. In the demonstration the indicator resolves to US, AS14061 DigitalOcean.
- **Outcome** (`make ti-demo DEMO_IOC=162.243.103.246`, a Feodo command-and-control address marked TLP:CLEAR): the lab port scan is replayed with its attacker rewritten to the indicator, next to a slow HTTPS beacon to it (`enrichment/make_demo.py`, 15 sessions a minute apart).

  | Records touching the indicator | Count | Before | After |
  |---|---|---|---|
  | ML-IDS flow alerts of the scan | 4,100 | alert, no priority | high, risk 72 |
  | ML-IDS episode of the scan | 1 | alert, no priority | high, risk 72 |
  | Suricata flows of the scan | 4,125 | flow, no priority | medium, risk 48 |
  | Suricata flows of the beacon | 15 | flow, no priority; **no sensor alerted** | medium, risk 48 |

  The same scan from its original address, 192.168.20.11, is in no feed. Its 11,773 records keep no priority and no tag. The beacon is the outcome that changes: the ML-IDS scores all 15 flows benign and no Suricata rule fires, yet the analyst sees them as medium, linked to a MISP event.
- **Exposure** (`enrichment/shodan_exposure.py`, tested in `tests/test_shodan_exposure.py`): one lookup per run of the lab's own public address only. The address is printed masked and never committed. A free Shodan account has no host-API credits, so the lookup falls back to InternetDB, Shodan's free per-address service. First snapshot, 2026-11-20: the address is not indexed, and no open port is seen from the internet. `exposure/changes.json` records ports opened or closed since the previous run; ExposureChanged fires on a newly open port.
- **Freshness** (F7, `docs/monitoring.md`):
  - `make schedule` puts the MISP pull every 6 hours and the exposure check every Monday into the student's crontab in WSL.
  - The exporter reads when the dictionary in use was written and what the last check found. An empty pull keeps the old dictionary and its old date.
  - IocFeedStale fires when the dictionary is over 12 hours old or missing, ExposureChanged on a newly open port, and ExposureCheckStale when the weekly check has not run for 8 days.
  - A clone without MISP therefore shows IocFeedStale from the start: no feed is a stale feed.
- **Not covered yet**:
  - domain and URL indicators;
  - CIDR indicators;

Evidence: `docs/evidence/R-10-misp-matched.png`, `docs/evidence/R-10-beacon-medium.png`, `docs/evidence/R-10-clean-untouched.png`.

## 7. Demonstration

The recorded demonstration follows `docs/demo.md`, about 6 minutes, each step tied to a risk:

| Step | Shows | Row | Evidence |
|---|---|---|---|
| Repository and register | ten rows, all Implemented; rulesets with five required checks, `ai-review` among them | R-01 | `RISK-REGISTER.md`, `docs/evidence/R-01-rulesets-active.json` |
| Two sensors | the ML-IDS and Suricata on the same scan, in ECS, written and indexed alike | R-06, R-09 | `docs/evidence/R-06-mlids-alerts-in-dashboards.png` |
| Threat intelligence | the same scan from a MISP indicator raised to high; a beacon no sensor caught raised to medium | R-10 | `docs/evidence/R-10-*.png` |
| Stopped sensor | `make demo-sensor-down`: SensorDown fires in Grafana within about 2 minutes | R-06 | `docs/evidence/R-06-sensor-down-alert.png` |
| Automated review | a careless pull request gets 5 blocking findings before any approval; the App cannot approve | R-01, R-05 | `docs/evidence/R-01-ai-review-*.png` |
| The honest limit | 23 false episodes per hour on local benign traffic, against a budget of 1 | R-08 | `docs/evidence/R-08-fp-budget.md`, `R-08-grafana.png` |

**Reproduce after cloning** (README, "Run it as a reviewer"):

1. `make reviewer-setup` gives the reviewer their own secrets and a self-signed certificate. The student's SOPS files stay encrypted for the student.
2. `make model-release` verifies the model's Cosign signature with the pinned tools image and its SHA-256 before use.
3. `make up`, then the demonstration commands.
4. `make ti-demo-offline` runs the enrichment step with the test dictionary when there is no MISP.

Three parts cannot be reproduced from a clone, by design:

- **The MISP feeds and the Shodan check:** the keys are the student's.
- **The local benign capture:** it holds the student's personal traffic. Its measured numbers are in the evidence.
- **The automated review:** it runs only on pull requests to this repository. Pull requests 17 to 27 show it.
