# Changelog

Each release is a `v*` tag cut by the student. The release workflow builds both images, attaches a Syft SBOM, and signs the images and the model by digest with Cosign keyless (R-04, R-07). Release tags cannot be moved or deleted (ruleset `release-tags`). Every change arrives through a pull request that cites the risk IDs it addresses; the numbers below point to them.

## v0.5.0

Session 7: operate, review and document. All ten register rows are Implemented.

- **Automated pull-request review** (R-01, R-03, R-04, R-05; #17, #18, #20, #21, #23):
  - **Who reviews:** the GitHub App `ml-ids-stack-agent` sets the required check `ai-review` from a Claude review of the diff. The workflow token posts the same review as a comment.
  - **No approval:** neither can approve. The workflow runs `main`'s own file on `pull_request_target` and never checks out the branch.
  - **Model:** Claude Sonnet 5.5, after Opus 5.5 reviews proved too costly for large pull requests.
- **Monitoring and alerting** (R-06; #22, #24):
  - **Detector:** the detector runs as a service that replays captures dropped into `inbox/` and writes a heartbeat.
  - **Exporter:** an exporter written here, standard library only, reads OpenSearch as a read-only user.
  - **Prometheus, Alertmanager and Grafana:** pinned by digest, Grafana behind the TLS front door.
  - **Alerts:** SensorDown, PipelineStalled, OpenSearchDown and ExporterDown, each tested by promtool in the required check `lint`.
- **Scheduled threat intelligence** (R-10; #25): `make schedule` pulls MISP every 6 hours and checks the lab's public address weekly. IocFeedStale, ExposureChanged and ExposureCheckStale fire when they fall behind or find a new open port.
- **Site calibration** (R-08; #26):
  - **What it does:** `make calibrate` measures false alarms and false episodes per hour on a local benign capture against a budget, with detection on the attack fixtures.
  - **Result on 2 hours of the student's traffic:** 23 false episodes per hour at the current threshold. No threshold meets the budget without losing detection; R-08 keeps a residual likelihood of 4.
  - **Alert:** AlertBudgetExceeded.
- **Reviewer path** (R-02; #27):
  - `make reviewer-setup` gives a reviewer new local secrets and a self-signed certificate, without the student's age key.
  - `make model-release` verifies the model with the pinned Cosign image.
  - `make ti-demo-offline` shows enrichment without MISP.
  - The project document is complete, with the demonstration script in `docs/demo.md`.
- **Fixes on the way:**
  - libxml2 CVE-2026-86144 in the front door (#20);
  - config mounts that git branch switches left stale (#25);
  - a heartbeat thread that ended on one failed write (#26).

## v0.4.2, v0.4.1, v0.4.0

Sessions 4 to 6.

- **CI** (R-04, R-06, R-07; #5, #9 to #11):
  - **Checks:** Hadolint, ShellCheck, Semgrep, zizmor, gitleaks and Trivy as pinned containers.
  - **Detection gate:** replays the lab captures and fails a pull request that loses detection.
  - **Releases:** signed releases of both images and the model.
  - **Demos:** pull requests 6 to 8 showed each gate refusing a change.
- **Alert path** (R-06, R-08, R-09; #12, #13): ML-IDS alerts and episodes and Suricata EVE events into OpenSearch through Logstash and ECS, with Sigma rules and deterministic replay.
- **Enrichment** (R-10; #14 to #16): MISP feeds pulled into a translate dictionary, GeoIP context, and the Shodan exposure check of the lab's own address. An indicator match changes an alert's priority.

## Before v0.4.0

Sessions 1 to 3 (#1 to #4): the register, rulesets, pre-commit and gitleaks, the AI configuration with its guard hook and dev container, the Compose stack with SOPS secrets and the lab PKI, and the detector container with its pcap fixtures.
