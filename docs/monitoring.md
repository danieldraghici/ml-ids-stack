# Monitoring and alerting (F7, R-06)

A silent sensor looks the same as a quiet network. The monitoring turns the stack's own failures into alerts: a stopped detector, a stuck pipeline, a red cluster. Without it, silence reads as "no attacks" (R-06).

## Components

| Service | What it does | Reached at |
|---|---|---|
| `detector` | Replays every capture dropped into `inbox/` (`detector/watch.py`) and rewrites `out/heartbeat.json` every 10 s. It keeps the hardening of `make replay`: read-only, no network, no capabilities, an unprivileged user, and the model read-only and verified on every capture (R-07). | no port, no network |
| `exporter` | `monitoring/exporter.py`, standard library only, on the detector's pinned Python base. It reads `out/` read-only and asks OpenSearch and Logstash, inside the compose network. | Prometheus only |
| `prometheus` | Scrapes the exporter every 15 s and evaluates `monitoring/alerts.yml`. | `127.0.0.1:PROMETHEUS_PORT` (9090) |
| `alertmanager` | Keeps firing alerts. A lab has no pager, so the receiver has no integration. | `127.0.0.1:ALERTMANAGER_PORT` (9093) |
| `grafana` | The dashboard "ML-IDS stack health" and the alert rules, provisioned from `monitoring/grafana/`. Admin password from `secrets/stack.enc.yaml`. | `https://localhost:8443/grafana/`, through the front door only |

One exporter written here replaces an OpenSearch exporter, a Logstash exporter and a file exporter from third parties. That leaves fewer images to pin, scan and patch (R-04), and every metric is tested in `tests/test_monitoring.py`. Prometheus, Alertmanager and Grafana are pinned by digest. `make scan-upstream` lists their findings without failing the pull request, as it does for Logstash and Suricata.

## Metrics

| Metric | Source |
|---|---|
| `mlids_detector_heartbeat_timestamp_seconds` | `out/heartbeat.json`, absent when the file is missing or broken |
| `mlids_detector_captures_processed`, `_failed` | the same file |
| `mlids_out_records{pipeline}` | non-empty lines of `out/*.alerts.jsonl` and `*.episodes.jsonl` (`mlids`) and `out/*.eve.json` (`suricata`), the files Logstash reads |
| `mlids_indexed_documents{pipeline}` | `_count` of `mlids-*` and `suricata-*` in OpenSearch, error indices included |
| `opensearch_up`, `opensearch_cluster_status` | `_cluster/health`: 0 green, 1 yellow, 2 red |
| `logstash_up` | the Logstash monitoring API answers |

A source that does not answer gets 0 in its `_up` metric and its other metrics are left out. An alert never reads a stale number as a live one.

## Alerts (`monitoring/alerts.yml`)

| Alert | Fires when | After |
|---|---|---|
| SensorDown | the heartbeat is older than 60 s, or missing | 30 s |
| PipelineStalled (`logstash-down`) | Logstash does not answer | 1 min |
| PipelineStalled (`records-not-indexed`) | records in `out/` are not all in OpenSearch, per pipeline | 5 min |
| OpenSearchDown | OpenSearch does not answer, or the cluster is red | 1 min |
| ExporterDown | Prometheus cannot scrape the exporter; without it the other alerts are blind | 1 min |

`records-not-indexed` compares what the sensors wrote with what OpenSearch holds. That gap would have caught the Suricata records lost to a shared ruby variable before pull request 16: 510 of 9,880 records were missing on one ingest.

Every alert has a case where it fires and a case where it stays quiet in `monitoring/alerts.test.yml`. `make lint-ci`, and so the required check `lint`, runs `promtool test rules` on them, with `promtool check config` and `amtool check-config`. A changed threshold that breaks a case fails the pull request, like a changed detection rule.

## Demonstration

```bash
make up                  # the whole stack, detector included
make demo-sensor-down    # stops the detector
# about 2 minutes: SensorDown on 127.0.0.1:9090/alerts, Alertmanager, and Grafana
make demo-sensor-up      # starts it again; the alert resolves
```

Live input: drop a capture into `inbox/`. The detector replays it within 10 s, Logstash indexes the output, and the "Records written and indexed" panel shows both counts meet.
