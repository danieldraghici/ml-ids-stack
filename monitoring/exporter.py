#!/usr/bin/env python3
"""Prometheus metrics of the detection stack, standard library only (R-06).

One small exporter written here, instead of an OpenSearch exporter, a Logstash exporter and
a file exporter from third parties: less to pin and patch (R-04), and every metric is tested
(tests/test_monitoring.py). Each scrape of /metrics reads:

- the detector's heartbeat (out/heartbeat.json, detector/watch.py): SensorDown;
- the records the sensors wrote (lines of out/*.alerts.jsonl and *.episodes.jsonl for the
  ML-IDS, out/*.eve.json for Suricata, the same files Logstash reads) and the documents
  OpenSearch holds for each: PipelineStalled when records stay unindexed. This gap is the
  measure that would have caught the lost Suricata records of pull request 16;
- OpenSearch cluster health and whether Logstash answers: OpenSearchDown, PipelineStalled.

A source that does not answer gives its _up metric 0 and leaves its other metrics out, so an
alert never reads a stale number as a live one.

OpenSearch uses the demo certificate its image ships, whose CA key is public, so the TLS
certificate is not verified here, as in Logstash (R-02). The connection stays inside the
compose network. The exporter logs in as its own user, monitor, whose role allows cluster
health and searches of mlids-* and suricata-* only (scripts/monitor-user.sh); the password
comes from the environment.

Usage: exporter.py    env OUT_DIR, OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASSWORD,
                          LOGSTASH_URL, PORT
"""
from __future__ import annotations

import base64
import glob
import json
import os
import ssl
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUT_DIR = os.environ.get("OUT_DIR", "/out")
OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "https://opensearch:9200")
LOGSTASH_URL = os.environ.get("LOGSTASH_URL", "http://logstash:9600")
PORT = int(os.environ.get("PORT", "9108"))
TIMEOUT_S = 5

# The file patterns of pipelines/00-input.conf, per pipeline, and the indices they fill.
SOURCES = {"mlids": ["*.alerts.jsonl", "*.episodes.jsonl"], "suricata": ["*.eve.json"]}
INDICES = {"mlids": "mlids-*", "suricata": "suricata-*"}
CLUSTER_STATUS = {"green": 0, "yellow": 1, "red": 2}


def count_lines(paths: list[str]) -> int:
    total = 0
    for path in paths:
        with open(path, "rb") as fh:
            total += sum(1 for line in fh if line.strip())
    return total


def out_records(out_dir: str) -> dict[str, int]:
    """Records each sensor wrote, counted like Logstash reads them: top level of out/, non-empty lines."""
    return {name: count_lines(sorted(p for pat in pats for p in glob.glob(os.path.join(out_dir, pat))))
            for name, pats in SOURCES.items()}


def heartbeat(out_dir: str) -> dict | None:
    try:
        with open(os.path.join(out_dir, "heartbeat.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc.get("ts"), (int, float)) else None
    except (OSError, ValueError):
        return None


def collect(out_dir: str, os_get, ls_get) -> list[tuple[str, dict, float]]:
    """(metric, labels, value) for one scrape. os_get/ls_get fetch a path as JSON or raise OSError."""
    samples = []
    beat = heartbeat(out_dir)
    if beat is not None:
        samples.append(("mlids_detector_heartbeat_timestamp_seconds", {}, beat["ts"]))
        samples.append(("mlids_detector_captures_processed", {}, beat.get("processed", 0)))
        samples.append(("mlids_detector_captures_failed", {}, beat.get("failed", 0)))
    for name, n in out_records(out_dir).items():
        samples.append(("mlids_out_records", {"pipeline": name}, n))

    try:
        health = os_get("/_cluster/health")
        found = [("opensearch_up", {}, 1),
                 ("opensearch_cluster_status", {}, CLUSTER_STATUS.get(health.get("status"), 2))]
        for name, pattern in INDICES.items():
            found.append(("mlids_indexed_documents", {"pipeline": name}, os_get(f"/{pattern}/_count")["count"]))
    except (OSError, ValueError, KeyError):
        found = [("opensearch_up", {}, 0)]      # no half answer: health and counts come together or not at all
    samples += found

    try:
        ls_get("/")
        samples.append(("logstash_up", {}, 1))
    except (OSError, ValueError):
        samples.append(("logstash_up", {}, 0))
    return samples


HELP = {
    "mlids_detector_heartbeat_timestamp_seconds": "Unix time of the detector's last heartbeat (detector/watch.py).",
    "mlids_detector_captures_processed": "Captures the running detector replayed since it started.",
    "mlids_detector_captures_failed": "Captures the running detector refused or failed on since it started.",
    "mlids_out_records": "Records the sensors wrote to out/, as Logstash reads them.",
    "mlids_indexed_documents": "Documents in OpenSearch for each pipeline, error indices included.",
    "opensearch_up": "1 if OpenSearch answered the cluster health request.",
    "opensearch_cluster_status": "OpenSearch cluster status: 0 green, 1 yellow, 2 red.",
    "logstash_up": "1 if the Logstash monitoring API answered.",
}


def render(samples: list[tuple[str, dict, float]]) -> str:
    """Prometheus text exposition format, one HELP and TYPE line per metric."""
    lines, seen = [], set()
    for name, labels, value in samples:
        if name not in seen:
            seen.add(name)
            lines += [f"# HELP {name} {HELP[name]}", f"# TYPE {name} gauge"]
        label = "{" + ",".join(f'{k}="{v}"' for k, v in sorted(labels.items())) + "}" if labels else ""
        lines.append(f"{name}{label} {value}")
    return "\n".join(lines) + "\n"


def getter(base: str, user: str | None = None, password: str | None = None):
    context = ssl.create_default_context()
    if base.startswith("https://"):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE     # OpenSearch demo certificate, see the docstring
    headers = {}
    if user:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def get(path: str):
        request = urllib.request.Request(base + path, headers=headers)
        with urllib.request.urlopen(request, timeout=TIMEOUT_S, context=context) as response:
            return json.load(response)
    return get


def main() -> None:
    os_get = getter(OPENSEARCH_URL, os.environ["OPENSEARCH_USER"], os.environ["OPENSEARCH_PASSWORD"])
    ls_get = getter(LOGSTASH_URL)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_error(404)
                return
            body = render(collect(OUT_DIR, os_get, ls_get)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
