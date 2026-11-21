"""Monitoring of the detection stack (R-06): the exporter, the detector's watch loop, the alert
rules and how compose.yaml runs them. promtool tests the rules' timing (make lint-ci); these
tests check what feeds them and that every rule has a case there.
"""
import importlib.util
import json
import os
import re
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


exporter = load("exporter", "monitoring/exporter.py")
watch = load("watch", "detector/watch.py")
SERVICES = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]


# ---------------------------------------------------------------- exporter

@pytest.fixture
def out(tmp_path):
    (tmp_path / "a.alerts.jsonl").write_text('{"x":1}\n{"x":2}\n\n')
    (tmp_path / "a.episodes.jsonl").write_text('{"e":1}\n')
    (tmp_path / "a.eve.json").write_text('{"s":1}\n{"s":2}\n{"s":3}\n')
    (tmp_path / "a.episodes.json").write_text('{"not":"read by Logstash"}\n')
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "b.alerts.jsonl").write_text('{"x":1}\n')
    return tmp_path


def test_records_are_counted_as_logstash_reads_them(out):
    # top level only, the two ML-IDS patterns and the EVE files, blank lines skipped
    assert exporter.out_records(str(out)) == {"mlids": 3, "suricata": 3}


def opensearch(status="yellow", counts=None):
    counts = counts or {"mlids-*": 3, "suricata-*": 3}

    def get(path):
        if path == "/_cluster/health":
            return {"status": status}
        return {"count": counts[path.strip("/").split("/")[0]]}
    return get


def down(path):
    raise OSError("connection refused")


def metrics(samples):
    return {(n, tuple(sorted(l.items()))): v for n, l, v in samples}


def test_a_healthy_stack(out):
    (out / "heartbeat.json").write_text(json.dumps({"ts": 1000.5, "processed": 2, "failed": 1}))
    m = metrics(exporter.collect(str(out), opensearch(), lambda p: {}))
    assert m[("mlids_detector_heartbeat_timestamp_seconds", ())] == 1000.5
    assert m[("mlids_detector_captures_processed", ())] == 2 and m[("mlids_detector_captures_failed", ())] == 1
    assert m[("opensearch_up", ())] == 1 and m[("opensearch_cluster_status", ())] == 1
    assert m[("mlids_indexed_documents", (("pipeline", "suricata"),))] == 3
    assert m[("logstash_up", ())] == 1


def test_a_silent_source_gives_up_0_and_no_stale_numbers(out):
    (out / "heartbeat.json").write_text("{not json")
    m = metrics(exporter.collect(str(out), down, down))
    assert m[("opensearch_up", ())] == 0 and m[("logstash_up", ())] == 0
    names = {n for n, _ in m}
    assert "mlids_detector_heartbeat_timestamp_seconds" not in names     # SensorDown sees absent()
    assert "mlids_indexed_documents" not in names and "opensearch_cluster_status" not in names
    assert "mlids_out_records" in names                                   # out/ is still read


def test_a_red_or_unknown_cluster_counts_as_red(out):
    assert metrics(exporter.collect(str(out), opensearch("red"), down))[("opensearch_cluster_status", ())] == 2
    assert metrics(exporter.collect(str(out), opensearch("purple"), down))[("opensearch_cluster_status", ())] == 2


def test_exposition_format():
    text = exporter.render([("mlids_out_records", {"pipeline": "mlids"}, 3),
                            ("mlids_out_records", {"pipeline": "suricata"}, 4), ("logstash_up", {}, 1)])
    lines = text.splitlines()
    assert lines.count("# TYPE mlids_out_records gauge") == 1
    assert 'mlids_out_records{pipeline="mlids"} 3' in lines and "logstash_up 1" in lines
    assert all(name in exporter.HELP for name in re.findall(r"^# TYPE (\S+)", text, re.M))


# ---------------------------------------------------------------- detector watch loop

def test_pending_skips_done_growing_and_other_files(tmp_path, monkeypatch):
    inbox, outd = tmp_path / "inbox", tmp_path / "out"
    inbox.mkdir(); outd.mkdir()
    for name, age in [("old.pcap", 100), ("new.pcapng", 50), ("done.pcap", 100), ("growing.pcap", 1), ("notes.txt", 100)]:
        (inbox / name).write_bytes(b"x")
        os.utime(inbox / name, (1000 - age, 1000 - age))
    (outd / "done.status.json").write_text("{}")
    assert [Path(p).name for p in watch.pending(str(inbox), str(outd), now=1000)] == ["old.pcap", "new.pcapng"]


def test_a_capture_goes_through_run_then_episodes(tmp_path):
    calls = []
    run = lambda argv: calls.append(argv) or NS(returncode=0)
    assert watch.process("/inbox/scan.pcap", "/out", run) == 0
    assert calls[0][1].endswith("/run.py") and calls[0][2] == "/inbox/scan.pcap"
    assert calls[1][1].endswith("/episodes.py") and calls[1][2:] == ["/out/scan.alerts.jsonl", "/out/scan.episodes.jsonl"]


def test_a_refused_capture_stops_before_episodes():
    calls = []
    run = lambda argv: calls.append(argv) or NS(returncode=3)     # model refused (run.py EXIT_MODEL)
    assert watch.process("/inbox/scan.pcap", "/out", run) == 3 and len(calls) == 1


def test_heartbeat_is_whole_json_with_the_time(tmp_path):
    watch.beat(str(tmp_path), {"processed": 4}, now=1700000000)
    doc = json.loads((tmp_path / "heartbeat.json").read_text())
    assert doc["ts"] == 1700000000 and doc["processed"] == 4 and doc["time"].startswith("2023-11-14T22:13:20")
    assert not list(tmp_path.glob(".*.tmp"))


# ---------------------------------------------------------------- rules and compose

def test_every_alert_has_a_promtool_case_and_a_risk():
    rules = [r for g in yaml.safe_load((ROOT / "monitoring/alerts.yml").read_text())["groups"] for r in g["rules"]]
    tested = set(re.findall(r"alertname: (\w+)", (ROOT / "monitoring/alerts.test.yml").read_text()))
    assert {"SensorDown", "PipelineStalled", "OpenSearchDown", "ExporterDown"} <= {r["alert"] for r in rules}
    for rule in rules:
        assert rule["alert"] in tested, f"{rule['alert']} has no promtool test"
        assert rule["labels"]["risk"] == "R-06"


def test_the_detector_service_keeps_the_replay_hardening():
    d = SERVICES["detector"]
    assert d["read_only"] is True and d["network_mode"] == "none" and d["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in d["security_opt"]
    assert "./models:/models:ro" in d["volumes"] and "./inbox:/inbox:ro" in d["volumes"]
    assert "ports" not in d


def test_the_exporter_reads_out_only_and_holds_no_secret_in_the_file():
    e = SERVICES["exporter"]
    assert e["read_only"] is True and e["cap_drop"] == ["ALL"] and "ports" not in e
    assert "./out:/out:ro" in e["volumes"]
    assert e["environment"]["OPENSEARCH_PASSWORD"].startswith("${")


def test_grafana_only_through_the_front_door_with_a_sops_password():
    g = SERVICES["grafana"]
    assert "ports" not in g
    assert g["environment"]["GF_SECURITY_ADMIN_PASSWORD"] == "${GRAFANA_ADMIN_PASSWORD:?run make secrets}"
    assert g["environment"]["GF_AUTH_ANONYMOUS_ENABLED"] == "false"
    assert "location /grafana/" in (ROOT / "nginx/frontdoor.conf").read_text()
