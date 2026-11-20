"""MISP enrichment changes the outcome, and only for records that touch an indicator (R-10).

Real record shapes through the real pipelines in the pinned Logstash, with a test dictionary of
documentation addresses (tests/samples/ioc_ip_test.yml):
- an ML-IDS alert from a known-bad source becomes priority high, risk score 90;
- a Suricata flow to a known-bad destination, which no sensor alerted on, becomes priority medium;
- the same records with clean addresses come out exactly as without enrichment.
"""
import json
from pathlib import Path

import pytest

from logstash_harness import get, run_pipeline

ROOT = Path(__file__).resolve().parent.parent
DICT = ROOT / "tests" / "samples" / "ioc_ip_test.yml"
BAD, WEAK = "198.51.100.66", "203.0.113.77"
ML_ALERT = json.loads((ROOT / "tests" / "samples" / "mlids_alerts.jsonl").read_text().splitlines()[0])
FLOW = json.loads((ROOT / "tests" / "samples" / "suricata_flow.jsonl").read_text().splitlines()[0])


def ml(src):
    return json.dumps(dict(ML_ALERT, src_ip=src))


def flow(dst):
    return json.dumps(dict(FLOW, dest_ip=dst))


@pytest.fixture(scope="module")
def mlids():
    lines = [ml(BAD), ml(ML_ALERT["src_ip"])]
    return run_pipeline(lines, "mlids", dictionary=DICT), run_pipeline(lines, "mlids")


@pytest.fixture(scope="module")
def suricata():
    lines = [flow(BAD), flow(FLOW["dest_ip"]), flow(WEAK)]
    return run_pipeline(lines, "suricata", dictionary=DICT), run_pipeline(lines, "suricata")


def test_ml_alert_from_a_known_bad_source_becomes_high(mlids):
    ev = mlids[0][0]
    assert get(ev, "labels.priority") == "high" and get(ev, "event.risk_score") == 90.0
    assert get(ev, "threat.indicator.matched") == "misp:4242:Network activity"
    assert "threat_match" in ev["tags"]
    (enr,) = get(ev, "threat.enrichments")
    assert enr["matched"] == {"atomic": BAD, "field": "source.ip", "type": "indicator_match_rule"}
    assert enr["indicator"]["provider"] == "CIRCL" and enr["indicator"]["marking"]["tlp"] == "CLEAR"


def test_flow_nobody_alerted_on_becomes_medium(suricata):
    ev = suricata[0][0]
    assert get(ev, "event.kind") == "event"
    assert get(ev, "labels.priority") == "medium" and get(ev, "event.risk_score") == 60.0
    assert get(ev, "threat.enrichments")[0]["matched"]["field"] == "destination.ip"


def test_a_less_trusted_feed_raises_the_score_less(suricata):
    ev = suricata[0][2]
    assert get(ev, "labels.priority") == "medium" and get(ev, "event.risk_score") == 30.0


def test_clean_records_are_untouched(mlids, suricata):
    for enriched, plain in ((mlids[0][1], mlids[1][1]), (suricata[0][1], suricata[1][1])):
        assert "threat" not in enriched and "labels" in enriched
        assert get(enriched, "labels.priority") is None and get(enriched, "event.risk_score") is None
        assert "threat_match" not in enriched.get("tags", [])
        assert enriched == plain


def test_enrichment_runs_after_every_mapping():
    filters = sorted(p.name for p in (ROOT / "pipelines").glob("*.conf") if not p.name[:2].isdigit())
    assert filters[-1] == "threat-intel.conf", filters
