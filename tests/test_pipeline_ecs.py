"""pipelines/mlids.conf in the real Logstash: detector records become ECS (R-06, R-08).

Positive samples are real records from the fixture replays (tests/samples/mlids_*.jsonl);
the negatives are a line that is not JSON and an alert that lost its address and port
fields, as a renamed detector field would. Both must land in mlids-error, never silently
in mlids-alert where no rule or lookup would match them.
"""
import json
from pathlib import Path

import pytest

from logstash_harness import get, run_pipeline

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "tests" / "samples"
ALERTS = (SAMPLES / "mlids_alerts.jsonl").read_text().splitlines()
EPISODE = (SAMPLES / "mlids_episode.jsonl").read_text().splitlines()
BROKEN = ["not json",
          json.dumps({"time": "2026-11-19T09:40:09+00:00", "prediction": "DoS",
                      "flow_end": "2026-08-14T20:36:07+00:00"})]


@pytest.fixture(scope="module")
def events():
    out = run_pipeline(ALERTS + EPISODE + BROKEN)
    assert len(out) == len(ALERTS) + len(EPISODE) + len(BROKEN), "Logstash lost or added events"
    return out


def test_flow_alert_maps_to_ecs(events):
    ev, raw = events[0], json.loads(ALERTS[0])
    assert get(ev, "test.index") == "mlids-alert"
    assert get(ev, "source.ip") == raw["src_ip"] and get(ev, "source.port") == raw["src_port"]
    assert get(ev, "destination.ip") == raw["dst_ip"] and get(ev, "destination.port") == raw["dst_port"]
    assert get(ev, "rule.name") == raw["prediction"] and get(ev, "rule.ruleset") == "nfv3_window"
    assert get(ev, "event.kind") == "alert" and get(ev, "event.dataset") == "mlids.alert"
    assert get(ev, "mlids.confidence") == raw["confidence"]
    assert get(ev, "mlids.window.W10_SRC_FAIL_DST_PORTS") == raw["W10_SRC_FAIL_DST_PORTS"]
    assert get(ev, "related.ip") == [raw["src_ip"], raw["dst_ip"]]
    assert get(ev, "labels.mode") == "replay"
    assert "host" not in ev and "message" not in ev and "tags" not in ev


def test_timestamp_is_the_flow_time_not_the_scoring_time(events):
    ev, raw = events[0], json.loads(ALERTS[0])
    assert ev["@timestamp"].startswith(raw["flow_end"][:19])
    assert get(ev, "event.created").startswith(raw["time"][:19])


def test_application_becomes_network_protocol(events):
    assert get(events[0], "network.protocol") == "imap"
    assert get(events[1], "network.protocol") == "tls"


def test_episode_maps_to_ecs(events):
    ev, raw = events[len(ALERTS)], json.loads(EPISODE[0])
    assert get(ev, "test.index") == "mlids-episode"
    assert get(ev, "event.dataset") == "mlids.episode"
    assert get(ev, "source.ip") == raw["src_ip"]
    assert sorted(get(ev, "rule.name")) == sorted(raw["families"])
    assert get(ev, "mlids.episode.alerts") == raw["alerts"]
    assert get(ev, "mlids.episode.families") == raw["families"]
    assert get(ev, "event.duration") == round(raw["duration_s"] * 1e9)
    assert get(ev, "destination.ip") == raw["dst_ips"][0]


def test_documents_have_stable_ids(events):
    ids = [get(e, "test.doc_id") for e in events[:len(ALERTS) + len(EPISODE)]]
    assert all(len(i) == 64 for i in ids) and len(set(ids)) == len(ids)
    again = run_pipeline(ALERTS[:1])
    assert get(again[0], "test.doc_id") == ids[0]


def test_line_that_is_not_json_goes_to_the_error_index(events):
    ev = events[-2]
    assert "_jsonparsefailure" in ev["tags"] and get(ev, "test.index") == "mlids-error"
    assert "source" not in ev and get(ev, "event.kind") is None


def test_alert_missing_its_address_fields_goes_to_the_error_index(events):
    ev = events[-1]
    assert "_mlids_missing_fields" in ev["tags"] and get(ev, "test.index") == "mlids-error"
