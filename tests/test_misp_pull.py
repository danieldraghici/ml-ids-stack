"""The MISP feed lifecycle without a MISP server (R-10): trust weight, age-out, deduplication,
CIDR handling and the empty-pull rule. Documentation addresses only (RFC 5737)."""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("misp_pull", ROOT / "enrichment" / "misp_pull.py")
misp_pull = importlib.util.module_from_spec(spec)
spec.loader.exec_module(misp_pull)

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
WEIGHTS = {"CIRCL": 1.0, "ORGNAME": 0.8}


def attr(value, event_id=7, org="CIRCL", days_old=1, type_="ip-dst", tlp="tlp:clear"):
    return {"value": value, "type": type_, "event_id": str(event_id), "category": "Network activity",
            "org": org, "tags": [{"name": tlp}],
            "timestamp": str(int((NOW - timedelta(days=days_old)).timestamp()))}


def parse(text):
    return {ip: json.loads(v) for ip, v in yaml.safe_load(text).items()}


def test_dictionary_is_valid_yaml_sorted_by_address():
    text, stats = misp_pull.render([attr("198.51.100.9"), attr("192.0.2.1"), attr("192.0.2.10")],
                                   WEIGHTS, 0.5, NOW)
    assert list(parse(text)) == ["192.0.2.1", "192.0.2.10", "198.51.100.9"]
    assert stats["indicators"] == 3


def test_entry_carries_event_org_weight_and_tlp():
    text, _ = misp_pull.render([attr("192.0.2.1", event_id=42, org="ORGNAME", tlp="tlp:green")],
                               WEIGHTS, 0.5, NOW)
    assert parse(text)["192.0.2.1"] == {"event": 42, "category": "Network activity", "org": "ORGNAME",
                                        "weight": 0.8, "tlp": "green", "updated": "2026-11-19"}


def test_unknown_organisation_gets_the_default_weight():
    text, _ = misp_pull.render([attr("192.0.2.1", org="Someone")], WEIGHTS, 0.5, NOW)
    assert parse(text)["192.0.2.1"]["weight"] == 0.5


def test_duplicates_keep_the_most_trusted_then_the_newest():
    text, stats = misp_pull.render([attr("192.0.2.1", event_id=1, org="Someone", days_old=1),
                                    attr("192.0.2.1", event_id=2, org="CIRCL", days_old=9),
                                    attr("192.0.2.1", event_id=3, org="CIRCL", days_old=3)],
                                   WEIGHTS, 0.5, NOW)
    assert parse(text)["192.0.2.1"]["event"] == 3 and stats == {
        "attributes": 3, "aged_out": 0, "cidr_skipped": 0, "invalid": 0, "indicators": 1}


def test_old_indicators_age_out():
    text, stats = misp_pull.render([attr("192.0.2.1", days_old=31), attr("192.0.2.2", days_old=29)],
                                   WEIGHTS, 0.5, NOW)
    assert list(parse(text)) == ["192.0.2.2"] and stats["aged_out"] == 1


def test_cidr_ranges_are_skipped_and_counted_and_ports_dropped():
    text, stats = misp_pull.render([attr("192.0.2.0/24"), attr("198.51.100.7|443", type_="ip-dst|port"),
                                    attr("not-an-ip")], WEIGHTS, 0.5, NOW)
    assert list(parse(text)) == ["198.51.100.7"]
    assert stats["cidr_skipped"] == 1 and stats["invalid"] == 1


def test_empty_feed_renders_nothing():
    assert misp_pull.render([], WEIGHTS, 0.5, NOW) == ("", {"attributes": 0, "aged_out": 0,
                                                            "cidr_skipped": 0, "invalid": 0,
                                                            "indicators": 0})


def test_empty_pull_never_replaces_the_dictionary(tmp_path, monkeypatch):
    out, meta = tmp_path / "ioc_ip.yml", tmp_path / "ioc_ip.meta.json"
    out.write_text('"192.0.2.1": "{}"\n')
    monkeypatch.setattr(misp_pull, "OUT", out)
    monkeypatch.setattr(misp_pull, "META", meta)
    monkeypatch.setattr(misp_pull, "fetch", lambda days: [])
    with pytest.raises(SystemExit):
        misp_pull.main()
    assert out.read_text() == '"192.0.2.1": "{}"\n'
    assert json.loads(meta.read_text())["result"].startswith("empty pull")


def test_a_pull_replaces_the_dictionary_atomically(tmp_path, monkeypatch):
    out, meta = tmp_path / "ioc_ip.yml", tmp_path / "ioc_ip.meta.json"
    monkeypatch.setattr(misp_pull, "OUT", out)
    monkeypatch.setattr(misp_pull, "META", meta)
    recent = attr("192.0.2.5", days_old=0)
    recent["timestamp"] = str(int(datetime.now(timezone.utc).timestamp()))
    monkeypatch.setattr(misp_pull, "fetch", lambda days: [recent])
    misp_pull.main()
    assert list(parse(out.read_text())) == ["192.0.2.5"]
    assert not list(tmp_path.glob("*.tmp"))
    assert json.loads(meta.read_text())["indicators"] == 1


def test_feed_weights_file_parses():
    weights, default = misp_pull.load_weights()
    assert default == 0.5 and weights["CIRCL"] == 1.0
