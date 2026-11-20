"""The Shodan exposure snapshot without a network call (R-10). Documentation addresses only."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("shodan_exposure", ROOT / "enrichment" / "shodan_exposure.py")
exposure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exposure)

IP, NOW = "198.51.100.20", "2026-11-20T10:00:00+00:00"
HOST = {"ip_str": IP, "ports": [443, 22, 443], "org": "Example ISP", "last_update": "2026-11-01T08:00:00.000000",
        "data": [{"port": 443, "transport": "tcp", "product": "nginx", "data": "banner noise"},
                 {"port": 22, "transport": "tcp", "_shodan": {"module": "ssh"}}]}


def test_snapshot_keeps_only_comparable_fields():
    snap = exposure.snapshot(HOST, IP, NOW)
    assert snap["ports"] == [22, 443] and snap["indexed"] is True
    assert snap["services"] == [{"port": 22, "transport": "tcp", "product": "ssh"},
                                {"port": 443, "transport": "tcp", "product": "nginx"}]
    assert "banner noise" not in json.dumps(snap)


def test_internetdb_answer_has_the_same_shape():
    record = {"ip": IP, "ports": [443, 22], "vulns": ["CVE-2023-48795"], "tags": [], "hostnames": [], "cpes": []}
    snap = exposure.snapshot(exposure.from_internetdb(record), IP, NOW)
    assert snap["ports"] == [22, 443] and snap["vulns"] == ["CVE-2023-48795"]
    assert snap["source"] == "InternetDB" and snap["services"] == []
    assert exposure.changes(exposure.snapshot(HOST, IP, NOW), snap) == {"baseline": False, "opened": [], "closed": []}


def test_not_indexed_is_a_valid_result():
    snap = exposure.snapshot(None, IP, NOW)
    assert snap["indexed"] is False and snap["ports"] == []


def test_changes_report_opened_and_closed_ports():
    old = exposure.snapshot(HOST, IP, NOW)
    new = dict(old, ports=[22, 3389])
    assert exposure.changes(old, new) == {"baseline": False, "opened": [3389], "closed": [443]}
    assert exposure.changes(None, new)["baseline"] is True
    assert exposure.changes(dict(old, ip="198.51.100.21"), new)["baseline"] is True


def test_the_address_is_never_printed(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(exposure, "OUT", tmp_path)
    monkeypatch.setenv("OWN_PUBLIC_IP", IP)
    monkeypatch.setattr(exposure, "query", lambda ip: HOST)
    exposure.main()
    exposure.main()
    out = capsys.readouterr().out
    assert IP not in out and "x.x.x.20" in out
    assert json.loads((tmp_path / "latest.json").read_text())["ip"] == IP
    assert json.loads((tmp_path / "changes.json").read_text())["baseline"] is False


@pytest.mark.parametrize("path", [".gitignore"])
def test_intelligence_and_exposure_stay_out_of_git(path):
    ignored = (ROOT / path).read_text().splitlines()
    assert "enrich/" in ignored and "exposure/" in ignored
