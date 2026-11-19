"""Feature contract of the model (R-07, R-09).

A model that reads addresses, raw ports or the TTL learns the testbed instead of the attack:
on the student's article, the same model type detects 87.6% of the lab slowloris flows and
0% when only the TTL changes. run.py refuses such a bundle after its hash is verified. These
tests need neither the model nor its libraries: the loader is replaced by a stub.
"""
import importlib.util
import re
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DET = ROOT / "detector"

spec = importlib.util.spec_from_file_location("detector_run_contract", DET / "run.py")
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

FORBIDDEN = ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT", "MIN_TTL", "MAX_TTL",
             "src_ip", "dst_ip", "src_port", "dst_port", "sport", "dport", "ttl", "SRC_IP_HASH"]
ALLOWED = ["PROTOCOL", "IN_BYTES", "MIN_IP_PKT_LEN", "FLOW_DURATION_MILLISECONDS", "SVC_WEB",
           "SVC_WELL_KNOWN", "SRC_TO_DST_IAT_AVG", "W10_SRC_DST_PORTS", "W60_SRC_FAIL_DST_PORTS",
           "W10_DST_SRC_HOSTS", "W60_SRC_TOP_SERVICE"]


@pytest.mark.parametrize("name", FORBIDDEN)
def test_address_port_and_ttl_break_the_contract(name):
    assert run.forbidden_features([name]) == [name]


@pytest.mark.parametrize("name", ALLOWED)
def test_flow_service_and_window_features_keep_it(name):
    assert run.forbidden_features([name]) == []


def literals(path, names):
    """String literals of the named tuples in a profile source file."""
    text = path.read_text(encoding="utf-8")
    found = []
    for name in names:
        m = re.search(rf"^{name}\s*=\s*\((.*?)\n\)", text, flags=re.M | re.S) or \
            re.search(rf"^{name}\s*=\s*\((.*?)\)\n", text, flags=re.M | re.S)
        assert m, f"{name} not found in {path.name}"
        found += re.findall(r'"([A-Z0-9_]+)"', m.group(1))
    return found


def test_the_shipped_profile_keeps_the_contract():
    per_flow = literals(DET / "src" / "profiles" / "nfv2_clean.py", ["KEPT_NETFLOW"])
    stems = literals(DET / "src" / "core" / "windows.py", ["FEATURE_STEMS"])
    windows = [f"W{w}_{s}" for w in (10, 60) for s in stems]
    assert len(per_flow) > 10 and len(stems) == 11
    assert run.forbidden_features(per_flow + windows) == []


def stub_loader(monkeypatch, names):
    core = types.ModuleType("core")
    bundle = types.ModuleType("core.bundle")
    bundle.load_bundle = lambda path: {"feature_names": names}
    monkeypatch.setitem(sys.modules, "core", core)
    monkeypatch.setitem(sys.modules, "core.bundle", bundle)


def test_bundle_with_an_address_feature_is_refused(monkeypatch, capsys):
    stub_loader(monkeypatch, ["IN_BYTES", "IPV4_SRC_ADDR"])
    assert run.check_features("/models/m.joblib") is False
    assert "REFUSED" in capsys.readouterr().err


def test_bundle_without_a_feature_list_is_refused(monkeypatch):
    stub_loader(monkeypatch, [])
    assert run.check_features("/models/m.joblib") is False


def test_clean_bundle_is_accepted(monkeypatch):
    stub_loader(monkeypatch, ALLOWED)
    assert run.check_features("/models/m.joblib") is True


def test_main_stops_before_the_replay(monkeypatch):
    stub_loader(monkeypatch, ["MAX_TTL"])
    monkeypatch.setattr(run, "verify_model", lambda conf: "/models/m.joblib")
    monkeypatch.setattr(run.runpy, "run_path", lambda *a, **k: pytest.fail("replay ran"))
    assert run.main(["/pcaps/a.pcap"]) == run.EXIT_FEATURES
