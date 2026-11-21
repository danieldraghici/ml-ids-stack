"""Site calibration of the threshold (detector/calibrate.py, R-08). The replays need the model and
the detector image (make calibrate); these tests check the capture span, the table and the choice."""
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detector"))     # calibrate imports episodes and run from its folder
_spec = importlib.util.spec_from_file_location("calibrate", ROOT / "detector" / "calibrate.py")
calibrate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(calibrate)


def pcap(times, order="<"):
    out = struct.pack(order + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for t in times:
        sec, usec = int(t), round((t - int(t)) * 1e6)
        out += struct.pack(order + "IIII", sec, usec, 4, 4) + b"abcd"
    return out


def block(btype, body, order="<"):
    body += b"\0" * (-len(body) % 4)
    n = 12 + len(body)
    return struct.pack(order + "II", btype, n) + body + struct.pack(order + "I", n)


def pcapng(times, tsresol=None):
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    options = b""
    if tsresol is not None:
        options = struct.pack("<HHB", 9, 1, tsresol) + b"\0\0\0" + struct.pack("<HH", 0, 0)
    idb = block(1, struct.pack("<HHI", 1, 0, 65535) + options)
    unit = 10.0 ** -(tsresol if tsresol is not None else 6)
    epbs = b""
    for t in times:
        ts = round(t / unit)
        epbs += block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, 4, 4) + b"abcd")
    dsb = block(0x0000000A, b"\0" * 8)          # a block type the reader skips
    return shb + idb + dsb + epbs


@pytest.mark.parametrize("make", [lambda t: pcap(t), lambda t: pcap(t, ">"), lambda t: pcapng(t),
                                  lambda t: pcapng(t, tsresol=9)], ids=["pcap", "pcap-be", "pcapng-us", "pcapng-ns"])
def test_capture_span_in_every_format(tmp_path, make):
    f = tmp_path / "c"
    f.write_bytes(make([1_700_000_000.5, 1_700_003_600.25, 1_700_007_200.75]))
    first, last = calibrate.capture_span(str(f))
    assert first == pytest.approx(1_700_000_000.5, abs=1e-3)
    assert (last - first) / 3600 == pytest.approx(2.0000694, abs=1e-5)


def test_a_fixture_capture_has_a_span():
    first, last = calibrate.capture_span(str(ROOT / "tests/fixtures/pcaps/portscan.pcap"))
    assert last > first


def test_something_else_is_refused(tmp_path):
    (tmp_path / "x").write_bytes(b"not a capture")
    with pytest.raises(ValueError):
        calibrate.capture_span(str(tmp_path / "x"))


ATTACKS_OK = {"portscan.pcap": {"flows": 4100, "alerts": 4100}, "slowloris.pcap": {"flows": 1076, "alerts": 1070}}
ATTACKS_LOST = {"portscan.pcap": {"flows": 4100, "alerts": 4100}, "slowloris.pcap": {"flows": 1076, "alerts": 900}}


def test_a_row_reports_rates_per_hour_and_the_two_conditions():
    r = calibrate.row(0.01, {"flows": 20000, "alerts": 40, "episodes": 3}, 2.0, ATTACKS_OK, budget=1.0)
    assert r["false_alarm_rate"] == 0.002 and r["false_episodes_per_hour"] == 1.5
    assert r["within_budget"] is False and r["keeps_detection"] is True
    assert r["detection"]["slowloris.pcap"] == pytest.approx(0.9944, abs=1e-4)


def test_recommend_the_lowest_threshold_that_meets_both():
    rows = [calibrate.row(0.005, {"flows": 20000, "alerts": 90, "episodes": 8}, 2.0, ATTACKS_OK, 1.0),
            calibrate.row(0.05, {"flows": 20000, "alerts": 10, "episodes": 2}, 2.0, ATTACKS_OK, 1.0),
            calibrate.row(0.2, {"flows": 20000, "alerts": 2, "episodes": 1}, 2.0, ATTACKS_OK, 1.0),
            calibrate.row(0.5, {"flows": 20000, "alerts": 0, "episodes": 0}, 2.0, ATTACKS_LOST, 1.0)]
    assert calibrate.recommend(rows) == 0.05
    assert calibrate.recommend(rows[:1]) is None          # over budget: nothing to recommend
    assert calibrate.recommend(rows[3:]) is None          # quiet, but loses an attack


def test_the_table_holds_counts_and_rates_only():
    rows = [calibrate.row(0.05, {"flows": 20000, "alerts": 10, "episodes": 2}, 2.0, ATTACKS_OK, 1.0)]
    text = calibrate.table({"rows": rows})
    assert "| 0.05 | 10 / 20,000 | 0.050% | 1.00 | 100.00% | 99.44% |" in text
    # no flow detail leaves the tool: a row holds these fields and nothing else
    assert set(rows[0]) == {"threshold", "benign_flows", "false_alerts", "false_alarm_rate", "false_episodes",
                            "false_episodes_per_hour", "detection", "within_budget", "keeps_detection"}
    assert set(rows[0]["detection"]) == set(ATTACKS_OK)     # fixture names only
