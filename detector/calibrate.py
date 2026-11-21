#!/usr/bin/env python3
"""Site calibration of the decision threshold against an alert budget (R-08).

The threshold in thresholds.json was calibrated on CICIoT2023 benign traffic, not on this
network. This tool replays a local benign capture, plus the attack fixtures of the detection
gate, through the same live path as run.py at a ladder of thresholds, and reports for each:

- benign flows, false alerts and false-alarm rate;
- false episodes (detector/episodes.py, keyed by source) per hour of capture time;
- detection on every attack fixture, which the gate holds at 99% or more.

It recommends the lowest threshold that keeps false episodes within the budget and every
attack fixture at 99%. It never changes thresholds.json: that file is protected and changes
only in a reviewed pull request by the student (R-05, R-06). Output (OUT_DIR/calibration.json
and the table on stdout) holds counts and rates only: no address, port or name from the
capture, which stays on the student's machine.

Usage (inside the detector container, see make calibrate):
    calibrate.py --benign /capture/<file> --attacks /pcaps/a.pcap ... [--budget 1] [--thresholds ...]
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile

APP = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP)
import episodes  # noqa: E402  (detector/episodes.py, same folder)
import run  # noqa: E402       (detector/run.py: model check, feature contract, live arguments)

OUT_DIR = os.environ.get("OUT_DIR", "/out")
MIN_DETECTION = 0.99            # the detection gate's floor (tests/regression/baseline.json)
DEFAULT_BUDGET = 1.0            # false episodes per hour of benign traffic an analyst accepts
LADDER = [0.01, 0.02, 0.05, 0.1, 0.2, 0.5]


# ---------------------------------------------------------------- capture time span

def capture_span(path: str) -> tuple[float, float]:
    """First and last packet time (Unix seconds) of a pcap or pcapng file. Standard library only,
    read block by block: a capture of a few hours can be larger than the container's memory."""
    with open(path, "rb") as fh:
        magic = fh.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            fh.seek(0)
            return _pcapng_span(fh)
        for order in ("<", ">"):
            m = struct.unpack(order + "I", magic)[0]
            if m in (0xA1B2C3D4, 0xA1B23C4D):
                fh.seek(24)
                return _pcap_span(fh, order, 1e-9 if m == 0xA1B23C4D else 1e-6)
    raise ValueError(f"{path}: not a pcap or pcapng file")


def _pcap_span(fh, order: str, scale: float) -> tuple[float, float]:
    first = last = None
    while len(head := fh.read(16)) == 16:
        sec, frac, incl, _ = struct.unpack(order + "IIII", head)
        t = sec + frac * scale
        first = t if first is None else first
        last = t
        fh.seek(incl, os.SEEK_CUR)
    if first is None:
        raise ValueError("capture holds no packet")
    return first, last


def _pcapng_span(fh) -> tuple[float, float]:
    order, resolutions, first, last = "<", [], None, None
    while len(head := fh.read(12)) == 12:
        if head[:4] == b"\x0a\x0d\x0d\x0a":     # section header: byte order, then interfaces again
            order = "<" if head[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
            resolutions = []
        btype, blen = struct.unpack(order + "II", head[:8])
        if blen < 12:
            break
        if btype == 1:                          # interface description: if_tsresol, default microseconds
            body = head[8:] + fh.read(blen - 12)
            resolutions.append(_tsresol(body[8:-4], order))
        elif btype == 6:                        # enhanced packet: interface, timestamp high and low
            rest = fh.read(8)
            iface = struct.unpack(order + "I", head[8:12])[0]
            hi, lo = struct.unpack(order + "II", rest)
            scale = resolutions[iface] if iface < len(resolutions) else 1e-6
            t = ((hi << 32) | lo) * scale
            first = t if first is None else min(first, t)
            last = t if last is None else max(last, t)
            fh.seek(blen - 20, os.SEEK_CUR)
        else:
            fh.seek(blen - 12, os.SEEK_CUR)
    if first is None:
        raise ValueError("capture holds no packet")
    return first, last


def _tsresol(options: bytes, order: str) -> float:
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(order + "HH", options[pos:pos + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = options[pos + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        pos += 4 + length + (-length % 4)
    return 1e-6


# ---------------------------------------------------------------- one replay, one threshold

def replay(model: str, conf: dict, pcap: str, threshold: float, work: str) -> dict:
    """Replay pcap at threshold in a child process (the live path keeps module state); return
    flows, alerts and episodes, counted from the outputs run.py's live path writes."""
    conf = dict(conf, decision_threshold=threshold)
    argv = run.live_args(conf, model, pcap, out_dir=work)
    code = ("import runpy, sys; sys.path.insert(0, %r); import run; run.single_meter_replay(); "
            "sys.argv = %r; runpy.run_path(%r, run_name='__main__')"
            % (APP, argv, os.path.join(APP, "src", "live.py")))
    subprocess.run([sys.executable, "-c", code], check=True, stdout=subprocess.DEVNULL)
    name = os.path.splitext(os.path.basename(pcap))[0]
    with open(os.path.join(work, f"{name}.status.json"), encoding="utf-8") as fh:
        status = json.load(fh)
    alerts_path = os.path.join(work, f"{name}.alerts.jsonl")
    lines = open(alerts_path, encoding="utf-8").read().splitlines() if os.path.exists(alerts_path) else []
    grouped = []
    episodes.run(lines, grouped.append)
    for f in (alerts_path, os.path.join(work, f"{name}.status.json")):
        if os.path.exists(f):
            os.remove(f)
    return {"flows": status["n_flows"], "alerts": status["n_alerts"], "episodes": len(grouped)}


def row(threshold: float, benign: dict, hours: float, attacks: dict[str, dict], budget: float) -> dict:
    """One line of the trade-off table, rates rounded for reading."""
    fp_rate = benign["alerts"] / benign["flows"] if benign["flows"] else 0.0
    per_hour = benign["episodes"] / hours if hours > 0 else float("inf")
    detection = {name: (a["alerts"] / a["flows"] if a["flows"] else 0.0) for name, a in attacks.items()}
    return {"threshold": threshold, "benign_flows": benign["flows"], "false_alerts": benign["alerts"],
            "false_alarm_rate": round(fp_rate, 5), "false_episodes": benign["episodes"],
            "false_episodes_per_hour": round(per_hour, 3),
            "detection": {k: round(v, 4) for k, v in detection.items()},
            "within_budget": per_hour <= budget,
            "keeps_detection": all(v >= MIN_DETECTION for v in detection.values())}


def recommend(rows: list[dict]) -> float | None:
    """The lowest threshold that meets the budget without losing detection, or None."""
    good = [r["threshold"] for r in rows if r["within_budget"] and r["keeps_detection"]]
    return min(good) if good else None


def table(result: dict) -> str:
    names = list(result["rows"][0]["detection"]) if result["rows"] else []
    head = ["threshold", "false alerts / flows", "false-alarm rate", "false episodes / h"] + names
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in result["rows"]:
        lines.append("| " + " | ".join([f"{r['threshold']:g}", f"{r['false_alerts']:,} / {r['benign_flows']:,}",
                                        f"{r['false_alarm_rate']:.3%}", f"{r['false_episodes_per_hour']:.2f}"]
                                       + [f"{r['detection'][n]:.2%}" for n in names]) + " |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--benign", required=True, help="local benign capture (pcap or pcapng)")
    parser.add_argument("--attacks", nargs="+", required=True, help="attack fixtures of the detection gate")
    parser.add_argument("--budget", type=float, default=DEFAULT_BUDGET, help="false episodes per hour (default 1)")
    parser.add_argument("--thresholds", type=float, nargs="+", default=None, help="ladder (default: current, then 0.01 to 0.5)")
    args = parser.parse_args(argv)

    conf = run.load_config()
    model = run.verify_model(conf)
    if model is None:
        return run.EXIT_MODEL
    if not run.check_features(model):
        return run.EXIT_FEATURES
    current = conf["decision_threshold"]
    ladder = sorted(set(args.thresholds or [current] + [t for t in LADDER if t > current]))
    first, last = capture_span(args.benign)
    hours = (last - first) / 3600
    if hours < 1 / 60:
        print(f"calibrate: {args.benign} spans {last - first:.1f} s; a rate per hour needs at least a minute",
              file=sys.stderr)
        return 2

    rows = []
    with tempfile.TemporaryDirectory() as work:
        for t in ladder:
            benign = replay(model, conf, args.benign, t, work)
            attacks = {os.path.basename(p): replay(model, conf, p, t, work) for p in args.attacks}
            rows.append(row(t, benign, hours, attacks, args.budget))
            print(f"calibrate: threshold {t:g} done", flush=True)

    result = {"current_threshold": current, "budget_false_episodes_per_hour": args.budget,
              "capture_hours": round(hours, 2), "min_detection": MIN_DETECTION,
              "recommended_threshold": recommend(rows), "rows": rows}
    with open(os.path.join(OUT_DIR, "calibration.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"\nBenign capture: {hours:.2f} h. Budget: {args.budget:g} false episodes per hour. "
          f"Detection floor: {MIN_DETECTION:.0%}.\n\n{table(result)}\n")
    rec = result["recommended_threshold"]
    print(f"Recommended threshold: {rec:g}" if rec is not None else
          "No threshold on the ladder meets the budget and keeps detection: the budget or the model must change.")
    print("thresholds.json is not changed; the student changes it in a reviewed pull request.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
