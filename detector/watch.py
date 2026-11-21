#!/usr/bin/env python3
"""Long-running detector: replay every capture that lands in the inbox, and keep a heartbeat (R-06).

make replay runs the detector once per capture. As a stack service the detector instead
watches INBOX: a new .pcap or .pcapng, once its size has stopped changing, goes through run.py
(model hash and feature contract checked on every capture, R-07) and episodes.py, exactly
as make replay does, so the output lands in OUT_DIR where Logstash picks it up. A capture
with a <name>.status.json in OUT_DIR is done and never replayed again.

The heartbeat is OUT_DIR/heartbeat.json, rewritten every BEAT_S seconds by a thread of its
own, also while a long capture is being replayed. The exporter turns its time into
mlids_detector_heartbeat_timestamp_seconds; a stopped or hung detector stops beating and
SensorDown fires (monitoring/alerts.yml). Silence then reads as an outage, not as "no attacks".

Usage (inside the container): watch.py    env INBOX, OUT_DIR, POLL_S, BEAT_S, SETTLE_S
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

APP = os.path.dirname(os.path.abspath(__file__))
INBOX = os.environ.get("INBOX", "/inbox")
OUT_DIR = os.environ.get("OUT_DIR", "/out")
POLL_S = float(os.environ.get("POLL_S", "10"))      # how often the inbox is listed
BEAT_S = float(os.environ.get("BEAT_S", "10"))      # how often the heartbeat is rewritten
SETTLE_S = float(os.environ.get("SETTLE_S", "5"))   # a capture still growing is left alone
HEARTBEAT = "heartbeat.json"
CAPTURES = (".pcap", ".pcapng")


def stem(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]


def pending(inbox: str, out_dir: str, now: float | None = None) -> list[str]:
    """Captures in the inbox without a status file in out_dir, oldest first, settled for SETTLE_S."""
    now = time.time() if now is None else now
    found = []
    for name in os.listdir(inbox):
        path = os.path.join(inbox, name)
        if not name.endswith(CAPTURES) or not os.path.isfile(path):
            continue
        if os.path.exists(os.path.join(out_dir, f"{stem(name)}.status.json")):
            continue
        if now - os.path.getmtime(path) < SETTLE_S:
            continue
        found.append(path)
    return sorted(found, key=os.path.getmtime)


def process(pcap: str, out_dir: str, run=subprocess.run) -> int:
    """run.py, then episodes.py on its alerts; the return code of the first step that failed, else 0."""
    rc = run([sys.executable, os.path.join(APP, "run.py"), pcap]).returncode
    if rc != 0:
        return rc
    alerts = os.path.join(out_dir, f"{stem(pcap)}.alerts.jsonl")
    episodes = os.path.join(out_dir, f"{stem(pcap)}.episodes.jsonl")
    return run([sys.executable, os.path.join(APP, "episodes.py"), alerts, episodes]).returncode


def beat(out_dir: str, state: dict, now: float | None = None) -> None:
    """Rewrite the heartbeat atomically, so a reader never sees half a file."""
    now = time.time() if now is None else now
    doc = dict(state, ts=now, time=datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds"))
    tmp = os.path.join(out_dir, f".{HEARTBEAT}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    os.replace(tmp, os.path.join(out_dir, HEARTBEAT))


def main() -> int:
    state = {"processed": 0, "failed": 0, "current": None, "last": None}
    lock = threading.Lock()

    def beater():
        while True:
            with lock:
                beat(OUT_DIR, state)
            time.sleep(BEAT_S)

    threading.Thread(target=beater, daemon=True).start()
    print(f"watch: replaying captures from {INBOX} into {OUT_DIR}", flush=True)
    failed = set()      # a capture that failed (refused model, bad file) is not retried until a restart
    while True:
        for pcap in pending(INBOX, OUT_DIR):
            if pcap in failed:
                continue
            with lock:
                state["current"] = os.path.basename(pcap)
            rc = process(pcap, OUT_DIR)
            print(f"watch: {os.path.basename(pcap)} done, exit {rc}", flush=True)
            if rc != 0:
                failed.add(pcap)
            with lock:
                state["processed" if rc == 0 else "failed"] += 1
                state["current"], state["last"] = None, os.path.basename(pcap)
        time.sleep(POLL_S)


if __name__ == "__main__":
    sys.exit(main())
