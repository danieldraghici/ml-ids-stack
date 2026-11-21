#!/usr/bin/env python3
"""Long-running detector: replay every capture that lands in the inbox, and keep a heartbeat (R-06).

make replay runs the detector once per capture. As a stack service the detector instead
watches INBOX: a new .pcap or .pcapng that nobody has written to for SETTLE_S seconds goes
through run.py (model hash and feature contract checked on every capture, R-07) and
episodes.py, exactly as make replay does, so the output lands in OUT_DIR where Logstash picks
it up. The inbox is listed every POLL_S seconds, so a capture starts within about
SETTLE_S + POLL_S seconds. A capture with a <name>.status.json in OUT_DIR is done and never
replayed again; one that fails is not retried until a restart.

The heartbeat is OUT_DIR/heartbeat.json, rewritten every BEAT_S seconds by a thread of its own,
so a long replay does not look like an outage. The exporter turns its time into
mlids_detector_heartbeat_timestamp_seconds, and SensorDown fires when it goes stale
(monitoring/alerts.yml). A beating thread alone does not prove the sensor works, so:
- a replay that runs longer than REPLAY_TIMEOUT_S is killed and counted as failed;
- the thread beats only while the main loop has made progress within STALL_S, which is
  longer than any replay may take. A main loop stuck for longer stops the heartbeat.
A stopped, crashed or stuck detector therefore reads as an outage, never as "no attacks".

Usage (inside the container): watch.py    env INBOX, OUT_DIR, POLL_S, BEAT_S, SETTLE_S, REPLAY_TIMEOUT_S
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
SETTLE_S = float(os.environ.get("SETTLE_S", "5"))   # a capture written to more recently is left alone
REPLAY_TIMEOUT_S = float(os.environ.get("REPLAY_TIMEOUT_S", "1800"))   # one step of one capture
STALL_S = 2 * REPLAY_TIMEOUT_S + 3 * POLL_S         # run.py and episodes.py, plus three listings
EXIT_TIMEOUT = 124                                  # as timeout(1)
HEARTBEAT = "heartbeat.json"
CAPTURES = (".pcap", ".pcapng")


def stem(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]


def pending(inbox: str, out_dir: str, now: float | None = None) -> list[str]:
    """Captures in the inbox without a status file in out_dir, oldest first, untouched for SETTLE_S.

    A capture deleted or renamed while the inbox is listed is skipped, never fatal."""
    now = time.time() if now is None else now
    found = []
    for name in os.listdir(inbox):
        path = os.path.join(inbox, name)
        if not name.endswith(CAPTURES) or os.path.exists(os.path.join(out_dir, f"{stem(name)}.status.json")):
            continue
        try:
            if not os.path.isfile(path):
                continue
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if now - mtime >= SETTLE_S:
            found.append((mtime, path))
    return [path for _, path in sorted(found)]


def process(pcap: str, out_dir: str, run=subprocess.run, timeout: float = REPLAY_TIMEOUT_S) -> int:
    """run.py, then episodes.py on its alerts. The return code of the first step that failed, else 0;
    EXIT_TIMEOUT when a step ran longer than timeout and was killed."""
    alerts = os.path.join(out_dir, f"{stem(pcap)}.alerts.jsonl")
    episodes = os.path.join(out_dir, f"{stem(pcap)}.episodes.jsonl")
    for argv in ([sys.executable, os.path.join(APP, "run.py"), pcap],
                 [sys.executable, os.path.join(APP, "episodes.py"), alerts, episodes]):
        try:
            rc = run(argv, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            return EXIT_TIMEOUT
        if rc != 0:
            return rc
    return 0


def alive(progress: float, now: float, stall: float = STALL_S) -> bool:
    """True while the main loop made progress recently enough to vouch for the sensor."""
    return now - progress <= stall


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
    progress = [time.time()]
    lock = threading.Lock()

    def beater():
        while True:
            with lock:
                if alive(progress[0], time.time()):
                    beat(OUT_DIR, state)
            time.sleep(BEAT_S)

    threading.Thread(target=beater, daemon=True).start()
    print(f"watch: replaying captures from {INBOX} into {OUT_DIR}", flush=True)
    failed = set()      # a capture that failed (refused model, bad file, timeout) is not retried until a restart
    while True:
        with lock:
            progress[0] = time.time()
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
                progress[0] = time.time()
        time.sleep(POLL_S)


if __name__ == "__main__":
    sys.exit(main())
