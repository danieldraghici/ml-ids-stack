#!/usr/bin/env python3
"""Group the detector's flow alerts into episodes, one per attacking source (R-08).

A scan is thousands of flow alerts, and the dissertation's own tracker keys episodes by
source and predicted family, so one attack shows up as 4 to 6 lines whenever the model
calls some of its flows PortScan and others DoS. An analyst needs one line per attack:
who, since when, against what, and which families the model saw. Here an episode is keyed
by the source address only; alerts whose flow end times are at most GAP_S apart extend it,
and the families are counted inside it.

The grouping streams: add() takes one alert at a time and returns the episodes it closes,
using the newest flow end time seen so far as the clock. A replayed file and a live feed
group the same way, and nothing waits for the end of the input. Uses the standard library
only, so it runs in the detector image and on the host alike.

Usage: episodes.py <name>.alerts.jsonl [<name>.episodes.jsonl]   (default: stdout)
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

GAP_S = 120
MAX_LISTED = 20


def epoch(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(timespec="seconds")


class Episodes:
    def __init__(self, gap_s: float = GAP_S):
        self.gap_s = gap_s
        self.open: dict[str, dict] = {}
        self.clock: float | None = None

    def add(self, alert: dict) -> list[dict]:
        """Add one flow alert; return the episodes that are now closed."""
        src = alert.get("src_ip")
        t = epoch(alert.get("flow_end") or alert["time"])
        closed = []
        ep = self.open.get(src)
        if ep is not None and t - ep["last"] > self.gap_s:
            closed.append(self._close(src))
            ep = None
        if ep is None:
            ep = self.open[src] = {"src": src, "first": t, "last": t, "alerts": 0, "families": {},
                                   "dst": set(), "ports": set(), "max_conf": 0.0}
        ep["first"], ep["last"] = min(ep["first"], t), max(ep["last"], t)
        ep["alerts"] += 1
        family = alert.get("prediction") or "unknown"
        ep["families"][family] = ep["families"].get(family, 0) + 1
        if alert.get("dst_ip") is not None:
            ep["dst"].add(str(alert["dst_ip"]))
        if isinstance(alert.get("dst_port"), int):
            ep["ports"].add(alert["dst_port"])
        if isinstance(alert.get("confidence"), (int, float)):
            ep["max_conf"] = max(ep["max_conf"], float(alert["confidence"]))
        self.clock = t if self.clock is None else max(self.clock, t)
        for other in [s for s, e in self.open.items() if self.clock - e["last"] > self.gap_s]:
            closed.append(self._close(other))
        return closed

    def flush(self) -> list[dict]:
        """Close every open episode (end of input)."""
        return sorted((self._close(s) for s in list(self.open)), key=lambda e: e["first_flow_end"])

    def _close(self, src: str) -> dict:
        ep = self.open.pop(src)
        dst, ports = sorted(ep["dst"]), sorted(ep["ports"])
        return {
            "episode_id": f"{src}@{iso(ep['first'])}",
            "src_ip": src,
            "first_flow_end": iso(ep["first"]),
            "last_flow_end": iso(ep["last"]),
            "duration_s": round(ep["last"] - ep["first"], 1),
            "alerts": ep["alerts"],
            "families": dict(sorted(ep["families"].items(), key=lambda kv: -kv[1])),
            "destinations": len(dst),
            "dst_ips": dst[:MAX_LISTED],
            "dst_ports": len(ports),
            "ports": ports[:MAX_LISTED],
            "max_confidence": round(ep["max_conf"], 4),
        }


def run(lines, write) -> tuple[int, int]:
    """Stream alert lines into episodes; return (alerts read, lines skipped)."""
    eps, read, skipped = Episodes(), 0, 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
            closed = eps.add(alert)
        except (ValueError, KeyError, TypeError):
            skipped += 1
            continue
        read += 1
        for ep in closed:
            write(ep)
    for ep in eps.flush():
        write(ep)
    return read, skipped


def main(argv: list[str]) -> int:
    if len(argv) not in (1, 2):
        print("usage: episodes.py <alerts.jsonl> [<episodes.jsonl>]", file=sys.stderr)
        return 2
    out = open(argv[1], "w", encoding="utf-8") if len(argv) == 2 else sys.stdout
    count = 0

    def write(ep):
        nonlocal count
        count += 1
        out.write(json.dumps(ep) + "\n")
        out.flush()

    with open(argv[0], encoding="utf-8") as fh:
        read, skipped = run(fh, write)
    if out is not sys.stdout:
        out.close()
    print(f"episodes: {read} alerts -> {count} episodes ({skipped} lines skipped)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
