#!/usr/bin/env python3
"""What the internet already sees on the lab's own public address, from Shodan (R-10).

Rules of engagement: Shodan is asked about one address only, OWN_PUBLIC_IP, which the student
owns; one host() call per run (the free tier rate-limits loops). Asking is passive: Shodan's own
scans are read, nothing is sent to the address.

The address is personal data: it is written only to exposure/ (git-ignored) and never printed;
the console shows the open ports and a masked address. Each run writes
  exposure/<date>.json     the snapshot: ports, services, organisation, last Shodan update
  exposure/latest.json     the same, the baseline for the next run
  exposure/changes.json    ports opened or closed since the previous snapshot; F7's
                           ExposureChanged alert reads it
"No information available" from Shodan is a valid result: nothing on the address is indexed.

Usage: make exposure   (reads SHODAN_KEY and OWN_PUBLIC_IP from .env.secrets)
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "exposure"


def mask(ip):
    """203.0.113.7 -> x.x.x.7: enough to tell runs apart, not enough to identify the address."""
    return "x.x.x." + str(ip).rsplit(".", 1)[-1] if ip else "unknown"


def snapshot(host, ip, now):
    """The fields that show whether the exposure changed; banners and raw data are left out."""
    if host is None:
        return {"ip": ip, "indexed": False, "ports": [], "services": [], "org": None,
                "last_update": None, "checked_at": now}
    services = sorted({(d.get("port"), d.get("transport", "tcp"), d.get("product") or d.get("_shodan", {}).get("module"))
                       for d in host.get("data", []) if d.get("port") is not None}, key=lambda s: (s[0], s[1]))
    return {"ip": host.get("ip_str", ip), "indexed": True, "ports": sorted(set(host.get("ports", []))),
            "services": [{"port": p, "transport": t, "product": prod} for p, t, prod in services],
            "org": host.get("org"), "last_update": host.get("last_update"), "checked_at": now}


def changes(previous, current):
    """Ports opened and closed between two snapshots of the same address."""
    if previous is None or previous.get("ip") != current.get("ip"):
        return {"baseline": True, "opened": [], "closed": []}
    old, new = set(previous.get("ports", [])), set(current.get("ports", []))
    return {"baseline": False, "opened": sorted(new - old), "closed": sorted(old - new)}


def query(ip):
    import shodan

    api = shodan.Shodan(os.environ["SHODAN_KEY"])
    try:
        return api.host(ip)
    except shodan.APIError as err:
        if "No information available" in str(err):
            return None
        raise SystemExit(f"exposure: Shodan answered: {err}")


def main():
    ip = os.environ["OWN_PUBLIC_IP"].strip()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    snap = snapshot(query(ip), ip, now)
    OUT.mkdir(exist_ok=True)
    latest = OUT / "latest.json"
    previous = json.loads(latest.read_text()) if latest.exists() else None
    diff = dict(changes(previous, snap), checked_at=now)
    text = json.dumps(snap, indent=2) + "\n"
    (OUT / f"{now[:10]}.json").write_text(text)
    latest.write_text(text)
    (OUT / "changes.json").write_text(json.dumps(diff, indent=2) + "\n")
    state = "indexed" if snap["indexed"] else "not indexed by Shodan"
    print(f"exposure: {mask(ip)} {state}; open ports {snap['ports']}; "
          f"opened {diff['opened']}, closed {diff['closed']}{' (first snapshot)' if diff['baseline'] else ''}")


if __name__ == "__main__":
    main()
