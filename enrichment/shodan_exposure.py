#!/usr/bin/env python3
"""What the internet already sees on the lab's own public address, from Shodan (R-10).

Rules of engagement: Shodan is asked about one address only, OWN_PUBLIC_IP, which the student
owns; one lookup per run. Asking is passive: Shodan's own scans are read, nothing is sent to the
address. The full host API needs a paid plan; a free account's key is refused (403), and the
lookup then goes to InternetDB, Shodan's free per-address API: the same scans, with open ports,
known CVEs and tags but no banners. The snapshot records which source answered.

The address is personal data: it is written only to exposure/ (git-ignored) and never printed;
the console shows the open ports and a masked address. Each run writes
  exposure/<date>.json     the snapshot: ports, services, CVEs, organisation, last Shodan update
  exposure/latest.json     the same, the baseline for the next run
  exposure/changes.json    ports opened or closed since the previous snapshot; F7's
                           ExposureChanged alert reads it
"No information available" from Shodan is a valid result: nothing on the address is indexed.

Usage: make exposure   (reads SHODAN_KEY and OWN_PUBLIC_IP from .env.secrets)
"""
from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.request
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
        return {"ip": ip, "indexed": False, "ports": [], "services": [], "vulns": [], "org": None,
                "last_update": None, "source": None, "checked_at": now}
    services = sorted({(d.get("port"), d.get("transport", "tcp"), d.get("product") or d.get("_shodan", {}).get("module"))
                       for d in host.get("data", []) if d.get("port") is not None}, key=lambda s: (s[0], s[1]))
    return {"ip": host.get("ip_str", ip), "indexed": True, "ports": sorted(set(host.get("ports", []))),
            "services": [{"port": p, "transport": t, "product": prod} for p, t, prod in services],
            "vulns": sorted(set(host.get("vulns") or [])), "org": host.get("org"),
            "last_update": host.get("last_update"), "source": host.get("_source", "host API"),
            "checked_at": now}


def changes(previous, current):
    """Ports opened and closed between two snapshots of the same address."""
    if previous is None or previous.get("ip") != current.get("ip"):
        return {"baseline": True, "opened": [], "closed": []}
    old, new = set(previous.get("ports", [])), set(current.get("ports", []))
    return {"baseline": False, "opened": sorted(new - old), "closed": sorted(old - new)}


def from_internetdb(record):
    """An InternetDB answer in the shape of a host() answer: ports and CVEs, no banners."""
    return {"ip_str": record.get("ip"), "ports": record.get("ports", []), "vulns": record.get("vulns", []),
            "data": [], "org": None, "last_update": None, "_source": "InternetDB"}


def internetdb(ip):
    url = "https://internetdb.shodan.io/" + ipaddress.ip_address(ip).compressed
    request = urllib.request.Request(url, headers={"User-Agent": "ml-ids-stack-exposure"})
    try:
        with urllib.request.urlopen(request, timeout=20) as answer:
            return from_internetdb(json.load(answer))
    except urllib.error.HTTPError as err:
        if err.code == 404:  # nothing indexed on the address
            return None
        raise SystemExit(f"exposure: InternetDB answered HTTP {err.code}") from None


def query(ip):
    import shodan

    api = shodan.Shodan(os.environ["SHODAN_KEY"].strip())
    try:
        return api.host(ip)
    except shodan.APIError as err:
        if "No information available" in str(err):
            return None
        if "Access denied" in str(err):  # free plan: no host() credits
            return internetdb(ip)
        raise SystemExit(f"exposure: Shodan answered: {err}") from None


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
    print(f"exposure: {mask(ip)} {state} (source: {snap['source'] or 'none'}); open ports {snap['ports']}, "
          f"{len(snap['vulns'])} known CVEs; opened {diff['opened']}, closed {diff['closed']}"
          f"{' (first snapshot)' if diff['baseline'] else ''}")


if __name__ == "__main__":
    main()
