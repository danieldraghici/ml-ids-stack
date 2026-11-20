#!/usr/bin/env python3
"""Pull IP indicators from MISP into the dictionary Logstash's translate filter reads (R-10).

The feed lifecycle in one place:
- trust: only attributes flagged to_ids, minus anything on a MISP warninglist (known benign
  addresses such as public resolvers), each weighted by the organisation that published it
  (enrichment/feeds.yml);
- age-out: an indicator not updated within MAX_AGE_DAYS (default 30) is dropped here and
  counted, so the meta file shows how much of each pull was stale (a feed that stopped
  publishing shows up as everything aged out, not as an unexplained zero);
- deduplication: one line per address, keeping the highest weight, then the newest;
- exact match only: translate compares whole values, so CIDR ranges cannot match; they are
  skipped and counted instead of silently pretending to cover something;
- safety: an empty result never replaces the previous dictionary, and the file is written to a
  temporary name and renamed, so Logstash never reads half of it.

Output (git-ignored, live intelligence never goes into the repository):
  enrich/ioc_ip.yml        "<ip>": "<json with event, category, org, weight, tlp, updated>"
  enrich/ioc_ip.meta.json  when it was pulled and what was kept or skipped (F7: IocFeedStale)

Usage: make misp-pull   (reads MISP_URL, MISP_KEY and MISP_CA from .env.secrets)
"""
from __future__ import annotations

import ipaddress
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "enrich" / "ioc_ip.yml"
META = ROOT / "enrich" / "ioc_ip.meta.json"
FEEDS = ROOT / "enrichment" / "feeds.yml"
TYPES = ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port"]
MAX_AGE_DAYS = int(os.environ.get("MISP_MAX_AGE_DAYS", "30"))


def load_weights(path=FEEDS):
    """{org name: weight} and the default weight, from a two-level YAML file without PyYAML."""
    weights, default = {}, 0.5
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].rstrip()
        if not line.strip() or line.strip().endswith(":") and not line.startswith(" "):
            continue
        key, _, value = line.strip().partition(":")
        key, value = key.strip().strip('"'), value.strip()
        if line.startswith(" "):
            weights[key] = float(value)
        elif key == "default_weight":
            default = float(value)
    return weights, default


def tlp_of(tags):
    for t in tags or []:
        name = (t.get("name") if isinstance(t, dict) else str(t)).lower()
        if name.startswith("tlp:"):
            return name[4:]
    return "unknown"


def render(attrs, weights, default_weight, now, max_age_days=MAX_AGE_DAYS):
    """Turn MISP attributes (dicts) into the dictionary text and the statistics.

    Each attribute: value, type, event_id, category, org, tags, timestamp (epoch seconds).
    """
    cutoff = (now - timedelta(days=max_age_days)).timestamp()
    best, stats = {}, {"attributes": 0, "aged_out": 0, "cidr_skipped": 0, "invalid": 0}
    for a in attrs:
        stats["attributes"] += 1
        value = str(a["value"]).split("|", 1)[0].strip()
        if "/" in value:
            stats["cidr_skipped"] += 1
            continue
        try:
            ip = str(ipaddress.ip_address(value))
        except ValueError:
            stats["invalid"] += 1
            continue
        ts = float(a.get("timestamp") or 0)
        if ts < cutoff:
            stats["aged_out"] += 1
            continue
        entry = {"event": int(a["event_id"]), "category": a.get("category", ""),
                 "org": a.get("org") or "unknown",
                 "weight": round(weights.get(a.get("org") or "", default_weight), 2),
                 "tlp": tlp_of(a.get("tags")),
                 "updated": datetime.fromtimestamp(ts, tz=timezone.utc).date().isoformat()}
        old = best.get(ip)
        if old is None or (entry["weight"], entry["updated"]) > (old["weight"], old["updated"]):
            best[ip] = entry
    stats["indicators"] = len(best)

    def by_address(item):  # IPv4 first, then IPv6; the two cannot be compared directly
        address = ipaddress.ip_address(item[0])
        return address.version, int(address)

    text = "".join(f"{json.dumps(ip)}: {json.dumps(json.dumps(e, sort_keys=True))}\n"
                   for ip, e in sorted(best.items(), key=by_address))
    return text, stats


def write_atomic(path, text):
    path.parent.mkdir(exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def fetch():
    """Attributes from MISP as plain dicts. Imported here, so the tests need no MISP client."""
    import pymisp

    ca = os.environ.get("MISP_CA") or False
    misp = pymisp.PyMISP(os.environ["MISP_URL"], os.environ["MISP_KEY"], ssl=ca)
    orgs = {str(o["Organisation"]["id"]): o["Organisation"]["name"]
            for o in misp.organisations(scope="all")}
    raw = misp.search(controller="attributes", type_attribute=TYPES, to_ids=True,
                      enforce_warninglist=True, include_event_tags=True)
    out = []
    for a in raw.get("Attribute", []):
        event = a.get("Event", {})
        out.append({"value": a["value"], "type": a["type"], "event_id": a["event_id"],
                    "category": a.get("category"), "timestamp": a.get("timestamp"),
                    "org": orgs.get(str(event.get("orgc_id")), "unknown"), "tags": a.get("Tag", [])})
    return out


def main():
    weights, default = load_weights()
    now = datetime.now(timezone.utc)
    text, stats = render(fetch(), weights, default, now)
    meta = {"pulled_at": now.isoformat(timespec="seconds"), "max_age_days": MAX_AGE_DAYS, **stats}
    if not text:
        meta["result"] = "empty pull: previous dictionary kept"
        write_atomic(META, json.dumps(meta, indent=2) + "\n")
        sys.exit("misp-pull: MISP returned no usable indicator; the previous dictionary stays in place")
    write_atomic(OUT, text)
    meta["result"] = "written"
    write_atomic(META, json.dumps(meta, indent=2) + "\n")
    print(f"misp-pull: {stats['indicators']} indicators from {stats['attributes']} attributes "
          f"({stats['aged_out']} aged out, {stats['cidr_skipped']} CIDR skipped, {stats['invalid']} invalid)")


if __name__ == "__main__":
    main()
