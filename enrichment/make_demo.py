#!/usr/bin/env python3
"""A quiet HTTPS beacon from a lab host to one address, for the enrichment demonstration (R-10).

Every 60 s for 15 minutes, 192.168.10.5 opens a TLS-looking session to the address on port 443,
sends a little and closes it: the shape of a C2 check-in, slow and small, which neither the
ML-IDS nor the Suricata rules here alert on. If the address is a MISP indicator, the enrichment
still raises every one of these flows to priority medium. The address is live intelligence, so
the capture is written under out/demo/ (git-ignored) and never committed.

Usage: python3 enrichment/make_demo.py <address> <out.pcap>   (make ti-demo runs it)
"""
import ipaddress
import random
import sys
from datetime import datetime, timezone

from scapy.all import IP, TCP, Ether, Raw, wrpcap

LAB_HOST = "192.168.10.5"
T0 = datetime(2026, 8, 21, 9, 0, 0, tzinfo=timezone.utc).timestamp()


def session(rng, dst, t):
    sport, cs, ss = rng.randint(32768, 60999), rng.randint(1, 2**31), rng.randint(1, 2**31)
    pkts = []

    def add(to_server, flags, payload=b""):
        nonlocal cs, ss, t
        if to_server:
            layer = IP(src=LAB_HOST, dst=dst) / TCP(sport=sport, dport=443, flags=flags, seq=cs,
                                                    ack=ss if "A" in flags else 0)
            cs += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
        else:
            layer = IP(src=dst, dst=LAB_HOST) / TCP(sport=443, dport=sport, flags=flags, seq=ss, ack=cs)
            ss += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
        pkt = Ether(src="02:00:00:00:10:05", dst="02:00:00:00:10:01") / (layer / Raw(payload) if payload else layer)
        pkt.time = t
        pkts.append(pkt)
        t += 0.03

    add(True, "S"); add(False, "SA"); add(True, "A")
    add(True, "PA", b"\x16\x03\x01" + rng.randbytes(200))   # looks like a TLS ClientHello
    add(False, "PA", b"\x16\x03\x03" + rng.randbytes(900))
    add(True, "PA", b"\x17\x03\x03" + rng.randbytes(120))   # application data
    add(False, "PA", b"\x17\x03\x03" + rng.randbytes(80))
    add(True, "FA"); add(False, "FA"); add(True, "A")
    return pkts


def main(argv):
    if len(argv) != 2:
        sys.exit("usage: make_demo.py <address> <out.pcap>")
    dst = str(ipaddress.ip_address(argv[0]))
    rng = random.Random(1071001)
    pkts = []
    for i in range(15):
        pkts += session(rng, dst, T0 + 60 * i + rng.uniform(0, 3))
    wrpcap(argv[1], pkts)
    print(f"make_demo: {len(pkts)} packets, 15 sessions to port 443, in {argv[1]}")


if __name__ == "__main__":
    main(sys.argv[1:])
