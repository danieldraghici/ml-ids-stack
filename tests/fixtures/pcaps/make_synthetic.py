#!/usr/bin/env python3
"""Synthetic pcap fixtures for the techniques the lab captures do not contain (R-09).

The dissertation's lab captures hold a port scan, slowloris, Hulk and benign traffic, but no
ping sweep, no password guessing and no DNS tunnelling. These four files are generated here
with scapy, on the same addressing (attacker 192.168.20.11, victim network 192.168.10.0/24),
so Suricata, the Sigma rules and the ML-IDS can be tested on them. They are synthetic: packet
shapes follow the tools named below, but no tool produced them, and the coverage table says so.

Every value comes from a fixed seed and a fixed start time, so running this script again
writes byte-identical files; tests/test_fixtures_synthetic.py checks that against the SHA-256
recorded in README.md.

  icmp_sweep.pcap      nmap -sn style host discovery: ICMP echo to 192.168.10.1-254 in 2.5 s,
                       four hosts answer (T1018)
  ssh_bruteforce.pcap  hydra style SSH password guessing: 60 sessions to 192.168.10.11:22 in
                       2 min, client banner SSH-2.0-libssh_0.10.6 (T1110.001)
  dns_txt.pcap         one DNS TXT answer of 240 base64 characters for a random-looking
                       subdomain, the shape of DNS tunnelling (T1071.004)
  near_misses.pcap     benign traffic that looks close to each of the above: an admin pinging
                       one host 30 times at 1/s, three SSH logins with an OpenSSH client, a
                       short SPF TXT answer and a long DKIM TXT answer

Usage: python3 tests/fixtures/pcaps/make_synthetic.py   (from the repository root)
"""
from __future__ import annotations

import base64
import random
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap  # noqa: E402

OUT = Path(__file__).resolve().parent
T0 = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc).timestamp()
ATTACKER, VICTIM, RESOLVER, CLIENT, ADMIN = (
    "192.168.20.11", "192.168.10.11", "192.168.10.53", "192.168.10.5", "192.168.10.50")
MAC = {ATTACKER: "02:00:00:00:20:11", VICTIM: "02:00:00:00:10:11", RESOLVER: "02:00:00:00:10:53",
       CLIENT: "02:00:00:00:10:05", ADMIN: "02:00:00:00:10:50"}
GATEWAY_MAC = "02:00:00:00:10:01"


def frame(src, dst, layer, t):
    pkt = Ether(src=MAC.get(src, GATEWAY_MAC), dst=MAC.get(dst, GATEWAY_MAC)) / IP(src=src, dst=dst) / layer
    pkt.time = t
    return pkt


def tcp_session(rng, src, dst, dport, t, client_banner, server_banner, extra_rounds):
    """Handshake, SSH banners, a few opaque key-exchange packets, then the client closes."""
    sport = rng.randint(32768, 60999)
    cs, ss = rng.randint(1, 2**31), rng.randint(1, 2**31)
    pkts, dt = [], 0.0005

    def add(direction, flags, payload=b""):
        nonlocal cs, ss, t
        if direction == "c":
            layer = TCP(sport=sport, dport=dport, flags=flags, seq=cs, ack=ss if "A" in flags else 0, window=64240)
            pkts.append(frame(src, dst, layer / Raw(payload) if payload else layer, t))
            cs += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
        else:
            layer = TCP(sport=dport, dport=sport, flags=flags, seq=ss, ack=cs, window=65160)
            pkts.append(frame(dst, src, layer / Raw(payload) if payload else layer, t))
            ss += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
        t += dt

    add("c", "S")
    add("s", "SA")
    add("c", "A")
    add("s", "PA", server_banner)
    add("c", "PA", client_banner)
    for _ in range(extra_rounds):
        add("c", "PA", rng.randbytes(rng.randint(80, 400)))
        add("s", "PA", rng.randbytes(rng.randint(80, 600)))
    add("c", "FA")
    add("s", "FA")
    add("c", "A")
    return pkts


def icmp_sweep(rng):
    pkts, t = [], T0
    live = {1, 11, 20, 53}
    for host in range(1, 255):
        dst = f"192.168.10.{host}"
        pkts.append(frame(ATTACKER, dst, ICMP(type=8, id=0x4d2, seq=host) / Raw(b"\x00" * 0), t))
        if host in live:
            pkts.append(frame(dst, ATTACKER, ICMP(type=0, id=0x4d2, seq=host), t + 0.0004))
        t += 0.01
    return pkts


def ssh_bruteforce(rng):
    pkts, t = [], T0 + 600
    for _ in range(60):
        pkts += tcp_session(rng, ATTACKER, VICTIM, 22, t, b"SSH-2.0-libssh_0.10.6\r\n",
                            b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n", extra_rounds=3)
        t += 2.0
    return pkts


def dns_exchange(rng, t, name, txt):
    qid = rng.randint(1, 65535)
    sport = rng.randint(32768, 60999)
    query = DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype="TXT"))
    answer = DNS(id=qid, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=name, qtype="TXT"),
                 an=DNSRR(rrname=name, type="TXT", ttl=60, rdata=[txt]))
    return [frame(CLIENT, RESOLVER, UDP(sport=sport, dport=53) / query, t),
            frame(RESOLVER, CLIENT, UDP(sport=53, dport=sport) / answer, t + 0.02)]


def dns_txt(rng):
    blob = base64.b64encode(rng.randbytes(180)).decode()            # 240 characters
    return dns_exchange(rng, T0 + 1200, "a1b2c3d4.updates.example.net", blob)


def near_misses(rng):
    pkts, t = [], T0 + 1800
    for seq in range(30):                                            # one host, 1/s: not a sweep
        pkts.append(frame(ADMIN, VICTIM, ICMP(type=8, id=0x77, seq=seq), t))
        pkts.append(frame(VICTIM, ADMIN, ICMP(type=0, id=0x77, seq=seq), t + 0.0003))
        t += 1.0
    for _ in range(3):                                               # three logins, a real client
        pkts += tcp_session(rng, ADMIN, VICTIM, 22, t, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n",
                            b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n", extra_rounds=6)
        t += 40.0
    pkts += dns_exchange(rng, t, "example.com", "v=spf1 include:_spf.example.com ~all")
    dkim = "v=DKIM1; k=rsa; p=" + base64.b64encode(rng.randbytes(170)).decode()
    pkts += dns_exchange(rng, t + 1, "selector1._domainkey.example.com", dkim)
    return pkts


def main():
    for name, build, seed in [("icmp_sweep.pcap", icmp_sweep, 1018), ("ssh_bruteforce.pcap", ssh_bruteforce, 1110),
                              ("dns_txt.pcap", dns_txt, 1071), ("near_misses.pcap", near_misses, 4242)]:
        pkts = build(random.Random(seed))
        wrpcap(str(OUT / name), sorted(pkts, key=lambda p: float(p.time)))
        print(f"{name}: {len(pkts)} packets")


if __name__ == "__main__":
    main()
