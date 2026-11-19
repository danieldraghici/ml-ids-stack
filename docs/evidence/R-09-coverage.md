# R-09 evidence: detection coverage before and after Suricata and Sigma

Recorded 2026-11-19 with `make gate` (ML-IDS model and threshold from `detector/thresholds.json`, Suricata 8.0.7 with `suricata/rules/local.rules`, Sigma rules in `rules/sigma/` applied to Suricata's events after `pipelines/suricata.conf`). The detection gate checks every number in the last three columns on each pull request (`tests/regression/baseline.json`).

## Before: what the model misses on real data

Measured on the dissertation's evaluation data at the calibrated threshold (`outputs/nfv3_eval/20261106_115920/summary.md`, R-09 in the register): ping sweep 0% of 82 flows, web attacks 1.5% of 262, dictionary brute force 58%, host discovery 83%. The lab captures in this repository hold none of these techniques.

## After: every fixture through all three sensors

| Technique | Fixture | ML-IDS (flows alerted, family) | Suricata local rule | Sigma rule |
|---|---|---|---|---|
| Port scan, T1046 | `portscan.pcap` (lab) | 4,100 of 4,100 (PortScan, DoS) | none | none |
| Slow HTTP DoS, T1499 | `slowloris.pcap` (lab) | 1,074 of 1,076 (DoS, PortScan, WebAttack) | none | none |
| HTTP flood, T1499 | `hulk1_head.pcap` (lab) | 601 of 601 (DoS-Slow, DoS) | none | none |
| Benign lab traffic | `benign_head.pcap` (lab) | 1 of 43 (PortScan, a false alarm) | none | none |
| Ping sweep, T1018 | `icmp_sweep.pcap` (synthetic) | 254 of 254 (PortScan) | sid 9000001, 1 alert, T1018 | none |
| SSH password guessing, T1110.001 | `ssh_bruteforce.pcap` (synthetic) | 60 of 60 (PortScan) | sid 9000002, 2 alerts (one per 60 s window), T1110.001 | `ssh_guessing_tool_client`: 60 sessions |
| DNS tunnelling, T1071.004 | `dns_txt.pcap` (synthetic) | 0 of 1 | none | `dns_long_txt`: 1 answer |
| Near misses (benign) | `near_misses.pcap` (synthetic) | 1 of 6 (DoS, a false alarm on an admin's pings) | none | none |

## What the table shows, and what it does not

- **The rules name the technique.** On the synthetic sweep and password guessing the model flags every flow, but as PortScan, the family closest to a burst of short failed connections. Suricata and Sigma report host discovery (T1018) and password guessing (T1110.001), with the tool's client named in the SSH events, which is what an analyst acts on.
- **DNS tunnelling reaches only the Sigma rule.** One small UDP exchange looks like any DNS lookup to a flow model; the payload length is what gives it away.
- **No rule fires on a near miss or on the lab captures.** The admin's pings, three OpenSSH logins, the SPF and DKIM TXT answers and all four lab captures stay quiet for both local rules and both Sigma rules. The model raises one false alarm on the admin's pings, the kind R-08 tracks.
- **The synthetic captures are easier than the real attacks.** They follow the shapes of nmap -sn, hydra and a TXT tunnel, but no tool produced them (`tests/fixtures/pcaps/make_synthetic.py`). That the model flags them here while it missed 100% of real ping sweeps says the real traffic is harder, not that the gap is closed; the before row stays the honest measure for the model.
- **Payload attacks stay uncovered.** Web attacks (1.5% for the model) need content rules such as ET Open, which this repository does not load yet; no sensor here sees them.

The ML-IDS episodes and the Suricata alerts for one source meet in the saved search "All sensors for one source" (`config/dashboards/mlids.ndjson`, `docs/evidence/R-09-correlated-source.png`): for the attacker 192.168.20.11, one episode per attack next to the Suricata alerts that name T1018 and T1110.001. The 60 SSH sessions the Sigma rule matches are in `suricata-*` (`event.dataset:suricata.ssh`).
