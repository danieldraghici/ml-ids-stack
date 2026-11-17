# Model card: nfv3_window_xgb_latest

The detector's model, built in the student's dissertation and used here unchanged (R-07). Facts below come from the bundle's own metadata and from the dissertation's evaluation report `outputs/nfv3_eval/20261106_115920`.

## Identity

| | |
|---|---|
| File | `nfv3_window_xgb_latest.joblib`, 4.42 MB |
| SHA-256 | `55c587d2a2a7f10049c1ea74f5e97bd7ea44634f4d83aecbff13a1bc8d1f8cbd` (pinned in `detector/thresholds.json`) |
| Built | 2026-11-06, scikit-learn 1.9.0, XGBoost 3.4.0 |
| Type | two-stage XGBoost: attack or benign, then the attack family; 400 trees, depth 8, learning rate 0.1 |
| Families | Bot, BruteForce, DDoS, DoS, DoS-Slow, PortScan, WebAttack |
| Decision threshold | 0.005151937318725348, for a 0.1% false-alarm budget on 53,852 held-out benign flows from CICIoT2023 (BenignTraffic, BenignTraffic1) |
| Inference | about 1.3 µs per flow |

## Input

66 features from flows built by nfstream (flow timeout 120 s, activity timeout 30 s):

- per-flow NetFlow v3 fields: protocol, bytes and packets each way, TCP flags, durations, packet-size histogram, TCP windows, ICMP type, rates and inter-arrival times;
- service flags derived from the destination port (web, DNS, SSH, ...);
- 10 s and 60 s windows per source and per destination host: flows, distinct hosts and ports, flows without reply, SYN-only, RST, failed connections, top service.

IP addresses, ports and TTL are never features; IPs are only window keys. Flows to multicast and broadcast destinations are never alerted.

## Training data

3,390,568 flows: NF-CSE-CIC-IDS2018-v3 (2,163,384, of which 1.5 M benign), NF-UNSW-NB15-v3 (516,516), NF-BoT-IoT-v3 (461,383 attacks) and 249,285 local benign flows from CICIoT2023, the cleaned NetFlow v3 data prepared in the student's project for the Cybersecurity and Machine Learning course. Removed before training, with the reason recorded in the bundle:

- SlowHTTPTest and FTP brute force from CIC-IDS2018: failed attacks, every flow a SYN answered by RST;
- web-attack labels on flows that are not TCP/80 (the time window was labelled, not the attack);
- benign labels on unsolicited inbound internet traffic (RDP/SMB scanners);
- BoT-IoT benign (TTL 64 alone separated it, a testbed fingerprint);
- classes no dataset claims.

ToN-IoT and the Infiltration class are kept for evaluation only.

## Measured results (calibrated threshold)

| Test | Result |
|---|---|
| Lab captures: Hulk, nmap -sS, slowloris | 100% of flows flagged |
| Lab benign capture | 3 of 144 flows flagged (2.1%) |
| CICIoT2023 floods, slowloris, PortScan, OSScan | 99.9-100% |
| CICIoT2023 vulnerability scan / host discovery | 95% / 83% |
| CICIoT2023 dictionary brute force | 58% |
| CICIoT2023 ping sweep | 0% |
| CICIoT2023 held-out benign | 0.2-0.4% flagged |
| Benign of a dataset left out of training (CIC-IDS2018 / ToN-IoT) | 45% / 70% flagged |
| This repository's fixtures | `docs/evidence/R-06-replay-baseline.txt` |

## Limits

- The threshold does not transfer between networks: it was calibrated on CICIoT2023 benign, not on the lab segment, and benign traffic from an unseen network raises far more alarms (R-08).
- Ping sweeps and slow password guessing are mostly missed; Suricata and Sigma rules cover them (R-09).
- One attack can be labelled with several families; detection holds, the label does not (R-08).
- The lab captures were also used while the model was developed, so replaying them proves "no worse than before", not accuracy on new traffic (R-06).
