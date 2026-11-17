# pcap fixtures

Lab captures from the dissertation work, replayed by `make replay PCAP=<file>` and, from F4, by the detection-quality gate (R-06). Each fixture stays under 5 MB, cut with `editcap`; this table records where it came from and how it was cut, so it can be regenerated and checked.

| Fixture | Source (dissertation workspace) | Source SHA-256 | Command | Fixture SHA-256 | Bytes | Packets | Duration (s) |
|---|---|---|---|---|---|---|---|
| `portscan.pcap` | `ML_IDS_Disertation/data/traffic_captures/portscan.pcap` | `6b5c4691374ecbf85e974f2f743d2697fd3a125b1b2ee8e076cf4e3e68001cd3` | `copied unchanged` | `6b5c4691374ecbf85e974f2f743d2697fd3a125b1b2ee8e076cf4e3e68001cd3` | 630584 | 8254 | 66.3 |
| `slowloris.pcap` | `ML_IDS_Disertation/data/traffic_captures/slowloris.pcap` | `b476b9e2e2fb28207c17fce173ef322f04d44ef4b863afaec17b522382d11e84` | `copied unchanged` | `b476b9e2e2fb28207c17fce173ef322f04d44ef4b863afaec17b522382d11e84` | 2785586 | 27215 | 227.7 |
| `hulk1_head.pcap` | `ML_IDS_Disertation/data/traffic_captures/hulk1.pcap` | `610569586065d8acdf0292276e2039aec769c8628ac0e5f7a341664beb4cfa84` | `editcap -r hulk1.pcap hulk1_head.pcap 1-5500` | `1bfc9ccf3b1a7199adf0ceaa94943792c513461907416355778e8200d6cb04e1` | 4706632 | 5500 | 23.0 |
| `benign_head.pcap` | `Capturi/benign_test.pcap` | `a1983db6fbed82dd837b912948d0f978ab9c43afd404d01aae28d284df1bd66c` | `editcap -s 128 benign_test.pcap tmp.pcap && editcap -r tmp.pcap benign_head.pcap 1-30000` | `dbc887f56acfd92d68d17ec99ac99429449e1ce7b9bdbe5befbec95bfda5c0bb` | 4635068 | 30000 | 23.5 |

Notes:

- `portscan.pcap` (nmap -sS) and `slowloris.pcap` were already under 5 MB and are copied unchanged.
- `hulk1_head.pcap` keeps the first 5,500 whole packets (23 s) of the Hulk HTTP flood; no packet is altered.
- `benign_head.pcap`: the benign capture is 147 MB, mostly large downloads, so whole packets cannot fit in 5 MB with more than a few flows. It is cut to 128-byte packets (`-s 128`, headers kept) and to the first 30,000 packets (23 s, 43 flows). Cutting packets changes byte-based features slightly: on the full capture the detector sees 181 flows and 3 false PortScan alerts, on the 128-byte version of the whole capture 175 flows and the same 3.

## Baseline (detector as of this commit, threshold from `detector/thresholds.json`)

| Fixture | Flows | Alert records | Predicted classes |
|---|---|---|---|
| `portscan.pcap` | 4100 | 4100 | PortScan 3098, DoS 1002 |
| `slowloris.pcap` | 1076 | 1067 | DoS 693, DDoS 310, PortScan 37, WebAttack 27, Benign 9 |
| `hulk1_head.pcap` | 601 | 601 | DoS-Slow 371, DoS 228, DDoS 1, PortScan 1 |
| `benign_head.pcap` | 43 | 1 | Benign 41, PortScan 2 |

Every flow of the three attack fixtures except 9 slowloris flows is flagged as an attack; on the benign fixture 2 of 43 flows are flagged (PortScan), the false alarms R-08 tracks. The attack families are mixed inside one attack (the Hulk flood shows up as DoS and DoS-Slow), a known limit recorded under R-08.
