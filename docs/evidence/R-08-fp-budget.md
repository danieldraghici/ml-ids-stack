# R-08: false-alarm budget on local benign traffic

Run on 2026-11-21 with `make calibrate`, using `detector/calibrate.py` and the model `nfv3_window_xgb_latest.joblib` (SHA-256 checked, 66 features, feature contract kept).

## Input

- **Benign capture:** 2.00 hours of the student's own laptop on the home Wi-Fi (`dumpcap`, interface Wi-Fi, pcapng, 2.6 GB). It gives 16,008 flows, above the 10,000 the R-08 control asks for.
  - **Activity:** ordinary use of the laptop: browsing, video, messaging, downloads and idle time. No scan or attack traffic.
  - **Privacy:** the capture holds personal traffic. It stays on the student's machine outside the repository. Only the counts and rates below leave it.
- **Attack fixtures** of the detection gate, replayed at each threshold: `portscan.pcap`, `slowloris.pcap`, `hulk1_head.pcap`.
- **Budget:** 1 false alert episode per hour of traffic (episodes keyed by source, 120 s gap, `detector/episodes.py`).
- **Detection floor:** 99%, as in the gate.

## Result

| Threshold | False alerts / flows | False-alarm rate | False episodes (per hour) | portscan | slowloris | hulk |
|---|---|---|---|---|---|---|
| 0.00515 (current, `thresholds.json`) | 175 / 16,008 | 1.09% | 46 (23.0) | 100.00% | 99.81% | 100.00% |
| 0.01 | 138 / 16,008 | 0.86% | 33 (16.5) | 100.00% | 99.81% | 100.00% |
| 0.02 | 113 / 16,008 | 0.71% | 24 (12.0) | 100.00% | 99.81% | 100.00% |
| 0.05 | 91 / 16,008 | 0.57% | 11 (5.5) | 100.00% | 99.63% | 100.00% |
| 0.1 | 81 / 16,008 | 0.51% | 8 (4.0) | 100.00% | 99.26% | 100.00% |
| 0.2 | 41 / 16,008 | 0.26% | 4 (2.0) | 100.00% | 96.65% | 100.00% |
| 0.5 | 33 / 16,008 | 0.21% | 3 (1.5) | 100.00% | 93.87% | 100.00% |

No threshold on the ladder meets the budget and keeps every attack fixture at 99%.

- The lowest rate of false episodes that still holds the floor is 4 per hour, at 0.1.
- Above 0.1, slowloris falls under the floor, and even 0.5 leaves 1.5 false episodes per hour.

## What this shows

- **The model's threshold does not transfer to this network.** It was calibrated on CICIoT2023 benign traffic, where false alarms were 0.2-0.4%. Here the rate is 1.09% at the same threshold, on traffic the model never saw. This is the limit R-08 names, now measured on the student's own network.
- **Grouping is worth it but not enough.** Episodes turn 175 false alerts into 46 lines, a quarter of the work, but 23 per hour is still far over what an analyst can follow.
- **Raising the threshold trades detection for quiet, and the gate stops it at 0.1.** Above 0.1, slowloris, the slowest attack of the fixtures, is the first to drop.

## Decision

The threshold stays at 0.00515 until the student decides otherwise. `thresholds.json` and the gate's baseline are protected, and change only in a reviewed pull request (R-05, R-06).

The measured options:

1. **Keep 0.00515:** full detection on the fixtures; about 23 false episodes per hour on this network.
2. **Raise to 0.1:** about 4 false episodes per hour, slowloris at 99.26%. The baseline in `tests/regression/baseline.json` must be re-recorded in the same pull request.
3. **Retrain with local benign traffic,** in the dissertation repository. This is the only route this table shows to the budget without losing detection.

AlertBudgetExceeded (`monitoring/alerts.yml`) fires whenever more than one episode is written in an hour. On this network it would fire most of the time at the current threshold, and that is the intended signal.
