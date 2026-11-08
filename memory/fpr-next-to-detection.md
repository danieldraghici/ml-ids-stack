---
name: fpr-next-to-detection
description: no detection rate without the false-alarm rate on a large benign set
type: correction
---

Whenever you report a detection rate (a test, a doc, a pull request), report the false-alarm rate on benign traffic next to it, with the number of benign flows.

**Why:** the dissertation model detects Hulk, nmap and slowloris at 100% in the lab, but raises 45% false alarms on CIC-IDS2018 benign and 70% on ToN-IoT benign. Detection alone hides the real limit (R-08). With n benign flows and zero alarms, the rule of three only supports a false-alarm rate below 3/n, so 3,000 flows are needed to claim under 0.1%.

**How to apply:** tables of results always have a benign row with its flow count. Do not write "detects X" in docs without the matching false-alarm figure.
