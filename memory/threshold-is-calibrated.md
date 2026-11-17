---
name: threshold-is-calibrated
description: the decision threshold 0.00515 comes from local benign; only the student changes it
type: correction
---

The detector's decision threshold (0.00515) was calibrated for a 0.1% false-alarm budget on held-out local benign traffic. It lives in `detector/thresholds.json`. Do not change it, and do not propose changing it to fix a failing test or to cut false alarms.

**Why:** the threshold is a security decision with a measured trade-off (R-06, R-08). A silent change can lower detection without anyone noticing. The guard hook blocks edits to the file; this note explains why.

**How to apply:** if false alarms look too high, report them with the flow counts and suggest re-calibration on more local benign. The student decides and edits the file by hand in a reviewed pull request.
