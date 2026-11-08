---
name: ip-is-not-a-feature
description: IPs, ports and TTL are window keys only, never model inputs
type: correction
---

Never add source or destination IP, port numbers or TTL to the detector's feature set. Use IPs only as keys for the 10 s and 60 s windows.

**Why:** in the dissertation data, MIN_TTL = 64 alone meant 97.7% attack in a 200k-flow sample, because the attacker was Linux (Kali). The 100% lab detection of the first model was this fingerprint, not behaviour. Learned 2026-11-06.

**How to apply:** any change under `detector/` that touches the feature list must show the list in the pull request description. Reject features derived from IP or TTL values themselves.
