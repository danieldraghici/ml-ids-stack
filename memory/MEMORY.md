# Memory index

One correction per file. Read the file before acting in its area. New corrections get a new file and one line here, in the pull request where they happened; this folder is reviewed like code (CODEOWNERS, R-05).

- [IP is not a feature](ip-is-not-a-feature.md): IPs, ports and TTL are window keys only, never model inputs
- [False alarms next to detection](fpr-next-to-detection.md): no detection rate without the false-alarm rate on a large benign set
- [Threshold is calibrated](threshold-is-calibrated.md): 0.00515 comes from local benign; only the student changes it
- [Hooks over prose](hooks-over-prose.md): a safety rule goes into the guard hook or a permission rule, not only into text
- [WSL, not /mnt](wsl-not-mnt.md): run make, sops and Docker from the WSL home, never from the Windows mounts
