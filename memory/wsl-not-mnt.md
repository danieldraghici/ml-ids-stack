---
name: wsl-not-mnt
description: run make, sops and Docker from the WSL home, never from the Windows mounts
type: correction
---

The student's machine is Windows 11 with WSL2 Ubuntu. Run every command from the clone in the WSL home (`~/ml-ids-stack`) or inside the dev container. Do not use paths under `/mnt/c` or `/mnt/d`, and do not write PowerShell commands.

**Why:** on the Windows mounts file permissions are not enforced, so `umask 077` does not protect `.env.secrets` (R-02). Docker bind mounts from there are also slow. Docker Desktop on Windows cannot capture the host Wi-Fi, so the detector runs on pcap replay.

**How to apply:** commands in docs and Makefiles are Bash for Ubuntu. Live capture is out of scope for the stack; use `make replay` (F3).
