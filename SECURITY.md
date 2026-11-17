# Security policy

## Reporting

Report a vulnerability privately to the repository owner (@danieldraghici). Do not open a public issue.

## Rules this repository enforces

- Every change reaches `main` through a pull request with passing checks. The student reviews each branch before its pull request is opened and merges it personally; from F7 an automated review comes first, and it never approves (R-01).
- Secrets are never committed in plaintext. gitleaks runs before every commit and on the full history in the required CI check `lint`; real secrets live only as SOPS ciphertext under `secrets/` (R-02). GitHub secret scanning and push protection are not available on this personal private repository, so the CI scan is the server-side layer.
- The AI agent works with the student's fine-grained token for this repository only, without administration, and never holds the student's own login. The pull-request reviewer is a separate GitHub App with one-hour tokens (R-03).
- The guard hook in `.claude/hooks/guard.py` blocks the agent from reading secrets, force pushing, pushing to `main`, merging or approving, and editing the detector threshold, models or regression fixtures (R-02, R-05, R-06).

## Key rotation runbook (R-02)

Rotate the key as soon as it may have left the machine: a gitleaks or push-protection hit, a key seen in a log, a lost laptop.

| Secret | Where it lives | Rotate |
|---|---|---|
| MISP automation key | `secrets/stack.enc.yaml` | MISP UI: Administration, Auth keys: delete the key, add a new one; `sops secrets/stack.enc.yaml` to replace it; `make down && make up` |
| Shodan API key | `secrets/stack.enc.yaml` | shodan.io account page: reset API key; update with `sops`; redeploy |
| OpenSearch admin password | `secrets/stack.enc.yaml` | update with `sops`; `make down && make up` (named volume is recreated) |
| Agent fine-grained token | `~/.config/ml-ids-stack/agent-token` in WSL, mounted read-only in the dev container | Settings, Developer settings, Fine-grained tokens: revoke it, generate a new one with the same settings (`docs/credentials.md`), replace the file. It expires by itself after 30 days |
| Reviewer GitHub App private key | `~/.config/ml-ids-stack-agent/app.pem` in WSL; an environment secret limited to `main` from F7 | App settings page, Private keys: generate a new key, delete the old one, replace the file and the secret. Tokens minted from the old key expire within one hour |
| age private key | `~/.config/sops/age/keys.txt` in WSL, never in the repo | `age-keygen` a new key; put the new public key in `.sops.yaml`; `sops updatekeys secrets/*.enc.yaml`; rotate every secret above, since the old key could read them |

Record each rotation in the pull request that closes the incident, citing R-02.
