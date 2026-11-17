# Evidence

Screenshots, logs and command output that prove a control works. Each file name starts with the risk ID it supports, so a reviewer can go from a register row to its proof. "Captured by" says who produces the file: the student (a screenshot of a browser page or terminal) or the agent (an API answer or command output saved as text).

| File | Risk | Captured by | What it shows |
|---|---|---|---|
| `R-01-rulesets-active.json` | R-01 | agent | the rules GitHub applies to `main`, read from the API |
| `R-01-rulesets-page.png` | R-01 | student | Settings, Rules, Rulesets: both rulesets active |
| `R-01-agent-pr-blocked-until-checks.png` | R-01 | student | a pull request from the agent session, blocked while the required checks run and the approval is missing |
| `R-01-push-refused.png` | R-01 | student | direct push and force push to `main` refused by the server |
| `R-01-bypass-waits-for-checks.png` | R-01 | student | the pull-request-only bypass stays unavailable while checks run |
| `R-01-agent-token-merge-test.txt` | R-01 | agent | the agent's token merged a pull request that had no approval, through the student's bypass: why the guard hook holds the merge step |
| `R-02-secret-scanning-unavailable.txt` | R-02 | agent | GitHub's answer when secret scanning was switched on: not available here |
| `R-02-stack-up-down-twice.txt` | R-02, R-04 | agent | `make up` and `make down` twice in a row: green cluster both times, `.env.secrets` mode 600 while up and deleted after, no volume left |
| `R-02-frontdoor-tls-chain.txt` | R-02 | agent | `make tls`: frontdoor.lab, issued by the lab intermediate, issued by the lab root, TLS 1.3, verify return code 0 |
| `R-02-frontdoor-cert-chain.png` | R-02 | student | the browser at `https://localhost:8443`, certificate viewer open on the three-level chain |
| `R-02-fake-key-rejected.png` | R-02 | student | gitleaks refusing a commit with a fake MISP key |
| `R-03-R-04-actions-permissions.json` | R-03, R-04 | agent | workflow token read-only, Actions cannot approve, SHA pinning required |
| `R-03-agent-token-scope.png` | R-03 | student | the agent's fine-grained token: this repository only, its permissions and expiry, never the token value |
| `R-03-agent-token-check.txt` | R-03 | agent | what the agent's token reaches: this repository yes, rulesets and other private repositories no |
| `R-03-app-permissions.png` | R-03 | student | F7: the reviewer App's permissions page |
| `R-03-app-installation.png` | R-03 | student | F7: the reviewer App installed on this repository only |
| `R-06-replay-baseline.txt` | R-06 | agent | flows, alerts and predicted classes per pcap fixture, the baseline the F4 gate compares against |
| `R-07-tampered-model-refused.txt` | R-07 | agent | a model changed by one byte, refused by `detector/run.py` before it is unpickled (exit code 3) |
| `R-05-memory-correction-persists.png` | R-05 | student | a correction saved to `memory/` and followed in a new session |
| `R-05-poisoned-memory-refused-by-model.png` | R-05 | student | the model declining a line planted in a memory file (the prose layer) |
| `R-05-poisoned-memory-blocked.png` | R-05 | student | the write a planted memory line asked for, refused by the deny rule in `.claude/settings.json` (the technical layer) |

Later phases add their own rows (R-04, R-06 to R-10).
