# Demonstration script (about 6 minutes)

The recorded demonstration the course asks for (Session 7, project assessment). Every step runs from a clean clone. On the student's machine the secrets come from SOPS; a reviewer runs `make reviewer-setup` first (README). Each step names the risk it shows and the evidence file that records it.

## 0. Before recording

```bash
make down && make up       # a clean stack, all services healthy
make dashboards            # index patterns and saved searches
```

Open three browser tabs:

1. **Dashboards:** `https://localhost:8443`, saved search "Threat intel matches".
2. **Grafana:** `https://localhost:8443/grafana/d/ml-ids-stack`.
3. **GitHub:** the repository's pull requests.

## 1. The repository and the register (1 min)

- Show `RISK-REGISTER.md`: ten rows in three registers, each with a control, a residual score and evidence. All ten are Implemented.
- Show the rulesets: no direct push to `main`, and five required checks, `ai-review` among them (R-01).

## 2. Two sensors into one stack (1 min, R-06, R-09)

```bash
make replay PCAP=portscan.pcap
make suricata PCAP=portscan.pcap
```

- **Dashboards:** the ML-IDS shows the scan as one episode, and Suricata shows the same scan's flows, in ECS.
- **Grafana:** the "Records written and indexed" curves rise and meet.

## 3. Threat intelligence changes the outcome (1 min, R-10)

```bash
make ti-demo DEMO_IOC=<a TLP:CLEAR address from enrich/ioc_ip.yml>   # reviewer: make ti-demo-offline
```

- **Dashboards:** "Threat intel matches" shows the same scan from a MISP indicator, now at high priority with risk 72.
- **On camera:** only a TLP:CLEAR indicator may appear, as in the evidence screenshots (R-10).
- **The beacon:** no sensor alerted on it, yet it is raised to medium.
- **The original address:** in no feed, so it stays unchanged.
- **Evidence:** `docs/evidence/R-10-*.png`.

## 4. A stopped sensor raises an alert (1.5 min, R-06)

```bash
make demo-sensor-down
```

- **What to show:** while waiting, Grafana's heartbeat age climbing past 60 s.
- **Alert:** SensorDown goes pending after about 70 s and fires after about 1 min 45 s, in Grafana and in Alertmanager.
- **End:** `make demo-sensor-up` resolves it.
- **Evidence:** `docs/evidence/R-06-sensor-down-alert.png`.

## 5. Automated review before human approval (1 min, R-01, R-05)

- Open closed pull request 19, a deliberately careless change.
- **What `ai-review` found:** it failed with 5 blocking findings before any approval:
  - an instruction to the reviewer hidden in a docstring;
  - minutes taken for hours;
  - errors read as a fresh feed;
  - no test;
  - a detection rate without its false-alarm rate.
- **Who can merge:** the merge box shows the required check failing and no approval. The App cannot approve; the student decides.
- **Evidence:** `docs/evidence/R-01-ai-review-*.png`.

## 6. The honest limit (30 s, R-08)

Show `docs/evidence/R-08-fp-budget.md`:

- **Measurement:** on 2 hours of local benign traffic the current threshold gives 23 false episodes per hour against a budget of 1.
- **Limit:** no threshold reaches the budget without losing detection.
- **Monitoring:** AlertBudgetExceeded makes that visible.
- **Register:** this is why R-08 keeps a residual likelihood of 4.

## After recording

```bash
make down
```

The recording file is not committed: it is on Google Drive, linked from `docs/project.md` section 7.
