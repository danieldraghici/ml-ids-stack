# Project document: ML-IDS detection stack

Risk and Damage Management, ULBS Cybersecurity master, Module 4A (instructor Dan Candea). Student: Daniel Draghici. This document grows with each phase; sections marked *to write* are filled when their phase lands.

## 1. Definition and scope

The security function this project serves is network intrusion detection for a small lab segment. Its main sensor is the ML-IDS from the student's dissertation: an XGBoost model on NetFlow-style flows with 10 s and 60 s windows, calibrated to a 0.1% false-alarm budget on held-out benign traffic. This repository does not train the model. It packages it as a sensor, runs it next to Suricata in a self-hosted stack (Logstash with ECS, OpenSearch, MISP, Prometheus, Grafana), enriches its alerts with threat intelligence, and governs every change through pull requests, CI and AI configuration the student authors.

The model is the student's own work. It is the one with the best measured results among the models compared in the dissertation, and its training data was cleaned in the student's project for the Cybersecurity and Machine Learning course. [RISK-REGISTER.md](../RISK-REGISTER.md) summarises the cleaning rules, their measured effect and the known limits; `docs/model-card.md` records them in full (F3).

In scope: the detector container on pcap replay, the stack as code, detection content with tests, MISP and Shodan enrichment, monitoring, and the AI-assisted engineering workflow.
Out of scope: model training and research (dissertation repository), live capture on the student's Windows laptop (Docker Desktop cannot capture the host Wi-Fi), production deployment.

## 2. Risks addressed

The register comes first: [RISK-REGISTER.md](../RISK-REGISTER.md), ten rows across the three registers the module asks for:

- operational risk from the AI agent in the engineering loop: R-01, R-02, R-03, R-05;
- internal risk in the detection function: R-06, R-07, R-08;
- external risk from the threat landscape: R-04, R-09, R-10.

Each row names the asset, the technique (ATT&CK or ATLAS), likelihood and impact, the control in this repository, the residual score with its justification, and the evidence a reviewer can open.

## 3. GitHub route and governance

Route 2 of the syllabus: a personal private repository with GitHub Pro from GitHub Education. Rulesets `main-checks` (pull request, required checks, no force push or deletion, no bypass) and `main-review` (one approving review) protect `main`. The student authors every commit and pull request, with the agent as co-author when it helped. The agent works with a fine-grained token limited to this repository, and a separate GitHub App reviews pull requests from F7. It comments and sets a required check but never approves, so every merge stays the student's decision. Details: `docs/setup.md`, `docs/credentials.md`.

## 4. Architecture and components

*To write in F3*: diagram and description of the detector container, Suricata, Logstash pipelines, OpenSearch, MISP, Prometheus and Grafana, with the data flow from pcap to alert to enriched alert.

## 5. AI workflow

*To complete in F2*: `CLAUDE.md` and its imported memory, the skills, the `reviewer` sub-agent and model routing, the guard hook as the enforced safety rule, the memory-poisoning note (`docs/memory-poisoning.md`), and the automated pull-request review (F7).

## 6. Threat intelligence enrichment

*To write in F6*: MISP feeds and their lifecycle, the Logstash translate enrichment, the priority rule, Shodan exposure for the lab's own IP, and the evidence that enrichment changes an outcome.

## 7. Demonstration

*To write in F7*: what the recorded demonstration shows and how a reviewer reproduces it after cloning.
