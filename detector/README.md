# Detector

The ML-IDS sensor from the student's dissertation, packaged to replay pcaps in a hardened container. This repository does not train it.

## Where the code comes from

`src/` holds the 16 files the dissertation's `live.py --replay` loads for the `nfv3_window` profile with the `nfstream` extractor, found by recording the modules a real replay imported. They are copied unchanged from the dissertation workspace (`ML_IDS_Disertation/src/`, branch `feat/realtime-profiles`, working tree of 2026-11-17, not yet committed there). The only change is line endings, CRLF to LF. `SOURCES.tsv` lists, for each file, the SHA-256 of the dissertation file as it was on disk and the SHA-256 of the copy here; `tests/test_detector.py` fails if a copy changes without that table being updated.

## The model

- `nfv3_window_xgb_latest.joblib`, 4.42 MB, SHA-256 in `thresholds.json`. A two-stage XGBoost on 66 features: per-flow NetFlow fields plus 10 s and 60 s windows keyed by source and destination IP (IPs are keys, never features).
- Decision threshold 0.005151937318725348, calibrated for a 0.1% false-alarm budget on 53,852 held-out benign flows from CICIoT2023, not on the lab network.
- It never enters git (`.gitignore`). `make model` copies it from the dissertation workspace into `models/` and checks the SHA-256. From F4 it comes as a signed release asset.

## How it runs

`make replay PCAP=<file>` builds the image and runs one fixture from `tests/fixtures/pcaps/`:

- the container is read-only, has no network and no capabilities, runs as the invoking user, and sees the model read-only;
- `run.py` hashes the model and refuses to start if the SHA-256 differs from `thresholds.json`, before anything unpickles it (R-07; `docs/evidence/R-07-tampered-model-refused.txt`);
- the model and the threshold come from `thresholds.json` only; nothing is picked by file date (R-06);
- results land in `out/<name>.alerts.jsonl`, `out/<name>.episodes.json` and `out/<name>.status.json`.

Baseline per fixture: `tests/fixtures/pcaps/README.md` and `docs/evidence/R-06-replay-baseline.txt`.

## Known limits (R-08)

- One attack shows up under several families (the Hulk flood as DoS and DoS-Slow); detection holds, the label does not.
- Server-to-client continuation flows can be scored as coming from the victim, so the victim may appear as a source in episodes.
- False alarms on benign traffic depend on the network: 2 of 43 flows on the benign fixture, 0.2-0.4% on held-out CICIoT2023 benign, far more on networks the threshold was not calibrated for.

`detector/thresholds.json` and `models/` are protected from agent edits by the guard hook; they change only by the student, in a reviewed pull request.
