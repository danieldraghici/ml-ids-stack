#!/usr/bin/env python3
"""Detector entry point: verify the model, then replay one pcap through the ML-IDS live path.

R-07: the model file is a pickle, and loading a tampered one runs its code. Its SHA-256 is
checked against thresholds.json before anything unpickles it; a mismatch stops the run.
R-06: the model is named in thresholds.json and the decision threshold comes from there,
the only place it is set. Nothing is picked by file date.

Usage (inside the container): run.py /pcaps/<file>.pcap
Writes <name>.alerts.jsonl, <name>.episodes.json and <name>.status.json to $OUT_DIR.
"""
import hashlib
import json
import os
import runpy
import sys

APP = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.environ.get("MODEL_DIR", "/models")
OUT_DIR = os.environ.get("OUT_DIR", "/out")
EXIT_USAGE, EXIT_MODEL = 2, 3


def load_config(path=os.path.join(APP, "thresholds.json")):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_model(conf, model_dir=MODEL_DIR):
    """Path of the model if its SHA-256 matches thresholds.json, else None (never unpickled)."""
    path = os.path.join(model_dir, conf["model"])
    if not os.path.isfile(path):
        print(f"detector: model {path} not found (make model)", file=sys.stderr)
        return None
    digest = sha256(path)
    if digest != conf["model_sha256"]:
        print(f"detector: REFUSED {path}: SHA-256 {digest} does not match thresholds.json "
              f"({conf['model_sha256']}); the file is not loaded", file=sys.stderr)
        return None
    print(f"detector: model verified, SHA-256 {digest[:16]}...")
    return path


def live_args(conf, model, pcap, out_dir=OUT_DIR):
    name = os.path.splitext(os.path.basename(pcap))[0]
    return ["live.py", "--profile", conf["profile"], "--model", model, "--replay", pcap,
            "--decision-threshold", repr(conf["decision_threshold"]),
            "--out-jsonl", os.path.join(out_dir, f"{name}.alerts.jsonl"),
            "--episodes-json", os.path.join(out_dir, f"{name}.episodes.json"),
            "--status-json", os.path.join(out_dir, f"{name}.status.json"),
            "--quiet"]


def main(argv):
    if len(argv) != 1:
        print("usage: run.py /pcaps/<file>.pcap", file=sys.stderr)
        return EXIT_USAGE
    conf = load_config()
    model = verify_model(conf)
    if model is None:
        return EXIT_MODEL
    sys.argv = live_args(conf, model, argv[0])
    sys.path.insert(0, os.path.join(APP, "src"))
    runpy.run_path(os.path.join(APP, "src", "live.py"), run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
