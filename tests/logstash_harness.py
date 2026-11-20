"""Run the real Logstash filters on sample records (R-06).

The image is the base of logstash/Dockerfile, pinned by digest, the same Logstash the stack
runs; the filters under test are the files the stack mounts. Records go in on stdin and come
back as JSON lines. Docker is required: these tests fail rather than skip without it, so a
broken mapping cannot pass CI unnoticed.
"""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FROM = re.search(r"^FROM\s+(\S+)", (ROOT / "logstash" / "Dockerfile").read_text(), flags=re.M)
IMAGE = FROM.group(1)


def run_pipeline(lines, pipeline="mlids", timeout=600, dictionary=None, workers=1):
    """Feed lines (strings) through tests/harness + pipelines/<pipeline>.conf; return the events.

    workers > 1 runs the filters on several threads, as the stack does, to catch shared state.
    With dictionary (a path to a translate dictionary), pipelines/threat-intel.conf runs after the
    mapping, reading that file as /enrich/ioc_ip.yml, as it does in the stack.
    """
    mounts = ["-v", f"{ROOT / 'tests' / 'harness' / '00-input.conf'}:/pipe/00-input.conf:ro",
              "-v", f"{ROOT / 'tests' / 'harness' / '99-output.conf'}:/pipe/99-output.conf:ro",
              "-v", f"{ROOT / 'pipelines' / (pipeline + '.conf')}:/pipe/10-{pipeline}.conf:ro"]
    if dictionary is not None:
        mounts += ["-v", f"{ROOT / 'pipelines' / 'threat-intel.conf'}:/pipe/20-threat-intel.conf:ro",
                   "-v", f"{Path(dictionary).resolve()}:/enrich/ioc_ip.yml:ro"]
    cmd = ["docker", "run", "--rm", "-i", "--network", "none", "--hostname", "localhost",
           "-e", f"PIPELINE={pipeline}", *mounts, IMAGE,
           "logstash", "-f", "/pipe", "--log.level=error", f"--pipeline.workers={workers}",
           "--pipeline.ecs_compatibility=v8"]
    out = subprocess.run(cmd, input="".join(l.rstrip("\n") + "\n" for l in lines),
                         capture_output=True, text=True, timeout=timeout, check=True).stdout
    return [json.loads(l) for l in out.splitlines() if l.startswith("{")]


def get(event, dotted):
    """Value at a dotted path, or None."""
    for key in dotted.split("."):
        if not isinstance(event, dict) or key not in event:
            return None
        event = event[key]
    return event
