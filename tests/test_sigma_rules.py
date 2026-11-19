"""Detection as code (R-09): every Sigma rule fires on its positive sample and stays quiet on its
near misses, after the real Logstash pipeline has turned Suricata's EVE output into ECS.

The samples are what Suricata wrote for the synthetic fixtures, so a rule is tested against the
field names the pipeline really produces. A rule edited without reconverting its committed
OpenSearch query fails here too.
"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from logstash_harness import run_pipeline
from sigma_match import rule_matches

ROOT = Path(__file__).resolve().parent.parent
SIGMA = ROOT / "rules" / "sigma"
QUERIES = ROOT / "rules" / "opensearch"
SAMPLES = ROOT / "tests" / "samples"
RULES = sorted(SIGMA.glob("*.yml"))
# rule file -> (positive sample, negative sample): the negative holds the near misses
CASES = {
    "dns_long_txt.yml": ("suricata_dns_positive.jsonl", "suricata_dns_negative.jsonl"),
    "ssh_guessing_tool_client.yml": ("suricata_ssh_positive.jsonl", "suricata_ssh_negative.jsonl"),
}


def ecs(sample):
    lines = [l for l in (SAMPLES / sample).read_text().splitlines() if l.strip()]
    return run_pipeline(lines, pipeline="suricata")


@pytest.fixture(scope="module")
def mapped():
    return {s: ecs(s) for pair in CASES.values() for s in pair}


def test_every_rule_has_samples():
    assert {r.name for r in RULES} == set(CASES)


@pytest.mark.parametrize("rule", list(CASES))
def test_rule_fires_on_every_positive_event(rule, mapped):
    events = mapped[CASES[rule][0]]
    assert events and all(rule_matches(SIGMA / rule, ev) for ev in events)


@pytest.mark.parametrize("rule", list(CASES))
def test_rule_stays_quiet_on_the_near_misses(rule, mapped):
    events = mapped[CASES[rule][1]]
    assert events and not any(rule_matches(SIGMA / rule, ev) for ev in events)


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.name)
def test_rule_metadata(rule):
    r = yaml.safe_load(rule.read_text())
    assert re.fullmatch(r"[0-9a-f-]{36}", r["id"])
    assert any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in r["tags"]), "no ATT&CK technique tag"
    assert r["falsepositives"] and r["level"] and r["logsource"]["product"] == "suricata"


SIGMA_CLI = shutil.which("sigma") or shutil.which("sigma", path=str(Path(sys.executable).parent))


@pytest.mark.skipif(not SIGMA_CLI, reason="sigma-cli not installed (requirements-dev.txt)")
@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.name)
def test_committed_query_matches_the_rule(rule):
    out = subprocess.run([SIGMA_CLI, "convert", "-t", "opensearch_lucene", "--without-pipeline",
                          "-f", "dsl_lucene", str(rule)], capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == json.loads((QUERIES / (rule.stem + ".json")).read_text())
