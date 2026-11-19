"""Detection gate, Suricata and Sigma (R-09): each local rule and each Sigma rule fires on its own
fixture, as often as the baseline records, and nowhere else.

`make gate` runs Suricata on every fixture; the EVE output then goes through the real Logstash
pipeline and the Sigma rules are applied to what comes out, as they would be in OpenSearch.
A rule that stops firing, or starts firing on a near miss or on the lab captures, fails the PR.
"""
import json
import os
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logstash_harness import get, run_pipeline  # noqa: E402
from sigma_match import rule_matches  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
BASE = json.loads((Path(__file__).parent / "baseline.json").read_text(encoding="utf-8"))
OUT = os.environ.get("REPLAY_OUT")
SIGMA = ROOT / "rules" / "sigma"
pytestmark = pytest.mark.skipif(not OUT, reason="no replay output: run `make gate` (REPLAY_OUT unset)")
FIXTURES = sorted(BASE["fixtures"])


def eve(name):
    path = Path(ROOT, OUT, name.rsplit(".", 1)[0] + ".eve.json")
    assert path.is_file(), f"{path} missing: Suricata did not run on {name}"
    return [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


@pytest.mark.parametrize("name", FIXTURES)
def test_suricata_alerts_match_the_baseline(name):
    sids = Counter(str(json.loads(l)["alert"]["signature_id"]) for l in eve(name)
                   if json.loads(l).get("event_type") == "alert")
    assert dict(sids) == BASE["fixtures"][name]["suricata"], f"{name}: Suricata alerts {dict(sids)}"


@pytest.mark.parametrize("name", [n for n in FIXTURES if BASE["fixtures"][n]["suricata"]])
def test_suricata_alerts_name_the_attacker(name):
    srcs = {json.loads(l)["src_ip"] for l in eve(name) if json.loads(l).get("event_type") == "alert"}
    assert srcs == {BASE["fixtures"][name]["attacker"]}


@pytest.fixture(scope="module")
def mapped():
    # Only the event types the Sigma rules read; flow records would only slow Logstash down.
    lines, owner = [], []
    for name in FIXTURES:
        for l in eve(name):
            if json.loads(l).get("event_type") in ("dns", "ssh", "alert"):
                lines.append(l)
                owner.append(name)
    events = run_pipeline(lines, pipeline="suricata")
    assert len(events) == len(lines)
    return list(zip(owner, events))


def test_no_suricata_record_lands_in_the_error_index(mapped):
    bad = [n for n, e in mapped if get(e, "test.index") != "suricata"]
    assert not bad, f"{len(bad)} records in suricata-error, from {sorted(set(bad))}"


@pytest.mark.parametrize("rule", sorted(p.name for p in SIGMA.glob("*.yml")))
def test_sigma_rule_fires_only_on_its_fixture(rule, mapped):
    hits = Counter(n for n, e in mapped if rule_matches(SIGMA / rule, e))
    expected = {n: fx["sigma"][rule] for n, fx in BASE["fixtures"].items() if rule in fx["sigma"]}
    assert dict(hits) == expected, f"{rule}: hits {dict(hits)}, expected {expected}"
