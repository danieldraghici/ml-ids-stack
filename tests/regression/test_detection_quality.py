"""Detection gate (R-06): the replay of the lab fixtures is no worse than the baseline.

`make gate` replays every fixture through the hardened detector container into out/ and then
runs this file with REPLAY_OUT=out; the CI job detection-gate does the same on every pull
request. Without REPLAY_OUT (a plain `make test`) the tests are skipped, never passed.

A pull request fails if, on any fixture:
- detection on an attack fixture drops below 99% of its flows,
- the benign fixture raises more alerts than the baseline,
- an alert names the victim as its source,
- the flow count moves (extractor or fixture changed: update the baseline in a reviewed PR),
- the replay did not use the model and threshold pinned in detector/thresholds.json,
- an attack fixture is not exactly one episode with the attacker as its source (R-08).
"""
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASE = json.loads((Path(__file__).parent / "baseline.json").read_text(encoding="utf-8"))
CONF = json.loads((ROOT / "detector" / "thresholds.json").read_text(encoding="utf-8"))
OUT = os.environ.get("REPLAY_OUT")

pytestmark = pytest.mark.skipif(not OUT, reason="no replay output: run `make gate` (REPLAY_OUT unset)")
FIXTURES = sorted(BASE["fixtures"])


def stem(name):
    return name.rsplit(".", 1)[0]


def status(name):
    path = Path(ROOT, OUT, f"{stem(name)}.status.json")
    assert path.is_file(), f"{path} missing: the replay of {name} did not run"
    return json.loads(path.read_text(encoding="utf-8"))


def alerts(name):
    path = Path(ROOT, OUT, f"{stem(name)}.alerts.jsonl")
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.mark.parametrize("name", FIXTURES)
def test_replay_finished_with_the_pinned_model_and_threshold(name):
    s = status(name)
    assert s["state"] == "finished" and s["error"] is None, s
    assert s["model"] == CONF["model"]
    assert s["decision_threshold"] == CONF["decision_threshold"]


@pytest.mark.parametrize("name", FIXTURES)
def test_flow_count_unchanged(name):
    assert status(name)["n_flows"] == BASE["fixtures"][name]["flows"]


@pytest.mark.parametrize("name", FIXTURES)
def test_alert_file_matches_the_status(name):
    # live.py appends to the alert file, so a stale file from an earlier run shows here
    assert len(alerts(name)) == status(name)["n_alerts"]


@pytest.mark.parametrize("name", [n for n in FIXTURES if BASE["fixtures"][n]["kind"] == "attack"])
def test_attack_detection_at_least_99_percent(name):
    s = status(name)
    rate = s["n_alerts"] / s["n_flows"]
    assert rate >= BASE["min_detection"], f"{name}: detection {rate:.2%} < {BASE['min_detection']:.0%}"


@pytest.mark.parametrize("name", [n for n in FIXTURES if BASE["fixtures"][n]["kind"] == "attack"])
def test_no_alert_names_the_victim_as_source(name):
    victim = BASE["fixtures"][name]["victim"]
    wrong = [a for a in alerts(name) if a.get("src_ip") == victim]
    assert not wrong, f"{name}: {len(wrong)} alerts have the victim {victim} as source"


@pytest.mark.parametrize("name", [n for n in FIXTURES if BASE["fixtures"][n]["kind"] == "benign"])
def test_benign_alerts_not_above_baseline(name):
    got, allowed = status(name)["n_alerts"], BASE["fixtures"][name]["alerts"]
    assert got <= allowed, f"{name}: {got} alerts on benign traffic, baseline {allowed}"


def episodes(name):
    path = Path(ROOT, OUT, f"{stem(name)}.episodes.jsonl")
    assert path.is_file(), f"{path} missing: episodes.py did not run for {name}"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.mark.parametrize("name", [n for n in FIXTURES if BASE["fixtures"][n]["kind"] == "attack"])
def test_each_attack_is_one_episode_from_the_attacker(name):
    eps, fx = episodes(name), BASE["fixtures"][name]
    assert len(eps) == fx["episodes"], f"{name}: {len(eps)} episodes, expected {fx['episodes']}"
    assert eps[0]["src_ip"] == fx["attacker"]
    assert sum(e["alerts"] for e in eps) == status(name)["n_alerts"]


@pytest.mark.parametrize("name", [n for n in FIXTURES if BASE["fixtures"][n]["kind"] == "benign"])
def test_benign_episodes_not_above_baseline(name):
    got, allowed = len(episodes(name)), BASE["fixtures"][name]["episodes"]
    assert got <= allowed, f"{name}: {got} episodes on benign traffic, baseline {allowed}"
