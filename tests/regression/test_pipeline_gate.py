"""Detection gate, second half (R-06): the replay output survives the Logstash pipeline.

Every alert and episode `make gate` wrote goes through pipelines/mlids.conf in the pinned
Logstash. The gate fails if a record is lost, lands in mlids-error, or lacks a field the
detection content and the MISP lookup read: a renamed detector field would otherwise be
indexed and silently never match anything.
"""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logstash_harness import get, run_pipeline  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
BASE = json.loads((Path(__file__).parent / "baseline.json").read_text(encoding="utf-8"))
OUT = os.environ.get("REPLAY_OUT")
pytestmark = pytest.mark.skipif(not OUT, reason="no replay output: run `make gate` (REPLAY_OUT unset)")

ALERT_FIELDS = ["@timestamp", "source.ip", "source.port", "destination.ip", "destination.port",
                "rule.name", "event.kind", "event.dataset", "mlids.confidence"]
EPISODE_FIELDS = ["@timestamp", "source.ip", "rule.name", "event.start", "event.end",
                  "mlids.episode.alerts", "mlids.episode.families"]


def lines(suffix):
    out = []
    for name in sorted(BASE["fixtures"]):
        path = Path(ROOT, OUT, name.rsplit(".", 1)[0] + suffix)
        out += [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return out


@pytest.fixture(scope="module")
def result():
    alerts, eps = lines(".alerts.jsonl"), lines(".episodes.jsonl")
    events = run_pipeline(alerts + eps)
    return alerts, eps, events


def test_no_record_is_lost(result):
    alerts, eps, events = result
    assert len(events) == len(alerts) + len(eps)


def test_no_record_lands_in_the_error_index(result):
    bad = [e for e in result[2] if get(e, "test.index") == "mlids-error"]
    assert not bad, f"{len(bad)} records went to mlids-error, first: {json.dumps(bad[0])[:300]}"


def test_alerts_carry_every_field_the_rules_read(result):
    alerts, _, events = result
    for ev in events[:len(alerts)]:
        missing = [f for f in ALERT_FIELDS if get(ev, f) is None]
        assert not missing, f"alert without {missing}: {json.dumps(ev)[:300]}"


def test_episodes_carry_their_fields(result):
    alerts, eps, events = result
    for ev in events[len(alerts):]:
        assert get(ev, "event.dataset") == "mlids.episode"
        missing = [f for f in EPISODE_FIELDS if get(ev, f) is None]
        assert not missing, f"episode without {missing}"
