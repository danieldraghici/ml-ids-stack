"""Episodes keyed by source (R-08): one attack is one line for the analyst."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("episodes", ROOT / "detector" / "episodes.py")
episodes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(episodes)

ATTACKER, VICTIM, OTHER = "192.168.20.11", "192.168.10.11", "192.168.20.12"


def alert(src, second, family="PortScan", port=80, conf=0.99, dst=VICTIM):
    minute, sec = divmod(second, 60)
    hour, minute = divmod(minute, 60)
    return {"src_ip": src, "dst_ip": dst, "dst_port": port, "prediction": family, "confidence": conf,
            "flow_end": f"2026-08-14T{20 + hour:02d}:{minute:02d}:{sec:02d}+00:00"}


def group(alerts):
    eps = episodes.Episodes()
    out = []
    for a in alerts:
        out += eps.add(a)
    return out + eps.flush()


def test_one_attack_with_two_families_is_one_episode():
    alerts = [alert(ATTACKER, s, "PortScan" if s < 60 else "DoS", port=s) for s in range(0, 120, 2)]
    (ep,) = group(alerts)
    assert ep["src_ip"] == ATTACKER and ep["alerts"] == 60
    assert ep["families"] == {"PortScan": 30, "DoS": 30}
    assert ep["dst_ips"] == [VICTIM] and ep["dst_ports"] == 60 and len(ep["ports"]) == 20


def test_a_pause_longer_than_the_gap_starts_a_new_episode():
    eps = group([alert(ATTACKER, 0), alert(ATTACKER, 100), alert(ATTACKER, 100 + 121)])
    assert [e["alerts"] for e in eps] == [2, 1]


def test_a_pause_of_exactly_the_gap_does_not():
    assert len(group([alert(ATTACKER, 0), alert(ATTACKER, 120)])) == 1


def test_sources_never_share_an_episode():
    eps = group([alert(ATTACKER, s) for s in range(0, 30, 3)] + [alert(OTHER, s) for s in range(1, 30, 3)])
    assert sorted(e["src_ip"] for e in eps) == [ATTACKER, OTHER]


def test_alerts_slightly_out_of_order_stay_in_one_episode():
    (ep,) = group([alert(ATTACKER, 50), alert(ATTACKER, 10), alert(ATTACKER, 90)])
    assert ep["first_flow_end"].endswith("20:00:10+00:00") and ep["duration_s"] == 80.0


def test_an_idle_source_closes_while_the_feed_goes_on():
    # streaming: the first source's episode is returned before the input ends
    eps = episodes.Episodes()
    assert eps.add(alert(ATTACKER, 0)) == []
    closed = eps.add(alert(OTHER, 200))
    assert [e["src_ip"] for e in closed] == [ATTACKER]
    assert [e["src_ip"] for e in eps.flush()] == [OTHER]


def test_episode_record_fields():
    (ep,) = group([alert(ATTACKER, 0, conf=0.9), alert(ATTACKER, 5, conf=0.97)])
    assert ep["episode_id"] == f"{ATTACKER}@2026-08-14T20:00:00+00:00"
    assert ep["max_confidence"] == 0.97 and ep["duration_s"] == 5.0


def test_cli_skips_broken_lines(tmp_path, capsys):
    src = tmp_path / "x.alerts.jsonl"
    src.write_text("\n".join([json.dumps(alert(ATTACKER, 0)), "not json", json.dumps({"src_ip": "x"}),
                              json.dumps(alert(ATTACKER, 3))]) + "\n")
    dst = tmp_path / "x.episodes.jsonl"
    assert episodes.main([str(src), str(dst)]) == 0
    (ep,) = [json.loads(l) for l in dst.read_text().splitlines()]
    assert ep["alerts"] == 2
    assert "2 alerts -> 1 episodes (2 lines skipped)" in capsys.readouterr().err
