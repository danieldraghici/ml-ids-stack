"""pipelines/suricata.conf in the real Logstash: Suricata 8 EVE becomes ECS (R-06, R-09).

The samples are real EVE lines Suricata wrote for the synthetic fixtures (tests/samples/
suricata_*.jsonl); the negative is a line that is not JSON.
"""
import json
import re
from pathlib import Path

import pytest

from logstash_harness import get, run_pipeline

SAMPLES = Path(__file__).resolve().parent / "samples"


def sample(name):
    return [l for l in (SAMPLES / f"suricata_{name}.jsonl").read_text().splitlines() if l.strip()]


@pytest.fixture(scope="module")
def events():
    names = ["alerts", "dns_positive", "dns_negative", "ssh_positive", "ssh_negative", "flow"]
    lines = {n: sample(n) for n in names}
    out = run_pipeline([l for n in names for l in lines[n]] + ["not json"], pipeline="suricata")
    assert len(out) == sum(len(v) for v in lines.values()) + 1
    grouped, i = {}, 0
    for n in names:
        grouped[n] = out[i:i + len(lines[n])]
        i += len(lines[n])
    grouped["broken"] = out[i:]
    return grouped, lines


def test_alert_maps_to_ecs_with_its_technique(events):
    grouped, lines = events
    for ev, raw in zip(grouped["alerts"], map(json.loads, lines["alerts"])):
        assert get(ev, "event.kind") == "alert" and get(ev, "event.dataset") == "suricata.alert"
        assert get(ev, "rule.id") == raw["alert"]["signature_id"]
        assert get(ev, "rule.name") == raw["alert"]["signature"]
        assert get(ev, "threat.technique.id") == raw["alert"]["metadata"]["mitre_technique_id"]
        assert get(ev, "source.ip") == raw["src_ip"] and get(ev, "destination.ip") == raw["dest_ip"]
        assert get(ev, "test.index") == "suricata"
        assert ev["@timestamp"].startswith(raw["timestamp"][:19])


def test_dns_answer_maps_to_ecs(events):
    grouped, lines = events
    (ev,), raw = grouped["dns_positive"], json.loads(lines["dns_positive"][0])
    assert get(ev, "dns.type") == "answer"
    assert get(ev, "dns.question.name") == raw["dns"]["queries"][0]["rrname"]
    assert get(ev, "dns.answers")[0] == {"name": raw["dns"]["answers"][0]["rrname"], "type": "TXT",
                                         "ttl": 60, "data": raw["dns"]["answers"][0]["rdata"]}


def test_dns_request_is_a_query_without_answers(events):
    grouped, _ = events
    queries = [e for e in grouped["dns_negative"] if get(e, "dns.type") == "query"]
    assert queries and all(get(e, "dns.answers") is None for e in queries)


def test_ssh_banners_map_to_ssh_fields(events):
    grouped, _ = events
    assert {get(e, "ssh.client.software_version") for e in grouped["ssh_positive"]} == {"libssh_0.10.6"}
    assert {get(e, "ssh.client.software_version") for e in grouped["ssh_negative"]} == {"OpenSSH_9.6p1"}
    assert all(get(e, "destination.port") == 22 for e in grouped["ssh_positive"])


def test_icmp_flow_keeps_type_and_counters(events):
    grouped, _ = events
    (ev,) = grouped["flow"]
    assert get(ev, "network.transport") == "icmp" and get(ev, "icmp.type") == 8
    assert get(ev, "source.packets") == 1 and get(ev, "event.category") == "network"


def test_every_record_has_a_stable_unique_id(events):
    grouped, _ = events
    ids = [get(e, "test.doc_id") for k, v in grouped.items() if k != "broken" for e in v]
    assert all(len(i) == 64 for i in ids) and len(set(ids)) == len(ids)


def test_line_that_is_not_json_goes_to_the_error_index(events):
    (ev,) = events[0]["broken"]
    assert "_jsonparsefailure" in ev["tags"] and get(ev, "test.index") == "suricata-error"


def test_document_ids_stay_unique_on_several_workers():
    """Each EVE record keeps its own document id when the filters run on several threads (R-06).

    A ruby filter variable named e was shared by all threads, so records took each other's id
    and overwrote each other in OpenSearch; the stack runs one worker per core.
    """
    base = json.loads(sample("flow")[0])
    lines = [json.dumps(dict(base, flow_id=10**15 + i, src_port=40000 + i % 20000)) for i in range(3000)]
    events = run_pipeline(lines, "suricata", workers=4)
    ids = {get(e, "test.doc_id") for e in events}
    assert len(events) == 3000 and len(ids) == 3000


def test_no_ruby_filter_uses_a_variable_named_e():
    """logstash-filter-ruby shares a variable named e across events and threads (see suricata.conf)."""
    for conf in (SAMPLES.parent.parent / "pipelines").glob("*.conf"):
        for block in re.findall(r"code => '(.*?)'", conf.read_text(), flags=re.S):
            assert not re.search(r"(?<![\w@\]])e\s*=[^=~]", block), f"{conf.name}: ruby variable e"


def test_reused_port_keeps_two_flow_records():
    """Two sessions on one reused source port share flow_id and timestamp, not flow.start (R-06)."""
    base = json.loads(sample("flow")[0])
    second = dict(base, flow=dict(base["flow"], start="2026-08-20T10:11:26.000000+0000"))
    events = run_pipeline([json.dumps(base), json.dumps(second)], "suricata")
    assert len({get(e, "test.doc_id") for e in events}) == 2
