"""Monitoring of the detection stack (R-06): the exporter, the detector's watch loop, the alert
rules and how compose.yaml runs them. promtool tests the rules' timing (make lint-ci); these
tests check what feeds them and that every rule has a case there.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


exporter = load("exporter", "monitoring/exporter.py")
watch = load("watch", "detector/watch.py")
SERVICES = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]


# ---------------------------------------------------------------- exporter

@pytest.fixture
def out(tmp_path):
    (tmp_path / "a.alerts.jsonl").write_text('{"x":1}\n{"x":2}\n\n')
    (tmp_path / "a.episodes.jsonl").write_text('{"e":1}\n')
    (tmp_path / "a.eve.json").write_text('{"s":1}\n{"s":2}\n{"s":3}\n')
    (tmp_path / "a.episodes.json").write_text('{"not":"read by Logstash"}\n')
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "b.alerts.jsonl").write_text('{"x":1}\n')
    return tmp_path


def test_records_are_counted_as_logstash_reads_them(out):
    # top level only, the two ML-IDS patterns and the EVE files, blank lines skipped
    assert exporter.out_records(str(out)) == {"mlids": (3, 0), "suricata": (3, 0)}


def test_an_unreadable_file_is_counted_not_fatal(out):
    # a file deleted between glob and open, or not readable by the exporter's user
    assert exporter.count_lines([str(out / "a.eve.json"), str(out / "gone.eve.json")]) == (3, 1)
    m = metrics(exporter.collect(str(out), down, down))
    assert m[("mlids_out_unreadable_files", (("pipeline", "suricata"),))] == 0


def opensearch(status="yellow", counts=None):
    counts = counts or {"mlids-*": 3, "suricata-*": 3}

    def get(path):
        if path == "/_cluster/health":
            return {"status": status}
        return {"count": counts[path.strip("/").split("/")[0]]}
    return get


def down(path):
    raise OSError("connection refused")


def metrics(samples):
    return {(n, tuple(sorted(l.items()))): v for n, l, v in samples}


def test_a_healthy_stack(out):
    (out / "heartbeat.json").write_text(json.dumps({"ts": 1000.5, "processed": 2, "failed": 1}))
    m = metrics(exporter.collect(str(out), opensearch(), lambda p: {}))
    assert m[("mlids_detector_heartbeat_timestamp_seconds", ())] == 1000.5
    assert m[("mlids_detector_captures_processed", ())] == 2 and m[("mlids_detector_captures_failed", ())] == 1
    assert m[("opensearch_up", ())] == 1 and m[("opensearch_cluster_status", ())] == 1
    assert m[("mlids_indexed_documents", (("pipeline", "suricata"),))] == 3
    assert m[("logstash_up", ())] == 1


def test_a_silent_source_gives_up_0_and_no_stale_numbers(out):
    (out / "heartbeat.json").write_text("{not json")
    m = metrics(exporter.collect(str(out), down, down))
    assert m[("opensearch_up", ())] == 0 and m[("logstash_up", ())] == 0
    names = {n for n, _ in m}
    assert "mlids_detector_heartbeat_timestamp_seconds" not in names     # SensorDown sees absent()
    assert "mlids_indexed_documents" not in names and "opensearch_cluster_status" not in names
    assert "mlids_out_records" in names                                   # out/ is still read


def test_a_red_or_unknown_cluster_counts_as_red(out):
    assert metrics(exporter.collect(str(out), opensearch("red"), down))[("opensearch_cluster_status", ())] == 2
    assert metrics(exporter.collect(str(out), opensearch("purple"), down))[("opensearch_cluster_status", ())] == 2


def test_exposition_format():
    text = exporter.render([("mlids_out_records", {"pipeline": "mlids"}, 3),
                            ("mlids_out_records", {"pipeline": "suricata"}, 4), ("logstash_up", {}, 1)])
    lines = text.splitlines()
    assert lines.count("# TYPE mlids_out_records gauge") == 1
    assert 'mlids_out_records{pipeline="mlids"} 3' in lines and "logstash_up 1" in lines
    assert all(name in exporter.HELP for name in re.findall(r"^# TYPE (\S+)", text, re.M))


def test_feed_age_and_exposure_without_the_address(tmp_path):
    enrich, exposure = tmp_path / "enrich", tmp_path / "exposure"
    enrich.mkdir(); exposure.mkdir()
    (enrich / "ioc_ip.meta.json").write_text(json.dumps({
        "pulled_at": "2026-11-21T12:00:00+00:00", "result": "empty pull: previous dictionary kept",
        "dictionary_written_at": "2026-11-20T12:00:00+00:00", "dictionary_indicators": 24346, "indicators": 0}))
    (exposure / "changes.json").write_text(json.dumps({
        "baseline": False, "opened": [22, 8080], "closed": [], "checked_at": "2026-11-21T03:41:00+00:00"}))
    m = metrics(exporter.intel(str(enrich), str(exposure)))
    assert m[("mlids_ioc_dictionary_timestamp_seconds", ())] == 1795176000.0      # the dictionary's date, not the empty pull's
    assert m[("mlids_ioc_last_pull_timestamp_seconds", ())] == 1795262400.0
    assert m[("mlids_ioc_indicators", ())] == 24346
    assert m[("mlids_exposure_ports_opened", ())] == 2 and m[("mlids_exposure_ports_closed", ())] == 0
    assert all("ip" not in name for name, _ in m)                                  # counts and times only


def test_no_feed_and_no_check_leave_the_metrics_out(tmp_path):
    # absent() then fires IocFeedStale and ExposureCheckStale: no feed is a stale feed
    assert exporter.intel(str(tmp_path / "none"), str(tmp_path / "none")) == []
    (tmp_path / "ioc_ip.meta.json").write_text(json.dumps({"pulled_at": "2026-11-21T12:00:00+00:00",
                                                           "result": "empty pull: previous dictionary kept"}))
    names = {n for n, _, _ in exporter.intel(str(tmp_path), str(tmp_path / "none"))}
    assert names == {"mlids_ioc_last_pull_timestamp_seconds"}


def test_the_exporter_reads_the_intel_outputs_read_only():
    vols = SERVICES["exporter"]["volumes"]
    assert any(v.startswith("./enrich:/enrich:ro") for v in vols) and any(v.startswith("./exposure:/exposure:ro") for v in vols)


@pytest.fixture
def crontab(tmp_path):
    """A stand-in crontab command that keeps the table in a file."""
    table, bin_dir = tmp_path / "table", tmp_path / "bin"
    bin_dir.mkdir()
    table.write_text("0 1 * * * echo the student's own job\n")
    (bin_dir / "crontab").write_text(
        '#!/usr/bin/env bash\nif [ "$1" = "-l" ]; then cat "$TABLE"; else data=$(cat); printf "%s\\n" "$data" > "$TABLE"; fi\n')
    (bin_dir / "crontab").chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", TABLE=str(table))

    def make(target):
        return subprocess.run(["make", "--no-print-directory", "-C", str(ROOT), target], env=env,
                              capture_output=True, text=True, check=True)
    return table, make


def test_schedule_installs_its_two_jobs_once_and_unschedule_removes_only_them(crontab):
    table, make = crontab
    make("schedule"); make("schedule")
    lines = table.read_text().splitlines()
    ours = [l for l in lines if l.endswith("# ml-ids-stack schedule")]
    assert len(ours) == 2 and "0 1 * * * echo the student's own job" in lines
    assert ours[0].startswith("17 */6 * * * ") and "make misp-pull" in ours[0]      # every 6 hours
    assert ours[1].startswith("41 3 * * 1 ") and "make exposure" in ours[1]        # Mondays
    assert all("PATH=/usr/local/bin:/usr/bin:/bin " in l for l in ours)
    make("unschedule")
    assert table.read_text().splitlines() == ["0 1 * * * echo the student's own job"]


# ---------------------------------------------------------------- detector watch loop

@pytest.fixture
def dirs(tmp_path):
    inbox, outd = tmp_path / "inbox", tmp_path / "out"
    inbox.mkdir(); outd.mkdir()

    def drop(name, age=100, data=b"x"):
        (inbox / name).write_bytes(data)
        os.utime(inbox / name, (1000 - age, 1000 - age))
        return str(inbox / name)
    return inbox, outd, drop


def names(paths):
    return [Path(p).name for p in paths]


def test_pending_skips_done_growing_and_other_files(dirs):
    inbox, outd, drop = dirs
    for name, age in [("old.pcap", 100), ("new.pcapng", 50), ("done.pcap", 100), ("growing.pcap", 1), ("notes.txt", 100)]:
        drop(name, age)
    watch.mark_done(str(outd), str(inbox / "done.pcap"))
    assert names(watch.pending(str(inbox), str(outd), now=1000)) == ["old.pcap", "new.pcapng"]


def test_a_new_file_under_a_replayed_name_is_replayed(dirs):
    # make replay left hulk.status.json, and an earlier hulk.pcap was replayed from the inbox:
    # neither hides a new hulk.pcap with other content
    inbox, outd, drop = dirs
    (outd / "hulk.status.json").write_text("{}")
    path = drop("hulk.pcap", 100, b"first")
    assert names(watch.pending(str(inbox), str(outd), now=1000)) == ["hulk.pcap"]
    watch.mark_done(str(outd), path)
    assert watch.pending(str(inbox), str(outd), now=1000) == []
    drop("hulk.pcap", 50, b"second capture")
    assert names(watch.pending(str(inbox), str(outd), now=1000)) == ["hulk.pcap"]


def test_the_marker_records_the_version_that_ran(dirs):
    # the file is replaced while its replay runs: the new content must not count as done
    inbox, outd, drop = dirs
    path = drop("scan.pcap", 100, b"first")
    replayed = watch.fingerprint(path)
    drop("scan.pcap", 50, b"replaced during the replay")
    watch.mark_done(str(outd), path, replayed)
    assert names(watch.pending(str(inbox), str(outd), now=1000)) == ["scan.pcap"]
    assert watch.version(replayed) != watch.version(watch.fingerprint(path))   # a failed copy is retried once complete


def test_a_capture_that_would_overwrite_another_is_refused(dirs):
    inbox, outd, drop = dirs
    watch.mark_done(str(outd), drop("a.pcap"))
    assert watch.conflict(str(outd), drop("a.pcapng")) == "a.pcap"
    assert watch.conflict(str(outd), str(inbox / "a.pcap")) is None


def test_a_capture_deleted_while_listed_is_skipped(dirs, monkeypatch):
    inbox, outd, drop = dirs
    drop("gone.pcap"); drop("kept.pcap")
    real = os.stat
    monkeypatch.setattr(watch.os, "stat",
                        lambda p, *a, **k: (_ for _ in ()).throw(FileNotFoundError(p)) if str(p).endswith("gone.pcap") else real(p, *a, **k))
    assert names(watch.pending(str(inbox), str(outd), now=1000)) == ["kept.pcap"]


def test_a_capture_goes_through_run_then_episodes(tmp_path):
    calls = []
    run = lambda argv, timeout: calls.append((argv, timeout)) or NS(returncode=0)
    assert watch.process("/inbox/scan.pcap", "/out", run, timeout=60) == 0
    (first, t1), (second, t2) = calls
    assert first[1].endswith("/run.py") and first[2] == "/inbox/scan.pcap" and t1 == 60
    assert second[1].endswith("/episodes.py") and second[2:] == ["/out/scan.alerts.jsonl", "/out/scan.episodes.jsonl"]


def test_a_replay_starts_from_clean_outputs(tmp_path):
    for suffix in ("alerts.jsonl", "episodes.jsonl", "status.json"):
        (tmp_path / f"scan.{suffix}").write_text("old run")
    seen = []
    run = lambda argv, timeout: seen.append(sorted(p.name for p in tmp_path.iterdir())) or NS(returncode=0)
    watch.process("/inbox/scan.pcap", str(tmp_path), run)
    assert seen[0] == []     # nothing left for the detector to append to


def test_a_refused_capture_stops_before_episodes():
    calls = []
    run = lambda argv, timeout: calls.append(argv) or NS(returncode=3)     # model refused (run.py EXIT_MODEL)
    assert watch.process("/inbox/scan.pcap", "/out", run) == 3 and len(calls) == 1


def test_a_hung_replay_is_killed_and_fails():
    def run(argv, timeout):
        raise watch.subprocess.TimeoutExpired(argv, timeout)
    assert watch.process("/inbox/scan.pcap", "/out", run, timeout=1) == watch.EXIT_TIMEOUT


def test_a_stuck_main_loop_stops_the_heartbeat():
    # beats while the loop progressed within STALL_S (longer than the two timed steps of a replay)
    assert watch.STALL_S > 2 * watch.REPLAY_TIMEOUT_S
    assert watch.alive(progress=1000, now=1000 + watch.STALL_S)
    assert not watch.alive(progress=1000, now=1001 + watch.STALL_S)


def test_heartbeat_is_whole_json_with_the_time(tmp_path):
    watch.beat(str(tmp_path), {"processed": 4}, now=1700000000)
    doc = json.loads((tmp_path / "heartbeat.json").read_text())
    assert doc["ts"] == 1700000000 and doc["processed"] == 4 and doc["time"].startswith("2023-11-14T22:13:20")
    assert not list(tmp_path.glob(".*.tmp"))


# ---------------------------------------------------------------- rules and compose

def test_every_alert_has_a_promtool_case_and_a_risk():
    rules = [r for g in yaml.safe_load((ROOT / "monitoring/alerts.yml").read_text())["groups"] for r in g["rules"]]
    tested = set(re.findall(r"alertname: (\w+)", (ROOT / "monitoring/alerts.test.yml").read_text()))
    assert {"SensorDown", "PipelineStalled", "OpenSearchDown", "ExporterDown",
            "IocFeedStale", "ExposureChanged", "ExposureCheckStale"} <= {r["alert"] for r in rules}
    for rule in rules:
        assert rule["alert"] in tested, f"{rule['alert']} has no promtool test"
        assert rule["labels"]["risk"] in ("R-06", "R-10")


def test_the_detector_service_keeps_the_replay_hardening():
    d = SERVICES["detector"]
    assert d["read_only"] is True and d["network_mode"] == "none" and d["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in d["security_opt"]
    assert "./models:/models:ro" in d["volumes"] and "./inbox:/inbox:ro" in d["volumes"]
    assert "ports" not in d


def test_the_exporter_reads_out_only_as_its_own_opensearch_user():
    e = SERVICES["exporter"]
    assert e["read_only"] is True and e["cap_drop"] == ["ALL"] and "ports" not in e
    assert "./out:/out:ro" in e["volumes"]
    assert e["environment"]["OPENSEARCH_USER"] == "monitor"
    assert e["environment"]["OPENSEARCH_PASSWORD"] == "${OPENSEARCH_MONITOR_PASSWORD:?run make secrets}"
    assert e["image"].split("@")[1] in (ROOT / "detector/Dockerfile").read_text()   # scanned with the detector


def test_the_monitor_role_reads_health_and_the_stack_indices_only():
    role = json.loads((ROOT / "config/opensearch/stack-monitor-role.json").read_text())
    assert role["cluster_permissions"] == ["cluster:monitor/health"]
    (grant,) = role["index_permissions"]
    assert grant["index_patterns"] == ["mlids-*", "suricata-*"] and "*" not in grant["index_patterns"]
    assert grant["allowed_actions"] == ["indices:data/read/search"]
    assert "monitor-user.sh" in (ROOT / "Makefile").read_text()      # written on every make up


def test_grafana_only_through_the_front_door_with_a_sops_password():
    g = SERVICES["grafana"]
    assert "ports" not in g
    assert g["environment"]["GF_SECURITY_ADMIN_PASSWORD"] == "${GRAFANA_ADMIN_PASSWORD:?run make secrets}"
    assert g["environment"]["GF_AUTH_ANONYMOUS_ENABLED"] == "false"
    assert "location /grafana/" in (ROOT / "nginx/frontdoor.conf").read_text()


# ---------------------------------------------------------------- scripts/monitor-user.sh

@pytest.fixture
def stack(tmp_path):
    """A copy of what monitor-user.sh reads, and a stub curl that records its stdin and answers CODE."""
    (tmp_path / "config/opensearch").mkdir(parents=True)
    shutil.copy(ROOT / "config/opensearch/stack-monitor-role.json", tmp_path / "config/opensearch")
    (tmp_path / ".env").write_text("OPENSEARCH_PORT=9200\n")
    # the format make secrets writes: KEY=value, unquoted; the admin password tries to run a command
    (tmp_path / ".env.secrets").write_text("OPENSEARCH_INITIAL_ADMIN_PASSWORD=ad\"m\\in$(touch PWNED);x\nOPENSEARCH_MONITOR_PASSWORD=mo\"n\\itor\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    curl.write_text('#!/usr/bin/env bash\ncat >> "$STUB_LOG"; echo >> "$STUB_LOG"; printf "%s" "$CODE"\n')
    curl.chmod(0o755)

    def run(code):
        env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", STUB_LOG=str(tmp_path / "stdin.log"), CODE=code)
        result = subprocess.run(["bash", str(ROOT / "scripts/monitor-user.sh")], cwd=tmp_path, env=env,
                                capture_output=True, text=True)
        return result, (tmp_path / "stdin.log").read_text()
    return run


def curl_config_value(line):
    """What curl makes of `key = "value"` in its config: \\" is a quote, \\\\ a backslash."""
    raw = line.split(" = ", 1)[1]
    assert raw.startswith('"') and raw.endswith('"')
    return re.sub(r'\\(.)', r'\1', raw[1:-1])


def test_monitor_user_written_with_escaped_passwords_on_stdin(stack):
    result, stdin = stack("201")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["PUT roles/stack_monitor: 201", "PUT internalusers/monitor: 201"]
    lines = stdin.splitlines()
    assert curl_config_value(lines[0]) == 'admin:ad"m\\in$(touch PWNED);x'    # passed on as it is
    role = json.loads(curl_config_value(lines[1]))
    assert role["cluster_permissions"] == ["cluster:monitor/health"]
    user = json.loads(curl_config_value(lines[4]))
    assert user == {"password": 'mo"n\\itor', "opendistro_security_roles": ["stack_monitor"]}


def test_secrets_are_read_as_data_never_run(stack, tmp_path):
    stack("200")
    assert not (tmp_path / "PWNED").exists()


def test_monitor_user_fails_when_opensearch_refuses(stack):
    result, _ = stack("403")
    assert result.returncode != 0 and "PUT roles/stack_monitor: 403" in result.stdout
