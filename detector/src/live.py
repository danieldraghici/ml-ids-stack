"""Classify flows as they close, on live traffic or on a replayed capture.

    Source -> Extractor.live() -> batcher -> align -> clean -> predict -> alerts

What "live" means here, precisely
---------------------------------
A flow's features - Flow Duration, every IAT statistic, Active and Idle - are
only defined once the flow is over. Nothing can be scored until the flow ends,
either by FIN/RST or by hitting the flow timeout. So the detection latency of
this system is bounded below by the flow timeout (120 s by default, matching
what produced CIC-IDS2017), not by how fast the model runs: the model takes
about 0.4 us per flow, six orders of magnitude less. Calling this "real-time"
without that qualifier would be false. What it is, exactly, is per-flow-on-close.

Lowering --flow-timeout shortens that latency, but it also changes what every
timing feature means relative to the training data. That is a trade-off to
measure, not to assume - which is why the flag exists and why its value is
recorded in every alert.

Usage:
    # What can I capture on?
    python live.py --list-interfaces

    # Live capture, CICFlowMeter engine (exact CIC-IDS2017 feature semantics)
    python live.py --source "\\Device\\NPF_{...}" --model models/FINAL_xgb_xgb_latest.joblib

    # Reproducible demo: replay a capture through the same code path
    python live.py --replay data/traffic_captures/slowloris.pcap --extractor nfstream

    # Own traffic, so every alert is a false positive
    python live.py --source "\\Device\\NPF_{...}" --expect BENIGN
"""

import argparse
import json
import os
import queue
import signal
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.bundle import load_bundle, newest_bundle                 # noqa: E402
from core.inference import (                                       # noqa: E402
    NON_FEATURE_HINTS,
    align_features,
    check_profile,
    clean_features,
    predict_frame,
    print_alignment,
)
from core.paths import LOGS_DIR, relative                          # noqa: E402
from core.windows import WindowAggregator                          # noqa: E402
from core.windows import feature_names as window_feature_names     # noqa: E402
from extractors import for_profile, get_extractor, list_extractors  # noqa: E402
from extractors.base import ExtractorError                         # noqa: E402
from profiles import (                                             # noqa: E402
    DEFAULT_PROFILE,
    get_profile,
    profile_names,
    resolve_bundle_profile,
)

# Which label means "no attack" is the profile's business, not this script's:
# CIC-IDS2017 writes BENIGN, NF-v2 and Gotham write Benign, NSL-KDD writes
# normal. A fixed set here once made every benign NF-v2 flow an alert.


class StatusWriter:
    """A small JSON snapshot of the session, rewritten after every batch.

    The alert JSONL only holds what was flagged, so on its own it cannot say
    how much traffic was looked at - and a dashboard that shows 3 alerts
    without saying "out of 40,000 flows" is reporting half a number. Written
    to a temporary file and swapped in with os.replace(), so a reader never
    sees a half-written snapshot.
    """

    def __init__(self, path, context):
        self.path = path
        self.context = context

    def write(self, **state):
        if not self.path:
            return
        payload = dict(self.context)
        payload.update(state)
        payload["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        tmp = f"{self.path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, default=str)
            os.replace(tmp, self.path)
        except OSError:
            pass            # a missed snapshot is not worth stopping a capture


class FlowBatcher:
    """Collect flows off a blocking iterator and hand them over in batches.

    Batching is not an optimisation detail here, it is what makes the whole
    thing viable: predict_proba on 200 rows costs about what it costs on one,
    because the per-call overhead dominates a tree ensemble at this size. But a
    batch that only flushes when it is full would sit on a half-full buffer
    forever on a quiet link, so it also flushes on a deadline.

    The extractor's iterator blocks, so it runs on its own thread and pushes
    into a queue the consumer can poll with a timeout. That is the only way to
    honour the deadline without a timer interrupt.
    """

    def __init__(self, iterator, batch_size=200, batch_seconds=5.0, heartbeat=False):
        self.iterator = iterator
        self.batch_size = batch_size
        self.batch_seconds = batch_seconds
        # heartbeat: also yield an empty batch at every deadline, so a consumer
        # with its own clock (the window aggregator, live) runs on a quiet link.
        self.heartbeat = heartbeat
        self.queue = queue.Queue(maxsize=10000)
        self.stop_event = threading.Event()
        self.error = None
        self._thread = None

    def _pump(self):
        try:
            for record in self.iterator:
                if self.stop_event.is_set():
                    break
                try:
                    self.queue.put(record, timeout=1.0)
                except queue.Full:
                    # Dropping is the honest failure here. Blocking would stall
                    # the capture thread and silently lose packets inside the
                    # kernel instead, where nothing can count them.
                    pass
        except Exception as exc:                              # noqa: BLE001
            self.error = exc
        finally:
            self.queue.put(None)          # sentinel: the source is finished

    def start(self):
        self._thread = threading.Thread(target=self._pump, daemon=True,
                                        name="flow-source")
        self._thread.start()
        return self

    def stop(self):
        self.stop_event.set()

    def batches(self):
        """Yield lists of flow records, by size or by deadline."""
        batch = []
        deadline = time.monotonic() + self.batch_seconds

        while True:
            timeout = max(0.0, deadline - time.monotonic())
            try:
                record = self.queue.get(timeout=timeout)
            except queue.Empty:
                record = _EMPTY

            if record is None:                    # source exhausted
                if batch:
                    yield batch
                return

            if record is not _EMPTY:
                batch.append(record)

            expired = time.monotonic() >= deadline
            if len(batch) >= self.batch_size or (expired and batch):
                yield batch
                batch = []
                deadline = time.monotonic() + self.batch_seconds
            elif expired:
                if self.heartbeat:
                    yield []
                deadline = time.monotonic() + self.batch_seconds

            if self.stop_event.is_set():
                if batch:
                    yield batch
                return


_EMPTY = object()


class EpisodeTracker:
    """Alerts grouped into episodes: one source, one attack type, no long pause.

    A scan is a thousand flows and so a thousand flow alerts; an operator
    needs one line saying who, what, against whom, since when. Flows of the
    same (source, predicted type) whose end times are within GAP_S of the
    episode's last flow extend it; a longer pause starts a new one. Times are
    the flows' own end times, so a replay groups the same way as live.

    The episodes are rewritten as one JSON list after every batch (small, and
    a reader never sees a partial file thanks to os.replace).
    """

    GAP_S = 120
    MAX_LISTED = 20

    def __init__(self, path):
        self.path = path
        self.episodes = []
        self.open = {}
        self.dirty = False

    def add(self, label, confidence, ids, t_end_s):
        key = (ids.get("src_ip"), label)
        ep = self.open.get(key)
        if ep is None or t_end_s - ep["_last"] > self.GAP_S:
            ep = {"episode": len(self.episodes) + 1, "prediction": label,
                  "src_ip": ids.get("src_ip"), "_first": t_end_s, "_last": t_end_s,
                  "flows": 0, "max_confidence": 0.0,
                  "_dst": set(), "_ports": set(), "_sites": set(), "evidence": {}}
            self.episodes.append(ep)
            self.open[key] = ep
        ep["_first"] = min(ep["_first"], t_end_s)
        ep["_last"] = max(ep["_last"], t_end_s)
        ep["flows"] += 1
        if confidence is not None:
            ep["max_confidence"] = max(ep["max_confidence"], round(float(confidence), 4))
        ep["_dst"].add(ids.get("dst_ip"))
        ep["_ports"].add(ids.get("dst_port"))
        if ids.get("site"):
            ep["_sites"].add(ids["site"])
        for k, v in ids.items():
            if k.startswith("W") and isinstance(v, (int, float)):
                ep["evidence"][k] = max(ep["evidence"].get(k, 0), v)
        self.dirty = True

    def snapshot(self):
        def iso(t):
            return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds")
        out = []
        for ep in self.episodes:
            dst = sorted(str(d) for d in ep["_dst"] if d is not None)
            ports = sorted(int(p) for p in ep["_ports"] if p is not None and p == p)
            out.append({
                "episode": ep["episode"], "prediction": ep["prediction"], "src_ip": ep["src_ip"],
                "first_flow_end": iso(ep["_first"]), "last_flow_end": iso(ep["_last"]),
                "duration_s": round(ep["_last"] - ep["_first"], 1), "flows": ep["flows"],
                "destinations": len(dst), "dst_ip": ", ".join(dst[:self.MAX_LISTED]),
                "dst_ports": len(ports), "ports": ", ".join(map(str, ports[:self.MAX_LISTED])),
                "sites": ", ".join(sorted(ep["_sites"])[:self.MAX_LISTED]),
                "max_confidence": ep["max_confidence"], **ep["evidence"],
            })
        return out

    def write(self):
        if not self.path or not self.dirty:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.snapshot(), fh, default=str)
        os.replace(tmp, self.path)
        self.dirty = False


def site_name(record, names):
    """The website or service a flow went to, as nfstream's DPI saw it.

    requested_server_name is the TLS SNI, the HTTP Host or the DNS query -
    the name the client asked for, which an IP alone does not give. A flow
    without one (no handshake in it, e.g. a continuation record) borrows the
    name last seen for the same address on this capture.
    """
    sni = record.get("requested_server_name")
    if isinstance(sni, str) and sni.strip():
        return sni.strip()
    return names.get(record.get("dst_ip")) or names.get(record.get("src_ip")) or ""


class AlertSink:
    """Where a detection goes: the console, and a JSONL file if asked.

    JSONL rather than CSV because the alert stream is append-only and is read
    while it is still being written - a partially written line is a line a
    reader can skip, whereas a partially written CSV row is indistinguishable
    from a complete one.
    """

    def __init__(self, path=None, threshold=0.0, quiet=False, context=None):
        self.path = path
        self.threshold = threshold
        self.quiet = quiet
        self.context = context or {}
        self.handle = None
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
            self.handle = open(path, "a", encoding="utf-8")

    def emit(self, label, confidence, identifiers):
        if confidence is not None and confidence < self.threshold:
            return False

        record = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "prediction": label,
            "confidence": None if confidence is None else round(float(confidence), 4),
        }
        record.update(identifiers)
        record.update(self.context)

        if self.handle:
            self.handle.write(json.dumps(record, default=str) + "\n")
            self.handle.flush()

        if not self.quiet:
            who = " ".join(
                f"{k}={v}" for k, v in identifiers.items()
                if k.lower() in ("src ip", "src_ip", "dst ip", "dst_ip",
                                 "dst port", "dst_port", "protocol")
            )
            conf = "" if confidence is None else f"  p={confidence:.3f}"
            print(f"  [ALERT] {label:<24}{conf}  {who}", flush=True)
        return True

    def close(self):
        if self.handle:
            self.handle.close()


def identifiers_for(row, profile):
    """The fields that say which flow this was, carried into the alert."""
    wanted = profile.identifier_columns or NON_FEATURE_HINTS
    found = {}
    for key, value in row.items():
        if key.lower() in wanted and key.lower() not in ("label", "is_attack"):
            found[key] = value
    return found


def describe_setup(profile, extractor, bundle, bundle_path, coverage, source, args):
    print("=" * 70)
    print("LIVE FLOW DETECTION")
    print("=" * 70)
    print(f"  profile    : {profile.name} - {profile.description}")
    print(f"  extractor  : {extractor.name} - {extractor.description}")
    print(f"  model      : {relative(bundle_path)}")
    print(f"               {bundle['metadata']['model']} "
          f"({bundle['metadata']['target']}), "
          f"{len(bundle['label_encoder'].classes_)} classes")
    print(f"  source     : {source}")
    if extractor.name == "nfstream":
        # nfstream: idle_timeout = activity_timeout, active_timeout = flow_timeout
        print(f"  flow expiry: {extractor.activity_timeout:.0f}s without packets, "
              f"or {extractor.flow_timeout:.0f}s at most per flow record")
    else:
        print(f"  flow expiry: {extractor.flow_timeout:.0f}s idle-to-close, "
              f"{extractor.activity_timeout:.0f}s activity")

    if coverage is not None and not coverage.is_faithful():
        total = len(profile.feature_names or ())
        print(f"  fidelity   : {coverage.summary(total)}")
        if coverage.unavailable:
            print(f"               {len(coverage.unavailable)} feature(s) this "
                  f"extractor cannot measure will be zero-filled")
    else:
        print("  fidelity   : exact - this extractor produced the training set")

    print()
    print("  Detection latency is bounded by flow closure, not by the model:")
    print(f"  a flow is scored when it ends (FIN/RST) or after "
          f"{extractor.flow_timeout:.0f}s.")
    print("=" * 70 + "\n")


def run(args):
    profile = get_profile(args.profile)

    bundle_path = args.model or newest_bundle(
        profile=args.profile, resolver=resolve_bundle_profile)
    bundle = load_bundle(bundle_path)
    if args.decision_threshold is not None and hasattr(bundle["model"], "threshold"):
        # Set for this session only: the bundle on disk keeps its calibrated value.
        bundle["model"].threshold = float(args.decision_threshold)
        bundle["metadata"]["decision_threshold"] = float(args.decision_threshold)
        print(f"Decision threshold set to {args.decision_threshold} for this session\n")

    mismatch = check_profile(bundle, args.profile,
                             inferred=resolve_bundle_profile(bundle))
    if mismatch:
        print("STOPPING: profile mismatch\n")
        print(mismatch + "\n")
        return 1

    # Timeouts default to the profile's, because they are part of the schema:
    # the value of every duration and inter-arrival feature depends on them.
    # An explicit flag still wins - that is how the latency trade-off is
    # measured - and the value actually used is recorded in every alert.
    timeouts = {}
    if args.flow_timeout is not None:
        timeouts["flow_timeout"] = args.flow_timeout
    if args.activity_timeout is not None:
        timeouts["activity_timeout"] = args.activity_timeout

    try:
        extractor = for_profile(profile, args.extractor, **timeouts)
    except KeyError as exc:
        # KeyError stringifies through repr(), which would print the embedded
        # newlines literally. These messages are multi-line on purpose.
        print(f"STOPPING: {exc.args[0]}\n")
        return 1

    ok, problems = extractor.available()
    if not ok:
        print(f"STOPPING: extractor {extractor.name!r} cannot run here\n")
        for problem in problems:
            print(f"  - {problem}\n")
        return 1

    coverage = profile.coverage(extractor.name)
    fillable = coverage.fillable if coverage else frozenset()

    source = args.replay or args.source
    if not source:
        print("Nothing to read: pass --source <interface> or --replay <pcap>.")
        print("Run --list-interfaces to see what this machine can capture on.\n")
        return 2

    describe_setup(profile, extractor, bundle, bundle_path, coverage, source, args)

    # A model with features computed across flows cannot score a flow the
    # moment it closes: its 10 s / 60 s windows must be complete first. The
    # aggregator holds flows until the longest window they end in can no
    # longer change (window length + the idle timeout), then releases them
    # all at once; the profile's adapt() computes the window features over
    # the released flows exactly as it does over a whole capture offline
    # (core/windows.py; checked identical in notebooks/verify_windows.py).
    windows = tuple(getattr(profile, "windows", ()) or ())
    uses_windows = bool(windows) and bool(
        set(window_feature_names(windows)) & set(bundle["feature_names"]))
    aggregator = None
    if uses_windows:
        aggregator = WindowAggregator(schema="nfstream", windows=windows,
                                      grace_s=extractor.activity_timeout, compute=False)
        print(f"  windows    : {', '.join(f'{w}s' for w in windows)} per source and destination;"
              f" alerts follow a flow by up to {max(windows) + extractor.activity_timeout:.0f}s\n")
    evidence_cols = [c for c in ("W10_SRC_FLOWS", "W10_SRC_DST_HOSTS", "W10_SRC_FAIL_DST_PORTS",
                                 "W10_SRC_TOP_SERVICE", "W60_DST_SRC_HOSTS")
                     if c in bundle["feature_names"]]

    sink = AlertSink(args.out_jsonl, args.threshold, args.quiet,
                     context={"profile": profile.name,
                              "extractor": extractor.name,
                              "flow_timeout_s": extractor.flow_timeout})

    classes = list(bundle["label_encoder"].classes_)
    expect = profile.expect_label(args.expect, classes)

    status = StatusWriter(args.status_json, context={
        "profile": profile.name,
        "extractor": extractor.name,
        "model": os.path.basename(bundle_path),
        "source": source,
        "flow_timeout_s": extractor.flow_timeout,
        "activity_timeout_s": extractor.activity_timeout,
        "benign_label": profile.benign_label,
        "zero_filled": profile.zero_filled_for(bundle, extractor.name),
        "windows_s": list(windows) if uses_windows else [],
        "decision_threshold": bundle["metadata"].get("decision_threshold"),
        "pid": os.getpid(),
    })
    status.write(state="starting", n_flows=0, n_alerts=0, totals={}, elapsed_s=0)

    stop_event = threading.Event()

    def handle_signal(signum, frame):                          # noqa: ARG001
        print("\nStopping (finishing the current batch)...", flush=True)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    # The dashboard stops a capture with CTRL_BREAK_EVENT: on Windows that is
    # the only console signal a parent can send to one child process group,
    # and ending the session this way lets nfstream shut its meter process
    # down instead of leaving it capturing as an orphan.
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, handle_signal)

    iterator = extractor.live(source, stop_event=stop_event,
                              on_status=lambda m: print(f"  [{extractor.name}] {m}",
                                                        flush=True))
    is_live = not args.replay
    batcher = FlowBatcher(iterator, args.batch_size, args.batch_seconds,
                          heartbeat=is_live and aggregator is not None)
    batcher.stop_event = stop_event
    batcher.start()

    totals = Counter()
    n_flows = 0
    n_alerts = 0
    alignment_shown = False
    started = time.monotonic()

    n_unscored = 0
    n_midstream = 0
    episodes = EpisodeTracker(args.episodes_json)
    names = {}                      # address -> last server name seen for it
    capture_start_ms = time.time() * 1000
    # Live, connections already open when the capture starts are seen from
    # the middle: no SYN, and nfstream may take the server for the client
    # (the first packet it sees decides). Their direction and counts are
    # wrong, so for the first flow_timeout seconds a TCP flow with no SYN in
    # either direction feeds the windows but is not alerted on. Later, a TCP
    # flow without SYN is a continuation record of a flow seen from its start.
    warmup_ms = extractor.flow_timeout * 1000

    def flows_to_score(batch, flush=False):
        """Raw flow dicts ready to be scored now (all of them without windows)."""
        if aggregator is None:
            return pd.DataFrame(batch)
        for flow in batch:
            aggregator.add(flow)
        # Live, the wall clock closes windows a quiet link never would.
        return aggregator.ready(flush=flush, now_ms=time.time() * 1000 if is_live else None)

    def pending():
        return aggregator.pending() if aggregator is not None else 0

    def feed():
        """Batches from the source; at the end (or on stop) one flush of the
        windows still open, so the last flows of a replay are scored too."""
        for batch in batcher.batches():
            yield batch, False
            if args.duration and time.monotonic() - started >= args.duration:
                print(f"\n--duration {args.duration:.0f}s reached, stopping.", flush=True)
                stop_event.set()
            if stop_event.is_set():
                break
        if aggregator is not None:
            yield [], True

    try:
        for batch, flush in feed():
            raw = flows_to_score(batch, flush=flush)
            if raw.empty:
                status.write(state="running", n_flows=n_flows, n_alerts=n_alerts,
                             totals=dict(totals), pending_flows=pending(),
                             elapsed_s=round(time.monotonic() - started, 1))
                continue
            raw.columns = raw.columns.str.strip()
            records = raw.to_dict("records")
            # Renames are the alias map's job; columns needing arithmetic are
            # computed here, per batch, exactly as the batch path does them.
            df = profile.adapt(raw, extractor.name)
            unscored = (profile.unscored(df) if hasattr(profile, "unscored")
                        else np.zeros(len(df), dtype=bool))
            midstream = np.zeros(len(df), dtype=bool)
            if is_live and {"protocol", "src2dst_syn_packets", "dst2src_syn_packets",
                            "bidirectional_first_seen_ms"} <= set(raw.columns):
                def num(c):
                    return pd.to_numeric(raw[c], errors="coerce").fillna(0).to_numpy()
                midstream = ((num("protocol") == 6)
                             & (num("src2dst_syn_packets") == 0) & (num("dst2src_syn_packets") == 0)
                             & (num("bidirectional_first_seen_ms") < capture_start_ms + warmup_ms))
            n_midstream += int((midstream & ~unscored).sum())
            unscored = unscored | midstream
            for rec in records:
                sni = rec.get("requested_server_name")
                if isinstance(sni, str) and sni.strip() and rec.get("dst_ip"):
                    names[rec["dst_ip"]] = sni.strip()

            X, report = align_features(
                df, bundle["feature_names"],
                aliases=profile.aliases,
                fillable=fillable,
                identifiers=profile.identifier_columns or NON_FEATURE_HINTS,
            )

            if not alignment_shown:
                print_alignment(report, len(bundle["feature_names"]))
                alignment_shown = True

            if X is None:
                print("STOPPING: the extractor's columns do not match this "
                      "model's schema.\n")
                batcher.stop()
                return 1

            X = clean_features(X, quiet=True)
            labels, confidence, _ = predict_frame(bundle, X)

            n_flows += len(labels)
            totals.update(labels)

            n_unscored += int(unscored.sum())
            for i, label in enumerate(labels):
                if profile.is_benign(label) or unscored[i]:
                    continue
                conf = None if confidence is None else confidence[i]
                ids = identifiers_for(records[i], profile)
                ids["site"] = site_name(records[i], names)
                app = records[i].get("application_name")
                if isinstance(app, str) and app:
                    ids["application"] = app
                end_ms = records[i].get("bidirectional_last_seen_ms")
                has_end = end_ms is not None and end_ms == end_ms
                if has_end:
                    ids["flow_end"] = datetime.fromtimestamp(
                        float(end_ms) / 1000, tz=timezone.utc).isoformat(timespec="seconds")
                    if is_live:
                        ids["delay_s"] = round(time.time() - float(end_ms) / 1000, 1)
                # Why it fired, in the units an operator reads: what the
                # source did in the window this flow belongs to.
                for c in evidence_cols:
                    ids[c] = int(X[c].iloc[i])
                if sink.emit(label, conf, ids):
                    n_alerts += 1
                    episodes.add(label, conf, ids,
                                 float(end_ms) / 1000 if has_end else time.time())
            episodes.write()

            status.write(state="running", n_flows=n_flows, n_alerts=n_alerts,
                         totals=dict(totals), pending_flows=pending(),
                         unscored_flows=n_unscored, midstream_unscored=n_midstream,
                         n_episodes=len(episodes.episodes),
                         elapsed_s=round(time.monotonic() - started, 1))

            if not args.quiet:
                elapsed = time.monotonic() - started
                rate = n_flows / elapsed if elapsed else 0
                print(f"  {n_flows:,} flows | {n_alerts:,} alerts | "
                      f"{rate:.1f} flows/s | {elapsed:.0f}s elapsed"
                      + (f" | {pending():,} waiting for their window" if aggregator else ""),
                      flush=True)
    except ExtractorError as exc:
        print(f"\nExtractor failed: {exc}\n")
        status.write(state="failed", error=str(exc), n_flows=n_flows,
                     n_alerts=n_alerts, totals=dict(totals),
                     elapsed_s=round(time.monotonic() - started, 1))
        return 1
    finally:
        batcher.stop()
        sink.close()

    error = None
    if batcher.error:
        error = f"{type(batcher.error).__name__}: {batcher.error}"
        print(f"\nSource thread failed: {error}\n")

    elapsed = time.monotonic() - started
    status.write(state="failed" if error else "finished", error=error,
                 unscored_flows=n_unscored, midstream_unscored=n_midstream,
                 n_episodes=len(episodes.episodes),
                 n_flows=n_flows, n_alerts=n_alerts, totals=dict(totals),
                 elapsed_s=round(elapsed, 1))
    summarise(totals, n_flows, n_alerts, elapsed, expect, profile, sink)
    return 1 if error else 0


def summarise(totals, n_flows, n_alerts, elapsed, expect, profile, sink):
    print("\n" + "=" * 70)
    print("SESSION SUMMARY")
    print("=" * 70)
    print(f"  {n_flows:,} flows scored in {elapsed:.0f}s")
    if not n_flows:
        print("\n  No flows were scored. On a live interface that usually means")
        print("  no flow has closed yet - a flow is only emitted on FIN/RST or")
        print("  after the flow timeout, so a quiet link can take minutes.\n")
        return

    print(f"  {n_alerts:,} alert(s)\n")
    print(f"  {'class':<32} {'flows':>10} {'share':>9}")
    print("  " + "-" * 53)
    for name, count in totals.most_common():
        print(f"  {name:<32} {count:>10,} {count / n_flows * 100:>8.2f}%")

    if expect:
        wrong = n_flows - totals.get(expect, 0)
        print(f"\n  Expected everything to be {expect!r}")
        print(f"    NOT matching: {wrong:,} ({wrong / n_flows * 100:.2f}%)")
        if profile.is_benign(expect):
            print(f"    False positive rate: {wrong / n_flows * 100:.3f}%")
            if wrong:
                print("    On a network handling 1M flows/day that is roughly")
                print(f"    {wrong / n_flows * 1_000_000:,.0f} alerts per day.")

    if sink.path:
        print(f"\n  Alerts -> {sink.path}")
    print()


def print_interfaces():
    print("CAPTURE INTERFACES")
    print("-" * 70)
    shown = False
    for name, extractor, ok, problems in list_extractors():
        if not ok:
            print(f"  {name}: unavailable")
            for problem in problems:
                print(f"    {problem.splitlines()[0]}")
            continue
        if shown:
            continue
        try:
            for device, description in extractor.list_interfaces():
                print(f"  {description or '(no description)'}")
                print(f"      {device}")
            shown = True
        except ExtractorError as exc:
            print(f"  {name}: {exc}")
    print("-" * 70)
    print("\nPass one of the \\Device\\NPF_... names to --source.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Classify network flows as they close, live or replayed.")
    parser.add_argument("--profile", default=DEFAULT_PROFILE, choices=profile_names(),
                        help=f"dataset schema to serve (default: {DEFAULT_PROFILE})")
    parser.add_argument("--extractor", default=None,
                        help="flow extractor; default is the profile's first "
                             "declared one")
    parser.add_argument("--model", default=None,
                        help="bundle path (default: newest one for the profile)")

    source = parser.add_mutually_exclusive_group()
    source.add_argument("--source", default=None,
                        help="interface to capture on (see --list-interfaces)")
    source.add_argument("--replay", default=None,
                        help="pcap to replay through the live path instead of "
                             "capturing - the reproducible demo, and the only "
                             "way to show a detection without generating the "
                             "attack. nfstream only.")

    parser.add_argument("--list-interfaces", action="store_true",
                        help="show capturable interfaces and exit")
    parser.add_argument("--batch-size", type=int, default=200,
                        help="score at most this many flows per prediction call")
    parser.add_argument("--batch-seconds", type=float, default=5.0,
                        help="score a partial batch after this long (default: 5)")
    parser.add_argument("--flow-timeout", type=float, default=None,
                        help="seconds before an open flow is closed and scored "
                             "(default: the profile's - 120 for every profile "
                             "shipped). Lowering it cuts latency but shifts every "
                             "timing feature away from what the model was "
                             "trained on.")
    parser.add_argument("--activity-timeout", type=float, default=None,
                        help="seconds of silence that end an active period, or "
                             "close the flow for nfstream (default: the "
                             "profile's)")
    parser.add_argument("--threshold", type=float, default=0.0,
                        help="suppress alerts below this confidence (default: 0)")
    parser.add_argument("--episodes-json", default=None,
                        help="write alerts grouped into episodes (source + type) to this JSON file")
    parser.add_argument("--duration", type=float, default=None,
                        help="stop by itself after this many seconds (a timed live test)")
    parser.add_argument("--decision-threshold", type=float, default=None,
                        help="attack-probability threshold of a two-stage model (nfv3_window); "
                             "default: the one stored in the bundle, set on held-out benign")
    parser.add_argument("--out-jsonl", default=None,
                        help="append alerts to this JSONL file")
    parser.add_argument("--status-json", default=None,
                        help="rewrite a JSON snapshot of the session (flows "
                             "scored, per-class counts, state) after every "
                             "batch - what the dashboard's Live tab reads")
    parser.add_argument("--expect", default=None,
                        help="ground truth for the whole session, e.g. BENIGN "
                             "for your own traffic - turns the output into a "
                             "false-positive measurement. BENIGN works on every "
                             "profile, whatever the dataset calls it")
    parser.add_argument("--quiet", action="store_true",
                        help="summary only, no per-alert or progress lines")
    args = parser.parse_args()

    if args.list_interfaces:
        print_interfaces()
        return 0

    return run(args)


if __name__ == "__main__":
    # The guard is load-bearing, not decoration: nfstream's meter runs in a
    # spawned subprocess that re-imports this module, and without it the child
    # would start another capture of its own.
    raise SystemExit(main())
