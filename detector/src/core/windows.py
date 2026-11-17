"""Features computed across flows: what one host did in the last few seconds.

A single NetFlow record cannot show a port scan. Each probe is a one-packet
flow that looks like any short benign connection - after cleaning, 95% of
NF-ToN-IoT-v2 scanning is byte-for-byte identical to benign traffic. The scan
exists only in the aggregate: one source touching hundreds of ports. The same
holds for floods (one destination, many flows) and, partly, for slow DoS
(many long connections from one source). Dube (2024) names this as the reason
per-flow models over summarised data cannot match a production IDS.

Every flow is given the statistics of its time window:

  W{s}_SRC_FLOWS      flows started by the same source in the window
  W{s}_SRC_DST_HOSTS  distinct destinations it contacted
  W{s}_SRC_DST_PORTS  distinct destination ports it contacted
  W{s}_SRC_NO_REPLY   share of its flows the other side never answered
  W{s}_SRC_SYN_ONLY   share of its flows whose client sent SYN and nothing else
  W{s}_SRC_RST        share of its flows the server reset
  W{s}_DST_FLOWS      flows received by the same destination in the window
  W{s}_DST_SRC_HOSTS  distinct sources that contacted that destination
  W{s}_SRC_FAIL_DST_HOSTS  distinct destinations among the source's failed flows
  W{s}_SRC_FAIL_DST_PORTS  distinct destination ports among its failed flows
  W{s}_SRC_TOP_SERVICE     flows to its most-contacted (destination, port) pair

A failed flow is one the other side never answered, reset, or that carried a
lone SYN. The two FAIL counts separate a scan from a busy client: a scanner
fails on most of the ports and hosts it touches, while a device asking twelve
NTP servers for the time gets twelve answers. Without them a model leaned on
SRC_DST_HOSTS alone and flagged 83% of CICIoT2023's benign NTP traffic.
TOP_SERVICE is repetition against one service - a brute force's many logins
to one SSH server, or a flood's many connections to one web server.

Windows are tumbling, aligned to the epoch, and keyed on the time a flow
ENDED. That choice is what makes the offline and the live values identical:
live, a flow is known only once it ends, so a window can be closed - and its
flows scored - once every flow ending inside it has been emitted, i.e. window
length plus the extractor's idle timeout after the window starts. A sliding
window keyed on start time would need flows that, live, have not ended yet.
The cost is latency: an alert can wait up to W + idle timeout seconds.

Counts are behaviour, not identity: no address or port value enters a feature,
only how many distinct ones there were.
"""

import numpy as np
import pandas as pd

#: Window lengths in seconds. Short enough to catch a scan while it runs, long
#: enough that a slow DoS's connections accumulate.
DEFAULT_WINDOWS = (10, 60)

FEATURE_STEMS = ("SRC_FLOWS", "SRC_DST_HOSTS", "SRC_DST_PORTS", "SRC_NO_REPLY",
                 "SRC_SYN_ONLY", "SRC_RST", "DST_FLOWS", "DST_SRC_HOSTS",
                 "SRC_FAIL_DST_HOSTS", "SRC_FAIL_DST_PORTS", "SRC_TOP_SERVICE")

SYN, RST = 0x02, 0x04

#: Where each input lives in the two schemas this module serves. NetFlow v3
#: (nProbe) for training; nfstream after the profile's adapt() for serving -
#: adapt() writes CLIENT/SERVER_TCP_FLAGS under the NetFlow names.
COLUMNS = {
    "netflow": {"src": "IPV4_SRC_ADDR", "dst": "IPV4_DST_ADDR", "dport": "L4_DST_PORT",
                "t_end_ms": "FLOW_END_MILLISECONDS", "out_pkts": "OUT_PKTS",
                "client_flags": "CLIENT_TCP_FLAGS", "server_flags": "SERVER_TCP_FLAGS"},
    "nfstream": {"src": "src_ip", "dst": "dst_ip", "dport": "dst_port",
                 "t_end_ms": "bidirectional_last_seen_ms", "out_pkts": "dst2src_packets",
                 "client_flags": "CLIENT_TCP_FLAGS", "server_flags": "SERVER_TCP_FLAGS"},
}


def feature_names(windows=DEFAULT_WINDOWS):
    return [f"W{w}_{stem}" for w in windows for stem in FEATURE_STEMS]


def window_features(df, schema, windows=DEFAULT_WINDOWS):
    """Window statistics for every row of df, aligned to df.index.

    'schema' is 'netflow' or 'nfstream' (see COLUMNS). Rows are not reordered
    and no row is dropped; a flow alone in its window gets counts of 1.
    """
    c = COLUMNS[schema]
    missing = [v for v in c.values() if v not in df.columns]
    if missing:
        raise KeyError(f"window_features({schema!r}): missing columns {missing}")

    num = lambda name: pd.to_numeric(df[c[name]], errors="coerce").fillna(0)
    # Addresses are replaced by integer codes before grouping: the groups and
    # the distinct counts are the same, and grouping 27M rows by an int64 is
    # several times faster and smaller than by the address strings. No code
    # value ever reaches a feature, only how many distinct ones there were.
    base = pd.DataFrame({
        "src": pd.factorize(df[c["src"]].astype(str))[0],
        "dst": pd.factorize(df[c["dst"]].astype(str))[0],
        "dport": num("dport").astype("int32").to_numpy(),
        "t": num("t_end_ms").astype("int64").to_numpy(),
        "no_reply": (num("out_pkts") == 0).to_numpy(),
        "syn_only": (num("client_flags").astype("int64") == SYN).to_numpy(),
        "rst": ((num("server_flags").astype("int64") & RST) > 0).to_numpy(),
    }, index=df.index)

    failed = (base["no_reply"] | base["syn_only"] | base["rst"]).to_numpy()
    src_codes = base["src"].to_numpy().astype("int64")

    out = {}
    for w in windows:
        base["bin"] = base["t"] // (w * 1000)
        # (source, window) as one int64 key, to map per-group results back
        # onto the rows without a MultiIndex join over tens of millions of rows.
        key = (src_codes << 32) | (base["bin"].to_numpy().astype("int64") & 0xFFFFFFFF)
        fail = base[failed]
        fail_key = key[failed]
        by_src = base.groupby(["src", "bin"], sort=False)
        by_dst = base.groupby(["dst", "bin"], sort=False)
        p = f"W{w}_"
        out[p + "SRC_FLOWS"] = by_src["t"].transform("size")
        out[p + "SRC_DST_HOSTS"] = by_src["dst"].transform("nunique")
        out[p + "SRC_DST_PORTS"] = by_src["dport"].transform("nunique")
        out[p + "SRC_NO_REPLY"] = by_src["no_reply"].transform("mean")
        out[p + "SRC_SYN_ONLY"] = by_src["syn_only"].transform("mean")
        out[p + "SRC_RST"] = by_src["rst"].transform("mean")
        out[p + "DST_FLOWS"] = by_dst["t"].transform("size")
        out[p + "DST_SRC_HOSTS"] = by_dst["src"].transform("nunique")
        for col, name in (("dst", "SRC_FAIL_DST_HOSTS"), ("dport", "SRC_FAIL_DST_PORTS")):
            per_key = pd.Series(fail[col].to_numpy()).groupby(fail_key).nunique()
            out[p + name] = pd.Series(key).map(per_key).fillna(0).to_numpy()
        pair = base.groupby([key, base["dst"].to_numpy(), base["dport"].to_numpy()], sort=False).size()
        top = pair.groupby(level=0).max()
        out[p + "SRC_TOP_SERVICE"] = pd.Series(key).map(top).to_numpy()
    # float32: counts and shares are exact in it, and a 27M-row testbed's
    # window features would not fit in memory as float64 next to the flows.
    result = pd.DataFrame({k: np.asarray(v, dtype="float32") for k, v in out.items()}, index=df.index)
    return result[feature_names(windows)]


class WindowAggregator:
    """The live counterpart of window_features(): buffer flows, release windows.

    add() takes flows as the extractor emits them (one dict each, after the
    profile's adapt()); ready() returns the flows whose windows can no longer
    change, with their window features attached - the same values
    window_features() computes offline over the whole capture.

    A window of length W starting at time b is complete once the newest flow
    seen ended after b + W + grace, where grace covers flows still open when
    the window ended (the extractor's idle timeout). Windows are released in
    whole, which is what keeps the counts identical to the offline ones.
    """

    def __init__(self, schema="nfstream", windows=DEFAULT_WINDOWS, grace_s=30.0, compute=True):
        longest = max(windows)
        if any(longest % w for w in windows):
            # Releasing by the longest window releases whole shorter windows
            # only when they nest inside it.
            raise ValueError(f"every window must divide the longest one: {windows}")
        self.schema = schema
        self.windows = tuple(windows)
        # compute=False releases the raw flows only, for a caller (live.py)
        # whose profile computes the window features itself in adapt() - the
        # inputs those need (TCP flag masks) exist only after adapt().
        self.compute = compute
        self.grace_ms = int(grace_s * 1000)
        self._longest_ms = longest * 1000
        self._t_col = COLUMNS[schema]["t_end_ms"]
        self._pending = {}          # longest-window index -> flows ending in it
        self._newest = None

    def add(self, flow):
        t = int(flow.get(self._t_col) or 0)
        self._pending.setdefault(t // self._longest_ms, []).append(flow)
        self._newest = t if self._newest is None else max(self._newest, t)

    #: Live, nfstream emits an idle flow on a periodic scan, and the record
    #: then crosses a thread and a queue; this much extra wall-clock time is
    #: allowed for that before a window is declared complete.
    WALLCLOCK_SLACK_MS = 5000

    def ready(self, flush=False, now_ms=None):
        """Flows of every closed window, with window features (may be empty).

        A window is closed once a flow has been seen ending after its end plus
        the grace period. On a quiet live link no such flow may come for a
        long time, so a live caller also passes the wall clock (now_ms, epoch
        milliseconds - the clock nfstream stamps live flows with): once it is
        past the window's end plus the grace and WALLCLOCK_SLACK_MS, every flow
        ending in the window has been emitted, whether or not anything newer
        arrived. Replays must not pass it - their flows carry the capture's
        time, not today's.

        Cheap when nothing has closed: only the window indices are compared,
        so calling it after every add() costs nothing until a window ends.
        """
        if not self._pending:
            return pd.DataFrame()
        ref = self._newest
        if now_ms is not None:
            ref = max(ref or 0, int(now_ms) - self.WALLCLOCK_SLACK_MS)
        closed = [b for b in self._pending
                  if flush or (b + 1) * self._longest_ms + self.grace_ms <= ref]
        if not closed:
            return pd.DataFrame()
        # Released per longest window; the shorter windows nest inside it, so
        # every window in the released frame is complete.
        flows = [f for b in sorted(closed) for f in self._pending.pop(b)]
        released = pd.DataFrame(flows)
        if not self.compute:
            return released
        return pd.concat([released, window_features(released, self.schema, self.windows)], axis=1)

    def pending(self):
        """Flows buffered and not yet released."""
        return sum(len(v) for v in self._pending.values())
