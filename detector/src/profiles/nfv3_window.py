"""NetFlow v3, cleaned for live use, with features computed across flows.

The step from nfv2_clean to this profile is the one Dube (2024) argues for and
the v2 data could not support: v3 keeps the addresses and adds flow start and
end times (Luay et al., 2025), so every flow can be given the statistics of
what its source and its destination did in the same 10 s and 60 s
(core/windows.py). Those are the features a scan, a flood or a brute force
actually shows; per flow, 30% of NF-CSE-CIC-IDS2018-v3 occurs identically
under both labels, with the window features 0.06% does.

Features (FEATURE_NAMES, 66):
  per flow     the nfv2_clean NetFlow fields, minus the two nProbe throughput
               fields, plus FLOW_DURATION_MILLISECONDS (correct in v3: end minus
               start in 100% of rows, where v2 had a 32-bit underflow), two
               rates recomputed from bytes and duration, and the eight
               inter-arrival fields v3 adds
  service      SVC_* from the destination port (nfv2_clean)
  windows      W10_* and W60_*, per source and per destination (core/windows.py)

Every feature is computed from fields both nProbe (training) and nfstream
(serving) measure the same way, so offline and live values agree by
construction rather than by emulation:
  - the AVG_THROUGHPUT fields are dropped: nProbe computes them from internal
    microsecond timers, and no rule over the millisecond fields reproduces
    more than 54-68% of them. RATE_IN_BPS / RATE_OUT_BPS replace them, the
    same formula on both sides.
  - IAT: nProbe reports integer milliseconds, the population standard
    deviation, and 0 for a direction with one packet; nfstream reports the
    sample standard deviation and a fractional mean. adapt() converts.
  - IAT values that cannot be measurements of the flow - a gap longer than
    the flow, or a gap on a one-packet direction (0-5.5% of rows, mostly
    benign) - are set missing (NaN) rather than repaired: nfstream never
    produces them, and an invented value would be a feature nobody measured.
  - window features are computed by the same function on both sides, over
    every flow of the testbed or the capture before any row is selected.

Labels (clean_testbed): the rules come from notebooks/verify_nfv3.py and are
reported per testbed by src/build_nfv3_window.py.
  CSE-CIC-IDS2018  training. Attack names map onto the CIC-IDS2017 families.
                   Excluded, with the reason recorded:
                   - FTP-BruteForce and DoS-SlowHTTPTest: 100% of their flows
                     are one SYN answered by RST/ACK - the FTP server refused
                     every connection, so neither attack ever happened on the
                     wire. Training on them would teach "SYN->RST to port 21"
                     as brute force.
                   - web attacks not on TCP port 80: the label was given to
                     every flow reaching the victim in the attack window
                     (84% are UDP 500, 445, 22...), not to the attack.
                   - benign flows from the internet into the testbed (29% of
                     its benign, 3.0M of them to RDP and 1.0M to SMB): that is
                     internet background - scanners and RDP brute forcers -
                     hitting public addresses, labelled benign because it was
                     not part of the scenario. Its true label is unknown.
                   Infiltration is kept for evaluation only: 55% of its flows
                   are the victims' ordinary DNS queries.
  BoT-IoT          training: Reconnaissance, DoS, DDoS. Benign (52k flows, 93%
                   from hosts that also attack) and Theft are excluded.
  UNSW-NB15        training: Benign and Reconnaissance. Its other classes
                   (exploits, fuzzers...) are content attacks this profile
                   does not claim and are excluded.
  ToN-IoT          evaluation only. 97.6% of its benign flows come from hosts
                   that also attack, and flows labelled benign include scans
                   of ~946 ports in 10 s: time-window labelling, not behaviour.
"""

import numpy as np
import pandas as pd

from core.windows import COLUMNS as WINDOW_COLUMNS
from core.windows import DEFAULT_WINDOWS, feature_names as window_feature_names
from core.windows import window_features

from .base import Coverage
from .nfv2 import NFSTREAM_ALIASES, NFSTREAM_DERIVED
from .nfv2_clean import (AMBIGUOUS_COL, COPIES_COL, KEPT_NETFLOW, SERVICE_COLUMNS,
                         NfV2CleanProfile, service_indicators)

IAT_COLUMNS = tuple(f"{side}_IAT_{stat}" for side in ("SRC_TO_DST", "DST_TO_SRC")
                    for stat in ("MIN", "MAX", "AVG", "STDDEV"))
RATE_COLUMNS = ("RATE_IN_BPS", "RATE_OUT_BPS")
PER_FLOW = tuple(f for f in KEPT_NETFLOW
                 if f not in ("SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT")) + (
    "FLOW_DURATION_MILLISECONDS",) + RATE_COLUMNS + IAT_COLUMNS
WINDOW_FEATURES = tuple(window_feature_names(DEFAULT_WINDOWS))
FEATURE_NAMES = PER_FLOW + SERVICE_COLUMNS + WINDOW_FEATURES

FAMILY_COL = "Family"
ROLE_COL = "Role"           # train | eval  (excluded rows are not written)
UNSCORED_COL = "Unscored"   # 1 = flow to a multicast/broadcast address: counted in windows, never alerted
TIME_COL = "FLOW_END_MILLISECONDS"

# Families named after CIC-IDS2017's attack groups, which are the target.
# None = excluded; the reason is in EXCLUDED_REASON.
FAMILY = {
    "NF-CSE-CIC-IDS2018-v3": {
        "Benign": "Benign",
        "DoS_attacks-Hulk": "DoS", "DoS_attacks-GoldenEye": "DoS",
        "DoS_attacks-Slowloris": "DoS-Slow",
        "DoS_attacks-SlowHTTPTest": None,
        "DDoS_attacks-LOIC-HTTP": "DDoS", "DDOS_attack-HOIC": "DDoS", "DDOS_attack-LOIC-UDP": "DDoS",
        "FTP-BruteForce": None,
        "SSH-Bruteforce": "BruteForce",
        "Bot": "Bot",
        "Infilteration": "Infiltration",
        "Brute_Force_-Web": "WebAttack", "Brute_Force_-XSS": "WebAttack", "SQL_Injection": "WebAttack",
    },
    "NF-BoT-IoT-v3": {"Benign": None, "Reconnaissance": "PortScan", "DoS": "DoS", "DDoS": "DDoS",
                      "Theft": None},
    "NF-UNSW-NB15-v3": {"Benign": "Benign", "Reconnaissance": "PortScan"},
    "NF-ToN-IoT-v3": {"Benign": "Benign", "dos": "DoS", "ddos": "DDoS", "scanning": "PortScan",
                      "password": "BruteForce", "xss": "WebAttack", "injection": "WebAttack",
                      "Backdoor": "Backdoor", "ransomware": "Other", "mitm": "Other"},
    # NetFlow v2: the same testbeds and attacks under v2's spellings. One map
    # per version, one set of rules (label_rules) for both, so that the v2 and
    # v3 models of the article are cleaned identically.
    "NF-CSE-CIC-IDS2018-v2": {
        "Benign": "Benign",
        "DoS attacks-Hulk": "DoS", "DoS attacks-GoldenEye": "DoS",
        "DoS attacks-Slowloris": "DoS-Slow",
        "DoS attacks-SlowHTTPTest": None,
        "DDoS attacks-LOIC-HTTP": "DDoS", "DDOS attack-HOIC": "DDoS", "DDOS attack-LOIC-UDP": "DDoS",
        "FTP-BruteForce": None,
        "SSH-Bruteforce": "BruteForce",
        "Bot": "Bot",
        "Infilteration": "Infiltration",
        "Brute Force -Web": "WebAttack", "Brute Force -XSS": "WebAttack", "SQL Injection": "WebAttack",
    },
    "NF-BoT-IoT-v2": {"Benign": None, "Reconnaissance": "PortScan", "DoS": "DoS", "DDoS": "DDoS",
                      "Theft": None},
    "NF-UNSW-NB15-v2": {"Benign": "Benign", "Reconnaissance": "PortScan"},
    "NF-ToN-IoT-v2": {"Benign": "Benign", "dos": "DoS", "ddos": "DDoS", "DoS": "DoS", "DDoS": "DDoS",
                      "scanning": "PortScan",
                      "password": "BruteForce", "xss": "WebAttack", "injection": "WebAttack",
                      "backdoor": "Backdoor", "Backdoor": "Backdoor", "ransomware": "Other",
                      "mitm": "Other"},
}
EVAL_ONLY_TESTBEDS = {"NF-ToN-IoT-v3", "NF-ToN-IoT-v2"}
EVAL_ONLY_FAMILIES = {"Infiltration"}

EXCLUDED_REASON = {
    "DoS_attacks-SlowHTTPTest": "failed attack: every flow is one SYN answered by RST/ACK on port 21",
    "FTP-BruteForce": "failed attack: every flow is one SYN answered by RST/ACK on port 21",
    "DoS attacks-SlowHTTPTest": "failed attack: every flow is one SYN answered by RST/ACK on port 21",
    "web_not_http": "web-attack label on a flow that is not TCP/80: the window was labelled, not the attack",
    "internet_inbound_benign": "benign label on unsolicited internet traffic into the testbed "
                               "(RDP/SMB scanners): true label unknown",
    "bot_iot_benign": "52k flows, 93% from hosts that also attack",
    "unclaimed_class": "class outside the CIC-IDS2017 families this profile targets",
}

# CSE-CIC-IDS2018 runs in one AWS VPC; anything else is the internet.
CIC2018_INTERNAL_PREFIX = "172.31."

# Distinct rows kept per (testbed, attack name) after deduplication. Rows keep
# their Copies count, so per-flow rates stay computable.
CAP_ATTACK = 200_000
PRESAMPLE = 5
CAP_BENIGN = {"NF-CSE-CIC-IDS2018-v3": 1_500_000, "NF-UNSW-NB15-v3": 500_000,
              "NF-ToN-IoT-v3": 1_000_000,
              "NF-CSE-CIC-IDS2018-v2": 1_500_000, "NF-UNSW-NB15-v2": 500_000,
              "NF-ToN-IoT-v2": 1_000_000}

#: nProbe's two throughput fields: not features of this profile (not
#: reproducible live, see the module docstring), but carried in the built
#: file so that the article can train a v3 model on exactly the 35 features
#: of the cleaned v2 model (nfv2_clean.FEATURE_NAMES).
EXTRA_COLUMNS = ("SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT")

#: Columns read from the v3 Parquet files: everything the features and the
#: label rules need, nothing else (the largest file is 27M rows).
SOURCE_COLUMNS = tuple(dict.fromkeys(
    ("FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS", "IPV4_SRC_ADDR", "IPV4_DST_ADDR",
     "L4_DST_PORT") + tuple(KEPT_NETFLOW) + ("FLOW_DURATION_MILLISECONDS",) + IAT_COLUMNS
    + ("Label", "Attack", "Dataset")))


def unscored_destination(dst):
    """True for flows to multicast or broadcast addresses.

    Local discovery protocols (mDNS, SSDP, LLMNR, DHCP, NetBIOS) talk to these
    addresses all the time, one device to every device, which in window
    counts looks like one source reaching many hosts. A deployed IDS does not
    alert on them; here they still feed every window count - live, they are
    on the wire - but are never scored. The subnet broadcast is recognised by
    a last octet of 255, which is right for the /24 networks of the testbeds
    and the lab, and stated here because it is an assumption.
    """
    d = pd.Series(dst, copy=False).astype(str)
    first = pd.to_numeric(d.str.split(".", n=1).str[0], errors="coerce")
    v4_multicast = first.between(224, 239)
    broadcast = (d == "255.255.255.255") | d.str.endswith(".255")
    v6_multicast = d.str.lower().str.startswith("ff")
    return (v4_multicast | broadcast | v6_multicast).to_numpy()


def _rates(in_bytes, out_bytes, duration_ms):
    d = np.maximum(np.asarray(duration_ms, dtype="float64"), 1.0)
    return (np.asarray(in_bytes, dtype="float64") * 8000.0 / d,
            np.asarray(out_bytes, dtype="float64") * 8000.0 / d)


def _sanitize_iat(df):
    """Zero IAT on one-packet directions, NaN where a gap exceeds the flow."""
    out = {}
    bad_rows = np.zeros(len(df), dtype=bool)
    dur = df["FLOW_DURATION_MILLISECONDS"].to_numpy(dtype="float64")
    for side, pk in (("SRC_TO_DST", "IN_PKTS"), ("DST_TO_SRC", "OUT_PKTS")):
        cols = [f"{side}_IAT_{s}" for s in ("MIN", "MAX", "AVG", "STDDEV")]
        vals = df[cols].to_numpy(dtype="float64", copy=True)
        n = df[pk].to_numpy()
        one = n <= 1
        impossible = (~one) & (vals[:, 1] > dur + 1)
        vals[one] = 0.0
        vals[impossible] = np.nan
        bad_rows |= impossible | (one & (df[cols[2]].to_numpy() > 0))
        for i, c in enumerate(cols):
            out[c] = vals[:, i]
    return pd.DataFrame(out, index=df.index), int(bad_rows.sum())


def per_flow_features(df):
    """NetFlow v3 rows -> the per-flow and service features, float32."""
    feat = df[[c for c in KEPT_NETFLOW
               if c not in ("SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT")]].astype("float32")
    feat.loc[df["PROTOCOL"].to_numpy() != 1, "ICMP_TYPE"] = 0
    feat["FLOW_DURATION_MILLISECONDS"] = df["FLOW_DURATION_MILLISECONDS"].astype("float32")
    rin, rout = _rates(df["IN_BYTES"], df["OUT_BYTES"], df["FLOW_DURATION_MILLISECONDS"])
    feat["RATE_IN_BPS"], feat["RATE_OUT_BPS"] = rin.astype("float32"), rout.astype("float32")
    iat, n_bad = _sanitize_iat(df)
    feat = pd.concat([feat, iat.astype("float32"), service_indicators(df["L4_DST_PORT"]).astype("float32")],
                     axis=1)
    return feat, n_bad


def label_rules(df, testbed):
    """The label rules of this profile, for any NetFlow version of a testbed.

    Returns (attack, family, reason): reason is NA for a kept row and the
    EXCLUDED_REASON text for an excluded one. The CSE-CIC-IDS2018 rules need
    the addresses (inbound internet traffic) and the destination port.
    """
    base = testbed.rsplit("-v", 1)[0]
    attack = df["Attack"].astype(str)
    fam_map = FAMILY[testbed]
    family = attack.map(fam_map)                       # NaN = not in map, None = excluded
    reason = pd.Series(pd.NA, index=df.index, dtype="object")
    for name, why in EXCLUDED_REASON.items():
        if name in fam_map and fam_map[name] is None:
            reason[attack == name] = why
    reason[family.isna() & reason.isna()] = EXCLUDED_REASON["unclaimed_class"]
    if base == "NF-BoT-IoT":
        reason[attack == "Benign"] = EXCLUDED_REASON["bot_iot_benign"]
    if base == "NF-CSE-CIC-IDS2018":
        web = family == "WebAttack"
        not_http = ~((df["PROTOCOL"] == 6) & (df["L4_DST_PORT"] == 80))
        reason[web & not_http] = EXCLUDED_REASON["web_not_http"]
        if "IPV4_SRC_ADDR" not in df.columns:
            raise KeyError(f"{testbed}: the inbound-benign rule needs IPV4_SRC_ADDR / IPV4_DST_ADDR")
        src_int = df["IPV4_SRC_ADDR"].astype(str).str.startswith(CIC2018_INTERNAL_PREFIX)
        dst_int = df["IPV4_DST_ADDR"].astype(str).str.startswith(CIC2018_INTERNAL_PREFIX)
        reason[(attack == "Benign") & ~src_int & dst_int] = EXCLUDED_REASON["internet_inbound_benign"]
    return attack, family, reason


def dedup_and_cap(out, features, testbed, rng, rep, time_col=None):
    """Collapse identical rows (keeping a Copies count), then cap distinct rows."""
    keys = pd.util.hash_pandas_object(out[list(features) + ["Label", "Attack", UNSCORED_COL]],
                                      index=False).to_numpy()
    copies = pd.Series(keys).map(pd.Series(keys).value_counts()).to_numpy()
    out[COPIES_COL] = copies.astype("int64")
    first = ~pd.Series(keys).duplicated().to_numpy()
    rep["duplicates_dropped"] = int((~first).sum())
    out = out[first]
    parts = []
    for name, grp in out.groupby("Attack", sort=False):
        cap = CAP_BENIGN.get(testbed, 0) if name == "Benign" else CAP_ATTACK
        parts.append(grp.sample(n=cap, random_state=rng) if cap and len(grp) > cap else grp)
    out = pd.concat(parts)
    if time_col:
        out = out.sort_values(time_col, kind="stable")
    rep["rows_out"] = int(len(out))
    rep["rows_out_by_family_role"] = {f"{f} | {r}": int(n) for (f, r), n in
                                      out.groupby([FAMILY_COL, ROLE_COL]).size().items()}
    rep["flows_represented_by_family"] = {f: int(n) for f, n in out.groupby(FAMILY_COL)[COPIES_COL].sum().items()}
    return out


def clean_v2_testbed(df, testbed, rng=42, quiet=False):
    """One NetFlow v2 testbed -> the 35 cleaned per-flow features, same rules as v3.

    v2 has no timestamps, so there are no window features; everything else -
    label rules, excluded classes, evaluation-only roles, deduplication and
    caps - is the code clean_testbed() runs on v3.
    """
    from .nfv2_clean import FEATURE_NAMES as V2_FEATURES
    say = (lambda *a: None) if quiet else print
    rep = {"rows_in": int(len(df))}
    attack, family, reason = label_rules(df, testbed)
    keep = reason.isna().to_numpy()
    rep["excluded"] = {k: int(v) for k, v in reason[~keep].value_counts().items()}
    rep["excluded_by_attack"] = {k: int(v) for k, v in attack[~keep].value_counts().items()}
    sub = df[keep]
    out = sub[list(KEPT_NETFLOW)].astype("float32")
    out.loc[sub["PROTOCOL"].to_numpy() != 1, "ICMP_TYPE"] = 0
    out = pd.concat([out, service_indicators(sub["L4_DST_PORT"]).astype("float32")], axis=1)[list(V2_FEATURES)]
    out["Label"] = (attack[keep] != "Benign").astype("int8").to_numpy()
    out["Attack"] = attack[keep].to_numpy()
    out[FAMILY_COL] = family[keep].astype(str).to_numpy()
    out["Dataset"] = testbed
    eval_only = (testbed in EVAL_ONLY_TESTBEDS) | out[FAMILY_COL].isin(EVAL_ONLY_FAMILIES).to_numpy()
    out[ROLE_COL] = np.where(eval_only, "eval", "train")
    out[UNSCORED_COL] = (unscored_destination(sub["IPV4_DST_ADDR"]).astype("int8")
                         if "IPV4_DST_ADDR" in sub.columns else np.int8(0))
    out = dedup_and_cap(out, V2_FEATURES, testbed, rng, rep)
    say(f"{testbed}: {rep['rows_in']:,} flows -> {rep['rows_out']:,} rows "
        f"(excluded {sum(rep['excluded'].values()):,}, duplicates {rep['duplicates_dropped']:,})")
    return out, rep


def clean_testbed(df, testbed, rng=42, quiet=False):
    """One v3 testbed (raw Parquet columns) -> cleaned rows with all features.

    Window features are computed over every flow before any row is dropped:
    live, the IDS sees all of the traffic, including the flows whose label is
    unknown here. Returns (frame, report).
    """
    say = (lambda *a: None) if quiet else print
    rep = {"rows_in": int(len(df))}
    win = window_features(df, "netflow")
    attack, family, reason = label_rules(df, testbed)

    keep = reason.isna().to_numpy()
    rep["excluded"] = {k: int(v) for k, v in reason[~keep].value_counts().items()}
    rep["excluded_by_attack"] = {k: int(v) for k, v in attack[~keep].value_counts().items()}

    # An evaluation-only testbed (ToN-IoT, 27.5M flows) does not need every
    # flow as a row, and its full 66-feature matrix does not fit in memory.
    # Its windows were computed over every flow above; only the rows built
    # from them are sampled here, up to PRESAMPLE x the cap per attack name.
    # Copies then counts identical flows within the sample.
    sel = np.flatnonzero(keep)
    if testbed in EVAL_ONLY_TESTBEDS:
        gen = np.random.default_rng(rng)
        att_kept = attack.to_numpy()[sel]
        chosen = []
        for name in np.unique(att_kept):
            ii = sel[att_kept == name]
            cap = PRESAMPLE * (CAP_BENIGN.get(testbed, 0) if name == "Benign" else CAP_ATTACK)
            chosen.append(gen.choice(ii, size=cap, replace=False) if cap and len(ii) > cap else ii)
        sel = np.sort(np.concatenate(chosen))
        rep["presampled_rows"] = int(len(sel))
    sub = df.iloc[sel]
    feat, rep["iat_impossible_rows"] = per_flow_features(sub)
    out = pd.concat([feat, win.iloc[sel]], axis=1)[list(FEATURE_NAMES)]
    del win, feat

    out["Label"] = (attack.iloc[sel] != "Benign").astype("int8").to_numpy()
    out["Attack"] = attack.iloc[sel].to_numpy()
    out[FAMILY_COL] = family.iloc[sel].astype(str).to_numpy()
    out["Dataset"] = testbed
    eval_only = (testbed in EVAL_ONLY_TESTBEDS) | out[FAMILY_COL].isin(EVAL_ONLY_FAMILIES).to_numpy()
    out[ROLE_COL] = np.where(eval_only, "eval", "train")
    out[TIME_COL] = sub[TIME_COL].to_numpy()
    out[UNSCORED_COL] = unscored_destination(sub["IPV4_DST_ADDR"]).astype("int8")
    for c in EXTRA_COLUMNS:
        if c in sub.columns:
            out[c] = sub[c].astype("float32").to_numpy()

    # Deduplicate identical rows (features, label, attack name), keeping the
    # earliest and recording how many flows each one stands for; cap distinct
    # rows per attack name and benign per testbed.
    out = dedup_and_cap(out, FEATURE_NAMES, testbed, rng, rep, time_col=TIME_COL)
    say(f"{testbed}: {rep['rows_in']:,} flows -> {rep['rows_out']:,} rows "
        f"(excluded {sum(rep['excluded'].values()):,}, duplicates {rep['duplicates_dropped']:,}, "
        f"IAT set missing on {rep['iat_impossible_rows']:,})")
    return out, rep


def mark_ambiguous(df, features=FEATURE_NAMES):
    """Flag training rows whose features occur with both labels."""
    train = df[ROLE_COL] == "train"
    h = pd.util.hash_pandas_object(df.loc[train, list(features)], index=False).to_numpy()
    n_lab = pd.Series(df.loc[train, "Label"].to_numpy()).groupby(h).transform("nunique").to_numpy()
    df[AMBIGUOUS_COL] = np.int8(0)
    df.loc[train, AMBIGUOUS_COL] = (n_lab > 1).astype("int8")
    return df


class NfV3WindowProfile(NfV2CleanProfile):
    """NetFlow v3, cleaned, with per-source and per-destination window features."""

    name = "nfv3_window"
    description = (f"NetFlow v3 (CIC-2018 + BoT/UNSW scans), {len(FEATURE_NAMES)} live-measurable "
                   "features incl. 10 s / 60 s windows; families as CIC-IDS2017")

    feature_names = FEATURE_NAMES
    label_column = FAMILY_COL
    binary_column = "Label"
    meta_columns = ("Dataset", "Attack", ROLE_COL, TIME_COL, COPIES_COL, AMBIGUOUS_COL, UNSCORED_COL)
    default_data = "data/processed/nfv3_window_latest.parquet"

    # The windows are released per 60 s once the idle timeout has passed, so
    # they and the flow expiry belong together. nProbe's defaults, as for nfv2;
    # the v3 paper states only that flows are exported within two minutes.
    flow_timeout = 120.0
    activity_timeout = 30.0
    windows = DEFAULT_WINDOWS

    extractors = {
        "nfstream": Coverage(
            native=frozenset(f for f in NFSTREAM_ALIASES if f in PER_FLOW),
            derived={
                **{f: n for f, n in NFSTREAM_DERIVED.items() if f in PER_FLOW},
                "FLOW_DURATION_MILLISECONDS": "bidirectional_duration_ms (end minus start, as in v3)",
                "RATE_IN_BPS": "IN_BYTES * 8000 / max(FLOW_DURATION_MILLISECONDS, 1), same formula offline",
                "RATE_OUT_BPS": "OUT_BYTES * 8000 / max(FLOW_DURATION_MILLISECONDS, 1), same formula offline",
                **{c: "from *_piat_ms: integer ms, population std, 0 for a one-packet direction"
                   for c in IAT_COLUMNS},
                **{c: "1 if the destination port is this service/range" for c in SERVICE_COLUMNS},
                **{c: "core/windows.py over the capture, the same function as offline"
                   for c in WINDOW_FEATURES},
            },
            unavailable=frozenset(),
        ),
    }

    def load_raw(self, path=None):
        from core.paths import PROJECT_ROOT
        import os

        path = path or os.path.join(PROJECT_ROOT, *self.default_data.split("/"))
        if not os.path.exists(path):
            raise FileNotFoundError(f"{path} not found: run src/build_nfv3_window.py first")
        df = pd.read_parquet(path)
        print(f"Loaded {path}\n  {df.shape[0]:,} rows x {df.shape[1]} columns\n")
        return df

    def build_features(self, df, target):
        rows = df[ROLE_COL] == "train"
        if AMBIGUOUS_COL in df.columns:
            amb = rows & (df[AMBIGUOUS_COL] == 1)
            if amb.any():
                print(f"  leaving out {int(amb.sum()):,} ambiguous training row(s)")
            rows &= ~amb
        print(f"  leaving out {int((df[ROLE_COL] != 'train').sum()):,} evaluation-only row(s) "
              "(ToN-IoT, Infiltration)")
        df = df[rows]
        X = df[list(FEATURE_NAMES)]
        y_raw = df[self.binary_column] if target == "binary" else df[FAMILY_COL]
        print(f"Target: {target} ({y_raw.nunique()} classes)\nFeatures: {X.shape[1]}\n")
        return X, y_raw

    def adapt(self, df, extractor_name):
        """nfstream output -> this profile's per-flow features, plus windows.

        The windows need every flow of the capture. Offline (a pcap) that is
        the frame passed in; live, WindowAggregator attaches them before this
        is called, and they are left untouched.
        """
        df = super().adapt(df, extractor_name)
        if extractor_name != "nfstream":
            return df

        def col(name):
            if name not in df.columns:
                return pd.Series(0.0, index=df.index)
            return pd.to_numeric(df[name], errors="coerce").fillna(0)

        duration = col("bidirectional_duration_ms")
        df["FLOW_DURATION_MILLISECONDS"] = duration
        df["RATE_IN_BPS"], df["RATE_OUT_BPS"] = _rates(col("src2dst_bytes"), col("dst2src_bytes"), duration)
        for side, prefix, pk in (("SRC_TO_DST", "src2dst", "src2dst_packets"),
                                 ("DST_TO_SRC", "dst2src", "dst2src_packets")):
            n = col(pk)
            gaps = np.maximum(n - 1, 1)
            one = n <= 1
            sample_std = col(f"{prefix}_stddev_piat_ms")
            # nfstream: sample std over the gaps; nProbe: population std.
            pop_std = sample_std * np.sqrt(np.where(gaps > 1, (gaps - 1) / gaps, 0.0))
            values = {"MIN": col(f"{prefix}_min_piat_ms"), "MAX": col(f"{prefix}_max_piat_ms"),
                      "AVG": col(f"{prefix}_mean_piat_ms"), "STDDEV": pop_std}
            for stat, v in values.items():
                df[f"{side}_IAT_{stat}"] = np.where(one, 0.0, np.floor(v))
        if not all(c in df.columns for c in WINDOW_FEATURES):
            if all(c in df.columns for c in WINDOW_COLUMNS["nfstream"].values()):
                df = pd.concat([df, window_features(df, "nfstream", self.windows)], axis=1)
        return df

    def unscored(self, df):
        """Flows that feed the windows but are never alerted on (see unscored_destination)."""
        for col in ("dst_ip", "IPV4_DST_ADDR"):
            if col in df.columns:
                return unscored_destination(df[col])
        return np.zeros(len(df), dtype=bool)

    def bundle_extra(self):
        return {"family_map": FAMILY, "excluded": EXCLUDED_REASON,
                "windows_s": list(self.windows), "eval_only": sorted(EVAL_ONLY_TESTBEDS | EVAL_ONLY_FAMILIES)}

    def benign_names(self):
        return {"benign", "0"}


PROFILE = NfV3WindowProfile()
