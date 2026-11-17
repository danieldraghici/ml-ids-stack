"""NF-UQ-NIDS-v2, cleaned for a model that has to work on traffic it has not seen.

The nfv2 profile reproduces the published schema as faithfully as possible,
artefacts included, because the models trained on it learned those artefacts.
This profile makes the opposite choice: a feature stays only if it describes
the traffic, means the same thing in every testbed, and can be measured live by
nfstream. Everything else is dropped before the model ever sees it, so there is
nothing to emulate at serving time. nfv2 stays registered unchanged: it is the
baseline this profile is measured against, and the bundles trained on it keep
working.

What is dropped, and why (DROPPED below repeats this per feature, and every
bundle records it):

  testbed identity  IPV4_SRC/DST_ADDR, L4_SRC_PORT. In a testbed the attacker
                    sits at a fixed address and the client port range is an
                    operating-system default, so both identify the machine,
                    not the attack. L4_DST_PORT is replaced by service
                    indicators (SVC_*): "is this web, DNS, SSH..." is a
                    property of the traffic, port 50007 is not.
  not measurable    L7_PROTO, RETRANSMITTED_*, DNS_*, FTP_COMMAND_RET_CODE.
  live              nfstream cannot produce them; a model that relies on a
                    value it will only ever see as zero is broken by design.
  probe artefacts   FLOW_DURATION_MILLISECONDS is nProbe's 32-bit underflow,
                    4294967 - max(DURATION_IN, DURATION_OUT): an invertible
                    transform of two columns that stay, so dropping it loses
                    nothing. SRC/DST_TO_SRC_SECOND_BYTES switch definition at
                    one second and reach 1e38 bytes/s; the AVG_THROUGHPUT
                    columns measure the same thing without either problem.
  environment       MIN_TTL, MAX_TTL depend on the operating systems and the
  fingerprints      number of routers in each testbed. TTL 31 appears only on
                    benign traffic, 64 almost only on attacks: a perfect label
                    inside the data and meaningless on any other network.
  exact duplicates  TCP_FLAGS (= CLIENT | SERVER, 100%), MAX_IP_PKT_LEN
                    (= LONGEST_FLOW_PKT, 100%), ICMP_IPV4_TYPE (= ICMP_TYPE
                    without the code byte).

Rows are cleaned as well (clean() below, used by build_nfv2_clean.py):
ICMP fields that nProbe filled in on TCP flows are zeroed, exact duplicates
are collapsed into one row that records how many flows it stands for (Copies),
feature vectors that occur as both benign and attack are marked Ambiguous
rather than deleted, and the 20 attack names are merged into families that
exist in more than one testbed, so that training on three testbeds and testing
on the fourth tests the same thing on both sides.

What the cleaning showed, on the 3.1M-flow sample (nfuq_3M):
  - 91% of flows are exact copies of another once ports and addresses are
    gone: a flood is thousands of identical flows, and only the random client
    port made them look distinct. With L4_SRC_PORT kept, 0.2% of flows are
    ambiguous; without it, 16.5% - the old models could separate the classes
    by memorising port numbers.
  - 26% of flows (15% of attacks, 49% of benign) are identical to flows of the
    other label. That is the per-flow limit of this schema, not a cleaning
    error: 95% of NF-ToN-IoT-v2 scanning is byte-for-byte benign-looking.
    Detecting it needs features computed across flows (per source, per time
    window), which a single NetFlow record cannot carry.
"""

import numpy as np
import pandas as pd

from .base import Coverage
from .nfv2 import NFSTREAM_ALIASES, NFSTREAM_DERIVED, NfV2Profile

# Service of the destination port. The mapping is the IANA assignment for the
# services that occur in the four testbeds; it says what the client asked for,
# which an IDS legitimately uses, without handing the model a raw port number
# it could memorise.
SERVICES = {
    "WEB": (80, 443, 8000, 8080, 8443),
    "DNS": (53,),
    "SSH": (22,),
    "TELNET": (23,),
    "FTP": (20, 21),
    "MAIL": (25, 110, 143, 465, 587, 993, 995),
    "SMB": (139, 445),
    "RDP": (3389,),
    "MQTT": (1883, 8883),
}
# Ports not listed above fall into one of the IANA ranges.
RANGES = ("NONE", "WELL_KNOWN", "REGISTERED", "DYNAMIC")
SERVICE_COLUMNS = tuple(f"SVC_{name}" for name in (*SERVICES, *RANGES))

KEPT_NETFLOW = (
    "PROTOCOL",
    "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS",
    "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS",
    "DURATION_IN", "DURATION_OUT",
    "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN",
    "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
    "ICMP_TYPE",
)
FEATURE_NAMES = KEPT_NETFLOW + SERVICE_COLUMNS

_IDENTITY = "testbed identity: fixed per machine in a testbed, says who, not what"
_LIVE = "not measurable by nfstream; would be a constant zero live"
DROPPED = {
    "IPV4_SRC_ADDR": _IDENTITY,
    "IPV4_DST_ADDR": _IDENTITY,
    "L4_SRC_PORT": _IDENTITY + " (client port range = OS default)",
    "L4_DST_PORT": "replaced by SVC_* service indicators",
    "L7_PROTO": _LIVE,
    "RETRANSMITTED_IN_BYTES": _LIVE,
    "RETRANSMITTED_IN_PKTS": _LIVE,
    "RETRANSMITTED_OUT_BYTES": _LIVE,
    "RETRANSMITTED_OUT_PKTS": _LIVE,
    "DNS_QUERY_ID": _LIVE,
    "DNS_QUERY_TYPE": _LIVE,
    "DNS_TTL_ANSWER": _LIVE,
    "FTP_COMMAND_RET_CODE": _LIVE,
    "FLOW_DURATION_MILLISECONDS": "nProbe 32-bit underflow of max(DURATION_IN, "
                                  "DURATION_OUT): redundant and not a duration",
    "SRC_TO_DST_SECOND_BYTES": "definition changes at 1 s, values up to 1e38; "
                               "SRC_TO_DST_AVG_THROUGHPUT measures the same",
    "DST_TO_SRC_SECOND_BYTES": "definition changes at 1 s, values up to 1e38; "
                               "DST_TO_SRC_AVG_THROUGHPUT measures the same",
    "MIN_TTL": "environment fingerprint (OS defaults and hop count per testbed)",
    "MAX_TTL": "environment fingerprint (OS defaults and hop count per testbed)",
    "TCP_FLAGS": "exact duplicate of CLIENT_TCP_FLAGS | SERVER_TCP_FLAGS",
    "MAX_IP_PKT_LEN": "exact duplicate of LONGEST_FLOW_PKT",
    "ICMP_IPV4_TYPE": "duplicate of ICMP_TYPE (type without the code byte)",
}

# Attack names merged into families. Thirteen of the twenty names exist in a
# single testbed, so a model tested on another testbed could never be asked
# about them; the families below are what the testbeds have in common.
FAMILY = {
    "Benign": "Benign",
    "DoS": "DoS",
    "DDoS": "DDoS",
    "Reconnaissance": "Scan", "scanning": "Scan",
    "Brute Force": "BruteForce", "password": "BruteForce",
    "xss": "WebAttack", "injection": "WebAttack",
    "Backdoor": "Backdoor",
}
OTHER_FAMILY = "Other"          # everything else: single-testbed attack names

FAMILY_COL = "Family"
COPIES_COL = "Copies"           # how many identical flows a deduplicated row stands for
AMBIGUOUS_COL = "Ambiguous"     # 1 = the same feature vector also occurs with the other label


def service_indicators(port):
    """One 0/1 column per service, from a destination-port series."""
    port = pd.to_numeric(port, errors="coerce").fillna(-1).astype("int64")
    out = {}
    matched = pd.Series(False, index=port.index)
    for name, ports in SERVICES.items():
        hit = port.isin(ports)
        out[f"SVC_{name}"] = hit.astype("int8")
        matched |= hit
    rest = ~matched
    out["SVC_NONE"] = (rest & (port <= 0)).astype("int8")
    out["SVC_WELL_KNOWN"] = (rest & (port > 0) & (port < 1024)).astype("int8")
    out["SVC_REGISTERED"] = (rest & (port >= 1024) & (port < 49152)).astype("int8")
    out["SVC_DYNAMIC"] = (rest & (port >= 49152)).astype("int8")
    return pd.DataFrame(out, index=port.index)[list(SERVICE_COLUMNS)]


def family_of(attack):
    return attack.astype(str).map(FAMILY).fillna(OTHER_FAMILY)


class NfV2CleanProfile(NfV2Profile):
    """NF-UQ-NIDS-v2 with testbed artefacts and fingerprints removed."""

    name = "nfv2_clean"
    description = (f"NF-UQ-NIDS-v2 cleaned for transfer: {len(FEATURE_NAMES)} "
                   "features, all measurable live, no testbed identity")

    feature_names = FEATURE_NAMES
    label_column = FAMILY_COL           # multiclass target: attack family
    binary_column = "Label"

    # Provenance and bookkeeping: never features. Copies says how many raw flows
    # a deduplicated row stands for.
    meta_columns = ("Dataset", COPIES_COL, AMBIGUOUS_COL)

    default_data = "data/processed/nfv2_clean_latest.parquet"

    # Every feature is produced live: renamed, or computed by the parent's
    # adapt() and service_indicators(). Nothing is zero-filled.
    extractors = {
        "nfstream": Coverage(
            native=frozenset(f for f in NFSTREAM_ALIASES if f in KEPT_NETFLOW),
            derived={**{f: n for f, n in NFSTREAM_DERIVED.items() if f in KEPT_NETFLOW},
                     **{c: "1 if the destination port is this service/range"
                        for c in SERVICE_COLUMNS}},
            unavailable=frozenset(),
        ),
    }

    # -- cleaning ----------------------------------------------------------

    def clean(self, df, quiet=False):
        """Raw NF-v2 rows -> the cleaned frame this profile trains on.

        Returns (frame, report). The frame holds the features in training
        order plus Label, Attack, Family, Copies, Ambiguous and Dataset (when
        present).
        The original index is kept, so callers holding a column of the raw
        frame (train.py's group column) can still select by it.
        """
        report = {"rows_in": int(len(df))}
        say = (lambda *a: None) if quiet else print

        missing = [c for c in KEPT_NETFLOW + ("L4_DST_PORT", "Attack", "Label")
                   if c not in df.columns]
        if missing:
            raise KeyError(f"nfv2_clean: input lacks {missing}")

        out = df[list(KEPT_NETFLOW)].copy()

        # nProbe fills ICMP_TYPE on TCP flows - exactly the ones with
        # retransmissions, which is where the false ICMP/retransmission
        # correlation came from. nfstream only sets it for ICMP.
        non_icmp = pd.to_numeric(out["PROTOCOL"], errors="coerce") != 1
        report["icmp_zeroed_on_non_icmp"] = int((non_icmp & (out["ICMP_TYPE"] != 0)).sum())
        out.loc[non_icmp, "ICMP_TYPE"] = 0

        out = pd.concat([out, service_indicators(df["L4_DST_PORT"])], axis=1)

        values = out.to_numpy(dtype="float64")
        finite = np.isfinite(values).all(axis=1) & (np.abs(values) <= np.finfo(np.float32).max).all(axis=1)
        report["non_finite_dropped"] = int((~finite).sum())

        out["Label"] = pd.to_numeric(df["Label"], errors="coerce").astype("int8")
        out["Attack"] = df["Attack"].astype(str)
        out[FAMILY_COL] = family_of(df["Attack"])
        if "Dataset" in df.columns:
            out["Dataset"] = df["Dataset"].astype(str)
        out = out[finite]

        # Exact duplicates: identical features and labels from the same
        # testbed. Without ports and addresses a flood collapses into a few
        # thousand distinct flows; keeping every copy lets a random split put
        # the same vector on both sides and score it as a detection.
        # The number of copies is kept in COPIES_COL (never a feature), so that a
        # rate can still be stated per real flow - a false alarm on a pattern
        # that occurs 10,000 times is 10,000 false alarms live.
        keys = list(FEATURE_NAMES) + ["Label", FAMILY_COL] + (
            ["Dataset"] if "Dataset" in out.columns else [])
        out[COPIES_COL] = out.groupby(keys, sort=False)["Label"].transform("size").astype("int64")
        dup = out.duplicated(subset=keys)
        report["exact_duplicates_dropped"] = int(dup.sum())
        report["duplicates_by_family"] = out.loc[dup, FAMILY_COL].value_counts().to_dict()
        out = out[~dup]

        # A feature vector seen as both benign and attack cannot be learned:
        # no per-flow model can tell the two apart, because they are the same
        # input. They are marked rather than deleted. Training leaves them out
        # (build_features), but they are real traffic - in NF-ToN-IoT-v2 most
        # 'scanning' flows are byte-for-byte identical to benign ones - and an
        # evaluation that deleted them would report a detector that never meets
        # its hardest cases.
        n_labels = out.groupby(list(FEATURE_NAMES), sort=False)["Label"].transform("nunique")
        conflict = n_labels > 1
        out[AMBIGUOUS_COL] = conflict.astype("int8")
        report["ambiguous_rows"] = int(conflict.sum())
        report["ambiguous_flows"] = int(out.loc[conflict, COPIES_COL].sum())
        report["flows_after_dedup"] = int(out[COPIES_COL].sum())
        if "Dataset" in out.columns:
            amb = out[conflict].groupby(["Dataset", FAMILY_COL])[COPIES_COL].sum()
            tot = out.groupby(["Dataset", FAMILY_COL])[COPIES_COL].sum()
            report["ambiguous_flow_share"] = {
                f"{d} | {f}": round(float(amb.get((d, f), 0) / n), 4)
                for (d, f), n in tot.items()}

        report["rows_out"] = int(len(out))
        say(f"nfv2_clean: {report['rows_in']:,} flows -> {report['rows_out']:,} distinct rows "
            f"(duplicates {report['exact_duplicates_dropped']:,}, non-finite "
            f"{report['non_finite_dropped']:,}; ICMP fields zeroed on "
            f"{report['icmp_zeroed_on_non_icmp']:,} non-ICMP flows)")
        say(f"  ambiguous (same features, both labels): {report['ambiguous_rows']:,} rows = "
            f"{report['ambiguous_flows']:,} flows "
            f"({report['ambiguous_flows'] / max(report['flows_after_dedup'], 1):.1%} of all flows)")
        return out, report

    # -- Profile contract --------------------------------------------------

    def build_features(self, df, target):
        # A raw NF-v2 file can be passed straight to train.py; a file written
        # by build_nfv2_clean.py is already clean and has the Family column.
        if FAMILY_COL not in df.columns:
            df, _ = self.clean(df)
        if AMBIGUOUS_COL in df.columns:
            amb = df[AMBIGUOUS_COL] == 1
            if amb.any():
                print(f"  leaving out {int(amb.sum()):,} ambiguous row(s) "
                      f"({int(df.loc[amb, COPIES_COL].sum()):,} flows): the same "
                      "features occur with both labels, so no label is learnable")
                df = df[~amb]
        X = df[list(FEATURE_NAMES)].astype("float64")
        y_raw = df[self.binary_column] if target == "binary" else df[FAMILY_COL]
        print(f"Target: {target} ({y_raw.nunique()} classes)")
        print(f"Features: {X.shape[1]} (dropped {len(DROPPED)} NetFlow fields; "
              "see profiles/nfv2_clean.py)\n")
        return X, y_raw

    def adapt(self, df, extractor_name):
        """nfstream output -> this profile's features.

        The parent computes the TCP flag masks, throughput and MIN_IP_PKT_LEN
        with nProbe's conventions - those reproduce the published values
        exactly or nearly so, and they are units, not artefacts. It also
        computes the dropped columns, which align_features() then ignores.
        """
        df = super().adapt(df, extractor_name)
        if extractor_name != "nfstream":
            return df
        port = df["dst_port"] if "dst_port" in df.columns else df.get("L4_DST_PORT")
        if port is None:
            return df
        svc = service_indicators(port)
        return pd.concat([df.drop(columns=[c for c in svc.columns if c in df.columns]), svc],
                         axis=1)

    def bundle_extra(self):
        return {"dropped_features": dict(DROPPED), "family_map": dict(FAMILY),
                "other_family": OTHER_FAMILY}

    def benign_names(self):
        return {"benign", "0"}


PROFILE = NfV2CleanProfile()
