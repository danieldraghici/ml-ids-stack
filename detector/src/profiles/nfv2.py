"""NF-UQ-NIDS-v2: 43 NetFlow v9 fields, four testbeds, one schema.

Sarhan, Layeghy and Portmann's standard feature set (2021), extracted with
nProbe. 75,987,976 flows unifying NF-UNSW-NB15-v2, NF-BoT-IoT-v2, NF-ToN-IoT-v2
and NF-CSE-CIC-IDS2018-v2.

Two reasons this is the more serious target than CIC-IDS2017:

  - The features are NetFlow/IPFIX fields, which is what real network equipment
    exports natively. A model over these can be deployed against a router's own
    flow export, not only against a span port with a Java flow meter on it.
  - Four different testbeds in one schema means training on one and testing on
    another is possible. That is the cross-domain generalisation test
    CIC-IDS2017 cannot give - every one of its attacks sits on a single day -
    and it extends the NSL-KDD result directly (macro F1 0.9175 on a random
    split, 0.5630 on the official one).

The honest problem with it
--------------------------
The published CSVs came out of nProbe, a commercial probe. Serving this schema
from nfstream means about half the columns are a rename, nine need arithmetic,
and nine cannot be reproduced at all. Those nine are zero-filled and reported -
see Coverage in profiles/base.py for why that is stated rather than quietly
done. A model trained on all 43 and served on 32 real values plus nine zeros is
a model with train/serve skew; the way to measure it is to train a second model
on the 32 nfstream can produce and compare. That is one flag:

    python src/train.py --profile nfv2 --data <file> --servable-by nfstream

which drops the nine before fitting, so the model never learns to rely on a
value it will only ever see as zero live. Both models live in this profile and
the dashboard says, per model, what is zero-filled.

Getting the data
----------------
The UQ portal (https://staff.itee.uq.edu.au/marius/NIDS_datasets/) needs a
login. Each testbed is a component of NF-UQ-NIDS-v2 in the identical schema, so
any of them trains this profile; the union adds a 'Dataset' column that
--split group can use to train on one testbed and test on another.

Scale note: 76M rows x 43 columns does not fit in memory here, and train.py
loads the whole file before --sample applies. Reduce a large file first with

    python src/sample_large.py --profile nfv2 --input <file.csv> --rows 2000000

which reads it in chunks and keeps every row of the rare classes.
"""

import os

import numpy as np
import pandas as pd

from .base import Coverage, Profile

# The 43 features of the standard set, in the order the paper lists them.
ALL_FEATURES = (
    "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL",
    "L7_PROTO", "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS", "TCP_FLAGS",
    "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS", "FLOW_DURATION_MILLISECONDS",
    "DURATION_IN", "DURATION_OUT", "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT",
    "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES", "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
    "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE",
)

# The two addresses are dropped before training, deliberately and permanently.
# In a testbed the attacker sits at a fixed address, so an IP is a perfect
# label: a model keeping them scores ~99.9% by memorising who the attacker was
# and detects nothing whatsoever on a network it has not seen. This is the
# single most common way a NIDS paper reports a number that means nothing.
LEAKY_COLUMNS = ("IPV4_SRC_ADDR", "IPV4_DST_ADDR")

FEATURE_NAMES = tuple(f for f in ALL_FEATURES if f not in LEAKY_COLUMNS)

# NetFlow fields that are unsigned by definition, with their width in bits.
# A negative value in any of them is a storage artefact, never a measurement.
UNSIGNED_WIDTH = {"L4_SRC_PORT": 16, "L4_DST_PORT": 16, "DNS_QUERY_ID": 16,
                  "DNS_TTL_ANSWER": 32}

LABEL_COL = "Attack"        # attack family name; 'Benign' for benign traffic
BINARY_COL = "Label"        # 0/1, as shipped

# nfstream measures these under its own names. A rename costs nothing and
# cannot be got wrong, so it belongs here rather than in adapt().
NFSTREAM_ALIASES = {
    "L4_SRC_PORT": "src_port",
    "L4_DST_PORT": "dst_port",
    "PROTOCOL": "protocol",
    "IN_BYTES": "src2dst_bytes",
    "OUT_BYTES": "dst2src_bytes",
    "IN_PKTS": "src2dst_packets",
    "OUT_PKTS": "dst2src_packets",
    "DURATION_IN": "src2dst_duration_ms",
    "DURATION_OUT": "dst2src_duration_ms",
    "LONGEST_FLOW_PKT": "bidirectional_max_ps",
    "SHORTEST_FLOW_PKT": "bidirectional_min_ps",
    "TCP_WIN_MAX_IN": "tcp_win_max_in",
    "TCP_WIN_MAX_OUT": "tcp_win_max_out",
    "NUM_PKTS_UP_TO_128_BYTES": "num_pkts_up_to_128_bytes",
    "NUM_PKTS_128_TO_256_BYTES": "num_pkts_128_to_256_bytes",
    "NUM_PKTS_256_TO_512_BYTES": "num_pkts_256_to_512_bytes",
    "NUM_PKTS_512_TO_1024_BYTES": "num_pkts_512_to_1024_bytes",
    "NUM_PKTS_1024_TO_1514_BYTES": "num_pkts_1024_to_1514_bytes",
    "ICMP_TYPE": "icmp_type",
    "ICMP_IPV4_TYPE": "icmp_ipv4_type",
}

# Computed in adapt(). The note is the point: "derived" spans honest arithmetic
# and rough proxies, and a reader has to be able to tell which is which.
#
# Several of these reproduce nProbe's conventions rather than the textbook
# quantity, because the model learned nProbe's values. The conventions were
# read off NF-ToN-IoT-v2 itself (2M-row sample); the percentage is how often
# the stated rule reproduces the published value there. Computing the "right"
# number instead - a real duration, a real bytes/second - hands the model
# values it has never seen: on a replayed port scan that made 99.5% of the
# probes look benign.
NFSTREAM_DERIVED = {
    "TCP_FLAGS": "OR of per-flag packet counts over both directions "
                 "(= CLIENT | SERVER, as in the data: 100%)",
    "CLIENT_TCP_FLAGS": "OR of per-flag packet counts, src->dst",
    "SERVER_TCP_FLAGS": "OR of per-flag packet counts, dst->src",
    "FLOW_DURATION_MILLISECONDS": "nProbe's wrapped value: 4294967 - max(DURATION_IN, "
                                  "DURATION_OUT), 0 for a zero-length flow "
                                  "(reproduces the data: 99%)",
    "MIN_TTL": "client->server TTL minimum, 0 when the client sent one packet "
               "(zero rule reproduces the data: 99.7%)",
    "MAX_TTL": "client->server TTL maximum, 0 when the client sent one packet "
               "(zero rule reproduces the data: 99.7%)",
    "SRC_TO_DST_SECOND_BYTES": "IN_BYTES for flows under 1 s, else IN_BYTES / s "
                               "(reproduces the data: ~94%)",
    "DST_TO_SRC_SECOND_BYTES": "OUT_BYTES for flows under 1 s, else OUT_BYTES / s "
                               "(reproduces the data: ~94%)",
    "SRC_TO_DST_AVG_THROUGHPUT": "8000 * floor(IN_BYTES / DURATION_IN ms), with a "
                                 "1 ms floor (reproduces the data: ~93%)",
    "DST_TO_SRC_AVG_THROUGHPUT": "8000 * floor(OUT_BYTES / DURATION_OUT ms), with a "
                                 "1 ms floor (reproduces the data: ~93%)",
    "MIN_IP_PKT_LEN": "shortest IP packet, 0 when the server never answered "
                      "(reproduces the data: 100%)",
    "MAX_IP_PKT_LEN": "longest IP packet (= LONGEST_FLOW_PKT, as in the data: 100%)",
}

# Not obtainable from nfstream, and not worth faking.
#
#   RETRANSMITTED_*  need per-direction TCP sequence-space tracking, which
#                    nfstream does not do and a plugin would have to reimplement
#   L7_PROTO         nfstream carries nDPI's application NAME, not nProbe's
#                    numeric id; any mapping we invent is a different id space
#                    from the one the model learned, which is worse than absent
#   DNS_*, FTP_*     per-protocol dissection nfstream does not surface per flow
NFSTREAM_UNAVAILABLE = frozenset({
    "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS",
    "L7_PROTO",
    "DNS_QUERY_ID", "DNS_QUERY_TYPE", "DNS_TTL_ANSWER",
    "FTP_COMMAND_RET_CODE",
})

# Standard TCP flag bits, for the CLIENT/SERVER/TCP_FLAGS bitmasks.
TCP_FLAG_BITS = (
    ("fin", 0x01), ("syn", 0x02), ("rst", 0x04), ("psh", 0x08),
    ("ack", 0x10), ("urg", 0x20), ("ece", 0x40), ("cwr", 0x80),
)


def _flag_mask(df, prefix):
    """Rebuild a TCP flag bitmask from nfstream's per-flag packet counts.

    nProbe reports the cumulative OR of the flag bits seen on a flow; nfstream
    reports how many packets carried each flag. A non-zero count means the bit
    was set at least once, which is exactly what the OR records - so the two
    agree on the value even though they measure different things to get there.
    """
    mask = pd.Series(0, index=df.index, dtype="int64")
    for name, bit in TCP_FLAG_BITS:
        column = f"{prefix}_{name}_packets"
        if column in df.columns:
            mask |= (pd.to_numeric(df[column], errors="coerce").fillna(0) > 0) * bit
    return mask


class NfV2Profile(Profile):
    """NF-UQ-NIDS-v2 - 43 NetFlow v9 fields, as nProbe produces them."""

    name = "nfv2"
    description = ("NF-UQ-NIDS-v2 (41 NetFlow v9 features after dropping both "
                   "IPs) - four testbeds, one schema")

    feature_names = FEATURE_NAMES
    label_column = LABEL_COL
    binary_column = BINARY_COL
    meta_columns = ("Dataset",)          # which testbed a row came from
    unit = "flow"
    benign_label = "Benign"

    # nProbe's own defaults (-t 120 lifetime, -d 30 idle). The NF-v2 paper does
    # not state the settings it used, so these are the documented defaults of
    # the tool that produced the data, not a measured match - stated here so
    # that the assumption has one place to be corrected.
    flow_timeout = 120.0
    activity_timeout = 30.0

    # NetFlow counts IP bytes: in the data a bare TCP ACK is SHORTEST_FLOW_PKT
    # 40, which is 20 bytes of IP header plus 20 of TCP and no Ethernet.
    # nfstream counts whole frames by default, which would add 14 bytes to
    # every packet size and to every byte counter. accounting_mode=1 measures
    # at the IP layer instead, so IN_BYTES, LONGEST_FLOW_PKT and the rest are
    # the same quantity the model was trained on.
    extractor_options = {"nfstream": {"accounting_mode": 1}}

    identifier_columns = frozenset({
        "ipv4_src_addr", "ipv4_dst_addr", "l4_src_port", "l4_dst_port",
        "src_ip", "dst_ip", "src_port", "dst_port", "attack", "label",
        "dataset", "id",
    })

    aliases = NFSTREAM_ALIASES

    extractors = {
        "nfstream": Coverage(
            native=frozenset(NFSTREAM_ALIASES),
            derived=NFSTREAM_DERIVED,
            unavailable=NFSTREAM_UNAVAILABLE,
        ),
    }

    default_data = "data/processed/nfv2_clean_latest.parquet"

    def load_raw(self, path=None):
        from core.paths import PROJECT_ROOT

        path = path or os.path.join(PROJECT_ROOT, *self.default_data.split("/"))
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"NF-UQ-NIDS-v2 not found at {path!r}.\n"
                "  Download a per-testbed CSV from "
                "https://staff.itee.uq.edu.au/marius/NIDS_datasets/\n"
                "  and pass it with --data. The full 76M-flow union will not "
                "fit in memory here;\n  reduce it first with "
                "src/sample_large.py, or use one testbed at a time."
            )

        df = (pd.read_parquet(path) if path.endswith(".parquet")
              else pd.read_csv(path, low_memory=False))
        df.columns = df.columns.str.strip()
        print(f"Loaded {path}")
        print(f"  {df.shape[0]:,} rows x {df.shape[1]} columns\n")
        return self.repair(df)

    def repair(self, df):
        """Undo integer wrap-around in downcast copies of the dataset.

        NetFlow ports are 16-bit unsigned and DNS_TTL_ANSWER is 32-bit
        unsigned. The Kaggle Parquet of NF-UQ-NIDS-v2 (dhoogla) stores ports as
        int16, so 70% of source ports - every ephemeral port - read as
        negative, and a few DNS TTLs wrapped the same way in int32. Two's
        complement makes it exactly reversible: add 2^16 (2^32) back. Left
        alone, "port -15000" would be a feature value no live flow can have.
        """
        for column, bits in UNSIGNED_WIDTH.items():
            if column not in df.columns:
                continue
            values = df[column]
            if not pd.api.types.is_integer_dtype(values):
                continue
            negative = values < 0
            if negative.any():
                # assign() returns a new frame, so a caller's slice is never
                # modified in place.
                df = df.assign(**{column: values.astype("int64") % (1 << bits)})
                print(f"  repaired {column}: {int(negative.sum()):,} value(s) "
                      f"had wrapped around a signed {bits}-bit type")
        return df

    def build_features(self, df, target):
        drop = [c for c in (self.label_column, self.binary_column,
                            *self.meta_columns, *LEAKY_COLUMNS)
                if c in df.columns]
        X = df.drop(columns=drop)

        non_numeric = X.select_dtypes(exclude=[np.number]).columns.tolist()
        if non_numeric:
            print(f"  dropping {len(non_numeric)} non-numeric columns: {non_numeric}")
            X = X.drop(columns=non_numeric)

        y_raw = (df[self.binary_column] if target == "binary"
                 else df[self.label_column])

        leaked = [c for c in LEAKY_COLUMNS if c in X.columns]
        if leaked:
            raise AssertionError(
                f"address columns leaked into the features: {leaked}. "
                "In a testbed an IP identifies the attacker perfectly, so a "
                "model keeping them measures nothing."
            )

        # nProbe occasionally writes a per-second rate as a number of 1e40 to
        # 1e257 bytes/s - a division by a near-zero duration, not a measurement.
        # Beyond float32 it cannot even be represented by XGBoost. Such rows are
        # dropped, as prepare_data.py drops CIC-IDS2017's infinities; at
        # inference clean_features() fills instead, so no live flow is lost.
        limit = np.finfo(np.float32).max
        values = X.to_numpy(dtype="float64", copy=False)
        invalid = ~np.isfinite(values).all(axis=1) | (np.abs(values) > limit).any(axis=1)
        if invalid.any():
            dropped = y_raw[invalid].astype(str).value_counts()
            print(f"  dropping {int(invalid.sum()):,} row(s) with non-finite or "
                  f"out-of-range values: "
                  + ", ".join(f"{k} {v}" for k, v in dropped.items()))
            X, y_raw = X[~invalid], y_raw[~invalid]

        print(f"Target: {target} ({y_raw.nunique()} classes)")
        print(f"Features: {X.shape[1]} "
              f"(dropped {', '.join(LEAKY_COLUMNS)} as testbed leakage)\n")
        return X, y_raw

    def adapt(self, df, extractor_name):
        """Compute the NetFlow fields that need arithmetic, not a rename.

        Each rule, and how well it reproduces the published data, is stated in
        NFSTREAM_DERIVED above.
        """
        if extractor_name != "nfstream":
            return df

        df = df.copy()

        def col(name):
            if name not in df.columns:
                return pd.Series(0.0, index=df.index)
            return pd.to_numeric(df[name], errors="coerce").fillna(0)

        src_bytes, dst_bytes = col("src2dst_bytes"), col("dst2src_bytes")
        src_pkts, dst_pkts = col("src2dst_packets"), col("dst2src_packets")
        dur_in, dur_out = col("src2dst_duration_ms"), col("dst2src_duration_ms")
        dur = np.maximum(dur_in, dur_out)

        # nProbe's flow duration underflows: the published value is
        # 2^32 us / 1000 minus the real duration, and 0 for a flow shorter
        # than a millisecond. Reproduced, not corrected - it is what the model
        # was fitted on.
        df["FLOW_DURATION_MILLISECONDS"] = np.where(dur > 0, 4294967 - dur, 0)

        # Bytes "per second" is the byte count itself below one second.
        seconds = dur / 1000.0
        per_second = seconds.where(seconds >= 1, 1)
        df["SRC_TO_DST_SECOND_BYTES"] = np.where(seconds < 1, src_bytes,
                                                 src_bytes / per_second)
        df["DST_TO_SRC_SECOND_BYTES"] = np.where(seconds < 1, dst_bytes,
                                                 dst_bytes / per_second)

        # Throughput in bps from whole bytes-per-millisecond, 1 ms floor.
        df["SRC_TO_DST_AVG_THROUGHPUT"] = 8000 * np.floor(
            src_bytes / np.maximum(dur_in, 1))
        df["DST_TO_SRC_AVG_THROUGHPUT"] = 8000 * np.floor(
            dst_bytes / np.maximum(dur_out, 1))

        df["TCP_FLAGS"] = _flag_mask(df, "bidirectional")
        df["CLIENT_TCP_FLAGS"] = _flag_mask(df, "src2dst")
        df["SERVER_TCP_FLAGS"] = _flag_mask(df, "dst2src")

        # TTL from the client direction (see NFv2Fields), zeroed for a
        # one-packet client side as nProbe does.
        one = src_pkts <= 1
        df["MIN_TTL"] = np.where(one, 0, col("min_ttl"))
        df["MAX_TTL"] = np.where(one, 0, col("max_ttl"))

        # With accounting_mode=1 (see extractor_options) nfstream's packet
        # sizes are IP lengths, which is what these fields are. nProbe leaves
        # the minimum at 0 when the server never answered.
        df["MIN_IP_PKT_LEN"] = np.where(dst_pkts == 0, 0, col("bidirectional_min_ps"))
        df["MAX_IP_PKT_LEN"] = col("bidirectional_max_ps")

        return df


PROFILE = NfV2Profile()
