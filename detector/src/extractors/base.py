"""The Extractor contract: turning packets into flow records.

Two implementations sit behind this: CICFlowMeter, which built the CIC-IDS2017
training CSVs and therefore reproduces that schema exactly, and nfstream, which
runs the same code offline and live and therefore has no train/serve skew by
construction for any dataset extracted with it.

Both offer the same two operations, and the reason there are two rather than
one is worth stating:

    offline(pcap)  - a whole capture at once, used to build training sets and
                     to score a saved pcap
    live(source)   - an iterator that yields one record per flow AS IT CLOSES

live() is not offline() over a growing file. A flow's features - Flow Duration,
the IAT statistics, Idle and Active - are only defined once the flow is over,
so nothing can be emitted until the flow ends by FIN/RST or by timing out. The
detection latency of the whole system is therefore bounded below by the flow
timeout, not by how fast the model runs. Calling that "real-time" without the
qualifier would be false; what this is, precisely, is per-flow-on-close.
"""

import os


class ExtractorError(RuntimeError):
    """Raised when an extractor cannot run, with an actionable message."""


class Extractor:
    """One way of turning packets into flow records."""

    #: Registry key, and the value a profile names in Profile.extractors.
    name = ""
    #: One line for `--list-extractors`.
    description = ""

    #: Seconds after which an open flow is closed and emitted, and seconds of
    #: silence that ends an "active" period. These are not tuning knobs: they
    #: decide the value of every timing feature, so training and serving must
    #: use the same numbers or the model sees a different quantity than it
    #: learned. Defaults match what produced CIC-IDS2017.
    flow_timeout = 120.0
    activity_timeout = 5.0

    def available(self):
        """Returns (ok, [problem, ...]).

        Checked before anything runs, so a missing JVM or a missing Npcap is
        reported as a sentence rather than as a stack trace two layers down.
        """
        raise NotImplementedError

    def list_interfaces(self):
        """Capturable interfaces as [(name, description), ...]."""
        raise NotImplementedError

    def offline(self, pcap_path, out_dir=None):
        """Extract every flow from a pcap. Returns a path to a CSV of records."""
        raise NotImplementedError

    def live(self, source, stop_event=None):
        """Yield one dict per flow, as each flow closes.

        'source' is an interface name for live capture. Implementations that
        can also replay a pcap in place of an interface say so in their own
        docstring - replay is what makes a live demo reproducible without
        generating attack traffic on the spot.

        'stop_event' is a threading.Event; the iterator returns when it is set.
        """
        raise NotImplementedError

    def __repr__(self):
        return f"<Extractor {self.name}>"


def default_out_dir():
    from core.paths import CAPTURES_DIR
    return CAPTURES_DIR


def expected_csv_path(pcap_path, out_dir):
    """CICFlowMeter names its output '<input filename>_Flow.csv'.

    Kept here rather than in the CICFlowMeter module because nfstream's offline
    path writes to the same convention on purpose: two extractions of the same
    capture then sit side by side with predictable names, which is what the
    extractor-comparison experiment needs.
    """
    return os.path.join(out_dir, os.path.basename(pcap_path) + "_Flow.csv")
