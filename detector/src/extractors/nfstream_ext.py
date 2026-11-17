"""nfstream: one flow engine for both training and serving.

The reason this extractor exists alongside CICFlowMeter is not speed or
convenience, it is skew. CIC-IDS2017's CSVs were produced in 2017 by a
CICFlowMeter build that no longer exists; anything serving that model today is
computing the features slightly differently from how they were learned, and
nothing in the output reveals by how much. With nfstream the training set and
the live capture go through the identical code - `NFStreamer(source=...)` takes
a pcap path or an interface name and changes nothing else - so for any dataset
extracted this way the skew is zero by construction rather than by argument.

Two Windows details that are not optional:

  - Npcap installs wpcap.dll into C:\\Windows\\System32\\Npcap, which is not on
    the DLL search path. Since Python 3.8 PATH is ignored for extension-module
    dependencies, and nfstream's meter runs in a spawned subprocess that would
    not inherit os.add_dll_directory() anyway. _ensure_npcap() below copies the
    two DLLs next to _lib_engine.pyd, where the loader always looks.
  - nfstream's meter uses multiprocessing with the spawn start method, so any
    script that drives it must guard its entry point with
    `if __name__ == "__main__":` and any NFPlugin must live in an importable
    module - which is why NFv2Fields is defined here and not inline.
"""

import os
import shutil
import sys

import pandas as pd

from core.paths import CAPTURES_DIR

from .base import Extractor, ExtractorError, expected_csv_path

#: Where Npcap puts its DLLs on Windows when not installed in WinPcap-
#: compatible mode (which is the default, and the case on this machine).
NPCAP_DIR = os.environ.get("CFM_NPCAP", r"C:\Windows\System32\Npcap")

_NPCAP_READY = False


def _ensure_npcap():
    """Put wpcap.dll where nfstream's spawned meter process can find it.

    Copying into site-packages is deliberate: the Windows loader always
    searches the directory holding the DLL being loaded, and that is the only
    search location which survives both Python 3.8's PATH change and the spawn
    of a fresh interpreter for the meter.
    """
    global _NPCAP_READY
    if _NPCAP_READY or not sys.platform.startswith("win"):
        _NPCAP_READY = True
        return

    try:
        import _lib_engine                                    # noqa: F401
        _NPCAP_READY = True
        return
    except ImportError:
        pass

    target = None
    for entry in sys.path:
        if os.path.isfile(os.path.join(entry, "_lib_engine.pyd")):
            target = entry
            break
    if target is None or not os.path.isdir(NPCAP_DIR):
        _NPCAP_READY = True     # let the real import raise its own message
        return

    for dll in ("wpcap.dll", "Packet.dll"):
        src = os.path.join(NPCAP_DIR, dll)
        dst = os.path.join(target, dll)
        if os.path.isfile(src) and not os.path.isfile(dst):
            try:
                shutil.copy2(src, dst)
            except OSError:
                pass
    _NPCAP_READY = True


def _import_nfstream():
    _ensure_npcap()
    try:
        from nfstream import NFStreamer, NFPlugin
    except ImportError as exc:
        raise ExtractorError(
            f"nfstream is not usable: {exc}\n"
            "  Install it with: pip install nfstream\n"
            "  On Windows it also needs Npcap "
            "(https://npcap.com), which provides wpcap.dll."
        ) from exc
    return NFStreamer, NFPlugin


try:
    from nfstream import NFPlugin as _NFPluginBase
except Exception:                                             # noqa: BLE001
    _NFPluginBase = object


class NFv2Fields(_NFPluginBase):
    """Compute the NetFlow v9 fields nfstream does not expose natively.

    NF-UQ-NIDS-v2's 43 columns came out of nProbe. nfstream measures most of
    them under different names - that part is a rename, handled by the profile's
    alias map. These ten are different: the measurement exists in the packets
    but nfstream does not surface it, so it is computed here from the raw IP
    bytes.

    What is deliberately NOT here: the four RETRANSMITTED_* counters and the
    DNS/FTP fields. Retransmissions need TCP sequence-space tracking per
    direction, and the protocol fields need dissection nfstream does not expose
    per-flow. Guessing at them would be worse than declaring them missing, so
    profiles/nfv2.py marks them unavailable and align_features() zero-fills them
    and says so.
    """

    def on_init(self, packet, flow):
        flow.udps.min_ttl = 255
        flow.udps.max_ttl = 0
        flow.udps.tcp_win_max_in = 0
        flow.udps.tcp_win_max_out = 0
        flow.udps.num_pkts_up_to_128_bytes = 0
        flow.udps.num_pkts_128_to_256_bytes = 0
        flow.udps.num_pkts_256_to_512_bytes = 0
        flow.udps.num_pkts_512_to_1024_bytes = 0
        flow.udps.num_pkts_1024_to_1514_bytes = 0
        flow.udps.icmp_type = 0
        flow.udps.icmp_ipv4_type = 0
        self._update(packet, flow)

    def on_update(self, packet, flow):
        self._update(packet, flow)

    @staticmethod
    def _update(packet, flow):
        raw = packet.ip_packet
        size = packet.ip_size

        # Packet-size histogram: nProbe's buckets, on the IP length.
        if size <= 128:
            flow.udps.num_pkts_up_to_128_bytes += 1
        elif size <= 256:
            flow.udps.num_pkts_128_to_256_bytes += 1
        elif size <= 512:
            flow.udps.num_pkts_256_to_512_bytes += 1
        elif size <= 1024:
            flow.udps.num_pkts_512_to_1024_bytes += 1
        elif size <= 1514:
            flow.udps.num_pkts_1024_to_1514_bytes += 1

        if not raw or packet.ip_version != 4 or len(raw) < 20:
            return

        # IPv4 header: TTL is byte 8, IHL is the low nibble of byte 0.
        # Client-to-server packets only: in NF-ToN-IoT-v2 a flow whose only
        # packet from the client is its first has MIN_TTL = MAX_TTL = 0 even
        # when the server answered (99.7% of such flows), so nProbe's TTL does
        # not come from the reply direction. profiles/nfv2.py applies the
        # one-packet zero on top of this.
        if packet.direction == 0:
            ttl = raw[8]
            if ttl < flow.udps.min_ttl:
                flow.udps.min_ttl = ttl
            if ttl > flow.udps.max_ttl:
                flow.udps.max_ttl = ttl

        ihl = (raw[0] & 0x0F) * 4
        protocol = raw[9]

        if protocol == 6 and len(raw) >= ihl + 20:
            # TCP window is bytes 14-15 of the TCP header.
            window = int.from_bytes(raw[ihl + 14:ihl + 16], "big")
            if packet.direction == 0:
                if window > flow.udps.tcp_win_max_in:
                    flow.udps.tcp_win_max_in = window
            elif window > flow.udps.tcp_win_max_out:
                flow.udps.tcp_win_max_out = window

        elif protocol == 1 and len(raw) >= ihl + 2:
            # ICMP type is byte 0, code byte 1. nProbe reports both the
            # combined type*256+code and the bare type.
            icmp_type, icmp_code = raw[ihl], raw[ihl + 1]
            flow.udps.icmp_type = icmp_type * 256 + icmp_code
            flow.udps.icmp_ipv4_type = icmp_type

    def on_expire(self, flow):
        # A flow that saw no IPv4 packet keeps the sentinel, which would read
        # as a real measurement of 255 downstream.
        if flow.udps.min_ttl == 255 and flow.udps.max_ttl == 0:
            flow.udps.min_ttl = 0


def flow_to_dict(flow):
    """One NFlow as a flat dict, with udps.* lifted to the top level.

    Flattening is what lets a profile's alias map reach the plugin's fields the
    same way it reaches nfstream's own - a consumer should not have to know
    which of the two computed a column.
    """
    record = {}
    for key in dir(flow):
        if key.startswith("_") or key in ("udps", "keys", "values"):
            continue
        # dir() advertises the SPLT attributes whether or not splt_analysis was
        # enabled, and reading one that was not computed raises. Skipping on
        # AttributeError keeps the record to what was actually measured.
        try:
            value = getattr(flow, key)
        except AttributeError:
            continue
        if callable(value):
            continue
        record[key] = value

    udps = getattr(flow, "udps", None)
    if udps is not None:
        for key, value in vars(udps).items():
            record[key] = value
    return record


class NfstreamExtractor(Extractor):
    """nfstream (nDPI) - identical code offline and live, so no train/serve skew."""

    name = "nfstream"
    description = "nfstream / nDPI - same engine for pcap and live capture"

    def __init__(self, flow_timeout=120.0, activity_timeout=5.0, n_dissections=20,
                 accounting_mode=0):
        # nfstream calls these active_timeout and idle_timeout. The names
        # differ from CICFlowMeter's but the roles line up, and keeping one
        # vocabulary at this layer is what lets a profile state one pair of
        # numbers for both extractors.
        self.flow_timeout = flow_timeout
        self.activity_timeout = activity_timeout
        self.n_dissections = n_dissections
        # Which layer byte counts and packet sizes are measured at: 0 link,
        # 1 IP, 2 transport, 3 payload. Set by the profile, never per call.
        self.accounting_mode = accounting_mode

    def available(self):
        try:
            _import_nfstream()
            return True, []
        except ExtractorError as exc:
            return False, [str(exc)]

    def _streamer(self, source, **kwargs):
        NFStreamer, _ = _import_nfstream()
        return NFStreamer(
            source=source,
            statistical_analysis=True,
            active_timeout=int(self.flow_timeout),
            idle_timeout=int(self.activity_timeout),
            n_dissections=self.n_dissections,
            accounting_mode=self.accounting_mode,
            udps=NFv2Fields(),
            **kwargs,
        )

    def list_interfaces(self):
        """Capturable interfaces.

        nfstream binds interfaces through libpcap/Npcap exactly as CICFlowMeter
        does, so the device names are the same ones; the CICFlowMeter extractor
        already has a working enumerator and reusing it avoids a second, subtly
        different list.
        """
        from .cicflowmeter_ext import CicFlowMeterExtractor
        return CicFlowMeterExtractor().list_interfaces()

    def offline(self, pcap_path, out_dir=None, reuse=False, verbose=False):
        """Extract every flow from a pcap into a CSV of nfstream records."""
        out_dir = out_dir or CAPTURES_DIR
        csv_path = expected_csv_path(pcap_path, out_dir).replace(
            "_Flow.csv", "_nfstream.csv")

        if reuse and os.path.isfile(csv_path):
            print(f"Reusing existing extraction\n  {csv_path}\n")
            return csv_path

        os.makedirs(out_dir, exist_ok=True)
        size_mb = os.path.getsize(pcap_path) / 1024 ** 2
        print(f"Extracting flows from {os.path.basename(pcap_path)} "
              f"({size_mb:.1f} MB) with nfstream")

        rows = [flow_to_dict(flow) for flow in self._streamer(pcap_path)]
        if not rows:
            print("  no complete flows in this capture\n")
            return None

        pd.DataFrame(rows).to_csv(csv_path, index=False)
        print(f"  {len(rows):,} flows -> {csv_path}\n")
        return csv_path

    def live(self, source, stop_event=None, on_status=None):
        """Yield one dict per flow as it closes.

        'source' is an interface name, or a pcap path - nfstream treats the two
        identically, which is what makes a reproducible live demo possible:
        replay slowloris.pcap through the same code path that reads the NIC,
        without generating attack traffic on the spot.

        Note for callers: the meter runs in a spawned subprocess, so the script
        driving this must be under `if __name__ == "__main__":`.
        """
        if on_status:
            on_status(f"listening on {source} "
                      f"(flow timeout {self.flow_timeout}s)")

        streamer = self._streamer(source)
        try:
            for flow in streamer:
                if stop_event is not None and stop_event.is_set():
                    break
                yield flow_to_dict(flow)
        finally:
            try:
                streamer.stop()
            except Exception:                                 # noqa: BLE001
                pass


EXTRACTOR = NfstreamExtractor()
