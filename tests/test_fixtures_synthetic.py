"""The synthetic fixtures are reproducible (R-09): regenerating them gives the committed bytes.

A fixture whose origin cannot be checked is evidence nobody can trust. The generator uses fixed
seeds and a fixed start time, so a fresh run must match the SHA-256 recorded in README.md.
"""
import hashlib
import importlib.util
import re
from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parent / "fixtures" / "pcaps"
SYNTHETIC = ["icmp_sweep.pcap", "ssh_bruteforce.pcap", "dns_txt.pcap", "near_misses.pcap"]


def recorded():
    rows = {re.search(r"`([^`]+)`", l).group(1): l for l in (FIX / "README.md").read_text().splitlines()
            if l.startswith("| `") and "synthetic" in l and l.count("|") == 9}
    return {name: re.findall(r"`([0-9a-f]{64})`", row)[0] for name, row in rows.items()}


def test_every_synthetic_fixture_is_documented():
    assert set(recorded()) == set(SYNTHETIC)


@pytest.mark.parametrize("name", SYNTHETIC)
def test_committed_file_matches_its_recorded_hash(name):
    assert hashlib.sha256((FIX / name).read_bytes()).hexdigest() == recorded()[name]


def test_regenerating_gives_identical_bytes(tmp_path):
    pytest.importorskip("scapy")
    spec = importlib.util.spec_from_file_location("make_synthetic", FIX / "make_synthetic.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.OUT = tmp_path
    gen.main()
    for name, digest in recorded().items():
        assert hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() == digest, name
