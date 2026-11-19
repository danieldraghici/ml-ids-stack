"""The detector package keeps its promises (R-04, R-06, R-07).

Runs without Docker and without the model: it checks the model gate in run.py with
temporary files, the pins, the provenance of the copied code and the fixtures.
"""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DET = ROOT / "detector"
FIX = ROOT / "tests" / "fixtures" / "pcaps"
CONF = json.loads((DET / "thresholds.json").read_text(encoding="utf-8"))

spec = importlib.util.spec_from_file_location("detector_run", DET / "run.py")
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --- model gate (R-07) -----------------------------------------------------------

def test_thresholds_file_is_complete():
    assert CONF["profile"] == "nfv3_window"
    assert CONF["model"].endswith(".joblib") and "/" not in CONF["model"]
    assert re.fullmatch(r"[0-9a-f]{64}", CONF["model_sha256"])
    assert 0 < CONF["decision_threshold"] < 1


def test_model_with_the_right_hash_is_accepted(tmp_path):
    model = tmp_path / "m.joblib"
    model.write_bytes(b"model bytes")
    conf = dict(CONF, model="m.joblib", model_sha256=sha(model))
    assert run.verify_model(conf, str(tmp_path)) == str(model)


def test_tampered_model_is_refused(tmp_path, capsys):
    model = tmp_path / "m.joblib"
    model.write_bytes(b"model bytes plus one")
    conf = dict(CONF, model="m.joblib", model_sha256=hashlib.sha256(b"model bytes").hexdigest())
    assert run.verify_model(conf, str(tmp_path)) is None
    assert "REFUSED" in capsys.readouterr().err


def test_missing_model_is_refused(tmp_path):
    assert run.verify_model(CONF, str(tmp_path)) is None


def test_live_gets_the_named_model_and_the_calibrated_threshold():
    args = run.live_args(CONF, "/models/x.joblib", "/pcaps/a.pcap", "/out")
    assert args[args.index("--model") + 1] == "/models/x.joblib"
    assert float(args[args.index("--decision-threshold") + 1]) == CONF["decision_threshold"]
    assert args[args.index("--profile") + 1] == CONF["profile"]


def test_no_pcap_is_a_usage_error():
    assert run.main([]) == run.EXIT_USAGE


# --- deterministic replay (R-06) ---------------------------------------------------

def test_replay_batches_by_size_not_by_the_clock():
    args = run.live_args(CONF, "/models/x.joblib", "/pcaps/a.pcap", "/out")
    assert float(args[args.index("--batch-seconds") + 1]) >= 3600


def test_replay_uses_a_single_nfstream_meter(monkeypatch):
    import sys
    import types

    seen = {}

    class FakeStreamer:
        def __init__(self, *args, **kwargs):
            seen.update(kwargs)

    fake = types.ModuleType("nfstream")
    fake.NFStreamer = FakeStreamer
    monkeypatch.setitem(sys.modules, "nfstream", fake)
    run.single_meter_replay()
    run.single_meter_replay()  # idempotent: never wraps twice
    sys.modules["nfstream"].NFStreamer(source="x.pcap", n_meters=0)
    assert seen["n_meters"] == 1
    assert sys.modules["nfstream"].NFStreamer.__mro__[1] is FakeStreamer


# --- image and pins (R-04) -------------------------------------------------------

def test_requirements_pinned_exactly():
    # Exact pins with hashes are checked for every requirements file in tests/test_pinning.py.
    text = (DET / "requirements.txt").read_text()
    names = {m.lower() for m in re.findall(r"^([A-Za-z0-9_.\-]+)==", text, flags=re.M)}
    assert "xgboost-cpu" in names and "xgboost" not in names
    assert "--require-hashes" in (DET / "Dockerfile").read_text()


def test_dockerfile_pinned_and_unprivileged():
    text = (DET / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(\S+)", text, flags=re.M)
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    users = re.findall(r"^USER\s+(\S+)", text, flags=re.M)
    assert users and users[-1] not in ("0", "root")


def test_replay_runs_hardened():
    make = (ROOT / "Makefile").read_text()
    hardened = make[make.index("HARDENED :="):make.index("replay: detector")]
    for flag in ("--read-only", "--network none", "--cap-drop ALL", "no-new-privileges", "--user"):
        assert flag in hardened, flag
    block = make[make.index("replay: detector"):make.index("\nsuricata:")]
    assert block.count("$(HARDENED)") == 2 and "docker run" not in block
    for mount in ("/models:ro", "/pcaps:ro"):
        assert mount in block, mount


# --- provenance of the copied code -------------------------------------------------

def sources():
    rows = [l.split("\t") for l in (DET / "SOURCES.tsv").read_text().splitlines() if l and not l.startswith("#")]
    return {r[0]: r for r in rows}


def test_every_copied_file_is_listed_and_unchanged():
    listed = sources()
    present = {p.relative_to(DET / "src").as_posix() for p in (DET / "src").rglob("*.py")}
    assert present == set(listed)
    for path, row in listed.items():
        assert sha(DET / "src" / path) == row[2], f"{path} differs from SOURCES.tsv"


# --- fixtures ----------------------------------------------------------------------

def fixture_rows():
    # the provenance table has 8 columns (9 pipes); the baseline table below it has 4
    rows = [l for l in (FIX / "README.md").read_text().splitlines() if l.startswith("| `") and l.count("|") == 9]
    return {re.search(r"`([^`]+)`", r).group(1): r for r in rows}


def test_fixtures_are_small_and_documented():
    rows = fixture_rows()
    pcaps = {p.name for p in FIX.glob("*.pcap")}
    assert pcaps and pcaps == set(rows)
    for name in pcaps:
        assert (FIX / name).stat().st_size < 5 * 1024 * 1024, f"{name} is over 5 MB"
        assert sha(FIX / name) in rows[name], f"{name} does not match its SHA-256 in the README"
