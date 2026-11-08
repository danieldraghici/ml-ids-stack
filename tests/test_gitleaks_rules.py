"""The custom gitleaks rules catch this stack's keys and ignore look-alikes (R-02).

Fake keys are assembled at run time, so this file never contains a string that
gitleaks would flag. Python's re and gitleaks' Go RE2 agree on these patterns.
"""
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONFIG = tomllib.loads((ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
RULES = {r["id"]: r for r in CONFIG["rules"]}


def fake(n):
    """A random-looking alphanumeric string of length n."""
    alphabet = "q7Zk2Xv9Lm4Rt8Wb3Np6Hs5Jd1Fc0Gy"
    return "".join(alphabet[(i * 7 + 3) % len(alphabet)] for i in range(n))


def finds(rule_id, text):
    rule = RULES[rule_id]
    m = re.search(rule["regex"], text)
    return m.group(rule.get("secretGroup", 0)) if m else None


def test_default_rules_stay_on():
    assert CONFIG["extend"]["useDefault"] is True


@pytest.mark.parametrize("line", [
    "MISP_KEY=" + fake(40),
    "misp_auth_key: '" + fake(40) + "'",
    '"authkey": "' + fake(40) + '"',
    "MISP-API-KEY = " + fake(40),
])
def test_misp_key_found(line):
    assert finds("misp-auth-key", line) == fake(40)


@pytest.mark.parametrize("line", [
    "MISP_KEY=${MISP_KEY}",                       # a reference, not a value
    "MISP_KEY=" + fake(39),                       # too short
    "MISP_URL=https://misp.lab.local",
    "authkey: " + fake(41),                       # too long to be a MISP key
])
def test_misp_key_not_found(line):
    assert finds("misp-auth-key", line) is None


@pytest.mark.parametrize("line", [
    "SHODAN_API_KEY=" + fake(32),
    "shodan_key: " + fake(32),
])
def test_shodan_key_found(line):
    assert finds("shodan-api-key", line) == fake(32)


@pytest.mark.parametrize("line", [
    "SHODAN_API_KEY=${SHODAN_API_KEY}",
    "SHODAN_API_KEY=" + fake(31),
    "shodan_query: port:443 org:example",
])
def test_shodan_key_not_found(line):
    assert finds("shodan-api-key", line) is None


def test_every_rule_has_keywords():
    for rule in CONFIG["rules"]:
        assert rule.get("keywords"), rule["id"]
