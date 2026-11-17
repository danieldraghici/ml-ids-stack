"""compose.yaml keeps the stack's rules (R-02, R-04).

Every image is pinned by digest, every published port binds to 127.0.0.1 and comes
from .env, no secret is written in the file, and .sops.yaml encrypts secrets/ only
for an age recipient.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]
ENV_EXAMPLE = (ROOT / ".env.example").read_text(encoding="utf-8")
VAR = re.compile(r"\$\{([A-Z0-9_]+)[^}]*\}")


DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_image_pinned_by_digest(name):
    service = SERVICES[name]
    if "build" in service:  # built locally: its base image must be pinned instead
        context = service["build"] if isinstance(service["build"], str) else service["build"]["context"]
        froms = [l.split()[1] for l in (ROOT / context / "Dockerfile").read_text(encoding="utf-8").splitlines()
                 if l.upper().startswith("FROM ")]
        assert froms and all(DIGEST.search(f) for f in froms), f"{name}: Dockerfile FROM not pinned by digest"
        return
    image = service["image"]
    assert DIGEST.search(image), f"{name}: {image} is not pinned by digest"
    assert not re.search(r":latest(@|$)", image), f"{name}: floating tag"


def test_only_the_front_door_reaches_dashboards():
    assert "ports" not in SERVICES["opensearch-dashboards"], "Dashboards must not publish a port"
    conf = (ROOT / "nginx" / "frontdoor.conf").read_text(encoding="utf-8")
    assert "listen 443 ssl" in conf and "proxy_pass http://opensearch-dashboards:5601" in conf
    assert re.search(r"ssl_protocols\s+TLSv1\.2 TLSv1\.3;", conf), "only TLS 1.2 and 1.3"


def test_certificates_are_mounted_read_only_and_ignored():
    mounts = SERVICES["frontdoor"]["volumes"]
    assert all(m.endswith(":ro") for m in mounts)
    assert "certs/" in (ROOT / ".gitignore").read_text(encoding="utf-8").split()


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_ports_bind_to_localhost_from_env(name):
    for port in SERVICES[name].get("ports", []):
        assert str(port).startswith("127.0.0.1:"), f"{name}: {port} listens beyond localhost"
        assert VAR.search(str(port)), f"{name}: host port {port} is hardcoded, read it from .env"


def test_every_port_variable_is_documented():
    used = {m for s in SERVICES.values() for p in s.get("ports", []) for m in VAR.findall(str(p))}
    for var in used:
        assert re.search(rf"^{var}=", ENV_EXAMPLE, flags=re.M), f"{var} missing from .env.example"


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_no_secret_in_the_file(name):
    env = SERVICES[name].get("environment", {}) or {}
    items = env.items() if isinstance(env, dict) else (e.split("=", 1) for e in env)
    for key, value in items:
        if re.search(r"PASSWORD|SECRET|TOKEN|_KEY$", key):
            assert VAR.fullmatch(str(value).strip()), f"{name}: {key} must come from the environment"


def test_data_lives_on_named_volumes():
    assert "opensearch-data" in COMPOSE.get("volumes", {})


def test_sops_encrypts_secrets_for_age():
    rules = yaml.safe_load((ROOT / ".sops.yaml").read_text(encoding="utf-8"))["creation_rules"]
    assert rules and all(r["path_regex"].startswith("secrets/") for r in rules)
    assert all(re.fullmatch(r"age1[0-9a-z]{58}", r["age"]) for r in rules)


def test_committed_secrets_are_ciphertext():
    for f in (ROOT / "secrets").glob("*.enc.yaml"):
        text = f.read_text(encoding="utf-8")
        assert "sops:" in text and "ENC[AES256_GCM" in text, f"{f.name} is not SOPS ciphertext"
        values = [l.split(":", 1)[1].strip() for l in text.splitlines()
                  if ":" in l and not l.startswith((" ", "sops")) and not l.startswith("#")]
        assert all(v.startswith("ENC[") for v in values if v), f"{f.name} has a plaintext value"
