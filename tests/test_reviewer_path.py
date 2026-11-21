"""The path a reviewer takes after cloning, without the student's age key (R-02, F7e)."""
import importlib.util
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("reviewer_secrets", ROOT / "scripts" / "reviewer_secrets.py")
reviewer_secrets = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reviewer_secrets)


def test_every_stack_password_is_generated_and_meets_the_policy():
    lines = reviewer_secrets.render().splitlines()
    values = dict(line.split("=", 1) for line in lines)
    assert set(values) == set(reviewer_secrets.KEYS)
    for v in values.values():
        assert len(v) >= 16 and re.search(r"[a-z]", v) and re.search(r"[A-Z]", v) and re.search(r"\d", v)
        assert any(c in reviewer_secrets.SYMBOLS for c in v)
        assert not set(v) & set("\"'\\$ `;&|")         # read as it is by compose, Bash and curl config
    assert len(set(values.values())) == len(values)     # never one password for two accounts


def test_the_keys_match_what_compose_and_the_scripts_read():
    compose = (ROOT / "compose.yaml").read_text() + (ROOT / "scripts/monitor-user.sh").read_text()
    for key in reviewer_secrets.KEYS:
        assert key in compose


def make(target, cwd, env=None):
    return subprocess.run(["make", "--no-print-directory", "-f", str(ROOT / "Makefile"), target], cwd=cwd,
                          env=dict(os.environ, **(env or {})), capture_output=True, text=True)


def test_secrets_keeps_reviewer_secrets_without_an_age_key(tmp_path):
    (tmp_path / ".env").write_text("OPENSEARCH_PORT=9200\n")
    (tmp_path / ".env.secrets").write_text("OPENSEARCH_INITIAL_ADMIN_PASSWORD=x\n")
    result = make("secrets", tmp_path, {"SOPS_AGE_KEY_FILE": str(tmp_path / "no-such-key")})
    assert result.returncode == 0 and "make reviewer-setup" in result.stdout
    assert (tmp_path / ".env.secrets").read_text() == "OPENSEARCH_INITIAL_ADMIN_PASSWORD=x\n"


def test_secrets_without_an_age_key_or_reviewer_secrets_says_what_to_run(tmp_path):
    (tmp_path / ".env").write_text("OPENSEARCH_PORT=9200\n")
    result = make("secrets", tmp_path, {"SOPS_AGE_KEY_FILE": str(tmp_path / "no-such-key")})
    assert result.returncode != 0 and "make reviewer-setup" in result.stdout + result.stderr
