#!/usr/bin/env python3
"""Local secrets for a reviewer who has no access to the student's age key (R-02).

The stack's passwords live in secrets/stack.enc.yaml, encrypted for the student's age key, so a
reviewer who clones the repository cannot decrypt them. make reviewer-setup calls this once and
writes the output to .env.secrets (owner-only, git-ignored, deleted by make down). Every password
is new and random, so nothing from the student's stack is shared.

Each password meets OpenSearch's policy (upper and lower case, a digit and a symbol, at least 8
characters) and avoids quotes, backslashes, $ and spaces, so every consumer reads it as it is.
"""
import secrets
import string

KEYS = ("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "GRAFANA_ADMIN_PASSWORD", "OPENSEARCH_MONITOR_PASSWORD")
SYMBOLS = "_-+=.@"
LENGTH = 24


def password(length: int = LENGTH) -> str:
    alphabet = string.ascii_letters + string.digits + SYMBOLS
    while True:
        p = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in p) and any(c.isupper() for c in p)
                and any(c.isdigit() for c in p) and any(c in SYMBOLS for c in p)):
            return p


def render() -> str:
    return "".join(f"{key}={password()}\n" for key in KEYS)


if __name__ == "__main__":
    print(render(), end="")
