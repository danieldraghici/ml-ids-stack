# ML-IDS detector, replay mode (R-04, R-07). Base pinned by tag and digest: Python 3.14, the
# minor version the model was trained with. This build was pushed on 2026-11-05, past the 14-day
# cooldown; the 3.14.7 build of September carried 12 fixable HIGH or CRITICAL Debian findings
# (openssl, perl, apt, pcre2), so Trivy failed it. The detection gate checks that the model
# still behaves the same on it.
FROM python:3.14.10-slim-bookworm@sha256:3fe1a0b6c2d6b2ebb572906cdabeca75aeb558c0c17db5ffefbcf8094871c32b

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
# pip is removed once the pinned packages are in: the detector never installs anything at run
# time, and pip's own vendored libraries (urllib3, certifi, msgpack) are the image's only
# fixable Python findings.
RUN pip install --only-binary=:all: --require-hashes -r requirements.txt \
 && pip uninstall --yes pip

COPY thresholds.json run.py episodes.py ./
COPY src/ src/

# Runs as an unprivileged user; at run time the container is also read-only, without network
# and without capabilities (Makefile, make replay). The model comes in read-only from /models.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin detector
USER 10001
ENTRYPOINT ["python", "/app/run.py"]
