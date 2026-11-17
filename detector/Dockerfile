# ML-IDS detector, replay mode (R-04, R-07). Base pinned by tag and digest: Python 3.14.7 is the
# version the model was trained with, released 2026-09-19, past the 14-day cooldown.
FROM python:3.14.7-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --only-binary=:all: -r requirements.txt

COPY thresholds.json run.py ./
COPY src/ src/

# Runs as an unprivileged user; at run time the container is also read-only, without network
# and without capabilities (Makefile, make replay). The model comes in read-only from /models.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin detector
USER 10001
ENTRYPOINT ["python", "/app/run.py"]
