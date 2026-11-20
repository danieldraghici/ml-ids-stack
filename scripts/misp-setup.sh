#!/usr/bin/env bash
# Clone misp-docker next to this repository at a pinned commit and configure it (R-10, R-02).
#
# - The clone lives in $MISP_DIR (default ../misp-docker), never inside this repository.
# - It is checked out at a fixed commit and verified, and compose.override.yaml from misp/
#   pins every image by digest.
# - MISP answers only on 127.0.0.1:8444 (HTTPS) and 127.0.0.1:8081.
# - The database and cache passwords are random, written once into misp-docker/.env (mode 600)
#   and never printed. They never leave this machine; MISP's own admin account and API key
#   are created by the student in the web UI (docs/misp-setup.md).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
MISP_DIR="${MISP_DIR:-$REPO/../misp-docker}"
COMMIT=27ec05e1701d8482fa2a4b863a7142cedd69dcf3

if [ ! -d "$MISP_DIR/.git" ]; then
  git clone --quiet https://github.com/MISP/misp-docker.git "$MISP_DIR"
fi
git -C "$MISP_DIR" fetch --quiet origin "$COMMIT"
git -C "$MISP_DIR" -c advice.detachedHead=false checkout --quiet "$COMMIT"
test "$(git -C "$MISP_DIR" rev-parse HEAD)" = "$COMMIT"

cp "$REPO/misp/compose.override.yaml" "$MISP_DIR/docker-compose.override.yml"

# MISP's nginx needs a certificate for HTTPS. A self-signed one for localhost, valid one year, is
# enough here: misp_pull.py pins it as its only trusted CA (MISP_CA), instead of turning checks off.
CERTS="$MISP_DIR/certs-local"
if [ ! -f "$CERTS/cert.pem" ]; then
  mkdir -p "$CERTS"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$CERTS/key.pem" -out "$CERTS/cert.pem" 2>/dev/null
  # nginx reads the key as its own unprivileged user inside the container
  chmod 755 "$CERTS" && chmod 644 "$CERTS/cert.pem" "$CERTS/key.pem"
  echo "misp-setup: localhost certificate in $CERTS (set MISP_CA to $CERTS/cert.pem)"
fi

if [ ! -f "$MISP_DIR/.env" ]; then
  umask 077
  cp "$MISP_DIR/template.env" "$MISP_DIR/.env"
  rand() { openssl rand -hex 24; }
  {
    echo ""
    echo "# ml-ids-stack (scripts/misp-setup.sh): localhost only, pinned images, random internal passwords"
    echo "BASE_URL=https://localhost:8444"
    echo "NGINX_HTTP_PORT=127.0.0.1:8081"
    echo "NGINX_HTTPS_PORT=127.0.0.1:8444"
    echo "CORE_RUNNING_TAG=27ec05e"
    echo "MODULES_RUNNING_TAG=27ec05e"
    echo "GUARD_RUNNING_TAG=27ec05e"
    echo "MYSQL_PASSWORD=$(rand)"
    echo "MYSQL_ROOT_PASSWORD=$(rand)"
    echo "REDIS_PASSWORD=$(rand)"
    echo "DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true"
  } >> "$MISP_DIR/.env"
  chmod 600 "$MISP_DIR/.env"
  echo "misp-setup: wrote $MISP_DIR/.env (mode 600, internal passwords generated, not shown)"
fi

echo "misp-setup: misp-docker at ${COMMIT:0:7} in $MISP_DIR, images pinned by misp/compose.override.yaml"
