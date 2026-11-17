#!/usr/bin/env bash
# Lab PKI with the step CLI, offline (R-02): one root CA, one intermediate CA, and the
# front-door leaf certificate that nginx serves in front of OpenSearch Dashboards.
# The CA keys live outside the repository in $PKI_DIR, encrypted with passwords you choose.
# New passwords are asked twice and compared; they pass to step through owner-only temporary
# files, never on a command line. The leaf goes to certs/ (git-ignored), lasts 30 days;
# rerun to renew. A run that stopped half-way resumes where it stopped.
set -euo pipefail

PKI_DIR="${PKI_DIR:-$HOME/.config/ml-ids-stack/pki}"
CERTS_DIR="${CERTS_DIR:-certs}"
NAME="ML-IDS Stack Lab"

mkdir -p "$PKI_DIR" "$CERTS_DIR"
chmod 700 "$PKI_DIR"
TMP=$(mktemp -d)
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT

new_password() {  # $1 label, $2 output file: ask twice until both entries match
  local a b
  while true; do
    read -rsp "New password for the $1 key: " a; echo
    read -rsp "Same password again: " b; echo
    if [ -n "$a" ] && [ "$a" = "$b" ]; then printf '%s' "$a" > "$2"; return; fi
    echo "The two entries differ or are empty, try again."
  done
}

existing_password() {  # $1 label, $2 key file, $3 output file: ask until it decrypts the key
  local p
  while true; do
    read -rsp "Password of the $1 key: " p; echo
    printf '%s' "$p" > "$3"
    if step crypto key format "$2" --password-file "$3" --no-password --insecure --out /dev/null --force >/dev/null 2>&1; then
      return
    fi
    echo "Wrong password, try again."
  done
}

if [ ! -f "$PKI_DIR/root_ca.crt" ]; then
  echo "== creating the root CA"
  new_password "root CA" "$TMP/root"
  step certificate create "$NAME Root CA" "$PKI_DIR/root_ca.crt" "$PKI_DIR/root_ca.key" \
    --profile root-ca --not-after 87600h --password-file "$TMP/root"
fi

if [ ! -f "$PKI_DIR/intermediate_ca.crt" ]; then
  echo "== creating the intermediate CA"
  [ -f "$TMP/root" ] || existing_password "root CA" "$PKI_DIR/root_ca.key" "$TMP/root"
  new_password "intermediate CA" "$TMP/intermediate"
  step certificate create "$NAME Intermediate CA" "$PKI_DIR/intermediate_ca.crt" "$PKI_DIR/intermediate_ca.key" \
    --profile intermediate-ca --ca "$PKI_DIR/root_ca.crt" --ca-key "$PKI_DIR/root_ca.key" \
    --ca-password-file "$TMP/root" --password-file "$TMP/intermediate" --not-after 43800h
fi

echo "== issuing the front-door certificate"
[ -f "$TMP/intermediate" ] || existing_password "intermediate CA" "$PKI_DIR/intermediate_ca.key" "$TMP/intermediate"
step certificate create frontdoor.lab "$CERTS_DIR/frontdoor.crt" "$CERTS_DIR/frontdoor.key" \
  --profile leaf --ca "$PKI_DIR/intermediate_ca.crt" --ca-key "$PKI_DIR/intermediate_ca.key" \
  --ca-password-file "$TMP/intermediate" \
  --san frontdoor.lab --san localhost --san 127.0.0.1 --not-after 720h \
  --bundle --no-password --insecure --force
chmod 600 "$CERTS_DIR/frontdoor.key"
cp "$PKI_DIR/root_ca.crt" "$CERTS_DIR/root_ca.crt"

step certificate verify "$CERTS_DIR/frontdoor.crt" --roots "$CERTS_DIR/root_ca.crt" && echo "chain verifies against the lab root"
step certificate inspect "$CERTS_DIR/frontdoor.crt" --short
