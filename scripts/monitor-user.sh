#!/usr/bin/env bash
# The exporter's own OpenSearch account (R-02, R-06): it may read cluster health and search the
# stack's indices (mlids-*, suricata-*), which _count needs, and nothing else, instead of using
# the admin password. make up writes the role and the user on every start, from
# config/opensearch/stack-monitor-role.json and OPENSEARCH_MONITOR_PASSWORD in
# secrets/stack.enc.yaml. Passwords reach curl through its config on stdin, never as arguments.
set -euo pipefail

# .env and .env.secrets are read as data, not sourced: a password holding $, ; or a quote is
# passed on as it is, never expanded or run as a command.
setting() { sed -n "s/^$1=//p" "$2" | tail -n 1; }
OPENSEARCH_PORT=$(setting OPENSEARCH_PORT .env)
OPENSEARCH_INITIAL_ADMIN_PASSWORD=$(setting OPENSEARCH_INITIAL_ADMIN_PASSWORD .env.secrets)
OPENSEARCH_MONITOR_PASSWORD=$(setting OPENSEARCH_MONITOR_PASSWORD .env.secrets)
: "${OPENSEARCH_MONITOR_PASSWORD:?add OPENSEARCH_MONITOR_PASSWORD to secrets/stack.enc.yaml (docs/setup.md, section 9)}"

api="https://127.0.0.1:${OPENSEARCH_PORT}/_plugins/_security/api"

# Escape backslashes and double quotes, for a JSON string and for a quoted curl config value.
escape() { local s=${1//\\/\\\\}; printf '%s' "${s//\"/\\\"}"; }

# put <path> <json>: admin credentials and the body go to curl on stdin (-K -).
put() {
  local code
  code=$(printf 'user = "admin:%s"\ndata = "%s"\n' "$(escape "$OPENSEARCH_INITIAL_ADMIN_PASSWORD")" "$(escape "$2")" \
    | curl -skS -K - -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' "$api/$1")
  echo "PUT $1: $code"
  [[ $code == 200 || $code == 201 ]]
}

put roles/stack_monitor "$(tr -d '\n' < config/opensearch/stack-monitor-role.json)"
put internalusers/monitor "{\"password\": \"$(escape "$OPENSEARCH_MONITOR_PASSWORD")\", \"opendistro_security_roles\": [\"stack_monitor\"]}"
