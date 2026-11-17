# Run from WSL2 Ubuntu (see docs/setup.md). Ports come from .env, the admin password from
# secrets/stack.enc.yaml through .env.secrets (owner-only, deleted by make down, R-02).
.PHONY: lint test secrets pki up down health tls

COMPOSE := docker compose --env-file .env --env-file .env.secrets

lint:
	pre-commit run --all-files

test:
	python3 -m pytest -q

# Decrypt the SOPS secrets into .env.secrets for compose; readable by the owner only.
secrets:
	@test -f .env || { echo ".env is missing: cp .env.example .env"; exit 1; }
	umask 077 && sops -d secrets/stack.enc.yaml | sed 's/: /=/' > .env.secrets

# Lab PKI: root and intermediate CA outside the repo, front-door certificate in certs/ (30 days).
pki:
	bash scripts/pki.sh

up: secrets
	@test -f certs/frontdoor.crt || { echo "no front-door certificate: run make pki"; exit 1; }
	$(COMPOSE) up -d --build --wait
	@$(MAKE) --no-print-directory health

# Named volumes go too (-v), so the next `make up` starts from nothing.
down: secrets
	$(COMPOSE) down -v
	rm -f .env.secrets

# Cluster health over HTTPS on 127.0.0.1. The credentials reach curl on stdin (-K -),
# so the password never appears on a command line or in the process list.
health:
	@set -a; . ./.env; . ./.env.secrets; set +a; \
	printf 'user = "admin:%s"\n' "$$OPENSEARCH_INITIAL_ADMIN_PASSWORD" \
	  | curl -sk -K - "https://127.0.0.1:$$OPENSEARCH_PORT/_cluster/health?pretty"

# The front door's certificate chain, verified against the lab root only.
tls:
	@set -a; . ./.env; set +a; \
	openssl s_client -connect "127.0.0.1:$$HTTPS_PORT" -servername localhost -CAfile certs/root_ca.crt -showcerts </dev/null 2>/dev/null \
	  | grep -E "^ *[0-9] s:|^ *i:|Verify return code|Protocol *:"
