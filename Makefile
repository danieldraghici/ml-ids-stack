# Run from WSL2 Ubuntu (see docs/setup.md). Ports come from .env, the admin password from
# secrets/stack.enc.yaml through .env.secrets (owner-only, deleted by make down, R-02).
.PHONY: lint test secrets pki up down health tls model detector replay

# Where the dissertation's model bundle lives on this machine (never committed, R-07).
MODEL_SRC ?= /mnt/d/ML_IDS_Disertation/ML_IDS_Disertation/models/nfv3_window_xgb_latest.joblib
PCAP ?=

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

# Copy the model into models/ (git-ignored) and check its SHA-256 against detector/thresholds.json.
model:
	@mkdir -p models
	cp "$(MODEL_SRC)" models/
	@python3 -c 'import hashlib,json,sys; c=json.load(open("detector/thresholds.json")); d=hashlib.sha256(open("models/"+c["model"],"rb").read()).hexdigest(); print("model SHA-256", "matches" if d==c["model_sha256"] else "DOES NOT MATCH", "thresholds.json"); sys.exit(d!=c["model_sha256"])'

detector:
	docker build -q -t ml-ids-stack/detector:local detector

# Replay one pcap from tests/fixtures/pcaps: read-only container, no network, no capabilities,
# unprivileged user, model mounted read-only. Alerts land in out/ (git-ignored).
replay: detector
	@test -n "$(PCAP)" || { echo "usage: make replay PCAP=portscan.pcap"; exit 1; }
	@mkdir -p out
	docker run --rm --read-only --tmpfs /tmp --network none --cap-drop ALL \
	  --security-opt no-new-privileges --user "$$(id -u):$$(id -g)" \
	  -v "$$PWD/models:/models:ro" -v "$$PWD/tests/fixtures/pcaps:/pcaps:ro" -v "$$PWD/out:/out" \
	  ml-ids-stack/detector:local "/pcaps/$(PCAP)"
