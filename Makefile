# Run from WSL2 Ubuntu (see docs/setup.md). Ports come from .env, the admin password from
# secrets/stack.enc.yaml through .env.secrets (owner-only, deleted by make down, R-02).
.PHONY: lint lint-ci test review secrets pki up down single-node health dashboards tls model model-check model-release \
        detector frontdoor logstash images scan scan-upstream sbom replay suricata fixtures-synthetic gate \
        misp-setup misp-up misp-down misp-pull exposure ti-demo geoip demo-sensor-down demo-sensor-up schedule unschedule calibrate \
        reviewer-setup ti-demo-offline

# Where the dissertation's model bundle lives on this machine (never committed, R-07).
MODEL_SRC ?= /mnt/d/ML_IDS_Disertation/ML_IDS_Disertation/models/nfv3_window_xgb_latest.joblib
MODEL := $(shell jq -r .model detector/thresholds.json)
# Release to take the signed model from (make model-release); empty means the latest release.
MODEL_RELEASE ?=
PCAP ?=
# Folder of the capture, relative to the repository: the fixtures, or out/demo for make ti-demo.
PCAP_DIR ?= tests/fixtures/pcaps
FIXTURES := portscan.pcap slowloris.pcap hulk1_head.pcap benign_head.pcap \
            icmp_sweep.pcap ssh_bruteforce.pcap dns_txt.pcap near_misses.pcap

COMPOSE := docker compose --env-file .env --env-file .env.secrets
# CI tools as containers pinned by digest (ci/compose.yaml, R-04).
TOOLS := docker compose -f ci/compose.yaml run --rm -T
# Fail on HIGH or CRITICAL findings that have a fix; a finding without one is listed, since
# no rebuild can remove it yet.
SCAN_FLAGS := --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress

lint:
	pre-commit run --all-files

# The linters of the CI lint job: shell scripts, Dockerfiles, code patterns, the workflows, and the
# monitoring configuration with the promtool tests of the alert rules (R-06).
lint-ci:
	$(TOOLS) shellcheck scripts/*.sh
	$(TOOLS) hadolint nginx/Dockerfile detector/Dockerfile logstash/Dockerfile
	$(TOOLS) semgrep scan --config p/ci --error --metrics off
	$(TOOLS) zizmor --offline .
	$(TOOLS) promtool check config monitoring/prometheus.yml
	$(TOOLS) promtool test rules monitoring/alerts.test.yml
	$(TOOLS) amtool check-config monitoring/alertmanager.yml

test:
	python3 -m pytest -q

# Decrypt the SOPS secrets into .env.secrets for compose; readable by the owner only. The MISP
# and Shodan keys (secrets/intel.enc.yaml, F6) join when that file exists.
# The automated pull-request review of the current branch against origin/main, printed instead
# of posted (docs/review.md). The API key is decrypted into this one process only (R-02).
review:
	@test -f secrets/review.enc.yaml || { echo "secrets/review.enc.yaml is missing: docs/setup.md, section 8"; exit 1; }
	git fetch -q origin main
	sops exec-env secrets/review.enc.yaml '$(REVIEW_PYTHON) ci/review.py --local $(if $(BODY),--body-file "$(BODY)")'

AGE_KEY := $(or $(SOPS_AGE_KEY_FILE),$(HOME)/.config/sops/age/keys.txt)
secrets:
	@test -f .env || { echo ".env is missing: cp .env.example .env, or make reviewer-setup"; exit 1; }
	@if [ ! -f "$(AGE_KEY)" ]; then \
	  test -f .env.secrets || { echo "no age key and no .env.secrets: run make reviewer-setup"; exit 1; }; \
	  echo "secrets: no age key; using the local .env.secrets of make reviewer-setup"; \
	else \
	  umask 077 && { sops -d secrets/stack.enc.yaml; test ! -f secrets/intel.enc.yaml || sops -d secrets/intel.enc.yaml; } \
	    | sed 's/: /=/' > .env.secrets; \
	fi

# Lab PKI: root and intermediate CA outside the repo, front-door certificate in certs/ (30 days).
pki:
	bash scripts/pki.sh

# Logstash refuses to start without its MISP dictionary; before the first make misp-pull it is an
# empty file, which matches nothing (enrich/ is git-ignored, R-10).
enrich/ioc_ip.yml:
	@mkdir -p enrich && touch $@

# GeoIP databases (R-10, geoip/README.md): unpacked for Logstash only after their SHA-256 matches.
GEOIP_MONTH := 2026-11
geoip:
	@cd geoip && sha256sum --check --quiet SHA256SUMS
	@for k in country asn; do gunzip -c geoip/dbip-$$k-lite-$(GEOIP_MONTH).mmdb.gz > geoip/dbip-$$k-lite.mmdb; done

up: secrets enrich/ioc_ip.yml geoip
	@test -f certs/frontdoor.crt || { echo "no front-door certificate: run make pki"; exit 1; }
	@mkdir -p inbox out exposure
	$(COMPOSE) up -d --build --wait
	@$(MAKE) --no-print-directory single-node
	@bash scripts/monitor-user.sh
	@# Prometheus and Alertmanager read their mounted configs only at start or on SIGHUP: a changed
	@# alert rule takes effect on the next make up, without losing Prometheus's history.
	@$(COMPOSE) kill -s SIGHUP prometheus alertmanager >/dev/null
	@# The exporter holds no state; a restart loads a changed monitoring/exporter.py.
	@$(COMPOSE) restart exporter >/dev/null
	@$(MAKE) --no-print-directory health

# One node holds no replica, so the security plugin's audit-log indices would keep the cluster
# yellow. A template gives them zero replicas, and the ones that already exist are set the same.
# The mlids-* indices get theirs from the template Logstash installs (config/opensearch/).
single-node:
	@set -a; . ./.env; . ./.env.secrets; set +a; \
	for req in "PUT _index_template/single-node --data @config/opensearch/single-node-template.json" \
	           "PUT security-auditlog-*/_settings --data {\"index\":{\"number_of_replicas\":0}}"; do \
	  set -- $$req; \
	  printf 'user = "admin:%s"\n' "$$OPENSEARCH_INITIAL_ADMIN_PASSWORD" \
	    | curl -sk -K - -o /dev/null -w "$$1 $$2: %{http_code}\n" -X "$$1" -H 'Content-Type: application/json' \
	      "https://127.0.0.1:$$OPENSEARCH_PORT/$$2" "$$3" "$$4"; \
	done

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

# Index patterns and saved searches for the ML-IDS indices (config/dashboards/), imported
# through the front door with its certificate checked against the lab root, into the global
# tenant so every Dashboards user sees them.
dashboards:
	@set -a; . ./.env; . ./.env.secrets; set +a; \
	printf 'user = "admin:%s"\n' "$$OPENSEARCH_INITIAL_ADMIN_PASSWORD" \
	  | curl -s -K - --cacert certs/root_ca.crt -H 'osd-xsrf: true' -H 'securitytenant: global' \
	    -F file=@config/dashboards/mlids.ndjson \
	    "https://localhost:$$HTTPS_PORT/api/saved_objects/_import?overwrite=true" \
	  | jq -c '{success, successCount, errors}'

# The front door's certificate chain, verified against the lab root only.
tls:
	@set -a; . ./.env; set +a; \
	openssl s_client -connect "127.0.0.1:$$HTTPS_PORT" -servername localhost -CAfile certs/root_ca.crt -showcerts </dev/null 2>/dev/null \
	  | grep -E "^ *[0-9] s:|^ *i:|Verify return code|Protocol *:"

# Copy the model into models/ (git-ignored) and check its SHA-256 against detector/thresholds.json.
model:
	@mkdir -p models
	cp "$(MODEL_SRC)" models/
	@$(MAKE) --no-print-directory model-check

model-check:
	@python3 -c 'import hashlib,json,sys; c=json.load(open("detector/thresholds.json")); d=hashlib.sha256(open("models/"+c["model"],"rb").read()).hexdigest(); print("model SHA-256", "matches" if d==c["model_sha256"] else "DOES NOT MATCH", "thresholds.json"); sys.exit(d!=c["model_sha256"])'

# The model of a signed release: its Cosign signature must come from this repository's release
# workflow on a v* tag, checked before the file is kept, then the SHA-256 check (R-07).
model-release:
	@mkdir -p models
	gh release download $(MODEL_RELEASE) --clobber --dir models --pattern "$(MODEL)" --pattern "$(MODEL).sigstore.json"
	$(TOOLS) cosign verify-blob --bundle "models/$(MODEL).sigstore.json" \
	  --certificate-identity-regexp "^https://github.com/$$(gh repo view --json nameWithOwner -q .nameWithOwner)/\.github/workflows/release\.yml@refs/tags/v" \
	  --certificate-oidc-issuer https://token.actions.githubusercontent.com "models/$(MODEL)" \
	  || { rm -f "models/$(MODEL)"; exit 1; }
	@$(MAKE) --no-print-directory model-check

# One plain image manifest per image. With the containerd image store, docker build would
# also attach a BuildKit provenance attestation and push an index; GHCR refused that push in the
# first release run. The SBOM comes from Syft and the signature from Cosign instead.
BUILD := docker build -q --provenance=false --sbom=false

detector:
	$(BUILD) -t ml-ids-stack/detector:local detector

frontdoor:
	$(BUILD) -t ml-ids-stack/frontdoor:local nginx

logstash:
	$(BUILD) -t ml-ids-stack/logstash:local logstash

# Both images as tarballs in out/images/, the input of the scanner and of the SBOM.
images: detector frontdoor
	@mkdir -p out/images
	docker save -o out/images/detector.tar ml-ids-stack/detector:local
	docker save -o out/images/frontdoor.tar ml-ids-stack/frontdoor:local

# R-04: Trivy on both images and on the Python dependencies. Trivy reads only files named
# requirements.txt by default; the pattern adds requirements-dev.txt and requirements-intel.txt.
scan: images
	$(TOOLS) trivy image --input out/images/detector.tar $(SCAN_FLAGS)
	$(TOOLS) trivy image --input out/images/frontdoor.tar $(SCAN_FLAGS)
	$(TOOLS) trivy fs --scanners vuln --skip-dirs out --file-patterns 'pip:requirements-.*\.txt' $(SCAN_FLAGS) .

# R-04, accepted risk: Logstash and Suricata bundle libraries this repository cannot patch, so
# their findings are listed on every pull request without failing it. Neither publishes a port;
# Logstash reads only the detector's output folder and Suricata runs without network on pcaps.
# Dependabot proposes each new pinned release.
SURICATA_IMAGE := $(shell awk '/image: jasonish\/suricata/ {print $$2}' ci/compose.yaml)
MONITORING_IMAGES := $(shell awk '/image: (prom|grafana)\// {print $$2}' compose.yaml)
scan-upstream: logstash
	@mkdir -p out/images
	docker save -o out/images/logstash.tar ml-ids-stack/logstash:local
	docker pull -q $(SURICATA_IMAGE) >/dev/null && docker save -o out/images/suricata.tar $(SURICATA_IMAGE)
	$(TOOLS) trivy image --input out/images/logstash.tar --severity HIGH,CRITICAL --ignore-unfixed --exit-code 0 --no-progress
	$(TOOLS) trivy image --input out/images/suricata.tar --severity HIGH,CRITICAL --ignore-unfixed --exit-code 0 --no-progress
	@for img in $(MONITORING_IMAGES); do \
	  f=out/images/$$(echo $${img%%@*} | tr '/:' '__').tar; \
	  docker pull -q $$img >/dev/null && docker save -o $$f $$img && \
	  $(TOOLS) trivy image --input $$f --severity HIGH,CRITICAL --ignore-unfixed --exit-code 0 --no-progress || exit 1; \
	done

# SPDX SBOM of each image (Syft), attached to every release.
sbom: images
	$(TOOLS) syft scan docker-archive:out/images/detector.tar -o spdx-json > out/detector.sbom.spdx.json
	$(TOOLS) syft scan docker-archive:out/images/frontdoor.tar -o spdx-json > out/frontdoor.sbom.spdx.json

# Replay one pcap from tests/fixtures/pcaps: read-only container, no network, no capabilities,
# unprivileged user, model mounted read-only. Alerts, then the episodes grouped from them
# (detector/episodes.py, R-08), land in out/ (git-ignored); a running stack ingests both.
HARDENED := docker run --rm --read-only --tmpfs /tmp --network none --cap-drop ALL \
	  --security-opt no-new-privileges --user "$$(id -u):$$(id -g)"
replay: detector
	@test -n "$(PCAP)" || { echo "usage: make replay PCAP=portscan.pcap"; exit 1; }
	@mkdir -p out
	@rm -f out/$(basename $(PCAP)).alerts.jsonl out/$(basename $(PCAP)).episodes.jsonl out/$(basename $(PCAP)).status.json
	$(HARDENED) -v "$$PWD/models:/models:ro" -v "$$PWD/$(PCAP_DIR):/pcaps:ro" -v "$$PWD/out:/out" \
	  ml-ids-stack/detector:local "/pcaps/$(PCAP)"
	$(HARDENED) -v "$$PWD/out:/out" --entrypoint python ml-ids-stack/detector:local \
	  /app/episodes.py "/out/$(basename $(PCAP)).alerts.jsonl" "/out/$(basename $(PCAP)).episodes.jsonl"

# Suricata 8 on one pcap (R-09), with only the rules in suricata/rules/: same hardening as the
# detector (ci/compose.yaml: read-only, no network, no capabilities). EVE JSON lands in
# out/<name>.eve.json, which a running stack ingests next to the ML-IDS alerts.
suricata:
	@test -n "$(PCAP)" || { echo "usage: make suricata PCAP=icmp_sweep.pcap"; exit 1; }
	@mkdir -p out
	@rm -f out/$(basename $(PCAP)).eve.json
	$(TOOLS) --user "$$(id -u):$$(id -g)" suricata -c /src/suricata/suricata.yaml -S /src/suricata/rules/local.rules \
	  -l /out -k none -r "/src/$(PCAP_DIR)/$(PCAP)" --set "outputs.0.eve-log.filename=$(basename $(PCAP)).eve.json"

# The synthetic fixtures for the techniques the lab captures lack (R-09), byte-identical each run.
fixtures-synthetic:
	python3 tests/fixtures/pcaps/make_synthetic.py

# R-06, R-09 detection gate: replay every fixture through the ML-IDS and Suricata into out/,
# then compare with tests/regression/baseline.json. The CI job detection-gate runs exactly this.
gate:
	@for p in $(FIXTURES); do $(MAKE) --no-print-directory replay PCAP=$$p || exit 1; done
	@for p in $(FIXTURES); do $(MAKE) --no-print-directory suricata PCAP=$$p >/dev/null || exit 1; done
	REPLAY_OUT=out python3 -m pytest -q tests/regression

# R-10, F6: MISP next to this repository (docs/misp-setup.md), on 127.0.0.1:8444 only.
MISP_DIR ?= ../misp-docker
MISP := docker compose --project-directory $(MISP_DIR)
# MISP and Shodan clients live in their own virtual environment (requirements-intel.txt), outside CI.
INTEL_PYTHON ?= $(HOME)/.venvs/intel/bin/python
REVIEW_PYTHON ?= $(HOME)/.venvs/review/bin/python

misp-setup:
	MISP_DIR="$(MISP_DIR)" bash scripts/misp-setup.sh

misp-up: misp-setup
	$(MISP) up -d --wait

misp-down:
	$(MISP) down

# Indicators from MISP into enrich/ioc_ip.yml (git-ignored), which Logstash rereads every five
# minutes. The keys reach the script through the environment only; it prints counts, never them.
misp-pull: secrets
	@set -a; . ./.env.secrets; set +a; $(INTEL_PYTHON) enrichment/misp_pull.py
	@jq -c '{pulled_at, result, indicators, attributes, aged_out, cidr_skipped, invalid}' enrich/ioc_ip.meta.json

# One Shodan lookup of the own public address; prints it masked, writes exposure/ (git-ignored).
exposure: secrets
	@set -a; . ./.env.secrets; set +a; $(INTEL_PYTHON) enrichment/shodan_exposure.py

# The enrichment demonstration (R-10): the lab port scan with its attacker rewritten to a MISP
# indicator, and a quiet beacon to it, replayed through the ML-IDS and Suricata into out/.
DEMO_IOC ?=
ti-demo:
	@test -n "$(DEMO_IOC)" || { echo "usage: make ti-demo DEMO_IOC=<an address from enrich/ioc_ip.yml>"; exit 1; }
	@grep -qF '"$(DEMO_IOC)":' enrich/ioc_ip.yml || { echo "ti-demo: $(DEMO_IOC) is not in enrich/ioc_ip.yml"; exit 1; }
	@mkdir -p out/demo
	tcprewrite --pnat=192.168.20.11/32:$(DEMO_IOC)/32 --fixcsum \
	  --infile=tests/fixtures/pcaps/portscan.pcap --outfile=out/demo/ti_portscan.pcap
	python3 enrichment/make_demo.py "$(DEMO_IOC)" out/demo/ti_beacon.pcap
	@for p in ti_portscan.pcap ti_beacon.pcap; do \
	  $(MAKE) --no-print-directory replay PCAP=$$p PCAP_DIR=out/demo || exit 1; \
	  $(MAKE) --no-print-directory suricata PCAP=$$p PCAP_DIR=out/demo >/dev/null || exit 1; \
	done

# R-06 demonstration: stop the detector service; SensorDown fires within about 2 minutes on
# Prometheus (127.0.0.1:PROMETHEUS_PORT/alerts) and in Grafana. make demo-sensor-up starts it again.
demo-sensor-down:
	$(COMPOSE) stop detector
	@echo "detector stopped: SensorDown fires within ~2 min, Grafana https://localhost:$$(sed -n 's/^HTTPS_PORT=//p' .env)/grafana/d/ml-ids-stack"

demo-sensor-up:
	$(COMPOSE) start detector

# R-10: the MISP pull every 6 hours and the exposure check every Monday, from the student's own
# crontab in WSL (cron runs under systemd there). Each line carries the tag below, so schedule
# replaces only its own lines and unschedule removes only them; other crontab lines stay.
# The output goes to out/cron-*.log. A pull that fails leaves the dictionary to age, and
# IocFeedStale fires after 12 hours; a check that stops fires ExposureCheckStale after 8 days.
CRON_TAG := ml-ids-stack schedule
CRON_PATH := /usr/local/bin:/usr/bin:/bin
schedule:
	@current="$$(crontab -l 2>/dev/null | grep -vF '# $(CRON_TAG)')"; \
	{ [ -z "$$current" ] || printf '%s\n' "$$current"; \
	   echo '17 */6 * * * cd $(CURDIR) && PATH=$(CRON_PATH) make misp-pull >> $(CURDIR)/out/cron-misp-pull.log 2>&1 # $(CRON_TAG)'; \
	   echo '41 3 * * 1 cd $(CURDIR) && PATH=$(CRON_PATH) make exposure >> $(CURDIR)/out/cron-exposure.log 2>&1 # $(CRON_TAG)'; \
	 } | crontab -
	@crontab -l | grep -F '# $(CRON_TAG)'

unschedule:
	@current="$$(crontab -l 2>/dev/null | grep -vF '# $(CRON_TAG)')"; \
	{ [ -z "$$current" ] || printf '%s\n' "$$current"; } | crontab -

# R-08: site calibration of the threshold on a local benign capture, with the attack fixtures of
# the gate, in the hardened detector container (no network, read-only, model verified). The
# capture's folder is mounted read-only and never copied; out/calibration.json and the table hold
# counts and rates only. thresholds.json is not changed (docs/evidence/R-08-fp-budget.md).
CAPTURE ?=
BUDGET ?= 1
calibrate: detector
	@test -f "$(CAPTURE)" || { echo "usage: make calibrate CAPTURE=/mnt/d/.../benign.pcapng [BUDGET=1]"; exit 1; }
	@mkdir -p out
	$(HARDENED) -v "$$PWD/models:/models:ro" -v "$(abspath $(dir $(CAPTURE))):/capture:ro" \
	  -v "$$PWD/tests/fixtures/pcaps:/pcaps:ro" -v "$$PWD/out:/out" --entrypoint python ml-ids-stack/detector:local \
	  /app/calibrate.py --benign "/capture/$(notdir $(CAPTURE))" --budget $(BUDGET) \
	  --attacks /pcaps/portscan.pcap /pcaps/slowloris.pcap /pcaps/hulk1_head.pcap

# A reviewer who clones the repository has no access to the student's age key or lab CA
# (docs/setup.md, "Run it as a reviewer"). This writes, once and only if missing: .env from
# .env.example with the reviewer's own user id, .env.secrets with new random passwords
# (owner-only, git-ignored, deleted by make down) and a self-signed 30-day front-door certificate.
reviewer-setup:
	@test -f .env || { sed "s/^DETECTOR_UID=.*/DETECTOR_UID=$$(id -u)/; s/^DETECTOR_GID=.*/DETECTOR_GID=$$(id -g)/" .env.example > .env; echo ".env written from .env.example"; }
	@test -f .env.secrets || { umask 077; python3 scripts/reviewer_secrets.py > .env.secrets; echo ".env.secrets written: new random passwords, owner-only"; }
	@test -f certs/frontdoor.crt || { mkdir -p certs; umask 077; \
	  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost" \
	    -addext "subjectAltName=DNS:localhost,DNS:frontdoor.lab" \
	    -keyout certs/frontdoor.key -out certs/frontdoor.crt 2>/dev/null; \
	  chmod 644 certs/frontdoor.crt; echo "certs/frontdoor.crt: self-signed, 30 days"; }

# The threat-intel demonstration without MISP or any key (R-10): the test dictionary of the
# pipeline tests (documentation addresses, RFC 5737) becomes enrich/ioc_ip.yml when no real
# dictionary is there, then make ti-demo replays the scan from 198.51.100.66. A real dictionary
# from make misp-pull is never overwritten.
OFFLINE_IOC := 198.51.100.66
ti-demo-offline:
	@if [ -s enrich/ioc_ip.yml ] && ! grep -qF '"$(OFFLINE_IOC)":' enrich/ioc_ip.yml; then \
	  echo "enrich/ioc_ip.yml holds a real dictionary: use make ti-demo DEMO_IOC=<one of its addresses>"; exit 1; fi
	@mkdir -p enrich && cp tests/samples/ioc_ip_test.yml enrich/ioc_ip.yml
	@$(COMPOSE) restart logstash >/dev/null
	@$(MAKE) --no-print-directory ti-demo DEMO_IOC=$(OFFLINE_IOC)
