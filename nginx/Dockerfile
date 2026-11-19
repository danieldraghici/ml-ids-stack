# Front door: nginx terminates TLS in front of OpenSearch Dashboards (R-02).
# Base pinned by tag and digest, on the stable 1.30 line (R-04). 1.30.7 (pushed 2026-11-18) is
# adopted inside the 14-day cooldown under the security exception: the 1.30.5 build carried 27
# fixable HIGH or CRITICAL findings (nginx, musl, libexpat, curl...) and no build older than
# 14 days is free of them, because the nginx and musl fixes are newer than that.
FROM nginx:1.30.7-alpine@sha256:bef154735288bc38d99fac41ae63730684bcc661503673a04a0f9bc526ba8598

# Site config only. Certificates stay out of the image and are mounted at runtime from
# certs/ (git-ignored), issued by scripts/pki.sh.
COPY frontdoor.conf /etc/nginx/conf.d/default.conf

EXPOSE 443
