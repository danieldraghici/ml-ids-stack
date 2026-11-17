# Front door: nginx terminates TLS in front of OpenSearch Dashboards (R-02).
# Base pinned by tag and digest; 1.30.5 is the stable line, past the 14-day cooldown (R-04).
FROM nginx:1.30.5-alpine@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94

# Site config only. Certificates stay out of the image and are mounted at runtime from
# certs/ (git-ignored), issued by scripts/pki.sh.
COPY frontdoor.conf /etc/nginx/conf.d/default.conf

EXPOSE 443
