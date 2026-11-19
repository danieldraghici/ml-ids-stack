# Logstash for the stack (R-04, R-06). The Apache-2.0 OSS build of Logstash 8.19.23, pinned by
# tag and digest and past the 14-day cooldown, plus the OpenSearch output plugin at a fixed
# version. The prebuilt opensearchproject/logstash-oss-with-opensearch-output-plugin image
# stopped at 8.9.0 in 2023, so it is built here instead. The pipeline tests run the same base
# image (tests/logstash_harness.py reads the FROM line below).
FROM docker.elastic.co/logstash/logstash-oss:8.19.23@sha256:93009108ef6a14dae2945e12d61e6616b202b62619b07cea8a71d8d63500ba75

# The plugin manager needs more than its default 1 GB heap to resolve the gem.
RUN JRUBY_OPTS="-J-Xmx2g" bin/logstash-plugin install --version 2.1.1 logstash-output-opensearch
