FROM ghcr.io/ratify-project/ratify:v1.2.1 AS ratify

COPY ./bin/snyk-os-verifier /.ratify/plugins/snyk-os-verifier