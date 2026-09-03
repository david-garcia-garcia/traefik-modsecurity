---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/src/bin/healthcheck
title: CRS Docker image HEALTHCHECK script
fetched: 2026-09-03
authority: source
ref: coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde:src/bin/healthcheck
---

Comment: “Endpoint /healthz should always return 200.”

`curl -sk -A healthcheck` to `${scheme}://${host}:${port}/healthz`. Default scheme https / `SSL_PORT`. Apache with `SSL_ENGINE=off` uses http / `PORT`.

Dockerfiles set `HEALTHCHECK CMD /usr/local/bin/healthcheck`.
