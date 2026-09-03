---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/nginx/Dockerfile-alpine
title: CRS Docker image ENV BACKEND defaults and overlay copy paths
fetched: 2026-09-03
authority: source
ref: coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde:nginx/Dockerfile-alpine
---

nginx Dockerfiles: `ENV BACKEND=http://localhost:80`, `NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx`. `COPY nginx/templates /etc/nginx/templates/`. Comment: “We use the templating mechanism from the nginx image here.”

`apache/Dockerfile`: `BACKEND=http://localhost:80`, `BACKEND_WS=ws://localhost:8081`.

`apache/Dockerfile-alpine`: `BACKEND=http://localhost:8080`, `BACKEND_WS=ws://localhost:8081`. `COPY apache/conf/extra/*.conf /usr/local/apache2/conf/extra/`. Enables `Include conf/extra/httpd-vhosts.conf`; appends `httpd-locations.conf` and `httpd-modsecurity.conf`.

`docker-bake.hcl`: `modsecurity-nginx-version` default `1.0.4`; nginx dynamic module `owasp-modsecurity/ModSecurity-nginx` at `v${modsecurity-nginx-version}`.
