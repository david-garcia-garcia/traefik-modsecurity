---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/README.md
title: OWASP CRS Docker Image README
fetched: 2026-09-03
authority: official
ref: coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde:README.md
---

Nginx overlay: mount a local file as `/etc/nginx/templates/conf.d/default.conf.template`. Files in the templates directory are copied; subdirectories are preserved. Kubernetes error names `/docker-entrypoint.d/20-envsubst-on-templates.sh`.

Common ENV `BACKEND`: Partial URL for the remote server of `ProxyPass` (httpd) and `proxy_pass` (nginx). Table default `http://localhost:80` (nginx column `-`).

Apache ENV `BACKEND_WS`: WebSocket service URL. Default `ws://localhost:8081`.

Container Health Checks: images return HTTP status 200 from `/healthz`.

Proxy Configuration: default configuration (no file overrides) acts as a reverse proxy and requires a running backend at `BACKEND`. If `BACKEND` is not an address where a web server is listening, nothing useful happens with the default configuration.
