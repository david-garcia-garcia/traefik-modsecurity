---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/nginx/templates/includes/proxy_backend.conf.template
title: CRS Docker nginx proxy and location templates
fetched: 2026-09-03
authority: source
ref: coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde:nginx/templates/includes/proxy_backend.conf.template
---

`proxy_backend.conf.template`: `proxy_set_header` Host/Upgrade/Connection/`REAL_IP_PROXY_HEADER`/X-Forwarded-*; `proxy_pass ${BACKEND};` then real_ip placeholders. No `BACKEND_WS`.

`conf.d/default.conf.template`: both servers `location / { include includes/proxy_backend.conf; index index.html index.htm; root /usr/share/nginx/html; }` then `include includes/location_common.conf`.

`includes/location_common.conf.template`: `location /healthz { access_log off; add_header Content-Type text/plain; return 200 "OK"; }` — no `proxy_pass`, no `modsecurity off`.

`conf.d/modsecurity.conf.template`: `modsecurity on;` and `modsecurity_rules_file /etc/modsecurity.d/setup.conf;` (http-level via `conf.d`).

`nginx.conf.template`: `http { include /etc/nginx/conf.d/*.conf; }`.
