---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/README.md
title: OWASP CRS Docker Image README
fetched: 2026-09-01
authority: official
ref: coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde:README.md
---

Rolling tags `apache` / `nginx`. Apache image: ModSecurity v2.9.x on httpd. Nginx image: ModSecurity v3.x.

`BACKEND` default `http://localhost:80` (`ProxyPass` / `proxy_pass`). Default config is reverse proxy; a listening backend is required or “nothing useful will happen”.

`PROXY_ERROR_OVERRIDE` default `on` (Apache). `PROXY_TIMEOUT` default 60.

CORS env vars are named for **403** responses (`CORS_HEADER_403_*`).
