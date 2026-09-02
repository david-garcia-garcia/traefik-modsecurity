---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/nginx/templates/includes/location_common.conf.template
title: nginx/templates/includes/location_common.conf.template
fetched: 2026-09-01
authority: source
ref: coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde:nginx/templates/includes/location_common.conf.template
---

`error_page 500 502 503 504 /50x.html;`

Nginx sidecar treats those four codes as its own error page, separate from the 403 CORS headers.
