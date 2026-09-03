---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/apache/conf/extra/httpd-vhosts.conf
title: CRS Docker Apache vhost and /healthz locations
fetched: 2026-09-03
authority: source
ref: coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde:apache/conf/extra/httpd-vhosts.conf
---

`httpd-vhosts.conf`: no DocumentRoot. `ProxyPass / ${BACKEND}/ disablereuse=on`, `ProxyPassReverse / ${BACKEND}/`. Websocket: `RewriteCond` Upgrade/Connection, `RewriteRule .* "${BACKEND_WS}%{REQUEST_URI}" [P]`. `${REMOTEIP_HEADER}` (current tree; this product’s 4.3.0 overlay hardcodes `X-Real-IP` instead).

`httpd-locations.conf`: `<Location "/healthz">` `RewriteRule .* - [R=200,L]`, `ErrorDocument 200 "OK"`, `ProxyPass !`.
