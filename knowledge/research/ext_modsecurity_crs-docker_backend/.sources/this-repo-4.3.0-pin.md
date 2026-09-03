---
url: file://crs-apache/httpd-vhosts.conf
title: This worktree 4.3.0 pin overlay and compose BACKEND
fetched: 2026-09-03
authority: source
---

`crs-apache/httpd-vhosts.conf` header: overlay for `owasp/modsecurity-crs:4.3.0-apache-alpine-202406090906`; “this copy is the image vhost” with RemoteIPHeader changed to X-Real-IP. Same `ProxyPass / ${BACKEND}/` and `RewriteRule .* "${BACKEND_WS}%{REQUEST_URI}" [P]` as current CRS `httpd-vhosts.conf`. No DocumentRoot.

`docker-compose.yml`, `docker-compose.local.yml`, `docker-compose.test.yml`: image `4.3.0-apache-alpine-202406090906`, `BACKEND=http://dummy`, volume `./crs-apache/httpd-vhosts.conf:/usr/local/apache2/conf/extra/httpd-vhosts.conf:ro`.

`docker-compose.test.nginx.yml`: image `4.3.0-nginx-alpine-202406090906`, `BACKEND=http://dummy`. Overlay is only `crs-nginx/realip.conf` → `/etc/nginx/conf.d/zz-realip.conf` (real_ip, not BACKEND).
