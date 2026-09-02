---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/apache/conf/extra/httpd-vhosts.conf
title: apache/conf/extra/httpd-vhosts.conf
fetched: 2026-09-01
authority: source
ref: coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde:apache/conf/extra/httpd-vhosts.conf
---

`ProxyErrorOverride ${PROXY_ERROR_OVERRIDE}`
`ProxyPass / ${BACKEND}/ disablereuse=on`
`ProxyTimeout ${PROXY_TIMEOUT}`

This is the Apache sidecar’s origin mapping. A dead `BACKEND` is an httpd proxy failure, not a ModSecurity deny.
