---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/master/README.md
title: CRS Docker README — Nginx ENV Variables (real_ip)
fetched: 2026-09-02
authority: official
---

Extract from https://raw.githubusercontent.com/coreruleset/modsecurity-crs-docker/master/README.md (Nginx ENV Variables + shared ModSecurity audit keys).

REAL_IP_HEADER: Name of the header containing the real IP value(s) (Default: `X-REAL-IP`). See real_ip_header.

REAL_IP_PROXY_HEADER: Name of the header containing `$remote_addr` to be passed to proxy (Default: `X-REAL-IP`). See proxy_set_header.

REAL_IP_RECURSIVE: A string value indicating whether to use recursive replacement on addresses in `REAL_IP_HEADER` (Allowed values: `on`, `off`. Default: `on`). See real_ip_recursive.

SET_REAL_IP_FROM: A string of comma separated IP, CIDR, or UNIX domain socket addresses that are trusted to replace addresses in `REAL_IP_HEADER` (Default: `127.0.0.1`). See set_real_ip_from.

MODSEC_AUDIT_LOG: A string indicating the path to the main audit log file or the concurrent logging index file (Default: `/dev/stdout`).

MODSEC_AUDIT_LOG_FORMAT: A string indicating the output format of the AuditLogs (Default: `JSON`). Accepted values: `JSON`, `Native`.

Both nginx and httpd containers now run with an unprivileged user. Defaults for both nginx and httpd are PORT `8080` and SSL_PORT `8443`.
