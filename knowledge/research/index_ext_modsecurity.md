# ext / modsecurity

## Redirect action
priority: normal
local: ext_modsecurity_actions_redirect/
description: How ModSecurity redirect and deny+status produce a 3xx client response.

## Deny vs error HTTP status
priority: normal
local: ext_modsecurity_http-status_deny-vs-error/
description: Official ModSecurity, Apache, and CRS HTTP status codes for security deny actions versus sidecar or backend failures.

## REMOTE_ADDR
priority: normal
local: ext_modsecurity_variables_remote-addr/
description: How ModSecurity REMOTE_ADDR is filled and when the official Apache CRS image rewrites it from X-Forwarded-For.

## nginx real_ip env
priority: normal
local: ext_modsecurity_crs-docker_nginx-real-ip/
description: Official owasp/modsecurity-crs nginx image env vars for real_ip (REAL_IP_HEADER, SET_REAL_IP_FROM, REAL_IP_RECURSIVE) and audit log path.

## CRS Docker BACKEND
priority: normal
local: ext_modsecurity_crs-docker_backend/
description: Official owasp/modsecurity-crs reverse-proxy BACKEND/BACKEND_WS wiring, overlay mount paths, and inspect-only response behavior.

## Host
priority: normal
local: ext_modsecurity_variables_host/
description: How ModSecurity and CRS read the HTTP Host header.
