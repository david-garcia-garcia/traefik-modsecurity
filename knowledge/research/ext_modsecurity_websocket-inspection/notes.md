# ModSecurity WebSocket inspection

libmodsecurity inspects HTTP requests. It does not inspect WebSocket frames after the protocol switch. Maintainers say it is “only capable to understand the http requests.” In-line nginx+ModSecurity historically broke 101 (forced 200). That is not a documented skip of the handshake HTTP request.

## Vendor: frames are not inspectable; HTTP requests are

zimmerle (ModSecurity maintainer) on issue #1368: “Currently ModSecurity is not capable to inspect WebSockets. It is only capable to understand the http requests.”

Owner: [owasp-modsecurity/ModSecurity#1368](https://github.com/owasp-modsecurity/ModSecurity/issues/1368) (zimmerle, 2017-05-05).

Extract: `.sources/issue-1368.md`

## Vendor: in-line ModSecurity can rewrite 101 to 200

Issue #831 reporter: “Modsecurity forces status code 200 instead of 101. WebSockets doesn't work.” Maintainers point at #1368: not capable to inspect WebSockets.

Owner: [owasp-modsecurity/ModSecurity#831](https://github.com/owasp-modsecurity/ModSecurity/issues/831).

Extract: `.sources/issue-831.md`

## Inference: handshake HTTP is still an HTTP request

A GET with `Upgrade` / `Connection` is still an HTTP request, which is the unit ModSecurity understands. Skipping that request is not stated as engine behavior. The 101-rewrite problem is in-line proxying of the upgrade response, not “Upgrade headers skip phase 1–2.”

This plugin copies sidecar `3xx`/`4xx` as a block and treats sidecar status below 300 (including 200 and 101) as allow, then calls `next`. The client’s 101 comes from Traefik `next`, not from the sidecar.

Authority: inference from #1368 plus `pkg/modsecurity/serve.go` allow/block split.

## CRS 4.3.0 rules do not name WebSocket

Inside `owasp/modsecurity-crs:4.3.0-apache-alpine-202406090906`, `grep -RIn -i websocket /etc/modsecurity.d/owasp-crs/rules` returned no matches. REQUEST-920 inspects `REQUEST_HEADERS:Connection` for duplicate `keep-alive`/`close` tokens (rule around line 336), not for `Upgrade` or `websocket`.

Owner: image `owasp/modsecurity-crs:4.3.0-apache-alpine-202406090906` files `/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf` and the rest of that `rules/` tree (exec 2026-09-03).

Extract: `.sources/crs-4.3.0-image-websocket-grep.md`

Runtime on this product's compose (`PARANOIA=1`, `ANOMALY_INBOUND=5`): a GET `/ws-echo` with RFC 6455 handshake headers returned sidecar 200 on both Apache and nginx stacks; the same GET with `id=1' OR '1'='1` returned 403 (rule 942100). That is this pin's anomaly threshold, not a CRS skip-on-Upgrade.
