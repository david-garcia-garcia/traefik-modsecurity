# Explore

## Concepts

This plugin is not an in-line WAF. `ServeHTTP` copies the HTTP request to a ModSecurity sidecar, then either copies a sidecar `3xx`/`4xx` to the client or calls Traefik `next`. WebSocket *frames* never enter `ServeHTTP` again: Traefik tunnels after the backend's 101. The only HTTP the plugin can inspect is the opening GET.

```
Client GET Upgrade ──► Plugin ──┬─ (today) isWebsocket? ──► next  ──► backend (200 or 101)
                                 └─ sidecar inspect ──► 3xx/4xx block | <300 allow + next
```

`isWebsocket` today is GET + `Connection` token `upgrade` + `Upgrade` EqualFold `websocket`. That is a subset of RFC 6455. It is also entirely client-controlled. A PHP/HTML route that is not a WebSocket endpoint still answers ordinary HTTP 200; Go `ReverseProxy` only tunnels on 101.

`bypassRules` already skip chosen method+path before `isWebsocket`. A separate Traefik router without this middleware is the other operator skip.

Status request header: every terminal path except the WebSocket skip `Set`s it. A client `X-Waf-Status: ok` therefore survives only on that skip.

## Decisions

Industry WAFs that cannot parse frames after 101 still inspect the handshake HTTP request. They do not treat `Upgrade`/`Connection` as “not HTTP.” This plugin's skip is the outlier, and it is a WAF bypass for every GET.

`isWebsocket` landed in `0c658f2` (2021-12-28, Alexis Couvreur): “fix: do not forward webscoket requests to ModSecurity”, citing [ModSecurity#1368](https://github.com/owasp-modsecurity/ModSecurity/issues/1368) verbatim (“not capable to inspect WebSockets. It is only capable to understand the http requests.”). The commit treated a handshake-shaped request as a WebSocket, not as HTTP. #1368 was about **frames after the protocol switch**. The handshake is an HTTP GET. In-line nginx+ModSecurity can also rewrite 101 to 200 ([#831](https://github.com/owasp-modsecurity/ModSecurity/issues/831)); that is a different architecture (WAF owns the client response). This plugin already does not: sidecar `< 300` is allow, then `next` writes the client 101.

Tightening to `Sec-WebSocket-Key` + `Version: 13` does not close that bypass: those headers are also client-supplied, and a non-WS backend still 200s. That was the leftover `fix-websocket-bypass` idea; it is not enough.

Drop `isWebsocket`. Inspect every request that does not match `bypassRules` (and is not already-unhealthy). Operators who run WebSocket paths that CRS false-positives add a `bypassRules` entry (or omit the middleware on that router). Independently, delete `modSecurityStatusRequestHeader` from `req.Header` at the start of `ServeHTTP` so no path forwards a client value.

This plugin can send the handshake to the sidecar without terminating WebSocket: sidecar `< 300` (including 200 and 101) is allow, then `next` does the real 101. Frames after 101 never enter `ServeHTTP`.

Measured 2026-09-03 on this product's CRS 4.3.0 pin (`PARANOIA=1`, `ANOMALY_INBOUND=5`). Direct sidecar GET `/ws-echo` with RFC 6455 handshake headers (`Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Version: 13`, `Host: localhost:8000`). Plugin skip was not in the path (curl/nc to `waf:8080`).

| Stack | Clean handshake | Same handshake + `id=1' OR '1'='1` | Elapsed |
| --- | --- | --- | --- |
| apache-drain (running `remove-dummy` overlay, `RewriteRule` 200) | 200 body `OK` | 403 CRS 942100 + 949110 | ~100–130 ms |
| apache-whoami (`wsprobe-apache`, `BACKEND=http://dummy`) | 200 whoami dump | 403 same CRS ids | ~120 ms |
| nginx-whoami (`wsprobe-nginx`) | 200 whoami dump | 403 | ~120 ms |
| nginx-drain (`wsprobe-nginx-drain`) | 200 body `OK` | 403 | ~126 ms |

Also 200: empty User-Agent (ClientWebSocket-like) and browser-like `Connection: keep-alive, Upgrade` + `Origin` + `Sec-WebSocket-Extensions`. Image rules have no `websocket` string; REQUEST-920's Connection rule is duplicate `keep-alive`/`close`, not Upgrade.

Apache whoami overlay still contains `RewriteRule` to `BACKEND_WS` (`ws://localhost:8081`, nothing listens). That rewrite sits outside the `:8080` VirtualHost. The handshake was `ProxyPass`'d to dummy as HTTP (dummy saw `Connection: close` and `Sec-WebSocket-Key`; ~107 ms, not a 502/timeout). Residual: if that rewrite later inherits into the vhost, sidecar 5xx is a plugin WAF failure (502 until the health tracker fail-opens), not a CRS deny.

CI `/ws-echo` does not need a test `bypassRules` for a clean handshake on these four stacks. A probe with SQLi in the query is still 403 — CRS is inspecting the GET.

## Open questions

- Q: Why was `isWebsocket` introduced?
  Decision: resolved — 2021 skip copied ModSecurity#1368 (“cannot inspect WebSockets”) onto the handshake GET. That issue is about frames after 101, not the opening HTTP request. In-line 101→200 (#831) does not apply here because this plugin does not copy sidecar 2xx/101 to the client.
  By: explore

- Q: What do other WAF products do when they cannot tell a WebSocket handshake from a forged Upgrade?
  Decision: resolved — they inspect the opening HTTP request and do not inspect frames after 101. Cloudflare WAF: initial upgrade is subject to managed/custom/rate-limit rules; after the connection is established, no further inspections (`knowledge/research/ext_cloudflare_waf_websocket/`). AWS WAF: HTTP(S) web requests including the upgrade; after ALB connection upgrade, WAF integrations no longer apply (`knowledge/research/ext_aws_waf_websocket/`). Azure Front Door and Application Gateway WAF: handshake is HTTP; after upgrade, pass-through (`knowledge/research/ext_azure_waf_websocket/`). Google Cloud Armor: evaluates the first HTTP(S) request only (`knowledge/research/ext_google_cloud-armor_websocket/`). libmodsecurity: HTTP requests only, not WebSocket streams (`knowledge/research/ext_modsecurity_websocket-inspection/`). Coraza: phases 1–2 on the upgrade GET; deny still 403s the handshake; skip only response processing after Hijack (`knowledge/research/ext_coraza_waf_websocket/`). Fastly Edge NGWAF does not inspect WS; Core can opt-in per location (`knowledge/research/ext_fastly_ngwaf_websocket/`). HAProxy tunnels after a successful 101 and by default rejects a handshake missing `Sec-WebSocket-Key` (`knowledge/research/ext_haproxy_http_websocket/`). Traefik Hub Coraza WAF docs do not add a skip-on-Upgrade (`knowledge/research/ext_traefik_waf_websocket/`). No official doc skips WAF because Upgrade headers are present. Operators add allow/exclusion rules when managed rules false-positive a real handshake (AWS blog), which is this plugin's `bypassRules`.
  By: explore

- Q: Should this plugin drop automatic WebSocket detection and rely on `bypassRules` for operator-chosen WebSocket paths?
  Decision: resolved — yes. Inspect the opening HTTP request like other WAFs. Do not treat `Upgrade`/`Connection` as a skip. Frames after 101 already never enter `ServeHTTP` (Traefik tunnels). `bypassRules` remains for CRS false positives on a real handshake path, not as the default for every Upgrade GET.
  By: propose

- Q: Independently, must a client-supplied status request header be stripped?
  Decision: resolved — yes. Delete `modSecurityStatusRequestHeader` from `req.Header` at the top of `ServeHTTP` before any branch. Reproduced: GET + Upgrade + `X-Waf-Status: ok` reached `next` with `ok` and zero sidecar hits (throwaway test, deleted, not committed).
  By: explore

- Q: Will sending the handshake to the sidecar break a real WebSocket through Traefik?
  Decision: resolved — CRS 4.3.0 at this pin's PL1/inbound-5 allows a clean `/ws-echo` handshake GET on all four stacks (sidecar 200 in ~130 ms). Plugin then `next`s; Traefik still does the real 101. Same GET with SQLi in the query is 403 (942100). No test `bypassRules` needed for a clean handshake. Residual: Apache `BACKEND_WS` rewrite did not fire on whoami (vhost inherit); if it later did, sidecar 5xx is fail-open/502, not a CRS 403.
  By: explore

- Q: Who owns “this request is a WebSocket”?
  Decision: resolved — none in this plugin. Traefik may later 101-tunnel; the backend may refuse the upgrade. The plugin SHALL NOT reconstruct that fact from client `Upgrade` headers. The operator owns an optional skip via `bypassRules` or router wiring.
  By: propose
