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

Tightening to `Sec-WebSocket-Key` + `Version: 13` does not close that bypass: those headers are also client-supplied, and a non-WS backend still 200s. That was the leftover `fix-websocket-bypass` idea; it is not enough.

Drop `isWebsocket`. Inspect every request that does not match `bypassRules` (and is not already-unhealthy). Operators who run WebSocket paths that CRS false-positives add a `bypassRules` entry (or omit the middleware on that router). Independently, delete `modSecurityStatusRequestHeader` from `req.Header` at the start of `ServeHTTP` so no path forwards a client value.

This plugin can send the handshake to the sidecar without trying to terminate WebSocket: sidecar `< 300` (including 200 and 101) is allow, then `next` does the real 101. That is different from in-line nginx+ModSecurity, which historically rewrote 101 to 200.

## Open questions

- Q: What do other WAF products do when they cannot tell a WebSocket handshake from a forged Upgrade?
  Decision: resolved — they inspect the opening HTTP request and do not inspect frames after 101. Cloudflare WAF: initial upgrade is subject to managed/custom/rate-limit rules; after the connection is established, no further inspections (`knowledge/research/ext_cloudflare_waf_websocket/`). AWS WAF: HTTP(S) web requests including the upgrade; after ALB connection upgrade, WAF integrations no longer apply (`knowledge/research/ext_aws_waf_websocket/`). Azure Front Door and Application Gateway WAF: handshake is HTTP; after upgrade, pass-through (`knowledge/research/ext_azure_waf_websocket/`). Google Cloud Armor: evaluates the first HTTP(S) request only (`knowledge/research/ext_google_cloud-armor_websocket/`). libmodsecurity: HTTP requests only, not WebSocket streams (`knowledge/research/ext_modsecurity_websocket-inspection/`). Coraza: phases 1–2 on the upgrade GET; deny still 403s the handshake; skip only response processing after Hijack (`knowledge/research/ext_coraza_waf_websocket/`). Fastly Edge NGWAF does not inspect WS; Core can opt-in per location (`knowledge/research/ext_fastly_ngwaf_websocket/`). HAProxy tunnels after a successful 101 and by default rejects a handshake missing `Sec-WebSocket-Key` (`knowledge/research/ext_haproxy_http_websocket/`). Traefik Hub Coraza WAF docs do not add a skip-on-Upgrade (`knowledge/research/ext_traefik_waf_websocket/`). No official doc skips WAF because Upgrade headers are present. Operators add allow/exclusion rules when managed rules false-positive a real handshake (AWS blog), which is this plugin's `bypassRules`.
  By: explore

- Q: Should this plugin drop automatic WebSocket detection and rely on `bypassRules` for operator-chosen WebSocket paths?
  Decision: assumed — yes. Drop `isWebsocket`. Header-based skip cannot name a WebSocket *route*; it only names client headers. `bypassRules` (or a Traefik router without this middleware) is the trustworthy skip. Default is inspect, including the handshake GET.
  By: explore

- Q: Independently, must a client-supplied status request header be stripped?
  Decision: resolved — yes. Delete `modSecurityStatusRequestHeader` from `req.Header` at the top of `ServeHTTP` before any branch. Reproduced: GET + Upgrade + `X-Waf-Status: ok` reached `next` with `ok` and zero sidecar hits (throwaway test, deleted, not committed).
  By: explore

- Q: Will sending the handshake to the sidecar break a real WebSocket through Traefik?
  Decision: assumed — not for this plugin's allow/block split: sidecar status below 300 is allow, then `next` upgrades. CRS may 403 a legitimate handshake (same as AWS managed CRS on CloudFront). Then the operator adds `bypassRules` for that path. Integration `/ws-echo` currently depends on the skip; after the drop it must still 101. If CRS blocks it in CI, add a test `bypassRules` for `/ws-echo` or confirm drain-200 still lets `next` upgrade.
  By: explore

- Q: Who owns “this request is a WebSocket”?
  Decision: assumed — none in this plugin. Traefik may later 101-tunnel; the backend may refuse the upgrade. The plugin must not reconstruct that fact from client `Upgrade` headers (`skill:sbs-dev-commandments:One job, one owner`). The operator owns the skip via `bypassRules` or router wiring.
  By: explore
