## Context

See proposal.md for why. `ServeHTTP` today returns before the sidecar when `isWebsocket` is true (`pkg/modsecurity/serve.go`). Traefik `ReverseProxy` only hijacks after a backend 101, so frames after 101 never call this middleware. Sidecar status below 300 is already allow-then-`next`; 3xx/4xx is a security block copied to the client. That split is enough to inspect a handshake GET without terminating WebSocket.

## Goals / Non-Goals

**Goals:**

- Same inspect unit as other WAFs: the opening HTTP request.
- Same non-unit as other WAFs: frames after 101 (already true).
- No client-supplied status request header forwarded.

**Non-Goals:**

- Inspecting WebSocket frames.
- Teaching the CRS sidecar to terminate or proxy WebSocket.
- Changing `bypassRules` matching (unanchored regex is a different ticket).
- Requiring `Sec-WebSocket-Key` / `Version` to decide inspection.

## Decisions

- **Remove `isWebsocket` instead of tightening it.** Alternative: require `Sec-WebSocket-Key` and `Version: 13`. Rejected: those headers are still client-supplied; a non-WS backend still 200s. Owner of “this is a WebSocket” is Traefik/backend, not this plugin.
- **Del the status header at the top of `ServeHTTP`.** Alternative: set it only on the old skip path. Rejected: every path must overwrite or the client value survives any future early return.
- **Keep `bypassRules` as the operator skip.** Alternative: auto-skip real RFC 6455 handshakes. Rejected: still not a route. Operators who hit CRS false positives on `/ws-echo` (or production WS paths) add a rule, same as AWS WAF allow-before-managed-rules.

## Risks / Trade-offs

- [CRS 403 on a legitimate handshake] → Operator `bypassRules` or a router without this middleware. Measured 2026-09-03: CRS 4.3.0 at this pin's PL1 allows a clean `/ws-echo` handshake GET (sidecar 200). Integration still must prove **full communication**: handshake, two distinct text frames echoed, close. If CI CRS later 403s, add a test `bypassRules` for that path — do not restore `isWebsocket`.
- [Sidecar still ProxyPasses Upgrade and hangs] → `timeoutMillis` then fail-open or 502. Drain overlays already answer 200 without a WS origin. Whoami stacks may 101 the dummy; this plugin treats 101 as allow and calls `next`. Apache whoami's `BACKEND_WS` rewrite did not fire in explore (vhost inherit); residual 5xx would be a WAF failure, not a CRS deny.
- [Operators relied on the silent skip] → **BREAKING**. README and usage packet MUST say handshake GETs are inspected.

## Migration Plan

No Config key change. Upgrade the plugin version. Operators with WebSocket routes that CRS blocks add `bypassRules`. Rollback is the previous plugin version that skipped.

## Open Questions

None. CRS allow of a clean `/ws-echo` handshake was measured in explore. The skip itself was a 2021 misread of [ModSecurity#1368](https://github.com/owasp-modsecurity/ModSecurity/issues/1368) (frames after 101, not the opening HTTP GET).
