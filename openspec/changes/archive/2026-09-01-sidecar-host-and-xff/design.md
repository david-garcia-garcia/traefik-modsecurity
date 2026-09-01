## Context

`ServeHTTP` builds the sidecar request as `ModSecurityUrl + RequestURI`, then copies `req.Header`. Incoming `Host` lives on `req.Host`, not in that map. `RemoteAddr` is unused. A probe recorded sidecar `Host=127.0.0.1:<waf-port>` and `X-Forwarded-For` equal to the copied prior chain only.

## Goals / Non-Goals

**Goals:**

- Sidecar `Host` is the incoming `req.Host`.
- Peer IP from `RemoteAddr` is appended to `X-Forwarded-For` the ReverseProxy Director way.

**Non-Goals:**

- `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`
- `http.NewRequestWithContext`
- New config keys
- ReverseProxy `Rewrite` / `SetXForwarded` (those also set Host/Proto and delete XFF on parse failure)

## Decisions

- Set `proxyReq.Host = req.Host` after the header copy. Go's client sends `Request.Host` as the Host header; do not also write `Header["Host"]`.
- Own the append in one helper (`appendPeerToXForwardedFor`). Algorithm: `net.SplitHostPort(remoteAddr)`; on success, `strings.Join` existing `Header["X-Forwarded-For"]` values with `", "` then `", " + clientIP`, then `Set`. On parse failure, return without writing or deleting.
- Do not implement ReverseProxy Issue 38079 (nil map entry means omit). After `make` + range copy the key is absent or a real slice.
- No public config. This is default sidecar construction.

## Risks / Trade-offs

- [Duplicated last hop] If Traefik already appended this peer, XFF may list it twice. Accepted: matches ReverseProxy and keeps the immediate peer visible.
- [Unparseable RemoteAddr] Rare in net/http servers (`ip:port` or `[ipv6]:port`). We skip rather than guess.

## Migration Plan

No migration. Existing deployments start sending Host and XFF on the next plugin load. No config change.

## Open Questions

None beyond `devstate/explore.md` assumed rows (Traefik may already set XFF; still append).
