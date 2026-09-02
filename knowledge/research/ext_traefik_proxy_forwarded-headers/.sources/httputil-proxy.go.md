---
url: https://github.com/traefik/traefik/blob/237f13c677edb45ab696b7347b517e1f6b46b849/pkg/proxy/httputil/proxy.go
title: pkg/proxy/httputil/proxy.go X-Forwarded-For append
fetched: 2026-09-01
authority: source
ref: github.com/traefik/traefik@237f13c677edb45ab696b7347b517e1f6b46b849:pkg/proxy/httputil/proxy.go
---

Inspected from a shallow temp clone of traefik/traefik master; clone deleted after extract.

`SetNotAppendXFF` / `ShouldNotAppendXFF`: context value `NotAppendXFF`. Set by the entrypoint wrapper when `notAppendXForwardedFor` is true.

`rewriteRequestBuilder` (stdlib ReverseProxy Rewrite):

1. `copyForwardedHeader` copies inbound `X-Forwarded-For`, `Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Proto` onto Out (Rewrite would otherwise have deleted them).
2. If `!ShouldNotAppendXFF(pr.In.Context())` and `SplitHostPort(pr.In.RemoteAddr)` succeeds:
   - `prior, ok := pr.Out.Header["X-Forwarded-For"]`
   - `omit := ok && prior == nil` (Go issue 38079)
   - if `len(prior) > 0`: `clientIP = strings.Join(prior, ", ") + ", " + clientIP`
   - if `!omit`: `Set("X-Forwarded-For", clientIP)`

`pkg/proxy/fast/proxy.go` uses the same SplitHostPort / Join / omit / context-flag sequence on the outbound request.

proxy_test.go rewriteRequestBuilder: inbound `X-Forwarded-For: 1.2.3.4`, `RemoteAddr 127.0.0.1:1234` → `1.2.3.4, 127.0.0.1`. With `SetNotAppendXFF`, stays `1.2.3.4`.
