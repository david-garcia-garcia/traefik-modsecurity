---
url: https://github.com/traefik/traefik/blob/237f13c677edb45ab696b7347b517e1f6b46b849/pkg/middlewares/forwardedheaders/forwarded_header.go
title: pkg/middlewares/forwardedheaders/forwarded_header.go
fetched: 2026-09-01
authority: source
ref: github.com/traefik/traefik@237f13c677edb45ab696b7347b517e1f6b46b849:pkg/middlewares/forwardedheaders/forwarded_header.go
---

Inspected from a shallow temp clone of traefik/traefik master; clone deleted after extract.

Constants include `X-Forwarded-For` and `xRealIP = "X-Real-Ip"`. Both are in `XHeadersSet` (deleted on untrusted).

ServeHTTP:

- If `!insecure && !isTrustedIP(RemoteAddr)`: `DeleteXForwardedHeaders`.
- `rewrite(r)`
- `removeConnectionHeaders(r)`
- If `notAppendXForwardedFor`: `r = r.WithContext(httputil.SetNotAppendXFF(r.Context()))`
- `next.ServeHTTP(w, r)`

rewrite (XFF / Real-IP only):

- `clientIP, _, err := net.SplitHostPort(outreq.RemoteAddr)`; on success `removeIPv6Zone` (`strings.Cut` on `%`).
- If `X-Real-Ip` is empty, `Set` it to `clientIP`.
- If `Values("X-Forwarded-For")` is non-empty, `Set` the join of those values with `", "`. No append of `clientIP`.

removeIPv6Zone: `fe80::1%eth0` → `fe80::1`.

forwarded_header_test.go:

- Default / untrusted: incoming XFF becomes `""`.
- insecure or trusted: incoming XFF kept (multi-value folded: `10.0.0.4, 10.0.0.3` + `10.0.0.2, 10.0.0.1` + `10.0.0.0` → one header).
- `xRealIP populated from remote address`: `RemoteAddr 10.0.1.101:80` → `X-Real-Ip: 10.0.1.101`.
- Existing `X-Real-Ip` under insecure is kept.
- `all Empty` with empty RemoteAddr: expected `X-Forwarded-For: ""`.
