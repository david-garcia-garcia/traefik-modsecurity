---
url: https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/
title: Traefik EntryPoints — Forwarded Headers
fetched: 2026-09-01
authority: official
---

Table (defaults):

- `forwardedHeaders.insecure`: always trust `X-Forwarded-*`. Recommend tests only, not production. Default `false`.
- `forwardedHeaders.trustedIPs`: IPs or CIDR from which Traefik trusts `X-Forwarded-*`. Default empty.
- `forwardedHeaders.notAppendXForwardedFor`: when `true`, Traefik will not append the client's `RemoteAddr` to `X-Forwarded-For`. Existing header preserved as-is. If no header exists, none is added. Default `false`.
- `forwardedHeaders.connection`: Connection headers allowed to pass through the middleware chain before removal.

Section “Forwarded Headers”: “You can configure Traefik to trust the forwarded headers information (`X-Forwarded-*`).”

`connection` paragraph: removal of Connection-listed fields happens as soon as Traefik handles the request; removed headers are not available when the request passes through the middleware chain.

The page does not say that the entrypoint wrapper appends `RemoteAddr` to `X-Forwarded-For` before middleware. The `notAppendXForwardedFor` sentence names the append without saying which hop performs it.
