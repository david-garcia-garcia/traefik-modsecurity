## Context

See proposal.md Why. Stock `owasp/modsecurity-crs` 4.3.0 pins reverse-proxy to `BACKEND` (Apache `ProxyPass`, nginx `proxy_pass`). This repo mounts `crs-apache/httpd-vhosts.conf` and nginx `crs-nginx/realip.conf`. Plugin `ServeHTTP` already allows sidecar `< 300` and copies 3xx/4xx as a block — do not change it.

Explore measured: nginx `return 200` in `location /` skips CRS (URI and POST-body probes returned 200). Apache image `/healthz` `RewriteRule` `[R=200]` still 403s those probes, but a 2-byte 200 + `Range: bytes=10240-` is still 416.

## Goals / Non-Goals

**Goals:**

- Inspect-only 200 after request phases on Apache and nginx compose in this repo
- Drop unlabeled `dummy`; keep labeled whoami apps
- Sidecar never 416 on `Range`; client-IP overlays unchanged

**Non-Goals:**

- Plugin Config / `serve.go` / in-process libmodsecurity
- Pointing `BACKEND` at Traefik or the real app
- Committing `Benchmark*` (throughput is measured for the delivery card only)

## Decisions

1. **Apache inspect-only = existing `/healthz` rewrite, not Lua/CGI.** `rewrite_module` is loaded; `mod_lua` / `mod_cgi` are on disk but not loaded. Live `/healthz`: benign POST 200, URI/POST SQLi 403. Alternative (Lua `DONE`) needs `LoadModule` we do not want.

2. **Unset `Range` and `If-Range` on the Apache inspect-only vhost.** Tiny 200 bodies 416 without this; dummy whoami was the same class of failure. Alternative: CGI that ignores Range — extra module.

3. **Nginx: loopback drain-200, never `return`.** Measured `return 200` allowed SQLi. Image has `nc`, not Python/`httpd`. Entrypoint.d starts a loopback listener that always writes HTTP 200 (ignore Range); `BACKEND=http://127.0.0.1:18081` (or the next free high port). Keep `zz-realip.conf`. Alternative: custom image — heavier.

4. **Identity stays with Traefik + CRS remoteip/real_ip.** Do not set `X-Real-IP` in the drain or rewrite handler.

## Risks / Trade-offs

- [nginx drain dies] → sidecar 502 → plugin WAF failure / fail-open. Mitigation: simple `nc` loop, loopback only, compose healthcheck still hits `/` or `/healthz`.
- [Apache rewrite 200 skips a future CRS phase] → Mitigation: Pester URI + POST-body probes are the gate; abort if they 200.
- [Range unset hides a real Range from CRS] → CRS does not need Range for request rules; app still sees Range via `next`.

## Migration Plan

Operators who copied `BACKEND=http://dummy` from this repo’s compose drop dummy and take the overlay files. Rollback: restore previous compose + vhost. No plugin version bump required.

## Open Questions

None that change specs. Drain port 18081 is assumed; implement may pick another loopback high port.
