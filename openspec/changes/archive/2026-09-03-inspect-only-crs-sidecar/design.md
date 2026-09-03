## Context

See proposal.md Why. Stock `owasp/modsecurity-crs` 4.3.0 pins reverse-proxy to `BACKEND` (Apache `ProxyPass`, nginx `proxy_pass`). This repo mounts `crs-apache/httpd-vhosts.conf` (whoami hop) and `crs-apache/httpd-vhosts.drain.conf` (inspect-only). nginx whoami uses image `proxy_pass` to dummy; nginx drain adds `crs-nginx/drain-origin.conf`. Plugin `ServeHTTP` already allows sidecar `< 300` and copies 3xx/4xx as a block — do not change it.

Explore measured: nginx `return 200` in CRS `location /` skips CRS (URI and POST-body probes returned 200). Apache image `/healthz` `RewriteRule` `[R=200]` still 403s those probes, but a 2-byte 200 + `Range: bytes=10240-` is still 416.

## Goals / Non-Goals

**Goals:**

- Inspect-only 200 after request phases on demo compose and drain test stacks
- Keep unlabeled `dummy` on apache-whoami and nginx-whoami test stacks
- Sidecar never 416 on `Range` on drain stacks; client-IP overlays unchanged
- Benchmark allow-path GET and POST on all four stacks inside the integration suite

**Non-Goals:**

- Plugin Config / `serve.go` / in-process libmodsecurity
- Pointing `BACKEND` at Traefik or the real app
- Committing Go `Benchmark*` tests (throughput is Pester + bombardier)

## Decisions

1. **Apache inspect-only = existing `/healthz` rewrite, not Lua/CGI.** `rewrite_module` is loaded; `mod_lua` / `mod_cgi` are on disk but not loaded. Live `/healthz`: benign POST 200, URI/POST SQLi 403. Alternative (Lua `DONE`) needs `LoadModule` we do not want. Whoami Apache vhost stays stock ProxyPass.

2. **Unset `Range` and `If-Range` on the Apache inspect-only vhost.** Tiny 200 bodies 416 without this; dummy whoami was the same class of failure. Alternative: CGI that ignores Range — extra module.

3. **Nginx drain origin = loopback `server` after `proxy_pass`, never `return` on CRS `location /`.** Measured `return 200` on `location /` allowed SQLi. A second listen on `127.0.0.1:18081` with `max_ranges 0` and `return 200` is dummy-equivalent (CRS already ran). Concurrent (unlike serial `nc`). Keep `zz-realip.conf`. Alternative: `nc` loop — serial, invalid for throughput compare.

4. **Four compose stacks, not drain-only tests.** Base whoami files plus drain overlays (`dummy` `profiles: [whoami-origin]`). `Test-Integration.ps1 -Stack` / `-AllStacks`. CI matrix of four. Pester skips dummy-absent / Range-not-416 on whoami stacks and skips dummy-present on drain.

5. **Identity stays with Traefik + CRS remoteip/real_ip.** Do not set `X-Real-IP` in the drain or rewrite handler.

## Risks / Trade-offs

- [nginx drain origin down] → sidecar 502 → plugin WAF failure / fail-open. Mitigation: in-process nginx `server` on loopback; compose healthcheck still hits public `:8080`.
- [Apache rewrite 200 skips a future CRS phase] → Mitigation: Pester URI + POST-body probes are the gate; abort if they 200.
- [Range unset hides a real Range from CRS] → CRS does not need Range for request rules; app still sees Range via `next`.
- [Absolute RPS assertions flake] → Assert req/s > 0; print `BENCH stack=` lines for the card.

## Migration Plan

Operators who copied `BACKEND=http://dummy` from this repo’s **demo** compose drop dummy and take `httpd-vhosts.drain.conf`. Test whoami stacks stay on dummy. Rollback: restore previous compose + vhost. No plugin version bump required.

## Open Questions

None that change specs. Drain listen is `127.0.0.1:18081`.
