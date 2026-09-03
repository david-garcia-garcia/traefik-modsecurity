## Context

See proposal.md Why. Demo compose is already Apache drain. Tests still run unlabeled `dummy` on whoami stacks. Plugin `ServeHTTP` copies sidecar `300–499` as a block — do not change it.

Explore measured 2026-09-03: Apache drain stays 200 on Range, `If-Modified-Since`, and `If-None-Match: *`. Nginx drain Range is 200 (`max_ranges 0`) but `If-None-Match: *` is 304 on the loopback `return 200` origin, the public sidecar, and Traefik. nginx `etag off` / `if_modified_since off` / `error_page 304=200` do not stop `*`. `return 204` stays 204 (rejected: keep 200). `proxy_set_header If-None-Match ""; If-Modified-Since ""` then `proxy_pass` to `return 200` stays 200. CRS rewrite/preaccess run before `proxy_pass`, so the public listener still sees the client headers. Finding: `knowledge/research/ext_nginx_not-modified_if-none-match/`.

## Goals / Non-Goals

**Goals:**

- Dummy gone from test compose, CI, Pester, and README
- Sidecar 200 on Range and on `If-None-Match` / `If-Modified-Since` for both Apache and nginx drain
- README points at the sample CRS files tests mount
- Two-stack suite (`apache-drain`, `nginx-drain`) with allow-path benches

**Non-Goals:**

- Plugin Config / `serve.go` / treating 304 as allow
- Pointing `BACKEND` at Traefik or the real app
- Archiving leftover `openspec/changes/inspect-only-crs-sidecar/`
- Committing Go `Benchmark*` tests

## Decisions

1. **Bake drain into the test compose files; delete overlays and dummy.** `docker-compose.test.yml` mounts `httpd-vhosts.drain.conf` and drops `dummy` / `BACKEND=http://dummy`. `docker-compose.test.nginx.yml` sets `BACKEND=http://127.0.0.1:18081` and mounts `drain-origin.conf` plus the drain `proxy_backend` overlay. Delete `docker-compose.test.apache-drain.yml`, `docker-compose.test.nginx-drain.yml`, and `crs-apache/httpd-vhosts.conf`. Stack names stay `apache-drain` / `nginx-drain` so CI and Pester strings stay honest.

2. **Nginx 304 fix = omit conditionals on `proxy_pass`, not `return 204`.** Overlay CRS `includes/proxy_backend.conf.template` with this pin’s stock file (`Host $host`, `proxy_pass $upstream`) plus empty `If-None-Match` and `If-Modified-Since`. Later CRS docker templates use `${PROXY_HOST_HEADER}` / `${BACKEND}`; those names fail nginx on `4.3.0-nginx-alpine-202406090906`. Do not `return` on CRS `location /`. Keep loopback `return 200` + `max_ranges 0`.

3. **Apache also unsets `If-Modified-Since` / `If-None-Match` early.** Already 200 without that; same defense as Range/`If-Range` so a future vhost tweak cannot 304.

4. **Identity stays with Traefik + CRS remoteip/real_ip.** Do not set `X-Real-IP` in drain handlers. Do not reconstruct client IP in the plugin.

5. **Pester asserts the probes that dummy used to fail.** Range not 416 and `If-None-Match: *` / `If-Modified-Since` not 304 on both stacks. Drop dummy-present / whoami skip helpers that exist only for the four-stack matrix.

## Risks / Trade-offs

- [nginx drain origin down] → sidecar 502 → plugin WAF failure / fail-open. Mitigation: in-process loopback `server`; healthcheck still hits public `:8080`.
- [Empty `proxy_set_header` hides conditionals from CRS] → Mitigation: those headers are cleared only on the upstream request after rewrite/preaccess. CRS on the public server still sees them.
- [Operators still copy dummy from old README / forks] → Mitigation: README states drain-only and links the sample files. Plugin still copies origin 304 if they use a static `BACKEND`.
- [Absolute RPS assertions flake] → Assert req/s > 0; print `BENCH stack=` lines.

## Migration Plan

Operators on demo compose: no change (already drain). Operators who copied test whoami compose: drop `dummy`, mount drain vhost / nginx drain origin + `proxy_backend` overlay, set nginx `BACKEND=http://127.0.0.1:18081`. Rollback: restore previous compose + `httpd-vhosts.conf`. No plugin version bump.

## Open Questions

None that change specs. Drain listen stays `127.0.0.1:18081`.
