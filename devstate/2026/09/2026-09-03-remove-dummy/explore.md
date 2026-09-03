# Explore
IssueKey: 2026-09-03-remove-dummy

## Concepts

Client → Traefik plugin → copy to CRS sidecar → if sidecar `< 300`, Traefik `next` (labeled whoami / real app). Sidecar `300–499` is copied as a security block. The unlabeled compose `dummy` service is only the CRS image’s `BACKEND`, not `next`.

Inspect-only **drain** means: after CRS request phases, the sidecar answers 200 without that dummy hop. Apache: `httpd-vhosts.drain.conf` (`RewriteRule .* - [R=200,L]`, unset `Range`/`If-Range`). Nginx: public `:8080` still `proxy_pass` (so phase 2 runs); loopback `127.0.0.1:18081` `return 200` + `max_ranges 0`.

Demo compose on main is already Apache drain, no dummy. Tests still ship four stacks so whoami dummy can be compared with drain.

## Decisions

Drain is robust enough to **drop dummy from tests and docs**, after nginx drain is hardened so an origin 304 cannot surface. Do not keep whoami-origin stacks as a museum of known false blocks. Do not change `ServeHTTP`’s 3xx/4xx copy rule.

## Measured (2026-09-03, this worktree)

Apache drain (`docker-compose.test.yml` + `apache-drain` overlay). No `*-dummy-1` in this project. Sidecar `:8080` and Traefik `:8000/protected`:

| Probe | Sidecar | Traefik |
| --- | --- | --- |
| GET allow | 200 | 200 |
| POST allow | 200 | 200 |
| URI SQLi | 403 | 403 |
| POST body SQLi | 403 | 403 |
| `Range: bytes=10240-` | 200 | 200 |
| `If-Modified-Since` (2030) | 200 | 200 |
| `If-None-Match: *` | 200 | 200 |
| HEAD / OPTIONS | (not sidecar-logged) | 200 |

Nginx drain. Same allow/block/Range/If-Modified-Since are 200/403 as expected. **`If-None-Match: *` is 304** on loopback origin, public sidecar, and Traefik (plugin copies it as a block). `etag off` + `if_modified_since off` cannot be applied (overlay is read-only); throwaway `nginx:alpine` showed they would not help anyway. `error_page 304=200` still 304. `return 204` stays 204 (plugin would allow it) — rejected, keep 200. Two-server throwaway: `proxy_set_header If-None-Match ""; If-Modified-Since ""` then `proxy_pass` to `return 200` stays **200**. CRS runs before `proxy_pass`, so the public location still sees the client header.

## Approach

1. Bake drain into `docker-compose.test.yml` / `docker-compose.test.nginx.yml`. Delete unlabeled `dummy`, `BACKEND=http://dummy`, whoami stacks, drain *overlays* (they become the base). Default `Test-Integration.ps1` / CI matrix: `apache-drain`, `nginx-drain` only.
2. Nginx: overlay/include on `proxy_pass` to the loopback origin that clears `If-None-Match` and `If-Modified-Since`. Keep `drain-origin.conf` `return 200` + `max_ranges 0`. Do not `return` on CRS `location /`.
3. Apache: keep drain vhost 200; also unset `If-Modified-Since` / `If-None-Match` early (same pattern as Range). Delete `crs-apache/httpd-vhosts.conf` (ProxyPass dummy hop) once nothing mounts it.
4. Pester: drop dummy-present / whoami skips. Assert Range not 416 **and** `If-None-Match: *` / `If-Modified-Since` not 304 on both remaining stacks. Keep URI + POST-body CRS denies.
5. README: remove dummy architecture/benches. Tell operators to mount the same Apache/nginx sample files the tests use (`httpd-vhosts.drain.conf`, `drain-origin.conf`, `crs-nginx/realip.conf`). Fix the stale RemoteIP link (demo already mounts drain, not ProxyPass vhost).
6. Fold spec `core_crs_sidecar_inspect-only`: drop “whoami stacks keep dummy”. Allow stays sidecar HTTP 200 without dummy.

Plugin `serve.go` unchanged.

## Open questions

- Q: Is nginx drain `If-None-Match: *` → 304 a reason to keep dummy stacks?
  Decision: resolved — no. Strip those request headers on `proxy_pass` to the loopback origin; add Pester; then dummy goes.
  By: explore

- Q: Change the plugin so 304 is not a security block?
  Decision: resolved — no. Ticket is drain-only origins. Classifier stays 3xx/4xx copy. Operators who still point `BACKEND` at a real static site can still 304; README must not teach that hop.
  By: explore

- Q: Keep `crs-apache/httpd-vhosts.conf` (ProxyPass) as a sample?
  Decision: assumed — delete with dummy stacks. Apache sample is `httpd-vhosts.drain.conf`.
  By: explore

- Q: Sidecar allow via `return 204` to dodge nginx 304?
  Decision: resolved — no. Keep HTTP 200; strip conditionals on proxy_pass.
  By: explore

- Q: Who owns client IP / Host for WAF audit if we change drain?
  Decision: resolved — unchanged owners: Traefik `ClientHost` / incoming `Host`; CRS `RemoteIPHeader` / nginx `real_ip` overlays. This change does not reconstruct identity.
  By: explore

- Q: Archive leftover `openspec/changes/inspect-only-crs-sidecar/` (tasks complete, still on main)?
  Decision: assumed — not this ticket’s archive. Fold the spec in a new change. Note as follow-up.
  By: explore
