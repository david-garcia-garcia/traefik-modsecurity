## MODIFIED Requirements

### Requirement: Sidecar allow is HTTP 200 without a dummy origin

After ModSecurity request phases, the CRS sidecar used by this repo’s demo compose and integration test stacks SHALL respond HTTP 200 to a benign GET and to a benign POST with a small body. Those compose files SHALL NOT run an unlabeled `dummy` whoami as that sidecar’s origin. Traefik `next` remains the application. The plugin SHALL treat that sidecar 200 as allow (existing `< 300` rule).

#### Scenario: Benign GET through Traefik

- **WHEN** a client GET with no CRS probe reaches a WAF-protected route
- **THEN** the sidecar SHALL respond HTTP 200
- **AND** the application body and status SHALL be unchanged from Traefik `next`

#### Scenario: Benign POST through Traefik

- **WHEN** a client POST with a small non-attack body reaches a WAF-protected route
- **THEN** the sidecar SHALL respond HTTP 200 (not 405)
- **AND** the application SHALL receive that body via `next`

#### Scenario: No dummy service on demo or test stacks

- **WHEN** demo compose, `apache-drain`, or `nginx-drain` is up
- **THEN** `docker compose ps` SHALL NOT list a running `dummy` service

### Requirement: Range does not become a sidecar security block on drain origins

A client `Range` that would be unsatisfiable on a small sidecar body (including `Range: bytes=10240-` on a tiny inspect-only 200) SHALL NOT produce a sidecar 4xx. The sidecar SHALL respond HTTP 200 for that inspect. Traefik `next` may still return 206 or 200 from the application. Client IP for WAF audit SHALL remain Traefik `ClientHost` via the existing `X-Real-IP` overlays (`RemoteIPHeader` / nginx `real_ip`). The plugin SHALL NOT reconstruct client IP.

#### Scenario: Large Range on a small GET

- **WHEN** a client GET to a WAF-protected route includes `Range: bytes=10240-`
- **THEN** the sidecar SHALL respond HTTP 200
- **AND** the client SHALL NOT receive a sidecar 416 copied as a WAF block

#### Scenario: Deny audit still has Traefik ClientHost

- **WHEN** CRS denies a request on a drain stack
- **THEN** the WAF JSON audit `REMOTE_ADDR` SHALL equal Traefik access-log `ClientHost` for that request

## ADDED Requirements

### Requirement: Conditional request headers do not become a sidecar security block

A client `If-None-Match` (including `*`) or `If-Modified-Since` SHALL NOT produce a sidecar 304 or other 3xx on drain origins. The sidecar SHALL respond HTTP 200 for that inspect. Nginx SHALL omit those request headers on `proxy_pass` to the loopback origin so `return 200` is not rewritten to 304. Apache SHALL unset them on the inspect-only vhost. The plugin SHALL NOT change its 3xx/4xx copy rule. CRS request phases SHALL still see the original client headers on the public sidecar listener.

#### Scenario: If-None-Match asterisk

- **WHEN** a client GET to a WAF-protected route includes `If-None-Match: *`
- **THEN** the sidecar SHALL respond HTTP 200
- **AND** the client SHALL NOT receive a sidecar 304 copied as a WAF block

#### Scenario: If-Modified-Since in the future

- **WHEN** a client GET to a WAF-protected route includes `If-Modified-Since` with a date in the future
- **THEN** the sidecar SHALL respond HTTP 200
- **AND** Traefik `next` SHALL be called

### Requirement: Two-stack suite measures allow-path throughput

The integration suite SHALL include `apache-drain` and `nginx-drain` only. Each stack run SHALL measure allow-path GET and POST throughput on `/protected` (bombardier `-c 50 -d 15s` or equivalent in Pester). The assertion is that req/s is greater than zero; absolute RPS is recorded for the delivery card, not as a flake-prone floor.

#### Scenario: Both drain stacks are in CI

- **WHEN** the integration-test workflow runs
- **THEN** it SHALL start `apache-drain` and `nginx-drain`
- **AND** it SHALL NOT start `apache-whoami` or `nginx-whoami`
- **AND** it SHALL print a `BENCH stack=... method=... rps=...` line for GET and POST when bombardier is installed

## REMOVED Requirements

### Requirement: Whoami-origin stacks keep the dummy hop

**Reason:** Dummy `BACKEND` returns Range 416 and (on nginx `return 200`) `If-None-Match: *` 304, which the plugin copies as a WAF block. Drain origins plus conditional-header stripping are the supported inspect-only setup.

**Migration:** Use `apache-drain` / `nginx-drain` (baked into `docker-compose.test.yml` / `docker-compose.test.nginx.yml`). Mount `crs-apache/httpd-vhosts.drain.conf` or nginx `drain-origin.conf` plus the drain `proxy_backend` overlay. Do not run unlabeled `dummy`.

### Requirement: Four-stack suite measures allow-path throughput

**Reason:** Whoami-origin stacks exist only to keep dummy measurable. This change drops dummy.

**Migration:** Run `./Test-Integration.ps1 -Stack apache-drain` or `-Stack nginx-drain`, or `-AllStacks` for both remaining stacks.
