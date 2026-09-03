## Purpose

Defines how this repo’s OWASP CRS Docker sidecar inspects a request copy and answers HTTP 200. Demo compose and drain test stacks do that without a dummy origin. Whoami test stacks keep the stock dummy hop so both origins stay measurable. CRS request rules still apply. Drain origins MUST NOT turn `Range` into a sidecar 4xx that the plugin copies as a block.

## ADDED Requirements

### Requirement: Sidecar allow is HTTP 200 without a dummy origin

After ModSecurity request phases, the CRS sidecar used by this repo’s demo compose and drain test stacks SHALL respond HTTP 200 to a benign GET and to a benign POST with a small body. Those compose files SHALL NOT run an unlabeled `dummy` whoami as that sidecar’s origin. Traefik `next` remains the application. The plugin SHALL treat that sidecar 200 as allow (existing `< 300` rule).

#### Scenario: Benign GET through Traefik

- **WHEN** a client GET with no CRS probe reaches a WAF-protected route
- **THEN** the sidecar SHALL respond HTTP 200
- **AND** the application body and status SHALL be unchanged from Traefik `next`

#### Scenario: Benign POST through Traefik

- **WHEN** a client POST with a small non-attack body reaches a WAF-protected route
- **THEN** the sidecar SHALL respond HTTP 200 (not 405)
- **AND** the application SHALL receive that body via `next`

#### Scenario: No dummy service on drain and demo stacks

- **WHEN** demo compose, `apache-drain`, or `nginx-drain` is up
- **THEN** `docker compose ps` SHALL NOT list a running `dummy` service

### Requirement: Whoami-origin stacks keep the dummy hop

The integration suite SHALL still ship Apache+whoami and nginx+whoami stacks that run unlabeled `dummy` and set `BACKEND=http://dummy` (Apache `ProxyPass` / nginx `proxy_pass`). Those stacks exist to compare the extra hop against drain.

#### Scenario: Dummy present on whoami stacks

- **WHEN** `apache-whoami` or `nginx-whoami` is up
- **THEN** a `dummy` container SHALL be running

### Requirement: CRS still blocks URI and POST-body probes

The inspect-only 200 handler SHALL NOT skip ModSecurity request-header or request-body inspection. A classic CRS probe in the URI or query SHALL produce a sidecar deny (typically 403). A classic CRS probe in the POST body SHALL produce a sidecar deny. A nginx `return` that answers 200 on the CRS-facing `location /` without running those phases SHALL NOT be used. A `return 200` on a loopback origin after `proxy_pass` is allowed (CRS already ran).

#### Scenario: URI probe is denied

- **WHEN** a client GET includes a CRS SQL-injection query on a WAF-protected route
- **THEN** the sidecar SHALL respond 403 (or the configured deny status below 500)
- **AND** Traefik `next` SHALL NOT be called

#### Scenario: POST-body probe is denied

- **WHEN** a client POST body contains a CRS SQL-injection probe and the URI is otherwise benign
- **THEN** the sidecar SHALL respond 403 (or the configured deny status below 500)
- **AND** Traefik `next` SHALL NOT be called

### Requirement: Range does not become a sidecar security block on drain origins

A client `Range` that would be unsatisfiable on a small sidecar body (including `Range: bytes=10240-` on a tiny inspect-only 200) SHALL NOT produce a sidecar 4xx on drain stacks. The sidecar SHALL respond HTTP 200 for that inspect. Traefik `next` may still return 206 or 200 from the application. Whoami-origin stacks MAY still copy dummy 416. Client IP for WAF audit SHALL remain Traefik `ClientHost` via the existing `X-Real-IP` overlays (`RemoteIPHeader` / nginx `real_ip`). The plugin SHALL NOT reconstruct client IP.

#### Scenario: Large Range on a small GET (drain)

- **WHEN** a client GET to a WAF-protected route on a drain stack includes `Range: bytes=10240-`
- **THEN** the sidecar SHALL respond HTTP 200
- **AND** the client SHALL NOT receive a sidecar 416 copied as a WAF block

#### Scenario: Deny audit still has Traefik ClientHost

- **WHEN** CRS denies a request on any of the four stacks
- **THEN** the WAF JSON audit `REMOTE_ADDR` SHALL equal Traefik access-log `ClientHost` for that request

### Requirement: Four-stack suite measures allow-path throughput

The integration suite SHALL include all four stacks: `apache-whoami`, `nginx-whoami`, `apache-drain`, `nginx-drain`. Each stack run SHALL measure allow-path GET and POST throughput on `/protected` (bombardier `-c 50 -d 15s` or equivalent in Pester). The assertion is that req/s is greater than zero; absolute RPS is recorded for the delivery card, not as a flake-prone floor.

#### Scenario: All four stacks are in CI

- **WHEN** the integration-test workflow runs
- **THEN** it SHALL start each of the four stacks
- **AND** it SHALL print a `BENCH stack=... method=... rps=...` line for GET and POST when bombardier is installed
