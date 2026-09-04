# core_crs_sidecar_inspect-only

## Purpose

Defines how this repo’s OWASP CRS Docker sidecar inspects a request copy and answers HTTP 200 after ModSecurity request phases. Demo compose and integration test stacks use that inspect-only pattern only. CRS request rules still apply. The sidecar MUST NOT turn `Range` or conditional request headers into a 3xx/4xx that the plugin copies as a block. CI-visible Pester MUST pin Range as a labeled-app success and large POST as not 5xx.

## Requirements

### Requirement: Sidecar allow is HTTP 200 after CRS

After ModSecurity request phases, the CRS sidecar used by this repo’s demo compose and integration test stacks SHALL respond HTTP 200 to a benign GET and to a benign POST with a small body. Those compose files SHALL NOT run an unlabeled `dummy` service as the sidecar’s `BACKEND`. Traefik `next` remains the application. The plugin SHALL treat that sidecar 200 as allow (existing `< 300` rule).

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

### Requirement: CRS still blocks URI and POST-body probes

The inspect-only 200 handler SHALL NOT skip ModSecurity request-header or request-body inspection. A classic CRS probe in the URI or query SHALL produce a sidecar deny (typically 403). A classic CRS probe in the POST body SHALL produce a sidecar deny. A nginx `return` that answers 200 on the CRS-facing `location /` without running those phases SHALL NOT be used. A `return 200` on an in-process origin after `proxy_pass` (unix socket or loopback TCP) is allowed (CRS already ran).

#### Scenario: URI probe is denied

- **WHEN** a client GET includes a CRS SQL-injection query on a WAF-protected route
- **THEN** the sidecar SHALL respond 403 (or the configured deny status below 500)
- **AND** Traefik `next` SHALL NOT be called

#### Scenario: POST-body probe is denied

- **WHEN** a client POST body contains a CRS SQL-injection probe and the URI is otherwise benign
- **THEN** the sidecar SHALL respond 403 (or the configured deny status below 500)
- **AND** Traefik `next` SHALL NOT be called

### Requirement: Range does not become a sidecar security block

A client `Range` that would be unsatisfiable on a small sidecar body (including `Range: bytes=10240-` on a tiny inspect-only 200) SHALL NOT produce a sidecar 4xx. The sidecar SHALL respond HTTP 200 for that inspect. The client SHALL receive a successful labeled-application response (HTTP 200, or 206 if that application serves partial content), and the body or headers SHALL identify the labeled application, not a WAF 416 page. Client IP for WAF audit SHALL remain Traefik `ClientHost` via the existing `X-Real-IP` overlays (`RemoteIPHeader` / nginx `real_ip`). The plugin SHALL NOT reconstruct client IP.

#### Scenario: Large Range on a small GET

- **WHEN** a client GET to a WAF-protected route includes `Range: bytes=10240-`
- **THEN** the sidecar SHALL respond HTTP 200
- **AND** the client SHALL NOT receive a sidecar 416 copied as a WAF block
- **AND** the client SHALL receive HTTP 200 or 206 from the labeled application
- **AND** the response body or headers SHALL identify the labeled application

#### Scenario: Deny audit still has Traefik ClientHost

- **WHEN** CRS denies a request on an integration stack
- **THEN** the WAF JSON audit `REMOTE_ADDR` SHALL equal Traefik access-log `ClientHost` for that request

### Requirement: Conditional request headers do not become a sidecar security block

A client `If-None-Match` (including `*`) or `If-Modified-Since` SHALL NOT produce a sidecar 304 or other 3xx. The sidecar SHALL respond HTTP 200 for that inspect. Nginx SHALL omit those request headers on `proxy_pass` to the in-process origin so `return 200` is not rewritten to 304. Apache SHALL unset them on the inspect-only vhost. The plugin SHALL NOT change its 3xx/4xx copy rule. CRS request phases SHALL still see the original client headers on the public sidecar listener.

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

#### Scenario: Both stacks are in CI

- **WHEN** the integration-test workflow runs
- **THEN** it SHALL start `apache-drain` and `nginx-drain`
- **AND** it SHALL NOT start `apache-whoami` or `nginx-whoami`
- **AND** it SHALL print a `BENCH stack=... method=... rps=...` line for GET and POST when bombardier is installed

### Requirement: Drain large POST is not a sidecar 5xx

A benign POST of about 12–16 MiB to the large-body test route (`maxBodySizeBytes` 20 MiB) SHALL NOT produce a sidecar 5xx (Apache AH01084 class). CRS may still reject that body with 413 when image or compose request-body limits are smaller than the POST.

#### Scenario: Large POST on drain

- **WHEN** a client POSTs about 12–16 MiB to `/large-body-test` on `apache-drain` or `nginx-drain`
- **THEN** the client SHALL NOT receive HTTP 5xx
- **AND** the client MAY receive HTTP 200 when CRS allows the body, or HTTP 413 when CRS request-body limits reject it

### Requirement: CI-visible main suite pins Range and large POST

The two-stack integration workflow SHALL run the Range success and large-POST scenarios from `scripts/integration-tests.Tests.ps1`. The CRS POST-body probe on a WAF-protected route SHALL remain a deny (typically 403).

#### Scenario: Main Pester file covers the pins

- **WHEN** the integration-test workflow runs the two-stack matrix
- **THEN** it SHALL execute `scripts/integration-tests.Tests.ps1`
- **AND** that file SHALL contain the Range labeled-app success, large-POST not-5xx, and CRS POST-body deny scenarios
