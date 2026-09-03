## Purpose

Defines how this repo’s OWASP CRS Docker sidecar inspects a request copy and answers HTTP 200 without a dummy origin, while still applying CRS request rules and without turning `Range` into a sidecar 4xx that the plugin copies as a block.

## ADDED Requirements

### Requirement: Sidecar allow is HTTP 200 without a dummy origin

After ModSecurity request phases, the CRS sidecar used by this repo’s compose files SHALL respond HTTP 200 to a benign GET and to a benign POST with a small body. Compose SHALL NOT run an unlabeled `dummy` whoami as that sidecar’s origin. Traefik `next` remains the application. The plugin SHALL treat that sidecar 200 as allow (existing `< 300` rule).

#### Scenario: Benign GET through Traefik

- **WHEN** a client GET with no CRS probe reaches a WAF-protected route
- **THEN** the sidecar SHALL respond HTTP 200
- **AND** the application body and status SHALL be unchanged from Traefik `next`

#### Scenario: Benign POST through Traefik

- **WHEN** a client POST with a small non-attack body reaches a WAF-protected route
- **THEN** the sidecar SHALL respond HTTP 200 (not 405)
- **AND** the application SHALL receive that body via `next`

#### Scenario: No dummy service

- **WHEN** the demo or test compose stack is up
- **THEN** `docker compose ps` SHALL NOT list a `dummy` service

### Requirement: CRS still blocks URI and POST-body probes

The inspect-only 200 handler SHALL NOT skip ModSecurity request-header or request-body inspection. A classic CRS probe in the URI or query SHALL produce a sidecar deny (typically 403). A classic CRS probe in the POST body SHALL produce a sidecar deny. A nginx `return` that answers 200 without running those phases SHALL NOT be used.

#### Scenario: URI probe is denied

- **WHEN** a client GET includes a CRS SQL-injection query on a WAF-protected route
- **THEN** the sidecar SHALL respond 403 (or the configured deny status below 500)
- **AND** Traefik `next` SHALL NOT be called

#### Scenario: POST-body probe is denied

- **WHEN** a client POST body contains a CRS SQL-injection probe and the URI is otherwise benign
- **THEN** the sidecar SHALL respond 403 (or the configured deny status below 500)
- **AND** Traefik `next` SHALL NOT be called

### Requirement: Range does not become a sidecar security block

A client `Range` that would be unsatisfiable on a small sidecar body (including `Range: bytes=10240-` on a tiny inspect-only 200) SHALL NOT produce a sidecar 4xx. The sidecar SHALL respond HTTP 200 for that inspect. Traefik `next` may still return 206 or 200 from the application. Client IP for WAF audit SHALL remain Traefik `ClientHost` via the existing `X-Real-IP` overlays (`RemoteIPHeader` / nginx `real_ip`). The plugin SHALL NOT reconstruct client IP.

#### Scenario: Large Range on a small GET

- **WHEN** a client GET to a WAF-protected route includes `Range: bytes=10240-`
- **THEN** the sidecar SHALL respond HTTP 200
- **AND** the client SHALL NOT receive a sidecar 416 copied as a WAF block

#### Scenario: Deny audit still has Traefik ClientHost

- **WHEN** CRS denies a request on the inspect-only sidecar
- **THEN** the WAF JSON audit `REMOTE_ADDR` SHALL equal Traefik access-log `ClientHost` for that request
