## MODIFIED Requirements

### Requirement: Range does not become a sidecar security block on drain origins

A client `Range` that would be unsatisfiable on a small sidecar body (including `Range: bytes=10240-` on a tiny inspect-only 200) SHALL NOT produce a sidecar 4xx on drain stacks. The sidecar SHALL respond HTTP 200 for that inspect. The client SHALL receive a successful labeled-application response (HTTP 200, or 206 if that application serves partial content), and the body or headers SHALL identify the labeled application, not a WAF 416 page. Whoami-origin Apache stacks SHALL still copy dummy 416 for that Range so drain is distinguishable from a plugin that strips Range. Other whoami stacks MAY skip that contrast when the dummy does not 416. Client IP for WAF audit SHALL remain Traefik `ClientHost` via the existing `X-Real-IP` overlays (`RemoteIPHeader` / nginx `real_ip`). The plugin SHALL NOT reconstruct client IP.

#### Scenario: Large Range on a small GET (drain)

- **WHEN** a client GET to a WAF-protected route on a drain stack includes `Range: bytes=10240-`
- **THEN** the sidecar SHALL respond HTTP 200
- **AND** the client SHALL NOT receive a sidecar 416 copied as a WAF block
- **AND** the client SHALL receive HTTP 200 or 206 from the labeled application
- **AND** the response body or headers SHALL identify the labeled application

#### Scenario: Large Range on a small GET (apache-whoami)

- **WHEN** a client GET to a WAF-protected route on the Apache whoami-origin stack includes `Range: bytes=10240-`
- **THEN** the client SHALL receive HTTP 416 copied from the dummy origin

#### Scenario: Deny audit still has Traefik ClientHost

- **WHEN** CRS denies a request on any of the four stacks
- **THEN** the WAF JSON audit `REMOTE_ADDR` SHALL equal Traefik access-log `ClientHost` for that request

## ADDED Requirements

### Requirement: Drain large POST is not a sidecar 5xx

A benign POST of about 12–16 MiB to the large-body test route (`maxBodySizeBytes` 20 MiB) on a drain stack SHALL NOT produce a sidecar 5xx (Apache AH01084 class). CRS may still reject that body with 413 when image or compose request-body limits are smaller than the POST. Whoami-origin stacks SHALL NOT assert 5xx unless that dummy hop is measured to fail that way.

#### Scenario: Large POST on drain

- **WHEN** a client POSTs about 12–16 MiB to `/large-body-test` on a drain stack
- **THEN** the client SHALL NOT receive HTTP 5xx
- **AND** the client MAY receive HTTP 200 when CRS allows the body, or HTTP 413 when CRS request-body limits reject it

### Requirement: CI-visible main suite pins Range and large POST

The four-stack integration workflow SHALL run the Range drain, Range apache-whoami, and drain large-POST scenarios from `scripts/integration-tests.Tests.ps1`. The CRS POST-body probe on a WAF-protected route SHALL remain a deny (typically 403) on drain stacks.

#### Scenario: Main Pester file covers the pins

- **WHEN** the integration-test workflow runs the four-stack matrix
- **THEN** it SHALL execute `scripts/integration-tests.Tests.ps1`
- **AND** that file SHALL contain the drain Range success, apache-whoami Range 416, drain large-POST not-5xx, and CRS POST-body deny scenarios
