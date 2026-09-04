## ADDED Requirements

### Requirement: Four-stack suite proves sidecar 5xx is not copied

The four-stack integration suite SHALL include Pester coverage that a sidecar HTTP 5xx with a distinctive body is treated as a WAF failure, not a copied security block. The suite SHALL use a fixture origin that returns HTTP 503 with that body, not CRS `deny,status:500`. The Traefik route under test SHALL have fail-open backoff off.

#### Scenario: Sidecar 503 becomes client 502 without the fixture body

- **WHEN** the suite GET the fixture-backed route whose `modSecurityUrl` is the 503 origin
- **AND** that middleware has `unhealthyWafBackOffPeriodSecs` omitted or 0
- **THEN** the client status SHALL be HTTP 502
- **AND** the client status SHALL NOT be HTTP 503
- **AND** the client body SHALL NOT contain the fixture's distinctive marker
- **AND** Traefik access log `X-Waf-Status` for that path SHALL be `error`
