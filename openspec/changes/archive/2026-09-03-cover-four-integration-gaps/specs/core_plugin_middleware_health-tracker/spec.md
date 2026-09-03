## ADDED Requirements

### Requirement: Four-stack suite proves backoff resume

The four-stack integration suite SHALL include Pester coverage that after `/threshold-test` trips fail-open, the CRS container is healthy again, and `unhealthyWafBackOffPeriodSecs` (10 seconds on that route) has elapsed, the plugin consults the sidecar again.

#### Scenario: CRS probe is blocked after backoff elapses

- **WHEN** the suite has tripped `/threshold-test` fail-open
- **AND** it has started the CRS container and waited until it is healthy
- **AND** it has waited longer than that route's backoff period
- **AND** it then GET `/threshold-test` with a CRS SQL-injection query
- **THEN** the client status SHALL be 4xx or 5xx at or above 400
- **AND** the status SHALL NOT be HTTP 200 pass-through
