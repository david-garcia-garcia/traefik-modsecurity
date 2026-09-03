## ADDED Requirements

### Requirement: Four-stack suite proves deny-verb 400 during fail-open

The four-stack integration suite SHALL include Pester coverage that a GET with a body is rejected with HTTP 400 after the `/threshold-test` health tracker has tripped fail-open. The suite SHALL NOT use `/force-test` for this scenario (`/force-test` has no health tracker).

#### Scenario: GET with body is 400 after threshold trip

- **WHEN** the suite has stopped the CRS container and tripped `/threshold-test` (three failures, pass-through 200)
- **AND** it then GET `/threshold-test` with a non-empty body
- **THEN** the client status SHALL be HTTP 400
- **AND** the response SHALL NOT be the whoami body
