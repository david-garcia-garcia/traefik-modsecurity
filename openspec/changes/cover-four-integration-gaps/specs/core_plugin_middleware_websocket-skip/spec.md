## ADDED Requirements

### Requirement: Four-stack suite proves handshake-only skip

The four-stack integration suite (`scripts/integration-tests.Tests.ps1` on apache-whoami, nginx-whoami, apache-drain, nginx-drain) SHALL include Pester coverage that a forged WebSocket Upgrade is still inspected by CRS and that a real handshake skips CRS.

#### Scenario: Forged Upgrade with a CRS probe is blocked

- **WHEN** the suite GET `/protected` with a CRS SQL-injection query, `Upgrade: websocket`, and `Connection` without the token `upgrade`
- **THEN** the client status SHALL be 4xx or 5xx at or above 400
- **AND** the request SHALL NOT complete as an HTTP 200 from whoami

#### Scenario: Real handshake with a CRS probe still upgrades

- **WHEN** the suite opens a WebSocket to `/ws-echo` whose query string contains a CRS SQL-injection probe
- **THEN** the handshake SHALL complete and a text frame SHALL echo
