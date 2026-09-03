## ADDED Requirements

### Requirement: Handshake detection does not panic

The plugin SHALL decide whether a request is a WebSocket handshake without panicking when the request header map is missing, empty, or lacks `Upgrade` or `Connection`. A GET that is not a handshake SHALL still be sent to ModSecurity.

#### Scenario: Empty header map is not a handshake

- **WHEN** a GET request has an empty header map
- **THEN** the plugin SHALL NOT treat it as a handshake and SHALL NOT panic

#### Scenario: Nil header map is not a handshake

- **WHEN** a GET request has a nil header map
- **THEN** the plugin SHALL NOT treat it as a handshake and SHALL NOT panic

#### Scenario: Server-shaped empty GET does not panic

- **WHEN** a GET request has no body (server empty body) and a nil header map
- **AND** the sidecar allows the request
- **THEN** the plugin SHALL complete the request without panicking and SHALL call the next handler
