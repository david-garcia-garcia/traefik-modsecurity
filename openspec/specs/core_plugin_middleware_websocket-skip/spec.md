# core_plugin_middleware_websocket-skip

## Purpose

Lets the middleware skip ModSecurity only for a real HTTP/1.1 WebSocket handshake so a long-lived upgrade is not buffered, while every other request stays inspected.

## Requirements

### Requirement: Handshake-only WAF skip

The plugin SHALL skip the ModSecurity call and invoke the next handler when, and only when, all of the following are true: the request method is `GET`; some `Connection` header field contains the token `upgrade` (comma-separated tokens, comparison case-insensitive); some `Upgrade` header field value equals `websocket` (comparison case-insensitive). The plugin SHALL NOT require `Sec-WebSocket-Key` or `Sec-WebSocket-Version` for this skip. The plugin SHALL inspect any request that fails any of those checks, including a non-GET request that only adds `Upgrade: websocket`.

#### Scenario: Real handshake skips the WAF

- **WHEN** a `GET` request has `Connection` containing the token `upgrade` and `Upgrade` matching `websocket` case-insensitively
- **THEN** the plugin SHALL call the next handler without sending the request to ModSecurity

#### Scenario: Forged Upgrade header is inspected

- **WHEN** a non-GET request includes `Upgrade: websocket` and does not carry a `Connection` token `upgrade`
- **THEN** the plugin SHALL send the request to ModSecurity and SHALL NOT skip on that header alone

#### Scenario: Connection without upgrade token is inspected

- **WHEN** a `GET` request includes `Upgrade: websocket` and `Connection` has no `upgrade` token
- **THEN** the plugin SHALL send the request to ModSecurity

#### Scenario: Mixed-case handshake skips the WAF

- **WHEN** a `GET` request has `Connection: Upgrade` and `Upgrade: WebSocket`
- **THEN** the plugin SHALL call the next handler without sending the request to ModSecurity

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

### Requirement: Four-stack suite proves handshake-only skip

The four-stack integration suite (`scripts/integration-tests.Tests.ps1` on apache-whoami, nginx-whoami, apache-drain, nginx-drain) SHALL include Pester coverage that a forged WebSocket Upgrade is still inspected by CRS and that a real handshake skips CRS.

#### Scenario: Forged Upgrade with a CRS probe is blocked

- **WHEN** the suite GET `/protected` with a CRS SQL-injection query, `Upgrade: websocket`, and `Connection` without the token `upgrade`
- **THEN** the client status SHALL be 4xx or 5xx at or above 400
- **AND** the request SHALL NOT complete as an HTTP 200 from whoami

#### Scenario: Real handshake with a CRS probe still upgrades

- **WHEN** the suite opens a WebSocket to `/ws-echo` whose query string contains a CRS SQL-injection probe
- **THEN** the handshake SHALL complete and a text frame SHALL echo
