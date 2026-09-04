# core_plugin_middleware_websocket-handshake

## Purpose

Lets the middleware inspect the opening HTTP request of a WebSocket upgrade like any other GET, while Traefik (not this plugin) tunnels frames after the backend's 101.

## Requirements

### Requirement: Opening handshake HTTP is inspected

The plugin SHALL send a request to ModSecurity even when the method is `GET`, some `Connection` header field contains the token `upgrade` (comma-separated tokens, comparison case-insensitive), and some `Upgrade` header field value equals `websocket` (comparison case-insensitive). The plugin SHALL NOT skip the sidecar because those headers are present. The plugin SHALL NOT require or inspect `Sec-WebSocket-Key` or `Sec-WebSocket-Version` in order to decide whether to call ModSecurity. After a sidecar allow (status below 300), the plugin SHALL invoke the next handler so Traefik can complete a backend 101 and tunnel later frames. WebSocket frames after that 101 are outside this plugin's unit; a live integration test SHALL prove full communication (handshake plus echoed text frames on that connection), not 101-only.

#### Scenario: Handshake-shaped GET is sent to ModSecurity

- **WHEN** a `GET` request has `Connection` containing the token `upgrade` and `Upgrade` matching `websocket` case-insensitively
- **AND** the sidecar returns 403
- **THEN** the plugin SHALL copy the sidecar response to the client
- **AND** the plugin SHALL NOT call the next handler

#### Scenario: Mixed-case handshake is inspected

- **WHEN** a `GET` request has `Connection: Upgrade` and `Upgrade: WebSocket`
- **AND** the sidecar returns 403
- **THEN** the plugin SHALL copy the sidecar response to the client
- **AND** the plugin SHALL NOT call the next handler

#### Scenario: Allowed handshake reaches next

- **WHEN** a `GET` request has `Connection` containing the token `upgrade` and `Upgrade` matching `websocket` case-insensitively
- **AND** the sidecar returns 200
- **THEN** the plugin SHALL call the next handler so the backend can 101 and Traefik can tunnel frames

#### Scenario: Empty header map is inspected without panic

- **WHEN** a GET request has an empty header map
- **AND** the sidecar allows the request
- **THEN** the plugin SHALL complete the request without panicking and SHALL call the next handler

#### Scenario: Nil header map is inspected without panic

- **WHEN** a GET request has a nil header map
- **AND** the sidecar allows the request
- **THEN** the plugin SHALL complete the request without panicking and SHALL call the next handler

### Requirement: Drain-stack suite proves handshake inspect

The drain-stack integration suite SHALL include Pester coverage that a forged WebSocket Upgrade is still inspected by CRS and that a handshake-shaped GET with a CRS SQL-injection query is blocked.

#### Scenario: Forged Upgrade with a CRS probe is blocked

- **WHEN** the suite GET `/protected` with a CRS SQL-injection query, `Upgrade: websocket`, and `Connection` without the token `upgrade`
- **THEN** the client status SHALL be 4xx or 5xx at or above 400
- **AND** the request SHALL NOT complete as an HTTP 200 from whoami

#### Scenario: Handshake-shaped GET on /ws-echo with a CRS probe is blocked

- **WHEN** the suite GET `/ws-echo` with a CRS SQL-injection query, `Connection` containing the token `upgrade`, and `Upgrade: websocket`
- **THEN** the client status SHALL be HTTP 403
- **AND** the handshake SHALL NOT complete
