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
