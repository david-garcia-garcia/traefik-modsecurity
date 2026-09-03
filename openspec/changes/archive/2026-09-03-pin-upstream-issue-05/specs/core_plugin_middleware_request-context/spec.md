## ADDED Requirements

### Requirement: Inbound abort does not nil-deref

When the inbound request context is canceled, or an HTTP/2 client resets the stream, while the sidecar call is still in flight, the plugin SHALL NOT panic with a nil dereference. The plugin MAY surface the HTTP server abort used when a handler writes after the stream is reset.

#### Scenario: Inbound cancel does not nil-deref

- **WHEN** the inbound request context is canceled after the sidecar has received the request and before it responds
- **THEN** the plugin SHALL finish that request without a nil-dereference panic

#### Scenario: HTTP/2 client abort does not nil-deref

- **WHEN** an HTTP/2 client cancels an in-flight GET after the sidecar has received the request
- **THEN** the plugin SHALL NOT panic with a nil dereference
- **AND** a server abort after the reset is allowed
