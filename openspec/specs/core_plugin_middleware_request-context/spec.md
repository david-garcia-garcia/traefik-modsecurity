# core_plugin_middleware_request-context

## Purpose

Bind the outbound ModSecurity sidecar request to the inbound request context so a canceled inbound request stops the WAF call instead of holding a sidecar connection until the client timeout.

## Requirements

### Requirement: Sidecar request follows inbound context

The plugin SHALL send the ModSecurity sidecar request under the same context as the inbound HTTP request. When that inbound context is canceled before the sidecar responds, the plugin SHALL abort the sidecar call. The plugin SHALL still apply the configured client timeout when the inbound context stays live.

#### Scenario: Inbound cancel aborts the sidecar call

- **WHEN** the inbound request context is canceled while the sidecar has not yet responded
- **THEN** the plugin SHALL abort that sidecar call before the configured client timeout elapses

#### Scenario: Live inbound context still uses client timeout

- **WHEN** the inbound request context stays live and the sidecar does not respond
- **THEN** the plugin SHALL still end the sidecar call when the configured client timeout elapses

### Requirement: Inbound abort does not nil-deref

When the inbound request context is canceled, or an HTTP/2 client resets the stream, while the sidecar call is still in flight, the plugin SHALL NOT panic with a nil dereference. The plugin MAY surface the HTTP server abort used when the handler writes after the stream is reset.

#### Scenario: Inbound cancel does not nil-deref

- **WHEN** the inbound request context is canceled after the sidecar has received the request and before it responds
- **THEN** the plugin SHALL finish that request without a nil-dereference panic

#### Scenario: HTTP/2 client abort does not nil-deref

- **WHEN** an HTTP/2 client cancels an in-flight GET after the sidecar has received the request
- **THEN** the plugin SHALL NOT panic with a nil dereference
- **AND** a server abort after the reset is allowed
