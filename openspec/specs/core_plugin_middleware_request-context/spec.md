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
