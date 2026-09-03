## ADDED Requirements

### Requirement: Bypass rule writes bypassrule

When `modSecurityStatusRequestHeader` is set and the request matches a `bypassRules` entry, the plugin SHALL set that header to `bypassrule` and SHALL call `next`. The plugin SHALL NOT write `ok` on that skip.

#### Scenario: Matching rule is bypassrule

- **WHEN** the header name is set and a bypass rule matches the request
- **THEN** the request header value SHALL be `bypassrule`
- **AND** the plugin SHALL call the next handler

#### Scenario: Empty header name adds no bypass token

- **WHEN** `modSecurityStatusRequestHeader` is empty and a bypass rule matches the request
- **THEN** the request SHALL have no plugin-owned status header
- **AND** the plugin SHALL still skip the sidecar

## MODIFIED Requirements

### Requirement: Allow path writes ok

When `modSecurityStatusRequestHeader` is set and the sidecar response status is below 300 (allow), the plugin SHALL set that header to `ok`. The plugin SHALL NOT write `ok` on a WebSocket skip, a bypass-rule skip, an inbound cancel, a fail-open after a WAF failure, or an already-unhealthy pass-through.

#### Scenario: Allowed request is ok

- **WHEN** the header name is set and the sidecar returns 200
- **THEN** the request header value SHALL be `ok`
