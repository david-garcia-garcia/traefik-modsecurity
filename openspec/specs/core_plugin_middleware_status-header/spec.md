# core_plugin_middleware_status-header

## Purpose

Defines the coarse WAF-status tokens written on the optional request status header so Traefik access logs can tell a block from a broken WAF from fail-open. The header is not an HTTP status code.

## Requirements

### Requirement: Status header is off when the name is empty

When `modSecurityStatusRequestHeader` is empty, the plugin SHALL NOT add a status header to the request.

#### Scenario: Empty name leaves the request unmarked

- **WHEN** `modSecurityStatusRequestHeader` is empty and the sidecar returns 403
- **THEN** the request SHALL have no plugin-owned status header

### Requirement: Security block writes blocked

When `modSecurityStatusRequestHeader` is set and the sidecar response is a security block (`3xx` or `4xx`), the plugin SHALL set that header to `blocked`. The plugin SHALL NOT write an HTTP status code on this header.

#### Scenario: 403 is blocked

- **WHEN** the header name is set and the sidecar returns 403
- **THEN** the request header value SHALL be `blocked`

#### Scenario: 406 is blocked

- **WHEN** the header name is set and the sidecar returns 406
- **THEN** the request header value SHALL be `blocked`

#### Scenario: 302 is blocked

- **WHEN** the header name is set and the sidecar returns 302
- **THEN** the request header value SHALL be `blocked`

### Requirement: Local body-too-large writes blocked

When `modSecurityStatusRequestHeader` is set and the plugin rejects the request because the body exceeds `maxBodySizeBytes`, the plugin SHALL set that header to `blocked` and SHALL return 413.

#### Scenario: Over-limit body is blocked

- **WHEN** the header name is set and the request body exceeds `maxBodySizeBytes`
- **THEN** the request header value SHALL be `blocked` and the client status SHALL be 413

### Requirement: WAF failure writes error

When `modSecurityStatusRequestHeader` is set and the plugin cannot complete a sidecar inspection, the plugin SHALL set that header to `error`. That includes: the outbound call to `ModSecurityUrl` fails, the sidecar returns `5xx`, and the forwarded sidecar request cannot be built. The plugin SHALL write `error` on every such failure, including when no health tracker is configured and including failures that do not trip the tracker. The plugin SHALL NOT write `cannotforward`.

#### Scenario: Failure with no tracker is error

- **WHEN** the header name is set, `unhealthyWafBackOffPeriodSecs` is 0, and the sidecar call fails
- **THEN** the request header value SHALL be `error`

#### Scenario: Failure that does not trip the tracker is still error

- **WHEN** the header name is set, a health tracker is configured, and a sidecar call fails without marking the WAF newly unhealthy
- **THEN** the request header value SHALL be `error`

#### Scenario: Cannot build the sidecar request is error

- **WHEN** the header name is set and the plugin cannot build the forwarded sidecar request
- **THEN** the request header value SHALL be `error`

### Requirement: Already unhealthy writes unhealthy

When `modSecurityStatusRequestHeader` is set and the health tracker is already in backoff, the plugin SHALL set that header to `unhealthy` and SHALL call `next`.

#### Scenario: Already unhealthy is unhealthy

- **WHEN** the header name is set and the health tracker is already in backoff
- **THEN** the request header value SHALL be `unhealthy` and the plugin SHALL call `next`

### Requirement: Allow path writes ok

When `modSecurityStatusRequestHeader` is set and the sidecar response status is below 300 (allow), the plugin SHALL set that header to `ok`. The plugin SHALL NOT write `ok` on a WebSocket skip, an inbound cancel, a fail-open after a WAF failure, or an already-unhealthy pass-through.

#### Scenario: Allowed request is ok

- **WHEN** the header name is set and the sidecar returns 200
- **THEN** the request header value SHALL be `ok`
