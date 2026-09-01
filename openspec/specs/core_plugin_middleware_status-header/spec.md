# core_plugin_middleware_status-header

## Purpose

Defines the values written on the optional request status header so Traefik access logs can tell a sidecar block from a local reject from a broken WAF.

## Requirements

### Requirement: Status header is off when the name is empty

When `modSecurityStatusRequestHeader` is empty, the plugin SHALL NOT add a status header to the request.

#### Scenario: Empty name leaves the request unmarked

- **WHEN** `modSecurityStatusRequestHeader` is empty and the sidecar returns 403
- **THEN** the request SHALL have no plugin-owned status header

### Requirement: Sidecar block writes the HTTP status code

When `modSecurityStatusRequestHeader` is set and the sidecar response status is 400 or higher, the plugin SHALL set that header on the request to the decimal HTTP status code of the sidecar response (for example `403` or `406`). The plugin SHALL NOT write the literal `blocked` on this path.

#### Scenario: 403 block is the status string

- **WHEN** the header name is set and the sidecar returns 403
- **THEN** the request header value SHALL be `403`

#### Scenario: 406 block is distinguishable from 403

- **WHEN** the header name is set and the sidecar returns 406
- **THEN** the request header value SHALL be `406`

### Requirement: Local body-too-large writes toolarge

When `modSecurityStatusRequestHeader` is set and the plugin rejects the request because the body exceeds `maxBodySizeBytes`, the plugin SHALL set that header to `toolarge` and SHALL return 413. The plugin SHALL NOT write `blocked` or a sidecar status code on this path.

#### Scenario: Over-limit body is toolarge

- **WHEN** the header name is set and the request body exceeds `maxBodySizeBytes`
- **THEN** the request header value SHALL be `toolarge` and the client status SHALL be 413

### Requirement: Sidecar communication failure writes error

When `modSecurityStatusRequestHeader` is set and the outbound call to `ModSecurityUrl` fails, the plugin SHALL set that header to `error`. The plugin SHALL write `error` on every such failure, including when no health tracker is configured and including failures that do not trip the tracker.

#### Scenario: Failure with no tracker is error

- **WHEN** the header name is set, `unhealthyWafBackOffPeriodSecs` is 0, and the sidecar call fails
- **THEN** the request header value SHALL be `error`

#### Scenario: Failure that does not trip the tracker is still error

- **WHEN** the header name is set, a health tracker is configured, and a sidecar call fails without marking the WAF newly unhealthy
- **THEN** the request header value SHALL be `error`

### Requirement: Existing unhealthy and cannot-forward tokens stay

When `modSecurityStatusRequestHeader` is set and the health tracker is already in backoff, the plugin SHALL set that header to `unhealthy` and SHALL call `next`. When the plugin cannot build the forwarded sidecar request, it SHALL set that header to `cannotforward`.

#### Scenario: Already unhealthy is unhealthy

- **WHEN** the header name is set and the health tracker is already in backoff
- **THEN** the request header value SHALL be `unhealthy` and the plugin SHALL call `next`

#### Scenario: Cannot build the sidecar request is cannotforward

- **WHEN** the header name is set and the plugin cannot build the forwarded sidecar request
- **THEN** the request header value SHALL be `cannotforward`

### Requirement: Allow path does not set the header

When `modSecurityStatusRequestHeader` is set and the sidecar response status is below 400, the plugin SHALL NOT set that header.

#### Scenario: Allowed request has no status header

- **WHEN** the header name is set and the sidecar returns 200
- **THEN** the request SHALL have no value for that header
