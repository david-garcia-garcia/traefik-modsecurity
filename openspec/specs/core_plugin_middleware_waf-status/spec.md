# core_plugin_middleware_waf-status

## Purpose

Classifies the ModSecurity sidecar HTTP status so a security block is distinct from a sidecar failure, and so fail-open can trip on 5xx.

## Requirements

### Requirement: Sidecar success is a pass

When the sidecar answers with a success status (below 300), the plugin SHALL call the next handler and SHALL NOT copy the sidecar response to the client.

#### Scenario: 200 is forwarded to the backend

- **WHEN** the sidecar responds with HTTP 200
- **THEN** the plugin SHALL call the next handler
- **AND** the client SHALL receive the next handler's response

### Requirement: Sidecar 3xx is a security block

When the sidecar answers with a 3xx status, the plugin SHALL treat the request as blocked: copy the sidecar response to the client, SHALL NOT call the next handler, and SHALL set `modSecurityStatusRequestHeader` to `blocked` when that header name is configured.

#### Scenario: 302 is blocked

- **WHEN** the sidecar responds with HTTP 302
- **AND** `modSecurityStatusRequestHeader` is configured
- **THEN** the client SHALL receive status 302 and the sidecar body
- **AND** the request header SHALL be `blocked`
- **AND** the next handler SHALL NOT run

### Requirement: Sidecar 4xx is a security block

When the sidecar answers with a 4xx status, the plugin SHALL treat the request as blocked: copy the sidecar response to the client, SHALL NOT call the next handler, and SHALL set `modSecurityStatusRequestHeader` to `blocked` when that header name is configured.

#### Scenario: 403 is blocked

- **WHEN** the sidecar responds with HTTP 403
- **AND** `modSecurityStatusRequestHeader` is configured
- **THEN** the client SHALL receive status 403 and the sidecar body
- **AND** the request header SHALL be `blocked`
- **AND** the next handler SHALL NOT run

#### Scenario: 406 is blocked

- **WHEN** the sidecar responds with HTTP 406
- **AND** `modSecurityStatusRequestHeader` is configured
- **THEN** the client SHALL receive status 406
- **AND** the request header SHALL be `blocked`

#### Scenario: 413 oversize body is blocked

- **WHEN** the sidecar responds with HTTP 413
- **AND** `modSecurityStatusRequestHeader` is configured
- **THEN** the client SHALL receive status 413 and the sidecar body
- **AND** the request header SHALL be `blocked`
- **AND** the next handler SHALL NOT run
- **AND** the health tracker SHALL NOT record a failure

### Requirement: Sidecar 5xx is a WAF failure

When the sidecar answers with a 5xx status, the plugin SHALL treat that as a WAF communication failure, not a security block. The plugin SHALL NOT copy the sidecar 5xx response to the client as a block. When `modSecurityStatusRequestHeader` is configured, the plugin SHALL set it to `error`.

#### Scenario: 503 is not labeled blocked

- **WHEN** the sidecar responds with HTTP 503
- **AND** `modSecurityStatusRequestHeader` is configured
- **THEN** the request header SHALL be `error`
- **AND** the request header SHALL NOT be `blocked`

#### Scenario: 500 is not labeled blocked

- **WHEN** the sidecar responds with HTTP 500
- **AND** `modSecurityStatusRequestHeader` is configured
- **THEN** the request header SHALL be `error`
- **AND** the request header SHALL NOT be `blocked`

### Requirement: Sidecar 5xx uses the same fail-open path as a transport error

A sidecar 5xx SHALL count as a health-tracker failure when `unhealthyWafBackOffPeriodSecs` is greater than zero. If the tracker is unhealthy after that failure, the plugin SHALL call the next handler (fail-open). If the tracker is not configured, or is configured and still healthy, the plugin SHALL return HTTP 502 with an empty body.

#### Scenario: 503 trips fail-open at threshold 1

- **WHEN** `unhealthyWafBackOffPeriodSecs` is greater than zero
- **AND** `unhealthyWafFailureThreshold` is 1
- **AND** the sidecar responds with HTTP 503
- **THEN** the plugin SHALL call the next handler
- **AND** the client SHALL receive the next handler's response

#### Scenario: 500 trips fail-open at threshold 1

- **WHEN** `unhealthyWafBackOffPeriodSecs` is greater than zero
- **AND** `unhealthyWafFailureThreshold` is 1
- **AND** the sidecar responds with HTTP 500
- **THEN** the plugin SHALL call the next handler
- **AND** the client SHALL receive the next handler's response

#### Scenario: 503 without backoff returns 502

- **WHEN** `unhealthyWafBackOffPeriodSecs` is 0
- **AND** the sidecar responds with HTTP 503
- **THEN** the client SHALL receive HTTP 502 with an empty body
- **AND** the next handler SHALL NOT run

### Requirement: Large non-file body never returns client 500

A large non-file request body SHALL NOT become a forwarded client HTTP 500. Plugin oversize SHALL be HTTP 413 with status-header `blocked` and SHALL NOT call the sidecar. A sidecar HTTP 413 SHALL be copied as a security block (`blocked`). A sidecar HTTP 5xx SHALL be a WAF failure: HTTP 502 and status-header `error` when fail-open backoff is not configured. The plugin SHALL NOT treat file vs non-file as a distinct mapping.

#### Scenario: Plugin cap exceeded is 413 not 500

- **WHEN** the inbound body is larger than `maxBodySizeBytes`
- **AND** the body is `application/x-www-form-urlencoded` (not a multipart file)
- **THEN** the client SHALL receive HTTP 413
- **AND** the status request header SHALL be `blocked`
- **AND** the next handler SHALL NOT run
- **AND** the sidecar SHALL NOT be called
- **AND** the client SHALL NOT receive HTTP 500

#### Scenario: Sidecar 413 is copied as a block

- **WHEN** the inbound body is under `maxBodySizeBytes`
- **AND** the sidecar responds with HTTP 413
- **THEN** the client SHALL receive HTTP 413
- **AND** the status request header SHALL be `blocked`
- **AND** the next handler SHALL NOT run
- **AND** the client SHALL NOT receive HTTP 500

#### Scenario: Sidecar 500 is 502 not a copied 500

- **WHEN** the inbound body is under `maxBodySizeBytes`
- **AND** fail-open backoff is not configured
- **AND** the sidecar responds with HTTP 500
- **THEN** the client SHALL receive HTTP 502
- **AND** the status request header SHALL be `error`
- **AND** the next handler SHALL NOT run
- **AND** the client SHALL NOT receive HTTP 500
