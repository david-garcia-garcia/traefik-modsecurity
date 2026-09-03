## ADDED Requirements

### Requirement: Client-supplied status header is discarded

When `modSecurityStatusRequestHeader` is set, the plugin SHALL delete that header name from the incoming request before any skip, inspect, or next-handler path. The plugin SHALL then write the token for the outcome it actually took (`ok`, `blocked`, `error`, `unhealthy`, or `bypassrule`). The plugin SHALL NOT forward a client-supplied value on that name.

#### Scenario: Forged ok is overwritten on allow

- **WHEN** the header name is set
- **AND** the client sent that header with value `ok`
- **AND** the sidecar returns 200
- **THEN** the request header value SHALL be `ok` written by the plugin after inspection

#### Scenario: Forged ok does not survive a bypass rule

- **WHEN** the header name is set
- **AND** the client sent that header with value `ok`
- **AND** a bypass rule matches the request
- **THEN** the request header value SHALL be `bypassrule`

## MODIFIED Requirements

### Requirement: Allow path writes ok

When `modSecurityStatusRequestHeader` is set and the sidecar response status is below 300 (allow), the plugin SHALL set that header to `ok`. The plugin SHALL NOT write `ok` on a bypass-rule skip, an inbound cancel, a fail-open after a WAF failure, or an already-unhealthy pass-through.

#### Scenario: Allowed request is ok

- **WHEN** the header name is set and the sidecar returns 200
- **THEN** the request header value SHALL be `ok`

#### Scenario: Allowed handshake is ok

- **WHEN** the header name is set
- **AND** a `GET` has `Connection` containing the token `upgrade` and `Upgrade` matching `websocket` case-insensitively
- **AND** the sidecar returns 200
- **THEN** the request header value SHALL be `ok`
