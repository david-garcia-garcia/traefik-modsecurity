## MODIFIED Requirements

### Requirement: Sidecar 5xx uses the same WAF-failure path as a transport error

A sidecar 5xx SHALL count as a health-tracker failure when `unhealthyWafBackOffPeriodSecs` is greater than zero. Whether or not the tracker is configured, a WAF communication failure (sidecar 5xx or transport error, excluding inbound cancel) SHALL follow `failMode`: when `failMode` is `open` or omitted, the plugin SHALL call the next handler (fail-open) and SHALL NOT return HTTP 502; when `failMode` is `close`, the plugin SHALL return empty HTTP 502 and SHALL NOT call `next`. When `modSecurityStatusRequestHeader` is configured, the plugin SHALL set that header to `error` before fail-open or fail-close.

#### Scenario: 503 trips fail-open at threshold 1

- **WHEN** `failMode` is `open` or omitted
- **AND** `unhealthyWafBackOffPeriodSecs` is greater than zero
- **AND** `unhealthyWafFailureThreshold` is 1
- **AND** the sidecar responds with HTTP 503
- **THEN** the plugin SHALL call the next handler
- **AND** the client SHALL receive the next handler's response

#### Scenario: 500 trips fail-open at threshold 1

- **WHEN** `failMode` is `open` or omitted
- **AND** `unhealthyWafBackOffPeriodSecs` is greater than zero
- **AND** `unhealthyWafFailureThreshold` is 1
- **AND** the sidecar responds with HTTP 500
- **THEN** the plugin SHALL call the next handler

#### Scenario: 503 without backoff fail-opens to next

- **WHEN** `failMode` is `open` or omitted
- **AND** fail-open backoff is not configured
- **AND** the sidecar responds with HTTP 503
- **THEN** the plugin SHALL call the next handler
- **AND** the client SHALL NOT receive HTTP 502

#### Scenario: 503 fail-closes with 502 when failMode is close

- **WHEN** `failMode` is `close`
- **AND** the sidecar responds with HTTP 503
- **THEN** the client SHALL receive HTTP 502
- **AND** the next handler SHALL NOT run
