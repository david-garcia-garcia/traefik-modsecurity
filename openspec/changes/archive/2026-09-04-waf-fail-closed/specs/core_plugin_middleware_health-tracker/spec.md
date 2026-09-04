## MODIFIED Requirements

### Requirement: Unhealthy WAF follows failMode for the backoff period

When the WAF is marked unhealthy, the plugin SHALL NOT call the sidecar for `unhealthyWafBackOffPeriodSecs` seconds. When `failMode` is `open` or omitted, the plugin SHALL forward the request to `next`. When `failMode` is `close`, the plugin SHALL return empty HTTP 502 and SHALL NOT call `next`. When that period elapses, the plugin SHALL resume calling the sidecar.

#### Scenario: Request during backoff skips the sidecar (fail-open)

- **WHEN** `failMode` is `open` or omitted
- **AND** the WAF is unhealthy
- **AND** a request arrives
- **THEN** the plugin SHALL call `next` and SHALL NOT send that request to `ModSecurityUrl`

#### Scenario: Request during backoff fail-closes

- **WHEN** `failMode` is `close`
- **AND** the WAF is unhealthy
- **AND** a request arrives
- **THEN** the client SHALL receive HTTP 502
- **AND** the plugin SHALL NOT send that request to `ModSecurityUrl`
- **AND** the next handler SHALL NOT run

### Requirement: Backoff off leaves the tracker unused

When `unhealthyWafBackOffPeriodSecs` is 0 or omitted, the plugin SHALL NOT mark the WAF unhealthy. A sidecar client call failure SHALL still follow `failMode` (fail-open to `next` when `open` or omitted; empty HTTP 502 when `close`). Later requests SHALL still call the sidecar because the tracker is unused.

#### Scenario: Default config fail-opens without marking unhealthy

- **WHEN** the operator leaves `unhealthyWafBackOffPeriodSecs` unset
- **AND** `failMode` is `open` or omitted
- **AND** the sidecar client call fails
- **THEN** the plugin SHALL call the next handler
- **AND** the plugin SHALL NOT skip the sidecar on later requests due to unhealthy state
