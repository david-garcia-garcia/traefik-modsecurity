## Purpose

Defines how one Plugin core admits sidecar calls after repeated WAF communication failures: enablement knobs, trip, skip while open, one probe after cooldown, and failMode while the WAF is skipped.

## ADDED Requirements

### Requirement: Omitted threshold uses five failures

When `unhealthyWafBackOffPeriodSecs` is greater than zero and the operator omits `unhealthyWafFailureThreshold` (JSON/YAML zero), the plugin SHALL treat the threshold as 5. An explicit non-zero threshold SHALL be kept. When `unhealthyWafFailureWindowSecs` is omitted or zero, Prepare SHALL still store 10 so the reclaim hash stays stable; that window SHALL NOT reset the failure budget.

#### Scenario: README enablement uses threshold 5

- **WHEN** the operator sets only `unhealthyWafBackOffPeriodSecs` to 30 and leaves threshold and window unset
- **THEN** the plugin SHALL require 5 sidecar communication failures before skipping later sidecar calls

#### Scenario: Explicit threshold 1 is kept

- **WHEN** the operator sets `unhealthyWafFailureThreshold` to 1 and enables backoff
- **THEN** the first sidecar communication failure SHALL cause later requests to skip the sidecar until cooldown ends

### Requirement: Optional ratio and max cooldown knobs

When `unhealthyWafFailureRatio` is omitted or zero, the plugin SHALL use the packaged gate default 0.30. An explicit ratio in (0, 1) SHALL be kept. When `unhealthyWafMaxBackOffPeriodSecs` is omitted or zero, the plugin SHALL use the same duration as `unhealthyWafBackOffPeriodSecs` (fixed cooldown). An explicit max at least as large as the base backoff SHALL be kept.

#### Scenario: Omitted ratio and max stay packaged or equal to base

- **WHEN** backoff is enabled and the operator omits `unhealthyWafFailureRatio` and `unhealthyWafMaxBackOffPeriodSecs`
- **THEN** plugin construction SHALL succeed
- **AND** cooldown SHALL last `unhealthyWafBackOffPeriodSecs` seconds on the first trip

### Requirement: Unhealthy WAF follows failMode for the cooldown

When the WAF is skipped after a trip, the plugin SHALL NOT call the sidecar until the cooldown elapses. When `failMode` is `open` or omitted, the plugin SHALL forward the request to `next`. When `failMode` is `close`, the plugin SHALL return empty HTTP 502 and SHALL NOT call `next`. Denied skip requests SHALL NOT count as a new failure.

#### Scenario: Request during cooldown skips the sidecar (fail-open)

- **WHEN** `failMode` is `open` or omitted
- **AND** the WAF is being skipped after a trip
- **AND** a request arrives
- **THEN** the plugin SHALL call `next` and SHALL NOT send that request to `ModSecurityUrl`

#### Scenario: Request during cooldown fail-closes

- **WHEN** `failMode` is `close`
- **AND** the WAF is being skipped after a trip
- **AND** a request arrives
- **THEN** the client SHALL receive HTTP 502
- **AND** the plugin SHALL NOT send that request to `ModSecurityUrl`
- **AND** the next handler SHALL NOT run

### Requirement: One sidecar probe after cooldown

When the cooldown elapses, the plugin SHALL send at most one request to the sidecar before deciding whether to stay skipped. If that probe is a sidecar communication failure, the plugin SHALL skip again. If that probe receives a sidecar status below 500, the plugin SHALL resume normal sidecar calls.

#### Scenario: First request after cooldown reaches the sidecar

- **WHEN** backoff is enabled
- **AND** the WAF has been skipped for the configured backoff period
- **AND** a later request arrives
- **THEN** the plugin SHALL send that request to `ModSecurityUrl`

#### Scenario: Concurrent requests during the probe stay skipped

- **WHEN** a probe request is already in flight after cooldown
- **AND** another request arrives before that probe finishes
- **THEN** the plugin SHALL NOT send that other request to `ModSecurityUrl`

### Requirement: Backoff off leaves the gate unused

When `unhealthyWafBackOffPeriodSecs` is 0 or omitted, the plugin SHALL NOT skip the sidecar because of prior failures. A sidecar communication failure SHALL still follow `failMode`. Later requests SHALL still call the sidecar.

#### Scenario: Default config fail-opens without skipping later calls

- **WHEN** the operator leaves `unhealthyWafBackOffPeriodSecs` unset
- **AND** `failMode` is `open` or omitted
- **AND** the sidecar client call fails
- **THEN** the plugin SHALL call the next handler
- **AND** the plugin SHALL NOT skip the sidecar on later requests due to unhealthy state

### Requirement: Admitted success below 500 restores the budget

When backoff is enabled and the plugin has already admitted a sidecar call, a sidecar status below 500 SHALL count as success for the admission budget. A sidecar 5xx or a transport error that is not inbound cancel SHALL count as a failure.

#### Scenario: Sidecar block does not trip threshold 1

- **WHEN** backoff is enabled with failure threshold 1
- **AND** the sidecar returns HTTP 403
- **THEN** the plugin SHALL still call the sidecar on the next request

### Requirement: Drain-stack suite proves probe after cooldown

The drain-stack integration suite SHALL include Pester coverage that after `/threshold-test` trips fail-open, the CRS container is healthy again, and `unhealthyWafBackOffPeriodSecs` (10 seconds on that route) has elapsed, the plugin consults the sidecar again.

#### Scenario: CRS probe is blocked after backoff elapses

- **WHEN** the suite has tripped `/threshold-test` fail-open
- **AND** it has started the CRS container and waited until it is healthy
- **AND** it has waited longer than that route's backoff period
- **AND** it then GET `/threshold-test` with a CRS SQL-injection query
- **THEN** the client status SHALL be 4xx or 5xx at or above 400
- **AND** the status SHALL NOT be HTTP 200 pass-through
