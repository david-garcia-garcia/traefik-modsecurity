# core_plugin_middleware_health-tracker

## Purpose

Defines how the plugin trips WAF fail-open after repeated sidecar failures inside a tumbling window, and which defaults apply when an operator enables backoff without setting threshold or window.

## Requirements

### Requirement: Omitted threshold and window use safe defaults

When `unhealthyWafBackOffPeriodSecs` is greater than zero and the operator omits `unhealthyWafFailureThreshold` or `unhealthyWafFailureWindowSecs` (JSON/YAML zero), the plugin SHALL treat the threshold as 5 failures and the window as 10 seconds. An explicit non-zero threshold SHALL be kept. A prepared config SHALL NOT keep a zero window.

#### Scenario: README enablement uses threshold 5 and window 10s

- **WHEN** the operator sets only `unhealthyWafBackOffPeriodSecs` to 30 and leaves threshold and window unset
- **THEN** the plugin SHALL require 5 sidecar client failures inside a 10-second window before marking the WAF unhealthy

#### Scenario: Explicit threshold 1 is kept

- **WHEN** the operator sets `unhealthyWafFailureThreshold` to 1 and enables backoff
- **THEN** the first sidecar client failure SHALL mark the WAF unhealthy

### Requirement: Failure count tumbles with the window

While backoff is enabled, the plugin SHALL count sidecar client failures inside a tumbling window that starts when the health tracker is created. When the window elapses, the next failure SHALL start a new count at 1. Failures SHALL NOT accumulate across windows.

#### Scenario: Isolated failures after the window do not trip

- **WHEN** backoff is enabled with threshold 5 and window 10 seconds
- **AND** fewer than 5 sidecar client failures occur, then more than 10 seconds pass
- **THEN** a later single failure SHALL NOT mark the WAF unhealthy

#### Scenario: Five failures inside the window trip

- **WHEN** backoff is enabled with threshold 5 and window 10 seconds
- **AND** 5 sidecar client failures occur before the window elapses
- **THEN** the plugin SHALL mark the WAF unhealthy

### Requirement: Unhealthy WAF fails open for the backoff period

When the WAF is marked unhealthy, the plugin SHALL forward the request to `next` without calling the sidecar, for `unhealthyWafBackOffPeriodSecs` seconds. When that period elapses, the plugin SHALL resume calling the sidecar.

#### Scenario: Request during backoff skips the sidecar

- **WHEN** the WAF is unhealthy
- **AND** a request arrives
- **THEN** the plugin SHALL call `next` and SHALL NOT send that request to `ModSecurityUrl`

### Requirement: Backoff off leaves the tracker unused

When `unhealthyWafBackOffPeriodSecs` is 0 or omitted, the plugin SHALL NOT mark the WAF unhealthy and SHALL return 502 Bad Gateway when the sidecar client call fails.

#### Scenario: Default config does not fail open

- **WHEN** the operator leaves `unhealthyWafBackOffPeriodSecs` unset
- **AND** the sidecar client call fails
- **THEN** the plugin SHALL respond 502 and SHALL NOT skip the sidecar on later requests

### Requirement: Four-stack suite proves backoff resume

The four-stack integration suite SHALL include Pester coverage that after `/threshold-test` trips fail-open, the CRS container is healthy again, and `unhealthyWafBackOffPeriodSecs` (10 seconds on that route) has elapsed, the plugin consults the sidecar again.

#### Scenario: CRS probe is blocked after backoff elapses

- **WHEN** the suite has tripped `/threshold-test` fail-open
- **AND** it has started the CRS container and waited until it is healthy
- **AND** it has waited longer than that route's backoff period
- **AND** it then GET `/threshold-test` with a CRS SQL-injection query
- **THEN** the client status SHALL be 4xx or 5xx at or above 400
- **AND** the status SHALL NOT be HTTP 200 pass-through
