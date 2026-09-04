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

When `unhealthyWafBackOffPeriodSecs` is 0 or omitted, the plugin SHALL NOT mark the WAF unhealthy. A sidecar client call failure SHALL still fail-open to the next handler (never HTTP 502 for a WAF failure). Later requests SHALL still call the sidecar because the tracker is unused.

#### Scenario: Default config fail-opens without marking unhealthy

- **WHEN** the operator leaves `unhealthyWafBackOffPeriodSecs` unset
- **AND** the sidecar client call fails
- **THEN** the plugin SHALL call the next handler
- **AND** the plugin SHALL NOT skip the sidecar on later requests due to unhealthy state
