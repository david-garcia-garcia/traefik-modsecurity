# core_plugin_middleware_fail-closed

## Purpose

Lets the operator choose fail-close when the ModSecurity sidecar cannot inspect a request. Default stays fail-open so existing deploys do not flip.

## Requirements

### Requirement: Public failMode on middleware config

The plugin SHALL accept an optional `failMode` string on middleware configuration (Docker label / YAML). Allowed values after Prepare SHALL be `open` and `close` (case-insensitive; stored lowercase). Omitted or empty SHALL become `open` (fail-open: call `next` on a WAF communication failure). `failMode: close` SHALL fail-close. Any other value SHALL fail Prepare. Prepared `failMode` SHALL be part of the configuration used as the reclaim key, so a change to `failMode` SHALL create a new plugin core.

#### Scenario: Default is fail-open

- **WHEN** an operator omits `failMode`
- **THEN** a WAF communication failure SHALL call `next`
- **AND** the plugin SHALL NOT return HTTP 502 for that failure

#### Scenario: Explicit open is fail-open

- **WHEN** an operator sets `failMode` to `open`
- **THEN** a WAF communication failure SHALL call `next`

#### Scenario: Unknown failMode fails Prepare

- **WHEN** an operator sets `failMode` to a value other than `open` or `close`
- **THEN** Prepare SHALL fail

#### Scenario: Changing failMode rebuilds the core

- **WHEN** Traefik calls `New` twice with the same middleware name and prepared configs that differ only in `failMode`
- **THEN** the plugin SHALL create two cores

### Requirement: Fail-close refuses the client without calling next

When `failMode` is `close` and the plugin takes a WAF communication failure (sidecar transport error excluding inbound cancel, or sidecar HTTP 5xx), the plugin SHALL write empty HTTP 502, SHALL set `modSecurityStatusRequestHeader` to `error` when that name is configured, SHALL still record a health-tracker failure when the tracker exists, and SHALL NOT call `next`. The plugin SHALL NOT copy a sidecar 5xx body to the client.

#### Scenario: Sidecar 503 fail-closes with 502

- **WHEN** `failMode` is `close`
- **AND** the sidecar responds with HTTP 503
- **THEN** the client SHALL receive HTTP 502
- **AND** the next handler SHALL NOT run
- **AND** when `modSecurityStatusRequestHeader` is configured the request header SHALL be `error`

#### Scenario: Transport error fail-closes with 502

- **WHEN** `failMode` is `close`
- **AND** the sidecar client call fails for a reason other than inbound `Canceled`
- **THEN** the client SHALL receive HTTP 502
- **AND** the next handler SHALL NOT run

### Requirement: Fail-close applies to the already-unhealthy skip

When `failMode` is `close` and the health tracker is already unhealthy, the plugin SHALL write empty HTTP 502, SHALL set `modSecurityStatusRequestHeader` to `unhealthy` when that name is configured, SHALL NOT call the sidecar, and SHALL NOT call `next`.

#### Scenario: Unhealthy skip fail-closes

- **WHEN** `failMode` is `close`
- **AND** the WAF is marked unhealthy
- **AND** a request arrives
- **THEN** the client SHALL receive HTTP 502
- **AND** the plugin SHALL NOT send that request to `ModSecurityUrl`
- **AND** the next handler SHALL NOT run
