# core_plugin_middleware_log-level

## Purpose

Lets operators set a middleware `logLevel` so this plugin gates its own stdout. Traefik process log level does not reach Yaegi plugins.

## Requirements

### Requirement: Public logLevel on middleware config

The plugin SHALL accept an optional `logLevel` field on middleware configuration (Docker label / YAML). Omitted or empty `logLevel` SHALL become `info` during prepare. Accepted values SHALL be `debug`, `info`, `warn`, and `error` (comparison SHALL be case-insensitive; the prepared value SHALL be stored lowercase). Any other value SHALL cause plugin construction to fail. Prepared `logLevel` SHALL be part of the configuration used as the reclaim key, so a change to `logLevel` SHALL create a new plugin core.

#### Scenario: Default is info

- **WHEN** an operator omits `logLevel`
- **THEN** the prepared configuration SHALL use `info`

#### Scenario: Invalid logLevel is rejected

- **WHEN** an operator sets `logLevel` to a value other than `debug`, `info`, `warn`, or `error`
- **THEN** plugin construction SHALL fail

#### Scenario: Changing logLevel rebuilds the core

- **WHEN** Traefik calls `New` twice with the same middleware name and prepared configs that differ only in `logLevel`
- **THEN** the plugin SHALL create two cores

### Requirement: One plugin-owned logger

The shared plugin core SHALL own one logger used for request-path lines, health-tracker lines, and reclaim lines. That logger SHALL write to the Traefik process stdout and SHALL emit a line only when the line’s level is at least the prepared `logLevel`. The plugin SHALL NOT discard reclaim output by sending it to a sink that never prints.

#### Scenario: Default info hides reclaim diagnosis

- **WHEN** prepared `logLevel` is `info`
- **THEN** reclaim diagnosis lines (`reclaim_put`, `reclaim_bind`, `reclaim_reclaim`, `reclaim_dispose`) SHALL NOT appear on stdout

#### Scenario: Debug shows reclaim diagnosis

- **WHEN** prepared `logLevel` is `debug`
- **THEN** reclaim diagnosis lines SHALL be eligible to appear on stdout

### Requirement: Level map for request, health, and reclaim

The plugin SHALL emit request-path and health failures at `error` (cannot read the request body, cannot reach ModSecurity, health trip that marks the WAF unhealthy). The plugin SHALL emit health backoff expiry at `info`. The plugin SHALL emit reclaim bind, put, reclaim, and dispose lines at `debug`. The plugin SHALL NOT emit a log line on every request that merely observes an already-unhealthy WAF.

#### Scenario: Health trip is error

- **WHEN** the health tracker marks the WAF unhealthy
- **THEN** the plugin SHALL emit the trip line at `error`

#### Scenario: Backoff expired is info

- **WHEN** the unhealthy backoff period ends
- **THEN** the plugin SHALL emit the expiry line at `info`

#### Scenario: WAF forward failure is error

- **WHEN** the plugin cannot send the request to ModSecurity and does not fail open
- **THEN** the plugin SHALL emit the failure line at `error`
