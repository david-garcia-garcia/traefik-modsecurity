# core_plugin_middleware_instance-reuse

## Purpose

Reuse one plugin core per Traefik middleware name and prepared config so routes share the WAF HTTP client, logger, and health tracker.

## Requirements

### Requirement: One core per middleware name and config

The plugin SHALL create at most one plugin core for a given Traefik middleware name and prepared configuration while any `New` context for that key is live or reclaim grace has not elapsed. A change to name or to prepared config SHALL create a new core. Each `New` SHALL return a handler that uses that core and the `next` handler passed to that `New`.

#### Scenario: Same name and config reuse the core

- **WHEN** Traefik calls `New` twice with the same middleware name and the same prepared `Config`
- **THEN** both handlers SHALL use the same plugin core (same HTTP client and, when backoff is enabled, the same health tracker)

#### Scenario: Different name creates a new core

- **WHEN** Traefik calls `New` twice with different middleware names and the same prepared `Config`
- **THEN** the plugin SHALL create two cores

#### Scenario: Different config creates a new core

- **WHEN** Traefik calls `New` twice with the same middleware name and prepared configs that differ
- **THEN** the plugin SHALL create two cores

### Requirement: Shared core owns client, logger, and health tracker

The shared core SHALL own the HTTP client used to call `ModSecurityUrl` (including its transport and dialer), the plugin logger, and the WAF health tracker when `unhealthyWafBackOffPeriodSecs` is greater than zero. Per-route wrappers SHALL NOT create their own client, logger, or tracker.

#### Scenario: Health trip is shared

- **WHEN** two handlers share a core with backoff enabled
- **AND** the core marks the WAF unhealthy
- **THEN** both handlers SHALL observe unhealthy on the next request

### Requirement: Core is disposed after last holder

When every `New` context bound to a key is done and reclaim grace has elapsed, the plugin SHALL dispose that core and SHALL close idle HTTP connections owned by it. A later `New` with the same key SHALL create a new core.

#### Scenario: New after dispose is a new incarnation

- **WHEN** all holders for a key have ended and grace has elapsed
- **AND** Traefik calls `New` again with that key
- **THEN** the plugin SHALL create a new core (not the disposed instance)

### Requirement: Yaegi entry stays at module root

The module root package SHALL export `CreateConfig` and `New` with the Traefik plugin signatures. Isolated core types SHALL live under `pkg/` and SHALL NOT import the root package.

#### Scenario: Constructor still constructs a handler

- **WHEN** a caller invokes root `New` with a valid `ModSecurityUrl` and a next handler
- **THEN** the function SHALL return an `http.Handler` without returning an error
