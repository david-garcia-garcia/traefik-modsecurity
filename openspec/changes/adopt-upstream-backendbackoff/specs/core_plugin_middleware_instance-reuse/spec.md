## MODIFIED Requirements

### Requirement: One core per middleware name and config

The plugin SHALL create at most one plugin core for a given Traefik middleware name and prepared configuration while any `New` context for that key is live or reclaim grace has not elapsed. A change to name or to prepared config SHALL create a new core. Each `New` SHALL return a handler that uses that core and the `next` handler passed to that `New`.

#### Scenario: Same name and config reuse the core

- **WHEN** Traefik calls `New` twice with the same middleware name and the same prepared `Config`
- **THEN** both handlers SHALL use the same plugin core (same HTTP client and, when backoff is enabled, the same WAF admission gate)

#### Scenario: Different name creates a new core

- **WHEN** Traefik calls `New` twice with different middleware names and the same prepared `Config`
- **THEN** the plugin SHALL create two cores

#### Scenario: Different config creates a new core

- **WHEN** Traefik calls `New` twice with the same middleware name and prepared configs that differ
- **THEN** the plugin SHALL create two cores

### Requirement: Shared core owns client, logger, and health tracker

The shared core SHALL own the HTTP client used to call `ModSecurityUrl` (including its transport and dialer), the plugin logger, and the WAF admission gate when `unhealthyWafBackOffPeriodSecs` is greater than zero. Per-route wrappers SHALL NOT create their own client, logger, or gate.

#### Scenario: Health trip is shared

- **WHEN** two handlers share a core with backoff enabled
- **AND** the core is skipping the sidecar after a trip
- **THEN** both handlers SHALL skip the sidecar on the next request
