# traefik-middleware-utilities backendbackoff gate

Pinned upstream: [david-garcia-garcia/traefik-middleware-utilities](https://github.com/david-garcia-garcia/traefik-middleware-utilities) at **v1.0.3** (`950b08de86b6fd9ea68ac1d205e17a379ec60522`). Import path: `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff`.

## API surface

`backendbackoff.New(Config) (*Gate, error)` validates knobs and returns an in-process per-key admission gate. `Allow(ctx, key)` decides whether a backend attempt may proceed and returns a wait duration when denied. `Report(key, success bool)` records the outcome of an attempt the gate admitted. `Close()` drops stored keys.

Owner: `…/traefik-middleware-utilities@v1.0.3:backendbackoff/gate.go`, `…/backendbackoff/allow.go`.

## Semantics vs a simple failure counter

The gate uses CLOSED / OPEN / HALF-OPEN states with exponential cooldown (`BaseCooldown` doubled up to `MaxCooldown`, optional jitter), a credit budget derived from `TripFailures` and `FailureRatio`, and explicit half-open **probe** slots (`probeOutstanding`, `probeUntil`) so only one probe runs during recovery. Idle keys expire after `TTL` (minimum 1s). This is not a fixed tumbling-window failure count.

Defaults when `Config{}`: FailureRatio 0.30, TripFailures 5, BaseCooldown 1s, MaxCooldown 10s, Jitter 0.10, TTL 60s.

Owner: `…/backendbackoff/gate.go` (`resolveConfig`, defaults).

## Tests upstream

Package includes `gate_test.go`, `bench_test.go`, and Yaegi interpretation tests (`gate_yaegi_test.go`).

Owner: `…/backendbackoff/gate_test.go`.

## Implication for traefik-modsecurity

Local `pkg/health.Tracker` exposes `RecordFailure()` / `IsUnhealthy()` with `unhealthyWafBackOffPeriodSecs`, `unhealthyWafFailureThreshold`, and `unhealthyWafFailureWindowSecs` JSON fields. Wiring upstream `backendbackoff` requires mapping those operator knobs (or new ones) onto `backendbackoff.Config` and calling `Allow`/`Report` around sidecar `httpClient.Do` instead of the current counter API.
