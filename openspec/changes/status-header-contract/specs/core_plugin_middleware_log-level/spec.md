## MODIFIED Requirements

### Requirement: Level map for request, health, and reclaim

The plugin SHALL emit client-fault request rejections at `warn`: a body on an ignore-verb when deny is enabled, and a request body that exceeds `maxBodySizeBytes`. The plugin SHALL emit infrastructure request-path failures at `error` (cannot read the request body for a reason other than the size limit, cannot build the forwarded sidecar request, cannot reach ModSecurity). The plugin SHALL emit the health trip that marks the WAF unhealthy at `warn` (expected backoff). The plugin SHALL emit health backoff expiry at `info`. The plugin SHALL emit reclaim bind, put, reclaim, and dispose lines at `debug`. The plugin SHALL NOT emit a log line on every request that merely observes an already-unhealthy WAF.

#### Scenario: Health trip is warn

- **WHEN** the health tracker marks the WAF unhealthy
- **THEN** the plugin SHALL emit the trip line at `warn`

#### Scenario: Backoff expired is info

- **WHEN** the unhealthy backoff period ends
- **THEN** the plugin SHALL emit the expiry line at `info`

#### Scenario: WAF forward failure is error

- **WHEN** the plugin cannot send the request to ModSecurity and does not fail open
- **THEN** the plugin SHALL emit the failure line at `error`

#### Scenario: Body too large is warn

- **WHEN** the plugin rejects a request because the body exceeds `maxBodySizeBytes`
- **THEN** the plugin SHALL emit that rejection at `warn` and SHALL NOT emit it at `error`

#### Scenario: Ignore-verb body is warn

- **WHEN** the plugin rejects a request because an ignore-verb carries a body and deny is enabled
- **THEN** the plugin SHALL emit that rejection at `warn` and SHALL NOT emit it at `error`
