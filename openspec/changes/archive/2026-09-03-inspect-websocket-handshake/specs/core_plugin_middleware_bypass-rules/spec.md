## MODIFIED Requirements

### Requirement: Omitted bypassRules inspects every request

When `bypassRules` is omitted or empty, the plugin SHALL send the request to ModSecurity (subject to already-unhealthy backoff). The plugin SHALL NOT skip the sidecar solely because `bypassRules` is absent. The plugin SHALL NOT skip the sidecar because the request looks like a WebSocket handshake.

#### Scenario: No rules still inspects

- **WHEN** `bypassRules` is omitted
- **AND** the health tracker is not in backoff
- **THEN** the plugin SHALL send the request to ModSecurity

#### Scenario: Handshake GET without a rule is inspected

- **WHEN** `bypassRules` is omitted
- **AND** a `GET` has `Connection` containing the token `upgrade` and `Upgrade` matching `websocket` case-insensitively
- **AND** the health tracker is not in backoff
- **THEN** the plugin SHALL send the request to ModSecurity
