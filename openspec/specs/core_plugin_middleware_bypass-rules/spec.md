# core_plugin_middleware_bypass-rules

## Purpose

Lets an operator skip ModSecurity sidecar inspection for selected HTTP method and path-regexp patterns without omitting the middleware on a separate Traefik router.

## Requirements

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

### Requirement: Method and pathRegexp both match to skip

When a `bypassRules` entry has a non-empty `method` and a non-empty `pathRegexp`, the plugin SHALL skip the sidecar if and only if the request method matches that `method` (ASCII case-insensitive) and `req.URL.Path` contains a match of that `pathRegexp`. The plugin SHALL call the next handler. The plugin SHALL NOT read the inbound body for the sidecar on that request.

#### Scenario: GET path match skips the sidecar

- **WHEN** `bypassRules` contains `{ method: GET, pathRegexp: /search/v1/statement/executing/ }`
- **AND** the client sends `GET /search/v1/statement/executing/abc123`
- **THEN** the plugin SHALL call the next handler without sending the request to ModSecurity

#### Scenario: Method miss is inspected

- **WHEN** `bypassRules` contains `{ method: GET, pathRegexp: /search/v1/statement/executing/ }`
- **AND** the client sends `POST /search/v1/statement/executing/abc123`
- **THEN** the plugin SHALL send the request to ModSecurity

#### Scenario: Path miss is inspected

- **WHEN** `bypassRules` contains `{ method: GET, pathRegexp: /search/v1/statement/executing/ }`
- **AND** the client sends `GET /search/v1/statement/queued/abc123`
- **THEN** the plugin SHALL send the request to ModSecurity

### Requirement: Method-only rule skips every path for that method

When a `bypassRules` entry has a non-empty `method` and an empty `pathRegexp`, the plugin SHALL skip the sidecar for every request whose method matches that `method` (ASCII case-insensitive), regardless of path.

#### Scenario: Method-only GET skips any path

- **WHEN** `bypassRules` contains `{ method: GET }`
- **AND** the client sends `GET /any/path`
- **THEN** the plugin SHALL call the next handler without sending the request to ModSecurity

### Requirement: Path-only rule skips every method for that path

When a `bypassRules` entry has an empty `method` and a non-empty `pathRegexp`, the plugin SHALL skip the sidecar for every request whose `req.URL.Path` contains a match of that `pathRegexp`, regardless of method.

#### Scenario: Path-only health skips POST

- **WHEN** `bypassRules` contains `{ pathRegexp: /health }`
- **AND** the client sends `POST /health`
- **THEN** the plugin SHALL call the next handler without sending the request to ModSecurity

### Requirement: Invalid pathRegexp fails construction

When any `bypassRules` entry has a `pathRegexp` that is not a valid regular expression, plugin construction SHALL fail. The plugin SHALL NOT start serving requests with that config.

#### Scenario: Unclosed group fails New

- **WHEN** an operator sets `pathRegexp` to `a(b`
- **THEN** plugin construction SHALL fail

### Requirement: Bypass skip runs before body policy and sidecar

When a request matches a bypass rule, the plugin SHALL call the next handler without applying `denyVerbsWithBody` rejection and without buffering the body for ModSecurity.

#### Scenario: Bypassed GET with a body reaches next

- **WHEN** a method-only GET bypass rule is configured
- **AND** the client sends `GET /any` with a non-empty body
- **THEN** the plugin SHALL call the next handler
- **AND** the plugin SHALL NOT return HTTP 400 for a denied-verb body
