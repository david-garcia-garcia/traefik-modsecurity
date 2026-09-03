## ADDED Requirements

### Requirement: pathRegexp is unanchored substring search

When a `bypassRules` entry has a non-empty `pathRegexp`, the plugin SHALL match it with unanchored substring search against `req.URL.Path`. The plugin SHALL NOT insert `^`, `$`, `\A`, or `\z` around the operator pattern. Prefix or exact-path matching SHALL require those anchors in the operator-supplied `pathRegexp`.

#### Scenario: Unanchored slash-health skips healthz

- **WHEN** `bypassRules` contains `{ pathRegexp: /health }`
- **AND** the client sends `GET /healthz`
- **THEN** the plugin SHALL call the next handler without sending the request to ModSecurity

#### Scenario: Unanchored slash-health skips a later segment

- **WHEN** `bypassRules` contains `{ pathRegexp: /health }`
- **AND** the client sends `GET /index.php/health`
- **THEN** the plugin SHALL call the next handler without sending the request to ModSecurity

#### Scenario: Operator exact anchor does not skip a longer path

- **WHEN** `bypassRules` contains `{ pathRegexp: ^/health$ }`
- **AND** the client sends `GET /healthz`
- **THEN** the plugin SHALL send the request to ModSecurity

### Requirement: pathRegexp matches the percent-decoded path

The plugin SHALL match `pathRegexp` against `req.URL.Path`. The plugin SHALL NOT reject a bypass solely because the path contains `.` or `..` segments, or solely because the escaped request target differs from `req.URL.Path`.

#### Scenario: Dot-dot in the path still matches

- **WHEN** `bypassRules` contains `{ pathRegexp: /health }`
- **AND** the client sends `GET /health/../index.php`
- **THEN** the plugin SHALL call the next handler without sending the request to ModSecurity
