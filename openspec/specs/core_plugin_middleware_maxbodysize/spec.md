# core_plugin_middleware_maxbodysize

## Purpose

Pins the inbound request-body cap so omitted or zero `maxBodySizeBytes` does not 413 every non-empty POST the way upstream 1.2.0 did with `MaxBytesReader` limit 0.

## Requirements

### Requirement: Omitted or zero maxBodySizeBytes prepares to the CreateConfig default

When `maxBodySizeBytes` is omitted or set to `0`, plugin construction SHALL prepare that field to the CreateConfig default (8 MiB). A negative value remains a prepare failure (owned by `core_plugin_middleware_prepare-validation`). The prepared default SHALL NOT be treated as a zero `MaxBytesReader` limit.

#### Scenario: Omitted maxBodySizeBytes prepares to 8 MiB

- **WHEN** an operator omits `maxBodySizeBytes` and the plugin is constructed
- **THEN** the prepared body cap SHALL be 8 MiB

#### Scenario: Explicit zero maxBodySizeBytes prepares to 8 MiB

- **WHEN** an operator sets `maxBodySizeBytes` to `0` and the plugin is constructed
- **THEN** the prepared body cap SHALL be 8 MiB

### Requirement: Login-sized POST is allowed under the prepared default cap

When the WAF allows the request, a login-form-sized POST (small application/x-www-form-urlencoded body) SHALL return HTTP 200 and SHALL call the next handler when `maxBodySizeBytes` was omitted or `0` before prepare. The plugin SHALL NOT return 413 for that body solely because the operator omitted the field or wrote `0`.

#### Scenario: Omitted cap login POST is 200

- **WHEN** `maxBodySizeBytes` is omitted and a client POSTs a login-form-sized body
- **AND** the WAF allows the request
- **THEN** the plugin SHALL return HTTP 200
- **AND** the plugin SHALL call the next handler

#### Scenario: Explicit zero cap login POST is 200

- **WHEN** an operator sets `maxBodySizeBytes` to `0` and a client POSTs a login-form-sized body
- **AND** the WAF allows the request
- **THEN** the plugin SHALL return HTTP 200
- **AND** the plugin SHALL call the next handler

### Requirement: Zero leftover handler cap does not install MaxBytesReader

If the in-memory handler body cap is `0` after construction (a leftover field, not an operator-facing unlimited mode), the plugin SHALL NOT wrap the request body with `http.MaxBytesReader`. A login-form-sized POST SHALL NOT return 413 from that wrapper. Go `http.MaxBytesReader` with limit `0` rejects any non-empty body as `*http.MaxBytesError`; this plugin SHALL NOT apply that wrapper at limit `0`.

#### Scenario: Leftover handler cap 0 does not 413 a login POST

- **WHEN** the handler body cap is `0` and a client POSTs a login-form-sized body
- **AND** the WAF allows the request
- **THEN** the plugin SHALL NOT return HTTP 413
- **AND** the plugin SHALL return HTTP 200 and call the next handler
