# core_plugin_middleware_deny-verbs-with-body

## Purpose

When a request method is listed in `denyVerbsWithBody`, a present body is rejected with HTTP 400 so operators see the failure. Methods not on the list are inspected by ModSecurity and forwarded to `next`.

## Requirements

### Requirement: Listed methods with a body are rejected

When the request method is in `denyVerbsWithBody` and the request has a body, the plugin SHALL return HTTP 400 and SHALL NOT call `next`. The plugin SHALL NOT send that request to ModSecurity. CreateConfig SHALL default `denyVerbsWithBody` to `HEAD`, `GET`, `DELETE`, `OPTIONS`, `TRACE`, `CONNECT`.

#### Scenario: Default GET with a body is rejected

- **WHEN** a GET request carries a non-empty body and `denyVerbsWithBody` is the CreateConfig default
- **THEN** the client SHALL receive HTTP 400 and `next` SHALL NOT be called

#### Scenario: Default DELETE with a body is rejected

- **WHEN** a DELETE request carries a non-empty body and `denyVerbsWithBody` is the CreateConfig default
- **THEN** the client SHALL receive HTTP 400 and `next` SHALL NOT be called

#### Scenario: GET with a body is rejected when the WAF is unhealthy

- **WHEN** a GET request carries a non-empty body and `denyVerbsWithBody` is the CreateConfig default
- **AND** the WAF health tracker is already unhealthy
- **THEN** the client SHALL receive HTTP 400 and `next` SHALL NOT be called

#### Scenario: GET without a body is allowed

- **WHEN** a GET request has no body and `denyVerbsWithBody` is the CreateConfig default
- **THEN** the plugin SHALL call ModSecurity and SHALL call `next` on allow

### Requirement: Explicit empty list denies nothing

When `denyVerbsWithBody` is a non-nil empty slice, Prepare SHALL NOT replace it with the CreateConfig default. The plugin SHALL send that request body to ModSecurity and SHALL restore it for `next` on the allow path.

#### Scenario: GET with a body is inspected when the list is empty

- **WHEN** `denyVerbsWithBody` is an explicit empty array
- **AND** a GET request carries a non-empty body
- **AND** the sidecar allows the request
- **THEN** ModSecurity SHALL receive that body and `next` SHALL receive that same body

### Requirement: Methods not on the list still inspect and forward the body

When the request method is not in `denyVerbsWithBody`, the plugin SHALL send the request body to ModSecurity and SHALL restore that body for `next` on the allow path.

#### Scenario: POST with a body is inspected and forwarded

- **WHEN** a POST request carries a non-empty body and the sidecar allows the request
- **THEN** ModSecurity SHALL receive that body and `next` SHALL receive that same body

### Requirement: Omitted list uses the CreateConfig default

When `denyVerbsWithBody` is nil, Prepare SHALL set it to the CreateConfig default list.

#### Scenario: Nil list becomes the default verbs

- **WHEN** `denyVerbsWithBody` is nil at Prepare
- **THEN** Prepare SHALL set it to `HEAD`, `GET`, `DELETE`, `OPTIONS`, `TRACE`, `CONNECT`
