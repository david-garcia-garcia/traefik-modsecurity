# core_plugin_middleware_ignored-verb-body

## Purpose

When a request method is listed in `ignoreBodyForVerbs`, the plugin omits that body from ModSecurity and withholds it from the backend so an uninspected payload cannot reach the application.

## Requirements

### Requirement: Ignored-verb body is discarded

When the request method is in `ignoreBodyForVerbs` and `ignoreBodyForVerbsDeny` is false, the plugin SHALL consume the request body and SHALL call `next` with an empty body (`ContentLength` 0 and no `Content-Length` header). The plugin SHALL NOT send that body to ModSecurity. The plugin SHALL NOT change the default value of `ignoreBodyForVerbsDeny`.

#### Scenario: GET with a body reaches next empty

- **WHEN** a GET request carries a non-empty body and `ignoreBodyForVerbsDeny` is false
- **THEN** ModSecurity SHALL receive no body and `next` SHALL read an empty body

#### Scenario: DELETE with a body reaches next empty

- **WHEN** a DELETE request carries a non-empty body and `ignoreBodyForVerbsDeny` is false
- **THEN** ModSecurity SHALL receive no body and `next` SHALL read an empty body

### Requirement: Deny still rejects a body on an ignored verb

When `ignoreBodyForVerbsDeny` is true and the request method is in `ignoreBodyForVerbs`, the plugin SHALL reject a request that has a body with HTTP 400 and SHALL NOT call `next`.

#### Scenario: GET with a body is rejected when deny is true

- **WHEN** a GET request carries a non-empty body and `ignoreBodyForVerbsDeny` is true
- **THEN** the client SHALL receive HTTP 400 and `next` SHALL NOT be called

### Requirement: Methods not on the ignore list still inspect and forward the body

When the request method is not in `ignoreBodyForVerbs`, the plugin SHALL send the request body to ModSecurity and SHALL restore that body for `next` on the allow path.

#### Scenario: POST with a body is inspected and forwarded

- **WHEN** a POST request carries a non-empty body and the sidecar allows the request
- **THEN** ModSecurity SHALL receive that body and `next` SHALL receive that same body
