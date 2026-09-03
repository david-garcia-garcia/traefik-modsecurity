## ADDED Requirements

### Requirement: Large non-file body never returns client 500

A large non-file request body SHALL NOT become a forwarded client HTTP 500. Plugin oversize SHALL be HTTP 413 with status-header `blocked` and SHALL NOT call the sidecar. A sidecar HTTP 413 SHALL be copied as a security block (`blocked`). A sidecar HTTP 5xx SHALL be a WAF failure: HTTP 502 and status-header `error` when fail-open backoff is not configured. The plugin SHALL NOT treat file vs non-file as a distinct mapping.

#### Scenario: Plugin cap exceeded is 413 not 500

- **WHEN** the inbound body is larger than `maxBodySizeBytes`
- **AND** the body is `application/x-www-form-urlencoded` (not a multipart file)
- **THEN** the client SHALL receive HTTP 413
- **AND** the status request header SHALL be `blocked`
- **AND** the next handler SHALL NOT run
- **AND** the sidecar SHALL NOT be called
- **AND** the client SHALL NOT receive HTTP 500

#### Scenario: Sidecar 413 is copied as a block

- **WHEN** the inbound body is under `maxBodySizeBytes`
- **AND** the sidecar responds with HTTP 413
- **THEN** the client SHALL receive HTTP 413
- **AND** the status request header SHALL be `blocked`
- **AND** the next handler SHALL NOT run
- **AND** the client SHALL NOT receive HTTP 500

#### Scenario: Sidecar 500 is 502 not a copied 500

- **WHEN** the inbound body is under `maxBodySizeBytes`
- **AND** fail-open backoff is not configured
- **AND** the sidecar responds with HTTP 500
- **THEN** the client SHALL receive HTTP 502
- **AND** the status request header SHALL be `error`
- **AND** the next handler SHALL NOT run
- **AND** the client SHALL NOT receive HTTP 500
