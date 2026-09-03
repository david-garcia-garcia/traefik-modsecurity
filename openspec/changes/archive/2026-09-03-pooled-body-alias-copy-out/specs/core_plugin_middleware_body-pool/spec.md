## ADDED Requirements

### Requirement: Pooled body bytes are not aliased after Put

After a pooled inbound-body read, the plugin SHALL copy the unread bytes into a slice the pool does not own before building the sidecar request body or restoring `req.Body` for `next`. The plugin SHALL NOT Put a `bytes.Buffer` while any sidecar RoundTripper or `next` reader still aliases that buffer's backing array. A later Get and Reset of the same buffer SHALL NOT change what the earlier request's sidecar or `next` readers observe.

#### Scenario: Delayed sidecar body read still sees the first POST

- **WHEN** a pooled POST body is all byte `0xAA` and the sidecar RoundTripper returns 403 without reading `Request.Body` until after `ServeHTTP` has returned
- **AND** a second pooled POST on the same Plugin core then copies a body of all byte `0xBB` (so the pool can reuse the first buffer)
- **THEN** when the first RoundTripper reads `Request.Body`, that body SHALL be the first POST (`0xAA`), not the second (`0xBB`)
- **AND** the first request SHALL still be a security block (sidecar 403 copied to the client)

#### Scenario: Copy-out still forwards a small pooled body on allow

- **WHEN** a pooled POST is allowed by the sidecar (status below 300)
- **THEN** the sidecar and `next` SHALL each receive that request's own body
