## ADDED Requirements

### Requirement: Allow path keeps next response headers

When the sidecar response status is below 300, the plugin SHALL call `next` with the same client `ResponseWriter` it received. The client SHALL receive the response headers `next` writes. The plugin SHALL NOT copy sidecar response headers onto that writer on the allow path.

#### Scenario: Backend CORS headers survive a sidecar allow

- **WHEN** the sidecar returns 200
- **AND** `next` sets `Access-Control-Allow-Origin`, `Access-Control-Allow-Headers`, `Access-Control-Allow-Methods`, and a custom backend header
- **THEN** the client SHALL receive status 200, `next`'s body, and those headers
- **AND** headers that exist only on the sidecar response SHALL NOT appear on the client

#### Scenario: Both a real ResponseWriter and a recorder keep next headers

- **WHEN** the same allow request is served through a real `net/http` `ResponseWriter` and through an in-memory recorder
- **THEN** both surfaces SHALL expose `next`'s CORS and custom backend headers
- **AND** neither surface SHALL expose sidecar-only response headers
