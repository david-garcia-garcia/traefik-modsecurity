## MODIFIED Requirements

### Requirement: Allow path drains the sidecar body

When the sidecar response status is below 300, the plugin SHALL read the leftover response body up to 256 KiB and discard it before closing that body and calling `next`. The plugin SHALL NOT forward that body to the client. The plugin SHALL NOT expose a configuration key for this limit.

#### Scenario: Sequential allows reuse one connection

- **WHEN** the plugin handles several sequential requests whose sidecar responses are 200 with a whoami-sized body
- **THEN** the mock WAF SHALL see one new TCP connection for those requests

#### Scenario: Allow still calls next without the sidecar body

- **WHEN** the sidecar returns 200 with a non-empty body
- **THEN** the client response SHALL be the `next` handler's response, not the sidecar body

### Requirement: Block path still copies the sidecar response

When the sidecar response status is 300 or higher, the plugin SHALL copy that response to the client and SHALL NOT call `next`.

#### Scenario: Block still returns the sidecar page

- **WHEN** the sidecar returns 403 with a body
- **THEN** the client SHALL receive status 403 and that body

#### Scenario: Redirect status is a block

- **WHEN** the sidecar returns 302 with a Location header and a body
- **THEN** the client SHALL receive status 302, that Location, and that body
- **AND** `next` SHALL NOT be called

## ADDED Requirements

### Requirement: WAF client does not follow sidecar redirects

The shared WAF HTTP client SHALL return the sidecar's own response. It SHALL NOT follow `Location` on a 3xx sidecar status.

#### Scenario: Location-bearing 302 is not followed

- **WHEN** the sidecar returns 302 with Location pointing at a 200 notice page
- **THEN** the plugin SHALL treat that 302 as a block and SHALL NOT request the notice page
